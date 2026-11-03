// Package cloudtrailtest は LookupEvents のフェイクとテスト用イベントの組み立てを提供する。
package cloudtrailtest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

// Fake は LookupEvents のフェイク。窓に入るイベントだけをページ分けして返す。
type Fake struct {
	mu       sync.Mutex
	Events   []types.Event
	PageSize int
	Err      error
	Calls    []*ct.LookupEventsInput
	// FailAtPage > 0 なら、そのページ番号 (0 始まり) 以降の要求で Err を返す。0 なら最初から Err。
	FailAtPage int
	// ErrFor が非 nil なら要求ごとに呼び、nil 以外を返したらそのエラーにする (窓に応じた失敗用)。
	ErrFor func(in *ct.LookupEventsInput) error
}

// LookupEvents は API インターフェースの実装。
func (f *Fake) LookupEvents(_ context.Context, in *ct.LookupEventsInput, _ ...func(*ct.Options)) (*ct.LookupEventsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, in)
	if f.ErrFor != nil {
		if err := f.ErrFor(in); err != nil {
			return nil, err
		}
	}
	start := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	if f.Err != nil && (f.FailAtPage == 0 || start >= f.FailAtPage*f.pageSize()) {
		return nil, f.Err
	}
	var inWindow []types.Event
	for _, e := range f.Events {
		if e.EventTime == nil || !matchesAttributes(e, in.LookupAttributes) {
			continue
		}
		if (in.StartTime == nil || !e.EventTime.Before(*in.StartTime)) && (in.EndTime == nil || e.EventTime.Before(*in.EndTime)) {
			inWindow = append(inWindow, e)
		}
	}
	// LookupEvents は新しい順に返す
	sort.SliceStable(inWindow, func(i, j int) bool { return inWindow[i].EventTime.After(*inWindow[j].EventTime) })
	size := f.pageSize()
	end := start + size
	if end > len(inWindow) {
		end = len(inWindow)
	}
	out := &ct.LookupEventsOutput{}
	if start < end {
		out.Events = inWindow[start:end]
	}
	if end < len(inWindow) {
		tok := fmt.Sprint(end)
		out.NextToken = &tok
	}
	return out, nil
}

// matchesAttributes は LookupAttributes のうち ReadOnly だけを見る (他の属性は使っていない)。
func matchesAttributes(e types.Event, attrs []types.LookupAttribute) bool {
	for _, a := range attrs {
		if a.AttributeKey != types.LookupAttributeKeyReadOnly || a.AttributeValue == nil || e.CloudTrailEvent == nil {
			continue
		}
		var body struct {
			ReadOnly bool `json:"readOnly"`
		}
		_ = json.Unmarshal([]byte(*e.CloudTrailEvent), &body)
		if fmt.Sprint(body.ReadOnly) != *a.AttributeValue {
			return false
		}
	}
	return true
}

func (f *Fake) pageSize() int {
	if f.PageSize <= 0 {
		return 50
	}
	return f.PageSize
}

// Add はイベントを追加する。
func (f *Fake) Add(evs ...types.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Events = append(f.Events, evs...)
}

// Identity は userIdentity の組み立て用。
type Identity map[string]any

// User は IAM ユーザー。
func User(account, name string) Identity {
	return Identity{"type": "IAMUser", "principalId": "AID" + name, "arn": fmt.Sprintf("arn:aws:iam::%s:user/%s", account, name), "accountId": account, "userName": name}
}

// Root はルート。
func Root(account string) Identity {
	return Identity{"type": "Root", "principalId": account, "arn": fmt.Sprintf("arn:aws:iam::%s:root", account), "accountId": account}
}

// AssumedRole はロールセッション。
func AssumedRole(account, role, session string) Identity {
	return Identity{"type": "AssumedRole", "principalId": "AROA:" + session, "arn": fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", account, role, session), "accountId": account,
		"sessionContext": map[string]any{"sessionIssuer": map[string]any{"type": "Role", "arn": fmt.Sprintf("arn:aws:iam::%s:role/%s", account, role), "userName": role}}}
}

// Service は AWS のサービスの主体 (userIdentity.type = AWSService)。
func Service(invokedBy string) Identity {
	return Identity{"type": "AWSService", "invokedBy": invokedBy}
}

// Event は CloudTrailEvent JSON を持つ types.Event を組み立てる。
func Event(id string, t time.Time, who Identity, source, name, region, ip string, readOnly bool, request map[string]any) types.Event {
	body := map[string]any{
		"eventVersion": "1.08", "userIdentity": map[string]any(who), "eventTime": t.UTC().Format(time.RFC3339),
		"eventSource": source, "eventName": name, "awsRegion": region, "sourceIPAddress": ip, "readOnly": readOnly, "eventID": id,
	}
	if request != nil {
		body["requestParameters"] = request
	}
	b, _ := json.Marshal(body)
	s := string(b)
	return types.Event{EventId: &id, EventTime: &t, CloudTrailEvent: &s}
}

// WithError は ev に errorCode を付けたもの (拒否された呼び出しなど) を返す。
func WithError(ev types.Event, code string) types.Event {
	var body map[string]any
	_ = json.Unmarshal([]byte(*ev.CloudTrailEvent), &body)
	body["errorCode"] = code
	b, _ := json.Marshal(body)
	s := string(b)
	ev.CloudTrailEvent = &s
	return ev
}

// APIError は smithy.APIError を満たす最小のエラー。
type APIError struct{ Code string }

func (e APIError) Error() string                 { return e.Code }
func (e APIError) ErrorCode() string             { return e.Code }
func (e APIError) ErrorMessage() string          { return e.Code }
func (e APIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

var _ smithy.APIError = APIError{}
