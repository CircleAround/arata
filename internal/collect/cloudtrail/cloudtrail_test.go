package cloudtrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
	"golang.org/x/time/rate"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// Fake は LookupEvents のフェイク。ページングとエラーを模倣する。
type Fake struct {
	Pages [][]types.Event
	Err   error
	Calls []*ct.LookupEventsInput
	// FailFirst 回だけ FailErr を返してから成功する (スロットルの模倣)
	FailFirst int
	FailErr   error
	// FailAtPage 以降のページ要求は Err を返す (途中失敗の模倣)
	FailAtPage int
}

func (f *Fake) LookupEvents(ctx context.Context, in *ct.LookupEventsInput, _ ...func(*ct.Options)) (*ct.LookupEventsOutput, error) {
	f.Calls = append(f.Calls, in)
	if f.FailFirst > 0 {
		f.FailFirst--
		return nil, f.FailErr
	}
	page := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "p%d", &page)
	}
	if f.Err != nil && (f.FailAtPage == 0 || page >= f.FailAtPage) {
		return nil, f.Err
	}
	if page >= len(f.Pages) {
		return &ct.LookupEventsOutput{}, nil
	}
	out := &ct.LookupEventsOutput{Events: f.Pages[page]}
	if page+1 < len(f.Pages) {
		tok := fmt.Sprintf("p%d", page+1)
		out.NextToken = &tok
	}
	return out, nil
}

func ev(id string, t time.Time, body string) types.Event {
	return types.Event{EventId: &id, EventTime: &t, CloudTrailEvent: &body}
}

const (
	rootLogin = `{"userIdentity":{"type":"Root","principalId":"123456789012","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012"},
	  "eventTime":"2026-10-21T01:00:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.1",
	  "additionalEventData":{"MFAUsed":"Yes"},"responseElements":{"ConsoleLogin":"Success"},"readOnly":false,"eventID":"e-root"}`
	assumeRole = `{"userIdentity":{"type":"IAMUser","principalId":"AID","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012","userName":"alice"},
	  "eventTime":"2026-10-21T02:00:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"ap-northeast-1","sourceIPAddress":"203.0.113.2",
	  "requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/Admin","roleSessionName":"alice@example.com"},"readOnly":true,"eventID":"e-assume",
	  "resources":[{"ARN":"arn:aws:iam::123456789012:role/Admin","type":"AWS::IAM::Role"}]}`
	iamChange = `{"userIdentity":{"type":"AssumedRole","principalId":"AROA:bob@example.com","arn":"arn:aws:sts::123456789012:assumed-role/Admin/bob@example.com","accountId":"123456789012",
	  "sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/Admin","userName":"Admin"}}},
	  "eventTime":"2026-10-21T03:00:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.2",
	  "requestParameters":{"userName":"carol","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},"readOnly":false,"eventID":"e-iam"}`
	readOnlyNoise = `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},
	  "eventTime":"2026-10-21T03:30:00Z","eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","awsRegion":"ap-northeast-1","sourceIPAddress":"203.0.113.2","readOnly":true,"eventID":"e-noise"}`
	serviceEvent = `{"userIdentity":{"type":"AWSService","invokedBy":"ec2.amazonaws.com"},
	  "eventTime":"2026-10-21T03:40:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"ap-northeast-1","sourceIPAddress":"ec2.amazonaws.com",
	  "requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/EC2Role"},"readOnly":true,"eventID":"e-svc"}`
	chainedAssume = `{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/Admin/sess","accountId":"123456789012"},
	  "eventTime":"2026-10-21T04:00:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"ap-northeast-1","sourceIPAddress":"203.0.113.3",
	  "requestParameters":{"roleArn":"arn:aws:iam::999999999999:role/Cross"},"readOnly":true,"eventID":"e-chain"}`
)

type captured struct {
	events     []record.TrailEvent
	principals []record.PrincipalSeen
}

func (c *captured) Emit(_ context.Context, r record.Record) error {
	switch v := r.(type) {
	case record.TrailEvent:
		c.events = append(c.events, v)
	case record.PrincipalSeen:
		c.principals = append(c.principals, v)
	}
	return nil
}

func TestCollectNormalizes(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	fake := &Fake{Pages: [][]types.Event{
		{ev("e-root", base.Add(time.Hour), rootLogin), ev("e-assume", base.Add(2*time.Hour), assumeRole)},
		{ev("e-iam", base.Add(3*time.Hour), iamChange), ev("e-noise", base.Add(3*time.Hour+30*time.Minute), readOnlyNoise), ev("e-svc", base.Add(3*time.Hour+40*time.Minute), serviceEvent), ev("e-chain", base.Add(4*time.Hour), chainedAssume)},
	}}
	c, lim, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	sink := &captured{}
	w := collect.Window{From: base, To: base.Add(24 * time.Hour)}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if len(fake.Calls) != 2 || !fake.Calls[0].StartTime.Equal(base) || !fake.Calls[0].EndTime.Equal(w.To) || lim.n != 2 {
		t.Fatalf("calls: %d limiter: %d", len(fake.Calls), lim.n)
	}
	// 注目イベントのみ (DescribeInstances は落ちる)。サービス主体の AssumeRole は principal_seen に出ないが event は残す。
	ids := []string{}
	for _, e := range sink.events {
		ids = append(ids, e.EventID)
	}
	if strings.Join(ids, ",") != "e-root,e-assume,e-iam,e-svc,e-chain" {
		t.Fatalf("notable events: %v", ids)
	}
	byID := map[string]record.TrailEvent{}
	for _, e := range sink.events {
		byID[e.EventID] = e
	}
	root := byID["e-root"]
	if root.PrincipalKind != record.PrincipalRoot || root.PrincipalARN != "arn:aws:iam::123456789012:root" || root.IP != "203.0.113.1" || root.Region != "us-east-1" || root.Source != "trail" || root.Data["mfa"] != "Yes" {
		t.Fatalf("root: %+v", root)
	}
	as := byID["e-assume"]
	if as.PrincipalKind != record.PrincipalUser || as.Data["role_arn"] != "arn:aws:iam::123456789012:role/Admin" || as.Resource != "arn:aws:iam::123456789012:role/Admin" {
		t.Fatalf("assume: %+v", as)
	}
	if _, ok := as.Data["role_session_name"]; ok {
		t.Fatal("session name must not be recorded")
	}
	iam := byID["e-iam"]
	if iam.PrincipalKind != record.PrincipalAssumedRole || iam.PrincipalARN != "arn:aws:iam::123456789012:role/Admin" || iam.Data["user_name"] != "carol" || iam.Data["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" {
		t.Fatalf("iam: %+v", iam)
	}
	svc := byID["e-svc"]
	if svc.PrincipalKind != record.PrincipalService || svc.PrincipalARN != "ec2.amazonaws.com" {
		t.Fatalf("svc: %+v", svc)
	}
	chain := byID["e-chain"]
	if chain.PrincipalARN != "arn:aws:iam::123456789012:role/Admin" || chain.PrincipalKind != record.PrincipalAssumedRole {
		t.Fatalf("chained assumed role without sessionIssuer must derive role ARN: %+v", chain)
	}
	for _, e := range sink.events {
		if strings.Contains(fmt.Sprint(e), "example.com") {
			t.Fatalf("PII leaked: %+v", e)
		}
	}

	// principal_seen: alice (2 events, 1 IP), Admin role (2 events, 2 IPs), root。サービス主体は除く。
	got := map[string]record.PrincipalSeen{}
	for _, p := range sink.principals {
		got[p.ARN+"|"+p.IP] = p
	}
	if len(got) != 4 {
		t.Fatalf("principals: %+v", sink.principals)
	}
	a := got["arn:aws:iam::123456789012:user/alice|203.0.113.2"]
	if a.Count != 2 || a.Kind != record.PrincipalUser || !a.FirstTime.Equal(base.Add(2*time.Hour)) || !a.Time.Equal(base.Add(3*time.Hour+30*time.Minute)) {
		t.Fatalf("alice: %+v", a)
	}
	if got["arn:aws:iam::123456789012:role/Admin|203.0.113.3"].Count != 1 {
		t.Fatalf("admin role 2nd ip: %+v", sink.principals)
	}
}

type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.code }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestCollectErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"access denied", apiErr{"AccessDeniedException"}, collect.CodeAccessDenied},
		{"throttle", apiErr{"ThrottlingException"}, collect.CodeQueryLimit},
		{"invalid query", apiErr{"InvalidTimeRangeException"}, collect.CodeQueryInvalid},
		{"other", errors.New("boom"), collect.CodeCollectFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: &Fake{Err: tc.err}})
			err := c.Collect(context.Background(), collect.Window{From: time.Now().Add(-time.Hour), To: time.Now()}, &captured{})
			var ce *collect.Error
			if !errors.As(err, &ce) || ce.Code != tc.code || ce.Source != "trail" || !strings.Contains(err.Error(), "region ap-northeast-1") {
				t.Fatalf("got %v", err)
			}
			if tc.code == collect.CodeAccessDenied && ce.Action != "cloudtrail:LookupEvents" {
				t.Fatalf("action: %q", ce.Action)
			}
		})
	}
}

func TestCollectMultiRegion(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	// ap-northeast-1 には alice の通常操作、us-east-1 にはルートログインと alice の IAM 変更
	tokyo := &Fake{Pages: [][]types.Event{{ev("e-noise", base.Add(time.Hour), readOnlyNoise)}}}
	// e-noise は両リージョンに見える (実際には起きないが、起きても 1 回だけ数える)
	virginia := &Fake{Pages: [][]types.Event{{ev("e-root", base.Add(2*time.Hour), rootLogin), ev("e-iam", base.Add(3*time.Hour), iamChange), ev("e-noise", base.Add(time.Hour), readOnlyNoise)}}}
	c, lim, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: tokyo}, RegionClient{Region: "us-east-1", API: virginia})
	sink := &captured{}
	if err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(24 * time.Hour)}, sink); err != nil {
		t.Fatal(err)
	}
	if len(tokyo.Calls) != 1 || len(virginia.Calls) != 1 || lim.n != 2 {
		t.Fatalf("each region must be queried once through the shared limiter: %d %d %d", len(tokyo.Calls), len(virginia.Calls), lim.n)
	}
	ids := []string{}
	for _, e := range sink.events {
		ids = append(ids, e.EventID)
	}
	if strings.Join(ids, ",") != "e-root,e-iam" {
		t.Fatalf("events: %v", ids)
	}
	// alice はリージョン横断で 1 件に集計され、Region は最後に観測したもの、Admin ロールは us-east-1
	got := map[string]record.PrincipalSeen{}
	for _, p := range sink.principals {
		got[p.ARN] = p
	}
	if len(got) != 3 {
		t.Fatalf("principals: %+v", sink.principals)
	}
	root := got["arn:aws:iam::123456789012:root"]
	if root.Region != "us-east-1" || root.Count != 1 {
		t.Fatalf("root: %+v", root)
	}
	alice := got["arn:aws:iam::123456789012:user/alice"]
	if alice.Count != 1 || alice.Region != "ap-northeast-1" {
		t.Fatalf("alice must be counted once across regions: %+v", alice)
	}
	// 片方のリージョンが失敗したらソース全体を失敗として返す
	c, _, _ = testCollector("trail", RegionClient{Region: "ap-northeast-1", API: tokyo}, RegionClient{Region: "us-east-1", API: &Fake{Err: apiErr{"AccessDeniedException"}}})
	err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(24 * time.Hour)}, &captured{})
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeAccessDenied || !strings.Contains(err.Error(), "region us-east-1") {
		t.Fatalf("got %v", err)
	}
}

// countingLimiter は Wait の回数を数えるだけで待たない。
type countingLimiter struct{ n int }

func (l *countingLimiter) Wait(context.Context) error { l.n++; return nil }

func testCollector(id string, clients ...RegionClient) (*Collector, *countingLimiter, *[]time.Duration) {
	c := New(id, clients...)
	lim := &countingLimiter{}
	var slept []time.Duration
	c.Limiter = lim
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	return c, lim, &slept
}

func TestThrottleRetry(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	fake := &Fake{Pages: [][]types.Event{{ev("e-root", base.Add(time.Hour), rootLogin)}}, FailFirst: 2, FailErr: apiErr{"ThrottlingException"}}
	c, lim, slept := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	sink := &captured{}
	if err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(24 * time.Hour)}, sink); err != nil {
		t.Fatalf("must succeed after throttles: %v", err)
	}
	if len(fake.Calls) != 3 || lim.n != 3 {
		t.Fatalf("calls=%d limiter waits=%d (limiter must be called before every request)", len(fake.Calls), lim.n)
	}
	if len(*slept) != 2 || (*slept)[0] != time.Second || (*slept)[1] != 2*time.Second {
		t.Fatalf("backoff: %v", *slept)
	}
	if len(sink.events) != 1 || len(sink.principals) != 1 {
		t.Fatalf("records: %d %d", len(sink.events), len(sink.principals))
	}
	// 上限を超えたら諦めて QUERY_LIMIT
	fake = &Fake{Pages: [][]types.Event{{}}, FailFirst: 10, FailErr: apiErr{"ThrottlingException"}}
	c, _, _ = testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(24 * time.Hour)}, &captured{})
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeQueryLimit || len(fake.Calls) != maxThrottleRetries+1 {
		t.Fatalf("got %v after %d calls", err, len(fake.Calls))
	}
	// 他のエラーは再試行しない
	fake = &Fake{Pages: [][]types.Event{{}}, FailFirst: 1, FailErr: apiErr{"AccessDeniedException"}}
	c, _, _ = testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	if err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(24 * time.Hour)}, &captured{}); err == nil || len(fake.Calls) != 1 {
		t.Fatalf("got %v after %d calls", err, len(fake.Calls))
	}
}

func TestPartialFailureKeepsFetched(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	w := collect.Window{From: base, To: base.Add(24 * time.Hour)}
	// 新しい順に 2 ページ。2 ページ目で失敗する
	fake := &Fake{Pages: [][]types.Event{
		{ev("e-iam", base.Add(3*time.Hour), iamChange), ev("e-assume", base.Add(2*time.Hour), assumeRole)},
		{ev("e-root", base.Add(time.Hour), rootLogin)},
	}, Err: apiErr{"ThrottlingException"}, FailAtPage: 1}
	c, _, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	sink := &captured{}
	err := c.Collect(context.Background(), w, sink)
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeQueryLimit {
		t.Fatalf("got %v", err)
	}
	if !ce.CoveredFrom.Equal(base.Add(2*time.Hour)) || !ce.CoveredUntil.Equal(w.To) {
		t.Fatalf("covered range must be [oldest fetched, window.To]: %v - %v", ce.CoveredFrom, ce.CoveredUntil)
	}
	if !strings.Contains(err.Error(), "after 1 pages") {
		t.Fatalf("message: %v", err)
	}
	// 1 ページ目のイベントと、その主体の principal_seen は残っている
	if len(sink.events) != 2 || len(sink.principals) != 2 {
		t.Fatalf("fetched records must be kept: events=%d principals=%d", len(sink.events), len(sink.principals))
	}
	// 最初の要求から失敗した場合は covered がゼロ値
	fake = &Fake{Pages: [][]types.Event{{}}, Err: apiErr{"AccessDeniedException"}}
	c, _, _ = testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	err = c.Collect(context.Background(), w, &captured{})
	if !errors.As(err, &ce) || !ce.CoveredFrom.IsZero() {
		t.Fatalf("got %v covered=%v", err, ce.CoveredFrom)
	}
}

func TestProgressLog(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	var pages [][]types.Event
	for i := 0; i < 41; i++ {
		pages = append(pages, []types.Event{ev(fmt.Sprintf("e-%d", i), base.Add(time.Duration(41-i)*time.Minute), readOnlyNoise)})
	}
	fake := &Fake{Pages: pages}
	c, _, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	var buf strings.Builder
	c.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	if err := c.Collect(context.Background(), collect.Window{From: base, To: base.Add(time.Hour)}, &captured{}); err != nil {
		t.Fatal(err)
	}
	progress := 0
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		_ = json.Unmarshal([]byte(line), &m)
		if m["msg"] == "collect progress" {
			progress++
			if m["region"] != "ap-northeast-1" || m["pages"] == nil || m["events"] == nil || m["last_event_time"] == nil {
				t.Fatalf("progress line: %v", m)
			}
		}
	}
	if progress != 2 {
		t.Fatalf("progress lines: %d (41 pages → at 20 and 40)", progress)
	}
}

func TestDefaultLimiterIsRateLimiter(t *testing.T) {
	c := New("trail")
	if _, ok := c.Limiter.(*rate.Limiter); !ok || c.Sleep == nil || c.Logger == nil {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestNotable(t *testing.T) {
	cases := []struct {
		e    record.TrailEvent
		want bool
	}{
		{record.TrailEvent{PrincipalKind: record.PrincipalRoot, Name: "DescribeInstances", ReadOnly: true}, true},
		{record.TrailEvent{EventSource: "iam.amazonaws.com", Name: "GetUser", ReadOnly: true}, false},
		{record.TrailEvent{EventSource: "iam.amazonaws.com", Name: "CreateUser"}, true},
		{record.TrailEvent{EventSource: "sts.amazonaws.com", Name: "AssumeRoleWithSAML", ReadOnly: true}, true},
		{record.TrailEvent{EventSource: "cloudtrail.amazonaws.com", Name: "StopLogging"}, true},
		{record.TrailEvent{EventSource: "secretsmanager.amazonaws.com", Name: "GetSecretValue", ReadOnly: true}, true},
		{record.TrailEvent{EventSource: "ssm.amazonaws.com", Name: "StartSession"}, true},
		{record.TrailEvent{EventSource: "ec2.amazonaws.com", Name: "AuthorizeSecurityGroupIngress"}, true},
		{record.TrailEvent{EventSource: "s3.amazonaws.com", Name: "ListBuckets", ReadOnly: true}, false},
		{record.TrailEvent{EventSource: "ec2.amazonaws.com", Name: "RunInstances"}, false},
	}
	for _, tc := range cases {
		if got := DefaultNotable(tc.e); got != tc.want {
			t.Errorf("%s/%s: got %v", tc.e.EventSource, tc.e.Name, got)
		}
	}
}

// 再走査 (ADR 0013): [ScanFrom, From) も引き、注目イベントは出すが principal_seen の件数には数えない (前回の run で数え済みのため)。
func TestCollectRescanOverlap(t *testing.T) {
	from := time.Date(2026, 10, 21, 6, 0, 0, 0, time.UTC)
	w := collect.Window{From: from, To: from.Add(time.Hour), ScanFrom: from.Add(-15 * time.Minute)}
	fake := &Fake{Pages: [][]types.Event{{
		ev("e-in", from.Add(10*time.Minute), readOnlyNoise),
		ev("e-overlap", from.Add(-5*time.Minute), readOnlyNoise),
		ev("e-root-late", from.Add(-3*time.Minute), rootLogin),
	}}}
	c, _, _ := testCollector("trail", RegionClient{Region: "us-east-1", API: fake})
	sink := &captured{}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if !fake.Calls[0].StartTime.Equal(w.ScanFrom) || !fake.Calls[0].EndTime.Equal(w.To) {
		t.Fatalf("lookup range must start at ScanFrom: %v..%v", fake.Calls[0].StartTime, fake.Calls[0].EndTime)
	}
	if len(sink.events) != 1 || sink.events[0].EventID != "e-root-late" {
		t.Fatalf("notable events in the overlap must be emitted: %+v", sink.events)
	}
	got := map[string]record.PrincipalSeen{}
	for _, p := range sink.principals {
		got[p.ARN] = p
	}
	alice := got["arn:aws:iam::123456789012:user/alice"]
	if alice.Count != 1 || !alice.FirstTime.Equal(from.Add(-5*time.Minute)) || !alice.Time.Equal(from.Add(10*time.Minute)) {
		t.Fatalf("overlap must widen first/last seen but not the count: %+v", alice)
	}
	// 重なり区間でだけ見えた主体も principals の判定のために出す (件数は 0)
	root := got["arn:aws:iam::123456789012:root"]
	if root.ARN == "" || root.Count != 0 || root.RescanCount != 1 || alice.RescanCount != 1 {
		t.Fatalf("principal seen only in the overlap: %+v", root)
	}
}
