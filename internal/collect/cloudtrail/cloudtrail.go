// Package cloudtrail は CloudTrail LookupEvents から trail_event / principal_seen を作る collector。
package cloudtrail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// API は SDK クライアントのうち使う部分。テストではフェイクを注入する。
type API interface {
	LookupEvents(ctx context.Context, params *ct.LookupEventsInput, optFns ...func(*ct.Options)) (*ct.LookupEventsOutput, error)
}

// RegionClient はリージョンとそのクライアントの組。
type RegionClient struct {
	Region string
	API    API
}

// Limiter はリクエスト間隔の制御。既定は IntervalLimiter。テストでは差し替える。
type Limiter interface {
	Wait(ctx context.Context) error
}

// LookupEvents の上限は毎秒 2 リクエスト (アカウント単位)。
const (
	requestsPerSecond  = 2
	progressEveryPages = 20
	maxThrottleRetries = 5
)

// Collector は 1 ソース分の LookupEvents collector。複数リージョンを順に引く。
type Collector struct {
	id      string
	clients []RegionClient
	Notable func(record.TrailEvent) bool
	// Limiter はリージョンをまたいで 1 つ共有する (同じアカウントの上限のため)。
	Limiter Limiter
	// Sleep はスロットル時の待ち。テストでは時計を進めるだけの関数に差し替える。
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
}

var _ collect.Collector = (*Collector)(nil)

// NewLimiter は既定のレート制限 (2 req/s、バースト 1) を返す。
func NewLimiter() Limiter { return NewIntervalLimiter(requestsPerSecond) }

func sleepFor(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// New は collector を作る。決定: LookupEvents はリージョン単位なので、IAM / ConsoleLogin / STS の一部が記録される
// us-east-1 を含む複数リージョンを順に引き、principal_seen はリージョン横断で 1 つに集計する。
// events は event_id で重複排除されるので、同じイベントが複数リージョンに見えても二重にならない。
func New(id string, clients ...RegionClient) *Collector {
	return &Collector{id: id, clients: clients, Notable: DefaultNotable, Limiter: NewLimiter(), Sleep: sleepFor, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (c *Collector) ID() string { return c.id }

func (c *Collector) Yields() []record.Kind {
	return []record.Kind{record.KindTrailEvent, record.KindPrincipalSeen}
}

// Collect は窓内の管理イベントを全件引き、注目イベントを trail_event として、主体 × IP の集計を principal_seen として出す。
//
// 決定 (ADR 0013): [w.ScanFrom, w.To) を引く。再走査の区間 [ScanFrom, From) のイベントは、注目イベントの出力と主体の初出・最終観測には使うが、
// principal_seen の件数 (Count) には数えず RescanCount に分ける (前回の run で数え済みのものが二重に足されるため)。重なり区間でだけ見えた主体は Count 0 で出す。
func (c *Collector) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	seen := map[string]*record.PrincipalSeen{}
	doneIDs := map[string]bool{} // 同じイベントが複数リージョンに見えても 1 回だけ数える
	var firstErr error
	for _, rc := range c.clients {
		if err := c.collectRegion(ctx, rc, w, sink, seen, doneIDs); err != nil {
			firstErr = err
			break
		}
	}
	// 失敗しても取れた分の principal_seen は捨てない
	if err := c.flush(ctx, sink, seen); err != nil {
		return err
	}
	return firstErr
}

func (c *Collector) flush(ctx context.Context, sink collect.RecordSink, seen map[string]*record.PrincipalSeen) error {
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := sink.Emit(ctx, *seen[k]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Collector) collectRegion(ctx context.Context, rc RegionClient, w collect.Window, sink collect.RecordSink, seen map[string]*record.PrincipalSeen, doneIDs map[string]bool) error {
	var next *string
	pages, events := 0, 0
	var oldest, lastEvent time.Time // LookupEvents は新しい順に返す
	for {
		out, err := c.lookup(ctx, rc, &ct.LookupEventsInput{
			StartTime:  aws.Time(w.Start()),
			EndTime:    aws.Time(w.To),
			MaxResults: aws.Int32(50),
			NextToken:  next,
		})
		if err != nil {
			ce := collect.Classify(c.id, "cloudtrail:LookupEvents", err)
			ce.Err = fmt.Errorf("region %s (after %d pages): %w", rc.Region, pages, ce.Err)
			if !oldest.IsZero() {
				ce.CoveredFrom, ce.CoveredUntil = oldest, w.To
			}
			return ce
		}
		pages++
		events += len(out.Events)
		for _, raw := range out.Events {
			if raw.EventTime != nil {
				t := raw.EventTime.UTC()
				if oldest.IsZero() || t.Before(oldest) {
					oldest = t
				}
				lastEvent = t
			}
		}
		if pages%progressEveryPages == 0 {
			c.Logger.Info("collect progress", "source", c.id, "region", rc.Region, "pages", pages, "events", events, "last_event_time", lastEvent.Format(time.RFC3339))
		}
		for _, raw := range out.Events {
			e, ok := c.normalize(raw)
			if !ok || doneIDs[e.EventID] {
				continue
			}
			doneIDs[e.EventID] = true
			if e.PrincipalKind != record.PrincipalService && e.PrincipalARN != "" {
				k := e.PrincipalARN + "|" + e.IP
				p, ok := seen[k]
				if !ok {
					p = &record.PrincipalSeen{Source: c.id, ARN: e.PrincipalARN, Kind: e.PrincipalKind, IP: e.IP, Region: e.Region, FirstTime: e.Time, Time: e.Time}
					seen[k] = p
				}
				if e.Time.Before(w.From) {
					p.RescanCount++
				} else {
					p.Count++
				}
				if e.Time.Before(p.FirstTime) {
					p.FirstTime = e.Time
				}
				if !e.Time.Before(p.Time) {
					p.Time = e.Time
					p.Region = e.Region
				}
			}
			if c.Notable(e) {
				if err := sink.Emit(ctx, e); err != nil {
					return err
				}
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			c.Logger.Info("collect region done", "source", c.id, "region", rc.Region, "pages", pages, "events", events)
			return nil
		}
		next = out.NextToken
	}
}

// lookup はレート制限を守って 1 ページ引く。スロットルされたら待って再試行する (SDK のリトライの外側の保険)。
func (c *Collector) lookup(ctx context.Context, rc RegionClient, in *ct.LookupEventsInput) (*ct.LookupEventsOutput, error) {
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		if err := c.Limiter.Wait(ctx); err != nil {
			return nil, err
		}
		out, err := rc.API.LookupEvents(ctx, in)
		if err == nil {
			return out, nil
		}
		if collect.Classify(c.id, "", err).Code != collect.CodeQueryLimit || attempt >= maxThrottleRetries {
			return nil, err
		}
		c.Logger.Warn("throttled; retrying", "source", c.id, "region", rc.Region, "attempt", attempt+1, "wait", backoff.String())
		if err := c.Sleep(ctx, backoff); err != nil {
			return nil, err
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// rawEvent は CloudTrailEvent JSON のうち使うフィールド。
type rawEvent struct {
	UserIdentity struct {
		Type           string `json:"type"`
		PrincipalID    string `json:"principalId"`
		ARN            string `json:"arn"`
		AccountID      string `json:"accountId"`
		InvokedBy      string `json:"invokedBy"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
			Attributes struct {
				MFAAuthenticated string `json:"mfaAuthenticated"`
			} `json:"attributes"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	EventTime           string         `json:"eventTime"`
	EventSource         string         `json:"eventSource"`
	EventName           string         `json:"eventName"`
	AWSRegion           string         `json:"awsRegion"`
	SourceIPAddress     string         `json:"sourceIPAddress"`
	UserAgent           string         `json:"userAgent"`
	ErrorCode           string         `json:"errorCode"`
	ReadOnly            bool           `json:"readOnly"`
	EventID             string         `json:"eventID"`
	RequestParameters   map[string]any `json:"requestParameters"`
	ResponseElements    map[string]any `json:"responseElements"`
	AdditionalEventData map[string]any `json:"additionalEventData"`
	Resources           []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

func (c *Collector) normalize(raw types.Event) (record.TrailEvent, bool) {
	var r rawEvent
	if raw.CloudTrailEvent == nil || json.Unmarshal([]byte(*raw.CloudTrailEvent), &r) != nil {
		return record.TrailEvent{}, false
	}
	e := record.TrailEvent{
		EventID:     aws.ToString(raw.EventId),
		Source:      c.id,
		Name:        r.EventName,
		EventSource: r.EventSource,
		Region:      r.AWSRegion,
		ReadOnly:    r.ReadOnly,
		ErrorCode:   r.ErrorCode,
		Data:        map[string]any{},
	}
	if e.EventID == "" {
		e.EventID = r.EventID
	}
	if raw.EventTime != nil {
		e.Time = raw.EventTime.UTC()
	} else if t, err := time.Parse(time.RFC3339, r.EventTime); err == nil {
		e.Time = t.UTC()
	}
	if e.EventID == "" || e.Time.IsZero() {
		return record.TrailEvent{}, false
	}
	e.PrincipalARN, e.PrincipalKind = principalOf(r)
	// サービス名 (ec2.amazonaws.com など) は IP ではないので落とす
	if !strings.HasSuffix(r.SourceIPAddress, ".amazonaws.com") && r.SourceIPAddress != "AWS Internal" {
		e.IP = r.SourceIPAddress
	}
	if len(r.Resources) > 0 {
		e.Resource = r.Resources[0].ARN
	}
	// 根拠として残すのは識別子のみ (セッション名・氏名・メールは入れない)
	for src, dst := range map[string]string{"roleArn": "role_arn", "userName": "user_name", "roleName": "role_name", "groupName": "group_name", "policyArn": "policy_arn", "policyName": "policy_name", "name": "name", "secretId": "secret_id", "target": "target", "groupId": "group_id", "dBInstanceIdentifier": "db_instance"} {
		if v, ok := r.RequestParameters[src].(string); ok && v != "" {
			e.Data[dst] = v
		}
	}
	if v, ok := r.AdditionalEventData["MFAUsed"].(string); ok {
		e.Data["mfa"] = v
	}
	if v, ok := r.ResponseElements["ConsoleLogin"].(string); ok {
		e.Data["login_result"] = v
	}
	if r.UserIdentity.SessionContext.Attributes.MFAAuthenticated != "" {
		e.Data["session_mfa"] = r.UserIdentity.SessionContext.Attributes.MFAAuthenticated
	}
	if r.UserIdentity.AccountID != "" {
		e.Data["account_id"] = r.UserIdentity.AccountID
	}
	return e, true
}

// principalOf は userIdentity を主体 ARN と種類に正規化する。
// 決定: AssumedRole はセッション ARN ではなくロール ARN (sessionIssuer) に寄せる。セッション名に個人名やメールが入るため。
func principalOf(r rawEvent) (string, record.PrincipalKind) {
	u := r.UserIdentity
	switch u.Type {
	case "Root":
		if u.ARN != "" {
			return u.ARN, record.PrincipalRoot
		}
		return "arn:aws:iam::" + u.AccountID + ":root", record.PrincipalRoot
	case "IAMUser":
		return u.ARN, record.PrincipalUser
	case "AssumedRole", "FederatedUser", "SAMLUser", "WebIdentityUser", "IdentityCenterUser":
		if u.SessionContext.SessionIssuer.ARN != "" {
			return u.SessionContext.SessionIssuer.ARN, record.PrincipalAssumedRole
		}
		if role := roleARNFromSession(u.ARN); role != "" {
			return role, record.PrincipalAssumedRole
		}
		return u.ARN, record.PrincipalAssumedRole
	case "Role":
		return u.ARN, record.PrincipalRole
	case "AWSService":
		return u.InvokedBy, record.PrincipalService
	}
	// 決定: type が無い記録のうち、invokedBy があるもの・sourceIPAddress か userAgent が "AWS Internal" のものは
	// AWS サービス自身の記録 (ECR の PolicyExecutionEvent など) なのでサービスの主体にする (設計書 6 章)。
	if u.Type == "" && u.ARN == "" {
		if u.InvokedBy != "" {
			return u.InvokedBy, record.PrincipalService
		}
		if (r.SourceIPAddress == "AWS Internal" || r.UserAgent == "AWS Internal") && r.EventSource != "" {
			return r.EventSource, record.PrincipalService
		}
	}
	if u.ARN != "" {
		return u.ARN, record.PrincipalUnknown
	}
	if u.AccountID != "" {
		return "arn:aws:iam::" + u.AccountID + ":root", record.PrincipalUnknown
	}
	return u.PrincipalID, record.PrincipalUnknown
}

// roleARNFromSession は arn:aws:sts::ACCT:assumed-role/ROLE/SESSION を arn:aws:iam::ACCT:role/ROLE に変換する。
func roleARNFromSession(arn string) string {
	const marker = ":assumed-role/"
	i := strings.Index(arn, marker)
	if i < 0 || !strings.HasPrefix(arn, "arn:aws:sts::") {
		return ""
	}
	acct := strings.TrimPrefix(arn[:i], "arn:aws:sts::")
	rest := arn[i+len(marker):]
	role, _, _ := strings.Cut(rest, "/")
	if role == "" {
		return ""
	}
	return "arn:aws:iam::" + acct + ":role/" + role
}

var notableNames = map[string]bool{
	"ConsoleLogin": true, "GetSecretValue": true, "GetParameter": true, "GetParameters": true, "GetParametersByPath": true,
	"StartSession": true, "AuthorizeSecurityGroupIngress": true, "AuthorizeSecurityGroupEgress": true,
	"ModifyDBInstance": true, "CreateDBInstance": true, "PutBucketPolicy": true, "PutBucketAcl": true, "PutPublicAccessBlock": true, "DeletePublicAccessBlock": true,
}

// DefaultNotable は events テーブルに残す「注目イベント」の判定 (設計書 5-2)。拒否のコードは既定 (config.DefaultDeniedErrorCodes)。
// 決定: ルート利用、AssumeRole*、IAM / CloudTrail / GuardDuty の書き込み、秘匿値取得、SSM セッション、公開設定の変更、
// 拒否された呼び出し (access_denied。ADR 0021) を残す。それ以外は principal_seen にだけ集計する。
var DefaultNotable = NotableWith(config.DefaultDeniedErrorCodes)

// NotableWith は deniedCodes (errorCode の完全一致) の呼び出しも残す注目イベントの判定を返す (設定 checks.access_denied.error_codes)。
// 決定: 拒否の保存はチェックを有効にしているかに依らない (init のベースライン収集でも残し、平常帯に使う)。
func NotableWith(deniedCodes []string) func(record.TrailEvent) bool {
	denied := make(map[string]bool, len(deniedCodes))
	for _, c := range deniedCodes {
		denied[c] = true
	}
	return func(e record.TrailEvent) bool {
		return (e.ErrorCode != "" && denied[e.ErrorCode]) || notable(e)
	}
}

func notable(e record.TrailEvent) bool {
	if e.PrincipalKind == record.PrincipalRoot {
		return true
	}
	if strings.HasPrefix(e.Name, "AssumeRole") {
		return true
	}
	switch e.EventSource {
	case "iam.amazonaws.com", "cloudtrail.amazonaws.com", "guardduty.amazonaws.com", "access-analyzer.amazonaws.com", "organizations.amazonaws.com":
		return !e.ReadOnly
	}
	return notableNames[e.Name]
}
