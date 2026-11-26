package cloudtrail

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// aws login のログインのセッション (ADR 0092 の 1 節)。形は背景の「実際の記録で分かった形」のとおり。値は架空。
const (
	signinARN     = "arn:aws:signin:ap-northeast-1:123456789012:session/11111111-2222-3333-4444-555555555555"
	signinUUID    = "11111111-2222-3333-4444-555555555555"
	signinRefresh = `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012",
	  "sessionContext":{"attributes":{"mfaAuthenticated":"true"},"signInSessionArn":"` + signinARN + `"}},
	  "eventTime":"2026-11-26T01:00:00Z","eventSource":"signin.amazonaws.com","eventName":"CreateOAuth2Token","awsRegion":"ap-northeast-1",
	  "sourceIPAddress":"203.0.113.10","userAgent":"aws-cli/2.31.4 md/awscrt#0.27.6 ua/2.1 os/linux#6.8.0","eventType":"AwsApiCall",
	  "managementEvent":true,"readOnly":true,"eventID":"e-signin",
	  "requestParameters":{"client_id":"arn:aws:signin:::devtools/same-device"},"responseElements":null,
	  "additionalEventData":{"signInSessionArn":"` + signinARN + `","SignInSessionExtended":"false","grant_type":"refresh_token","success":"true"}}`
)

func TestNormalizeSigninRefresh(t *testing.T) {
	e := normalizeBody(t, signinRefresh)
	want := map[string]any{
		"signin_session": signinARN, "grant_type": "refresh_token", "signin_client": "same-device",
		"signin_success": true, "signin_extended": false, "cli_version": "aws-cli/2.31.4",
	}
	for k, v := range want {
		if e.Data[k] != v {
			t.Errorf("data.%s = %#v, want %#v", k, e.Data[k], v)
		}
	}
	if !e.ReadOnly || !DefaultNotable(e) {
		t.Error("CreateOAuth2Token must be kept even though it is read-only")
	}
}

// 同じ名前でもほかのサービスの記録は残さない (signin の出し直しだけ)
func TestSigninNotableOnlyFromSignin(t *testing.T) {
	e := record.TrailEvent{Name: "CreateOAuth2Token", EventSource: "example.amazonaws.com", ReadOnly: true}
	if DefaultNotable(e) {
		t.Error("CreateOAuth2Token from another event source must not be notable")
	}
}

// 形に合わない値は入れない (ADR 0037)。grant_type・client_id の知らない値は other。success・SignInSessionExtended は "true"/"false" の文字列だけ
func TestNormalizeSigninVariants(t *testing.T) {
	body := func(params, extra string) string {
		return `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},
		  "eventSource":"signin.amazonaws.com","eventName":"CreateOAuth2Token","sourceIPAddress":"203.0.113.10","readOnly":true,
		  "requestParameters":` + params + `,"additionalEventData":` + extra + `}`
	}
	cases := []struct {
		name, body string
		want       map[string]any
		absent     []string
	}{
		{
			name: "first login (cross-device)",
			body: body(`{"client_id":"arn:aws:signin:::devtools/cross-device"}`, `{"signInSessionArn":"`+signinARN+`","grant_type":"authorization_code","success":"true","SignInSessionExtended":"true"}`),
			want: map[string]any{"signin_session": signinARN, "grant_type": "authorization_code", "signin_client": "cross-device", "signin_success": true, "signin_extended": true},
		},
		{
			name:   "unknown values",
			body:   body(`{"client_id":"arn:aws:signin:::devtools/other-device"}`, `{"signInSessionArn":"`+signinARN+`","grant_type":"client_credentials","success":"yes","SignInSessionExtended":true}`),
			want:   map[string]any{"grant_type": "other", "signin_client": "other"},
			absent: []string{"signin_success", "signin_extended"},
		},
		{
			name:   "failure",
			body:   body(`{"client_id":"arn:aws:signin:::devtools/same-device"}`, `{"grant_type":"refresh_token","success":"false"}`),
			want:   map[string]any{"signin_success": false, "grant_type": "refresh_token"},
			absent: []string{"signin_session"},
		},
		{
			name:   "non-string values",
			body:   body(`{"client_id":7}`, `{"signInSessionArn":7,"grant_type":["refresh_token"],"success":true}`),
			want:   map[string]any{"grant_type": "other", "signin_client": "other"},
			absent: []string{"signin_session", "signin_success"},
		},
		{
			name:   "nothing",
			body:   body(`null`, `null`),
			absent: []string{"signin_session", "grant_type", "signin_client", "signin_success", "signin_extended", "cli_version"},
		},
	}
	for _, bad := range []string{
		"arn:aws:signin:ap-northeast-1:123456789012:session/11111111-2222-3333-4444-55555555555",    // 35 文字
		"arn:aws:signin:ap-northeast-1:123456789012:session/11111111-2222-3333-4444-55555555555X",   // 大文字・16 進でない
		"arn:aws:signin:ap-northeast-1:12345678901:session/11111111-2222-3333-4444-555555555555",    // 11 桁
		"arn:aws:signin:ap-northeast-1:123456789012:session/11111111-2222-3333-4444-555555555555\n", // 末尾の改行
		"arn:aws:iam::123456789012:user/alice",
	} {
		cases = append(cases, struct {
			name, body string
			want       map[string]any
			absent     []string
		}{name: "bad arn " + bad, body: body(`{}`, fmt.Sprintf(`{"signInSessionArn":%q}`, bad)), absent: []string{"signin_session"}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := normalizeBody(t, tc.body)
			for k, v := range tc.want {
				if e.Data[k] != v {
					t.Errorf("data.%s = %#v, want %#v", k, e.Data[k], v)
				}
			}
			for _, k := range tc.absent {
				if v, has := e.Data[k]; has {
					t.Errorf("data.%s must not be set (got %#v)", k, v)
				}
			}
		})
	}
}

// ほかの残す記録にも、sessionContext.signInSessionArn が形に合えば signin_session を足す (1 節)。
// CreateOAuth2Token でない記録には、出し直しの値 (grant_type など) を足さない
func TestNormalizeSigninSessionOnOtherEvents(t *testing.T) {
	body := `{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/Admin/alice","accountId":"111122223333",
	  "sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::111122223333:role/Admin"},"signInSessionArn":"` + signinARN + `"}},
	  "eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy","sourceIPAddress":"203.0.113.10","readOnly":false,
	  "userAgent":"aws-cli/2.31.4","requestParameters":{"userName":"bob","grant_type":"refresh_token","client_id":"arn:aws:signin:::devtools/same-device"},
	  "additionalEventData":{"success":"true","grant_type":"refresh_token"}}`
	e := normalizeBody(t, body)
	if e.Data["signin_session"] != signinARN {
		t.Errorf("signin_session = %#v", e.Data["signin_session"])
	}
	for _, k := range []string{"grant_type", "signin_client", "signin_success", "signin_extended", "cli_version"} {
		if v, has := e.Data[k]; has {
			t.Errorf("data.%s must not be set on other events (got %#v)", k, v)
		}
	}
	// 形に合わなければ足さない
	e = normalizeBody(t, `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","sessionContext":{"signInSessionArn":"session/x"}},
	  "eventSource":"iam.amazonaws.com","eventName":"CreateUser","readOnly":false}`)
	if v, has := e.Data["signin_session"]; has {
		t.Errorf("malformed signInSessionArn must not be kept (got %#v)", v)
	}
}

// 主体の活動の集計に、主体 × ログインのセッション (principal_signin_session) を足す。残すかどうかに依らず全部の記録を数える。
// キーは主体の ARN とセッションの UUID。送信元が IP でない記録も数える
func TestCollectSigninSessionMetric(t *testing.T) {
	const other = "arn:aws:signin:ap-northeast-1:123456789012:session/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	alice := func(id, session, ip string) string {
		return fmt.Sprintf(`{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012",
		  "sessionContext":{"signInSessionArn":%q}},"eventSource":"ec2.amazonaws.com","eventName":"DescribeInstances","awsRegion":"ap-northeast-1",
		  "sourceIPAddress":%q,"readOnly":true,"eventID":%q}`, session, ip, id)
	}
	day := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	fake := &Fake{Pages: [][]types.Event{{
		ev("s1", day.Add(time.Hour), alice("s1", signinARN, "203.0.113.10")),
		ev("s2", day.Add(time.Hour), alice("s2", signinARN, "198.51.100.7")),
		ev("s3", day.Add(time.Hour), alice("s3", other, "AWS Internal")),
		ev("s4", day.Add(2*time.Hour), alice("s4", "not-a-session", "203.0.113.10")),
		ev("s5", day.Add(2*time.Hour), signinRefresh),
	}}}
	c, _, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	sink := &captured{}
	if err := c.Collect(context.Background(), collect.Window{From: day, To: day.Add(24 * time.Hour)}, sink); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, m := range sink.metrics {
		if m.Metric == record.MetricPrincipalSigninSession {
			got[m.Hour+" "+m.Key] = m.Value
		}
	}
	const a = "arn:aws:iam::123456789012:user/alice|"
	want := map[string]float64{
		"2026-11-26T01 " + a + signinUUID:                             2,
		"2026-11-26T01 " + a + "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": 1,
		"2026-11-26T02 " + a + signinUUID:                             1,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("metrics:\n got  %v\n want %v", got, want)
	}
}

// サインインの長さの変更 (ADR 0092 の 3 節): UpdateLoginProfile の maxSigninSessionDuration (秒) を、0 以上の整数のときだけ残す。
// 書いてあるのに形が違えば、変更があったことだけを残す
func TestNormalizeUpdateLoginProfileDuration(t *testing.T) {
	body := func(v string) string {
		return `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice"},"eventSource":"iam.amazonaws.com",
		  "eventName":"UpdateLoginProfile","awsRegion":"us-east-1","readOnly":false,"requestParameters":{"userName":"bob"` + v + `}}`
	}
	for _, tc := range []struct {
		name, param string
		want        any
		changed     bool
	}{
		{"seconds", `,"maxSigninSessionDuration":43200`, 43200, true},
		{"zero", `,"maxSigninSessionDuration":0`, 0, true},
		{"negative", `,"maxSigninSessionDuration":-1`, nil, true},
		{"fraction", `,"maxSigninSessionDuration":1.5`, nil, true},
		{"string", `,"maxSigninSessionDuration":"43200"`, nil, true},
		{"huge", `,"maxSigninSessionDuration":1e300`, nil, true},
		{"password only", ``, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := normalizeBody(t, body(tc.param))
			if got, has := e.Data["max_signin_session_duration"]; tc.want == nil && has || tc.want != nil && got != tc.want {
				t.Errorf("max_signin_session_duration = %#v, want %#v", got, tc.want)
			}
			if got, _ := e.Data["signin_duration_changed"].(bool); got != tc.changed {
				t.Errorf("signin_duration_changed = %v, want %v", got, tc.changed)
			}
		})
	}
}

// collector が残した出し直しの記録を、ストアに入れて読み戻しても、signin_session のチェックが同じ値で読める (ADR 0092)。
// 平常帯の無いストア (導入直後) で、lookback の中に記録の無いセッションの出し直しは、平常帯の外なので high を medium に下げて出す
func TestSigninRoundTripThroughStore(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	day := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	fake := &Fake{Pages: [][]types.Event{{ev("e-signin", day.Add(time.Hour), signinRefresh)}}}
	c, _, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: fake})
	sink := &captured{}
	w := collect.Window{From: day, To: day.Add(24 * time.Hour)}
	if err := c.Collect(ctx, w, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events: %d", len(sink.events))
	}
	if err := st.InsertEvent(ctx, sink.events[0]); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultChecks().SigninSession
	cfg.SessionLookback = "3d"
	obs, err := checks.SigninSession{Config: cfg}.Evaluate(ctx, st, w, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Severity != checks.Medium || obs[0].Key != "arn:aws:iam::123456789012:user/alice|"+signinUUID+"|new_prefix" ||
		obs[0].Data["signin_client"] != "same-device" || obs[0].Data["first_outside_lookback"] != true || obs[0].Data["baseline_short"] != true {
		t.Fatalf("observations: %+v", obs)
	}
}
