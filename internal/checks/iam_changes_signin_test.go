package checks

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// ADR 0092 の 3 節: サインインの長さの変更 (UpdateLoginProfile の maxSigninSessionDuration) は medium。既知のデプロイの主体でも下げない。
// data に max_signin_session_duration (秒)。パスワードだけの変更 (maxSigninSessionDuration の無い UpdateLoginProfile) は今までどおり報告しない
func TestIAMChangesSigninDuration(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const deploy = "arn:aws:iam::123456789012:role/gha-deploy"
	const other = "arn:aws:iam::123456789012:user/bob"
	n := 0
	ev := func(principal, code string, data map[string]any) {
		n++
		e := record.TrailEvent{EventID: "s" + strings.Repeat("x", n), Time: now.Add(-time.Duration(n) * time.Minute), Name: "UpdateLoginProfile", EventSource: "iam.amazonaws.com",
			Source: "trail", PrincipalARN: principal, PrincipalKind: record.PrincipalAssumedRole, IP: "198.51.100.1", ErrorCode: code, Data: data}
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	ev(deploy, "", map[string]any{"user_name": "alice", "signin_duration_changed": true, "max_signin_session_duration": 43200})
	ev(other, "", map[string]any{"user_name": "carol", "signin_duration_changed": true}) // 値の形が違った
	ev(other, "", map[string]any{"user_name": "dave"})                                    // パスワードだけ
	// 同じ Key の 2 回: 新しい方 (先に入れたもの。時刻が新しい) の値を出す
	ev(other, "", map[string]any{"user_name": "erin", "signin_duration_changed": true, "max_signin_session_duration": 3600})
	ev(other, "", map[string]any{"user_name": "erin", "signin_duration_changed": true, "max_signin_session_duration": 86400})

	al, err := allowlist.Parse([]byte("principals:\n  - arn: " + deploy + "\n    tags: [deploy]\n"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := IAMChanges{}.Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, al)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Observation{}
	for _, o := range obs {
		by[o.Key] = o
	}
	if _, ok := by["UpdateLoginProfile|"+other+"|dave"]; ok {
		t.Error("a password-only change must not be reported")
	}
	for _, tc := range []struct {
		key        string
		duration   any
		notLowered []string
	}{
		{"UpdateLoginProfile|" + deploy + "|alice", 43200, []string{notLoweredSigninDuration}},
		{"UpdateLoginProfile|" + other + "|carol", nil, nil},
		{"UpdateLoginProfile|" + other + "|erin", 3600, nil},
	} {
		o, ok := by[tc.key]
		if !ok {
			t.Errorf("%s: not reported (got %v)", tc.key, keysOf(by))
			continue
		}
		if o.Severity != Medium {
			t.Errorf("%s: severity %s, want medium", tc.key, o.Severity)
		}
		if got := o.Data["max_signin_session_duration"]; got != tc.duration {
			t.Errorf("%s: max_signin_session_duration = %#v, want %#v", tc.key, got, tc.duration)
		}
		if got, _ := o.Data["not_lowered"].([]string); !reflect.DeepEqual(got, tc.notLowered) {
			t.Errorf("%s: not_lowered = %v, want %v", tc.key, got, tc.notLowered)
		}
		if !strings.Contains(o.Summary, "サインインの長さ") {
			t.Errorf("%s: summary %q", tc.key, o.Summary)
		}
	}
}
