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

// ADR 0056: 既知デプロイ主体でも、アクセスキーの作成と、信頼ポリシーを外へ広げる変更は下げない。CreateRole も信頼ポリシーを読んで報告する。
func TestIAMChangesDeployNotLowered(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const deploy = "arn:aws:iam::123456789012:role/gha-deploy"
	const other = "arn:aws:iam::123456789012:user/bob"
	n := 0
	ev := func(principal, name, code string, data map[string]any) {
		n++
		if data == nil {
			data = map[string]any{}
		}
		data["recipient_account"] = "123456789012"
		e := record.TrailEvent{EventID: "t" + strings.Repeat("x", n), Time: now.Add(-time.Duration(n) * time.Minute), Name: name, EventSource: "iam.amazonaws.com", Source: "trail",
			PrincipalARN: principal, PrincipalKind: record.PrincipalAssumedRole, IP: "198.51.100.1", ErrorCode: code, Data: data}
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	trust := func(role string, kv ...any) map[string]any {
		d := map[string]any{"role_name": role, "trust_policy": "ok"}
		for i := 0; i < len(kv); i += 2 {
			d[kv[i].(string)] = kv[i+1]
		}
		return d
	}
	// デプロイ主体
	ev(deploy, "PutRolePolicy", "", map[string]any{"role_name": "app"})
	ev(deploy, "CreateAccessKey", "", map[string]any{"user_name": "ci"})
	ev(deploy, "UpdateAssumeRolePolicy", "", trust("own", "trust_accounts", []any{"123456789012"}))
	ev(deploy, "UpdateAssumeRolePolicy", "", trust("ext", "trust_accounts", []any{"123456789012", "111122223333"}, "trust_has_condition", true))
	ev(deploy, "UpdateAssumeRolePolicy", "", trust("fed", "trust_federated", []any{"cognito-identity.amazonaws.com"}))
	ev(deploy, "UpdateAssumeRolePolicy", "", trust("star", "trust_wildcard", true, "trust_has_condition", true))
	ev(deploy, "UpdateAssumeRolePolicy", "", map[string]any{"role_name": "bad", "trust_policy": "unreadable"})
	ev(deploy, "UpdateAssumeRolePolicy", "", map[string]any{"role_name": "old"}) // 以前の版で集めた記録 (trust_policy が無い)
	// 同じ Key に、自アカウントだけの変更と * の変更が混ざる → 重い方
	ev(deploy, "UpdateAssumeRolePolicy", "", trust("mixed", "trust_accounts", []any{"123456789012"}))
	ev(deploy, "UpdateAssumeRolePolicy", "", trust("mixed", "trust_wildcard", true))
	ev(deploy, "CreateRole", "", trust("new-own"))
	ev(deploy, "CreateRole", "", trust("new-star", "trust_wildcard", true))
	ev(deploy, "CreateRole", "AccessDenied", map[string]any{"trust_policy": "unreadable"})
	// デプロイ主体でない主体
	ev(other, "CreateRole", "", trust("r1"))
	ev(other, "CreateRole", "", trust("r2", "trust_wildcard", true))
	ev(other, "UpdateAssumeRolePolicy", "", trust("r3", "trust_accounts", []any{"111122223333"}))

	al, err := allowlist.Parse([]byte("principals:\n  - arn: " + deploy + "\n    tags: [deploy]\n  - account: \"111122223333\"\n    note: 既知の SaaS\n"))
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
	for _, tc := range []struct {
		key        string
		sev        Severity
		notLowered []string
		summary    string
		data       map[string]any
	}{
		{"PutRolePolicy|" + deploy + "|app", Info, nil, "", nil},
		{"CreateAccessKey|" + deploy + "|ci", Medium, []string{"access_key"}, "", nil},
		{"UpdateAssumeRolePolicy|" + deploy + "|own", Info, nil, "", map[string]any{"trust_policy": "ok"}},
		// 外のアカウントが principals の account: で承認済みでも下げない
		{"UpdateAssumeRolePolicy|" + deploy + "|ext", Medium, []string{"trust_external"}, "信頼ポリシーに外のアカウント 111122223333",
			map[string]any{"trust_external_accounts": []string{"111122223333"}, "trust_has_condition": true}},
		{"UpdateAssumeRolePolicy|" + deploy + "|fed", Medium, []string{"trust_external"}, "信頼ポリシーに外の ID プロバイダ cognito-identity.amazonaws.com",
			map[string]any{"trust_external_federated": []string{"cognito-identity.amazonaws.com"}}},
		{"UpdateAssumeRolePolicy|" + deploy + "|star", High, []string{"trust_wildcard"}, "信頼ポリシーが誰でも (*) を許す (Condition あり。絞っているかは判定していない)",
			map[string]any{"trust_wildcard": true, "trust_has_condition": true}},
		{"UpdateAssumeRolePolicy|" + deploy + "|bad", Medium, []string{"trust_unreadable"}, "信頼ポリシーを読めない", map[string]any{"trust_policy": "unreadable"}},
		{"UpdateAssumeRolePolicy|" + deploy + "|old", Medium, []string{"trust_unreadable"}, "信頼ポリシーを読めない", map[string]any{"trust_policy": "unreadable"}},
		{"UpdateAssumeRolePolicy|" + deploy + "|mixed", High, []string{"trust_wildcard"}, "誰でも (*)", nil},
		{"CreateRole|" + deploy + "|new-own", Info, nil, "", nil},
		{"CreateRole|" + deploy + "|new-star", High, []string{"trust_wildcard"}, "誰でも (*)", nil},
		{"CreateRole|" + deploy + "|", Medium, []string{"trust_unreadable"}, "IAM 変更の試行 (拒否)", map[string]any{"denied": true}},
		{"CreateRole|" + other + "|r1", Medium, nil, "", nil},
		{"CreateRole|" + other + "|r2", High, nil, "誰でも (*)", nil},
		{"UpdateAssumeRolePolicy|" + other + "|r3", Medium, nil, "外のアカウント 111122223333", nil},
	} {
		o, ok := by[tc.key]
		if !ok {
			t.Fatalf("%s: 無い (%d 件)", tc.key, len(obs))
		}
		if o.Severity != tc.sev {
			t.Errorf("%s: severity %s, want %s", tc.key, o.Severity, tc.sev)
		}
		var nl []string
		if v, ok := o.Data["not_lowered"].([]string); ok {
			nl = v
		}
		if !reflect.DeepEqual(nl, tc.notLowered) {
			t.Errorf("%s: not_lowered %v, want %v", tc.key, nl, tc.notLowered)
		}
		if !strings.Contains(o.Summary, tc.summary) {
			t.Errorf("%s: summary %q", tc.key, o.Summary)
		}
		for k, v := range tc.data {
			if !reflect.DeepEqual(o.Data[k], v) {
				t.Errorf("%s: data.%s = %v, want %v", tc.key, k, o.Data[k], v)
			}
		}
		if strings.HasPrefix(tc.key, "CreateAccessKey|"+deploy) || strings.Contains(tc.key, deploy) {
			if o.Data["known_deploy_principal"] != true {
				t.Errorf("%s: known_deploy_principal が無い", tc.key)
			}
		}
	}
	if len(obs) != 15 {
		t.Errorf("%d 件", len(obs))
	}
	// 下げた変更に理由は付かない
	if _, has := by["UpdateAssumeRolePolicy|"+deploy+"|own"].Data["not_lowered"]; has {
		t.Error("下げた変更に not_lowered")
	}
}
