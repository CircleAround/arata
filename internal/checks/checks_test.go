package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

const alYAML = `
principals:
  - arn: arn:aws:iam::1:role/Deploy
    tags: [deploy]
  - arn: arn:aws:iam::1:user/approved
  - arn: arn:aws:iam::1:user/expired
    expires: 2026-01-01
`

func fixture(t *testing.T) (*store.Dir, *allowlist.List, collect.Window) {
	t.Helper()
	st := newStore(t)
	al, err := allowlist.Parse([]byte(alYAML))
	if err != nil {
		t.Fatal(err)
	}
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	ctx := context.Background()
	in := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	evs := []record.TrailEvent{
		{EventID: "r1", Time: in(1), Name: "ConsoleLogin", EventSource: "signin.amazonaws.com", PrincipalARN: "arn:aws:iam::1:root", PrincipalKind: record.PrincipalRoot, IP: "203.0.113.1", Data: map[string]any{"mfa": "Yes"}},
		{EventID: "r2", Time: in(2), Name: "CreateAccessKey", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:root", PrincipalKind: record.PrincipalRoot, IP: "203.0.113.1"},
		{EventID: "r3", Time: in(30), Name: "ConsoleLogin", EventSource: "signin.amazonaws.com", PrincipalARN: "arn:aws:iam::1:root", PrincipalKind: record.PrincipalRoot, IP: "203.0.113.9"}, // 窓外
		{EventID: "a1", Time: in(3), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown", PrincipalKind: record.PrincipalUser, IP: "198.51.100.1", Data: map[string]any{"role_arn": "arn:aws:iam::1:role/Admin"}, ReadOnly: true},
		{EventID: "a2", Time: in(4), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown", PrincipalKind: record.PrincipalUser, IP: "198.51.100.2", Data: map[string]any{"role_arn": "arn:aws:iam::1:role/Admin"}, ReadOnly: true},
		{EventID: "a3", Time: in(5), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/approved", PrincipalKind: record.PrincipalUser, IP: "198.51.100.1", Data: map[string]any{"role_arn": "arn:aws:iam::1:role/Admin"}, ReadOnly: true},
		{EventID: "a4", Time: in(5), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/expired", PrincipalKind: record.PrincipalUser, IP: "198.51.100.1", Data: map[string]any{"role_arn": "arn:aws:iam::1:role/Admin"}, ReadOnly: true},
		{EventID: "a5", Time: in(5), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "ec2.amazonaws.com", PrincipalKind: record.PrincipalService, Data: map[string]any{"role_arn": "arn:aws:iam::1:role/EC2"}, ReadOnly: true},
		{EventID: "a6", Time: in(5), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalKind: record.PrincipalUnknown, IP: "198.51.100.201", Data: map[string]any{"role_arn": "arn:aws:iam::1:role/ExampleSaaSRole"}, ReadOnly: true},
		{EventID: "i1", Time: in(6), Name: "AttachUserPolicy", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown", PrincipalKind: record.PrincipalUser, IP: "198.51.100.1", Data: map[string]any{"user_name": "carol", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
		{EventID: "i2", Time: in(7), Name: "PutRolePolicy", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:role/Deploy", PrincipalKind: record.PrincipalAssumedRole, IP: "198.51.100.3", Data: map[string]any{"role_name": "AppRole", "policy_name": "inline"}},
		{EventID: "i3", Time: in(8), Name: "GetUser", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown", PrincipalKind: record.PrincipalUser, ReadOnly: true},
		{EventID: "i4", Time: in(8), Name: "DeleteUser", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown", PrincipalKind: record.PrincipalUser, Data: map[string]any{"user_name": "x"}},
	}
	for _, e := range evs {
		e.Source = "trail"
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	ps := []struct {
		arn    string
		kind   record.PrincipalKind
		ip     string
		status string
	}{
		{"arn:aws:iam::1:user/unknown", record.PrincipalUser, "198.51.100.1", store.PrincipalUnknown},
		{"arn:aws:iam::1:user/unknown", record.PrincipalUser, "198.51.100.2", store.PrincipalUnknown},
		{"arn:aws:iam::1:user/approved", record.PrincipalUser, "198.51.100.1", store.PrincipalUnknown}, // status 未同期でも allowlist で除外される
		{"arn:aws:iam::1:user/expired", record.PrincipalUser, "198.51.100.1", store.PrincipalExpired},
		{"arn:aws:iam::1:user/base", record.PrincipalUser, "198.51.100.1", store.PrincipalBaseline},
		{"arn:aws:iam::1:root", record.PrincipalRoot, "203.0.113.1", store.PrincipalUnknown}, // root は root_usage が扱う
		{"arn:aws:iam::1:role/Deploy", record.PrincipalAssumedRole, "198.51.100.3", store.PrincipalApproved},
		{"arn:aws:iam::111122223333:root", record.PrincipalUnknown, "198.51.100.201", store.PrincipalUnknown}, // SaaS の外部アカウント
	}
	for _, p := range ps {
		if err := st.UpsertPrincipalSeen(ctx, record.PrincipalSeen{Time: in(2), FirstTime: in(4), Source: "trail", ARN: p.arn, Kind: p.kind, IP: p.ip, Count: 3}, p.status); err != nil {
			t.Fatal(err)
		}
	}
	return st, al, w
}

func keys(obs []Observation) string {
	ks := make([]string, 0, len(obs))
	for _, o := range obs {
		ks = append(ks, o.Key)
	}
	return strings.Join(ks, ";")
}

func TestChecks(t *testing.T) {
	st, al, w := fixture(t)
	ctx := context.Background()
	cases := []struct {
		check    Check
		wantKeys string
		verify   func(t *testing.T, obs []Observation)
	}{
		{RootUsage{}, "arn:aws:iam::1:root|203.0.113.1", func(t *testing.T, obs []Observation) {
			o := obs[0]
			if o.Severity != Critical || o.Data["count"] != 2 || o.Data["mfa"] != "Yes" || strings.Join(o.Data["event_names"].([]string), ",") != "ConsoleLogin,CreateAccessKey" {
				t.Fatalf("%+v", o)
			}
		}},
		{UnknownAssumeRole{}, "arn:aws:iam::111122223333:root->arn:aws:iam::1:role/ExampleSaaSRole;arn:aws:iam::1:user/expired->arn:aws:iam::1:role/Admin;arn:aws:iam::1:user/unknown->arn:aws:iam::1:role/Admin", func(t *testing.T, obs []Observation) {
			if !strings.Contains(obs[0].Summary, "外部アカウント 111122223333 (呼び出した主体は記録に無い) が") || obs[0].Data["external_account"] != "111122223333" || obs[0].Data["caller_identity"] != "account_only" {
				t.Fatalf("external account: %+v", obs[0])
			}
			if _, has := obs[2].Data["caller_identity"]; has {
				t.Fatalf("IAM ユーザーの呼び出し元に caller_identity は付けない: %+v", obs[2])
			}
			if obs[1].Data["allowlist_status"] != "expired" || obs[2].Data["allowlist_status"] != "unknown" || obs[2].Data["count"] != 2 || obs[2].Severity != High {
				t.Fatalf("%+v", obs)
			}
			if ips := obs[2].Data["ips"].([]string); len(ips) != 2 {
				t.Fatalf("ips: %v", ips)
			}
		}},
		{NewPrincipal{}, "arn:aws:iam::111122223333:root;arn:aws:iam::1:user/expired;arn:aws:iam::1:user/unknown", func(t *testing.T, obs []Observation) {
			if obs[0].Summary != "新規の主体 外部アカウント 111122223333 (unknown)" || obs[0].Data["external_account"] != "111122223333" || obs[0].Data["principal_identity"] != "account_only" {
				t.Fatalf("external account: %+v", obs[0])
			}
			if _, has := obs[2].Data["principal_identity"]; has {
				t.Fatalf("IAM ユーザーに principal_identity は付けない: %+v", obs[2])
			}
			if obs[2].Severity != Medium || obs[2].Data["count"] != 6 || len(obs[2].Data["ips"].([]string)) != 2 || obs[2].Data["kind"] != "user" {
				t.Fatalf("%+v", obs[2])
			}
			if obs[1].Data["allowlist_status"] != "expired" || !strings.Contains(obs[1].Summary, "期限切れ") {
				t.Fatalf("%+v", obs[1])
			}
		}},
		{IAMChanges{}, "AttachUserPolicy|arn:aws:iam::1:user/unknown|carol;CreateAccessKey|arn:aws:iam::1:root|;PutRolePolicy|arn:aws:iam::1:role/Deploy|AppRole", func(t *testing.T, obs []Observation) {
			if obs[0].Severity != Medium || obs[0].Data["policy_arn"] != "arn:aws:iam::aws:policy/AdministratorAccess" {
				t.Fatalf("%+v", obs[0])
			}
			if obs[1].Severity != Medium || obs[1].Data["principal_kind"] != "root" {
				t.Fatalf("%+v", obs[1])
			}
			if obs[2].Severity != Info || obs[2].Data["known_deploy_principal"] != true {
				t.Fatalf("%+v", obs[2])
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.check.Name(), func(t *testing.T) {
			obs, err := tc.check.Evaluate(ctx, st, w, al)
			if err != nil {
				t.Fatal(err)
			}
			if keys(obs) != tc.wantKeys {
				t.Fatalf("keys: got %q want %q", keys(obs), tc.wantKeys)
			}
			for _, o := range obs {
				if o.Check != tc.check.Name() || o.Summary == "" || o.Fingerprint == "" {
					t.Fatalf("observation incomplete: %+v", o)
				}
				for _, part := range strings.Split(o.Fingerprint, "|") {
					if part == fmt.Sprint(o.Data["count"]) || strings.Contains(part, "T") && strings.HasSuffix(part, "Z") {
						t.Fatalf("fingerprint must not contain time or count: %q", o.Fingerprint)
					}
				}
			}
			tc.verify(t, obs)
		})
	}
}

// 拒否されたイベント (access_denied のために events に残す) が増えても、ほかのイベント型チェックの結果は変わらない。
func TestDeniedEventsDoNotAffectOtherChecks(t *testing.T) {
	st, al, w := fixture(t)
	ctx := context.Background()
	others := []Check{RootUsage{}, UnknownAssumeRole{}, IAMChanges{}}
	before := map[string]string{}
	for _, c := range others {
		obs, err := c.Evaluate(ctx, st, w, al)
		if err != nil {
			t.Fatal(err)
		}
		before[c.Name()] = fmt.Sprintf("%+v", obs)
	}
	in := now.Add(-2 * time.Hour)
	for i, api := range []string{"iam.amazonaws.com:ListUsers", "iam.amazonaws.com:GetAccountAuthorizationDetails", "s3.amazonaws.com:ListBuckets", "ec2.amazonaws.com:DescribeInstances", "secretsmanager.amazonaws.com:ListSecrets", "sts.amazonaws.com:GetCallerIdentity"} {
		src, name, _ := strings.Cut(api, ":")
		code := "AccessDenied"
		if src == "ec2.amazonaws.com" {
			code = "Client.UnauthorizedOperation"
		}
		e := record.TrailEvent{EventID: fmt.Sprintf("denied%d", i), Time: in, Source: "trail", Name: name, EventSource: src, PrincipalARN: "arn:aws:iam::1:user/unknown",
			PrincipalKind: record.PrincipalUser, IP: "198.51.100.1", ErrorCode: code, ReadOnly: true}
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range others {
		obs, err := c.Evaluate(ctx, st, w, al)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%+v", obs); got != before[c.Name()] {
			t.Fatalf("%s changed:\n before %s\n after  %s", c.Name(), before[c.Name()], got)
		}
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	if strings.Join(r.Names(), ",") != "root_usage,unknown_assume_role,oidc_assume_role,new_principal,iam_changes,access_denied,defense_evasion,public_exposure,principal_new_source,secret_access,login_bruteforce,probe_paths,endpoint_abuse,unused_region_activity,cost_anomaly,waf_block_trend,ai_path_usage,credential_hygiene,guardduty_findings,posture,access_analyzer,waf_review,log_hygiene" {
		t.Fatalf("%v", r.Names())
	}
	for _, n := range r.Names() {
		c, _ := r.Get(n)
		// アプリ層チェックも event 型。週次チェックはすべて state 型
		if (n == "new_principal" || c.Cadence() == Weekly) != (c.Mode() == ModeState) {
			t.Fatalf("%s mode %s", n, c.Mode())
		}
	}
	d := r.Defaults()
	if strings.Join(d["daily"], ",") != "access_denied,ai_path_usage,cost_anomaly,defense_evasion,endpoint_abuse,iam_changes,login_bruteforce,new_principal,principal_new_source,probe_paths,public_exposure,secret_access,unused_region_activity,waf_block_trend" || strings.Join(d["hourly"], ",") != "oidc_assume_role,root_usage,unknown_assume_role" ||
		strings.Join(d["weekly"], ",") != "access_analyzer,credential_hygiene,guardduty_findings,log_hygiene,posture,waf_review" {
		t.Fatalf("%v", d)
	}
	// 監査対象のロググループはソースの設定から渡す
	r.SetAuditLogGroups([]string{"prod-nginx-access"})
	if c, _ := r.Get("defense_evasion"); strings.Join(c.(DefenseEvasion).AuditLogGroups, ",") != "prod-nginx-access" || c.(DefenseEvasion).LogBaselineDays != 14 {
		t.Fatalf("%+v", c)
	}
	if MaxSeverity([]Severity{Low, Critical, Medium}) != Critical || MaxSeverity(nil) != "" {
		t.Fatal("MaxSeverity")
	}
}

// イベント型チェックは、再走査の区間 [ScanFrom, From) のうち今回の収集で初めて保存したもの (遅れて届いたもの) も評価する (ADR 0013)。
// 前回までに収集済みの重なり区間のイベントは前回評価済みなので数えない。
func TestEventChecksIncludeLateEvents(t *testing.T) {
	st := newStore(t)
	al, _ := allowlist.Parse([]byte(alYAML))
	ctx := context.Background()
	from := now.Add(-time.Hour)
	prev := from // 前回の収集
	assume := func(id string, at, collected time.Time, ip string) record.TrailEvent {
		return record.TrailEvent{EventID: id, Time: at, Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown",
			PrincipalKind: record.PrincipalUser, IP: ip, Data: map[string]any{"role_arn": "arn:aws:iam::1:role/Admin"}, CollectedAt: collected}
	}
	root := func(id string, at, collected time.Time) record.TrailEvent {
		return record.TrailEvent{EventID: id, Time: at, Source: "trail", Name: "ConsoleLogin", EventSource: "signin.amazonaws.com", PrincipalARN: "arn:aws:iam::1:root",
			PrincipalKind: record.PrincipalRoot, IP: "203.0.113.1", CollectedAt: collected}
	}
	iam := func(id string, at, collected time.Time) record.TrailEvent {
		return record.TrailEvent{EventID: id, Time: at, Source: "trail", Name: "AttachUserPolicy", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/unknown",
			PrincipalKind: record.PrincipalUser, Data: map[string]any{"user_name": "carol"}, CollectedAt: collected}
	}
	for _, e := range []record.TrailEvent{
		assume("seen", from.Add(-10*time.Minute), prev, "198.51.100.1"), // 前回収集済み
		assume("late", from.Add(-5*time.Minute), now, "198.51.100.2"),   // 遅れて届いた
		root("root-late", from.Add(-2*time.Minute), now),
		iam("iam-late", from.Add(-1*time.Minute), now),
	} {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	w := collect.Window{From: from, To: now, ScanFrom: from.Add(-15 * time.Minute), CollectedAt: now}
	for _, c := range []Check{UnknownAssumeRole{}, RootUsage{}, IAMChanges{}} {
		obs, err := c.Evaluate(ctx, st, w, al)
		if err != nil || len(obs) != 1 {
			t.Fatalf("%s: late event must be observed: %+v %v", c.Name(), obs, err)
		}
		if obs[0].Data["count"] != 1 {
			t.Fatalf("%s: already collected overlap events must not be counted again: %+v", c.Name(), obs[0].Data)
		}
	}
	// 再走査しない窓では従来どおり [From, To) だけ
	if obs, _ := (UnknownAssumeRole{}).Evaluate(ctx, st, collect.Window{From: from, To: now}, al); len(obs) != 0 {
		t.Fatalf("without rescan: %+v", obs)
	}
}

// AWS のサービスが root の代わりに呼んだ記録 (送信元が IP でなく、data.invoked_by にサービス名) は、見出しに「どのサービス経由か」を出す。
// 重大度と Key (`<root>|` + 空の IP) は変えない。invoked_by が形に合わない・無い (以前の版で集めた) ときは「IP の記録の無い送信元から」と書く。
func TestRootUsageInvokedByService(t *testing.T) {
	const root = "arn:aws:iam::123456789012:root"
	for _, tc := range []struct {
		name        string
		invokedBy   []any
		wantSummary string
		wantData    string
	}{
		{"サービス経由", []any{"sso.amazonaws.com", "sso.amazonaws.com", "sso.amazonaws.com"},
			"ルートアカウント " + root + " が AWS のサービス (sso.amazonaws.com) 経由で 3 件の操作", "sso.amazonaws.com"},
		{"複数のサービス", []any{"sso.amazonaws.com", "AWS Internal", nil},
			"ルートアカウント " + root + " が AWS のサービス (AWS Internal, sso.amazonaws.com) 経由で 3 件の操作", "AWS Internal,sso.amazonaws.com"},
		{"記録なし", []any{nil, nil, nil}, "ルートアカウント " + root + " が IP の記録の無い送信元から 3 件の操作", ""},
		{"形に合わない値は出さない", []any{"x) <!here> (.amazonaws.com", 7, "a\nb"}, "ルートアカウント " + root + " が IP の記録の無い送信元から 3 件の操作", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			ctx := context.Background()
			for i, v := range tc.invokedBy {
				d := map[string]any{}
				if v != nil {
					d["invoked_by"] = v
				}
				e := record.TrailEvent{EventID: fmt.Sprint("r", i), Time: now.Add(-time.Duration(i+1) * time.Minute), Source: "trail", Name: "CreateManagedApplicationInstance",
					EventSource: "sso.amazonaws.com", PrincipalARN: root, PrincipalKind: record.PrincipalRoot, Data: d}
				if err := st.InsertEvent(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			obs, err := RootUsage{}.Evaluate(ctx, st, collect.Window{From: now.Add(-time.Hour), To: now}, nil)
			if err != nil || len(obs) != 1 {
				t.Fatalf("%v %v", obs, err)
			}
			o := obs[0]
			if o.Summary != tc.wantSummary || o.Severity != Critical || o.Key != root+"|" {
				t.Fatalf("summary=%q sev=%s key=%q", o.Summary, o.Severity, o.Key)
			}
			got, _ := o.Data["invoked_by"].([]string)
			if strings.Join(got, ",") != tc.wantData || (tc.wantData == "" && o.Data["invoked_by"] != nil) {
				t.Fatalf("invoked_by: %v", o.Data["invoked_by"])
			}
			if _, ok := o.Data["ips"]; ok {
				t.Fatalf("ips: %v", o.Data["ips"])
			}
		})
	}
}

// IP からの操作の見出しは変えない (IP があるときは invoked_by を見出しに出さない)。
func TestRootUsageSummaryWithIP(t *testing.T) {
	st, al, w := fixture(t)
	obs, err := RootUsage{}.Evaluate(context.Background(), st, w, al)
	if err != nil || len(obs) != 1 {
		t.Fatalf("%v %v", obs, err)
	}
	if want := "ルートアカウント arn:aws:iam::1:root が 203.0.113.1 から 2 件の操作"; obs[0].Summary != want {
		t.Fatalf("summary: %q", obs[0].Summary)
	}
	if _, ok := obs[0].Data["invoked_by"]; ok {
		t.Fatalf("invoked_by: %v", obs[0].Data)
	}
}

// 主体がアカウントしか分からないとき (record.ExternalAccount) だけ、external_account と <field> を足す。
func TestMarkAccountOnly(t *testing.T) {
	d := map[string]any{}
	markAccountOnly(d, "principal_identity", "arn:aws:iam::111122223333:root", record.PrincipalUnknown)
	if d["external_account"] != "111122223333" || d["principal_identity"] != "account_only" {
		t.Fatalf("%+v", d)
	}
	for _, c := range []struct {
		arn  string
		kind record.PrincipalKind
	}{
		{"arn:aws:iam::123456789012:root", record.PrincipalRoot}, // 本物のルートユーザー
		{"arn:aws:iam::111122223333:role/x", record.PrincipalRole},
		{"arn:aws:iam::111122223333:root\n", record.PrincipalUnknown},
	} {
		d := map[string]any{}
		markAccountOnly(d, "principal_identity", c.arn, c.kind)
		if len(d) != 0 {
			t.Errorf("%s (%s): %+v", c.arn, c.kind, d)
		}
	}
}
