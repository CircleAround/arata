package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `
principals:
  - arn: arn:aws:iam::123456789012:role/switch_role
    note: 社員の switch role
    approved_by: ops
    approved_at: 2026-10-21
    tags: [deploy]
  - arn: arn:aws:iam::123456789012:user/contractor-x
    approved_at: 2026-10-21
    expires: 2026-12-31
source_ips:
  - cidr: 203.0.113.0/24
    note: 本社
  - cidr: 198.51.100.7/32
admin_users: [113, 2048]
secrets_access:
  - principal: arn:aws:iam::123456789012:role/App
    secrets: ["prod/db/*"]
`

func load(t *testing.T, body string) *List {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	l, err := Load(filepath.Join(t.TempDir(), "none.yaml"))
	if err != nil || l == nil || len(l.Principals) != 0 {
		t.Fatalf("missing file should yield empty list: %v %v", l, err)
	}
	if _, st := l.Principal("arn:aws:iam::1:root", time.Now()); st != StatusUnknown {
		t.Fatalf("empty list: %v", st)
	}
}

func TestPrincipalLookup(t *testing.T) {
	l := load(t, sample)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		arn  string
		at   time.Time
		want Status
		tag  bool
	}{
		{"approved without expiry", "arn:aws:iam::123456789012:role/switch_role", now, StatusApproved, true},
		{"approved before expiry", "arn:aws:iam::123456789012:user/contractor-x", now, StatusApproved, false},
		{"on expiry day still approved", "arn:aws:iam::123456789012:user/contractor-x", time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC), StatusApproved, false},
		{"after expiry", "arn:aws:iam::123456789012:user/contractor-x", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), StatusExpired, false},
		{"unknown", "arn:aws:iam::123456789012:user/nobody", now, StatusUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, st := l.Principal(tc.arn, tc.at)
			if st != tc.want {
				t.Fatalf("got %v want %v", st, tc.want)
			}
			if st != StatusUnknown && e == nil {
				t.Fatal("entry should be returned")
			}
			if got := e.HasTag("deploy"); got != tc.tag {
				t.Fatalf("tag deploy: got %v want %v", got, tc.tag)
			}
		})
	}
}

func TestSourceIP(t *testing.T) {
	l := load(t, sample)
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.77", true},
		{"203.0.114.1", false},
		{"198.51.100.7", true},
		{"198.51.100.8", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := l.SourceIPAllowed(tc.ip); got != tc.want {
			t.Errorf("%q: got %v want %v", tc.ip, got, tc.want)
		}
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"bad cidr", "source_ips:\n  - cidr: 203.0.113.0/99\n"},
		{"bad expires", "principals:\n  - arn: arn:aws:iam::1:user/x\n    expires: 2026-13-40\n"},
		{"missing arn", "principals:\n  - note: x\n"},
		{"arn and account", "principals:\n  - arn: arn:aws:iam::1:user/x\n    account: \"123456789012\"\n"},
		{"short account", "principals:\n  - account: \"1234\"\n"},
		{"pattern not arn", "principals:\n  - arn_pattern: \"role/*\"\n"},
		{"unknown field", "principals:\n  - arn: arn:aws:iam::1:user/x\n    nope: 1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "allowlist.yaml")
			_ = os.WriteFile(p, []byte(tc.body), 0o600)
			if _, err := Load(p); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	l := load(t, sample)
	if len(l.AdminUsers) != 2 || len(l.SecretsAccess) != 1 || l.SecretsAccess[0].Secrets[0] != "prod/db/*" {
		t.Fatalf("other sections: %+v", l)
	}
}

func TestAccountAndPattern(t *testing.T) {
	l := load(t, `
principals:
  - account: "111122223333"
    note: SaaS の監視連携
  - arn_pattern: arn:aws:iam::123456789012:role/github-actions-*
    tags: [deploy]
  - arn: arn:aws:iam::123456789012:role/github-actions-old
    expires: 2026-01-01
  - account: "999999999999"
    expires: 2026-01-01
`)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		arn     string
		want    Status
		subject string
	}{
		{"arn:aws:iam::111122223333:root", StatusApproved, "account:111122223333"},
		{"arn:aws:iam::111122223333:role/ExampleSaaSRole", StatusApproved, "account:111122223333"},
		{"arn:aws:iam::123456789012:role/github-actions-deploy", StatusApproved, "arn:aws:iam::123456789012:role/github-actions-*"},
		{"arn:aws:iam::123456789012:role/github-actions-x/nested", StatusApproved, "arn:aws:iam::123456789012:role/github-actions-*"},
		// 具体的な arn は期限切れだが、パターンの承認が有効なので approved
		{"arn:aws:iam::123456789012:role/github-actions-old", StatusApproved, "arn:aws:iam::123456789012:role/github-actions-*"},
		{"arn:aws:iam::123456789012:role/other", StatusUnknown, ""},
		{"arn:aws:iam::999999999999:root", StatusExpired, "account:999999999999"},
		{"not-an-arn", StatusUnknown, ""},
	}
	for _, tc := range cases {
		e, st := l.Principal(tc.arn, now)
		if st != tc.want {
			t.Errorf("%s: got %v want %v", tc.arn, st, tc.want)
			continue
		}
		if tc.subject != "" && e.Subject() != tc.subject {
			t.Errorf("%s: subject %q want %q", tc.arn, e.Subject(), tc.subject)
		}
	}
	if AccountOf("arn:aws:sts::123456789012:assumed-role/r/s") != "123456789012" || AccountOf("x") != "" {
		t.Fatal("AccountOf")
	}
}

// TestExampleAllowlist は examples/allowlist.yaml が読めることを保証する。
func TestExampleAllowlist(t *testing.T) {
	l, err := Load("../../examples/allowlist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, st := l.Principal("arn:aws:iam::111122223333:root", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)); st != StatusApproved {
		t.Fatalf("account entry: %v", st)
	}
	if !l.DeniedExpected("arn:aws:iam::123456789012:role/ai-investigation-readonly", "logs:StartQuery", time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("expected_denied example")
	}
}

func TestExpectedDenied(t *testing.T) {
	const ai = "arn:aws:iam::123456789012:role/ai-investigation-readonly"
	l := load(t, `
principals:
  - arn: arn:aws:iam::123456789012:role/ai-investigation-readonly
    tags: [ai]
    note: 個人情報を含むロググループは IAM で Deny している
    expected_denied: ["logs:StartQuery", "logs:Get*"]
  - arn_pattern: arn:aws:iam::123456789012:role/ai-*
    note: AI 用ロール共通
    expected_denied: ["secretsmanager:*"]
  - arn: arn:aws:iam::123456789012:role/legacy-batch
    note: 移行中の旧ロール
    expires: 2026-10-31
    expected_denied: ["s3:*"]
  - arn: arn:aws:iam::123456789012:role/no-denied
    note: 主体の承認だけ
`)
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		arn, api string
		want     bool
	}{
		{ai, "logs:StartQuery", true},
		{ai, "logs:GetLogEvents", true},             // glob
		{ai, "logs:FilterLogEvents", false},         // 書いていない
		{ai, "secretsmanager:GetSecretValue", true}, // arn_pattern の項目との和
		{ai, "logs:startquery", false},              // 大文字小文字は区別する
		{"arn:aws:iam::123456789012:role/ai-other", "logs:StartQuery", false},
		{"arn:aws:iam::123456789012:role/ai-other", "secretsmanager:ListSecrets", true},
		{"arn:aws:iam::123456789012:role/legacy-batch", "s3:GetObject", false}, // 期限切れは除かない
		{"arn:aws:iam::123456789012:role/no-denied", "s3:GetObject", false},
		{"arn:aws:iam::123456789012:role/unknown", "logs:StartQuery", false},
	}
	for _, tc := range cases {
		if got := l.DeniedExpected(tc.arn, tc.api, at); got != tc.want {
			t.Errorf("DeniedExpected(%s, %s) = %v, want %v", tc.arn, tc.api, got, tc.want)
		}
	}
	// 期限内なら除く
	if !l.DeniedExpected("arn:aws:iam::123456789012:role/legacy-batch", "s3:GetObject", time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)) {
		t.Error("legacy-batch before expires should be expected")
	}
	if !l.HasExpectedDenied() {
		t.Error("HasExpectedDenied")
	}
	if load(t, sample).HasExpectedDenied() {
		t.Error("sample has no expected_denied")
	}
}

func TestExpectedDeniedValidation(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"no colon", "principals:\n  - arn: arn:aws:iam::1:user/x\n    note: x\n    expected_denied: [\"StartQuery\"]\n", `principals[0]: expected_denied[0] "StartQuery": want service:Action`},
		{"empty glob", "principals:\n  - arn: arn:aws:iam::1:user/x\n    note: x\n    expected_denied: [\"logs:StartQuery\", \"\"]\n", `principals[0]: expected_denied[1] "": want service:Action`},
		{"empty action", "principals:\n  - arn: arn:aws:iam::1:user/x\n    note: x\n    expected_denied: [\"logs:\"]\n", `expected_denied[0] "logs:"`},
		{"space", "principals:\n  - arn: arn:aws:iam::1:user/x\n    note: x\n    expected_denied: [\"logs: StartQuery\"]\n", `expected_denied[0] "logs: StartQuery"`},
		{"empty list", "principals:\n  - arn: arn:aws:iam::1:user/x\n    note: x\n    expected_denied: []\n", `principals[0]: expected_denied is empty`},
		{"no note", "principals:\n  - arn: arn:aws:iam::1:user/x\n    expected_denied: [\"logs:StartQuery\"]\n", `principals[0]: note is required with expected_denied`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// dynamic_source (送信元が毎回変わる主体。principal_new_source の low を出さない) と secrets_access (主体 × 秘匿値。ADR 0027)。
func TestDynamicSourceAndSecretsAccess(t *testing.T) {
	l := load(t, `
principals:
  - arn_pattern: arn:aws:iam::123456789012:role/github-actions-*
    tags: [deploy]
    dynamic_source: true
  - arn: arn:aws:iam::123456789012:user/alice
secrets_access:
  - principal: arn:aws:iam::123456789012:role/App
    secrets: ["prod/db/*", "/example/prod/*"]
`)
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if e, st := l.Principal("arn:aws:iam::123456789012:role/github-actions-deploy", at); st != StatusApproved || !e.DynamicSource {
		t.Fatalf("dynamic_source: %+v %v", e, st)
	}
	if e, _ := l.Principal("arn:aws:iam::123456789012:user/alice", at); e.DynamicSource {
		t.Fatal("dynamic_source must default to false")
	}
	const app = "arn:aws:iam::123456789012:role/App"
	for _, tc := range []struct {
		arn, secret string
		want        bool
	}{
		{app, "prod/db/main", true},
		{app, "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:prod/db/main-AbCdEf", true}, // ARN はシークレット名の部分でも比べる
		{app, "/example/prod/token", true},
		{app, "prod/api", false},
		{"arn:aws:iam::123456789012:role/Other", "prod/db/main", false},
	} {
		if got := l.SecretExpected(tc.arn, tc.secret); got != tc.want {
			t.Errorf("SecretExpected(%s, %s) = %v", tc.arn, tc.secret, got)
		}
	}
	for _, body := range []string{
		"secrets_access:\n  - principal: arn:aws:iam::123456789012:role/App\n    secrets: []\n",
		"secrets_access:\n  - secrets: [\"prod/*\"]\n",
		"secrets_access:\n  - principal: arn:aws:iam::123456789012:role/App\n    secrets: [\"\"]\n",
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("expected error for %q", body)
		}
	}
}
