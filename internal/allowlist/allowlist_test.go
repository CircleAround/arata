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

// arn_pattern はアカウントを固定する。広いパターンは主体の承認を丸ごと止めてしまう。
func TestArnPatternMustFixTheAccount(t *testing.T) {
	for _, p := range []string{"arn:*", "arn:aws:iam::*:role/x", "arn:aws:*:*:*:*", "arn:aws:iam::12345*:role/x", "arn:aws:iam::123456789012"} {
		if _, err := Parse([]byte("principals:\n  - arn_pattern: \"" + p + "\"\n")); err == nil {
			t.Errorf("%s を通した", p)
		}
	}
	for _, p := range []string{"arn:aws:iam::123456789012:role/ci-*", "arn:aws:sts::123456789012:assumed-role/x/*"} {
		if _, err := Parse([]byte("principals:\n  - arn_pattern: \"" + p + "\"\n")); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// TestAccount は account: の項目だけでアカウントの承認を引くことを確かめる (config check / doctor の audit_account の突き合わせ)。
func TestAccount(t *testing.T) {
	l, err := Parse([]byte(`principals:
  - account: "111122223333"
    expires: 2026-10-31
  - arn: arn:aws:iam::444455556666:root
  - arn_pattern: arn:aws:iam::111111111111:*
  - account: "999999999999"
    expires: 2026-10-01
  - account: "999999999999"
`))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for id, want := range map[string]Status{
		"111122223333": StatusApproved,
		"999999999999": StatusApproved, // 期限内の項目が 1 つでもあれば承認
		"444455556666": StatusUnknown,  // arn / arn_pattern の項目はアカウントの承認ではない
		"111111111111": StatusUnknown,
		"123456789012": StatusUnknown,
		"":             StatusUnknown,
	} {
		if got := l.Account(id, at); got != want {
			t.Errorf("Account(%q) = %s, want %s", id, got, want)
		}
	}
	if got := l.Account("111122223333", at.AddDate(0, 1, 0)); got != StatusExpired {
		t.Errorf("after expires: %s", got)
	}
}

// bulk: exempt (ADR 0073): 一致する秘匿値を secret_access の一括読み出しの数から外す、明示の opt-in。
// 外す範囲が広いと持ち出しが見えなくなるので、ロールでない主体・広い glob・ARN の形・note の無い項目は読み込みエラー。
func TestSecretsAccessBulkExempt(t *testing.T) {
	const app = "arn:aws:iam::123456789012:role/example-app-task-execution"
	l := load(t, `
secrets_access:
  - principal: `+app+`
    secrets: ["/example-app/prod/secrets/*", "prod/example-app/db"]
    bulk: exempt
    note: タスクの起動のたびに ECS がタスク定義の secrets を読む
  - principal: `+app+`
    secrets: ["prod/other/*"]
`)
	for _, tc := range []struct {
		arn, secret, pattern string
		ok                   bool
	}{
		{app, "/example-app/prod/secrets/DB_PASSWORD", "/example-app/prod/secrets/*", true},
		{app, "prod/example-app/db", "prod/example-app/db", true},
		{app, "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:prod/example-app/db", "prod/example-app/db", true},
		// bulk の無い項目は外さない (初出を止めるだけ)
		{app, "prod/other/x", "", false},
		{app, "/example-app/stg/secrets/X", "", false},
		{"arn:aws:iam::123456789012:role/other", "/example-app/prod/secrets/DB_PASSWORD", "", false},
	} {
		p, ok := l.SecretBulkExempt(tc.arn, tc.secret)
		if ok != tc.ok || p != tc.pattern {
			t.Errorf("SecretBulkExempt(%s, %s) = %q, %v", tc.arn, tc.secret, p, ok)
		}
	}
	// bulk の有無によらず、secrets_access の項目は初出を止める
	if !l.SecretExpected(app, "/example-app/prod/secrets/DB_PASSWORD") || !l.SecretExpected(app, "prod/other/x") {
		t.Fatal("SecretExpected")
	}
	if !l.HasBulkExempt() || (&List{}).HasBulkExempt() {
		t.Fatal("HasBulkExempt")
	}

	entry := func(principal, secret, bulk, note string) string {
		s := "secrets_access:\n  - principal: " + principal + "\n    secrets: [\"" + secret + "\"]\n"
		if bulk != "" {
			s += "    bulk: " + bulk + "\n"
		}
		if note != "" {
			s += "    note: " + note + "\n"
		}
		return s
	}
	for _, tc := range []struct{ name, body string }{
		{"未知の値", entry(app, "/example-app/prod/*", "count_as_one", "n")},
		{"真偽", entry(app, "/example-app/prod/*", "true", "n")},
		{"note が無い", entry(app, "/example-app/prod/*", "exempt", "")},
		{"ロールでない", entry("arn:aws:iam::123456789012:user/alice", "/example-app/prod/*", "exempt", "n")},
		{"主体が ARN でない", entry("example-app", "/example-app/prod/*", "exempt", "n")},
		{"*", entry(app, "*", "exempt", "n")},
		{"/*", entry(app, "/*", "exempt", "n")},
		{"区切り 1 つ", entry(app, "prod/*", "exempt", "n")},
		{"区切り 1 つ (先頭の /)", entry(app, "/example-app/*", "exempt", "n")},
		{"途中で切れた区切り", entry(app, "/example-app/prod*", "exempt", "n")},
		{"?", entry(app, "/example-app/?/x", "exempt", "n")},
		{"空の区切り", entry(app, "//example-app/*", "exempt", "n")},
		{"ARN", entry(app, "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:prod/example-app/*", "exempt", "n")},
	} {
		if _, err := Parse([]byte(tc.body)); err == nil {
			t.Errorf("%s: 読み込みエラーにならない: %q", tc.name, tc.body)
		}
	}
	for _, body := range []string{
		entry(app, "/example-app/prod/*", "exempt", "n"),
		entry(app, "prod/example-app/*", "exempt", "n"),
		entry(app, "/example-app/prod/secrets/DB_PASSWORD", "exempt", "n"),
		entry(app, "example-app-db", "exempt", "n"),                     // ワイルドカードの無い名前は 1 つだけに当たる
		entry("arn:aws:iam::123456789012:user/alice", "prod/*", "", ""), // bulk の無い項目は今までどおり
		entry(app, "*", "", "note は bulk が無くても書ける"),
	} {
		if _, err := Parse([]byte(body)); err != nil {
			t.Errorf("%q: %v", body, err)
		}
	}
}
