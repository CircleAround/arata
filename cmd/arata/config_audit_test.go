package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/scaffold"
)

// 監査する側のアカウント (架空)。acct (123456789012) が監査対象。
const auditAcct = "111122223333"

// auditAssume は、監査する側のアカウントが監査対象の読み取り専用ロールを引き受けた記録 (ロール側の CloudTrail の形。
// 呼び出し元はアカウント ID と principalId しか残らない)。
func (c *cli) auditAssume(id string) {
	c.fake.Add(cloudtrailtest.Event(id, c.now.Add(-10*time.Minute), cloudtrailtest.Identity{"type": "AWSAccount", "principalId": "AROAEXAMPLERUNNER:arata", "accountId": auditAcct},
		"sts.amazonaws.com", "AssumeRole", "us-east-1", "198.51.100.20", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/arata-readonly", "roleSessionName": "arata"}))
}

// findingChecks は直前の run の JSON レポートの finding のチェック名。
func (c *cli) findingChecks() []string {
	c.t.Helper()
	var rep struct {
		Findings struct {
			New []struct{ Check, Severity string }
		}
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
		c.t.Fatalf("%v\n%s", err, c.stdout)
	}
	var out []string
	for _, f := range rep.Findings.New {
		out = append(out, f.Check+":"+f.Severity)
	}
	return out
}

// TestConfigInitRequiresAuditAccount は、監査する側のアカウントを選ばない init がエラーになり、2 つの選択肢を示すことを確かめる (ADR 0045)。
func TestConfigInitRequiresAuditAccount(t *testing.T) {
	c := newCLI(t)
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{
		{"config", "init"},
		{"config", "init", "--out", "-"},
		{"config", "init", "--audit-account", ""},
		{"config", "init", "--audit-account", "self"},
		{"config", "init", "--audit-account", "1111-2222-3333"},
		{"config", "init", "--audit-account", "None"},
	} {
		if code := c.run(args...); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("%v: exit %d %v\n%s", args, code, c.codes(), c.stderr)
		}
		msg, _ := c.logLines()[0]["msg"].(string)
		for _, w := range []string{"--audit-account <12-digit AWS account ID>", "--audit-account none", "allowlist", "unknown_assume_role"} {
			if !strings.Contains(msg, w) {
				t.Errorf("%v: error lacks %q: %s", args, w, msg)
			}
		}
		if c.stdout.Len() != 0 {
			t.Errorf("%v: stdout: %s", args, c.stdout)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("%v: must not write anything: %v", args, ents)
		}
	}
	// --diff は選択を求めない (読むだけ)
	if code := c.run("config", "init", "--diff", "-c", c.cfg); code != 0 {
		t.Fatalf("--diff exit %d: %s", code, c.stderr)
	}
}

// TestConfigInitAuditAccountID は、ID を選んだ init が設定と既知リストの両方に残し、その既知リストで監査そのものの AssumeRole が
// 報告されないことを確かめる。既知リストに無ければ unknown_assume_role (high) が出る (この機能が防ぐ誤報)。
func TestConfigInitAuditAccountID(t *testing.T) {
	c := newCLI(t)
	c.now = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	cfg := filepath.Join(c.dir, "target", "arata.yaml")
	al := filepath.Join(c.dir, "target", "allowlist.yaml")
	if code := c.run("config", "init", "--audit-account", auditAcct, "--out", cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	for _, w := range []string{cfg + " を書き出しました", al + " に監査する側のアカウント " + auditAcct + " を書きました", "arata doctor -c " + cfg} {
		if !strings.Contains(c.stdout.String(), w) {
			t.Errorf("stdout lacks %q:\n%s", w, c.stdout)
		}
	}
	b, err := os.ReadFile(cfg)
	if err != nil || string(b) != string(scaffold.Generate(checks.NewRegistry(), auditAcct)) {
		t.Fatalf("config must be the template with the audit account: %v", err)
	}
	got, err := os.ReadFile(al)
	if err != nil {
		t.Fatal(err)
	}
	want := `# 既知リスト (arata config init が書き出した雛形)。人が承認したものだけを書く。arata.yaml と一緒に git 管理する。
# 主体の指定は arn (完全一致) / account (そのアカウントの全主体) / arn_pattern (glob) のどれか 1 つ。
# 書き方と承認の手順: arata help ai approve
principals:
  - account: "111122223333"
    note: 監査する側のアカウント。このアカウントの実行用ロールが、監査対象の読み取り専用ロールを引き受けて arata を動かす (arata config init --audit-account が記入)
    approved_at: 2026-11-13
`
	if string(got) != want {
		t.Fatalf("allowlist:\n%s", got)
	}
	c.cfg = cfg
	c.writeConfig(strings.Replace(string(b), "dir:///var/lib/arata/my-service", "dir://"+filepath.Join(c.dir, "store"), 1))
	if code := c.run("config", "check", "-c", cfg); code != 0 || !strings.Contains(c.stdout.String(), "audit_account "+auditAcct+" is approved in the allowlist") {
		t.Fatalf("config check exit %d:\n%s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("init", "-c", cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(time.Hour)
	c.auditAssume("a1")
	if code := c.run("run", "-c", cfg, "--profile", "hourly"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	if f := c.findingChecks(); len(f) != 0 {
		t.Fatalf("the audit's own AssumeRole must not be reported: %v", f)
	}
	// 既知リストから外すと (= 書き忘れた状態) 監査そのものが high で出る
	if err := os.WriteFile(al, []byte("principals: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(time.Hour)
	c.auditAssume("a2")
	if code := c.run("run", "-c", cfg, "--profile", "hourly"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	if f := strings.Join(c.findingChecks(), ","); f != "unknown_assume_role:high" {
		t.Fatalf("findings: %s", f)
	}
	// その食い違いを config check が PR の時点で止める
	if code := c.run("config", "check", "-c", cfg); code != 2 || !strings.Contains(c.stdout.String(), `ng    `) || !strings.Contains(c.stdout.String(), `account: "111122223333"`) {
		t.Fatalf("config check exit %d:\n%s", code, c.stdout)
	}
}

// TestConfigInitAuditAccountExistingAllowlist は、既にある既知リストには末尾に足すだけで、やり直しても重複させないことを確かめる。
func TestConfigInitAuditAccountExistingAllowlist(t *testing.T) {
	c := newCLI(t)
	cfg := filepath.Join(c.dir, "arata.yaml")
	al := filepath.Join(c.dir, "allowlist.yaml") // newCLI が Deploy ロールを書いている
	before, _ := os.ReadFile(al)
	if code := c.run("config", "init", "--audit-account", auditAcct, "--by", "alice", "--out", cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	after, _ := os.ReadFile(al)
	entry := "  - account: \"111122223333\"\n    note: " + scaffold.AuditAccountNote + "\n    approved_by: alice\n    approved_at: 2026-10-21\n"
	if string(after) != string(before)+entry {
		t.Fatalf("allowlist:\n%s", after)
	}
	if code := c.run("config", "init", "--audit-account", auditAcct, "--out", cfg, "--force"); code != 0 || !strings.Contains(c.stdout.String(), "既に書いてあります") {
		t.Fatalf("exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if again, _ := os.ReadFile(al); string(again) != string(after) {
		t.Fatalf("allowlist changed on rerun:\n%s", again)
	}
	// 壊れた既知リストは書き換えず、設定も書かない
	if err := os.WriteFile(al, []byte("principals:\n  - note: 主体が無い\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(c.dir, "arata2.yaml")
	if code := c.run("config", "init", "--audit-account", "444455556666", "--out", other); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("exit %d %v", code, c.codes())
	}
	if _, err := os.Stat(other); err == nil {
		t.Fatal("config must not be written when the allowlist cannot be updated")
	}
}

// TestConfigInitAuditAccountNone は、none が設定に残り、既知リストには何も書かないことを確かめる。
func TestConfigInitAuditAccountNone(t *testing.T) {
	c := newCLI(t)
	cfg := filepath.Join(c.dir, "target", "arata.yaml")
	if code := c.run("config", "init", "--audit-account", "none", "--out", cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "\naudit_account: none ") {
		t.Fatal("the choice must stay in the config")
	}
	if _, err := os.Stat(filepath.Join(c.dir, "target", "allowlist.yaml")); err == nil {
		t.Fatal("none must not write the allowlist")
	}
	if !strings.Contains(c.stdout.String(), "既知リストには何も書いていません") {
		t.Fatalf("stdout: %s", c.stdout)
	}
}

// TestConfigInitAuditAccountStdout は --out - のとき設定だけを標準出力に出し、既知リストに足す項目を標準エラーで知らせることを確かめる。
func TestConfigInitAuditAccountStdout(t *testing.T) {
	c := newCLI(t)
	t.Chdir(t.TempDir())
	if code := c.run("config", "init", "--audit-account", auditAcct, "--out", "-"); code != 0 || c.stdout.String() != string(scaffold.Generate(checks.NewRegistry(), auditAcct)) {
		t.Fatalf("stdout must be the template: exit %d", code)
	}
	// 打った人への案内で、運用で拾うログではない。JSON の行にせず、文で出す (ADR 0054)。標準出力 (雛形) には混ぜない
	if errOut := c.stderr.String(); !strings.Contains(errOut, `- account: "111122223333"`) || !strings.Contains(errOut, "allowlist.yaml の principals に足してください") ||
		strings.Contains(errOut, `"level"`) {
		t.Fatalf("stderr: %s", c.stderr)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Fatalf("--out - must not write files: %v", ents)
	}
}

// TestConfigCheckAuditAccount は config check が audit_account と既知リストの食い違いを見ることを確かめる。
// 決定 (ADR 0045): 選んでいない設定 (この項目より前の版) は warn (終了コード 0)。ID を書いたのに既知リストに無い・期限切れは ng。
func TestConfigCheckAuditAccount(t *testing.T) {
	c := newCLI(t)
	c.offline()
	b, _ := os.ReadFile(c.cfg)
	set := func(line string) { c.writeConfig(strings.Replace(string(b), "audit_account: none\n", line, 1)) }

	set("")
	if code := c.run("config", "check", "-c", c.cfg); code != 0 || strings.Contains(c.stderr.String(), "CONFIG_INVALID") {
		t.Fatalf("an unset audit_account must only warn: exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "warn  ") || !strings.Contains(c.stdout.String(), "audit_account is not set") || !strings.Contains(c.stdout.String(), "audit_account: none") {
		t.Fatalf("stdout:\n%s", c.stdout)
	}

	set("audit_account: \"" + auditAcct + "\"\n")
	if code := c.run("config", "check", "-c", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" || !strings.Contains(c.stdout.String(), "is not in the allowlist") {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	// arn の項目では足りない (ロール側の記録にはアカウント ID しか残らない)
	c.writeAllowlist("principals:\n  - arn: arn:aws:iam::" + auditAcct + ":role/arata-runner\n")
	if code := c.run("config", "check", "-c", c.cfg); code != 2 {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
	c.writeAllowlist("principals:\n  - account: \"" + auditAcct + "\"\n    expires: 2026-10-01\n")
	if code := c.run("config", "check", "-c", c.cfg); code != 2 || !strings.Contains(c.stdout.String(), "expired") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
	c.writeAllowlist("principals:\n  - account: \"" + auditAcct + "\"\n")
	if code := c.run("config", "check", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
	// 既知リストのファイルが無い
	if err := os.Remove(filepath.Join(c.dir, "allowlist.yaml")); err != nil {
		t.Fatal(err)
	}
	if code := c.run("config", "check", "-c", c.cfg); code != 2 || !strings.Contains(c.stdout.String(), "is not in the allowlist") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
	// 値の誤りは設定の読み込みが止める
	set("audit_account: self\n")
	if code := c.run("config", "check", "-c", c.cfg); code != 2 || !strings.Contains(c.stdout.String(), "audit_account") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
}

// TestAuditAccountUnsetStillRuns は、audit_account の無い設定 (この項目より前の版で作ったもの) で run / doctor が止まらないことを確かめる。
func TestAuditAccountUnsetStillRuns(t *testing.T) {
	c := newCLI(t)
	b, _ := os.ReadFile(c.cfg)
	c.writeConfig(strings.Replace(string(b), "audit_account: none\n", "", 1))
	if code := c.run("doctor", "-c", c.cfg); code != 0 {
		t.Fatalf("doctor exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("init", "-c", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(time.Hour)
	if code := c.run("run", "-c", c.cfg, "--profile", "hourly"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	if code := c.run("config", "init", "--diff", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "[missing_key] audit_account") {
		t.Fatalf("diff exit %d: %s", code, c.stdout)
	}
	c.assertCodesInVocabulary()
}

// TestDoctorAuditAccount は doctor が、audit_account が監査対象のアカウントそのものでないこと (account: で自アカウントの全主体を
// 承認してしまう誤り) と、既知リストとの食い違いを確かめることを確かめる。
func TestDoctorAuditAccount(t *testing.T) {
	c := newCLI(t)
	b, _ := os.ReadFile(c.cfg)
	set := func(id string) {
		c.writeConfig(strings.Replace(string(b), "audit_account: none\n", "audit_account: \""+id+"\"\n", 1))
		c.writeAllowlist("principals:\n  - account: \"" + id + "\"\n")
	}
	row := func() string {
		for _, l := range strings.Split(c.stdout.String(), "\n") {
			if strings.Contains(l, "audit_account") {
				return l
			}
		}
		return ""
	}
	set(auditAcct)
	if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(row(), "ok") || !strings.Contains(row(), auditAcct) {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	// フェイクの sts:GetCallerIdentity は 123456789012 (監査対象) を返す
	set(acct)
	if code := c.run("doctor", "-c", c.cfg); code != 2 || !strings.Contains(row(), "ng") || !strings.Contains(row(), "CONFIG_INVALID") || !strings.Contains(row(), config.AuditAccountNone) {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	// 既知リストに無い
	set(auditAcct)
	c.writeAllowlist("principals: []\n")
	if code := c.run("doctor", "-c", c.cfg); code != 2 || !strings.Contains(c.stdout.String(), "is not in the allowlist") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	c.assertCodesInVocabulary()
}
