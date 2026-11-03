package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/scaffold"
)

// TestConfigInitThenRun は「はじめての手順」(config init → doctor → init → run) を雛形のまま通す。
func TestConfigInitThenRun(t *testing.T) {
	c := newCLI(t)
	if code := c.run("config", "init", "--out", "-"); code != 0 || c.stdout.String() != string(scaffold.Generate(checks.NewRegistry())) {
		t.Fatalf("stdout must be the template: exit %d", code)
	}
	cfg := filepath.Join(c.dir, "new", "config.yaml")
	if code := c.run("config", "init", "--out", cfg); code != 0 || !strings.Contains(c.stdout.String(), "arata doctor -c "+cfg) {
		t.Fatalf("exit %d: %s%s", code, c.stdout, c.stderr)
	}
	// 既存ファイルは --force が無ければ上書きしない
	if err := os.WriteFile(cfg, []byte("name: kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := c.run("config", "init", "--out", cfg); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("must refuse to overwrite: exit %d %v", code, c.codes())
	}
	if b, _ := os.ReadFile(cfg); string(b) != "name: kept\n" {
		t.Fatalf("overwritten: %s", b)
	}
	if code := c.run("config", "init", "--out", cfg, "--force"); code != 0 {
		t.Fatalf("--force exit %d", code)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 書き換えるのはストアの場所だけ
	c.cfg = cfg
	c.writeConfig(strings.Replace(string(b), "dir:///var/lib/arata/my-service", "dir://"+filepath.Join(c.dir, "store"), 1))

	if code := c.run("doctor", "-c", c.cfg); code != 0 || strings.Contains(c.stdout.String(), "CHECK_UNUSED") {
		t.Fatalf("doctor exit %d:\n%s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("init", "-c", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(time.Hour)
	c.fake.Add(cloudtrailtest.Event("r1", c.now.Add(-10*time.Minute), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
	for _, p := range []string{"hourly", "daily", "weekly"} {
		if code := c.run("run", "-c", c.cfg, "--profile", p); code != 0 {
			t.Fatalf("run %s exit %d: %s", p, code, c.stderr)
		}
		if strings.Contains(strings.Join(c.codes(), ","), "CHECK_UNUSED") {
			t.Fatalf("template must use every check: %v", c.codes())
		}
	}
	var rep struct {
		Coverage struct {
			ChecksRun     []string                 `json:"checks_run"`
			ChecksSkipped []struct{ Check string } `json:"checks_skipped"`
		}
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	// weekly: GuardDuty が無効でアナライザーも無いアカウント (フェイクの既定) なので 2 つは skip、posture が無効であることを報告する。
	// waf_review は雛形で waf-config ソースがコメントなので skip
	if strings.Join(rep.Coverage.ChecksRun, ",") != "credential_hygiene,posture" || len(rep.Coverage.ChecksSkipped) != 3 || !strings.Contains(c.stdout.String(), "GuardDuty が有効でない (ap-northeast-1)") {
		t.Fatalf("weekly coverage: %+v", rep.Coverage)
	}
	// daily は hourly のチェックも走らせる。アプリ層は cloudwatch-logs ソースが無いので skip
	if code := c.run("run", "-c", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("daily exit %d", code)
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Coverage.ChecksRun, ",") != "access_denied,ai_path_usage,defense_evasion,iam_changes,new_principal,principal_new_source,public_exposure,root_usage,secret_access,unknown_assume_role" || len(rep.Coverage.ChecksSkipped) != 4 {
		t.Fatalf("coverage: %+v", rep.Coverage)
	}
	if code := c.run("config", "init", "--diff", "-c", c.cfg); code != 0 || c.stdout.String() != "この版の雛形との差分はありません。\n" {
		t.Fatalf("diff exit %d: %s", code, c.stdout)
	}
	c.assertCodesInVocabulary()
}

func TestConfigInitDiff(t *testing.T) {
	c := newCLI(t)
	// newCLI の設定は default-daily を使い、checks: を書いていない。未知のキーと既定値と違う値を足す
	b, _ := os.ReadFile(c.cfg)
	c.writeConfig(strings.Replace(string(b), "    window: 1h\n", "    window: 1h\n    max_catchupp: 2d\n", 1) + "checks:\n  probe_paths:\n    min_count: 3\n")
	if code := c.run("config", "init", "--diff", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	compareGolden(t, "config_diff.txt", c.stdout.Bytes())
	if code := c.run("config", "init", "--diff", "-c", c.cfg, "--format", "json"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var items []struct{ Kind, Path string }
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil || len(items) != 2 {
		t.Fatalf("json: %v %s", err, c.stdout)
	}
	t.Chdir(t.TempDir()) // ./arata.yaml も無い
	if code := c.run("config", "init", "--diff"); code != 2 {
		t.Fatalf("--diff without -c must fail: %d", code)
	}
}

func TestProfilesCmd(t *testing.T) {
	c := newCLI(t)
	b, _ := os.ReadFile(c.cfg)
	body := strings.Replace(string(b), "    checks: [default-daily, root_usage, unknown_assume_role]\n",
		"    checks: [default-daily, root_usage, unknown_assume_role]\n    overrides:\n      login_bruteforce: { factor: 5 }\n", 1)
	c.writeConfig(body + "checks:\n  login_bruteforce:\n    min_count: 30\n")
	if code := c.run("profiles", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	compareGolden(t, "profiles.txt", c.stdout.Bytes())
	if code := c.run("profiles", "-c", c.cfg, "--format", "json"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var v struct {
		Profiles []struct {
			Name   string
			Checks []struct{ Name, Via string }
			Params []struct {
				Check, Key, Origin string
				Value              any
			}
		}
		Unused []string `json:"unused_checks"`
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	origins := map[string]string{}
	for _, p := range v.Profiles[0].Params {
		origins[p.Check+"."+p.Key] = p.Origin
	}
	if v.Profiles[0].Name != "daily" || origins["login_bruteforce.factor"] != "overrides" || origins["login_bruteforce.min_count"] != "checks" || origins["login_bruteforce.baseline_days"] != "default" {
		t.Fatalf("origins: %v", origins)
	}
	if v.Profiles[1].Name != "hourly" || len(v.Profiles[1].Params) != 0 || len(v.Unused) != 0 || v.Profiles[2].Name != "weekly" || len(v.Profiles[2].Params) != 2+17 {
		t.Fatalf("hourly: %+v", v)
	}
}

// TestDoctorAccountSources は読み取りロールに無い権限があれば doctor が action を ng で示し、必要な action を列挙することを確かめる。
func TestDoctorAccountSources(t *testing.T) {
	c := newCLI(t)
	if code := c.run("config", "init", "--out", c.cfg, "--force"); code != 0 {
		t.Fatal(code)
	}
	b, _ := os.ReadFile(c.cfg)
	c.writeConfig(strings.Replace(string(b), "dir:///var/lib/arata/my-service", "dir://"+filepath.Join(c.dir, "store"), 1))
	c.acct.Errs = map[string]error{account.ActionGetPublicAccessBlock: accounttest.Denied, account.ActionListAnalyzers: accounttest.Denied}
	c.acct.ReportMissing = true // レポートがまだ無いのは権限の問題ではない
	if code := c.run("doctor", "-c", c.cfg); code != 2 {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
	compareGolden(t, "doctor_account.txt", c.stdout.Bytes())
	if c.acct.Called(account.ActionGenerateCredentialReport) != 0 {
		t.Fatal("doctor must not generate a credential report")
	}
	c.assertCodesInVocabulary()
}
