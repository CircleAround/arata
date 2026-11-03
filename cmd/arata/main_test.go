package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/engine"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

const acct = "123456789012"

// cli はテスト用の CLI ハーネス。Execute を直接呼び、出力をバッファに取る。
type cli struct {
	t      *testing.T
	dir    string
	cfg    string
	fake   *cloudtrailtest.Fake
	logs   *cwlogstest.Fake
	acct   *accounttest.Fake
	now    time.Time
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	nextID int
	env    map[string]string // Getenv が返す環境変数 (テストを動かす環境の ARATA_CONFIG を見ない)
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	dir := t.TempDir()
	c := &cli{t: t, dir: dir, cfg: filepath.Join(dir, "config.yaml"), fake: &cloudtrailtest.Fake{}, logs: &cwlogstest.Fake{}, acct: &accounttest.Fake{}, now: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, env: map[string]string{}}
	c.writeConfig(fmt.Sprintf(`
name: acme
store: dir://%s/store
aws:
  region: ap-northeast-1
sources:
  - id: trail
    kind: cloudtrail-lookup
profiles:
  hourly:
    window: 1h
    checks: [root_usage, unknown_assume_role]
  daily:
    window: 24h
    checks: [default-daily, root_usage, unknown_assume_role]
  weekly:
    window: 7d
    checks: [default-weekly]
`, dir))
	if err := os.WriteFile(filepath.Join(dir, "allowlist.yaml"), []byte("principals:\n  - arn: arn:aws:iam::"+acct+":role/Deploy\n    note: GitHub Actions のデプロイロール\n    tags: [deploy]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *cli) writeConfig(body string) {
	if err := os.WriteFile(c.cfg, []byte(body), 0o600); err != nil {
		c.t.Fatal(err)
	}
}

func (c *cli) run(args ...string) int {
	c.stdout.Reset()
	c.stderr.Reset()
	d := Deps{Stdout: c.stdout, Stderr: c.stderr, Getenv: func(k string) string { return c.env[k] }}
	d.Engine = engine.Deps{
		Limiter: noLimit{},
		Now:     func() time.Time { return c.now },
		NewID:   func() string { c.nextID++; return fmt.Sprintf("id-%03d", c.nextID) },
		CloudTrail: func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cloudtrail.API, error) {
			return c.fake, nil
		},
		CloudWatchLogs: func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cwlogs.API, error) {
			return c.logs, nil
		},
		Account: func(ctx context.Context, cfg *config.Config, src config.Source, region string) (account.Clients, error) {
			return c.acct.Clients(region), nil
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	return Execute(args, d)
}

type noLimit struct{}

func (noLimit) Wait(context.Context) error { return nil }

// logLines は標準エラーの JSON 行を返す。JSON でない行があれば失敗する。
func (c *cli) logLines() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(c.stderr.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			c.t.Fatalf("stderr line is not JSON: %q", line)
		}
		out = append(out, m)
	}
	return out
}

func (c *cli) codes() []string {
	var codes []string
	for _, m := range c.logLines() {
		if code, ok := m["code"].(string); ok {
			codes = append(codes, code)
		}
	}
	return codes
}

var vocabulary = map[string]bool{
	"FORMAT_MISMATCH": true, "FORMAT_DRIFT": true, "LOG_GROUP_MISSING": true, "ACCESS_DENIED": true, "QUERY_LIMIT": true, "QUERY_INVALID": true,
	"STORE_LOCKED": true, "STORE_CORRUPT": true, "RUN_MISSED": true, "COLLECT_FAILED": true, "CONFIG_INVALID": true, "CHECK_UNUSED": true, "REPORT_NOT_FOUND": true,
}

func (c *cli) assertCodesInVocabulary() {
	c.t.Helper()
	for _, code := range c.codes() {
		if !vocabulary[code] {
			c.t.Fatalf("log code %q is not in the fixed vocabulary", code)
		}
	}
	for _, code := range engine.Codes {
		if !vocabulary[code] {
			c.t.Fatalf("engine.Codes contains %q which is not in the documented vocabulary", code)
		}
	}
}

func TestEndToEnd(t *testing.T) {
	c := newCLI(t)
	c.fake.Add(
		cloudtrailtest.Event("b1", c.now.Add(-5*time.Hour), cloudtrailtest.User(acct, "alice"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
		cloudtrailtest.Event("b2", c.now.Add(-4*time.Hour), cloudtrailtest.AssumedRole(acct, "Deploy", "gha"), "iam.amazonaws.com", "PutRolePolicy", "us-east-1", "203.0.113.2", false, map[string]any{"roleName": "AppRole", "policyName": "inline"}),
	)
	if code := c.run("init", "--config", c.cfg, "--window", "3d"); code != 0 {
		t.Fatalf("init exit %d\nstderr: %s", code, c.stderr)
	}
	// 3d の窓は UTC の日の境界で 4 日分に分かれ (09:00〜24:00, 2 日, 0:00〜09:00)、それぞれ 2 リージョンを引く
	if len(c.fake.Calls) != 8 || !c.fake.Calls[0].StartTime.Equal(c.now.Add(-3*24*time.Hour)) || !c.fake.Calls[7].EndTime.Equal(c.now) {
		t.Fatalf("init must query both regions per day with --window: %d calls", len(c.fake.Calls))
	}
	if !strings.Contains(c.stdout.String(), "sources ok: trail") {
		t.Fatalf("init stdout: %s", c.stdout)
	}
	c.assertCodesInVocabulary()

	// 1 回目の run: ベースラインなので findings は出ない
	c.now = c.now.Add(time.Hour)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d\nstderr: %s", code, c.stderr)
	}
	var first map[string]any
	if err := json.Unmarshal(c.stdout.Bytes(), &first); err != nil {
		t.Fatalf("run stdout is not JSON: %v\n%s", err, c.stdout)
	}
	summary := first["summary"].(map[string]any)
	if summary["new"] != float64(0) || summary["max_severity"] != "" {
		t.Fatalf("first run must be quiet: %v", summary)
	}
	c.assertCodesInVocabulary()

	// 2 回目の run: 新規主体 + AssumeRole + root ログイン → new
	c.now = c.now.Add(23 * time.Hour)
	c.fake.Add(
		cloudtrailtest.Event("n1", c.now.Add(-2*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin", "roleSessionName": "mallory@example.com"}),
		cloudtrailtest.Event("n2", c.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
	)
	out := filepath.Join(c.dir, "out")
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--out", out); code != 0 {
		t.Fatalf("run exit %d\nstderr: %s", code, c.stderr)
	}
	got, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "report.json", got)
	md, err := os.ReadFile(filepath.Join(out, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "report.md", md)
	if strings.Contains(string(got), "example.com") {
		t.Fatal("report leaks session name")
	}
	c.assertCodesInVocabulary()

	// report コマンドは保存済みの最新レポートを同じ内容で出す
	if code := c.run("report", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("report exit %d\nstderr: %s", code, c.stderr)
	}
	if c.stdout.String() != string(got) {
		t.Fatalf("report output differs from run output")
	}
	if code := c.run("report", "--config", c.cfg, "--profile", "daily", "--format", "md"); code != 0 || !strings.HasPrefix(c.stdout.String(), "# arata daily レポート (acme)") {
		t.Fatalf("report md: exit %d\n%s", code, c.stdout)
	}

	// evaluate は収集せずに評価する。直前の run と同じ窓なので新規主体は「報告済み」に回り、新規は出ない
	c.now = c.now.Add(time.Hour)
	if code := c.run("evaluate", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("evaluate exit %d\nstderr: %s", code, c.stderr)
	}
	var ev map[string]any
	_ = json.Unmarshal(c.stdout.Bytes(), &ev)
	if s := ev["summary"].(map[string]any); s["new"] != float64(0) || s["still_open"] != float64(0) {
		t.Fatalf("evaluate summary: %v", s)
	}
	if ar := ev["already_reported"].([]any); len(ar) != 3 {
		t.Fatalf("evaluate already_reported: %v", ev["already_reported"])
	}
	cov := ev["coverage"].(map[string]any)
	if len(cov["sources_ok"].([]any)) != 1 {
		t.Fatalf("evaluate coverage: %v", cov)
	}

	// collect は収集だけ
	if code := c.run("collect", "--config", c.cfg, "--window", "2h", "--source", "trail"); code != 0 || !strings.Contains(c.stdout.String(), "sources ok: trail") {
		t.Fatalf("collect exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	c.assertCodesInVocabulary()
}

func TestExitCodes(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		c := newCLI(t)
		if code := c.run("run", "--config", c.cfg); code != 0 {
			t.Fatalf("exit %d: %s", code, c.stderr)
		}
	})
	t.Run("config missing flag", func(t *testing.T) {
		c := newCLI(t)
		if code := c.run("run"); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("exit %d codes %v", code, c.codes())
		}
	})
	t.Run("config file missing", func(t *testing.T) {
		c := newCLI(t)
		if code := c.run("run", "--config", filepath.Join(c.dir, "nope.yaml")); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("exit %d codes %v", code, c.codes())
		}
	})
	t.Run("config invalid", func(t *testing.T) {
		c := newCLI(t)
		c.writeConfig("name: acme\nstore: s3://nope\nsources: []\n")
		if code := c.run("init", "--config", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("exit %d codes %v", code, c.codes())
		}
	})
	t.Run("unknown profile", func(t *testing.T) {
		c := newCLI(t)
		if code := c.run("run", "--config", c.cfg, "--profile", "monthly"); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("exit %d codes %v", code, c.codes())
		}
	})
	t.Run("unknown flag", func(t *testing.T) {
		c := newCLI(t)
		if code := c.run("run", "--config", c.cfg, "--bogus"); code != 2 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("bad window", func(t *testing.T) {
		c := newCLI(t)
		if code := c.run("collect", "--config", c.cfg, "--window", "1w"); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("exit %d codes %v", code, c.codes())
		}
		if code := c.run("init", "--config", c.cfg, "--window", "0d"); code != 2 {
			t.Fatalf("init bad window exit %d", code)
		}
	})
	t.Run("report before run", func(t *testing.T) {
		// そのプロファイルの run が無ければ、固定語彙の code 付きで 1 行出して終了コード 2 (--out でもディレクトリを作らない)
		c := newCLI(t)
		out := filepath.Join(c.dir, "out")
		for _, args := range [][]string{{}, {"--profile", "daily"}, {"--profile", "daily", "--out", out}} {
			code := c.run(append([]string{"report", "--config", c.cfg}, args...)...)
			if code != 2 || strings.Join(c.codes(), ",") != "REPORT_NOT_FOUND" || !strings.Contains(c.stderr.String(), "プロファイル daily の run がまだありません") ||
				strings.Count(strings.TrimSpace(c.stderr.String()), "\n") != 0 {
				t.Fatalf("%v: exit %d stderr %q", args, code, c.stderr)
			}
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("--out directory must not be created")
		}
	})
	t.Run("collect partially failed", func(t *testing.T) {
		c := newCLI(t)
		c.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
		code := c.run("run", "--config", c.cfg, "--profile", "daily")
		if code != 3 {
			t.Fatalf("exit %d: %s", code, c.stderr)
		}
		var rep map[string]any
		if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
			t.Fatalf("report must still be emitted: %v", err)
		}
		cov := rep["coverage"].(map[string]any)
		if len(cov["sources_failed"].([]any)) != 1 || len(cov["checks_skipped"].([]any)) != 11 {
			t.Fatalf("coverage: %v", cov)
		}
		if sf := cov["sources_failed"].([]any)[0].(map[string]any); sf["source"] != "trail" || sf["code"] != "ACCESS_DENIED" {
			t.Fatalf("sources_failed: %v", sf)
		}
		if strings.Join(c.codes(), ",") != "ACCESS_DENIED" {
			t.Fatalf("codes %v", c.codes())
		}
		var line map[string]any
		for _, m := range c.logLines() {
			if m["code"] == "ACCESS_DENIED" {
				line = m
			}
		}
		if line["source"] != "trail" || line["action"] != "cloudtrail:LookupEvents" || line["level"] != "ERROR" {
			t.Fatalf("log line: %v", line)
		}
		c.assertCodesInVocabulary()
		if code := c.run("init", "--config", c.cfg); code != 3 {
			t.Fatalf("init partial exit %d", code)
		}
		if code := c.run("collect", "--config", c.cfg); code != 3 {
			t.Fatalf("collect partial exit %d", code)
		}
	})
	t.Run("store locked", func(t *testing.T) {
		c := newCLI(t)
		cfg, err := config.Load(c.cfg)
		if err != nil {
			t.Fatal(err)
		}
		e, err := engine.Open(cfg, engine.Deps{})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		if code := c.run("run", "--config", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "STORE_LOCKED" {
			t.Fatalf("exit %d codes %v", code, c.codes())
		}
	})
}

func TestInitResume(t *testing.T) {
	c := newCLI(t)
	c.fake.ErrFor = func(in *ct.LookupEventsInput) error {
		if !in.StartTime.Before(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) {
			return cloudtrailtest.APIError{Code: "ThrottlingException"}
		}
		return nil
	}
	if code := c.run("init", "--config", c.cfg, "--window", "2d"); code != 3 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "days: 1/3 (until 2026-10-20T00:00:00Z)") || !strings.Contains(c.stdout.String(), "arata init --resume") {
		t.Fatalf("stdout: %s", c.stdout)
	}
	c.fake.ErrFor = nil
	if code := c.run("init", "--config", c.cfg, "--resume"); code != 0 || !strings.Contains(c.stdout.String(), "days: 3/3") {
		t.Fatalf("resume exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("init", "--config", c.cfg, "--resume"); code != 0 || !strings.Contains(c.stdout.String(), "再開する init はありません") {
		t.Fatalf("nothing to resume exit %d: %s", code, c.stdout)
	}
	c.assertCodesInVocabulary()
}

func TestHelp(t *testing.T) {
	c := newCLI(t)
	if code := c.run("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, sub := range []string{"init", "doctor", "run", "collect", "evaluate", "report"} {
		if !strings.Contains(c.stdout.String(), sub) {
			t.Fatalf("help lacks %s:\n%s", sub, c.stdout)
		}
	}
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs from golden (review, then `go test ./cmd/arata -update`):\n--- got ---\n%s", name, got)
	}
}
