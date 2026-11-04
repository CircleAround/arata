package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/store"
)

const acct = "123456789012"

type harness struct {
	cfg     *config.Config
	fake    *cloudtrailtest.Fake
	logs    *cwlogstest.Fake
	acct    *accounttest.Fake
	stderr  *bytes.Buffer
	now     time.Time
	deps    Deps
	regions []string
}

func newHarness(t *testing.T) *harness {
	return newHarnessWith(t, "", "")
}

// newHarnessWith は trail に加えて sources (YAML の配列要素) と profiles を足した設定で harness を作る。
func newHarnessWith(t *testing.T, sources, profiles string) *harness {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`
name: acme
store: dir://%s/store
sources:
  - id: trail
    kind: cloudtrail-lookup
%sprofiles:
  daily:
    window: 24h
    checks: [default-daily, root_usage, unknown_assume_role]
  weekly:
    window: 7d
    checks: [default-weekly]
%s`, dir, sources, profiles)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "allowlist.yaml"), []byte("principals:\n  - arn: arn:aws:iam::"+acct+":role/Deploy\n    tags: [deploy]\n"), 0o600)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{cfg: cfg, fake: &cloudtrailtest.Fake{}, logs: &cwlogstest.Fake{}, acct: &accounttest.Fake{}, stderr: &bytes.Buffer{}, now: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	n := 0
	h.deps = Deps{
		Now:   func() time.Time { return h.now },
		NewID: func() string { n++; return fmt.Sprintf("id-%03d", n) },
		CloudTrail: func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cloudtrail.API, error) {
			h.regions = append(h.regions, region)
			return h.fake, nil
		},
		CloudWatchLogs: func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cwlogs.API, error) {
			return h.logs, nil
		},
		Account: func(ctx context.Context, cfg *config.Config, src config.Source, region string) (account.Clients, error) {
			return h.acct.Clients(region), nil
		},
		Sleep:   func(context.Context, time.Duration) error { return nil },
		Logger:  slog.New(slog.NewJSONHandler(h.stderr, nil)),
		Limiter: noLimit{},
	}
	return h
}

type noLimit struct{}

func (noLimit) Wait(context.Context) error { return nil }

func TestCloudTrailRetryer(t *testing.T) {
	r := NewCloudTrailRetryer()
	if r.MaxAttempts() != CloudTrailMaxAttempts {
		t.Fatalf("max attempts: %d", r.MaxAttempts())
	}
	if !r.IsErrorRetryable(cloudtrailtest.APIError{Code: "ThrottlingException"}) {
		t.Fatal("ThrottlingException must be retryable")
	}
	if r.IsErrorRetryable(cloudtrailtest.APIError{Code: "AccessDeniedException"}) {
		t.Fatal("AccessDeniedException must not be retryable")
	}
}

func (h *harness) open(t *testing.T) *Engine {
	t.Helper()
	e, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func (h *harness) logCodes(t *testing.T) []string {
	t.Helper()
	var codes []string
	for _, line := range strings.Split(strings.TrimSpace(h.stderr.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stderr is not JSON lines: %q", line)
		}
		if c, ok := m["code"].(string); ok {
			codes = append(codes, c)
		}
	}
	return codes
}

// 拒否された呼び出しは events に残り、access_denied が主体ごとに報告する。拒否のコードは設定 (checks.access_denied.error_codes) に従う。
func TestRunAccessDenied(t *testing.T) {
	h := newHarnessWith(t, "", "checks:\n  access_denied:\n    error_codes: [AccessDenied, Client.UnauthorizedOperation, Forbidden]\n")
	ctx := context.Background()
	scanner := cloudtrailtest.AssumedRole(acct, "example-scanner", "s1")
	at := h.now.Add(-2 * time.Hour)
	for i, api := range [][2]string{{"iam.amazonaws.com", "ListUsers"}, {"s3.amazonaws.com", "ListBuckets"}, {"secretsmanager.amazonaws.com", "ListSecrets"}, {"iam.amazonaws.com", "CreateUser"}} {
		h.fake.Add(cloudtrailtest.WithError(cloudtrailtest.Event(fmt.Sprintf("d%d", i), at, scanner, api[0], api[1], "us-east-1", "198.51.100.1", api[1] != "CreateUser", nil), "AccessDenied"))
	}
	h.fake.Add(
		cloudtrailtest.WithError(cloudtrailtest.Event("d-ec2", at, scanner, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "198.51.100.1", true, nil), "Client.UnauthorizedOperation"),
		cloudtrailtest.WithError(cloudtrailtest.Event("d-custom", at, scanner, "kms.amazonaws.com", "ListKeys", "ap-northeast-1", "198.51.100.1", true, nil), "Forbidden"),
		// 既定のコードでも設定に無ければ数えない。拒否でないエラーも数えない
		cloudtrailtest.WithError(cloudtrailtest.Event("d-other", at, scanner, "lambda.amazonaws.com", "ListFunctions", "ap-northeast-1", "198.51.100.1", true, nil), "AccessDeniedException"),
		cloudtrailtest.WithError(cloudtrailtest.Event("d-nse", at, scanner, "iam.amazonaws.com", "GetRole", "us-east-1", "198.51.100.1", true, nil), "NoSuchEntity"),
	)
	e := h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range r.Report.Findings.New {
		if f.Check == "access_denied" {
			found = append(found, fmt.Sprintf("%s %s %v", f.Key, f.Severity, f.Data["distinct_apis"]))
		}
	}
	if strings.Join(found, ";") != "arn:aws:iam::"+acct+":role/example-scanner medium 6" {
		t.Fatalf("access_denied: %v (%+v)", found, r.Report.Findings.New)
	}
	last, _ := e.Store().RecentRuns(ctx, 1)
	if last[0].Stats["denied_events"] != float64(6) {
		t.Fatalf("denied_events: %+v", last[0].Stats)
	}
}

func TestInitThenRunTwice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// ベースライン: alice と Deploy ロールが日常的に動いている
	h.fake.Add(
		cloudtrailtest.Event("b1", h.now.Add(-5*time.Hour), cloudtrailtest.User(acct, "alice"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
		cloudtrailtest.Event("b2", h.now.Add(-4*time.Hour), cloudtrailtest.AssumedRole(acct, "Deploy", "gha"), "iam.amazonaws.com", "PutRolePolicy", "us-east-1", "203.0.113.2", false, map[string]any{"roleName": "AppRole", "policyName": "inline"}),
	)
	e := h.open(t)
	cr, err := e.Init(ctx, InitOptions{})
	if err != nil || len(cr.SourcesOK) != 1 || cr.Records == 0 {
		t.Fatalf("init: %+v %v", cr, err)
	}
	if strings.Join(h.regions[:2], ",") != "ap-northeast-1,us-east-1" {
		t.Fatalf("regions queried: %v", h.regions)
	}
	if last, _ := e.Store().LastRun(ctx, "init", nil); !last.WindowFrom.Equal(h.now.Add(-7 * 24 * time.Hour)) {
		t.Fatalf("init window default 7d: %+v", last)
	}
	ps, _ := e.Store().Principals(ctx, store.PrincipalFilter{Statuses: []string{store.PrincipalBaseline}})
	if len(ps) != 2 {
		t.Fatalf("baseline principals: %+v", ps)
	}
	e.Close()

	// 1 回目の run (init と同じ窓): findings は出ない。Deploy の IAM 変更は info に回る
	h.now = h.now.Add(time.Hour)
	e = h.open(t)
	r1, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Exit != ExitOK || r1.Report.Summary.New != 0 || r1.Report.Summary.MaxSeverity != "" {
		t.Fatalf("first run should be quiet: exit=%d summary=%+v", r1.Exit, r1.Report.Summary)
	}
	if len(r1.Report.Info) != 1 || r1.Report.Info[0].Check != "iam_changes" {
		t.Fatalf("deploy principal IAM change should be info: %+v", r1.Report.Info)
	}
	if strings.Join(r1.Report.Coverage.ChecksRun, ",") != "access_denied,ai_path_usage,defense_evasion,iam_changes,new_principal,principal_new_source,public_exposure,root_usage,secret_access,unknown_assume_role" {
		t.Fatalf("checks_run: %v", r1.Report.Coverage.ChecksRun)
	}
	e.Close()

	// 2 回目: 新しい主体 mallory が現れ、AssumeRole し、root がログインする
	h.now = h.now.Add(23 * time.Hour)
	h.fake.Add(
		cloudtrailtest.Event("n1", h.now.Add(-2*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin", "roleSessionName": "mallory@example.com"}),
		cloudtrailtest.Event("n2", h.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
		cloudtrailtest.Event("n3", h.now.Add(-3*time.Hour), cloudtrailtest.User(acct, "alice"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
	)
	e = h.open(t)
	r2, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Exit != ExitOK || r2.Report.Summary.New != 3 || r2.Report.Summary.MaxSeverity != "critical" {
		t.Fatalf("second run: exit=%d summary=%+v", r2.Exit, r2.Report.Summary)
	}
	got := map[string]string{}
	for _, f := range r2.Report.Findings.New {
		got[f.Check] = f.Key
	}
	if got["new_principal"] != "arn:aws:iam::"+acct+":user/mallory" || !strings.HasPrefix(got["unknown_assume_role"], "arn:aws:iam::"+acct+":user/mallory->") || !strings.HasPrefix(got["root_usage"], "arn:aws:iam::"+acct+":root|") {
		t.Fatalf("new findings: %+v", got)
	}
	j, _ := r2.Report.JSON()
	if strings.Contains(string(j), "example.com") {
		t.Fatal("report leaks session name")
	}
	// 保存されたレポートが report コマンドで読める
	b, err := e.LastReport("daily")
	if err != nil || !bytes.Equal(b, j) {
		t.Fatalf("saved report mismatch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.Store.Dir, "reports", "daily.md")); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// 3 回目 (翌日、新しい事象なし): new_principal は still_open、event 型は沈黙、resolved は出ない
	h.now = h.now.Add(24 * time.Hour)
	e = h.open(t)
	r3, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	s := r3.Report.Summary
	if s.New != 0 || s.Changed != 0 || s.Recurred != 0 || s.Resolved != 0 || s.StillOpen != 1 || r3.Report.Findings.StillOpen[0].Check != "new_principal" {
		t.Fatalf("third run: %+v", s)
	}
	// 4 回目: root が再びログイン → recurred
	h.now = h.now.Add(24 * time.Hour)
	h.fake.Add(cloudtrailtest.Event("n4", h.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
	r4, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r4.Report.Summary.Recurred != 1 || r4.Report.Findings.Recurred[0].Check != "root_usage" || r4.Report.Summary.MaxSeverity != "critical" {
		t.Fatalf("fourth run: %+v", r4.Report.Summary)
	}
	if codes := h.logCodes(t); len(codes) != 0 {
		t.Fatalf("unexpected coded logs: %v", codes)
	}
}

func TestPartialFailureExit3(t *testing.T) {
	h := newHarness(t)
	h.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
	e := h.open(t)
	r, err := e.Run(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	// CloudTrail の収集に失敗した run には「収集し終えた」印を付けない (ADR 0027)
	if last, _ := e.Store().RecentRuns(context.Background(), 1); last[0].Stats[checks.TrailCollectedStat] != nil {
		t.Fatalf("failed trail must not be marked: %+v", last[0].Stats)
	}
	if r.Exit != ExitPartial || len(r.Report.Coverage.SourcesFailed) != 1 || r.Report.Summary.CollectErrors[0].Code != "ACCESS_DENIED" {
		t.Fatalf("exit=%d report=%+v", r.Exit, r.Report.Coverage)
	}
	if sf := r.Report.Coverage.SourcesFailed[0]; sf.Source != "trail" || sf.Code != "ACCESS_DENIED" || sf.CoveredFrom != "" {
		t.Fatalf("sources_failed: %+v", sf)
	}
	if len(r.Report.Coverage.ChecksRun) != 0 || len(r.Report.Coverage.ChecksSkipped) != 16 || r.Report.Coverage.ChecksSkipped[0].Reason != "source trail failed" {
		t.Fatalf("coverage: %+v", r.Report.Coverage)
	}
	if codes := h.logCodes(t); strings.Join(codes, ",") != "ACCESS_DENIED" {
		t.Fatalf("codes: %v", codes)
	}
}

func TestPartialFailureKeepsFetchedData(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// 1 ページ目 (新しい順) は取れ、2 ページ目でスロットルが収まらない
	h.fake.PageSize = 1
	h.fake.FailAtPage = 1
	h.fake.Err = cloudtrailtest.APIError{Code: "ThrottlingException"}
	h.fake.Add(
		cloudtrailtest.Event("new", h.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
		cloudtrailtest.Event("old", h.now.Add(-5*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}),
	)
	e := h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitPartial {
		t.Fatalf("exit %d", r.Exit)
	}
	sf := r.Report.Coverage.SourcesFailed
	if len(sf) != 1 || sf[0].Code != "QUERY_LIMIT" || sf[0].CoveredFrom != h.now.Add(-1*time.Hour).Format(time.RFC3339) || sf[0].CoveredUntil != h.now.Format(time.RFC3339) {
		t.Fatalf("sources_failed: %+v", sf)
	}
	if ce := r.Report.Summary.CollectErrors[0]; ce.CoveredFrom != sf[0].CoveredFrom || ce.CoveredUntil != sf[0].CoveredUntil {
		t.Fatalf("collect_errors must carry the same range: %+v", ce)
	}
	// 取れた分はストアに残っている (events と principals)
	evs, _ := e.Store().Events(ctx, h.now.Add(-24*time.Hour), h.now, store.EventFilter{})
	if len(evs) != 1 || evs[0].EventID != "new" {
		t.Fatalf("fetched events must be stored: %+v", evs)
	}
	ps, _ := e.Store().Principals(ctx, store.PrincipalFilter{})
	if len(ps) != 1 || ps[0].Kind != "root" {
		t.Fatalf("fetched principals must be stored: %+v", ps)
	}
	if codes := h.logCodes(t); strings.Join(codes, ",") != "QUERY_LIMIT" {
		t.Fatalf("codes: %v", codes)
	}
}

func TestUnknownProfileAndCheck(t *testing.T) {
	h := newHarness(t)
	e := h.open(t)
	_, err := e.Run(context.Background(), "monthly")
	var xe *ExitError
	if !asExit(err, &xe) || xe.Exit != ExitConfig || xe.Code != CodeConfigInvalid {
		t.Fatalf("%v", err)
	}
	p := h.cfg.Profiles["daily"]
	p.Checks = []string{"nope"}
	h.cfg.Profiles["daily"] = p
	_, err = e.Run(context.Background(), "daily")
	if !asExit(err, &xe) || xe.Exit != ExitConfig {
		t.Fatalf("%v", err)
	}
	if codes := h.logCodes(t); strings.Join(codes, ",") != "CONFIG_INVALID,CHECK_UNUSED,CONFIG_INVALID" {
		t.Fatalf("codes: %v", codes)
	}
}

func TestLock(t *testing.T) {
	h := newHarness(t)
	h.open(t)
	if _, err := Open(h.cfg, h.deps); err == nil {
		t.Fatal("second open must fail while locked")
	}
	if codes := h.logCodes(t); strings.Join(codes, ",") != "STORE_LOCKED" {
		t.Fatalf("codes: %v", codes)
	}
}

func TestWindowCatchUp(t *testing.T) {
	ctx := context.Background()
	lastWindow := func(t *testing.T, e *Engine) store.Run {
		t.Helper()
		r, err := e.Store().LastRun(ctx, "daily", nil)
		if err != nil || r == nil {
			t.Fatalf("%v %v", r, err)
		}
		return *r
	}
	t.Run("first run uses plain window", func(t *testing.T) {
		h := newHarness(t)
		e := h.open(t)
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		r := lastWindow(t, e)
		if !r.WindowFrom.Equal(h.now.Add(-24*time.Hour)) || !r.WindowTo.Equal(h.now) {
			t.Fatalf("%+v", r)
		}
		if len(h.logCodes(t)) != 0 {
			t.Fatalf("codes: %v", h.logCodes(t))
		}
	})
	t.Run("late run catches up from previous window end", func(t *testing.T) {
		h := newHarness(t)
		e := h.open(t)
		first := h.now
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		h.now = first.Add(30 * time.Hour)
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		r := lastWindow(t, e)
		if !r.WindowFrom.Equal(first) || !r.WindowTo.Equal(h.now) {
			t.Fatalf("from must be previous window_to: %+v", r)
		}
		// 30h は 2 × 24h 未満なので RUN_MISSED は出ない (取りこぼしも無い)
		if len(h.logCodes(t)) != 0 {
			t.Fatalf("codes: %v", h.logCodes(t))
		}
		// 窓内のイベントが後から取れていること
		h.fake.Add(cloudtrailtest.Event("late", first.Add(2*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
		h.now = h.now.Add(30 * time.Hour)
		res, err := e.Run(ctx, "daily")
		if err != nil {
			t.Fatal(err)
		}
		if res.Report.Summary.New != 0 {
			t.Fatalf("late event is before the covered window (first..first+30h was already collected): %+v", res.Report.Summary)
		}
	})
	t.Run("gap over 2x window warns but still catches up", func(t *testing.T) {
		h := newHarness(t)
		e := h.open(t)
		first := h.now
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		h.now = first.Add(72 * time.Hour)
		h.fake.Add(cloudtrailtest.Event("gap", first.Add(10*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
		res, err := e.Run(ctx, "daily")
		if err != nil {
			t.Fatal(err)
		}
		r := lastWindow(t, e)
		if !r.WindowFrom.Equal(first) {
			t.Fatalf("%+v", r)
		}
		if res.Report.Summary.New != 1 || res.Report.Findings.New[0].Check != "root_usage" {
			t.Fatalf("event in the gap must be found: %+v", res.Report.Summary)
		}
		if codes := h.logCodes(t); strings.Join(codes, ",") != "RUN_MISSED" {
			t.Fatalf("codes: %v", codes)
		}
		line := h.logLine(t, "RUN_MISSED")
		if line["covered_from"] != first.Format(time.RFC3339) || line["truncated"] != false || line["gap"] != "72h0m0s" {
			t.Fatalf("log: %v", line)
		}
	})
	t.Run("gap over max_catchup is truncated", func(t *testing.T) {
		h := newHarness(t)
		e := h.open(t)
		first := h.now
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		h.now = first.Add(10 * 24 * time.Hour)
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		r := lastWindow(t, e)
		if !r.WindowFrom.Equal(h.now.Add(-7 * 24 * time.Hour)) {
			t.Fatalf("from must be now - max_catchup: %+v", r)
		}
		line := h.logLine(t, "RUN_MISSED")
		if line["truncated"] != true || line["covered_from"] != r.WindowFrom.Format(time.RFC3339) {
			t.Fatalf("log: %v", line)
		}
	})
	t.Run("failed run is ignored, early run keeps plain window", func(t *testing.T) {
		h := newHarness(t)
		e := h.open(t)
		first := h.now
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		// 失敗した run (window_to が進んでいる) は無視される
		_ = e.Store().BeginRun(ctx, store.Run{ID: "bad", Profile: "daily", WindowFrom: first, WindowTo: first.Add(20 * time.Hour), StartedAt: first.Add(20 * time.Hour), Status: "running"})
		_ = e.Store().FinishRun(ctx, "bad", "failed", nil)
		h.now = first.Add(30 * time.Hour)
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		if r := lastWindow(t, e); !r.WindowFrom.Equal(first) {
			t.Fatalf("%+v", r)
		}
		// 早めに走った場合は通常の窓 (前回と重なる)
		h.now = h.now.Add(12 * time.Hour)
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
		if r := lastWindow(t, e); !r.WindowFrom.Equal(h.now.Add(-24 * time.Hour)) {
			t.Fatalf("%+v", r)
		}
	})
}

func (h *harness) logLine(t *testing.T, code string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(h.stderr.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["code"] == code {
			return m
		}
	}
	t.Fatalf("no log line with code %s", code)
	return nil
}

func asExit(err error, target **ExitError) bool {
	for err != nil {
		if xe, ok := err.(*ExitError); ok {
			*target = xe
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

const nginxSource = `  - id: web
    kind: cloudwatch-logs
    log_group: /app/nginx
    format: nginx_access
`

const hourlyProfile = `  hourly:
    window: 1h
    checks: [root_usage, unknown_assume_role]
`

func linesRows(day string, total, matched int) cwlogstest.Response {
	return cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", day+" 00:00:00.000", "lines_total", fmt.Sprint(total), "lines_matched", fmt.Sprint(matched))}, BytesScanned: 2e6}
}

func TestCloudWatchLogsSource(t *testing.T) {
	h := newHarnessWith(t, nginxSource, hourlyProfile)
	ctx := context.Background()
	h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 950))
	h.logs.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "30")}})
	e := h.open(t)

	// hourly は http_access を使うチェックを持たないので Insights を引かない
	r, err := e.Run(ctx, "hourly")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.logs.Started) != 0 || strings.Join(r.Report.Coverage.SourcesOK, ",") != "trail" || len(r.Report.Coverage.Formats) != 0 {
		t.Fatalf("hourly must not query Logs Insights: %d queries, coverage %+v", len(h.logs.Started), r.Report.Coverage)
	}

	h.now = h.now.Add(time.Minute)
	r, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK || strings.Join(r.Report.Coverage.SourcesOK, ",") != "trail,web" {
		t.Fatalf("daily: exit %d coverage %+v", r.Exit, r.Report.Coverage)
	}
	fc := r.Report.Coverage.Formats
	if len(fc) != 1 || fc[0].Source != "web" || *fc[0].MatchRate != 0.95 || fc[0].Code != "" || fc[0].BytesScanned == 0 {
		t.Fatalf("formats: %+v", fc)
	}
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: "sign_in_failures"})
	if len(ms) != 1 || ms[0].Key != "198.51.100.7" || ms[0].Value != 30 || ms[0].Source != "web" {
		t.Fatalf("metrics: %+v", ms)
	}
	last, _ := e.Store().RecentRuns(ctx, 1)
	if rates := last[0].Stats["match_rates"].(map[string]any); rates["web"] != 0.95 {
		t.Fatalf("runs.stats: %+v", last[0].Stats)
	}
	if codes := h.logCodes(t); len(codes) != 0 {
		t.Fatalf("codes: %v", codes)
	}
}

func TestFormatMismatch(t *testing.T) {
	h := newHarnessWith(t, nginxSource+"    expected_match_rate: 0.6\n", "")
	h.logs.On("as lines_total", linesRows("2026-10-21", 100, 12))
	h.logs.On("ispresent", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("@message", `{"user":"alice@example.com","msg":"json, not nginx"}`)}})
	e := h.open(t)
	r, err := e.Run(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitPartial {
		t.Fatalf("exit %d", r.Exit)
	}
	if sf := r.Report.Coverage.SourcesFailed; len(sf) != 1 || sf[0].Source != "web" || sf[0].Code != "FORMAT_MISMATCH" {
		t.Fatalf("sources_failed: %+v", sf)
	}
	if fc := r.Report.Coverage.Formats; len(fc) != 1 || fc[0].Code != "FORMAT_MISMATCH" || *fc[0].MatchRate != 0.12 {
		t.Fatalf("formats: %+v", fc)
	}
	line := h.logLine(t, "FORMAT_MISMATCH")
	if line["source"] != "web" || line["log_group"] != "/app/nginx" || line["format"] != "nginx_access" || line["match_rate"] != 0.12 || line["expected"] != 0.6 || line["run_id"] == nil {
		t.Fatalf("log line: %v", line)
	}
	samples, _ := line["samples"].([]any)
	if len(samples) != 1 || strings.Contains(samples[0].(string), "alice") {
		t.Fatalf("samples must be masked: %v", line["samples"])
	}
	j, _ := r.Report.JSON()
	if strings.Contains(string(j), "json, not nginx") || strings.Contains(string(j), "alice") {
		t.Fatal("report must not carry sample lines")
	}
}

func TestFormatDrift(t *testing.T) {
	h := newHarnessWith(t, nginxSource, "")
	ctx := context.Background()
	e := h.open(t)
	for i := 0; i < 3; i++ {
		h.logs.On("as lines_total", linesRows("2026-10-21", 100, 95))
		r, err := e.Run(ctx, "daily")
		if err != nil || r.Report.Coverage.Formats[0].Code != "" {
			t.Fatalf("run %d: %v %+v", i, err, r.Report.Coverage.Formats)
		}
		h.now = h.now.Add(24 * time.Hour)
	}
	// 0.95 → 0.81: 閾値 0.8 は上回るが直近平均から 14pt 低下 (20pt 未満) なのでまだ鳴らない
	h.logs.On("as lines_total", linesRows("2026-10-24", 100, 81))
	r, _ := e.Run(ctx, "daily")
	if fc := r.Report.Coverage.Formats[0]; fc.Code != "" || fc.RecentAverage == nil || *fc.RecentAverage != 0.95 {
		t.Fatalf("formats: %+v", fc)
	}
	h.now = h.now.Add(24 * time.Hour)
	// 0.95, 0.95, 0.95, 0.81 の平均 0.915 から 0.70 へ (21.5pt 低下) → FORMAT_DRIFT だが閾値は満たしている
	h.logs.On("as lines_total", linesRows("2026-10-25", 100, 70))
	src := h.cfg.Sources[1]
	src.ExpectedMatchRate = 0.5
	h.cfg.Sources[1] = src
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if fc := r.Report.Coverage.Formats[0]; fc.Code != "FORMAT_DRIFT" || r.Exit != ExitOK || len(r.Report.Coverage.SourcesFailed) != 0 {
		t.Fatalf("drift: exit %d %+v", r.Exit, fc)
	}
	line := h.logLine(t, "FORMAT_DRIFT")
	if line["level"] != "WARN" || line["match_rate"] != 0.7 || line["recent_average"] != 0.915 || line["source"] != "web" {
		t.Fatalf("log line: %v", line)
	}
}

// TestDailyMetricsNotOverwrittenByPartialDay は、窓が前日の末尾 2 時間しか含まなくても、前日の日次集計が
// 部分日の値で上書きされないことを固定する (集計クエリは窓に重なる UTC 日の 0 時から問い合わせる)。
func TestDailyMetricsNotOverwrittenByPartialDay(t *testing.T) {
	h := newHarnessWith(t, nginxSource, "")
	ctx := context.Background()
	h.now = time.Date(2026, 10, 21, 22, 0, 0, 0, time.UTC) // 07:00 JST
	d1 := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	// Insights の振る舞いを模す: 10-21 の値は 10-21 0 時から引けば丸 1 日分 (100)、22:00 からだと 2 時間分 (8)
	rows := func(in *cwl.StartQueryInput) []map[string]string {
		v := "100"
		if aws.ToInt64(in.StartTime) > d1.Unix() {
			v = "8"
		}
		return []map[string]string{
			cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "lines_total", v, "lines_matched", v),
			cwlogstest.Rows("day", "2026-10-22 00:00:00.000", "lines_total", "50", "lines_matched", "50"),
		}
	}
	h.logs.On("as lines_total", cwlogstest.Response{RowsFor: rows})
	e := h.open(t)
	if _, err := e.Run(ctx, "daily"); err != nil { // 窓 [10-20 22:00, 10-21 22:00)
		t.Fatal(err)
	}
	h.now = h.now.Add(24 * time.Hour) // 窓 [10-21 22:00, 10-22 22:00): 10-21 は末尾 2 時間だけ
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	last := h.logs.Started[len(h.logs.Started)-1]
	if aws.ToInt64(last.StartTime) != d1.Unix() {
		t.Fatalf("query must start at the UTC day start of the window: %v", time.Unix(aws.ToInt64(last.StartTime), 0).UTC())
	}
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: "lines_total", From: "2026-10-21", To: "2026-10-21"})
	if len(ms) != 1 || ms[0].Value != 100 {
		t.Fatalf("10-21 must keep the full-day value: %+v", ms)
	}
}

// 本番試用で判明した取りこぼし (ADR 0013): 前回の窓の終わりの 5 分前に起きたイベントが、前回の収集時点では CloudTrail に
// まだ記録されておらず、今回初めて返る。再走査 [From - ingest_delay, To) で今回の run が検知する。
func TestRunRescansIngestDelay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	alice := cloudtrailtest.User(acct, "alice")
	// 1 回目の run の時点で記録済み: alice の通常操作と root のログイン (前回の窓の末尾 = 重なり区間に入る)
	h.fake.Add(
		cloudtrailtest.Event("a1", h.now.Add(-10*time.Minute), alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
		cloudtrailtest.Event("r1", h.now.Add(-8*time.Minute), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
	)
	e := h.open(t)
	r1, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	var rootID string
	for _, f := range r1.Report.Findings.New {
		if f.Check == "root_usage" {
			rootID = f.ID
		}
	}
	if rootID == "" {
		t.Fatalf("first run must report root usage: %+v", r1.Report.Findings.New)
	}
	// 人が確認して resolve した
	if _, err := e.SetStatus(ctx, rootID, store.FindingResolved, time.Time{}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	prevTo := h.now

	// 1 回目の窓の終わりの 5 分前に起きた mallory の AssumeRole が、遅れて記録された
	h.fake.Add(cloudtrailtest.Event("late", prevTo.Add(-5*time.Minute), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true,
		map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}))
	h.now = h.now.Add(24 * time.Hour)
	calls := len(h.fake.Calls)
	e = h.open(t)
	r2, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if got := h.fake.Calls[calls].StartTime; !got.Equal(prevTo.Add(-15 * time.Minute)) {
		t.Fatalf("lookup must start ingest_delay before the window: %v", got)
	}
	if r2.Report.Window.From != prevTo.UTC().Format(time.RFC3339) {
		t.Fatalf("the window itself is unchanged: %+v", r2.Report.Window)
	}
	got := map[string]string{}
	for _, f := range r2.Report.Findings.New {
		got[f.Check] = f.Key
	}
	if !strings.HasPrefix(got["unknown_assume_role"], "arn:aws:iam::"+acct+":user/mallory->") || got["new_principal"] != "arn:aws:iam::"+acct+":user/mallory" {
		t.Fatalf("late event must be detected: %+v", r2.Report.Findings.New)
	}
	// 重なり区間の収集済みイベントで resolve 済みの root_usage が再報告されたり、recurred になったりしない
	if _, ok := got["root_usage"]; ok || len(r2.Report.Findings.Recurred) != 0 {
		t.Fatalf("rescanned events must not be reported again: new=%+v recurred=%+v", r2.Report.Findings.New, r2.Report.Findings.Recurred)
	}
	// 重なり区間の alice のイベントは principal_ips の件数に二重に足されない
	ips, _ := e.Store().PrincipalIPs(ctx, "arn:aws:iam::"+acct+":user/alice")
	if len(ips) != 1 || ips[0].Count != 1 {
		t.Fatalf("principal_ips count must not double: %+v", ips)
	}
	// 重なり区間でだけ見えた mallory × IP は前回数えていないので、初めて行を作るときは重なり分も数える
	if ips, _ := e.Store().PrincipalIPs(ctx, "arn:aws:iam::"+acct+":user/mallory"); len(ips) != 1 || ips[0].Count != 1 {
		t.Fatalf("late principal count: %+v", ips)
	}
}

// 前回 run で報告済みの event 型の事象は、再走査で同じイベントが窓に戻っても recurred にならない (ADR 0013)。
func TestRunRescanDoesNotRecur(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.fake.Add(cloudtrailtest.Event("r1", h.now.Add(-5*time.Minute), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
	e := h.open(t)
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	e.Close()
	h.now = h.now.Add(24 * time.Hour)
	e = h.open(t)
	r2, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Report.Summary.New != 0 || r2.Report.Summary.Recurred != 0 || r2.Report.Summary.Changed != 0 {
		t.Fatalf("rescan must be silent: %+v", r2.Report.Summary)
	}
}

// collector の取り出しから defense_evasion / public_exposure の判定までを通す。監査対象のロググループは cloudwatch-logs のソースから渡る。
func TestRunSecurityChecks(t *testing.T) {
	h := newHarnessWith(t, "  - id: nginx\n    kind: cloudwatch-logs\n    log_group: prod-nginx-access\n    format: nginx_access\n",
		"  security:\n    window: 24h\n    checks: [defense_evasion, public_exposure]\n")
	ctx := context.Background()
	alice := cloudtrailtest.User(acct, "alice")
	at := h.now.Add(-2 * time.Hour)
	h.fake.Add(
		cloudtrailtest.Event("l1", at, alice, "logs.amazonaws.com", "DeleteLogGroup", "ap-northeast-1", "198.51.100.1", false, map[string]any{"logGroupName": "prod-nginx-access"}),
		cloudtrailtest.Event("l2", at, alice, "logs.amazonaws.com", "DeleteLogGroup", "ap-northeast-1", "198.51.100.1", false, map[string]any{"logGroupName": "scratch"}),
		cloudtrailtest.Event("sg1", at, alice, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", "ap-northeast-1", "198.51.100.1", false, map[string]any{"groupId": "sg-1",
			"ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "0.0.0.0/0"}}}}}}}),
	)
	e := h.open(t)
	r, err := e.Run(ctx, "security")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range r.Report.Findings.New {
		found = append(found, fmt.Sprintf("%s %s %s", f.Check, f.Key, f.Severity))
	}
	want := "defense_evasion logs:DeleteLogGroup|arn:aws:iam::" + acct + ":user/alice|prod-nginx-access critical;" +
		"defense_evasion logs:DeleteLogGroup|arn:aws:iam::" + acct + ":user/alice|scratch high;" +
		"public_exposure ec2:AuthorizeSecurityGroupIngress|sg-1|tcp/22 0.0.0.0/0 high"
	sort.Strings(found)
	if strings.Join(found, ";") != want {
		t.Fatalf("findings:\n%s\nwant\n%s", strings.Join(found, ";"), want)
	}
}

// collector の日次集計 (送信元・書き込みのリージョン) と秘匿値の名前の取り出しから、principal_new_source / secret_access の判定までを通す (ADR 0027)。
// init で 30 日の平常帯を作り、run の窓で alice が初めての送信元から書き込み、app ロールが秘匿値を一括で読む。
func TestRunNewSourceAndSecretAccess(t *testing.T) {
	h := newHarnessWith(t, "", "  security:\n    window: 24h\n    checks: [principal_new_source, secret_access]\n")
	ctx := context.Background()
	alice := cloudtrailtest.User(acct, "alice")
	app := cloudtrailtest.AssumedRole(acct, "example-app", "task")
	for d := 2; d <= 31; d++ {
		at := h.now.Add(-time.Duration(d) * 24 * time.Hour)
		h.fake.Add(
			cloudtrailtest.Event(fmt.Sprintf("h-r%d", d), at, alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
			cloudtrailtest.Event(fmt.Sprintf("h-w%d", d), at, alice, "ec2.amazonaws.com", "CreateTags", "ap-northeast-1", "203.0.113.1", false, nil),
			cloudtrailtest.Event(fmt.Sprintf("h-s%d", d), at, app, "secretsmanager.amazonaws.com", "GetSecretValue", "ap-northeast-1", "203.0.113.2", true, map[string]any{"secretId": "prod/db"}),
		)
	}
	e := h.open(t)
	if _, err := e.Init(ctx, InitOptions{Window: 32 * 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	at := h.now.Add(-2 * time.Hour)
	for i := 0; i < 6; i++ {
		h.fake.Add(cloudtrailtest.Event(fmt.Sprintf("n-w%d", i), at, alice, "ec2.amazonaws.com", "CreateTags", "ap-northeast-1", "198.51.100.7", false, nil))
	}
	for i := 0; i < 10; i++ {
		h.fake.Add(cloudtrailtest.Event(fmt.Sprintf("n-s%d", i), at, app, "secretsmanager.amazonaws.com", "GetSecretValue", "ap-northeast-1", "203.0.113.2", true, map[string]any{"secretId": fmt.Sprintf("prod/s%02d", i)}))
	}
	h.fake.Add(cloudtrailtest.Event("n-p", at, app, "ssm.amazonaws.com", "GetParametersByPath", "ap-northeast-1", "203.0.113.2", true, map[string]any{"path": "/example/prod/", "recursive": true, "withDecryption": true}))
	h.now = h.now.Add(time.Hour)
	e = h.open(t)
	r, err := e.Run(ctx, "security")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, f := range r.Report.Findings.New {
		found = append(found, fmt.Sprintf("%s %s %s", f.Check, f.Key, f.Severity))
	}
	sort.Strings(found)
	want := "principal_new_source arn:aws:iam::" + acct + ":user/alice medium;secret_access arn:aws:iam::" + acct + ":role/example-app high"
	if strings.Join(found, ";") != want {
		t.Fatalf("findings:\n%s\nwant\n%s", strings.Join(found, ";"), want)
	}
	last, _ := e.Store().RecentRuns(ctx, 1)
	// CloudTrail の収集が成功した run と init には印が付く (導入直後の判定で「収集し終えた日」に数える。ADR 0027)
	runs, _ := e.Store().Runs(ctx, time.Time{}, h.now.Add(time.Hour))
	for _, run := range runs {
		if run.Stats[checks.TrailCollectedStat] != true {
			t.Fatalf("%s run must be marked: %+v", run.Profile, run.Stats)
		}
	}
	if last[0].Stats["secret_read_events"] != float64(11) {
		t.Fatalf("secret_read_events: %+v", last[0].Stats)
	}
	// 同じ窓を daily (既存のチェックすべて) で評価しても、新しく鳴るものは無い (既存のチェックの結果は変わらない)
	r2, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Report.Findings.New) != 0 {
		t.Fatalf("existing checks must not react: %+v", r2.Report.Findings.New)
	}
}

// --profile の値でストアの外のファイルを読ませない。設定に無い profile は「まだ無い」と同じ扱い。
func TestLastReportRejectsUnknownProfile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(secret, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{cfg: &config.Config{Profiles: map[string]config.Profile{"daily": {}}}, st: pathOnlyStore{dir: filepath.Join(dir, "store")}}
	b, err := e.LastReport("../../secret")
	if err != nil || b != nil {
		t.Fatalf("got %q, %v", b, err)
	}
}

type pathOnlyStore struct {
	store.Store
	dir string
}

func (s pathOnlyStore) Path() string { return s.dir }
