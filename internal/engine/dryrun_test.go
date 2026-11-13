package engine

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/store/storetest"
)

// scheduled は定時の実行 (書き込む run) を 1 回流す。
func (h *harness) scheduled(t *testing.T, profile string) *RunResult {
	t.Helper()
	e, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx := context.Background()
	r, err := e.Run(ctx, profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return r
}

// dryRun は試しの実行を 1 回流す (CLI と同じく Commit まで呼ぶ)。
func (h *harness) dryRun(t *testing.T, profile string, window time.Duration) *RunResult {
	t.Helper()
	ctx := context.Background()
	e, err := OpenDryRun(ctx, h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r, err := e.RunWithOptions(ctx, profile, RunOptions{DryRun: true, Window: window})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return r
}

// 試しの実行の後、dir:// のストアはファイルが増えも減りもせず 1 バイトも変わらない。出た指摘は報告済みにならず、
// 窓も進まないので、次の定時の実行は試しの実行が無かったときと同じ報告を出す (ADR 0049)。
func TestDryRunLeavesDirStoreUntouched(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	h.scheduled(t, "daily")

	h.now = day0.Add(20 * time.Hour)
	h.fake.Add(rootLogin("r1", h.now.Add(-30*time.Minute)))
	before := storetest.TreeState(t, h.cfg.Store.Dir)
	r := h.dryRun(t, "daily", time.Hour)
	if after := storetest.TreeState(t, h.cfg.Store.Dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("store changed:\nbefore %v\nafter  %v", before, after)
	}
	rep := r.Report
	if !rep.DryRun || rep.Summary.New != 1 || rep.Summary.MaxSeverity != "critical" {
		t.Fatalf("dry run must report the new finding as a dry run: dry_run=%v %+v", rep.DryRun, rep.Summary)
	}
	if rep.Window.From != "2026-10-22T04:00:00Z" || rep.Window.To != "2026-10-22T05:00:00Z" {
		t.Fatalf("window must be [now - window, now): %+v", rep.Window)
	}

	h.now = day0.Add(24 * time.Hour)
	next := h.scheduled(t, "daily").Report
	if next.Summary.New != 1 || next.Window.From != "2026-10-21T09:00:00Z" {
		t.Fatalf("the scheduled run must still report the finding from the previous window end: %+v %+v", next.Summary, next.Window)
	}
	if next.DryRun {
		t.Fatal("a scheduled run is not a dry run")
	}
}

// s3:// のストアでも、試しの実行は何も送らず、オブジェクトは変わらない。
func TestDryRunLeavesS3StoreUntouched(t *testing.T) {
	h := newHarness(t)
	f := useS3(t, h)
	h.now = day0
	h.scheduled(t, "daily")

	h.now = day0.Add(20 * time.Hour)
	h.fake.Add(rootLogin("r1", h.now.Add(-30*time.Minute)))
	before := f.Snapshot()
	f.ResetRequests()
	r := h.dryRun(t, "daily", time.Hour)
	if n := len(f.Requests("PUT")); n != 0 {
		t.Fatalf("dry run sent %d PUT requests", n)
	}
	if after := f.Snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("S3 changed:\nbefore %v\nafter  %v", before, after)
	}
	if !r.Report.DryRun || r.Report.Summary.New != 1 {
		t.Fatalf("%+v", r.Report.Summary)
	}
	h.now = day0.Add(24 * time.Hour)
	if next := h.scheduled(t, "daily").Report; next.Summary.New != 1 {
		t.Fatalf("the scheduled run must still report the finding: %+v", next.Summary)
	}
}

// 窓は now - window から now。前回の window_to からの追いつきも、失敗したソースの追いつきもしない (ingest_delay の再走査は同じ)。
// --window を省いたらプロファイルの window。
func TestDryRunWindow(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	h.scheduled(t, "daily")
	// 失敗した run を挟み、ソースごとの追いつき (ADR 0038) の位置を残す
	h.now = day0.Add(24 * time.Hour)
	h.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
	h.scheduled(t, "daily")
	h.fake.Err = nil

	// 前回から 5 日空いている: 定時の実行なら前回の window_to から引き直し、RUN_MISSED を警告する
	h.now = day0.Add(6 * 24 * time.Hour)
	h.stderr.Reset()
	h.fake.Calls = nil
	r := h.dryRun(t, "daily", 2*time.Hour)
	if len(h.fake.Calls) == 0 {
		t.Fatal("dry run must collect")
	}
	for _, c := range h.fake.Calls {
		if got, want := aws.ToTime(c.StartTime), h.now.Add(-2*time.Hour-15*time.Minute); !got.Equal(want) {
			t.Fatalf("LookupEvents must start at now - window - ingest_delay (%s), got %s", want, got)
		}
	}
	for _, code := range h.logCodes(t) {
		if code == CodeRunMissed || code == CodeSourceCatchup || code == CodeSourceCatchupTruncated {
			t.Fatalf("dry run must not catch up: %s\n%s", code, h.stderr)
		}
	}
	if r.Report.Window.From != "2026-10-27T07:00:00Z" {
		t.Fatalf("%+v", r.Report.Window)
	}

	h.fake.Calls = nil
	r = h.dryRun(t, "daily", 0)
	if r.Report.Window.From != "2026-10-26T09:00:00Z" {
		t.Fatalf("without --window the profile's window is used: %+v", r.Report.Window)
	}
}

// 新規・変化・再発の判定は「定時の実行ならどう出るか」の先取り。短い窓の始まりを再発の境界にすると、
// 前回の run で見た事象が続いているだけで「再発」になる。境界は定時の実行の窓の始まりに合わせる。
func TestDryRunClassifiesLikeTheScheduledRun(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	h.fake.Add(rootLogin("r1", day0.Add(-time.Hour)))
	if r := h.scheduled(t, "daily"); r.Report.Summary.New != 1 {
		t.Fatalf("%+v", r.Report.Summary)
	}
	// 同じ主体・同じ IP の操作が続く
	h.now = day0.Add(20 * time.Hour)
	h.fake.Add(rootLogin("r2", h.now.Add(-30*time.Minute)))
	dry := h.dryRun(t, "daily", time.Hour).Report.Summary
	want := h.scheduled(t, "daily").Report.Summary
	if dry.New != want.New || dry.Changed != want.Changed || dry.Recurred != want.Recurred || dry.StillOpen != want.StillOpen {
		t.Fatalf("dry run %+v\nscheduled %+v", dry, want)
	}
	if dry.Recurred != 0 {
		t.Fatalf("an ongoing finding must not be reported as recurred: %+v", dry)
	}
}

// 試しの実行は複製を開いたエンジンでだけ動く (本番のストアを開いたエンジンに dry-run を頼んでも書かせない)。
// --window は試しの実行でだけ使える。
func TestDryRunGuards(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	e := h.open(t)
	before := storetest.TreeState(t, h.cfg.Store.Dir)
	if _, err := e.RunWithOptions(ctx, "daily", RunOptions{DryRun: true}); err == nil {
		t.Fatal("dry run on a writable engine must fail")
	}
	if _, err := e.RunWithOptions(ctx, "daily", RunOptions{Window: time.Hour}); err == nil {
		t.Fatal("window without dry run must fail")
	}
	if after := storetest.TreeState(t, h.cfg.Store.Dir); !reflect.DeepEqual(before, after) {
		t.Fatal("a refused run must not write")
	}
	e.Close()
	d, err := OpenDryRun(ctx, h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.RunWithOptions(ctx, "daily", RunOptions{}); err == nil {
		t.Fatal("a scratch engine must only run dry runs")
	}
	if _, err := d.RunWithOptions(ctx, "daily", RunOptions{DryRun: true, Window: -time.Hour}); err == nil {
		t.Fatal("a negative window must fail")
	}
}

// 書き込み中の実行がいる間は STORE_LOCKED。試しの実行の間は、定時の実行がストアを開ける。
func TestDryRunLock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	e := h.open(t)
	_, err := OpenDryRun(ctx, h.cfg, h.deps)
	var xe *ExitError
	if !asExit(err, &xe) || xe.Code != CodeStoreLocked {
		t.Fatalf("want STORE_LOCKED, got %v", err)
	}
	e.Close()
	d, err := OpenDryRun(ctx, h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	w, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("the store must be free during a dry run: %v", err)
	}
	w.Close()
}

// レポートの coverage に、見た範囲が定時の実行より狭いことと、日次集計を使うチェックが評価しなかった日を注記する。
func TestDryRunCoverageNotes(t *testing.T) {
	h := newHarnessWith(t, nginxSource, "")
	h.logs.On("as lines_total", linesRows("2026-10-22", 1000, 950))
	h.now = day0
	h.scheduled(t, "daily")

	h.now = day0.Add(20 * time.Hour) // 10-22 05:00。定時なら [10-21 05:00, now) で 10-21 と 10-22 を評価する
	rep := h.dryRun(t, "daily", time.Hour).Report
	notes := strings.Join(rep.Coverage.Notes, "\n")
	for _, want := range []string{"2026-10-21T05:00:00Z", "2026-10-22T04:00:00Z", "login_bruteforce", "2026-10-21"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("notes must mention %q:\n%s", want, notes)
		}
	}
	if len(rep.Coverage.Notes) != 2 {
		t.Fatalf("want 2 notes (range, daily metrics), got:\n%s", notes)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "試しの実行") || !strings.Contains(md, rep.Coverage.Notes[1]) {
		t.Fatalf("report.md must say it is a dry run and carry the notes:\n%s", md)
	}

	// 定時と同じ範囲を見るなら、範囲と日の注記は要らない
	rep = h.dryRun(t, "daily", 0).Report
	if len(rep.Coverage.Notes) != 0 {
		t.Fatalf("no notes when the range matches the scheduled run:\n%s", strings.Join(rep.Coverage.Notes, "\n"))
	}
	// 定時の実行のレポートには注記も dry_run も出ない
	h.now = day0.Add(24 * time.Hour)
	next := h.scheduled(t, "daily").Report
	j, _ := next.JSON()
	if next.DryRun || next.Coverage.Notes != nil || strings.Contains(string(j), "dry_run") || strings.Contains(string(j), `"notes"`) {
		t.Fatalf("a scheduled report must not change:\n%s", j)
	}
}
