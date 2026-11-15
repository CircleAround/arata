package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// arata collect --incremental (ADR 0064): 評価も報告もせず、全プロファイルが要る CloudTrail のソースの続きだけを位置から集める。
// 位置が無ければ、そのソースを要るプロファイルの最も長い窓の分。集めた位置は profile の run が共有して、読み直さない。
func TestCollectIncremental(t *testing.T) {
	h := newHarnessWith(t, "", hourlyRootProfile)
	ctx := context.Background()
	e := h.open(t)
	h.now = day0
	cr, err := e.CollectIncremental(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.SourcesOK) != 1 || cr.SourcesOK[0] != "trail" {
		t.Fatalf("sources = %+v", cr)
	}
	// 位置が無い: daily の窓 (24h) の分を、ingest_delay 前の時の頭から
	if want := day0.Add(-24*time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) {
		t.Fatalf("first incremental starts at %v, want %v", lastStart(h), want)
	}
	// 6 時間後: 続きだけ
	h.now = day0.Add(6 * time.Hour)
	if _, err := e.CollectIncremental(ctx); err != nil {
		t.Fatal(err)
	}
	if want := day0.Add(-15 * time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) {
		t.Fatalf("second incremental starts at %v, want %v", lastStart(h), want)
	}
	// daily (初回) は、収集だけの run が読み終えた所を読み直さない
	calls := len(h.fake.Calls)
	h.now = day0.Add(6*time.Hour + 5*time.Minute)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if want := day0.Add(6*time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) || len(h.fake.Calls)-calls != 2 {
		t.Fatalf("daily starts at %v (want %v), calls %d", lastStart(h), want, len(h.fake.Calls)-calls)
	}
	if r.Exit != ExitOK {
		t.Fatalf("exit = %d", r.Exit)
	}
	// 収集だけの run は報告を作らない (aratam が送らない)
	if _, err := e.Store().LastRun(ctx, collectIncrementalProfile, nil); err != nil {
		t.Fatal(err)
	}
}

// max_collect: 1 回に集める範囲の上限。上限まで集めて位置を進め、partial にして SOURCE_COLLECT_LIMITED を出す。次の回が続きから集める。
func TestMaxCollect(t *testing.T) {
	h := newHarnessWith(t, "", hourlyRootProfile)
	h.cfg.Sources[0].MaxCollect = 12 * time.Hour
	ctx := context.Background()
	e := h.open(t)
	h.now = day0
	if _, err := e.CollectIncremental(ctx); err != nil { // 24h 分は上限を超える
		t.Fatal(err)
	}
	start := day0.Add(-24*time.Hour - 15*time.Minute).Truncate(time.Hour)
	last := h.fake.Calls[len(h.fake.Calls)-1]
	if !aws.ToTime(last.StartTime).Equal(start) || !aws.ToTime(last.EndTime).Equal(day0.Add(-12*time.Hour)) {
		t.Fatalf("limited range = %v - %v", aws.ToTime(last.StartTime), aws.ToTime(last.EndTime))
	}
	if !strings.Contains(h.stderr.String(), CodeSourceCollectLimited) {
		t.Fatalf("want %s: %s", CodeSourceCollectLimited, h.stderr.String())
	}
	runs, _ := e.Store().RecentRuns(ctx, 1)
	if runs[0].Status != "partial" {
		t.Fatalf("status = %s", runs[0].Status)
	}
	// 次の回は、上限で止めた所の続きから (ingest_delay 前の時の頭)
	h.now = day0.Add(10 * time.Minute)
	if _, err := e.CollectIncremental(ctx); err != nil {
		t.Fatal(err)
	}
	if want := day0.Add(-12*time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) {
		t.Fatalf("continues from %v, want %v", lastStart(h), want)
	}
	// profile の run でも同じ上限が効き、報告の coverage.notes に出る
	h.now = day0.Add(48 * time.Hour)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitPartial || !strings.Contains(strings.Join(r.Report.Coverage.Notes, "\n"), "max_collect") {
		t.Fatalf("exit = %d, notes = %v", r.Exit, r.Report.Coverage.Notes)
	}
}
