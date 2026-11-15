package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
)

// startOf は lines_total のクエリの StartTime (秒)。
func linesStarts(h *harness) []time.Time {
	var out []time.Time
	for _, in := range h.logs.Started {
		if strings.Contains(*in.QueryString, "as lines_total") {
			out = append(out, time.Unix(*in.StartTime, 0).UTC())
		}
	}
	return out
}

// 決定 (ADR 0065): collect: hourly の cloudwatch-logs は、位置 (読み終えた時) から続きだけを読み、部分の行をストアに残す。
// 位置は「今 − ingest_delay」を切り捨てた時までで、窓の終わりより前でも遅れ (SOURCE_CATCHUP) にしない。collect --incremental も集める。
func TestHourlyLogsSource(t *testing.T) {
	h := newHarnessWith(t, nginxSource+"    collect: hourly\n", "")
	ctx := context.Background()
	h.logs.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 05:00:00.000", "lines_total", "10", "lines_matched", "10")}})
	e := h.open(t)
	h.now = day0 // 09:00
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	// 初回: 窓の始まり (前日 09:00) の日の頭から、09:00 − 5m を切り捨てた 08:00 まで。1 時間ずつ流す (32 本)
	if s := linesStarts(h); len(s) != 32 || !s[0].Equal(day0.Add(-33*time.Hour)) || !s[31].Equal(day0.Add(-2*time.Hour)) {
		t.Fatalf("first starts %v", s)
	}
	rows, hours, err := e.Store().Parts(ctx, "web", "http_lines", day0.Add(-33*time.Hour), day0)
	if err != nil || hours != 32 || len(rows) != 1 {
		t.Fatalf("parts: %d hours, %d rows, %v", hours, len(rows), err)
	}
	// 6 時間後の収集だけの run は 08:00 の続きから
	h.now = day0.Add(6 * time.Hour)
	if _, err := e.CollectIncremental(ctx); err != nil {
		t.Fatal(err)
	}
	if s := linesStarts(h)[32:]; len(s) != 6 || !s[0].Equal(day0.Add(-time.Hour)) {
		t.Fatalf("incremental starts %v", s)
	}
	// 次の daily は 14:00 の続きから。遅れの警告は出ない
	h.stderr.Reset()
	h.now = day0.Add(24 * time.Hour)
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if s := linesStarts(h)[38:]; len(s) != 18 || !s[0].Equal(day0.Add(5*time.Hour)) {
		t.Fatalf("second daily starts %v", s)
	}
	if strings.Contains(h.stderr.String(), CodeSourceCatchup) {
		t.Fatalf("an hourly source behind by less than an hour is not catching up: %s", h.stderr.String())
	}
}

// 収集だけの run も、ソースごとの読み取り量を profile の run と同じ形で stats (bytes_scanned) とログ ("collect ok") に残す。
func TestIncrementalScanStats(t *testing.T) {
	h := newHarnessWith(t, nginxSource+"    collect: hourly\n", "")
	h.logs.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 05:00:00.000", "lines_total", "10", "lines_matched", "10")}, BytesScanned: 2e6})
	e := h.open(t)
	h.now = day0
	if _, err := e.CollectIncremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs, _ := e.Store().RecentRuns(context.Background(), 1)
	scanned, ok := runs[0].Stats["bytes_scanned"].(map[string]any)
	if !ok || scanned["web"].(float64) <= 0 {
		t.Fatalf("stats: %+v", runs[0].Stats)
	}
	if !strings.Contains(h.stderr.String(), `"msg":"collect ok","source":"web"`) || !strings.Contains(h.stderr.String(), `"bytes_scanned":`) {
		t.Fatalf("collect ok must carry bytes_scanned: %s", h.stderr.String())
	}
}
