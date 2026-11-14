package engine

import (
	"context"
	"testing"
	"time"

	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/store"
)

func TestInitChunks(t *testing.T) {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	got := initChunks(collect.Window{From: now.Add(-3 * 24 * time.Hour), To: now})
	want := []string{"2026-10-18T09:00:00Z..2026-10-19T00:00:00Z", "2026-10-19T00:00:00Z..2026-10-20T00:00:00Z", "2026-10-20T00:00:00Z..2026-10-21T00:00:00Z", "2026-10-21T00:00:00Z..2026-10-21T09:00:00Z"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i, w := range got {
		if s := w.From.Format(time.RFC3339) + ".." + w.To.Format(time.RFC3339); s != want[i] {
			t.Fatalf("chunk %d: %s want %s", i, s, want[i])
		}
	}
	if c := initChunks(collect.Window{From: now, To: now}); len(c) != 0 {
		t.Fatalf("empty window: %v", c)
	}
}

func TestInitStopsAndResumes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	d := func(day, hour int) time.Time { return time.Date(2026, 10, day, hour, 0, 0, 0, time.UTC) }
	h.fake.Add(
		cloudtrailtest.Event("e18", d(18, 12), cloudtrailtest.User(acct, "alice"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
		cloudtrailtest.Event("e20", d(20, 12), cloudtrailtest.User(acct, "bob"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.2", true, nil),
		cloudtrailtest.Event("e21", d(21, 8), cloudtrailtest.User(acct, "carol"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.3", true, nil),
	)
	// 10-20 の日でスロットルが収まらず止まる
	failing := true
	h.fake.ErrFor = func(in *ct.LookupEventsInput) error {
		if failing && !in.StartTime.Before(d(20, 0)) {
			return cloudtrailtest.APIError{Code: "AccessDeniedException"}
		}
		return nil
	}
	e := h.open(t)
	res, err := e.Init(ctx, InitOptions{Window: 3 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete || res.ChunksDone != 2 || res.ChunksTotal != 4 || !res.DoneUntil.Equal(d(20, 0)) || len(res.SourcesFailed) != 1 {
		t.Fatalf("init must stop at the failing day: %+v", res)
	}
	r, _ := e.Store().LastRun(ctx, InitProfile, nil)
	if r.Status != "partial" || r.Stats["chunks_done"] != float64(2) || r.Stats["done_until"] != "2026-10-20T00:00:00Z" || r.Stats["failed_chunk"] != "2026-10-20T00:00:00Z" {
		t.Fatalf("run progress: %+v", r)
	}
	ps, _ := e.Store().Principals(ctx, store.PrincipalFilter{Statuses: []string{store.PrincipalBaseline}})
	if len(ps) != 1 || ps[0].ARN != "arn:aws:iam::"+acct+":user/alice" {
		t.Fatalf("days before the failure are kept: %+v", ps)
	}

	// 再開: 失敗した日の頭から、再開時点まで
	failing = false
	h.now = h.now.Add(2 * time.Hour)
	h.fake.Add(cloudtrailtest.Event("e21b", d(21, 10), cloudtrailtest.User(acct, "dave"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.4", true, nil))
	calls := len(h.fake.Calls)
	res, err = e.Init(ctx, InitOptions{Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete || !res.Resumed || res.ChunksDone != 4 || res.RunID != r.ID {
		t.Fatalf("resume: %+v", res)
	}
	if first := h.fake.Calls[calls]; !first.StartTime.Equal(d(20, 0)) {
		t.Fatalf("resume must restart at the failed day: %v", first.StartTime)
	}
	r, _ = e.Store().LastRun(ctx, InitProfile, nil)
	if r.Status != "ok" || !r.WindowTo.Equal(h.now) || r.Stats["chunks_total"] != float64(4) {
		t.Fatalf("finished run: %+v", r)
	}
	ps, _ = e.Store().Principals(ctx, store.PrincipalFilter{Statuses: []string{store.PrincipalBaseline}})
	if len(ps) != 4 {
		t.Fatalf("all baseline principals: %+v", ps)
	}
	// 完了後の --resume は何もしない
	if res, _ := e.Init(ctx, InitOptions{Resume: true}); !res.NothingToResume {
		t.Fatalf("%+v", res)
	}
	// 止まった init は、失敗の ERROR と、続きからやり直す案内の WARN (INIT_INCOMPLETE) を出す
	if codes := h.logCodes(t); len(codes) != 2 || codes[0] != "ACCESS_DENIED" || codes[1] != "INIT_INCOMPLETE" {
		t.Fatalf("codes: %v", codes)
	}
}

func TestInitInterrupted(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	h.fake.ErrFor = func(in *ct.LookupEventsInput) error {
		n++
		if n == 3 { // 2 日目の最初のリージョンで Ctrl-C
			cancel()
			return context.Canceled
		}
		return nil
	}
	e := h.open(t)
	res, err := e.Init(ctx, InitOptions{Window: 2 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete || res.ChunksDone != 1 {
		t.Fatalf("%+v", res)
	}
	r, _ := e.Store().LastRun(context.Background(), InitProfile, nil)
	if r.Status != "partial" || r.Stats["interrupted"] != true {
		t.Fatalf("interrupted run must be recorded: %+v", r)
	}
	// 中断した run は --resume で続けられる
	h.fake.ErrFor = nil
	res, err = e.Init(context.Background(), InitOptions{Resume: true})
	if err != nil || !res.Complete {
		t.Fatalf("%+v %v", res, err)
	}
}

// 作ったばかりのロググループをソースにして init しても、作成より前の日は「データなし」として進み、止まらない。
func TestInitLogGroupCreatedRecently(t *testing.T) {
	h := newHarnessWith(t, nginxSource, "")
	ctx := context.Background()
	h.logs.Groups = map[string]cwlogstest.Group{"/app/nginx": {Created: h.now.Add(-time.Hour)}}
	h.logs.Now = func() time.Time { return h.now }
	h.logs.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "lines_total", "10", "lines_matched", "10")}})
	e := h.open(t)
	res, err := e.Init(ctx, InitOptions{Window: 3 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete || len(res.SourcesFailed) != 0 {
		t.Fatalf("init must finish: %+v", res)
	}
	r, _ := e.Store().LastRun(ctx, InitProfile, nil)
	oor, _ := r.Stats["logs_out_of_range"].(map[string]any)
	days, _ := oor["web"].([]any)
	if r.Status != "ok" || len(days) != 3 || days[0] != "2026-10-18" || days[2] != "2026-10-20" {
		t.Fatalf("skipped days must be recorded: %+v", r.Stats)
	}
	// 飛ばした日は metrics を持たない (min_baseline_days の「データのある日」に数えない)
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: "lines_total"})
	if len(ms) != 1 || ms[0].Date != "2026-10-21" {
		t.Fatalf("metrics: %+v", ms)
	}
	if codes := h.logCodes(t); len(codes) != 0 {
		t.Fatalf("no error codes: %v", codes)
	}
}
