package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/report"
)

var day0 = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

func rootLogin(id string, at time.Time) cttypes.Event {
	return cloudtrailtest.Event(id, at, cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "203.0.113.9", false, nil)
}

// 収集に失敗した期間のイベントは、権限が戻った次の run で追いつく (ADR 0038)。
func TestFailedSourceCatchesUp(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	e := h.open(t)
	ctx := context.Background()
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}

	h.now = day0.Add(24 * time.Hour)
	h.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
	r, err := e.Run(ctx, "daily")
	if err != nil || r.Exit != ExitPartial {
		t.Fatalf("%v %+v", err, r)
	}

	// 失敗した run の窓の中の出来事。次の run の窓より前
	h.fake.Err = nil
	h.fake.Add(rootLogin("lost", day0.Add(18*time.Hour)))
	h.now = day0.Add(48 * time.Hour)
	r, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Summary.New == 0 || r.Report.Summary.MaxSeverity != "critical" {
		t.Fatalf("追いついていない: %+v", r.Report.Summary)
	}
	last, _ := e.Store().RecentRuns(ctx, 1)
	if last[0].Stats[catchupStat] == nil {
		t.Fatalf("追いつきが stats に無い: %+v", last[0].Stats)
	}
	if !strings.Contains(h.stderr.String(), CodeSourceCatchup) {
		t.Fatal("追いつきの警告が無い")
	}

	// 追いついたら位置が進み、次の run は普通の窓に戻る
	h.now = day0.Add(72 * time.Hour)
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	last, _ = e.Store().RecentRuns(ctx, 1)
	if last[0].Stats[catchupStat] != nil {
		t.Fatalf("追いつきが続いている: %+v", last[0].Stats)
	}
}

// 初回の run が失敗しても、次の run はその窓の頭から引く。
func TestFirstRunFailureCatchesUp(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	h.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
	e := h.open(t)
	ctx := context.Background()
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	h.fake.Err = nil
	h.fake.Add(rootLogin("lost", day0.Add(-2*time.Hour)))
	h.now = day0.Add(48 * time.Hour)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Summary.New == 0 {
		t.Fatalf("%+v", r.Report.Summary)
	}
}

// 追いつきは max_catchup まで。超えた分は諦めて、そのことを警告する。
func TestCatchupStopsAtMaxCatchup(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	e := h.open(t)
	ctx := context.Background()
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	h.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
	for i := 1; i <= 9; i++ {
		h.now = day0.Add(time.Duration(i) * 24 * time.Hour)
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
	}
	h.fake.Err = nil
	h.stderr.Reset()
	h.now = day0.Add(10 * 24 * time.Hour)
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stderr.String(), CodeSourceCatchupTruncated) {
		t.Fatalf("%s", h.stderr)
	}
}

// 途中で止まった run の finding は、一度も報告していないので次の run で new になる (ADR 0038)。
func TestAbortedRunStillReportsNew(t *testing.T) {
	h := newHarness(t)
	h.now = day0
	h.fake.Add(rootLogin("r1", day0.Add(-2*time.Hour)))
	e := h.open(t)
	ctx := context.Background()
	boom := errors.New("cannot write the output")
	if _, err := e.RunWith(ctx, "daily", func(*report.Report) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	h.now = day0.Add(time.Hour)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Summary.New != 1 || r.Report.Summary.MaxSeverity != "critical" || len(r.Report.AlreadyReported) != 0 {
		t.Fatalf("%+v already=%d", r.Report.Summary, len(r.Report.AlreadyReported))
	}
	// 報告した後は new に戻らない
	h.now = day0.Add(2 * time.Hour)
	r, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Summary.New != 0 {
		t.Fatalf("%+v", r.Report.Summary)
	}
}
