package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

const hourlyRootProfile = "  hourly:\n    window: 1h\n    checks: [root_usage]\n"

// lastStart は fake が最後に受けた LookupEvents の StartTime。
func lastStart(h *harness) time.Time {
	return *h.fake.Calls[len(h.fake.Calls)-1].StartTime
}

// 決定 (ADR 0064): ソースの位置はプロファイルをまたいで共有する。hourly が読み続けた CloudTrail を、daily は読み直さない
// (位置 − ingest_delay の時の頭から続きだけを読む)。読み飛ばすのは、途切れずに読めている始まり (source_covered_from) が daily の窓を覆うときだけ。
// 主体の活動の集計は時ごとなので、daily が続きだけを読んでも日の値はその日の全件。
func TestSharedPositionsAcrossProfiles(t *testing.T) {
	h := newHarnessWith(t, "", hourlyRootProfile)
	ctx := context.Background()
	e := h.open(t)
	alice := cloudtrailtest.User(acct, "alice")
	run := func(profile string) {
		t.Helper()
		if _, err := e.Run(ctx, profile); err != nil {
			t.Fatal(err)
		}
	}
	// 1 日目: daily (初回)。窓の頭から読む
	h.now = day0
	run("daily")
	if want := day0.Add(-24*time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) {
		t.Fatalf("first daily starts at %v, want %v", lastStart(h), want)
	}
	// その後の 24 時間、hourly が毎時読む。alice が毎時 1 回呼ぶ
	for i := 1; i <= 24; i++ {
		h.fake.Add(cloudtrailtest.Event(fmt.Sprintf("a%02d", i), day0.Add(time.Duration(i)*time.Hour-10*time.Minute), alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.2", true, nil))
		h.now = day0.Add(time.Duration(i) * time.Hour)
		run("hourly")
		// hourly は前の位置 (daily・hourly のどちらが進めたものでも) − ingest_delay の時の頭から読む
		if want := h.now.Add(-time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) {
			t.Fatalf("hourly %d starts at %v, want %v", i, lastStart(h), want)
		}
	}
	// 2 日目の daily: CloudTrail は hourly が読み終えているので、続きだけを読む
	calls := len(h.fake.Calls)
	h.now = day0.Add(24*time.Hour + 5*time.Minute)
	run("daily")
	if want := day0.Add(24*time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) || len(h.fake.Calls)-calls != 2 {
		t.Fatalf("second daily starts at %v (want %v), calls %d", lastStart(h), want, len(h.fake.Calls)-calls)
	}
	// 日の値は、時ごとの値の和 (その日の全件)。前の版では、最後に引いた run が見た件数だった
	ms, err := e.Store().Metrics(ctx, store.MetricFilter{Metric: record.MetricPrincipalSource, From: day0.Format(record.DateLayout), To: day0.Format(record.DateLayout)})
	if err != nil {
		t.Fatal(err)
	}
	// day0 (09:00 UTC) の日に入るのは a01〜a14 (09:50〜23:50) と、daily 前の分は無い
	if len(ms) != 1 || ms[0].Value != 15 {
		t.Fatalf("principal_source of the day = %+v, want 15", ms)
	}
}

// 決定 (ADR 0064): イベント型のチェックの「遅れて届いたもの」は、このプロファイルの前回の評価の後に保存したもの。
// 別のプロファイルの run が先に拾っても、daily が 1 回だけ評価する。
func TestLateEventCollectedByAnotherProfile(t *testing.T) {
	h := newHarnessWith(t, "", hourlyRootProfile)
	ctx := context.Background()
	e := h.open(t)
	h.now = day0
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	// daily の窓の終わりの 5 分前に起きて、遅れて記録された IAM の変更。hourly (iam_changes を見ない) が先に拾う
	h.fake.Add(cloudtrailtest.Event("late", day0.Add(-5*time.Minute), cloudtrailtest.User(acct, "mallory"), "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.7", false,
		map[string]any{"userName": "backdoor"}))
	h.now = day0.Add(30 * time.Minute)
	if _, err := e.Run(ctx, "hourly"); err != nil {
		t.Fatal(err)
	}
	h.now = day0.Add(24 * time.Hour)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range r.Report.Findings.New {
		if f.Check == "iam_changes" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("the late IAM change should be evaluated once by daily: %+v", r.Report.Findings.New)
	}
	// 次の daily では、もう評価しない (前回の評価の前に保存したもの)
	h.now = day0.Add(48 * time.Hour)
	r, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Report.Findings.New {
		if f.Check == "iam_changes" {
			t.Fatalf("evaluated again: %+v", f)
		}
	}
}

// 途切れずに読めている始まりが窓を覆わない (hourly を始めたばかり) なら、daily は今までどおり窓の頭から読む。
func TestSharedPositionNeedsContiguousCoverage(t *testing.T) {
	h := newHarnessWith(t, "", hourlyRootProfile)
	ctx := context.Background()
	e := h.open(t)
	h.now = day0
	if _, err := e.Run(ctx, "hourly"); err != nil {
		t.Fatal(err)
	}
	h.now = day0.Add(time.Hour)
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if want := h.now.Add(-24*time.Hour - 15*time.Minute).Truncate(time.Hour); !lastStart(h).Equal(want) {
		t.Fatalf("daily starts at %v, want %v (hourly covered only its last hour)", lastStart(h), want)
	}
}
