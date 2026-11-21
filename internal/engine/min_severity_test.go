package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

// 重大度の下限 (ADR 0082)。1 時間ごとの run は、下限より下の観測を記録せず (報告済みにせず)、daily に新規として残す。
const hourlyMinHigh = `  hourly:
    window: 1h
    min_severity: high
    checks: [root_usage, ecs_exec, unknown_assume_role, oidc_assume_role]
`

// execEvent は ECS Exec (ExecuteCommand) の記録。who が allowlist の主体なら既知 (medium)、そうでなければ知らない主体 (high)。
func execEvent(id string, at time.Time, who cloudtrailtest.Identity, container string) types.Event {
	return cloudtrailtest.Event(id, at, who, "ecs.amazonaws.com", "ExecuteCommand", "ap-northeast-1", "203.0.113.1", false,
		map[string]any{"cluster": "prod-cluster", "container": container, "task": "t-1", "interactive": true, "command": "/bin/sh"})
}

var (
	execKnown   = cloudtrailtest.AssumedRole(acct, "Deploy", "alice")
	execUnknown = cloudtrailtest.User(acct, "example-unknown")
)

func findingsOf(t *testing.T, e *Engine, check string) []store.Finding {
	t.Helper()
	fs, err := e.Store().Findings(context.Background(), check, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// severities は ecs_exec の finding の重大度の並び (daily では new_principal も出るので、この ADR の対象だけを見る)。
func severities(fs []report.Finding) string {
	var out []string
	for _, f := range fs {
		if f.Check == "ecs_exec" {
			out = append(out, f.Check+":"+f.Severity)
		}
	}
	return strings.Join(out, ",")
}

func TestMinSeverityDefersBelowToDaily(t *testing.T) {
	ctx := context.Background()
	h := newHarnessWith(t, "", hourlyMinHigh)
	e := h.open(t)
	start := h.now
	h.fake.Add(
		execEvent("known", start.Add(-30*time.Minute), execKnown, "app"),
		execEvent("unknown", start.Add(-20*time.Minute), execUnknown, "app"),
	)
	res, err := e.Run(ctx, "hourly")
	if err != nil {
		t.Fatal(err)
	}
	rep := res.Report
	if got := severities(rep.Findings.New); got != "ecs_exec:high" {
		t.Fatalf("hourly は high 以上だけを報告する: %s", got)
	}
	if rep.MinSeverity != "high" || rep.Summary.Deferred != 1 {
		t.Fatalf("min_severity と deferred: %q %d", rep.MinSeverity, rep.Summary.Deferred)
	}
	// 下限より下の観測は記録しない (first_seen も reported_at も付かない)
	if fs := findingsOf(t, e, "ecs_exec"); len(fs) != 1 || fs[0].Severity != "high" || fs[0].ReportedAt.IsZero() {
		t.Fatalf("記録されたのは high の 1 件だけ: %+v", fs)
	}

	h.now = start.Add(15 * time.Hour)
	res, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	rep = res.Report
	if got := severities(rep.Findings.New); got != "ecs_exec:medium" {
		t.Fatalf("daily は medium を新規として報告する: %s", got)
	}
	if got := severities(rep.AlreadyReported); got != "ecs_exec:high" {
		t.Fatalf("hourly が報告した high は本日報告済み: %s", got)
	}
	if rep.MinSeverity != "" || rep.Summary.Deferred != 0 {
		t.Fatalf("下限の無いプロファイルには出さない: %q %d", rep.MinSeverity, rep.Summary.Deferred)
	}
}

// 下限より下の観測は ack / snooze の状態も触らない。下限以上に上がれば、今の規則のまま changed として再報告する。
func TestMinSeverityLeavesStateUntouched(t *testing.T) {
	ctx := context.Background()
	h := newHarnessWith(t, "", hourlyMinHigh)
	e := h.open(t)
	start := h.now
	h.fake.Add(execEvent("known", start.Add(-30*time.Minute), execKnown, "app"))
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	fs := findingsOf(t, e, "ecs_exec")
	if len(fs) != 1 || fs[0].Severity != "medium" {
		t.Fatalf("%+v", fs)
	}
	before := fs[0]
	// 同じ Key (同じ日・同じコンテナ) に既知の主体の記録が加わっても、hourly は medium を捨てる (記録を書き換えない)
	h.now = start.Add(time.Hour)
	h.fake.Add(execEvent("known-2", start.Add(30*time.Minute), execKnown, "app"))
	res, err := e.Run(ctx, "hourly")
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Summary.New+res.Report.Summary.Changed != 0 || res.Report.Summary.Deferred != 1 {
		t.Fatalf("%+v", res.Report.Summary)
	}
	after := findingsOf(t, e, "ecs_exec")
	if len(after) != 1 || !after[0].LastSeen.Equal(before.LastSeen) || after[0].Fingerprint != before.Fingerprint {
		t.Fatalf("hourly が下限より下の観測で finding を書き換えた: %+v → %+v", before, after)
	}
}

// 定時の遅れと飛び (ADR 0082 の 4 節)。hourly の窓は前の回の終わりから続き、出来事を取りこぼさず、2 回報告もしない。
func TestMinSeverityHourlyCatchUp(t *testing.T) {
	ctx := context.Background()
	lastHourly := func(t *testing.T, e *Engine) store.Run {
		t.Helper()
		r, err := e.Store().LastRun(ctx, "hourly", nil)
		if err != nil || r == nil {
			t.Fatalf("%v %v", r, err)
		}
		return *r
	}
	unknownExecs := func(t *testing.T, rep *report.Report) int {
		t.Helper()
		n := 0
		for _, f := range rep.Findings.New {
			if f.Check == "ecs_exec" && f.Severity == "high" {
				n++
			}
		}
		return n
	}
	for _, late := range []time.Duration{3 * time.Minute, 19 * time.Minute} {
		t.Run("late "+late.String(), func(t *testing.T) {
			h := newHarnessWith(t, "", hourlyMinHigh)
			e := h.open(t)
			t0 := h.now
			if _, err := e.Run(ctx, "hourly"); err != nil {
				t.Fatal(err)
			}
			// 次の定時が遅れる。前の回の終わり (t0) の直後の出来事も、遅れの間の出来事も、この回で 1 回だけ報告する
			h.fake.Add(
				execEvent("edge", t0.Add(time.Second), execUnknown, "edge"),
				execEvent("late", t0.Add(time.Hour+late/2), execUnknown, "late"),
			)
			h.now = t0.Add(time.Hour + late)
			res, err := e.Run(ctx, "hourly")
			if err != nil {
				t.Fatal(err)
			}
			if r := lastHourly(t, e); !r.WindowFrom.Equal(t0) {
				t.Fatalf("窓は前の回の終わりから: %+v", r)
			}
			if n := unknownExecs(t, res.Report); n != 2 {
				t.Fatalf("遅れた回で 2 件: %d (%s)", n, severities(res.Report.Findings.New))
			}
			// その次は定時どおり (前の回と窓が重なる)。重なりの出来事を 2 回報告しない
			h.now = t0.Add(2 * time.Hour)
			res, err = e.Run(ctx, "hourly")
			if err != nil {
				t.Fatal(err)
			}
			if n := unknownExecs(t, res.Report); n != 0 {
				t.Fatalf("重なりで再報告した: %s", severities(res.Report.Findings.New))
			}
		})
	}
	t.Run("skipped run", func(t *testing.T) {
		h := newHarnessWith(t, "", hourlyMinHigh)
		e := h.open(t)
		t0 := h.now
		if _, err := e.Run(ctx, "hourly"); err != nil {
			t.Fatal(err)
		}
		// t0+1h の定時が飛ぶ。飛んだ時の出来事は t0+2h の回で拾う
		h.fake.Add(execEvent("skipped", t0.Add(30*time.Minute), execUnknown, "app"))
		h.now = t0.Add(2 * time.Hour)
		res, err := e.Run(ctx, "hourly")
		if err != nil {
			t.Fatal(err)
		}
		if r := lastHourly(t, e); !r.WindowFrom.Equal(t0) {
			t.Fatalf("%+v", r)
		}
		if n := unknownExecs(t, res.Report); n != 1 {
			t.Fatalf("飛んだ時の出来事: %s", severities(res.Report.Findings.New))
		}
	})
}

// max_catchup を超えた遅れ (ADR 0082 の 4 節)。超えた分は hourly で評価せず (RUN_MISSED)、記録もしないので、次の daily が新規として報告する。
func TestMinSeverityBeyondMaxCatchupFallsToDaily(t *testing.T) {
	ctx := context.Background()
	h := newHarnessWith(t, "", strings.Replace(hourlyMinHigh, "    min_severity: high\n", "    min_severity: high\n    max_catchup: 3h\n", 1))
	e := h.open(t)
	t0 := h.now
	if _, err := e.Run(ctx, "hourly"); err != nil {
		t.Fatal(err)
	}
	h.fake.Add(execEvent("lost", t0.Add(30*time.Minute), execUnknown, "app"))
	h.now = t0.Add(5 * time.Hour)
	res, err := e.Run(ctx, "hourly")
	if err != nil {
		t.Fatal(err)
	}
	line := h.logLine(t, "RUN_MISSED")
	if line["truncated"] != true {
		t.Fatalf("log: %v", line)
	}
	if res.Report.Summary.New != 0 {
		t.Fatalf("超えた分は hourly では報告しない: %s", severities(res.Report.Findings.New))
	}
	if fs := findingsOf(t, e, "ecs_exec"); len(fs) != 0 {
		t.Fatalf("超えた分を記録した: %+v", fs)
	}
	h.now = t0.Add(6 * time.Hour)
	res, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if got := severities(res.Report.Findings.New); got != "ecs_exec:high" {
		t.Fatalf("daily が新規として報告する: %s", got)
	}
}

// min_severity のプロファイルに state 型のチェックは入れられない (観測を捨てると既存の finding を解消してしまう)。
func TestMinSeverityRejectsStateChecks(t *testing.T) {
	h := newHarnessWith(t, "", `  quick:
    window: 1h
    min_severity: high
    checks: [root_usage, new_principal]
`)
	e := h.open(t)
	_, err := e.Run(context.Background(), "quick")
	if err == nil || !strings.Contains(err.Error(), "min_severity") || !strings.Contains(err.Error(), "new_principal") {
		t.Fatalf("%v", err)
	}
	if got := MinSeverityStateChecks(h.cfg, checks.NewRegistryFor(h.cfg.Checks)); len(got) != 1 || !strings.Contains(got[0], "profile quick") {
		t.Fatalf("%v", got)
	}
}
