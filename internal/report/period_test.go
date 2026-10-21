package report

import (
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

func periodInput() PeriodInput {
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }
	ev := func(id, check, key, class, sev, summary string, at time.Time, profile string) store.FindingEvent {
		return store.FindingEvent{FindingID: id, Check: check, Key: key, Class: class, Severity: sev, Summary: summary, At: at, Profile: profile}
	}
	return PeriodInput{
		Name: "acme", From: "2026-10-01", To: "2026-10-31", Start: day(1, 0), End: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Now: day(31, 23),
		HistorySince: day(5, 9),
		Events: []store.FindingEvent{
			ev("f1", "root_usage", "arn:aws:iam::1:root|203.0.113.1", "new", "critical", "ルートユーザーの利用", day(6, 9), "daily"),
			ev("f2", "posture", "root_mfa", "new", "high", "ルートユーザーに MFA が無い", day(7, 9), "weekly"),
			ev("f3", "ai_path_usage", "arn|ip", "new", "info", "AI 用の主体の利用", day(7, 9), "daily"),
			ev("f4", "guardduty_findings", "g1", "changed", "medium", "GuardDuty: Recon (4 回)", day(14, 9), "weekly"),
			ev("f2", "posture", "root_mfa", "resolved", "high", "ルートユーザーに MFA が無い", day(14, 9), "weekly"),
			ev("f1", "root_usage", "arn:aws:iam::1:root|203.0.113.1", "recurred", "critical", "ルートユーザーの利用", day(20, 9), "daily"),
			ev("f5", "new_principal", "arn:aws:iam::1:user/mallory", "resolved", "medium", "新規の主体", day(21, 3), ""),
		},
		Open: []store.Finding{
			{ID: "f1", Check: "root_usage", Key: "k", Severity: "critical", Summary: "ルートユーザーの利用", Status: "open", FirstSeen: day(6, 9), LastSeen: day(20, 9), LastChanged: day(20, 9)},
			{ID: "f3", Check: "ai_path_usage", Key: "k", Severity: "info", Summary: "info は出さない", Status: "open", FirstSeen: day(7, 9)},
			{ID: "f4", Check: "guardduty_findings", Key: "g1", Severity: "medium", Summary: "GuardDuty: Recon (4 回)", Status: "acked", FirstSeen: day(2, 9)},
		},
		Principals: []store.Principal{{ARN: "arn:aws:iam::111122223333:root", Kind: record.PrincipalUnknown, FirstSeen: day(9, 2), Status: "unknown"}},
		Metrics: []record.Metric{
			{Date: "2026-10-06", Source: "web", Metric: "sign_in_failures", Key: "198.51.100.7", Value: 120},
			{Date: "2026-10-06", Source: "rails", Metric: "sign_in_failures", Key: "198.51.100.8", Value: 3},
			{Date: "2026-10-06", Source: "web", Metric: "probe_paths", Key: "/.env", Value: 9},
			{Date: "2026-10-07", Source: "web", Metric: "probe_hits", Key: "198.51.100.9", Value: 9},
		},
		Runs: []store.Run{
			{ID: "i", Profile: "init", StartedAt: day(5, 9), Status: "ok"},
			{ID: "d1", Profile: "daily", StartedAt: day(6, 9), Status: "ok"},
			{ID: "d2", Profile: "daily", StartedAt: day(7, 9), Status: "partial", Stats: map[string]any{"sources_failed": float64(1)}},
			{ID: "d3", Profile: "daily", StartedAt: day(20, 9), Status: "ok"}, // 7 日〜20 日が空いた
			{ID: "d4", Profile: "daily", StartedAt: day(31, 9), Status: "failed", Stats: map[string]any{"error": "check new_principal: boom"}},
			{ID: "w1", Profile: "weekly", StartedAt: day(7, 9), Status: "ok"},
			{ID: "w2", Profile: "weekly", StartedAt: day(14, 9), Status: "ok"},
			{ID: "w3", Profile: "weekly", StartedAt: day(21, 9), Status: "ok"},
			{ID: "w4", Profile: "weekly", StartedAt: day(28, 9), Status: "ok"},
		},
		Windows: map[string]time.Duration{"daily": 24 * time.Hour, "weekly": 7 * 24 * time.Hour, "hourly": time.Hour},
	}
}

func TestBuildPeriod(t *testing.T) {
	r := BuildPeriod(periodInput())
	if r.Summary.New != 2 || r.Summary.Recurred != 1 || r.Summary.Changed != 1 || r.Summary.Resolved != 2 || r.Summary.Open != 2 {
		t.Fatalf("summary: %+v", r.Summary)
	}
	// 重大度別は新規・再発した finding の重複なし (f1 は new と recurred で 1 件)
	if r.Summary.BySeverity["critical"] != 1 || r.Summary.BySeverity["high"] != 1 || len(r.Summary.BySeverity) != 2 {
		t.Fatalf("by severity: %v", r.Summary.BySeverity)
	}
	if len(r.Notes) != 1 || !strings.HasPrefix(r.Notes[0], "2026-10-05 以前は状態遷移の履歴なし") {
		t.Fatalf("notes: %v", r.Notes)
	}
	var kinds []string
	for _, m := range r.RunsMissing {
		kinds = append(kinds, m.Profile+":"+m.Kind+":"+m.At)
	}
	// hourly は期間内に run が無いので RUN_MISSED にしない。weekly は 28 日から月末まで 2 週間未満なので鳴らない
	if strings.Join(kinds, ",") != "daily:partial:2026-10-07T09:00:00Z,daily:RUN_MISSED:2026-10-07T09:00:00Z,daily:RUN_MISSED:2026-10-20T09:00:00Z,daily:failed:2026-10-31T09:00:00Z" {
		t.Fatalf("runs missing: %v", kinds)
	}
	if strings.Join(r.Metrics.Metrics, ",") != "probe_hits,sign_in_failures" || r.Metrics.Rows[0].Values[1] != 123 {
		t.Fatalf("metrics: %+v", r.Metrics)
	}
	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "period.json", j)
	compareGolden(t, "period.md", []byte(r.Markdown()))

	// 履歴が期間の前から始まっていれば注意書きは無い。run が一度も無ければその旨
	in := periodInput()
	in.HistorySince = in.Start.Add(-time.Hour)
	if r := BuildPeriod(in); len(r.Notes) != 0 || r.HistorySince != "" {
		t.Fatalf("notes: %v", r.Notes)
	}
	in.HistorySince = time.Time{}
	if r := BuildPeriod(in); len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "履歴がまだ無い") {
		t.Fatalf("notes: %v", r.Notes)
	}
}
