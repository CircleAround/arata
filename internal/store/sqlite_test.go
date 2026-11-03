package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
)

func open(t *testing.T) (*Dir, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dir
}

var ts = time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)

func TestLock(t *testing.T) {
	_, dir := open(t)
	if _, err := Open(dir); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestReopenKeepsSchema(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
}

func TestRuns(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	if r, err := st.LastRun(ctx, "daily", nil); err != nil || r != nil {
		t.Fatalf("expected no run: %v %v", r, err)
	}
	r := Run{ID: "r1", Profile: "daily", WindowFrom: ts.Add(-24 * time.Hour), WindowTo: ts, StartedAt: ts, Status: "running"}
	if err := st.BeginRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishRun(ctx, "r1", "ok", map[string]any{"events": 3}); err != nil {
		t.Fatal(err)
	}
	got, err := st.LastRun(ctx, "daily", nil)
	if err != nil || got == nil {
		t.Fatalf("%v %v", got, err)
	}
	if err := st.BeginRun(ctx, Run{ID: "r2", Profile: "daily", WindowFrom: ts, WindowTo: ts.Add(time.Hour), StartedAt: ts.Add(time.Hour), Status: "running"}); err != nil {
		t.Fatal(err)
	}
	_ = st.FinishRun(ctx, "r2", "failed", nil)
	if r, _ := st.LastRun(ctx, "daily", nil); r.ID != "r2" {
		t.Fatalf("latest regardless of status: %+v", r)
	}
	if r, _ := st.LastRun(ctx, "daily", []string{"ok", "partial"}); r.ID != "r1" {
		t.Fatalf("latest ok/partial: %+v", r)
	}
	if r, _ := st.LastRun(ctx, "hourly", nil); r != nil {
		t.Fatalf("other profile: %+v", r)
	}
	if got.Status != "ok" || got.FinishedAt.IsZero() || got.Stats["events"] != float64(3) || !got.WindowTo.Equal(ts) {
		t.Fatalf("unexpected run: %+v", got)
	}
}

func TestAppendRaw(t *testing.T) {
	st, dir := open(t)
	ctx := context.Background()
	rec := record.PrincipalSeen{Time: ts, FirstTime: ts, Source: "trail", ARN: "arn:aws:iam::1:root", Kind: record.PrincipalRoot, Count: 1}
	for i := 0; i < 2; i++ {
		if err := st.AppendRaw(ctx, "trail", rec); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "raw", "trail", "2026-10-21.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"kind":"principal_seen"`) {
		t.Fatalf("unexpected jsonl: %q", string(b))
	}
}

func TestPrincipals(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	p := record.PrincipalSeen{Time: ts, FirstTime: ts.Add(-time.Hour), Source: "trail", ARN: "arn:aws:iam::1:user/a", Kind: record.PrincipalUser, IP: "203.0.113.1", Count: 2}
	if err := st.UpsertPrincipalSeen(ctx, p, PrincipalBaseline); err != nil {
		t.Fatal(err)
	}
	// 2 回目: last_seen が伸び、status は変わらず、IP の count が足される
	p2 := p
	p2.Time = ts.Add(2 * time.Hour)
	p2.FirstTime = ts.Add(time.Hour)
	p2.Count = 3
	if err := st.UpsertPrincipalSeen(ctx, p2, PrincipalUnknown); err != nil {
		t.Fatal(err)
	}
	// 別 IP
	p3 := p2
	p3.IP = "198.51.100.9"
	p3.Count = 1
	if err := st.UpsertPrincipalSeen(ctx, p3, PrincipalUnknown); err != nil {
		t.Fatal(err)
	}
	ps, err := st.Principals(ctx, PrincipalFilter{})
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %v", ps, err)
	}
	if ps[0].Status != PrincipalBaseline || !ps[0].FirstSeen.Equal(ts.Add(-time.Hour)) || !ps[0].LastSeen.Equal(ts.Add(2*time.Hour)) || ps[0].Kind != record.PrincipalUser {
		t.Fatalf("unexpected principal: %+v", ps[0])
	}
	ips, err := st.PrincipalIPs(ctx, p.ARN)
	if err != nil || len(ips) != 2 {
		t.Fatalf("%v %v", ips, err)
	}
	for _, ip := range ips {
		if ip.IP == "203.0.113.1" && ip.Count != 5 {
			t.Fatalf("count not summed: %+v", ip)
		}
	}
	if err := st.SetPrincipalStatus(ctx, p.ARN, PrincipalApproved); err != nil {
		t.Fatal(err)
	}
	ps, _ = st.Principals(ctx, PrincipalFilter{Statuses: []string{PrincipalApproved}})
	if len(ps) != 1 {
		t.Fatalf("status filter: %v", ps)
	}
	ps, _ = st.Principals(ctx, PrincipalFilter{Statuses: []string{PrincipalUnknown}})
	if len(ps) != 0 {
		t.Fatalf("status filter: %v", ps)
	}
}

func TestEvents(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	evs := []record.TrailEvent{
		{EventID: "e1", Time: ts, Source: "trail", Name: "ConsoleLogin", EventSource: "signin.amazonaws.com", PrincipalARN: "arn:aws:iam::1:root", PrincipalKind: record.PrincipalRoot, IP: "203.0.113.1", Region: "us-east-1", Data: map[string]any{"mfa": "Yes"}},
		{EventID: "e2", Time: ts.Add(time.Minute), Source: "trail", Name: "AttachUserPolicy", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/a", PrincipalKind: record.PrincipalUser, Resource: "arn:aws:iam::1:user/b"},
		{EventID: "e3", Time: ts.Add(2 * time.Minute), Source: "trail", Name: "GetUser", EventSource: "iam.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/a", PrincipalKind: record.PrincipalUser, ReadOnly: true, ErrorCode: "AccessDenied"},
		{EventID: "e4", Time: ts.Add(48 * time.Hour), Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "arn:aws:iam::1:user/a", PrincipalKind: record.PrincipalUser},
	}
	for _, e := range evs {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// 重複は無視
	if err := st.InsertEvent(ctx, evs[0]); err != nil {
		t.Fatal(err)
	}
	from, to := ts.Add(-time.Hour), ts.Add(time.Hour)
	cases := []struct {
		name string
		f    EventFilter
		want []string
	}{
		{"all in window", EventFilter{}, []string{"e1", "e2", "e3"}},
		{"by kind", EventFilter{PrincipalKinds: []record.PrincipalKind{record.PrincipalRoot}}, []string{"e1"}},
		{"by source write only", EventFilter{EventSources: []string{"iam.amazonaws.com"}, WriteOnly: true}, []string{"e2"}},
		{"by name", EventFilter{Names: []string{"GetUser", "ConsoleLogin"}}, []string{"e1", "e3"}},
		{"by prefix", EventFilter{NamePrefixes: []string{"Attach"}}, []string{"e2"}},
		{"by error code", EventFilter{ErrorCodes: []string{"AccessDenied", "UnauthorizedOperation"}}, []string{"e3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.Events(ctx, from, to, tc.f)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, 0, len(got))
			for _, e := range got {
				ids = append(ids, e.EventID)
			}
			if strings.Join(ids, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v want %v", ids, tc.want)
			}
		})
	}
	got, _ := st.Events(ctx, from, to, EventFilter{Names: []string{"ConsoleLogin"}})
	if got[0].Data["mfa"] != "Yes" || got[0].IP != "203.0.113.1" || !got[0].Time.Equal(ts) {
		t.Fatalf("round trip: %+v", got[0])
	}
}

func TestFindings(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	f := Finding{ID: "f1", Check: "root_usage", Key: "arn:aws:iam::1:root|203.0.113.1", Severity: "critical", Summary: "root used",
		FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen, Fingerprint: "critical|203.0.113.1", Data: map[string]any{"count": 1}}
	if err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	f.Data["count"] = 2
	f.LastSeen = ts.Add(time.Hour)
	if err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	all, err := st.Findings(ctx, "", nil)
	if err != nil || len(all) != 1 {
		t.Fatalf("%v %v", all, err)
	}
	if all[0].Fingerprint != "critical|203.0.113.1" || all[0].Data["count"] != float64(2) || !all[0].ReportedAt.IsZero() || !all[0].LastSeen.Equal(ts.Add(time.Hour)) {
		t.Fatalf("unexpected: %+v", all[0])
	}
	if err := st.MarkReported(ctx, []string{"f1"}, ts.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	all, _ = st.Findings(ctx, "root_usage", []string{FindingOpen})
	if len(all) != 1 || !all[0].ReportedAt.Equal(ts.Add(2*time.Hour)) {
		t.Fatalf("reported_at: %+v", all)
	}
	if got, _ := st.Findings(ctx, "root_usage", []string{FindingResolved}); len(got) != 0 {
		t.Fatalf("status filter: %v", got)
	}
	if got, _ := st.Findings(ctx, "other", nil); len(got) != 0 {
		t.Fatalf("check filter: %v", got)
	}
}

func TestMetrics(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	ms := []record.Metric{
		{Date: "2026-10-20", Source: "nginx", From: record.KindHTTPAccess, Metric: "sign_in_failures", Key: "198.51.100.7", Value: 3},
		{Date: "2026-10-21", Source: "nginx", From: record.KindHTTPAccess, Metric: "sign_in_failures", Key: "198.51.100.7", Value: 5},
		{Date: "2026-10-21", Source: "nginx", From: record.KindHTTPAccess, Metric: "sign_in_failures", Key: "198.51.100.7", Value: 9}, // 置き換え
		{Date: "2026-10-21", Source: "alb", From: record.KindHTTPAccess, Metric: "sign_in_failures", Key: "198.51.100.7", Value: 1},
		{Date: "2026-10-21", Source: "nginx", From: record.KindHTTPAccess, Metric: "probe_hits", Key: "198.51.100.8", Value: 4},
	}
	for _, m := range ms {
		if err := st.UpsertMetric(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Metrics(ctx, MetricFilter{Metric: "sign_in_failures", From: "2026-10-21", To: "2026-10-21"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Source != "alb" || got[1].Value != 9 || got[1].From != record.KindHTTPAccess {
		t.Fatalf("metrics: %+v", got)
	}
	got, _ = st.Metrics(ctx, MetricFilter{Metric: "sign_in_failures", Sources: []string{"nginx"}})
	if len(got) != 2 || got[0].Date != "2026-10-20" {
		t.Fatalf("metrics by source: %+v", got)
	}
}

func TestRecentRuns(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		id := string(rune('a' + i))
		if err := st.BeginRun(ctx, Run{ID: id, Profile: "daily", WindowFrom: ts, WindowTo: ts, StartedAt: ts.Add(time.Duration(i) * time.Hour), Status: "running"}); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			if err := st.FinishRun(ctx, id, "ok", map[string]any{"match_rates": map[string]any{"nginx": 0.9}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	rs, err := st.RecentRuns(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].ID != "b" || rs[0].Stats["match_rates"] == nil {
		t.Fatalf("recent runs (unfinished excluded, newest first): %+v", rs)
	}
}

func TestFindingStatus(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	f := Finding{ID: "f1", Check: "new_principal", Key: "arn:x", Severity: "medium", FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen}
	if err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Finding(ctx, "nope"); err != nil || got != nil {
		t.Fatalf("missing: %v %v", got, err)
	}
	until := ts.Add(72 * time.Hour)
	if err := st.SetFindingStatus(ctx, "f1", FindingSnoozed, until, ts.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Finding(ctx, "f1")
	if got.Status != FindingSnoozed || !got.SnoozeUntil.Equal(until) || !got.LastChanged.Equal(ts.Add(time.Hour)) {
		t.Fatalf("%+v", got)
	}
	if err := st.SetFindingStatus(ctx, "f1", FindingAcked, until, ts); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Finding(ctx, "f1"); got.Status != FindingAcked || !got.SnoozeUntil.IsZero() {
		t.Fatalf("snooze_until must be cleared: %+v", got)
	}
	if err := st.SetFindingStatus(ctx, "nope", FindingAcked, time.Time{}, ts); err == nil {
		t.Fatal("unknown id must fail")
	}
}

func TestUpdateRun(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	_ = st.BeginRun(ctx, Run{ID: "i", Profile: "init", WindowFrom: ts, WindowTo: ts.Add(time.Hour), StartedAt: ts, Status: "running"})
	_ = st.FinishRun(ctx, "i", "partial", map[string]any{"chunks_done": 1})
	if err := st.UpdateRun(ctx, "i", ts.Add(5*time.Hour), map[string]any{"chunks_done": 2}); err != nil {
		t.Fatal(err)
	}
	r, _ := st.LastRun(ctx, "init", nil)
	if r.Status != "running" || !r.WindowTo.Equal(ts.Add(5*time.Hour)) || r.Stats["chunks_done"] != float64(2) || !r.FinishedAt.IsZero() {
		t.Fatalf("%+v", r)
	}
}

// 遅れて届いたイベント (ADR 0013): [LateFrom, from) のうち collected_at >= CollectedSince のものも返す。
func TestEventsLate(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	prev, now := ts, ts.Add(time.Hour) // 前回の収集と今回の収集
	for _, e := range []record.TrailEvent{
		{EventID: "old-overlap", Time: ts.Add(-5 * time.Minute), Name: "AssumeRole", CollectedAt: prev},
		{EventID: "late-overlap", Time: ts.Add(-3 * time.Minute), Name: "AssumeRole", CollectedAt: now},
		{EventID: "late-too-old", Time: ts.Add(-30 * time.Minute), Name: "AssumeRole", CollectedAt: now},
		{EventID: "in-window", Time: ts.Add(10 * time.Minute), Name: "AssumeRole", CollectedAt: prev},
	} {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// 再走査で同じイベントをもう一度入れても collected_at は最初の収集のまま
	if err := st.InsertEvent(ctx, record.TrailEvent{EventID: "old-overlap", Time: ts.Add(-5 * time.Minute), Name: "AssumeRole", CollectedAt: now}); err != nil {
		t.Fatal(err)
	}
	ids := func(f EventFilter) string {
		got, err := st.Events(ctx, ts, now, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range got {
			out = append(out, e.EventID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(EventFilter{}); got != "in-window" {
		t.Fatalf("without late filter: %s", got)
	}
	if got := ids(EventFilter{LateFrom: ts.Add(-15 * time.Minute), CollectedSince: now}); got != "late-overlap,in-window" {
		t.Fatalf("with late filter: %s", got)
	}
}

func TestMigrateAddsCollectedAt(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// schema version 2 (collected_at 列が無い) の DB を模す
	if _, err := st.db.Exec(`ALTER TABLE events DROP COLUMN collected_at`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_version SET version=2`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO events(event_id, time, source, name) VALUES ('e-old', ?, 'trail', 'AssumeRole')`, fmtTime(ts)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	// 移行前のイベントは「前回までに収集済み」として扱う
	got, err := st.Events(ctx, ts.Add(time.Minute), ts.Add(time.Hour), EventFilter{LateFrom: ts.Add(-time.Minute), CollectedSince: ts})
	if err != nil || len(got) != 0 {
		t.Fatalf("pre-migration events must not count as late: %v %v", got, err)
	}
	if err := st.InsertEvent(ctx, record.TrailEvent{EventID: "e-new", Time: ts, Name: "AssumeRole", CollectedAt: ts.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

// 再走査の区間の件数 (RescanCount) は、(arn, ip) の行を初めて作るときだけ数える (ADR 0013)。既にある行には前回の run で数え済みなので足さない。
func TestPrincipalSeenRescanCount(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	arn := "arn:aws:iam::1:user/a"
	seen := func(ip string, count, rescan int) {
		t.Helper()
		if err := st.UpsertPrincipalSeen(ctx, record.PrincipalSeen{ARN: arn, Kind: record.PrincipalUser, IP: ip, Time: ts, FirstTime: ts, Count: count, RescanCount: rescan}, PrincipalUnknown); err != nil {
			t.Fatal(err)
		}
	}
	seen("203.0.113.1", 2, 0)
	seen("203.0.113.1", 3, 2) // 既存の行: 重なり分は前回数え済み
	seen("203.0.113.2", 0, 1) // 新しい行: 重なり区間でだけ見えた
	ips, err := st.PrincipalIPs(ctx, arn)
	if err != nil || len(ips) != 2 {
		t.Fatalf("%+v %v", ips, err)
	}
	got := map[string]int{}
	for _, ip := range ips {
		got[ip.IP] = ip.Count
	}
	if got["203.0.113.1"] != 5 || got["203.0.113.2"] != 1 {
		t.Fatalf("counts: %v", got)
	}
}

func TestSnapshot(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	item := func(key string, v any) record.SnapshotItem {
		return record.SnapshotItem{Kind: record.KindPostureItem, Source: "posture", Key: key, Data: map[string]any{"v": v}}
	}
	if items, err := st.Snapshot(ctx, record.KindPostureItem); err != nil || len(items) != 0 {
		t.Fatalf("empty: %v %v", items, err)
	}
	if err := st.ReplaceSnapshot(ctx, record.KindPostureItem, "posture", []record.SnapshotItem{item("b", 1), item("a", "x")}, ts); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceSnapshot(ctx, record.KindGuardDuty, "gd", []record.SnapshotItem{{Kind: record.KindGuardDuty, Key: "f1"}}, ts); err != nil {
		t.Fatal(err)
	}
	items, err := st.Snapshot(ctx, record.KindPostureItem)
	if err != nil || len(items) != 2 || items[0].Key != "a" || items[0].String("v") != "x" || items[1].Number("v") != 1 || !items[0].Time.Equal(ts) || items[0].Source != "posture" {
		t.Fatalf("snapshot: %+v %v", items, err)
	}
	// 丸ごと置き換える (無くなった項目は消える)。空でも置き換える
	if err := st.ReplaceSnapshot(ctx, record.KindPostureItem, "posture", nil, ts.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if items, _ := st.Snapshot(ctx, record.KindPostureItem); len(items) != 0 {
		t.Fatalf("replaced: %+v", items)
	}
	if items, _ := st.Snapshot(ctx, record.KindGuardDuty); len(items) != 1 {
		t.Fatalf("other kinds stay: %+v", items)
	}
}

func TestFindingEventsAndHistory(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	if h, err := st.HistorySince(ctx); err != nil || !h.IsZero() {
		t.Fatalf("history before any run: %v %v", h, err)
	}
	if err := st.BeginRun(ctx, Run{ID: "r1", Profile: "daily", WindowFrom: ts.Add(-24 * time.Hour), WindowTo: ts, StartedAt: ts, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := st.BeginRun(ctx, Run{ID: "r2", Profile: "daily", WindowFrom: ts, WindowTo: ts.Add(24 * time.Hour), StartedAt: ts.Add(24 * time.Hour), Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if h, _ := st.HistorySince(ctx); !h.Equal(ts) {
		t.Fatalf("history since must be the first run: %v", h)
	}
	if runs, _ := st.Runs(ctx, ts, ts.Add(time.Hour)); len(runs) != 1 || runs[0].ID != "r1" {
		t.Fatalf("runs: %+v", runs)
	}
	evs := []FindingEvent{
		{FindingID: "f1", Check: "posture", Key: "root_mfa", Class: "new", Severity: "high", Summary: "s", At: ts, RunID: "r1", Profile: "weekly", Data: map[string]any{"a": 1}},
		{FindingID: "f1", Check: "posture", Key: "root_mfa", Class: "resolved", Severity: "high", At: ts.Add(2 * time.Hour), RunID: "r2"},
	}
	if err := st.AddFindingEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	got, err := st.FindingEvents(ctx, ts, ts.Add(time.Hour))
	if err != nil || len(got) != 1 || got[0].Class != "new" || got[0].Profile != "weekly" || got[0].Data["a"] != float64(1) {
		t.Fatalf("events: %+v %v", got, err)
	}
	// 人の resolve も履歴に残る (run_id は空)
	if err := st.UpsertFinding(ctx, Finding{ID: "f2", Check: "root_usage", Key: "k", Severity: "critical", FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, "f2", FindingAcked, time.Time{}, ts.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, "f2", FindingResolved, time.Time{}, ts.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = st.FindingEvents(ctx, ts.Add(3*time.Hour), ts.Add(5*time.Hour))
	if len(got) != 1 || got[0].FindingID != "f2" || got[0].Class != "resolved" || got[0].RunID != "" || got[0].Severity != "critical" {
		t.Fatalf("manual resolve: %+v", got)
	}
	if err := st.SetFindingStatus(ctx, "nope", FindingResolved, time.Time{}, ts); err == nil {
		t.Fatal("unknown finding must fail")
	}
}

// ack / snooze はその時点の重大度を suppressed_severity に記録する。resolve では空にする (ADR 0022)。
func TestSuppressedSeverity(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	f := Finding{ID: "f1", Check: "access_denied", Key: "arn:x", Severity: "medium", FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen}
	if err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, "f1", FindingAcked, time.Time{}, ts); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Finding(ctx, "f1")
	if got.SuppressedSeverity != "medium" {
		t.Fatalf("ack: %+v", got)
	}
	// suppressed の間に観測で severity が上書きされても suppressed_severity は残る
	got.Severity = "low"
	if err := st.UpsertFinding(ctx, *got); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Finding(ctx, "f1"); got.Severity != "low" || got.SuppressedSeverity != "medium" {
		t.Fatalf("upsert: %+v", got)
	}
	// snooze し直すとその時点の重大度
	if err := st.SetFindingStatus(ctx, "f1", FindingSnoozed, ts.Add(72*time.Hour), ts); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Finding(ctx, "f1"); got.SuppressedSeverity != "low" {
		t.Fatalf("snooze: %+v", got)
	}
	if err := st.SetFindingStatus(ctx, "f1", FindingResolved, time.Time{}, ts); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Finding(ctx, "f1"); got.SuppressedSeverity != "" {
		t.Fatalf("resolve: %+v", got)
	}
}

// schema 4 のストア (suppressed_severity 列が無い) は、acked / snoozed の行に今の severity を入れて移行する。
func TestMigrateAddsSuppressedSeverity(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`ALTER TABLE findings DROP COLUMN suppressed_severity`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_version SET version=4`); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ id, sev, status string }{{"a", "medium", FindingAcked}, {"s", "high", FindingSnoozed}, {"o", "low", FindingOpen}, {"r", "medium", FindingResolved}} {
		if _, err := st.db.Exec(`INSERT INTO findings(id, "check", key, severity, first_seen, last_seen, last_changed, status) VALUES (?, 'access_denied', ?, ?, ?, ?, ?, ?)`,
			r.id, "k-"+r.id, r.sev, fmtTime(ts), fmtTime(ts), fmtTime(ts), r.status); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var v int
	if err := st.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil || v != schemaVersion || schemaVersion < 5 {
		t.Fatalf("version %d (%v)", v, err)
	}
	want := map[string]string{"a": "medium", "s": "high", "o": "", "r": ""}
	for id, w := range want {
		f, err := st.Finding(context.Background(), id)
		if err != nil || f == nil || f.SuppressedSeverity != w {
			t.Fatalf("%s: %+v %v (want %q)", id, f, err, w)
		}
	}
}
