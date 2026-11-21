package store

import (
	"context"
	"testing"
	"time"
)

// 人の操作は finding_actions に 1 回 1 行で追記され、最後の操作を finding ごとに引ける (ADR 0068)。
func TestFindingActions(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	for _, f := range []Finding{
		{ID: "f1", Check: "secret_access", Key: "arn:a", Severity: "high", FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen},
		{ID: "f2", Check: "posture", Key: "k", Severity: "low", FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen},
	} {
		if err := st.UpsertFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	until := ts.Add(72 * time.Hour)
	if err := st.SetFindingStatus(ctx, "f1", FindingAcked, time.Time{}, ts, Action{Name: ActionAck, By: "alice", Reason: "migration", Forced: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, "f1", FindingSnoozed, until, ts.Add(time.Hour), Action{Name: ActionSnooze, By: "bob", Reason: "until baseline"}); err != nil {
		t.Fatal(err)
	}
	// 記録の無い操作 (Name が空) は表に残さない
	if err := st.SetFindingStatus(ctx, "f2", FindingAcked, time.Time{}, ts, Action{}); err != nil {
		t.Fatal(err)
	}

	hist, err := st.FindingActions(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("history: %+v", hist)
	}
	a := hist[0]
	if a.Action != ActionAck || a.By != "alice" || a.Reason != "migration" || !a.Forced || a.Severity != "high" ||
		a.StatusBefore != FindingOpen || !a.At.Equal(ts) || !a.SnoozeUntil.IsZero() || a.Check != "secret_access" || a.Key != "arn:a" {
		t.Fatalf("first: %+v", a)
	}
	b := hist[1]
	if b.Action != ActionSnooze || b.StatusBefore != FindingAcked || !b.SnoozeUntil.Equal(until) || b.Forced || b.Seq <= a.Seq {
		t.Fatalf("second: %+v", b)
	}

	last, err := st.LastFindingActions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(last) != 1 || last["f1"].Action != ActionSnooze || last["f1"].By != "bob" {
		t.Fatalf("last: %+v", last)
	}
	if _, ok := last["f2"]; ok {
		t.Fatal("f2 has no record")
	}

	// 状態の変更に失敗したら、記録も残らない (同じトランザクション)
	if err := st.SetFindingStatus(ctx, "nope", FindingAcked, time.Time{}, ts, Action{Name: ActionAck}); err == nil {
		t.Fatal("unknown id must fail")
	}
	if hist, _ := st.FindingActions(ctx, "nope"); len(hist) != 0 {
		t.Fatalf("no record for a failed change: %+v", hist)
	}
}

// schema 7 のストア (finding_actions が無い) は、開くと表が足され、schema 8 になる。既存の acked には記録が無い。
func TestMigrateAddsFindingActions(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DROP TABLE finding_actions`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_version SET version=7`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO findings(id, "check", key, severity, first_seen, last_seen, last_changed, status, suppressed_severity) VALUES ('a', 'secret_access', 'k', 'high', ?, ?, ?, 'acked', 'high')`,
		fmtTime(ts), fmtTime(ts), fmtTime(ts)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var v int
	if err := st.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil || v != schemaVersion || schemaVersion < 8 {
		t.Fatalf("version %d (%v)", v, err)
	}
	ctx := context.Background()
	if last, err := st.LastFindingActions(ctx); err != nil || len(last) != 0 {
		t.Fatalf("no records before schema 8: %+v %v", last, err)
	}
	if err := st.SetFindingStatus(ctx, "a", FindingSnoozed, ts.Add(48*time.Hour), ts, Action{Name: ActionSnooze, By: "alice"}); err != nil {
		t.Fatal(err)
	}
	if last, _ := st.LastFindingActions(ctx); last["a"].Action != ActionSnooze {
		t.Fatalf("after migration: %+v", last)
	}
}

// 複数の finding の状態は 1 つのトランザクションで変える (ack / snooze / resolve に複数の ID。全部か無しか)。
// 途中の 1 件が失敗したら、先の分の状態も記録も残らない。
func TestSetFindingStatusesIsAllOrNothing(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	for _, id := range []string{"f1", "f2", "f3"} {
		if err := st.UpsertFinding(ctx, Finding{ID: id, Check: "posture", Key: id, Severity: "low", FirstSeen: ts, LastSeen: ts, LastChanged: ts, Status: FindingOpen}); err != nil {
			t.Fatal(err)
		}
	}
	act := Action{Name: ActionResolve, By: "alice", Reason: "fixed"}
	if err := st.SetFindingStatuses(ctx, []StatusUpdate{
		{ID: "f1", Status: FindingResolved, At: ts, Action: act},
		{ID: "nope", Status: FindingResolved, At: ts, Action: act},
		{ID: "f2", Status: FindingResolved, At: ts, Action: act},
	}); err == nil {
		t.Fatal("unknown id must fail")
	}
	for _, id := range []string{"f1", "f2"} {
		f, err := st.Finding(ctx, id)
		if err != nil || f.Status != FindingOpen {
			t.Fatalf("%s must stay open: %+v %v", id, f, err)
		}
		if hist, _ := st.FindingActions(ctx, id); len(hist) != 0 {
			t.Fatalf("%s: no record for a failed batch: %+v", id, hist)
		}
	}
	until := ts.Add(48 * time.Hour)
	if err := st.SetFindingStatuses(ctx, []StatusUpdate{
		{ID: "f1", Status: FindingSnoozed, SnoozeUntil: until, At: ts, Action: Action{Name: ActionSnooze, By: "alice"}},
		{ID: "f3", Status: FindingSnoozed, SnoozeUntil: until, At: ts, Action: Action{Name: ActionSnooze, By: "alice"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"f1", "f3"} {
		f, _ := st.Finding(ctx, id)
		if f.Status != FindingSnoozed || !f.SnoozeUntil.Equal(until) {
			t.Fatalf("%s: %+v", id, f)
		}
		if hist, _ := st.FindingActions(ctx, id); len(hist) != 1 || hist[0].Action != ActionSnooze {
			t.Fatalf("%s: %+v", id, hist)
		}
	}
	if f, _ := st.Finding(ctx, "f2"); f.Status != FindingOpen {
		t.Fatalf("f2 is not in the batch: %+v", f)
	}
}
