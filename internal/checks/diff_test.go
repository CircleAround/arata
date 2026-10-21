package checks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/store"
)

var now = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

func newStore(t *testing.T) *store.Dir {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seqID() func() string {
	n := 0
	return func() string { n++; return fmt.Sprintf("f-%03d", n) }
}

func TestDiff(t *testing.T) {
	window := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	earlier := now.Add(-2 * time.Hour)      // 窓内 (前回の run で観測)
	dormant := now.Add(-3 * 24 * time.Hour) // 窓より前
	obs := func(key string, count int) Observation {
		return Observation{Check: "c", Key: key, Severity: High, Summary: "s " + key, Data: map[string]any{"count": count}}
	}
	fpObs := func(key, fp string, count int) Observation {
		o := obs(key, count)
		o.Fingerprint = fp
		return o
	}
	existing := func(key, status string, last time.Time, fp string, data map[string]any) store.Finding {
		return store.Finding{ID: "x-" + key, Check: "c", Key: key, Severity: "high", Status: status, FirstSeen: dormant, LastSeen: last, LastChanged: dormant, Fingerprint: fp, Data: data}
	}
	cases := []struct {
		name     string
		mode     Mode
		existing []store.Finding
		obs      []Observation
		want     map[string]Class // key → class
		status   map[string]string
	}{
		{name: "nothing before, one observed → new", mode: ModeState,
			obs: []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassNew}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, same data → still_open", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "", map[string]any{"count": 1})},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassStillOpen}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, data differs (no fingerprint) → changed", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "", map[string]any{"count": 1})},
			obs:      []Observation{obs("k1", 2)}, want: map[string]Class{"k1": ClassChanged}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, same fingerprint, count differs → still_open", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "high|1.1.1.1", map[string]any{"count": 1})},
			obs:      []Observation{fpObs("k1", "high|1.1.1.1", 9)}, want: map[string]Class{"k1": ClassStillOpen}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, fingerprint differs → changed", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "high|1.1.1.1", map[string]any{"count": 1})},
			obs:      []Observation{fpObs("k1", "high|1.1.1.1,2.2.2.2", 1)}, want: map[string]Class{"k1": ClassChanged}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, severity differs → changed", mode: ModeState,
			existing: []store.Finding{{ID: "x", Check: "c", Key: "k1", Severity: "medium", Status: store.FindingOpen, FirstSeen: dormant, LastSeen: earlier, LastChanged: dormant, Data: map[string]any{"count": 1}}},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassChanged}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "state: open, not observed → resolved", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "", map[string]any{"count": 1})},
			want:     map[string]Class{"k1": ClassResolved}, status: map[string]string{"k1": store.FindingResolved}},
		{name: "event: open, not observed → stays open silently", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "high|1.1.1.1", map[string]any{"count": 1})},
			want:     map[string]Class{}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "event: dormant open, observed again → recurred", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, dormant, "high|1.1.1.1", map[string]any{"count": 1})},
			obs:      []Observation{fpObs("k1", "high|1.1.1.1", 4)}, want: map[string]Class{"k1": ClassRecurred}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "state: dormant open, observed again → still_open (not recurred)", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingOpen, dormant, "", map[string]any{"count": 1})},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassStillOpen}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "resolved, not observed → nothing", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingResolved, earlier, "", map[string]any{"count": 1})},
			want:     map[string]Class{}, status: map[string]string{"k1": store.FindingResolved}},
		{name: "resolved, observed again → new (reopen)", mode: ModeState,
			existing: []store.Finding{{ID: "x", Check: "c", Key: "k1", Severity: "high", Status: store.FindingResolved, FirstSeen: dormant, LastSeen: earlier, LastChanged: earlier, ReportedAt: earlier, Data: map[string]any{"count": 1}}},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassNew}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "acked, observed → suppressed", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingAcked, earlier, "", map[string]any{"count": 1})},
			obs:      []Observation{obs("k1", 5)}, want: map[string]Class{"k1": ClassSuppressed}, status: map[string]string{"k1": store.FindingAcked}},
		{name: "event: acked, observed after gap → suppressed (not recurred)", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingAcked, dormant, "", map[string]any{"count": 1})},
			obs:      []Observation{obs("k1", 5)}, want: map[string]Class{"k1": ClassSuppressed}, status: map[string]string{"k1": store.FindingAcked}},
		{name: "state: acked, not observed → resolved", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingAcked, earlier, "", map[string]any{"count": 1})},
			want:     map[string]Class{"k1": ClassResolved}, status: map[string]string{"k1": store.FindingResolved}},
		{name: "snoozed until future, observed → suppressed", mode: ModeState,
			existing: []store.Finding{{ID: "x", Check: "c", Key: "k1", Severity: "high", Status: store.FindingSnoozed, SnoozeUntil: now.Add(time.Hour), FirstSeen: dormant, LastSeen: earlier, LastChanged: dormant, Data: map[string]any{"count": 1}}},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassSuppressed}, status: map[string]string{"k1": store.FindingSnoozed}},
		{name: "snoozed until past, observed → new (re-report)", mode: ModeState,
			existing: []store.Finding{{ID: "x", Check: "c", Key: "k1", Severity: "high", Status: store.FindingSnoozed, SnoozeUntil: now.Add(-time.Hour), FirstSeen: dormant, LastSeen: earlier, LastChanged: dormant, Data: map[string]any{"count": 1}}},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassNew}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "mixed state", mode: ModeState,
			existing: []store.Finding{
				existing("k1", store.FindingOpen, earlier, "", map[string]any{"count": 1}),
				existing("k2", store.FindingOpen, earlier, "", map[string]any{"count": 1}),
				{ID: "o", Check: "other", Key: "k1", Severity: "high", Status: store.FindingOpen, FirstSeen: dormant, LastSeen: earlier, LastChanged: dormant, Data: map[string]any{"count": 1}},
			},
			obs:    []Observation{obs("k1", 1), obs("k3", 1)},
			want:   map[string]Class{"k1": ClassStillOpen, "k2": ClassResolved, "k3": ClassNew},
			status: map[string]string{"k1": store.FindingOpen, "k2": store.FindingResolved, "k3": store.FindingOpen}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			ctx := context.Background()
			for _, f := range tc.existing {
				if err := st.UpsertFinding(ctx, f); err != nil {
					t.Fatal(err)
				}
			}
			res, err := Diff(ctx, st, DiffParams{Check: "c", Mode: tc.mode, Window: window, Now: now, NewID: seqID()}, tc.obs)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]Class{}
			for _, r := range res {
				got[r.Finding.Key] = r.Class
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for k, c := range tc.want {
				if got[k] != c {
					t.Fatalf("key %s: got %v want %v (all: %v)", k, got[k], c, got)
				}
			}
			all, _ := st.Findings(ctx, "c", nil)
			for _, f := range all {
				if want, ok := tc.status[f.Key]; ok && f.Status != want {
					t.Fatalf("key %s: status %s want %s", f.Key, f.Status, want)
				}
				switch got[f.Key] {
				case ClassNew:
					if !f.FirstSeen.Equal(now) || !f.LastChanged.Equal(now) || !f.ReportedAt.IsZero() || f.ID == "" {
						t.Fatalf("new finding timestamps: %+v", f)
					}
				case ClassChanged, ClassRecurred:
					if !f.LastChanged.Equal(now) || !f.FirstSeen.Equal(dormant) || !f.LastSeen.Equal(now) {
						t.Fatalf("%s finding: %+v", got[f.Key], f)
					}
					if got[f.Key] == ClassRecurred && f.Data["count"] != float64(4) {
						t.Fatalf("recurred must update data: %+v", f)
					}
				case ClassStillOpen:
					if !f.LastChanged.Equal(dormant) || !f.LastSeen.Equal(now) {
						t.Fatalf("still_open finding: %+v", f)
					}
				case ClassResolved:
					if !f.LastChanged.Equal(now) {
						t.Fatalf("resolved finding: %+v", f)
					}
				case "":
					// 結果に出ないもの (event の未観測、resolved のまま) は触らない
					if tc.mode == ModeEvent && f.Status == store.FindingOpen && !f.LastSeen.Equal(earlier) {
						t.Fatalf("silent event finding must stay untouched: %+v", f)
					}
				}
			}
			if other, _ := st.Findings(ctx, "other", nil); len(other) == 1 && other[0].Status != store.FindingOpen {
				t.Fatalf("other check touched: %+v", other[0])
			}
		})
	}
}

func TestFingerprintStableAcrossCounts(t *testing.T) {
	a := fingerprint(High, map[string]bool{"2.2.2.2": true, "1.1.1.1": true}, "x")
	b := fingerprint(High, map[string]bool{"1.1.1.1": true, "2.2.2.2": true}, "x")
	if a != b || a != "high|1.1.1.1,2.2.2.2|x" {
		t.Fatalf("%q %q", a, b)
	}
}

// 再走査 (ADR 0013) の窓でも recurred の判定は再走査を含まない From で行う。前回の run (= From) で観測した事象は recurred にならず、
// それより前に沈んでいた事象が遅れて届いたイベントで再び観測されたら recurred になる。
func TestDiffRecurredIgnoresRescan(t *testing.T) {
	from := now.Add(-time.Hour)
	w := collect.Window{From: from, To: now, ScanFrom: from.Add(-15 * time.Minute), CollectedAt: now}
	cases := []struct {
		name     string
		lastSeen time.Time
		want     Class
	}{
		{"last seen at the previous run", from, ClassStillOpen},
		{"last seen long before", from.Add(-24 * time.Hour), ClassRecurred},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			ctx := context.Background()
			f := store.Finding{ID: "x", Check: "c", Key: "k1", Severity: "high", Status: store.FindingOpen, FirstSeen: tc.lastSeen, LastSeen: tc.lastSeen, LastChanged: tc.lastSeen, Fingerprint: "high|1.1.1.1"}
			if err := st.UpsertFinding(ctx, f); err != nil {
				t.Fatal(err)
			}
			o := Observation{Check: "c", Key: "k1", Severity: High, Fingerprint: "high|1.1.1.1"}
			res, err := Diff(ctx, st, DiffParams{Check: "c", Mode: ModeEvent, Window: w, Now: now, NewID: seqID()}, []Observation{o})
			if err != nil || len(res) != 1 || res[0].Class != tc.want {
				t.Fatalf("got %+v %v, want %s", res, err, tc.want)
			}
		})
	}
}
