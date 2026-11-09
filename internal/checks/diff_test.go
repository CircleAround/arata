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
		return store.Finding{ID: "x-" + key, Check: "c", Key: key, Severity: "high", Status: status, ReportedAt: dormant, FirstSeen: dormant, LastSeen: last, LastChanged: dormant, Fingerprint: fp, Data: data}
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
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "high|192.0.2.101", map[string]any{"count": 1})},
			obs:      []Observation{fpObs("k1", "high|192.0.2.101", 9)}, want: map[string]Class{"k1": ClassStillOpen}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, fingerprint differs → changed", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "high|192.0.2.101", map[string]any{"count": 1})},
			obs:      []Observation{fpObs("k1", "high|192.0.2.101,192.0.2.102", 1)}, want: map[string]Class{"k1": ClassChanged}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "open, severity differs → changed", mode: ModeState,
			existing: []store.Finding{{ID: "x", Check: "c", Key: "k1", Severity: "medium", Status: store.FindingOpen, ReportedAt: dormant, FirstSeen: dormant, LastSeen: earlier, LastChanged: dormant, Data: map[string]any{"count": 1}}},
			obs:      []Observation{obs("k1", 1)}, want: map[string]Class{"k1": ClassChanged}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "state: open, not observed → resolved", mode: ModeState,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "", map[string]any{"count": 1})},
			want:     map[string]Class{"k1": ClassResolved}, status: map[string]string{"k1": store.FindingResolved}},
		{name: "event: open, not observed → stays open silently", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, earlier, "high|192.0.2.101", map[string]any{"count": 1})},
			want:     map[string]Class{}, status: map[string]string{"k1": store.FindingOpen}},
		{name: "event: dormant open, observed again → recurred", mode: ModeEvent,
			existing: []store.Finding{existing("k1", store.FindingOpen, dormant, "high|192.0.2.101", map[string]any{"count": 1})},
			obs:      []Observation{fpObs("k1", "high|192.0.2.101", 4)}, want: map[string]Class{"k1": ClassRecurred}, status: map[string]string{"k1": store.FindingOpen}},
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
				{ID: "o", Check: "other", Key: "k1", Severity: "high", Status: store.FindingOpen, ReportedAt: dormant, FirstSeen: dormant, LastSeen: earlier, LastChanged: dormant, Data: map[string]any{"count": 1}},
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
	a := fingerprint(High, map[string]bool{"192.0.2.102": true, "192.0.2.101": true}, "x")
	b := fingerprint(High, map[string]bool{"192.0.2.101": true, "192.0.2.102": true}, "x")
	if a != b || a != "high|192.0.2.101,192.0.2.102|x" {
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
			f := store.Finding{ID: "x", Check: "c", Key: "k1", Severity: "high", Status: store.FindingOpen, ReportedAt: time.Unix(1, 0), FirstSeen: tc.lastSeen, LastSeen: tc.lastSeen, LastChanged: tc.lastSeen, Fingerprint: "high|192.0.2.101"}
			if err := st.UpsertFinding(ctx, f); err != nil {
				t.Fatal(err)
			}
			o := Observation{Check: "c", Key: "k1", Severity: High, Fingerprint: "high|192.0.2.101"}
			res, err := Diff(ctx, st, DiffParams{Check: "c", Mode: ModeEvent, Window: w, Now: now, NewID: seqID()}, []Observation{o})
			if err != nil || len(res) != 1 || res[0].Class != tc.want {
				t.Fatalf("got %+v %v, want %s", res, err, tc.want)
			}
		})
	}
}

// ack / 期日前の snooze 中でも、観測の重大度が ack / snooze したときより重くなったら changed として再報告する (ADR 0022)。
func TestDiffEscalation(t *testing.T) {
	window := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	earlier := now.Add(-2 * time.Hour)
	dormant := now.Add(-3 * 24 * time.Hour)
	suppressed := func(status, sev, suppressedSev string, last time.Time) store.Finding {
		f := store.Finding{ID: "x", Check: "c", Key: "k1", Severity: sev, SuppressedSeverity: suppressedSev, Status: status, Summary: "old",
			FirstSeen: dormant, LastSeen: last, LastChanged: dormant, ReportedAt: dormant, Fingerprint: sev + "|192.0.2.101", Data: map[string]any{"count": 1}}
		if status == store.FindingSnoozed {
			f.SnoozeUntil = now.Add(48 * time.Hour)
		}
		return f
	}
	obs := func(sev Severity) Observation {
		return Observation{Check: "c", Key: "k1", Severity: sev, Summary: "拒否された API 呼び出し", Fingerprint: string(sev) + "|192.0.2.102", Data: map[string]any{"count": 30}}
	}
	cases := []struct {
		name     string
		mode     Mode
		existing store.Finding
		obs      Observation
		want     Class
		prefix   string
	}{
		{"acked medium → high", ModeEvent, suppressed(store.FindingAcked, "medium", "medium", earlier), obs(High), ClassChanged, "(確認済み (ack) だったが重大度が medium → high に上昇) "},
		{"acked medium, dormant → high (escalation wins over recurred)", ModeEvent, suppressed(store.FindingAcked, "medium", "medium", dormant), obs(High), ClassChanged, "(確認済み (ack) だったが重大度が medium → high に上昇) "},
		{"snoozed medium → critical", ModeState, suppressed(store.FindingSnoozed, "medium", "medium", earlier), obs(Critical), ClassChanged, "(snooze 中だったが重大度が medium → critical に上昇) "},
		{"acked medium, stays medium (other IPs) → suppressed", ModeEvent, suppressed(store.FindingAcked, "medium", "medium", earlier), obs(Medium), ClassSuppressed, ""},
		{"acked high → medium → suppressed", ModeEvent, suppressed(store.FindingAcked, "high", "high", earlier), obs(Medium), ClassSuppressed, ""},
		// 観測で severity が high に上書きされていても、比べるのは ack したときの重大度
		{"acked at medium, severity already overwritten to high → high", ModeEvent, suppressed(store.FindingAcked, "high", "medium", earlier), obs(High), ClassChanged, "(確認済み (ack) だったが重大度が medium → high に上昇) "},
		// 移行し損ねた行 (suppressed_severity が空) は今の severity と比べる
		{"acked, no suppressed_severity, medium → high", ModeEvent, suppressed(store.FindingAcked, "medium", "", earlier), obs(High), ClassChanged, "(確認済み (ack) だったが重大度が medium → high に上昇) "},
		{"acked, no suppressed_severity, same → suppressed", ModeEvent, suppressed(store.FindingAcked, "high", "", earlier), obs(High), ClassSuppressed, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			ctx := context.Background()
			if err := st.UpsertFinding(ctx, tc.existing); err != nil {
				t.Fatal(err)
			}
			res, err := Diff(ctx, st, DiffParams{Check: "c", Mode: tc.mode, Window: window, Now: now, NewID: seqID()}, []Observation{tc.obs})
			if err != nil {
				t.Fatal(err)
			}
			if len(res) != 1 || res[0].Class != tc.want {
				t.Fatalf("res: %+v", res)
			}
			f, _ := st.Finding(ctx, "x")
			if tc.want == ClassSuppressed {
				if f.Status != tc.existing.Status || f.SuppressedSeverity != tc.existing.SuppressedSeverity || f.Data["escalated_from_suppressed"] != nil {
					t.Fatalf("suppressed must stay: %+v", f)
				}
				return
			}
			wantFrom := tc.existing.SuppressedSeverity
			if wantFrom == "" {
				wantFrom = tc.existing.Severity
			}
			if f.Status != store.FindingOpen || !f.SnoozeUntil.IsZero() || f.SuppressedSeverity != "" || !f.LastChanged.Equal(now) || f.Severity != string(tc.obs.Severity) {
				t.Fatalf("escalated finding must reopen: %+v", f)
			}
			if f.Data["escalated_from_suppressed"] != true || f.Data["suppressed_status"] != tc.existing.Status || f.Data["suppressed_severity"] != wantFrom || f.Data["count"] != float64(30) {
				t.Fatalf("escalation data: %+v", f.Data)
			}
			if f.Summary != tc.prefix+"拒否された API 呼び出し" || res[0].Finding.Summary != f.Summary {
				t.Fatalf("summary: %q", f.Summary)
			}
			// 次の run で同じ観測なら still_open (印は Data に残るが再報告はしない)
			res, err = Diff(ctx, st, DiffParams{Check: "c", Mode: tc.mode, Window: window, Now: now.Add(time.Hour), NewID: seqID()}, []Observation{tc.obs})
			if err != nil || len(res) != 1 || res[0].Class != ClassStillOpen {
				t.Fatalf("next run: %+v %v", res, err)
			}
		})
	}
}

// 一度も報告していない open (run が途中で止まった) は、ID と初出を保ったまま new に戻す (ADR 0038)。
func TestDiffUnreportedOpenIsNew(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	first := now.Add(-time.Hour)
	if err := st.UpsertFinding(ctx, store.Finding{ID: "x", Check: "c", Key: "k1", Severity: "high", Status: store.FindingOpen, FirstSeen: first, LastSeen: first, LastChanged: first}); err != nil {
		t.Fatal(err)
	}
	res, err := Diff(ctx, st, DiffParams{Check: "c", Mode: ModeEvent, Window: collect.Window{From: now.Add(-24 * time.Hour), To: now}, Now: now, NewID: seqID()},
		[]Observation{{Check: "c", Key: "k1", Severity: High, Fingerprint: "f"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Class != ClassNew || res[0].Finding.ID != "x" || !res[0].Finding.FirstSeen.Equal(first) {
		t.Fatalf("%+v", res)
	}
}
