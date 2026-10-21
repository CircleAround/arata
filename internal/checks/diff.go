package checks

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/store"
)

// Class は差分判定の結果。
type Class string

const (
	ClassNew        Class = "new"
	ClassChanged    Class = "changed"
	ClassResolved   Class = "resolved"
	ClassStillOpen  Class = "still_open"
	ClassRecurred   Class = "recurred"   // ModeEvent: 窓外に沈んでいた事象が再び観測された
	ClassSuppressed Class = "suppressed" // acked / snoozed 中。レポートには出さない
)

// Result は finding 1 件の判定結果。
type Result struct {
	Class   Class
	Finding store.Finding
}

// DiffParams は Diff の入力。
type DiffParams struct {
	Check  string
	Mode   Mode
	Window collect.Window
	Now    time.Time
	NewID  func() string // finding ID の生成 (テストで固定できる)
}

// Diff は 1 チェック分の観測を findings テーブルと突合し、更新して結果を返す (設計書 4-2)。
//
// 共通:
//   - 無ければ new (status open)。resolved だったものが再び観測されても new。
//   - open で Fingerprint (空なら Data) か Severity が変わっていれば changed、同じなら still_open。
//   - acked、および期日前の snoozed は suppressed (再報告しない)。期日を過ぎた snoozed は new として再報告。
//
// ModeState: 観測されなかった open / acked / snoozed は resolved。
// ModeEvent: 観測されなくても resolved にしない (open のまま、結果にも出さない)。
// 前回の窓より前が last_seen の open finding が再観測されたら recurred (Data を更新)。
// 決定 (ADR 0013): 境界は再走査を含まない本来の From (p.Window.From)。ScanFrom ではない。チェックが評価する重なり区間のイベントは
// 今回初めて届いたものだけなので、last_seen (前回観測した run の時刻 ≥ From) の事象が再走査で recurred になることは無い。
//
// 決定: 時刻は now (実行時刻) を使う。
func Diff(ctx context.Context, st store.Store, p DiffParams, obs []Observation) ([]Result, error) {
	existing, err := st.Findings(ctx, p.Check, nil)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]store.Finding, len(existing))
	for _, f := range existing {
		byKey[f.Key] = f
	}
	var out []Result
	seen := map[string]bool{}
	for _, o := range obs {
		if seen[o.Key] {
			continue
		}
		seen[o.Key] = true
		f, ok := byKey[o.Key]
		var class Class
		switch {
		case !ok, f.Status == store.FindingResolved,
			f.Status == store.FindingSnoozed && !f.SnoozeUntil.IsZero() && !p.Now.Before(f.SnoozeUntil):
			id := f.ID
			if id == "" {
				id = p.NewID()
			}
			f = store.Finding{ID: id, Check: p.Check, Key: o.Key, FirstSeen: p.Now, Status: store.FindingOpen}
			class = ClassNew
		case f.Status == store.FindingAcked, f.Status == store.FindingSnoozed:
			class = ClassSuppressed
		case p.Mode == ModeEvent && f.LastSeen.Before(p.Window.From):
			class = ClassRecurred
		case string(o.Severity) != f.Severity || !sameObservation(o, f):
			class = ClassChanged
		default:
			class = ClassStillOpen
		}
		f.LastSeen = p.Now
		if class == ClassNew || class == ClassChanged || class == ClassRecurred {
			f.LastChanged = p.Now
		}
		if class != ClassStillOpen {
			f.Severity, f.Summary, f.Fingerprint, f.Data = string(o.Severity), o.Summary, o.Fingerprint, o.Data
		}
		if err := st.UpsertFinding(ctx, f); err != nil {
			return nil, err
		}
		out = append(out, Result{Class: class, Finding: f})
	}
	if p.Mode == ModeState {
		for _, f := range existing {
			if seen[f.Key] || f.Status == store.FindingResolved {
				continue
			}
			f.Status = store.FindingResolved
			f.LastChanged = p.Now
			if err := st.UpsertFinding(ctx, f); err != nil {
				return nil, err
			}
			out = append(out, Result{Class: ClassResolved, Finding: f})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Finding.Key < out[j].Finding.Key })
	return out, nil
}

// sameObservation は Fingerprint があればそれを、無ければ Data を JSON 化して比較する。
func sameObservation(o Observation, f store.Finding) bool {
	if o.Fingerprint != "" || f.Fingerprint != "" {
		return o.Fingerprint == f.Fingerprint
	}
	ab, _ := json.Marshal(nonNilMap(o.Data))
	bb, _ := json.Marshal(nonNilMap(f.Data))
	return string(ab) == string(bb)
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
