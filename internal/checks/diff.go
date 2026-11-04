package checks

import (
	"context"
	"encoding/json"
	"fmt"
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
//   - ただし acked / 期日前の snoozed でも、観測の重大度が ack / snooze したときの重大度 (SuppressedSeverity。空なら今の Severity) より
//     重ければ changed として再報告し、open に戻す。Data に escalated_from_suppressed / suppressed_status / suppressed_severity を、
//     Summary の先頭に印を付ける。ModeEvent の recurred の条件と重なっても changed (上昇を優先)。
//     決定 (ADR 0022): 新しい class にせず changed にする。report.json のスキーマと aratam の振り分け (max_severity) を変えずに済むため。
//     Fingerprint の変化 (IP が増えた等) では解かない。ack した事象の揺れで毎回再報告されると ack の意味が無くなるため。
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
		var escalated *store.Finding
		switch {
		case !ok, f.Status == store.FindingResolved,
			f.Status == store.FindingSnoozed && !f.SnoozeUntil.IsZero() && !p.Now.Before(f.SnoozeUntil):
			id := f.ID
			if id == "" {
				id = p.NewID()
			}
			f = store.Finding{ID: id, Check: p.Check, Key: o.Key, FirstSeen: p.Now, Status: store.FindingOpen}
			class = ClassNew
		case f.Status == store.FindingOpen && f.ReportedAt.IsZero():
			// 決定 (ADR 0038): 一度も報告していない open は new のまま (run が途中で止まった)。ID と初出は保つ
			class = ClassNew
		case (f.Status == store.FindingAcked || f.Status == store.FindingSnoozed) && escalates(o.Severity, f):
			prev := f
			escalated = &prev
			f.Status, f.SnoozeUntil, f.SuppressedSeverity = store.FindingOpen, time.Time{}, ""
			class = ClassChanged
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
		if escalated != nil {
			from := suppressedSeverity(*escalated)
			data := make(map[string]any, len(o.Data)+3)
			for k, v := range o.Data {
				data[k] = v
			}
			data["escalated_from_suppressed"] = true
			data["suppressed_status"] = escalated.Status
			data["suppressed_severity"] = from
			f.Data = data
			label := "確認済み (ack) だった"
			if escalated.Status == store.FindingSnoozed {
				label = "snooze 中だった"
			}
			f.Summary = fmt.Sprintf("(%sが重大度が %s → %s に上昇) %s", label, from, o.Severity, o.Summary)
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

// suppressedSeverity は ack / snooze したときの重大度。記録が無ければ (移行し損ねた行) 今の重大度。
func suppressedSeverity(f store.Finding) string {
	if f.SuppressedSeverity != "" {
		return f.SuppressedSeverity
	}
	return f.Severity
}

// escalates は観測の重大度が ack / snooze したときより重いか。
func escalates(sev Severity, f store.Finding) bool {
	return sev.Rank() > Severity(suppressedSeverity(f)).Rank()
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
