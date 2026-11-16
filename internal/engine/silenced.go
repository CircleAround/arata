package engine

import (
	"context"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

// silencedSection は報告の「黙らせているもの」の節を作る (ADR 0068 の 3 節・9 節)。
//
// 決定:
//   - 対象はストアの acked / snoozed の finding 全部 (このプロファイルのチェックに限らない。黙らせたものはどの run の報告にも出ないため)
//   - 「high 以上」は今の重大度と黙らせたときの重大度の重いほうで決める (黙らせた後に軽くなっても、黙らせた判断を見直す材料にする)
//   - 並びは、その重大度の高い順 → 黙らせた時刻の古い順 → ID
//   - 期日の近い snooze は now から 7 日以内、期日を過ぎた snooze は期日が now 以前のもの。allowlist は期限 (その日の終わりまで有効) が now から 30 日以内か過ぎたもの
//   - 状態は変えない (読むだけ)
func (e *Engine) silencedSection(ctx context.Context, now time.Time) (*schema.Silenced, error) {
	fs, err := e.st.Findings(ctx, "", []string{store.FindingAcked, store.FindingSnoozed})
	if err != nil {
		return nil, err
	}
	last, err := e.st.LastFindingActions(ctx)
	if err != nil {
		return nil, err
	}
	out := &schema.Silenced{Findings: []schema.SilencedFinding{}, SnoozeExpiring: []schema.SilencedFinding{}, SnoozeExpired: []schema.SilencedFinding{}, AllowlistExpiring: []schema.AllowlistExpiry{}}
	type row struct {
		f    schema.SilencedFinding
		rank int
		at   time.Time
	}
	var rows []row
	for _, f := range fs {
		// 報告の finding と同じく、個人を特定できる値を伏せる (ADR 0037)。理由も利用者の入力なので同じに伏せる
		sf := schema.SilencedFinding{ID: f.ID, Check: f.Check, Key: record.MaskIdentity(f.Key), Severity: f.Severity, SuppressedSeverity: f.SuppressedSeverity,
			Summary: record.MaskIdentity(f.Summary), Status: f.Status}
		at := f.LastChanged
		if a, ok := last[f.ID]; ok {
			at = a.At
			sf.LastAction = &schema.SilencedAction{Action: a.Action, By: a.By, Reason: record.MaskIdentity(a.Reason), Forced: a.Forced, At: a.At.UTC().Format(time.RFC3339)}
		}
		sf.SilencedAt = at.UTC().Format(time.RFC3339)
		if f.Status == store.FindingSnoozed && !f.SnoozeUntil.IsZero() {
			sf.SnoozeUntil = f.SnoozeUntil.UTC().Format(time.RFC3339)
		}
		rank := max(checks.Severity(f.Severity).Rank(), checks.Severity(f.SuppressedSeverity).Rank())
		high := rank >= checks.High.Rank()
		switch f.Status {
		case store.FindingAcked:
			out.Summary.Acked++
			if high {
				out.Summary.AckedHigh++
			}
			if sf.LastAction != nil && sf.LastAction.Forced {
				out.Summary.Forced++
			}
		case store.FindingSnoozed:
			out.Summary.Snoozed++
			if high {
				out.Summary.SnoozedHigh++
			}
		}
		rows = append(rows, row{sf, rank, at})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].rank != rows[j].rank {
			return rows[i].rank > rows[j].rank
		}
		if !rows[i].at.Equal(rows[j].at) {
			return rows[i].at.Before(rows[j].at)
		}
		return rows[i].f.ID < rows[j].f.ID
	})
	soon := now.Add(schema.SnoozeExpiringDays * 24 * time.Hour)
	for _, r := range rows {
		out.Findings = append(out.Findings, r.f)
	}
	// 期日の並びは期日の早い順
	byUntil := append([]store.Finding(nil), fs...)
	sort.SliceStable(byUntil, func(i, j int) bool { return byUntil[i].SnoozeUntil.Before(byUntil[j].SnoozeUntil) })
	index := map[string]schema.SilencedFinding{}
	for _, r := range rows {
		index[r.f.ID] = r.f
	}
	for _, f := range byUntil {
		if f.Status != store.FindingSnoozed || f.SnoozeUntil.IsZero() {
			continue
		}
		switch {
		case !f.SnoozeUntil.After(now):
			out.SnoozeExpired = append(out.SnoozeExpired, index[f.ID])
		case !f.SnoozeUntil.After(soon):
			out.SnoozeExpiring = append(out.SnoozeExpiring, index[f.ID])
		}
	}
	out.Summary.SnoozeExpiring, out.Summary.SnoozeExpired = len(out.SnoozeExpiring), len(out.SnoozeExpired)
	if e.al != nil {
		today := now.UTC().Format(record.DateLayout)
		limit := now.UTC().AddDate(0, 0, schema.AllowlistExpiringDays).Format(record.DateLayout)
		for _, x := range e.al.Expiring() {
			if x.Expires > limit {
				continue
			}
			// 期限の日は有効 (allowlist の expires と同じ読み方)。その日より後が「切れた」
			expired := x.Expires < today
			out.AllowlistExpiring = append(out.AllowlistExpiring, schema.AllowlistExpiry{Section: x.Section, Subject: record.MaskIdentity(x.Subject), Expires: x.Expires, Expired: expired})
			if expired {
				out.Summary.AllowlistExpired++
			} else {
				out.Summary.AllowlistExpiring++
			}
		}
	}
	return out, nil
}
