package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// dryRunInfo は試しの実行の窓と、定時の実行との違い (ADR 0049)。
type dryRunInfo struct {
	// scheduled は今、定時の実行を流したときの窓 (前回の window_to からの追いつきを含む。失敗したソースの追いつきは含まない)。
	scheduled collect.Window
	// diffFrom は差分判定の境界。
	diffFrom time.Time
}

// dryRunWindow は試しの実行の窓 [now - window, now) を返す (window がゼロならプロファイルの window)。
//
// 決定: 差分判定の境界 (再発と「本日報告済み」) は、試しの窓の始まりと定時の実行の窓の始まりの早いほうにする。
// 試しの窓の始まりを境界にすると、前回の run で見た事象が続いているだけで last_seen が境界より前になり「再発」と出る。
// 試しの実行は定時の実行の結果の先取りなので、定時の実行と同じ分類を出す。試しの窓のほうが長いときは、
// その中で見直した古い事象を再発にしないよう、試しの窓の始まりを使う。
func (e *Engine) dryRunWindow(ctx context.Context, profileName string, prof config.Profile, window time.Duration, now time.Time) (collect.Window, *dryRunInfo, error) {
	if window == 0 {
		window = prof.Window
	}
	w := collect.Window{From: now.Add(-window), To: now}
	sched, err := e.window(ctx, profileName, prof, now, false)
	if err != nil {
		return w, nil, err
	}
	d := &dryRunInfo{scheduled: sched, diffFrom: sched.From}
	if w.From.Before(d.diffFrom) {
		d.diffFrom = w.From
	}
	return w, d, nil
}

// dryRunNotes は試しの実行が定時の実行と違う点を、レポートの coverage.notes に書く文にする。違いが無ければ空。
//
//   - 見た範囲が定時の実行より狭い: その間に起きたことはこの報告に入らない。
//   - 日次集計を使うチェック: 評価するのは窓に重なる UTC の日だけなので、定時の実行なら評価する日が抜ける。
//
// 決定: 注記は範囲が狭いときだけ出す (同じか広ければ、定時の実行が見るものは全部見ている)。
// スナップショットを使うチェック (weekly の状態差分型) は窓に依らないので注記しない。
func (e *Engine) dryRunNotes(prof config.Profile, w collect.Window, d *dryRunInfo, ev EvalResult) []string {
	if !d.scheduled.From.Before(w.From) {
		return nil
	}
	notes := []string{fmt.Sprintf("見た範囲は %s から %s まで。定時の実行なら %s から見るので、%s から %s までに起きたことはこの報告に入っていない",
		ts(w.From), ts(w.To), ts(d.scheduled.From), ts(d.scheduled.From), ts(w.From))}
	seen := map[string]bool{}
	for _, day := range utcDays(w) {
		seen[day] = true
	}
	var missing []string
	for _, day := range utcDays(d.scheduled) {
		if !seen[day] {
			missing = append(missing, day)
		}
	}
	if names := e.dailyMetricChecks(ev.ChecksRun); len(missing) > 0 && len(names) > 0 {
		notes = append(notes, fmt.Sprintf("日次集計を使うチェック (%s) は、窓に重なる UTC の日だけを評価する。定時の実行なら評価する %s を評価していないので、結果が定時の実行と違うことがある",
			strings.Join(names, ", "), strings.Join(missing, ", ")))
	}
	return notes
}

// dailyMetricChecks は names のうち、日次集計 (cloudwatch-logs のソースが出す種類) を使うチェック。
func (e *Engine) dailyMetricChecks(names []string) []string {
	metricKinds := map[record.Kind]bool{}
	for _, src := range e.cfg.Sources {
		if src.Kind == config.KindCloudWatchLogs {
			metricKinds[record.Kind(src.Yields)] = true
		}
	}
	var out []string
	for _, name := range names {
		c, ok := e.deps.Registry.Get(name)
		if !ok {
			continue
		}
		kinds := c.Needs()
		if sn, ok := c.(checks.StoredNeeder); ok {
			kinds = append(append([]record.Kind(nil), kinds...), sn.StoredNeeds()...)
		}
		if anyNeeded(kinds, metricKinds) {
			out = append(out, name)
		}
	}
	return out
}

// utcDays は窓に重なる UTC の日 (YYYY-MM-DD) を古い順に返す (アプリ層チェックが評価する日と同じ)。
func utcDays(w collect.Window) []string {
	var out []string
	last := w.To.Add(-time.Nanosecond).UTC()
	from := w.From.UTC()
	for d := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC); !d.After(last); d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format(record.DateLayout))
	}
	return out
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }
