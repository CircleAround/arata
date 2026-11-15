package engine

import (
	"context"
	"time"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/config"
)

// ソースごとの追いつき (ADR 0038)。
//
// 決定: run の stats にソースごとの「取り終えた位置」を持つ。run の窓は全ソースで 1 つなので、失敗したソースの期間は
// 次の run の窓から外れて失われていた。表を足さないので移行が要らず、runs は rebuild で引き継がれ、S3 では SQLite と一緒に Commit される。
// 決定: 位置を持たない古い run は、全ソースがその window_to まで取れたものとして扱う (今までの動作)。
const (
	sourceCoveredStat = "source_covered_to"
	catchupStat       = "catchup_from"
	// sourceCoveredFromStat は、位置 (source_covered_to) まで途切れずに読めている始まり (ADR 0064)。
	sourceCoveredFromStat = "source_covered_from"
	// recentPositionRuns は位置を探す run の数 (ふつうは最新の 1 件で見つかる)。
	recentPositionRuns = 50
)

// 決定 (ADR 0064): 位置はプロファイルをまたいで共有する。全プロファイル (collect の run を含む) の ok / partial の run のうち、
// 位置を持つ最も新しい run から読む (どの run も前の位置を引き継いで書くので、最も新しい 1 件に全ソースが揃う)。
// 位置が窓の始まりより先にあり、途切れずに読めている始まり (source_covered_from) が窓の始まり − ingest_delay を覆うソースは、
// 位置から続きだけを読む (別のプロファイルが読んだ所を読み直さない)。覆わない (始めたばかりの hourly だけが読んだ) なら、今までどおり窓の頭から読む。
// 始まりを持たない前の版の位置は、覆わないものとして扱う (読み飛ばさない)。

// ログの code。
const (
	CodeSourceCatchup          = codes.SourceCatchup
	CodeSourceCatchupTruncated = codes.SourceCatchupTruncated
)

type catchup struct {
	// covered は前回までの位置。
	covered map[string]time.Time
	// from は遅れているソースの開始位置。
	from map[string]time.Time
	// metricsFrom / eventsFrom は遅れているソースの最も古い位置 (集計 / それ以外)。ゼロなら遅れなし。
	metricsFrom, eventsFrom time.Time
	// coveredFrom は位置まで途切れずに読めている始まり。ahead は位置から続きだけを読むソース (位置が窓の始まりより先)。
	coveredFrom map[string]time.Time
	ahead       map[string]time.Time
}

// latestPositions は、位置を持つ最も新しい ok / partial の run の位置と始まり。
func (e *Engine) latestPositions(ctx context.Context) (covered, from map[string]time.Time, err error) {
	covered, from = map[string]time.Time{}, map[string]time.Time{}
	runs, err := e.st.RecentRuns(ctx, recentPositionRuns)
	if err != nil {
		return covered, from, err
	}
	for _, r := range runs {
		if r.Status != "ok" && r.Status != "partial" {
			continue
		}
		m, ok := r.Stats[sourceCoveredStat].(map[string]any)
		if !ok {
			continue
		}
		covered = parseTimes(m)
		if f, ok := r.Stats[sourceCoveredFromStat].(map[string]any); ok {
			from = parseTimes(f)
		}
		return covered, from, nil
	}
	return covered, from, nil
}

func parseTimes(m map[string]any) map[string]time.Time {
	out := map[string]time.Time{}
	for id, v := range m {
		if s, ok := v.(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				out[id] = t
			}
		}
	}
	return out
}

// incrementalKind は、位置から続きだけを読めるソースの種類 (窓の範囲でイベントか日次集計を引くもの)。スナップショットは窓に依らないので含めない。
func incrementalKind(kind string) bool {
	switch kind {
	case config.KindCloudTrailLookup, config.KindCloudTrailS3, config.KindCloudTrailUnusedRegions, config.KindCloudWatchLogs:
		return true
	}
	return false
}

// planCatchup は前回の run の位置から、遅れているソースを決める。追いつきは max_catchup までで、超えた分は諦めて警告する。
func (e *Engine) planCatchup(ctx context.Context, profile string, prof config.Profile, base, now time.Time) (*catchup, error) {
	cu := &catchup{covered: map[string]time.Time{}, from: map[string]time.Time{}, coveredFrom: map[string]time.Time{}, ahead: map[string]time.Time{}}
	var err error
	if cu.covered, cu.coveredFrom, err = e.latestPositions(ctx); err != nil {
		return cu, err
	}
	floor := now.Add(-prof.MaxCatchup)
	needs := e.neededKinds(prof)
	for _, src := range e.cfg.Sources {
		t, ok := cu.covered[src.ID]
		// 決定 (ADR 0064): このプロファイルが読まないソースは見ない (位置は共有なので、hourly から見た daily だけのソースは常に古い)
		if !ok || !anyNeeded(kindsOf(e.cfg, src), needs) {
			continue
		}
		if !t.Before(base) {
			if f, ok := cu.coveredFrom[src.ID]; ok && incrementalKind(src.Kind) && !f.After(base.Add(-src.IngestDelay)) && t.After(base) {
				cu.ahead[src.ID] = t
			}
			continue
		}
		// 決定 (ADR 0050): このプロファイルが log_hygiene のためだけに読む cloudwatch-logs のソースは追いつかない。
		// 状態を見るチェックで、範囲は常に run の窓 (読み取りを増やさず、窓も広げない)
		if src.Kind == config.KindCloudWatchLogs && !anyNeeded(formatKinds(src), needs) {
			continue
		}
		if t.Before(floor) {
			e.log.Warn("source is too far behind; events before covered_from are lost", "code", CodeSourceCatchupTruncated, "source", src.ID,
				"covered_to", t.UTC().Format(time.RFC3339), "covered_from", floor.UTC().Format(time.RFC3339))
			t = floor
		}
		if !t.Before(base) {
			continue
		}
		cu.from[src.ID] = t
		// 読み取りが増える (Logs Insights はスキャン量に応じた費用がかかる) ので、気づけるように警告する
		e.log.Warn("source failed earlier; catching up from its last covered position", "code", CodeSourceCatchup, "source", src.ID, "from", t.UTC().Format(time.RFC3339))
		if src.Kind == config.KindCloudWatchLogs {
			cu.metricsFrom = earlier(cu.metricsFrom, t)
		} else {
			cu.eventsFrom = earlier(cu.eventsFrom, t)
		}
	}
	return cu, nil
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

// advance は今回の結果で位置を進める。成功したソースは窓の終わりへ、失敗したソースは前の位置のまま (無ければ窓の始まり)。
// 決定: 途中まで取れたソースも進めない。CoveredUntil は新しい側の端で、古い側が未取得のまま残るため。引き直しは重複しない (event_id と日次の置き換え)。
// 決定 (ADR 0064): 途切れずに読めている始まりも返す。成功したソースは、今回読み始めた所 (再走査を含む) が前の位置以前なら前の始まりを引き継ぎ、
// そうでなければ (前の位置が無い・途切れた) 今回読み始めた所。失敗したソースは前のまま。
func (c *catchup) advance(cr CollectResult, base, to time.Time) (covered, from map[string]string) {
	out := make(map[string]time.Time, len(c.covered))
	for id, t := range c.covered {
		out[id] = t
	}
	outFrom := make(map[string]time.Time, len(c.coveredFrom))
	for id, t := range c.coveredFrom {
		outFrom[id] = t
	}
	for _, id := range cr.SourcesOK {
		start, ok := cr.scanFrom[id]
		if !ok {
			start = base
		}
		prev, hasPrev := c.covered[id]
		prevFrom, hasFrom := c.coveredFrom[id]
		if hasPrev && hasFrom && !start.After(prev) {
			outFrom[id] = earlier(prevFrom, start)
		} else {
			outFrom[id] = start
		}
		out[id] = to
	}
	for _, id := range cr.SourcesFailed {
		if _, ok := out[id]; !ok {
			out[id] = base
		}
	}
	return timesText(out), timesText(outFrom)
}

func timesText(m map[string]time.Time) map[string]string {
	out := make(map[string]string, len(m))
	for k, t := range m {
		out[k] = t.UTC().Format(time.RFC3339Nano)
	}
	return out
}
