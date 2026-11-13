package engine

import (
	"context"
	"time"

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
)

// ログの code。
const (
	CodeSourceCatchup          = "SOURCE_CATCHUP"
	CodeSourceCatchupTruncated = "SOURCE_CATCHUP_TRUNCATED"
)

type catchup struct {
	// covered は前回までの位置。
	covered map[string]time.Time
	// from は遅れているソースの開始位置。
	from map[string]time.Time
	// metricsFrom / eventsFrom は遅れているソースの最も古い位置 (集計 / それ以外)。ゼロなら遅れなし。
	metricsFrom, eventsFrom time.Time
}

// planCatchup は前回の run の位置から、遅れているソースを決める。追いつきは max_catchup までで、超えた分は諦めて警告する。
func (e *Engine) planCatchup(ctx context.Context, profile string, prof config.Profile, base, now time.Time) (*catchup, error) {
	cu := &catchup{covered: map[string]time.Time{}, from: map[string]time.Time{}}
	last, err := e.st.LastRun(ctx, profile, []string{"ok", "partial"})
	if err != nil || last == nil {
		return cu, err
	}
	if m, ok := last.Stats[sourceCoveredStat].(map[string]any); ok {
		for id, v := range m {
			if s, ok := v.(string); ok {
				if t, err := time.Parse(time.RFC3339, s); err == nil {
					cu.covered[id] = t
				}
			}
		}
	}
	floor := now.Add(-prof.MaxCatchup)
	needs := e.neededKinds(prof)
	for _, src := range e.cfg.Sources {
		t, ok := cu.covered[src.ID]
		if !ok || !t.Before(base) {
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
func (c *catchup) advance(cr CollectResult, base, to time.Time) map[string]string {
	out := make(map[string]time.Time, len(c.covered))
	for id, t := range c.covered {
		out[id] = t
	}
	for _, id := range cr.SourcesOK {
		out[id] = to
	}
	for _, id := range cr.SourcesFailed {
		if _, ok := out[id]; !ok {
			out[id] = base
		}
	}
	return timesText(out)
}

func timesText(m map[string]time.Time) map[string]string {
	out := make(map[string]string, len(m))
	for k, t := range m {
		out[k] = t.UTC().Format(time.RFC3339)
	}
	return out
}
