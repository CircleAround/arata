package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/store"
)

// 続きだけの収集 (`arata collect --incremental`) と、1 回の収集の上限 (max_collect)。ADR 0064 の 2 段目。
//
// 決定:
//   - 収集だけの run は評価も報告もしない。全プロファイルが要る CloudTrail のソース (cloudtrail-lookup・cloudtrail-s3・cloudtrail-unused-regions) の
//     続きだけを、共有の位置から集めて位置を進める (run の stats に位置を書くので、プロファイルの run が読み直さない)。
//     cloudwatch-logs は時の単位で読むソース (collect: hourly。ADR 0065) だけを対象にする: 日の頭から読み直すソースを短い間隔で回すと、
//     読み取り (費用) が増える。collect: hourly を既定にしたら、この区別も無くす (行き着く先は、種類を問わず 1 つの間隔で全部を集め、利用者が決めるのは間隔だけ)
//   - 位置が無いソースは、そのソースを要るプロファイルの最も長い窓の分を集める (次のプロファイルの run が、その窓を覆う位置として使える)。
//     遅れが max_catchup (そのプロファイルの最も長いもの) を超えたら、超えた分は諦めて SOURCE_CATCHUP_TRUNCATED
//   - max_collect: ソースの 1 回の収集を読み始め + max_collect で止め、位置をそこまで進める。run は partial (終了コード 3) で SOURCE_COLLECT_LIMITED。
//     プロファイルの run でも同じ上限が効き、止めた時刻より後の記録が報告に入っていないことを coverage.notes に書く

// collectIncrementalProfile は収集だけの run の profile (runs の行。プロファイルの窓や RUN_MISSED には使わない)。
const collectIncrementalProfile = "collect-incremental"

// incrementalCollectSource は、収集だけの run が集めるソース (CloudTrail と、時の単位で読む cloudwatch-logs。上の決定)。
func incrementalCollectSource(src config.Source) bool {
	switch src.Kind {
	case config.KindCloudTrailLookup, config.KindCloudTrailS3, config.KindCloudTrailUnusedRegions:
		return true
	case config.KindCloudWatchLogs:
		return src.CollectHourly() && len(formatKinds(src)) > 0
	}
	return false
}

// collectStarts は、プロファイルの run で max_collect のあるソースの読み始め (再走査の前)。
func (e *Engine) collectStarts(prof config.Profile, base time.Time, cu *catchup) map[string]time.Time {
	out := map[string]time.Time{}
	needs := e.neededKinds(prof)
	for _, src := range e.cfg.Sources {
		if src.MaxCollect <= 0 || !anyNeeded(kindsOf(e.cfg, src), needs) {
			continue
		}
		start := base
		if t, ok := cu.from[src.ID]; ok && t.Before(start) {
			start = t
		}
		if t, ok := cu.ahead[src.ID]; ok && t.After(start) {
			start = t
		}
		out[src.ID] = start
	}
	return out
}

// limitCollect は max_collect を超えるソースの止める時刻を返し、SOURCE_COLLECT_LIMITED を出す。
func (e *Engine) limitCollect(starts map[string]time.Time, to time.Time, runID string) map[string]time.Time {
	out := map[string]time.Time{}
	for _, src := range e.cfg.Sources {
		start, ok := starts[src.ID]
		// 時の単位で読む cloudwatch-logs は collector が上限を効かせる (日の頭からの読み直しを含めて数えるため。ADR 0065)
		if !ok || src.MaxCollect <= 0 || to.Sub(start) <= src.MaxCollect || src.CollectHourly() {
			continue
		}
		out[src.ID] = start.Add(src.MaxCollect)
		e.log.Warn("source reached max_collect; collecting up to the limit and continuing next time", "code", CodeSourceCollectLimited, "source", src.ID,
			"from", start.UTC().Format(time.RFC3339), "until", out[src.ID].UTC().Format(time.RFC3339), "max_collect", src.MaxCollectRaw, "run_id", runID)
	}
	return out
}

// Limited は max_collect で止めたソースがあるか (収集だけの run の終了コード 3)。
func (r CollectResult) Limited() bool { return len(r.scanTo) > 0 }

// limitedNotes は max_collect で止めたソースの注記 (人が読む文)。
func limitedNotes(cr CollectResult) []string {
	ids := make([]string, 0, len(cr.scanTo))
	for id := range cr.scanTo {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%s は 1 回の収集の上限 (max_collect) に当たり、%s まで集めた。それより後の記録はこの報告に入っていない (次の回が続きから集める)",
			id, cr.scanTo[id].UTC().Format(time.RFC3339)))
	}
	return out
}

func collectWindow(from, to time.Time) collect.Window { return collect.Window{From: from, To: to} }

// CollectIncremental は収集だけの run (`arata collect --incremental`)。評価も報告もせず、共有の位置から続きだけを集める。
func (e *Engine) CollectIncremental(ctx context.Context) (*CollectResult, error) {
	now := e.deps.Now()
	covered, coveredFrom, err := e.latestPositions(ctx)
	if err != nil {
		return nil, err
	}
	starts := map[string]time.Time{}
	var ids []string
	from := now
	for _, src := range e.cfg.Sources {
		if !incrementalCollectSource(src) {
			continue
		}
		var window, maxCatchup time.Duration
		for _, p := range e.cfg.Profiles {
			if anyNeeded(kindsOf(e.cfg, src), e.neededKinds(p)) {
				window, maxCatchup = max(window, p.Window), max(maxCatchup, p.MaxCatchup)
			}
		}
		if window == 0 {
			continue // どのプロファイルも要らない
		}
		start, ok := covered[src.ID]
		if !ok {
			start = now.Add(-window)
		}
		if floor := now.Add(-maxCatchup); start.Before(floor) {
			e.log.Warn("source is too far behind; events before covered_from are lost", "code", CodeSourceCatchupTruncated, "source", src.ID,
				"covered_to", start.UTC().Format(time.RFC3339), "covered_from", floor.UTC().Format(time.RFC3339))
			start = floor
		}
		if start.After(now) {
			start = now
		}
		starts[src.ID] = start
		ids = append(ids, src.ID)
		if start.Before(from) {
			from = start
		}
	}
	if len(ids) == 0 {
		return nil, e.configErr(errors.New("collect --incremental: no CloudTrail source (cloudtrail-lookup / cloudtrail-s3 / cloudtrail-unused-regions) is used by any profile"))
	}
	runID := e.deps.NewID()
	if err := e.st.BeginRun(ctx, store.Run{ID: runID, Profile: collectIncrementalProfile, WindowFrom: from, WindowTo: now, StartedAt: now, Status: "running"}); err != nil {
		return nil, err
	}
	limits := e.limitCollect(starts, now, runID)
	w := collectWindow(from, now)
	w.CollectedAt = now
	cr := e.Collect(ctx, w, CollectOptions{SourceIDs: ids, PrincipalStatus: store.PrincipalUnknown, RunID: runID, Rescan: true, BaseFrom: from,
		SourceStart: starts, SourceTo: limits})
	cu := &catchup{covered: covered, coveredFrom: coveredFrom}
	status := "ok"
	if cr.partial() {
		status = "partial"
	}
	stats := map[string]any{"records": cr.Records, "sources_ok": len(cr.SourcesOK), "sources_failed": len(cr.SourcesFailed),
		collectResultStat: collectSummary{OK: cr.SourcesOK, Failed: cr.SourcesFailed, Errors: cr.Errors}}
	stats[sourceCoveredStat], stats[sourceCoveredFromStat] = cu.advance(cr, from, now)
	if len(cr.scanTo) > 0 {
		stats["collect_limited"] = timesText(cr.scanTo)
	}
	// 解釈率・ソースごとの読み取り量 (bytes_scanned)・truncated を profile の run と同じ形で残す
	addFormatStats(stats, cr.Formats)
	if err := e.st.FinishRun(ctx, runID, status, stats); err != nil {
		return nil, err
	}
	e.log.Info("incremental collect finished", "run_id", runID, "status", status, "records", cr.Records)
	return &cr, nil
}
