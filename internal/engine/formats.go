package engine

import (
	"context"
	"errors"
	"math"
	"sort"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/report"
)

// FORMAT_DRIFT の判定 (設計書 2-2): 直近 driftRuns 回の解釈率の平均から driftDrop 以上落ちたら警告する。
// 決定: 過去の計測が driftMinRuns 回未満なら判定しない (導入直後の 1〜2 回の揺れで鳴らさない)。
const (
	driftRuns    = 7
	driftMinRuns = 3
	driftDrop    = 0.20
	// driftScanRuns は解釈率を探す run の数。hourly の run は Logs Insights を引かないので多めに見る。
	driftScanRuns = 200
)

// formatCoverage は collector の解釈率を report の形にし、FORMAT_DRIFT を判定してログに出す。
// FORMAT_MISMATCH のログは収集エラーとして Collect が出す。
func (e *Engine) formatCoverage(ctx context.Context, st collect.FormatStats, collectErr error, runID string) report.FormatCoverage {
	fc := report.FormatCoverage{Source: st.Source, Format: st.Format, LogGroup: st.LogGroup, Total: st.Total, Matched: st.Matched,
		Expected: st.Expected, BytesScanned: st.BytesScanned}
	rate, ok := st.Rate()
	if !ok {
		return fc
	}
	r := round3(rate)
	fc.MatchRate = &r
	var ce *collect.Error
	if errors.As(collectErr, &ce) && ce.Code == collect.CodeFormatMismatch {
		fc.Code = collect.CodeFormatMismatch
		return fc
	}
	avg, n, err := e.recentMatchRate(ctx, st.Source)
	if err != nil {
		e.log.Warn("failed to read recent match rates", "source", st.Source, "error", err.Error())
		return fc
	}
	if n < driftMinRuns {
		return fc
	}
	a := round3(avg)
	fc.RecentAverage = &a
	if avg-rate >= driftDrop {
		fc.Code = collect.CodeFormatDrift
		attrs := []any{"code", collect.CodeFormatDrift, "source", st.Source, "log_group", st.LogGroup, "format", st.Format,
			"match_rate", r, "recent_average", a, "recent_runs", n}
		if runID != "" {
			attrs = append(attrs, "run_id", runID)
		}
		e.log.Warn("match rate dropped sharply; log format may have changed", attrs...)
	}
	return fc
}

// recentMatchRate は直近 driftRuns 回 (このソースの解釈率を記録した run) の平均。
func (e *Engine) recentMatchRate(ctx context.Context, source string) (float64, int, error) {
	runs, err := e.st.RecentRuns(ctx, driftScanRuns)
	if err != nil {
		return 0, 0, err
	}
	sum, n := 0.0, 0
	for _, r := range runs {
		rates, _ := r.Stats["match_rates"].(map[string]any)
		v, ok := rates[source].(float64)
		if !ok {
			continue
		}
		sum += v
		n++
		if n == driftRuns {
			break
		}
	}
	if n == 0 {
		return 0, 0, nil
	}
	return sum / float64(n), n, nil
}

// addFormatStats は runs.stats に解釈率とスキャン量を残す (FORMAT_DRIFT の判定元)。
func addFormatStats(stats map[string]any, formats []report.FormatCoverage) {
	if len(formats) == 0 {
		return
	}
	rates, scanned := map[string]any{}, map[string]any{}
	for _, f := range formats {
		if f.MatchRate != nil {
			rates[f.Source] = *f.MatchRate
		}
		scanned[f.Source] = f.BytesScanned
	}
	stats["match_rates"] = rates
	stats["bytes_scanned"] = scanned
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortFormats(l []report.FormatCoverage) {
	sort.Slice(l, func(i, j int) bool { return l[i].Source < l[j].Source })
}
