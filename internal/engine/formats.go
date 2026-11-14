package engine

import (
	"context"
	"errors"
	"math"
	"sort"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/report/schema"
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
		Expected: st.Expected, BytesScanned: st.BytesScanned, Truncated: st.Truncated}
	fc.Requests = requestCoverage(st.Requests)
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

// requestCoverage は request_lines のリクエスト単位の集計を report の形にする (それ以外の形式では nil)。
func requestCoverage(rs *collect.RequestStats) *report.RequestCoverage {
	if rs == nil {
		return nil
	}
	rc := &report.RequestCoverage{Total: rs.Total, Complete: rs.Complete, Expected: rs.Expected, WithStatus: rs.WithStatus,
		Starts: rs.Starts, Reused: rs.Reused, StartsUntagged: rs.StartsUntagged}
	if u := rs.Users; u != nil {
		rc.Users = &schema.UserCoverage{From: u.From, WithUser: u.Requests, Kinds: copyCounts(u.Kinds), WithBy: u.By, Invalid: u.Invalid}
	}
	if a := rs.Auth; a != nil {
		rc.Auth = &schema.AuthCoverage{Success: a.Success, Via: copyCounts(a.Via), Failure: a.Failure, Reasons: copyCounts(a.Reasons), Impersonate: a.Impersonate, Invalid: a.Invalid}
	}
	setCompleteRate(rc)
	return rc
}

func copyCounts(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// setCompleteRate は数から割合 (まとめられた割合と、ID の付いたリクエストの割合) を作り直す。
func setCompleteRate(rc *report.RequestCoverage) {
	rc.CompleteRate = nil
	if rc.Total > 0 {
		r := round3(float64(rc.Complete) / float64(rc.Total))
		rc.CompleteRate = &r
	}
	if rc.Users != nil {
		rc.Users.UserRate = nil
		if rc.Starts > 0 {
			r := round3(float64(rc.Users.WithUser) / float64(rc.Starts))
			rc.Users.UserRate = &r
		}
	}
}

// addRequestCoverage は q の数を t に足した複製を返す (init が日ごとの結果を合わせる)。割合は setCompleteRate で作り直す。
func addRequestCoverage(t, q *report.RequestCoverage) *report.RequestCoverage {
	r := *t
	r.Total, r.Complete, r.WithStatus = r.Total+q.Total, r.Complete+q.Complete, r.WithStatus+q.WithStatus
	r.Starts, r.Reused, r.StartsUntagged = r.Starts+q.Starts, r.Reused+q.Reused, r.StartsUntagged+q.StartsUntagged
	addCounts := func(dst, src map[string]int64) map[string]int64 {
		out := copyCounts(dst)
		for k, v := range src {
			out[k] += v
		}
		return out
	}
	if t.Users != nil && q.Users != nil {
		u := *t.Users
		u.WithUser, u.WithBy, u.Invalid, u.Kinds = u.WithUser+q.Users.WithUser, u.WithBy+q.Users.WithBy, u.Invalid+q.Users.Invalid, addCounts(u.Kinds, q.Users.Kinds)
		r.Users = &u
	}
	if t.Auth != nil && q.Auth != nil {
		a := *t.Auth
		a.Success, a.Failure, a.Impersonate, a.Invalid = a.Success+q.Auth.Success, a.Failure+q.Auth.Failure, a.Impersonate+q.Auth.Impersonate, a.Invalid+q.Auth.Invalid
		a.Via, a.Reasons = addCounts(a.Via, q.Auth.Via), addCounts(a.Reasons, q.Auth.Reasons)
		r.Auth = &a
	}
	return &r
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
	rates, scanned, truncated, requests := map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}
	for _, f := range formats {
		if q := f.Requests; q != nil {
			m := map[string]any{"total": q.Total, "complete": q.Complete, "with_status": q.WithStatus, "starts": q.Starts,
				"request_id_reused": q.Reused, "starts_untagged": q.StartsUntagged}
			if q.CompleteRate != nil {
				m["complete_rate"] = *q.CompleteRate
			}
			// ID の付いたリクエストの割合 (ADR 0052。後から「直近の平均から落ちた」を判定する元)
			if u := q.Users; u != nil {
				m["user_id_from"], m["with_user"], m["with_by"], m["user_id_invalid"] = u.From, u.WithUser, u.WithBy, u.Invalid
				if u.UserRate != nil {
					m["user_rate"] = *u.UserRate
				}
			}
			if a := q.Auth; a != nil {
				m["auth_success"], m["auth_failure"], m["auth_impersonate"], m["auth_invalid"] = a.Success, a.Failure, a.Impersonate, a.Invalid
			}
			requests[f.Source] = m
		}
		if f.MatchRate != nil {
			rates[f.Source] = *f.MatchRate
		}
		scanned[f.Source] = f.BytesScanned
		if len(f.Truncated) > 0 {
			truncated[f.Source] = f.Truncated
		}
	}
	stats["match_rates"] = rates
	stats["bytes_scanned"] = scanned
	// 行の上限 (10000) に当たった集計 (件数は少なめ。ADR 0023)
	if len(truncated) > 0 {
		stats["truncated_aggregates"] = truncated
	}
	// request_lines のリクエスト単位の集計 (まとめられた割合・使い回し。ADR 0051)
	if len(requests) > 0 {
		stats["request_stats"] = requests
	}
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
