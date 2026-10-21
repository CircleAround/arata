package checks

import (
	"context"
	"fmt"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ProbePaths は機密パス (/.env, /.git/ など。設定 checks.probe_paths) への 403/404 の IP 別件数が平常帯を超えたものを報告する (low)。
// 根拠としてその日に多かったパス (全 IP 合計の上位) を添える。
type ProbePaths struct {
	Config config.ProbePaths
}

func (ProbePaths) Name() string         { return "probe_paths" }
func (ProbePaths) Cadence() Cadence     { return Daily }
func (ProbePaths) Mode() Mode           { return ModeEvent }
func (ProbePaths) Needs() []record.Kind { return []record.Kind{record.KindHTTPAccess} }

// probeTopPaths は Data に添えるパスの数。
const probeTopPaths = 5

func (c ProbePaths) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	sps, err := detectSpikes(ctx, q, cwlogs.MetricProbeHits, w, c.Config.Baseline, c.Config.TopIPMinCount, al.SourceIPAllowed)
	if err != nil || len(sps) == 0 {
		return nil, err
	}
	dates := windowDates(w)
	paths, err := loadSeries(ctx, q, cwlogs.MetricProbePaths, dates[0], dates[len(dates)-1])
	if err != nil {
		return nil, err
	}
	obs := make([]Observation, 0, len(sps))
	for _, sp := range sps {
		d := sp.data("ip")
		var top []string
		for _, p := range topKeys(paths[sp.Date], probeTopPaths, 1) {
			top = append(top, fmt.Sprintf("%s (%.0f)", p, paths[sp.Date][p]))
		}
		if len(top) > 0 {
			d["top_paths_of_day"] = top
		}
		summary := fmt.Sprintf("機密パスの探索が平常帯を超過: %s から 403/404 が %.0f 件 (%s UTC、閾値 %.0f)", sp.Key, sp.Count, sp.Date, sp.Threshold)
		if sp.Reason == reasonNewTopIP {
			summary = fmt.Sprintf("機密パス探索の最多 IP が初出: %s から %.0f 件 (%s UTC)", sp.Key, sp.Count, sp.Date)
		}
		obs = append(obs, Observation{Check: c.Name(), Key: sp.Key, Severity: Low, Summary: summary,
			Fingerprint: fingerprint(Low, nil, sp.Reason), Data: d})
	}
	return obs, nil
}
