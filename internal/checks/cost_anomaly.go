package checks

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// CostAnomaly は AWS Cost Anomaly Detection が検出した費用の異常 (急増) を報告する (ADR 0032)。
// 採掘や漏洩した認証情報の悪用は、まず費用の急増として現れることがある。費用の削減の提案はしない (別の製品の候補)。
//
// 決定:
//   - 判定は AWS の異常検出の結果に乗る (arata が費用の平常帯を持たない)。重大度は予想に対する増加の割合 (TotalImpactPercentage、
//     無ければ TotalImpact / TotalExpectedSpend) で決める: medium_impact_ratio 以上で medium、high_impact_ratio 以上で high。
//     固定の金額はサービスの規模で意味が変わるので使わない。総影響額が min_impact_usd 未満のものは割合が大きくても報告しない (小さな額の誤報)。
//     予想額が 0 や欠けていて割合を出せなければ、下限以上の影響額を medium にする。critical は出さない (費用だけでは侵害と言えない)
//   - 利用者がコンソールで Feedback を付けた異常のうち、NO (異常でない) と PLANNED_ACTIVITY (計画した活動) は報告しない
//   - ModeEvent、Key は異常の ID。続いている間は毎日観測されて still_open。影響額が日々増えても重大度が同じなら再報告しない (Fingerprint は重大度だけ)
type CostAnomaly struct {
	Config config.CostAnomaly
}

func (CostAnomaly) Name() string         { return "cost_anomaly" }
func (CostAnomaly) Cadence() Cadence     { return Daily }
func (CostAnomaly) Mode() Mode           { return ModeEvent }
func (CostAnomaly) Needs() []record.Kind { return []record.Kind{record.KindCostAnomaly} }

func (c CostAnomaly) Evaluate(ctx context.Context, q store.Query, _ collect.Window, _ *allowlist.List) ([]Observation, error) {
	items, err := q.Snapshot(ctx, record.KindCostAnomaly)
	if err != nil {
		return nil, err
	}
	var obs []Observation
	for _, it := range items {
		feedback := it.String("feedback")
		if feedback == "NO" || feedback == "PLANNED_ACTIVITY" {
			continue
		}
		total := it.Number("total_impact")
		if total < c.Config.MinImpactUSD {
			continue
		}
		ratio, hasRatio := impactRatio(it)
		sev := Medium
		switch {
		case !hasRatio:
		case ratio >= c.Config.HighImpactRatio:
			sev = High
		case ratio < c.Config.MediumImpactRatio:
			continue
		}
		rcs := dataMaps(it.Data, "root_causes")
		var summary string
		if hasRatio {
			summary = fmt.Sprintf("費用の異常: %s の費用が予想 %.2f USD に対し %.2f USD (+%.0f%%、影響 %.2f USD。%s〜%s)", it.String("dimension_value"),
				it.Number("total_expected_spend"), actualSpend(it), ratio*100, total, it.String("start_date"), it.String("end_date"))
		} else {
			summary = fmt.Sprintf("費用の異常: %s の費用 %.2f USD (影響 %.2f USD。%s〜%s)。予想額が無いので割合を出せない", it.String("dimension_value"),
				actualSpend(it), total, it.String("start_date"), it.String("end_date"))
		}
		if len(rcs) > 0 {
			var parts []string
			for _, k := range []string{"region", "service", "usage_type"} {
				if v := dataStr(rcs[0], k); v != "" {
					parts = append(parts, v)
				}
			}
			if len(parts) > 0 {
				summary += "。主な原因: " + strings.Join(parts, " / ")
			}
		}
		d := map[string]any{"anomaly_id": it.Key, "root_causes": rcs, "total_actual_spend": actualSpend(it)}
		if hasRatio {
			d["impact_ratio"] = math.Round(ratio*1000) / 1000
		}
		for _, k := range []string{"monitor_arn", "dimension_value", "start_date", "end_date", "feedback"} {
			d[k] = it.String(k)
		}
		for _, k := range []string{"total_impact", "max_impact", "total_expected_spend", "total_impact_percentage", "max_score"} {
			if _, ok := it.Data[k]; ok {
				d[k] = it.Number(k)
			}
		}
		obs = append(obs, Observation{Check: c.Name(), Key: it.Key, Severity: sev, Summary: summary, Fingerprint: fingerprint(sev, nil), Data: d})
	}
	return obs, nil
}

// impactRatio は予想に対する増加の割合 (影響額 / 予想額)。TotalImpactPercentage を優先し、無ければ TotalImpact / TotalExpectedSpend。
// 予想額が 0 や欠けていれば ok=false。
func impactRatio(it record.SnapshotItem) (float64, bool) {
	if _, ok := it.Data["total_impact_percentage"]; ok {
		if exp := it.Number("total_expected_spend"); exp > 0 {
			return it.Number("total_impact_percentage") / 100, true
		}
	}
	if exp := it.Number("total_expected_spend"); exp > 0 {
		return it.Number("total_impact") / exp, true
	}
	return 0, false
}

// actualSpend は実際の額 (無ければ予想額 + 影響額)。
func actualSpend(it record.SnapshotItem) float64 {
	if _, ok := it.Data["total_actual_spend"]; ok {
		return it.Number("total_actual_spend")
	}
	return it.Number("total_expected_spend") + it.Number("total_impact")
}
