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

// WAFBlockTrend は WAF の BLOCK について、新規に鳴り始めたルールと、BLOCK 件数の Top IP の入れ替わり (新顔) を報告する (low)。
//
// 決定:
//   - 新規ルール: その日に new_rule_min_count 件以上 BLOCK し、過去 baseline_days 日に一度も BLOCK していないルール。Key は `rule|<ルール ID>`
//   - Top IP の新顔: その日の BLOCK 件数 Top N (min_count 以上) のうち、過去 baseline_days 日の合計 Top N に居ない IP。Key は `top_ip|<IP>`
//   - どちらも過去にデータのある日が min_baseline_days 未満の間 (導入直後) は判定しない
type WAFBlockTrend struct {
	Config config.WAFBlockTrend
}

func (WAFBlockTrend) Name() string         { return "waf_block_trend" }
func (WAFBlockTrend) Cadence() Cadence     { return Daily }
func (WAFBlockTrend) Mode() Mode           { return ModeEvent }
func (WAFBlockTrend) Needs() []record.Kind { return []record.Kind{record.KindWAFAction} }

func (c WAFBlockTrend) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	dates := windowDates(w)
	if len(dates) == 0 {
		return nil, nil
	}
	from, to := addDays(dates[0], -c.Config.BaselineDays), dates[len(dates)-1]
	rules, err := loadSeries(ctx, q, cwlogs.MetricWAFBlock, from, to)
	if err != nil {
		return nil, err
	}
	ips, err := loadSeries(ctx, q, cwlogs.MetricWAFBlockIP, from, to)
	if err != nil {
		return nil, err
	}
	obs := map[string]Observation{}
	keep := func(o Observation) {
		if cur, ok := obs[o.Key]; !ok || o.Data["count"].(float64) > cur.Data["count"].(float64) {
			obs[o.Key] = o
		}
	}
	for _, d := range dates {
		bds := baseDates(d, c.Config.BaselineDays)
		withData := 0
		pastRules := map[string]bool{}
		pastIPs := map[string]float64{}
		for _, bd := range bds {
			if len(rules[bd]) > 0 || len(ips[bd]) > 0 {
				withData++
			}
			for r, v := range rules[bd] {
				if v > 0 {
					pastRules[r] = true
				}
			}
			for ip, v := range ips[bd] {
				pastIPs[ip] += v
			}
		}
		if withData < c.Config.MinBaselineDays {
			continue
		}
		for _, r := range topKeys(rules[d], len(rules[d]), c.Config.NewRuleMinCount) {
			if pastRules[r] {
				continue
			}
			n := rules[d][r]
			keep(Observation{Check: c.Name(), Key: "rule|" + r, Severity: Low,
				Summary:     fmt.Sprintf("WAF ルール %s が新たに BLOCK し始めた: %.0f 件 (%s UTC)", r, n, d),
				Fingerprint: fingerprint(Low, nil, reasonNewRule),
				Data:        map[string]any{"rule": r, "date": d, "count": n, "reason": reasonNewRule, "baseline_days_with_data": withData}})
		}
		pastTop := map[string]bool{}
		for _, ip := range topKeys(pastIPs, c.Config.TopN, 0) {
			pastTop[ip] = true
		}
		for _, ip := range topKeys(ips[d], c.Config.TopN, c.Config.MinCount) {
			if pastTop[ip] || al.SourceIPAllowed(ip) {
				continue
			}
			n := ips[d][ip]
			keep(Observation{Check: c.Name(), Key: "top_ip|" + ip, Severity: Low,
				Summary:     fmt.Sprintf("WAF の BLOCK 上位に新しい IP %s: %.0f 件 (%s UTC)", ip, n, d),
				Fingerprint: fingerprint(Low, nil, reasonNewTopIP),
				Data:        map[string]any{"ip": ip, "date": d, "count": n, "reason": reasonNewTopIP, "past_top_ips": sortedKeys(pastTop), "baseline_days_with_data": withData}})
		}
	}
	return sortedObs(obs), nil
}
