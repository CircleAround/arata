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

// LoginBruteforce は sign-in 失敗の IP 別件数が平常帯を超えたもの、およびその日の Top IP が初出のものを報告する (medium)。
// 集計は cwlogs の sign_in_failures (設定 checks.login_bruteforce のパス・メソッド・ステータス)。source_ips の IP は対象外。
type LoginBruteforce struct {
	Config config.LoginBruteforce
}

func (LoginBruteforce) Name() string         { return "login_bruteforce" }
func (LoginBruteforce) Cadence() Cadence     { return Daily }
func (LoginBruteforce) Mode() Mode           { return ModeEvent }
func (LoginBruteforce) Needs() []record.Kind { return []record.Kind{record.KindHTTPAccess} }

func (c LoginBruteforce) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	sps, err := detectSpikes(ctx, q, cwlogs.MetricSignInFailures, w, c.Config.Baseline, c.Config.TopIPMinCount, al.SourceIPAllowed)
	if err != nil {
		return nil, err
	}
	obs := make([]Observation, 0, len(sps))
	for _, sp := range sps {
		summary := fmt.Sprintf("sign-in 失敗が平常帯を超過: %s から %.0f 件 (%s UTC、平常 %.1f、閾値 %.0f)", sp.Key, sp.Count, sp.Date, sp.Median, sp.Threshold)
		if sp.Reason == reasonNewTopIP {
			summary = fmt.Sprintf("sign-in 失敗の最多 IP が初出: %s から %.0f 件 (%s UTC)", sp.Key, sp.Count, sp.Date)
		}
		obs = append(obs, Observation{Check: c.Name(), Key: sp.Key, Severity: Medium, Summary: summary,
			Fingerprint: fingerprint(Medium, nil, sp.Reason), Data: sp.data("ip")})
	}
	return obs, nil
}
