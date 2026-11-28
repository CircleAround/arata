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
//
// 決定 (ADR 0094 の 1 節の実装): allowlist の shared_sources (人の多い送信元) の IP は、その日に期限内なら、平常帯の下限を
// shared_min_count にし、「その日の最多 IP が初出」(new_top_ip) を報告しない。報告するときは data に shared と shared_note を足す。
// source_ips とも当たる IP は source_ips を優先する (対象外)。
type LoginBruteforce struct {
	Config config.LoginBruteforce
}

func (LoginBruteforce) Name() string         { return "login_bruteforce" }
func (LoginBruteforce) Cadence() Cadence     { return Daily }
func (LoginBruteforce) Mode() Mode           { return ModeEvent }
func (LoginBruteforce) Needs() []record.Kind { return []record.Kind{record.KindHTTPAccess} }

func (c LoginBruteforce) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	shared := func(ip, date string) bool { _, ok := sharedSourceOn(al, ip, date); return ok }
	sps, err := detectSpikes(ctx, q, cwlogs.MetricSignInFailures, w, c.Config.Baseline, c.Config.TopIPMinCount, al.SourceIPAllowed, shared, c.Config.SharedMinCount)
	if err != nil {
		return nil, err
	}
	obs := make([]Observation, 0, len(sps))
	for _, sp := range sps {
		summary := fmt.Sprintf("sign-in 失敗が平常帯を超過: %s から %.0f 件 (%s UTC、平常 %.1f、閾値 %.0f)", sp.Key, sp.Count, sp.Date, sp.Median, sp.Threshold)
		if sp.Reason == reasonNewTopIP {
			summary = fmt.Sprintf("sign-in 失敗の最多 IP が初出: %s から %.0f 件 (%s UTC)", sp.Key, sp.Count, sp.Date)
		}
		data := sp.data("ip")
		if e, ok := sharedSourceOn(al, sp.Key, sp.Date); ok && sp.Shared {
			summary += "。人の多い送信元 (shared_sources) の下限で判定"
			addShared(data, e)
		}
		obs = append(obs, Observation{Check: c.Name(), Key: sp.Key, Severity: Medium, Summary: summary,
			Fingerprint: fingerprint(Medium, nil, sp.Reason), Data: data})
	}
	return obs, nil
}
