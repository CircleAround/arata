package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// AIPathUsage は allowlist で `tags: [ai]` を持つ主体 (監査ロール・AI 用の主体) の利用を、主体 × 送信元 IP で毎回 info に 1 行出す (日次、event)。
// 自己監査 (設計書 3-4): 監査や AI の経路が乗っ取られて使われても、いつもと違う IP が並ぶことで人が気づけるようにする。
// 窓内に観測された (principal_ips.last_seen が窓内の) 組だけを出す。件数は累計 (count_total)。info なので件数・通知には数えない。
type AIPathUsage struct{}

func (AIPathUsage) Name() string         { return "ai_path_usage" }
func (AIPathUsage) Cadence() Cadence     { return Daily }
func (AIPathUsage) Mode() Mode           { return ModeEvent }
func (AIPathUsage) Needs() []record.Kind { return []record.Kind{record.KindPrincipalSeen} }

func (c AIPathUsage) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	ps, err := q.Principals(ctx, store.PrincipalFilter{})
	if err != nil {
		return nil, err
	}
	var obs []Observation
	for _, p := range ps {
		e, status := al.Principal(p.ARN, w.To)
		if status != allowlist.StatusApproved || !e.HasTag(allowlist.TagAI) {
			continue
		}
		ips, err := q.PrincipalIPs(ctx, p.ARN)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.LastSeen.Before(w.Start()) || !ip.LastSeen.Before(w.To) {
				continue
			}
			obs = append(obs, Observation{Check: c.Name(), Key: p.ARN + "|" + ip.IP, Severity: Info,
				Summary:     fmt.Sprintf("AI / 監査用の主体の利用: %s from %s (最終 %s)", record.PrincipalLabel(p.ARN, p.Kind), ip.IP, ip.LastSeen.UTC().Format(time.RFC3339)),
				Fingerprint: fingerprint(Info, nil, ip.IP),
				Data: map[string]any{"arn": p.ARN, "ip": ip.IP, "first_seen": ip.FirstSeen.UTC().Format(time.RFC3339), "last_seen": ip.LastSeen.UTC().Format(time.RFC3339),
					"count_total": ip.Count}})
		}
	}
	return obs, nil
}
