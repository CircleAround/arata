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

// NewPrincipal は allowlist にも principals (ベースライン / 承認済み) にも無い主体を報告する (medium)。
// 承認されるまで毎回観測されるので、放置すると still_open として残る (設計書 6-2)。
// 決定: root は root_usage が扱うので対象外。
type NewPrincipal struct{}

func (NewPrincipal) Name() string         { return "new_principal" }
func (NewPrincipal) Cadence() Cadence     { return Daily }
func (NewPrincipal) Mode() Mode           { return ModeState }
func (NewPrincipal) Needs() []record.Kind { return []record.Kind{record.KindPrincipalSeen} }

func (c NewPrincipal) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	ps, err := q.Principals(ctx, store.PrincipalFilter{Statuses: []string{store.PrincipalUnknown, store.PrincipalExpired}})
	if err != nil {
		return nil, err
	}
	var obs []Observation
	for _, p := range ps {
		if p.Kind == record.PrincipalRoot {
			continue
		}
		_, status := al.Principal(p.ARN, w.To)
		if status == allowlist.StatusApproved {
			continue
		}
		ips, err := q.PrincipalIPs(ctx, p.ARN)
		if err != nil {
			return nil, err
		}
		ipSet := map[string]bool{}
		total := 0
		for _, ip := range ips {
			ipSet[ip.IP] = true
			total += ip.Count
		}
		data := map[string]any{
			"kind":             string(p.Kind),
			"first_seen":       p.FirstSeen.UTC().Format(time.RFC3339),
			"last_seen":        p.LastSeen.UTC().Format(time.RFC3339),
			"count":            total,
			"allowlist_status": string(status),
		}
		if len(ipSet) > 0 {
			data["ips"] = sortedKeys(ipSet)
		}
		label := "新規の主体"
		if status == allowlist.StatusExpired {
			label = "承認期限切れの主体"
		}
		if acct, ok := record.ExternalAccount(p.ARN, p.Kind); ok {
			data["external_account"] = acct
		}
		obs = append(obs, Observation{
			Check:       c.Name(),
			Key:         p.ARN,
			Severity:    Medium,
			Summary:     fmt.Sprintf("%s %s (%s)", label, record.PrincipalLabel(p.ARN, p.Kind), p.Kind),
			Fingerprint: fingerprint(Medium, ipSet, p.Kind, status),
			Data:        data,
		})
	}
	return obs, nil
}
