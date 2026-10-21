package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// RootUsage はルートアカウントの利用を報告する (critical)。Key は root ARN と送信元 IP。
type RootUsage struct{}

func (RootUsage) Name() string         { return "root_usage" }
func (RootUsage) Cadence() Cadence     { return Hourly }
func (RootUsage) Mode() Mode           { return ModeEvent }
func (RootUsage) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

func (c RootUsage) Evaluate(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{PrincipalKinds: []record.PrincipalKind{record.PrincipalRoot}})
	if err != nil {
		return nil, err
	}
	aggs := map[string]*eventAgg{}
	for _, e := range evs {
		k := e.PrincipalARN + "|" + e.IP
		a, ok := aggs[k]
		if !ok {
			a = newEventAgg()
			a.extra["principal"] = e.PrincipalARN
			aggs[k] = a
		}
		a.add(e.Time, e.Name, e.IP)
		if v, ok := e.Data["mfa"]; ok {
			a.extra["mfa"] = v
		}
		if e.ErrorCode != "" {
			a.extra["has_errors"] = true
		}
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		obs[k] = Observation{
			Check:       c.Name(),
			Key:         k,
			Severity:    Critical,
			Summary:     fmt.Sprintf("ルートアカウント %s が %s から %d 件の操作", a.extra["principal"], strings.Join(sortedKeys(a.ips), ","), a.count),
			Fingerprint: fingerprint(Critical, a.ips, a.extra["mfa"]),
			Data:        a.data(),
		}
	}
	return sortedObs(obs), nil
}
