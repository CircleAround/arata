package checks

import (
	"context"
	"fmt"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// RootUsage はルートアカウントの利用を報告する (critical)。Key は root ARN と送信元 IP。
//
// 決定: AWS のサービスが root の代わりに呼んだ記録は送信元が IP でない (collector が IP を空にし、data.invoked_by にサービス名を残す)。
// Key (`<root>|` + 空の IP)・重大度・Fingerprint は変えず、見出しに「AWS のサービス (<名前>) 経由で」と書き、data に invoked_by を出す
// (空の送信元のままだと「 から N 件」と崩れ、送信元不明の操作に見える)。
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
		if name, ok := record.ServiceName(dataStr(e.Data, "invoked_by")); ok {
			services, _ := a.extra["invoked_by"].(map[string]bool)
			if services == nil {
				services = map[string]bool{}
				a.extra["invoked_by"] = services
			}
			services[name] = true
		}
		if v, ok := e.Data["mfa"]; ok {
			a.extra["mfa"] = v
		}
		if e.ErrorCode != "" {
			a.extra["has_errors"] = true
		}
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		// 決定: invoked_by (どの AWS のサービス経由か) は送信元の IP が無いときだけ出す。IP があるときの見出しと data は変えない
		services, _ := a.extra["invoked_by"].(map[string]bool)
		delete(a.extra, "invoked_by")
		var invokedBy []string
		if len(a.ips) == 0 && len(services) > 0 {
			invokedBy = capList(sortedKeys(services), maxInvokedBy)
			a.extra["invoked_by"] = invokedBy
		}
		obs[k] = Observation{
			Check:       c.Name(),
			Key:         k,
			Severity:    Critical,
			Summary:     fmt.Sprintf("ルートアカウント %s が %s %d 件の操作", a.extra["principal"], sourcePhrase(sortedKeys(a.ips), invokedBy), a.count),
			Fingerprint: fingerprint(Critical, a.ips, a.extra["mfa"]),
			Data:        a.data(),
		}
	}
	return sortedObs(obs), nil
}
