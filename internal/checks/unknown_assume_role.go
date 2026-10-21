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

// UnknownAssumeRole は呼び出し元 ARN が allowlist に無い AssumeRole を報告する (high)。
// 決定: AWS サービス主体 (EC2 / Lambda などがインスタンスロールを引き受けるもの) は対象外。
type UnknownAssumeRole struct{}

func (UnknownAssumeRole) Name() string         { return "unknown_assume_role" }
func (UnknownAssumeRole) Cadence() Cadence     { return Hourly }
func (UnknownAssumeRole) Mode() Mode           { return ModeEvent }
func (UnknownAssumeRole) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

func (c UnknownAssumeRole) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{NamePrefixes: []string{"AssumeRole"}})
	if err != nil {
		return nil, err
	}
	aggs := map[string]*eventAgg{}
	for _, e := range evs {
		if e.PrincipalKind == record.PrincipalService || e.PrincipalARN == "" {
			continue
		}
		_, status := al.Principal(e.PrincipalARN, w.To)
		if status == allowlist.StatusApproved {
			continue
		}
		role, _ := e.Data["role_arn"].(string)
		if role == "" {
			role = e.Resource
		}
		k := e.PrincipalARN + "->" + role
		a, ok := aggs[k]
		if !ok {
			a = newEventAgg()
			a.extra["caller"] = e.PrincipalARN
			a.extra["caller_kind"] = string(e.PrincipalKind)
			a.extra["role_arn"] = role
			a.extra["allowlist_status"] = string(status)
			if acct, ok := record.ExternalAccount(e.PrincipalARN, e.PrincipalKind); ok {
				a.extra["external_account"] = acct
			}
			aggs[k] = a
		}
		a.add(e.Time, e.Name, e.IP)
		if e.ErrorCode != "" {
			a.extra["has_errors"] = true
		}
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		caller, role, _ := strings.Cut(k, "->")
		if acct, ok := a.extra["external_account"].(string); ok {
			caller = "外部アカウント " + acct
		}
		obs[k] = Observation{
			Check:       c.Name(),
			Key:         k,
			Severity:    High,
			Summary:     fmt.Sprintf("既知リストに無い %s が %s を %d 回引き受け", caller, role, a.count),
			Fingerprint: fingerprint(High, a.ips, a.extra["allowlist_status"]),
			Data:        a.data(),
		}
	}
	return sortedObs(obs), nil
}
