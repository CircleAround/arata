package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// UnusedRegionActivity はふだん使わないリージョン (cloudtrail-unused-regions のソースが引いたリージョン) での書き込みを報告する (ADR 0032)。
// 仮想通貨の採掘のためのインスタンス作成など、漏洩した認証情報の悪用は、利用者が見ないリージョンで行われることが多い。
//
// 決定:
//   - 見るのは cloudtrail-unused-regions のソースのイベントだけ (Sources)。AWS のサービスの主体と ignore_event_sources (グローバルサービス) は数えない
//   - 成功した書き込みが 1 件でもあれば high、計算資源の作成 (compute_apis) なら critical。失敗 (拒否など) は計算資源の作成の試行だけを medium にし、
//     他の失敗は報告しない (権限の列挙は access_denied の領分。使っていないリージョンの拒否はふだん 0 件だが、ノイズの元にしない)
//   - allowlist の `tags: [deploy]` の承認済みの主体 (StackSets などで全リージョンに配る IaC) なら 1 段下げる (info にはしない)
//   - Key は `<リージョン>|<主体 ARN>`。Fingerprint は重大度と操作の集合 (件数や時刻は入れない)
type UnusedRegionActivity struct {
	Config config.UnusedRegionActivity
	// Sources は cloudtrail-unused-regions のソースの ID (Registry.SetUnusedRegionSources)。
	Sources []string
}

func (UnusedRegionActivity) Name() string         { return "unused_region_activity" }
func (UnusedRegionActivity) Cadence() Cadence     { return Daily }
func (UnusedRegionActivity) Mode() Mode           { return ModeEvent }
func (UnusedRegionActivity) Needs() []record.Kind { return []record.Kind{record.KindUnusedRegionEvent} }

// apiVersionSuffix は Lambda などの eventName に付く API の版 (20150331、20150331v2)。
var apiVersionSuffix = regexp.MustCompile(`^\d{8}(v\d+)?$`)

// apiOf はイベントを IAM の action の形 (`lambda:CreateFunction`) にする (版の接尾辞は外す)。
func apiOf(e record.TrailEvent) string {
	name := e.Name
	if i := strings.IndexFunc(name, func(r rune) bool { return r >= '0' && r <= '9' }); i > 0 && apiVersionSuffix.MatchString(name[i:]) {
		name = name[:i]
	}
	return strings.TrimSuffix(e.EventSource, ".amazonaws.com") + ":" + name
}

func (c UnusedRegionActivity) isCompute(e record.TrailEvent) bool {
	api := apiOf(e)
	for _, a := range c.Config.ComputeAPIs {
		if a == api {
			return true
		}
	}
	return false
}

func (c UnusedRegionActivity) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	if len(c.Sources) == 0 {
		return nil, nil
	}
	evs, err := windowEvents(ctx, q, w, store.EventFilter{Sources: c.Sources, WriteOnly: true})
	if err != nil {
		return nil, err
	}
	ignore := map[string]bool{}
	for _, s := range c.Config.IgnoreEventSources {
		ignore[s] = true
	}
	type agg struct {
		*eventAgg
		sev     Severity
		apis    map[string]bool
		compute map[string]bool
		// computeOK は成功した計算資源の作成があったか (無ければ試行だけ)
		computeOK bool
		failed    int
	}
	aggs := map[string]*agg{}
	for _, e := range evs {
		if e.ReadOnly || e.PrincipalKind == record.PrincipalService || ignore[e.EventSource] {
			continue
		}
		compute := c.isCompute(e)
		var sev Severity
		switch {
		case e.ErrorCode != "" && compute:
			sev = Medium
		case e.ErrorCode != "":
			continue
		case compute:
			sev = Critical
		default:
			sev = High
		}
		deploy := knownDeploy(al, e.PrincipalARN, w.To)
		if deploy {
			sev = lowerOne(sev)
		}
		k := e.Region + "|" + e.PrincipalARN
		a, ok := aggs[k]
		if !ok {
			a = &agg{eventAgg: newEventAgg(), apis: map[string]bool{}, compute: map[string]bool{}}
			a.extra["region"] = e.Region
			a.extra["principal"] = e.PrincipalARN
			a.extra["principal_kind"] = string(e.PrincipalKind)
			if deploy {
				a.extra["known_deploy_principal"] = true
			}
			aggs[k] = a
		}
		if sev.Rank() > a.sev.Rank() {
			a.sev = sev
		}
		api := apiOf(e)
		a.apis[api] = true
		if compute {
			a.compute[api] = true
			a.computeOK = a.computeOK || e.ErrorCode == ""
		}
		if e.ErrorCode != "" {
			a.failed++
		}
		a.add(e.Time, e.Name, e.IP)
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		apis, compute := sortedKeys(a.apis), sortedKeys(a.compute)
		a.extra["apis"] = apis
		a.extra["compute_apis"] = compute
		a.extra["failed"] = a.failed
		region, principal := a.extra["region"].(string), a.extra["principal"].(string)
		summary := fmt.Sprintf("ふだん使わないリージョン %s での書き込み: %s (%d 件: %s)", region,
			record.PrincipalLabel(principal, record.PrincipalKind(a.extra["principal_kind"].(string))), a.count, strings.Join(apis, ", "))
		switch {
		case a.computeOK:
			summary += "。計算資源の作成を含む (" + strings.Join(compute, ", ") + ")"
		case len(compute) > 0:
			summary += "。計算資源の作成の試行 (失敗) を含む (" + strings.Join(compute, ", ") + ")"
		}
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: a.sev, Summary: summary, Data: a.data(),
			Fingerprint: fingerprint(a.sev, nil, strings.Join(apis, ","))}
	}
	return sortedObs(obs), nil
}
