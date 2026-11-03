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

// IAMChanges は IAM の権限変更 (設計書 7 章の一覧) を報告する (medium。既知デプロイ主体なら info)。
// 決定: 「既知デプロイ主体」は allowlist の principals で `tags: [deploy]` を持つもの。
type IAMChanges struct{}

func (IAMChanges) Name() string         { return "iam_changes" }
func (IAMChanges) Cadence() Cadence     { return Daily }
func (IAMChanges) Mode() Mode           { return ModeEvent }
func (IAMChanges) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

var iamChangeNames = []string{"CreateAccessKey", "CreateUser", "UpdateAssumeRolePolicy", "CreateLoginProfile"}

func isIAMChange(name string) bool {
	for _, n := range iamChangeNames {
		if name == n {
			return true
		}
	}
	return (strings.HasPrefix(name, "Attach") || strings.HasPrefix(name, "Put")) && strings.HasSuffix(name, "Policy")
}

func (c IAMChanges) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{EventSources: []string{"iam.amazonaws.com"}, WriteOnly: true})
	if err != nil {
		return nil, err
	}
	aggs := map[string]*eventAgg{}
	sev := map[string]Severity{}
	errs := map[string]int{}
	codes := map[string]map[string]bool{}
	for _, e := range evs {
		if !isIAMChange(e.Name) {
			continue
		}
		target := targetOf(e)
		k := e.Name + "|" + e.PrincipalARN + "|" + target
		a, ok := aggs[k]
		if !ok {
			a = newEventAgg()
			a.extra["principal"] = e.PrincipalARN
			a.extra["principal_kind"] = string(e.PrincipalKind)
			a.extra["target"] = target
			if v, ok := e.Data["policy_arn"]; ok {
				a.extra["policy_arn"] = v
			}
			aggs[k] = a
			entry, status := al.Principal(e.PrincipalARN, w.To)
			if status == allowlist.StatusApproved && entry.HasTag("deploy") {
				sev[k] = Info
				a.extra["known_deploy_principal"] = true
			} else {
				sev[k] = Medium
			}
		}
		a.add(e.Time, e.Name, e.IP)
		if e.ErrorCode != "" {
			a.extra["has_errors"] = true
			errs[k]++
			if codes[k] == nil {
				codes[k] = map[string]bool{}
			}
			codes[k][e.ErrorCode] = true
		}
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		name, _, _ := strings.Cut(k, "|")
		// 決定: 集約した呼び出しがすべてエラーなら、変更は起きていない。「IAM 変更の試行 (拒否)」として報告する
		// (重大度・Key は変えない)。拒否された呼び出しは requestParameters が記録されず対象が空になるため、表示では「不明」とする。
		denied := errs[k] > 0 && errs[k] == a.count
		if len(codes[k]) > 0 {
			a.extra["error_codes"] = sortedKeys(codes[k])
		}
		label, target := "IAM 変更", a.extra["target"].(string)
		if denied {
			a.extra["denied"] = true
			label = "IAM 変更の試行 (拒否)"
		}
		if target == "" {
			target = "不明"
			if denied {
				target = "不明 (拒否された呼び出しは内容が記録されない)"
			}
		}
		fp := fingerprint(sev[k], a.ips, a.extra["target"], a.extra["policy_arn"])
		if denied {
			fp += "|denied" // 成功が混ざる状態との変化を検出する。成功のみの既存 finding の指紋は変えない
		}
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: sev[k], Data: a.data(), Fingerprint: fp,
			Summary: fmt.Sprintf("%s %s: %s → %s (%d 件)", label, name, a.extra["principal"], target, a.count)}
	}
	return sortedObs(obs), nil
}

func targetOf(e record.TrailEvent) string {
	for _, k := range []string{"user_name", "role_name", "group_name", "policy_name"} {
		if v, ok := e.Data[k].(string); ok && v != "" {
			return v
		}
	}
	return e.Resource
}
