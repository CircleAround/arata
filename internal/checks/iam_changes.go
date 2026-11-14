package checks

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// IAMChanges は IAM の権限変更 (設計書 7 章の一覧) を報告する (medium。既知デプロイ主体なら info)。
// 決定: 「既知デプロイ主体」は allowlist の principals で `tags: [deploy]` を持つもの。
//
// 決定 (ADR 0056): 既知デプロイ主体でも、次の変更は下げない (CI のロールを奪った者が、長期のキーを作り、信頼ポリシーを広げる手口)。
//   - CreateAccessKey → medium
//   - UpdateAssumeRolePolicy / CreateRole で、信頼ポリシーに、そのアカウントの外の主体がある・信頼ポリシーを読めない → medium
//   - UpdateAssumeRolePolicy / CreateRole で、信頼ポリシーに `*` がある → high (デプロイ主体でない主体も high)
//
// 信頼ポリシーは cloudtrail の collector が読み、判定に使う値だけを data に残す (trust_policy・trust_wildcard・trust_accounts・trust_federated・
// trust_has_condition)。「読めて、`*` も外の主体も無い」と確かめられたときだけ下げる。trust_policy の無い記録 (以前の版で集めたもの) は「読めない」。
// 外のアカウントが principals の account: で承認済みでも下げない (あちらは「呼び出し元として既知」)。Condition は判定しない (有無を data に出す)。
// 1 つの Key にまとめた呼び出しの中で、いちばん重い重大度を採る。Key と Fingerprint の形は変えない。
type IAMChanges struct{}

func (IAMChanges) Name() string         { return "iam_changes" }
func (IAMChanges) Cadence() Cadence     { return Daily }
func (IAMChanges) Mode() Mode           { return ModeEvent }
func (IAMChanges) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

var iamChangeNames = []string{"CreateAccessKey", "CreateUser", "CreateRole", "UpdateAssumeRolePolicy", "CreateLoginProfile"}

// 既知デプロイ主体でも下げなかった理由 (data.not_lowered)。
const (
	notLoweredAccessKey       = "access_key"
	notLoweredTrustExternal   = "trust_external"
	notLoweredTrustWildcard   = "trust_wildcard"
	notLoweredTrustUnreadable = "trust_unreadable"
)

// maxTrustSummaryItems は見出しに出す外のアカウント・ID プロバイダの数の上限 (全部は data に出す)。
const maxTrustSummaryItems = 5

// trustsPolicy は、信頼ポリシーを要求に持つ操作か (collector の trustPolicyParams と同じ一覧)。
func trustsPolicy(name string) bool { return name == "UpdateAssumeRolePolicy" || name == "CreateRole" }

// iamTrust は 1 つの Key にまとめた呼び出しの、信頼ポリシーの判定の材料。
type iamTrust struct {
	unreadable, wildcard, condition bool
	accounts, federated             map[string]bool
}

// add は 1 件の記録の値を足す。own は自アカウント (記録を受け取ったアカウント。分からなければ空で、取り出したアカウントは全部「外」になる)。
func (t *iamTrust) add(e record.TrailEvent, own string) {
	if dataStr(e.Data, "trust_policy") != "ok" {
		t.unreadable = true
	}
	if v, _ := dataBool(e.Data, "trust_wildcard"); v {
		t.wildcard = true
	}
	if v, _ := dataBool(e.Data, "trust_has_condition"); v {
		t.condition = true
	}
	for _, a := range dataStrings(e.Data, "trust_accounts") {
		// data はストアから読み戻した値 (元はログ由来)。12 桁の数字だけを見出しと data に出す。違う形が混ざっていたら「読めない」
		if !accountIDRe.MatchString(a) {
			t.unreadable = true
		} else if a != own {
			t.accounts[a] = true
		}
	}
	for _, f := range dataStrings(e.Data, "trust_federated") {
		if !trustFederatedRe.MatchString(f) {
			t.unreadable = true
		} else {
			t.federated[f] = true
		}
	}
}

// trustFederatedRe は ARN でない Federated の値の形 (collector が残すときと同じ。ホスト名)。
var trustFederatedRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?\z`)

// reasons は下げない理由 (重い順ではなく、決まった順)。
func (t *iamTrust) reasons() []string {
	var out []string
	if len(t.accounts) > 0 || len(t.federated) > 0 {
		out = append(out, notLoweredTrustExternal)
	}
	if t.unreadable {
		out = append(out, notLoweredTrustUnreadable)
	}
	if t.wildcard {
		out = append(out, notLoweredTrustWildcard)
	}
	return out
}

// note は見出しに足す文。
func (t *iamTrust) note() string {
	var parts []string
	if t.wildcard {
		p := "信頼ポリシーが誰でも (*) を許す"
		if t.condition {
			p += " (Condition あり。絞っているかは判定していない)"
		}
		parts = append(parts, p)
	}
	if len(t.accounts) > 0 {
		parts = append(parts, "信頼ポリシーに外のアカウント "+strings.Join(capList(sortedKeys(t.accounts), maxTrustSummaryItems), ", "))
	}
	if len(t.federated) > 0 {
		parts = append(parts, "信頼ポリシーに外の ID プロバイダ "+strings.Join(capList(sortedKeys(t.federated), maxTrustSummaryItems), ", "))
	}
	if t.unreadable {
		parts = append(parts, "信頼ポリシーを読めない")
	}
	return strings.Join(parts, "。")
}

// ownAccountOf は記録の自アカウント: 記録を受け取ったアカウント。無ければ呼び出した主体のアカウント (IAM の操作は同じアカウントの中でしか呼べない)。
func ownAccountOf(e record.TrailEvent) string {
	for _, v := range []string{dataStr(e.Data, "recipient_account"), dataStr(e.Data, "account_id"), allowlist.AccountOf(e.PrincipalARN)} {
		if accountIDRe.MatchString(v) {
			return v
		}
	}
	return ""
}

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
	deploy := map[string]bool{}
	trusts := map[string]*iamTrust{}
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
			if knownDeploy(al, e.PrincipalARN, w.To) {
				deploy[k] = true
				a.extra["known_deploy_principal"] = true
			}
			if trustsPolicy(e.Name) {
				trusts[k] = &iamTrust{accounts: map[string]bool{}, federated: map[string]bool{}}
			}
		}
		if t := trusts[k]; t != nil {
			t.add(e, ownAccountOf(e))
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
		// 決定 (ADR 0056): 下げない理由があれば、デプロイ主体でも medium。`*` は誰でも high
		var reasons []string
		note := ""
		if name == "CreateAccessKey" {
			reasons = []string{notLoweredAccessKey}
		}
		if t := trusts[k]; t != nil {
			reasons, note = t.reasons(), t.note()
			a.extra["trust_policy"] = "ok"
			if t.unreadable {
				a.extra["trust_policy"] = "unreadable"
			}
			if t.wildcard {
				a.extra["trust_wildcard"] = true
			}
			if t.condition {
				a.extra["trust_has_condition"] = true
			}
			if len(t.accounts) > 0 {
				a.extra["trust_external_accounts"] = sortedKeys(t.accounts)
			}
			if len(t.federated) > 0 {
				a.extra["trust_external_federated"] = sortedKeys(t.federated)
			}
		}
		sev[k] = Medium
		if deploy[k] {
			if len(reasons) == 0 {
				sev[k] = Info
			} else {
				a.extra["not_lowered"] = reasons
			}
		}
		if t := trusts[k]; t != nil && t.wildcard {
			sev[k] = High
		}
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
		summary := fmt.Sprintf("%s %s: %s → %s (%d 件)", label, name, a.extra["principal"], target, a.count)
		if note != "" {
			summary += "。" + note
		}
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: sev[k], Data: a.data(), Fingerprint: fp, Summary: summary}
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
