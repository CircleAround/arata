package account

import (
	"context"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// UnavailableWebACL は WebACL が 1 つも無いときの skip の理由。
const UnavailableWebACL = "WAFv2 の WebACL が無い (REGIONAL は設定のリージョン、CLOUDFRONT は us-east-1 を見た)"

// ルールの種類 (waf_config の rule 項目の type)。
const (
	WAFRuleManagedGroup = "managed_group" // マネージドルールグループ (AWS や販売者のもの)
	WAFRuleGroup        = "rule_group"    // 自分で作ったルールグループの参照
	WAFRuleRateBased    = "rate_based"    // レートベースのルール
	WAFRuleRegular      = "regular"       // その他のルール (ByteMatch / IPSet など)
)

// WAFConfig は WAFv2 の WebACL の設定を取る collector (waf_config)。WebACL ごとに 1 項目 (key `acl|<scope>|<region>|<WebACL>`) と、
// ルールごとに 1 項目 (key `rule|<scope>|<region>|<WebACL>|<ルール>`) を出す。Data の item は web_acl / rule、rule の type は WAFRule*。
//
// 決定 (ADR 0023):
//   - REGIONAL はソースの regions の各リージョン、CLOUDFRONT は us-east-1 のクライアント (cloudfront) で引く (CloudFront の WebACL は us-east-1 にしか無い)
//   - Statement の全体は保存しない。waf_review が使う要約 (action・種類・マネージドの名前・COUNT に上書きした中のルール・
//     レート制限の値と評価窓・scope-down の URI パスの条件) だけを持つ。IP セットや正規表現の中身は持たない
//   - scope-down は UriPath の ByteMatch (STARTS_WITH / EXACTLY) とその And だけを解釈する。それ以外を含めば rate_scope_parsed=false
//     (waf_review は「どのパスを受け持つか分からない」として、レート制限が無いという候補を出さない)
//   - ListResourcesForWebACL は CloudFront に使えないので REGIONAL だけ、資源の種類ごとに呼ぶ。サービス側の権限が無い種類は不明 (resources_unknown)
//   - WebACL が 1 つも無ければ Unavailable を返し、waf_review は skip される
type WAFConfig struct {
	base
	cloudfront  Clients
	unavailable map[record.Kind]string
}

var (
	_ collect.Collector            = (*WAFConfig)(nil)
	_ collect.AvailabilityReporter = (*WAFConfig)(nil)
	_ collect.Prober               = (*WAFConfig)(nil)
)

// NewWAFConfig は collector を作る。cloudfront は us-east-1 のクライアント (CLOUDFRONT スコープ用)、regional は REGIONAL を引くリージョンのクライアント。
func NewWAFConfig(id string, cloudfront Clients, regional ...Clients) *WAFConfig {
	return &WAFConfig{base: newBase(id, regional), cloudfront: cloudfront}
}

func (c *WAFConfig) Yields() []record.Kind { return []record.Kind{record.KindWAFConfig} }

func (c *WAFConfig) Unavailable() map[record.Kind]string { return c.unavailable }

type wafScope struct {
	scope  waftypes.Scope
	region string
	api    WAFV2API
}

func (c *WAFConfig) scopes() []wafScope {
	var out []wafScope
	for _, cl := range c.clients {
		out = append(out, wafScope{waftypes.ScopeRegional, cl.Region, cl.WAFV2})
	}
	if c.cloudfront.WAFV2 != nil {
		out = append(out, wafScope{waftypes.ScopeCloudfront, c.cloudfront.Region, c.cloudfront.WAFV2})
	}
	return out
}

func (c *WAFConfig) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.unavailable = nil
	at := snapshotTime(w)
	found := 0
	for _, sc := range c.scopes() {
		sums, err := listWebACLs(ctx, sc)
		if err != nil {
			return c.fail(ActionListWebACLs, err)
		}
		found += len(sums)
		for _, s := range sums {
			out, err := sc.api.GetWebACL(ctx, &wafv2.GetWebACLInput{Id: s.Id, Name: s.Name, Scope: sc.scope})
			if err != nil {
				return c.fail(ActionGetWebACL, err)
			}
			acl := out.WebACL
			if acl == nil {
				continue
			}
			data, err := c.aclData(ctx, sc, acl)
			if err != nil {
				return err
			}
			name := aws.ToString(acl.Name)
			prefix := string(sc.scope) + "|" + sc.region + "|" + name
			if err := sink.Emit(ctx, item(record.KindWAFConfig, at, c.id, "acl|"+prefix, data)); err != nil {
				return err
			}
			for _, r := range acl.Rules {
				rd := ruleData(r)
				rd["acl"], rd["scope"], rd["region"] = name, string(sc.scope), sc.region
				if err := sink.Emit(ctx, item(record.KindWAFConfig, at, c.id, "rule|"+prefix+"|"+aws.ToString(r.Name), rd)); err != nil {
					return err
				}
			}
		}
	}
	if found == 0 {
		c.unavailable = map[record.Kind]string{record.KindWAFConfig: UnavailableWebACL}
	}
	return nil
}

func listWebACLs(ctx context.Context, sc wafScope) ([]waftypes.WebACLSummary, error) {
	var out []waftypes.WebACLSummary
	in := &wafv2.ListWebACLsInput{Scope: sc.scope, Limit: aws.Int32(100)}
	for {
		res, err := sc.api.ListWebACLs(ctx, in)
		if err != nil {
			return nil, err
		}
		out = append(out, res.WebACLs...)
		if res.NextMarker == nil || *res.NextMarker == "" {
			return out, nil
		}
		in.NextMarker = res.NextMarker
	}
}

func (c *WAFConfig) aclData(ctx context.Context, sc wafScope, acl *waftypes.WebACL) (map[string]any, error) {
	d := map[string]any{
		"item": "web_acl", "acl": aws.ToString(acl.Name), "arn": aws.ToString(acl.ARN), "scope": string(sc.scope), "region": sc.region,
		"default_action": "ALLOW", "rules": len(acl.Rules), "logging": false, "log_destinations": "", "resources": "",
	}
	if acl.DefaultAction != nil && acl.DefaultAction.Block != nil {
		d["default_action"] = "BLOCK"
	}
	lc, err := sc.api.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: acl.ARN})
	switch {
	case err == nil && lc.LoggingConfiguration != nil:
		var dst []string
		for _, a := range lc.LoggingConfiguration.LogDestinationConfigs {
			dst = append(dst, destinationName(a))
		}
		d["logging"], d["log_destinations"] = len(dst) > 0, strings.Join(dst, ",")
	case err != nil && collect.APICode(err) != "WAFNonexistentItemException":
		return nil, c.fail(ActionGetLoggingConfiguration, err)
	}
	if sc.scope == waftypes.ScopeRegional {
		var res, unknown []string
		for _, rt := range resourceTypes() {
			out, err := sc.api.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{WebACLArn: acl.ARN, ResourceType: rt})
			if err != nil {
				code, ok := resourceTypeProblem(rt, err)
				if !ok {
					return nil, c.fail(ActionListResourcesForWebACL, err)
				}
				unknown = append(unknown, string(rt)+": "+code)
				c.Logger.Warn("cannot list resources of this type for the web ACL; treating them as unknown", "code", codes.WAFResourcesUnknown, "source", c.id, "web_acl", aws.ToString(acl.Name),
					"region", sc.region, "resource_type", string(rt), "code", code, "error", err.Error())
				continue
			}
			res = append(res, out.ResourceArns...)
		}
		sort.Strings(res)
		sort.Strings(unknown)
		d["resources"], d["resources_unknown"] = strings.Join(res, ","), strings.Join(unknown, ",")
	}
	return d, nil
}

// resourceTypes は ListResourcesForWebACL を呼ぶ資源の種類。wafv2 の権限だけで呼べる APPLICATION_LOAD_BALANCER を最初に呼ぶ。
func resourceTypes() []waftypes.ResourceType {
	out := []waftypes.ResourceType{waftypes.ResourceTypeApplicationLoadBalancer}
	for _, rt := range waftypes.ResourceType("").Values() {
		if rt != waftypes.ResourceTypeApplicationLoadBalancer {
			out = append(out, rt)
		}
	}
	return out
}

// resourceTypeProblem は ListResourcesForWebACL の資源の種類 1 つのエラーが「その種類だけ不明にして続ける」ものかと、記録する code を返す。
//
// 決定 (ADR 0023): ListResourcesForWebACL は資源の種類ごとに、WAF の権限に加えて資源のサービス側の権限も要る
// (COGNITO_USER_POOL → cognito-idp:ListResourcesForWebACL、Verified Access、AgentCore Gateway など。sandbox の本物の AWS で確認)。
// 守っている資源は提案の補助なので、読み取りロールに各サービスの権限は足さず (最小権限)、呼べない種類は不明として記録する (resources_unknown)。
// エラー文は種類ごとにばらばらで action を名指ししないものもあるので、文言は解釈しない。wafv2 の権限だけで呼べる APPLICATION_LOAD_BALANCER を
// 最初に呼び、それが拒否されたときだけ wafv2:ListResourcesForWebACL 自体の拒否 (読み取りロールの更新漏れ) としてソースの失敗にする。
// ALB が通った後の拒否・パラメータエラー (その種類がリージョンで使えない WAFInvalidParameterException など) は、すべてその種類だけ不明にする。
func resourceTypeProblem(rt waftypes.ResourceType, err error) (string, bool) {
	ce := collect.Classify("", ActionListResourcesForWebACL, err)
	if ce.Code == collect.CodeAccessDenied {
		return ce.Code, rt != waftypes.ResourceTypeApplicationLoadBalancer
	}
	if code := collect.APICode(err); code != "" {
		return code, true
	}
	return ce.Code, true
}

// destinationName はログの送り先の ARN を短くする (CloudWatch Logs ならロググループ名)。
func destinationName(arn string) string {
	if _, name, ok := strings.Cut(arn, ":log-group:"); ok {
		return strings.TrimSuffix(name, ":*")
	}
	return arn
}

func ruleData(r waftypes.Rule) map[string]any {
	d := map[string]any{"item": "rule", "rule": aws.ToString(r.Name), "priority": int(r.Priority), "type": WAFRuleRegular, "action": ruleAction(r.Action)}
	if r.OverrideAction != nil {
		d["action"] = "NONE"
		if r.OverrideAction.Count != nil {
			d["action"] = "COUNT"
		}
	}
	st := r.Statement
	if st == nil {
		return d
	}
	switch {
	case st.ManagedRuleGroupStatement != nil:
		m := st.ManagedRuleGroupStatement
		d["type"], d["managed"] = WAFRuleManagedGroup, aws.ToString(m.VendorName)+"/"+aws.ToString(m.Name)
		d["count_overrides"] = countOverrides(m.RuleActionOverrides, m.ExcludedRules)
	case st.RuleGroupReferenceStatement != nil:
		g := st.RuleGroupReferenceStatement
		d["type"], d["rule_group_arn"] = WAFRuleGroup, aws.ToString(g.ARN)
		d["count_overrides"] = countOverrides(g.RuleActionOverrides, g.ExcludedRules)
	case st.RateBasedStatement != nil:
		rb := st.RateBasedStatement
		window := rb.EvaluationWindowSec
		if window == 0 {
			window = 300 // 既定の評価窓 (5 分)
		}
		d["type"], d["rate_limit"], d["rate_window_sec"], d["rate_aggregate"] = WAFRuleRateBased, aws.ToInt64(rb.Limit), window, string(rb.AggregateKeyType)
		paths, ok := []string{}, true
		if rb.ScopeDownStatement != nil {
			paths, ok = uriConditions(*rb.ScopeDownStatement)
		}
		d["rate_scope_paths"], d["rate_scope_parsed"] = strings.Join(paths, ","), ok
	}
	return d
}

// ruleAction は Rule.Action の名前 (BLOCK / ALLOW / COUNT / CAPTCHA / CHALLENGE)。無ければ "" (ルールグループは OverrideAction)。
func ruleAction(a *waftypes.RuleAction) string {
	switch {
	case a == nil:
		return ""
	case a.Block != nil:
		return "BLOCK"
	case a.Allow != nil:
		return "ALLOW"
	case a.Count != nil:
		return "COUNT"
	case a.Captcha != nil:
		return "CAPTCHA"
	case a.Challenge != nil:
		return "CHALLENGE"
	}
	return "OTHER"
}

// countOverrides はグループの中で COUNT にしたルールの名前 (RuleActionOverrides の Count と、古い ExcludedRules)。
func countOverrides(ov []waftypes.RuleActionOverride, ex []waftypes.ExcludedRule) string {
	var names []string
	for _, o := range ov {
		if o.ActionToUse != nil && o.ActionToUse.Count != nil {
			names = append(names, aws.ToString(o.Name))
		}
	}
	for _, e := range ex {
		names = append(names, aws.ToString(e.Name))
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// uriConditions は scope-down のうち UriPath の ByteMatch (STARTS_WITH / EXACTLY) を `<制約>:<文字列>` にする。
// And の中はそれぞれ見る。他の文を含めば ok=false (受け持つパスを決められない)。
func uriConditions(st waftypes.Statement) ([]string, bool) {
	switch {
	case st.ByteMatchStatement != nil:
		b := st.ByteMatchStatement
		if b.FieldToMatch == nil || b.FieldToMatch.UriPath == nil {
			return nil, false
		}
		switch b.PositionalConstraint {
		case waftypes.PositionalConstraintStartsWith, waftypes.PositionalConstraintExactly:
			return []string{string(b.PositionalConstraint) + ":" + string(b.SearchString)}, true
		}
		return nil, false
	case st.AndStatement != nil:
		var out []string
		for _, s := range st.AndStatement.Statements {
			p, ok := uriConditions(s)
			if !ok {
				return nil, false
			}
			out = append(out, p...)
		}
		return out, true
	}
	return nil, false
}

// Probe は ListWebACLs を各スコープで試し、WebACL があれば最初の 1 つで残りの読み取りを試す。
func (c *WAFConfig) Probe(ctx context.Context) []collect.ProbeResult {
	var out []collect.ProbeResult
	var first *wafScope
	var acl waftypes.WebACLSummary
	for _, sc := range c.scopes() {
		sums, err := listWebACLs(ctx, sc)
		out = append(out, collect.ProbeResult{Action: ActionListWebACLs, Detail: string(sc.scope) + " " + sc.region, Err: err})
		if err == nil && len(sums) > 0 && first == nil {
			sc := sc
			first, acl = &sc, sums[0]
		}
	}
	if first == nil {
		return out
	}
	detail := aws.ToString(acl.Name)
	_, err := first.api.GetWebACL(ctx, &wafv2.GetWebACLInput{Id: acl.Id, Name: acl.Name, Scope: first.scope})
	out = append(out, collect.ProbeResult{Action: ActionGetWebACL, Detail: detail, Err: err})
	_, err = first.api.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: acl.ARN})
	if collect.APICode(err) == "WAFNonexistentItemException" {
		err = nil
	}
	out = append(out, collect.ProbeResult{Action: ActionGetLoggingConfiguration, Detail: detail, Err: err})
	if first.scope == waftypes.ScopeRegional {
		// 実際に呼ぶ種類ごとに試す。サービス側の権限が無い・使えない種類は warn (収集はその種類だけ不明にして続ける)
		for _, rt := range resourceTypes() {
			_, err = first.api.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{WebACLArn: acl.ARN, ResourceType: rt})
			r := collect.ProbeResult{Action: ActionListResourcesForWebACL, Detail: detail + " " + string(rt), Err: err}
			if err != nil {
				if code, ok := resourceTypeProblem(rt, err); ok {
					r.Err, r.Warn = nil, "この種類の守っている資源は不明として扱う ("+code+": "+err.Error()+")"
				}
			}
			out = append(out, r)
		}
	}
	return out
}
