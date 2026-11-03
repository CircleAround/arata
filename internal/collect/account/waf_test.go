package account_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/record"
)

func wafRules() []waftypes.Rule {
	return []waftypes.Rule{
		{Name: aws.String("AWS-AWSManagedRulesCommonRuleSet"), Priority: 1, OverrideAction: &waftypes.OverrideAction{None: &waftypes.NoneAction{}},
			Statement: &waftypes.Statement{ManagedRuleGroupStatement: &waftypes.ManagedRuleGroupStatement{VendorName: aws.String("AWS"), Name: aws.String("AWSManagedRulesCommonRuleSet"),
				RuleActionOverrides: []waftypes.RuleActionOverride{{Name: aws.String("SizeRestrictions_BODY"), ActionToUse: &waftypes.RuleAction{Count: &waftypes.CountAction{}}}},
				ExcludedRules:       []waftypes.ExcludedRule{{Name: aws.String("NoUserAgent_HEADER")}}}}},
		{Name: aws.String("AWS-AWSManagedRulesKnownBadInputsRuleSet"), Priority: 2, OverrideAction: &waftypes.OverrideAction{Count: &waftypes.CountAction{}},
			Statement: &waftypes.Statement{ManagedRuleGroupStatement: &waftypes.ManagedRuleGroupStatement{VendorName: aws.String("AWS"), Name: aws.String("AWSManagedRulesKnownBadInputsRuleSet")}}},
		{Name: aws.String("rate-login"), Priority: 3, Action: &waftypes.RuleAction{Block: &waftypes.BlockAction{}},
			Statement: &waftypes.Statement{RateBasedStatement: &waftypes.RateBasedStatement{Limit: aws.Int64(100), EvaluationWindowSec: 300, AggregateKeyType: waftypes.RateBasedStatementAggregateKeyTypeIp,
				ScopeDownStatement: &waftypes.Statement{ByteMatchStatement: &waftypes.ByteMatchStatement{FieldToMatch: &waftypes.FieldToMatch{UriPath: &waftypes.UriPath{}},
					PositionalConstraint: waftypes.PositionalConstraintStartsWith, SearchString: []byte("/login")}}}}},
		{Name: aws.String("rate-geo"), Priority: 4, Action: &waftypes.RuleAction{Count: &waftypes.CountAction{}},
			Statement: &waftypes.Statement{RateBasedStatement: &waftypes.RateBasedStatement{Limit: aws.Int64(2000), EvaluationWindowSec: 60, AggregateKeyType: waftypes.RateBasedStatementAggregateKeyTypeIp,
				ScopeDownStatement: &waftypes.Statement{GeoMatchStatement: &waftypes.GeoMatchStatement{CountryCodes: []waftypes.CountryCode{"JP"}}}}}},
		{Name: aws.String("block-admin"), Priority: 5, Action: &waftypes.RuleAction{Block: &waftypes.BlockAction{}},
			Statement: &waftypes.Statement{ByteMatchStatement: &waftypes.ByteMatchStatement{FieldToMatch: &waftypes.FieldToMatch{UriPath: &waftypes.UriPath{}},
				PositionalConstraint: waftypes.PositionalConstraintStartsWith, SearchString: []byte("/admin")}}},
	}
}

func TestWAFConfig(t *testing.T) {
	regional := accounttest.WebACL(waftypes.ScopeRegional, "ap-northeast-1", "prod-waf", wafRules()...)
	second := accounttest.WebACL(waftypes.ScopeRegional, "ap-northeast-1", "stg-waf")
	cf := accounttest.WebACL(waftypes.ScopeCloudfront, "us-east-1", "cdn-waf")
	f := &accounttest.Fake{WAF: &accounttest.WAF{
		WebACLs:   map[string][]waftypes.WebACL{"REGIONAL|ap-northeast-1": {regional, second}, "CLOUDFRONT|us-east-1": {cf}},
		Logging:   map[string][]string{*regional.ARN: {"arn:aws:logs:ap-northeast-1:123456789012:log-group:aws-waf-logs-prod"}},
		Resources: map[string]map[waftypes.ResourceType][]string{*regional.ARN: {waftypes.ResourceTypeApiGateway: {"arn:aws:apigateway:ap-northeast-1::/restapis/abc/stages/prod"}}},
	}}
	c := account.NewWAFConfig("waf_config", f.Clients("us-east-1"), f.Clients("ap-northeast-1"))
	s, err := collectWith(t, c)
	if err != nil {
		t.Fatal(err)
	}
	m := s.byKey()
	if len(m) != 3+5 {
		t.Fatalf("items: %d %v", len(m), keysOf(m))
	}
	acl := m["acl|REGIONAL|ap-northeast-1|prod-waf"]
	if acl.Kind != record.KindWAFConfig || acl.String("default_action") != "ALLOW" || !acl.Bool("logging") ||
		acl.String("log_destinations") != "aws-waf-logs-prod" || acl.String("resources") != "arn:aws:apigateway:ap-northeast-1::/restapis/abc/stages/prod" || acl.Number("rules") != 5 {
		t.Fatalf("acl: %+v", acl.Data)
	}
	if stg := m["acl|REGIONAL|ap-northeast-1|stg-waf"]; stg.Bool("logging") || stg.String("resources") != "" {
		t.Fatalf("stg: %+v", stg.Data)
	}
	if cdn := m["acl|CLOUDFRONT|us-east-1|cdn-waf"]; cdn.String("scope") != "CLOUDFRONT" {
		t.Fatalf("cdn: %+v", cdn.Data)
	}
	crs := m["rule|REGIONAL|ap-northeast-1|prod-waf|AWS-AWSManagedRulesCommonRuleSet"]
	if crs.String("type") != account.WAFRuleManagedGroup || crs.String("action") != "NONE" || crs.String("managed") != "AWS/AWSManagedRulesCommonRuleSet" ||
		crs.String("count_overrides") != "NoUserAgent_HEADER,SizeRestrictions_BODY" || crs.Number("priority") != 1 || crs.String("acl") != "prod-waf" {
		t.Fatalf("crs: %+v", crs.Data)
	}
	if kbi := m["rule|REGIONAL|ap-northeast-1|prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet"]; kbi.String("action") != "COUNT" {
		t.Fatalf("kbi: %+v", kbi.Data)
	}
	rl := m["rule|REGIONAL|ap-northeast-1|prod-waf|rate-login"]
	if rl.String("type") != account.WAFRuleRateBased || rl.String("action") != "BLOCK" || rl.Number("rate_limit") != 100 || rl.Number("rate_window_sec") != 300 ||
		rl.String("rate_aggregate") != "IP" || rl.String("rate_scope_paths") != "STARTS_WITH:/login" || !rl.Bool("rate_scope_parsed") {
		t.Fatalf("rate-login: %+v", rl.Data)
	}
	// 解釈できない scope-down (地域) は parsed=false
	if rg := m["rule|REGIONAL|ap-northeast-1|prod-waf|rate-geo"]; rg.Bool("rate_scope_parsed") || rg.String("rate_scope_paths") != "" || rg.Number("rate_window_sec") != 60 {
		t.Fatalf("rate-geo: %+v", rg.Data)
	}
	if ba := m["rule|REGIONAL|ap-northeast-1|prod-waf|block-admin"]; ba.String("type") != account.WAFRuleRegular || ba.String("action") != "BLOCK" {
		t.Fatalf("block-admin: %+v", ba.Data)
	}
	// CLOUDFRONT は ListResourcesForWebACL を呼ばない (CloudFront は対象外の API)。REGIONAL は資源の種類ごと
	if n := f.Called(account.ActionListResourcesForWebACL); n != 2*len(waftypes.ResourceType("").Values()) {
		t.Fatalf("ListResourcesForWebACL calls: %d", n)
	}
	if c.Unavailable() != nil {
		t.Fatalf("unavailable: %v", c.Unavailable())
	}
}

func TestWAFConfigNoWebACL(t *testing.T) {
	f := &accounttest.Fake{}
	c := account.NewWAFConfig("waf_config", f.Clients("us-east-1"), f.Clients("ap-northeast-1"))
	s, err := collectWith(t, c)
	if err != nil || len(s.items) != 0 || c.Unavailable()[record.KindWAFConfig] == "" {
		t.Fatalf("%v %v %v", err, s.items, c.Unavailable())
	}
}

func TestWAFConfigDenied(t *testing.T) {
	f := &accounttest.Fake{WAF: &accounttest.WAF{}, Errs: map[string]error{account.ActionGetWebACL: accounttest.Denied}}
	f.WAF.WebACLs = map[string][]waftypes.WebACL{"REGIONAL|ap-northeast-1": {accounttest.WebACL(waftypes.ScopeRegional, "ap-northeast-1", "prod-waf")}}
	_, err := collectWith(t, account.NewWAFConfig("waf_config", f.Clients("us-east-1"), f.Clients("ap-northeast-1")))
	ce := collect.Classify("", "", err)
	if ce.Code != collect.CodeAccessDenied || ce.Action != account.ActionGetWebACL {
		t.Fatalf("%v", err)
	}
	// Probe は ListWebACLs を両方のスコープで試し、WebACL があれば GetWebACL / GetLoggingConfiguration / ListResourcesForWebACL も試す
	res := account.NewWAFConfig("waf_config", f.Clients("us-east-1"), f.Clients("ap-northeast-1")).Probe(context.Background())
	got := map[string]bool{}
	for _, r := range res {
		got[r.Action] = r.Err == nil
	}
	if !got[account.ActionListWebACLs] || got[account.ActionGetWebACL] || !got[account.ActionGetLoggingConfiguration] || !got[account.ActionListResourcesForWebACL] {
		t.Fatalf("%+v", res)
	}
}

func keysOf(m map[string]record.SnapshotItem) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
