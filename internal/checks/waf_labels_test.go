package checks

import (
	"reflect"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
)

func labelTestRule(name string, prio int, typ, action string, kv ...string) record.SnapshotItem {
	d := map[string]any{"item": "rule", "acl": "prod-waf", "rule": name, "priority": float64(prio), "type": typ, "action": action}
	for i := 0; i+1 < len(kv); i += 2 {
		d[kv[i]] = kv[i+1]
	}
	return record.SnapshotItem{Kind: record.KindWAFConfig, Data: d}
}

func labelACL(rules ...record.SnapshotItem) *wafACLConf {
	a := &wafACLConf{rules: map[string]record.SnapshotItem{}, labelPrefix: "awswaf:123456789012:webacl:prod-waf:"}
	for _, r := range rules {
		a.rules[r.String("rule")] = r
	}
	return a
}

const botNS = "awswaf:managed:aws:bot-control:"

// 決定 (ADR 0070): COUNT のルールが付けるラベルを、後ろ (Priority が大きい) のルールの LabelMatchStatement が使っていれば、目印のルール。
func TestLabelRule(t *testing.T) {
	a := labelACL(
		// WebACL の COUNT のルールがラベルを付け、後ろのルールが使う (名前空間を省いた鍵は、同じ WebACL のラベルに後ろから一致する)
		labelTestRule("tag-api", 1, account.WAFRuleRegular, "COUNT", "labels", "api:internal"),
		labelTestRule("tag-unused", 2, account.WAFRuleRegular, "COUNT", "labels", "unused"),
		// ラベルを付けない COUNT (BLOCK にするかの材料のまま)
		labelTestRule("count-geo", 3, account.WAFRuleRegular, "COUNT"),
		// マネージドのグループ。中の 3 つを COUNT にしている
		labelTestRule("bot", 10, account.WAFRuleManagedGroup, "NONE", "managed", "AWS/AWSManagedRulesBotControlRuleSet",
			"count_overrides", "CategoryHttpLibrary,CategorySearchEngine,SignalAutomatedBrowser", "label_namespace", botNS),
		labelTestRule("crs", 11, account.WAFRuleManagedGroup, "NONE", "managed", "AWS/AWSManagedRulesCommonRuleSet",
			"count_overrides", "SizeRestrictions_BODY,NoUserAgent_HEADER", "label_namespace", "awswaf:managed:aws:core-rule-set:"),
		labelTestRule("unknown-ns", 12, account.WAFRuleManagedGroup, "NONE", "managed", "AWS/AWSManagedRulesSQLiRuleSet",
			"count_overrides", "SQLi_BODY", "label_namespace_unknown", "true"),
		// 使う側
		labelTestRule("block-libs", 20, account.WAFRuleRegular, "BLOCK", "label_matches", "LABEL:"+botNS+"bot:category:http_library,LABEL:api:internal"),
		labelTestRule("signals", 21, account.WAFRuleRegular, "CAPTCHA", "label_matches", "NAMESPACE:"+botNS+"signal:"),
		labelTestRule("size", 22, account.WAFRuleRegular, "BLOCK", "label_matches", "LABEL:awswaf:managed:aws:core-rule-set:SizeRestrictions_Body"),
		// 前のルールのラベルは見えない (評価の順)
		labelTestRule("early", 0, account.WAFRuleRegular, "BLOCK", "label_matches", "LABEL:unused"),
	)
	a.rules["unknown-ns"].Data["label_namespace_unknown"] = true
	cases := map[countRule]struct {
		known     bool
		consumers []string
	}{
		{rule: "tag-api"}:                              {true, []string{"block-libs"}},
		{rule: "tag-unused"}:                           {true, nil},
		{rule: "count-geo"}:                            {true, nil},
		{rule: "bot", inner: "CategoryHttpLibrary"}:    {true, []string{"block-libs"}},
		{rule: "bot", inner: "CategorySearchEngine"}:   {true, nil},
		{rule: "bot", inner: "SignalAutomatedBrowser"}: {true, []string{"signals"}},
		{rule: "crs", inner: "SizeRestrictions_BODY"}:  {true, []string{"size"}},
		{rule: "crs", inner: "NoUserAgent_HEADER"}:     {true, nil},
		{rule: "unknown-ns", inner: "SQLi_BODY"}:       {false, nil},
	}
	for cr, want := range cases {
		use, known := labelRuleOf(a, cr)
		if known != want.known || !reflect.DeepEqual(use.consumers, want.consumers) {
			t.Errorf("%+v: known=%v consumers=%v, want %v %v", cr, known, use.consumers, want.known, want.consumers)
		}
	}
	// 使われているラベルを残す
	if use, _ := labelRuleOf(a, countRule{rule: "tag-api"}); !reflect.DeepEqual(use.labels, []string{"awswaf:123456789012:webacl:prod-waf:api:internal"}) {
		t.Errorf("labels = %v", use.labels)
	}
}

func TestLabelKeyMatches(t *testing.T) {
	const prefix = "awswaf:123456789012:webacl:prod-waf:"
	full := prefix + "testNS1:header:encoding:utf8"
	for _, tc := range []struct {
		match string
		want  bool
	}{
		{"LABEL:header:encoding:utf8", true}, // 前の名前空間を省ける
		{"LABEL:encoding:utf8", true},
		{"LABEL:" + full, true},
		{"LABEL:coding:utf8", false},     // 区間の途中では一致しない
		{"LABEL:header:encoding", false}, // 名前まで書く
		{"NAMESPACE:header:encoding:", true},
		{"NAMESPACE:" + prefix + "testNS1:", true},
		{"NAMESPACE:header:", false}, // 名前空間は名前の直前まで続ける
		{"LABEL:awswaf:123456789012:rulegroup:prod-waf:testNS1:header:encoding:utf8", false},
	} {
		if got := ownLabelMatches(tc.match, full, prefix); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.match, got, tc.want)
		}
	}
}

// 目印のルールは count_rule_status ではなく label_rule の observation (ラベル・件数・使っているルール)。ラベルの名前空間を読めなかったグループは、
// 今までどおり count_rule_status で出し、見分けられなかったことを書く (ADR 0070)。
func TestLabelRuleObservation(t *testing.T) {
	st := newStore(t)
	acl := wafACL("prod-waf")
	acl.Data["label_prefix"] = "awswaf:123456789012:webacl:prod-waf:"
	snapshot(t, st, record.KindWAFConfig, acl,
		wafRule("prod-waf", "bot", account.WAFRuleManagedGroup, "NONE", "priority", 1.0, "managed", "AWS/AWSManagedRulesBotControlRuleSet",
			"count_overrides", "CategoryHttpLibrary", "label_namespace", botNS),
		wafRule("prod-waf", "sqli", account.WAFRuleManagedGroup, "NONE", "priority", 2.0, "managed", "AWS/AWSManagedRulesSQLiRuleSet",
			"count_overrides", "SQLi_BODY", "label_namespace_unknown", true),
		wafRule("prod-waf", "block-libs", account.WAFRuleRegular, "BLOCK", "priority", 3.0, "label_matches", "LABEL:"+botNS+"bot:category:http_library"),
	)
	m := metricSeed{st: st, t: t}
	for _, d := range days("2026-10-21", 7) {
		m.put(d, "waf", cwlogs.MetricWAFCountMatch, "prod-waf|AWS#AWSManagedRulesBotControlRuleSet/CategoryHttpLibrary", 10)
		m.put(d, "waf", cwlogs.MetricWAFCountMatch, "prod-waf|AWS#AWSManagedRulesSQLiRuleSet/SQLi_BODY", 2)
	}
	props, _ := reviewWAF(t, st)
	got := map[string]schema.Proposal{}
	for _, p := range props {
		if p.About == AboutLabelRule || p.About == AboutCountRuleStatus {
			got[p.About+"|"+p.Rule+"/"+p.RuleInGroup] = p
		}
	}
	lr, ok := got[AboutLabelRule+"|bot/CategoryHttpLibrary"]
	if !ok || lr.Reason != ReasonInformational || lr.Evidence["matches"] != 70.0 ||
		!reflect.DeepEqual(lr.Evidence["consumers"], []string{"block-libs"}) ||
		lr.Summary != "prod-waf: 目印のルール: COUNT の bot の CategoryHttpLibrary: 直近 7 日でラベル "+botNS+"bot:category:http_library を 70 件付けた。使っているルール: block-libs" {
		t.Fatalf("label rule: %+v (all %v)", lr, got)
	}
	if _, dup := got[AboutCountRuleStatus+"|bot/CategoryHttpLibrary"]; dup {
		t.Fatal("a label rule must not also be listed as count_rule_status")
	}
	un := got[AboutCountRuleStatus+"|sqli/SQLi_BODY"]
	if un.Evidence["label_rule"] != "undetermined" || !strings.HasSuffix(un.Summary, "。目印のルールかどうかは見分けられなかった") {
		t.Fatalf("undetermined: %+v", un)
	}
}

// FuzzLabelMatches: ラベルの照合は利用者の WAF の設定の値 (ルール名・ラベル・鍵) を読む (ADR 0041)。
// 規則: パニックしない。前の名前空間を省いた鍵は、マネージドのグループのラベルに一致しない (同じ WebACL のラベルだけ)。
// WebACL の名前空間の外のラベルに、省いた鍵は一致しない。
func FuzzLabelMatches(f *testing.F) {
	f.Add("LABEL:"+botNS+"bot:category:http_library", "CategoryHttpLibrary", "api:internal")
	f.Add("NAMESPACE:"+botNS+"signal:", "SignalAutomatedBrowser", "x")
	f.Add("NAMESPACE::", "", ":")
	f.Add("LABEL:", "ä", "::::")
	const prefix = "awswaf:123456789012:webacl:prod-waf:"
	f.Fuzz(func(t *testing.T, m, inner, label string) {
		if key, ok := managedLabelMatches(m, botNS, inner); ok && !strings.HasPrefix(key, "awswaf:") {
			t.Fatalf("an unqualified key matched a managed label: %q", m)
		}
		_, key, _ := strings.Cut(m, ":")
		if !strings.HasPrefix(key, "awswaf:") && ownLabelMatches(m, "awswaf:111122223333:rulegroup:other:"+label, prefix) {
			t.Fatalf("an unqualified key matched a label outside the web ACL: %q", m)
		}
	})
}
