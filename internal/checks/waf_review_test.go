package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

func wafRule(acl, rule, typ, action string, kv ...any) record.SnapshotItem {
	return snap(record.KindWAFConfig, "rule|REGIONAL|ap-northeast-1|"+acl+"|"+rule,
		append([]any{"item", "rule", "acl", acl, "scope", "REGIONAL", "region", "ap-northeast-1", "rule", rule, "type", typ, "action", action}, kv...)...)
}

func wafACL(acl string) record.SnapshotItem {
	return snap(record.KindWAFConfig, "acl|REGIONAL|ap-northeast-1|"+acl, "item", "web_acl", "acl", acl, "scope", "REGIONAL", "region", "ap-northeast-1", "logging", true)
}

// days は end から遡って n 日 (end を含む) の日付。
func days(end string, n int) []string {
	var out []string
	for i := n - 1; i >= 0; i-- {
		out = append(out, addDays(end, -i))
	}
	return out
}

func seedWAFReview(t *testing.T) *store.Dir {
	st := newStore(t)
	snapshot(t, st, record.KindWAFConfig,
		wafACL("prod-waf"),
		wafRule("prod-waf", "AWS-AWSManagedRulesCommonRuleSet", account.WAFRuleManagedGroup, "NONE", "managed", "AWS/AWSManagedRulesCommonRuleSet", "count_overrides", "SizeRestrictions_BODY"),
		wafRule("prod-waf", "AWS-AWSManagedRulesKnownBadInputsRuleSet", account.WAFRuleManagedGroup, "COUNT", "managed", "AWS/AWSManagedRulesKnownBadInputsRuleSet"),
		wafRule("prod-waf", "AWS-AWSManagedRulesAmazonIpReputationList", account.WAFRuleManagedGroup, "NONE", "managed", "AWS/AWSManagedRulesAmazonIpReputationList"),
		wafRule("prod-waf", "rate-login", account.WAFRuleRateBased, "BLOCK", "rate_limit", 1000, "rate_window_sec", 300, "rate_aggregate", "IP", "rate_scope_paths", "STARTS_WITH:/login", "rate_scope_parsed", true),
		wafRule("prod-waf", "block-admin", account.WAFRuleRegular, "BLOCK"),
		wafRule("prod-waf", "count-geo", account.WAFRuleRegular, "COUNT"),
		wafRule("prod-waf", "unused-rule", account.WAFRuleRegular, "BLOCK"),
	)
	m := metricSeed{st: st, t: t}
	end := "2026-10-21"
	// 30 日分のデータ (使われていないルールの判定に要る)
	for _, d := range days(end, 30) {
		m.put(d, "waf", cwlogs.MetricWAFRuleAction, "prod-waf|Default_Action|ALLOW", 1000)
		for _, r := range []string{"AWS-AWSManagedRulesCommonRuleSet", "AWS-AWSManagedRulesAmazonIpReputationList", "block-admin", "rate-login"} {
			m.put(d, "waf", cwlogs.MetricWAFRuleAction, "prod-waf|"+r+"|BLOCK", 3)
		}
	}
	// 誤検知の疑い: 正規の画面で多数の IP が止められた (60 IP は finding にも)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/posts/:id", 200)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/posts/:id", 60)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/posts/:id", 50)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/posts/:id", 20)
	// 12 IP: 候補だけ (finding にはしない)
	m.put("2026-10-19", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|block-admin|GET|/admin/reports", 30)
	m.put("2026-10-19", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|block-admin|GET|/admin/reports", 12)
	// 提案しないもの: IP 数が少ない / レートベース / IP 評判のグループ / sign-in のパス / 設定に無いルール / 見る日数より前
	for _, k := range []string{
		"prod-waf|rate-login|POST|/login",
		"prod-waf|AWS-AWSManagedRulesAmazonIpReputationList|GET|/home",
		"prod-waf|AWS-AWSManagedRulesCommonRuleSet/SizeRestrictions_QUERYSTRING|POST|/users/sign_in",
		"prod-waf|deleted-rule|GET|/home",
	} {
		m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockPath, k, 500)
		m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockPathIPs, k, 100)
	}
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|block-admin|GET|/items/:id", 500)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|block-admin|GET|/items/:id", 1)
	m.put("2026-10-10", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|block-admin|GET|/old", 500)
	m.put("2026-10-10", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|block-admin|GET|/old", 100)

	// カウントのルール: KnownBadInputs は 14 日続けて一致し、全部が探索か BLOCK された IP から → BLOCK に上げてよい
	for _, d := range days(end, 14) {
		m.put(d, "waf", cwlogs.MetricWAFCountMatch, "prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet", 20)
		m.put(d, "waf", cwlogs.MetricWAFCountMatchSuspect, "prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet", 20)
		// グループの中で COUNT に上書きしたルール: 正規の通信が多い → 出さない
		m.put(d, "waf", cwlogs.MetricWAFCountMatch, "prod-waf|AWS#AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY", 20)
		m.put(d, "waf", cwlogs.MetricWAFCountMatchSuspect, "prod-waf|AWS#AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY", 5)
	}
	// count-geo は 13 日だけ → 出さない
	for _, d := range days(end, 13) {
		m.put(d, "waf", cwlogs.MetricWAFCountMatch, "prod-waf|count-geo", 20)
		m.put(d, "waf", cwlogs.MetricWAFCountMatchSuspect, "prod-waf|count-geo", 20)
	}
	// すり抜けている探索
	m.put("2026-10-20", "waf", cwlogs.MetricWAFAllowProbe, "prod-waf|/.env", 8)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFAllowProbeIPs, "prod-waf|/.env", 2)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFAllowProbe, "prod-waf|/.env", 5)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFAllowProbeIPs, "prod-waf|/.env", 3)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFAllowProbe, "prod-waf|/.git/config", 1)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFAllowProbeIPs, "prod-waf|/.git/config", 1)
	// レート
	rate := func(d, grp string, p50, p99, max float64) {
		m.put(d, "waf", cwlogs.MetricWAFIPRateP50, "prod-waf|"+grp, p50)
		m.put(d, "waf", cwlogs.MetricWAFIPRateP99, "prod-waf|"+grp, p99)
		m.put(d, "waf", cwlogs.MetricWAFIPRateMax, "prod-waf|"+grp, max)
	}
	rate("2026-10-20", cwlogs.RateGroupOther, 1, 20, 400) // 受け持つレート制限が無く、最大が p99 の 10 倍超え → 足す
	rate("2026-10-21", cwlogs.RateGroupOther, 1, 15, 100)
	rate("2026-10-20", "/login", 1, 8, 9)    // rate-login (1000/5 分) が観測の最大 9 の 10 倍より高い → 緩い
	rate("2026-10-20", "/api/", 2, 10, 5000) // expected_high_rate_paths → 出さない
	return st
}

func wafReviewConfig() config.WAFReview {
	c := config.DefaultChecks().WAFReview
	c.ExpectedHighRatePaths = []string{"/api/"}
	return c
}

func reviewWAF(t *testing.T, st *store.Dir) ([]schema.Proposal, []Observation) {
	t.Helper()
	cfg := config.DefaultChecks()
	cfg.WAFReview = wafReviewConfig()
	c := WAFReview{Config: cfg.WAFReview, SignInPaths: cfg.LoginBruteforce.Paths, ProbePaths: cfg.ProbePaths.Paths}
	props, obs, err := c.Propose(context.Background(), st, weekly())
	if err != nil {
		t.Fatal(err)
	}
	obs2, err := c.Evaluate(context.Background(), st, weekly(), nil)
	if err != nil || len(obs2) != len(obs) {
		t.Fatalf("Evaluate must return the same observations: %v %d %d", err, len(obs2), len(obs))
	}
	return props, obs
}

func TestWAFReview(t *testing.T) {
	props, obs := reviewWAF(t, seedWAFReview(t))
	var got []string
	byKind := map[string][]schema.Proposal{}
	for _, p := range props {
		line := p.Kind + ":" + p.Rule + "/" + p.RuleInGroup + ":" + p.Method + " " + p.Path
		if p.Kind == ProposalObservation {
			line += " (" + p.About + ", " + p.Reason + ")"
			if p.Stage != StageNone || p.FindingKey != "" {
				t.Fatalf("observation: %+v", p)
			}
		}
		got = append(got, line)
		byKind[p.Kind] = append(byKind[p.Kind], p)
		if p.WebACL != "prod-waf" || p.Summary == "" || p.Stage == "" || p.Scope != "REGIONAL" || p.Region != "ap-northeast-1" {
			t.Fatalf("incomplete: %+v", p)
		}
	}
	want := []string{
		"false_positive:AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY:POST /posts/:id",
		"false_positive:block-admin/:GET /admin/reports",
		"probe_allowed:/: ",
		"rate_limit_missing:/: *",
		"rate_limit_loose:rate-login/: /login",
		"unused_rule:unused-rule/: ",
		// 提案に至らなかった不審な観測 (理由つき)
		"observation:AWS-AWSManagedRulesAmazonIpReputationList/:GET /home (false_positive, excluded_by_rule)",
		"observation:AWS-AWSManagedRulesCommonRuleSet/SizeRestrictions_QUERYSTRING:POST /users/sign_in (false_positive, excluded_by_rule)",
		"observation:deleted-rule/:GET /home (false_positive, undetermined)",
		"observation:rate-login/:POST /login (false_positive, excluded_by_rule)",
		// COUNT のルールの状況 (計画の材料。提案ではない)
		"observation:AWS-AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY:  (count_rule_status, informational)",
		"observation:AWS-AWSManagedRulesKnownBadInputsRuleSet/:  (count_rule_status, informational)",
		"observation:count-geo/:  (count_rule_status, informational)",
		"observation:/: /api/ (rate_limit_missing, excluded_by_config)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("proposals:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	fp := byKind["false_positive"][0]
	if fp.Stage != StageCountFirst || fp.Evidence["count"] != 250.0 || fp.Evidence["distinct_ips_max_per_day"] != 60.0 || fp.Evidence["distinct_ips_is_lower_bound"] != true ||
		fp.Evidence["days"] != 7 || fp.FindingKey != "false_positive|prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST /posts/:id" {
		t.Fatalf("fp: %+v", fp)
	}
	if byKind["false_positive"][1].FindingKey != "" {
		t.Fatalf("12 IP は finding にしない: %+v", byKind["false_positive"][1])
	}
	status := map[string]schema.Proposal{}
	for _, p := range byKind[ProposalObservation] {
		if p.About == AboutCountRuleStatus {
			status[p.Rule+"/"+p.RuleInGroup] = p
		}
	}
	kbi := status["AWS-AWSManagedRulesKnownBadInputsRuleSet/"]
	if kbi.Reason != ReasonInformational || kbi.Evidence["matching_days"] != 7 || kbi.Evidence["days"] != 7 || kbi.Evidence["matches"] != 140.0 ||
		kbi.Evidence["suspect_ratio"] != 1.0 || kbi.Evidence["suspect_blocked_ip_excludes"] != "rate_based_rules,default_action,sign_in_paths" ||
		kbi.Summary != "prod-waf: COUNT の AWS-AWSManagedRulesKnownBadInputsRuleSet: 直近 7 日で 140 件一致、うち怪しい通信 100%、一致した日 7 / 7 日" {
		t.Fatalf("count status: %+v", kbi)
	}
	if crs := status["AWS-AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY"]; crs.Evidence["suspect_ratio"] != 0.25 {
		t.Fatalf("crs: %+v", crs)
	}
	for _, p := range props {
		if strings.Contains(p.Summary, "BLOCK に上げ") || strings.Contains(p.Summary, "BLOCK に変え") {
			t.Fatalf("COUNT → BLOCK は勧めない: %+v", p)
		}
	}
	pa := byKind["probe_allowed"][0]
	if pa.Stage != StageCountFirst || pa.Evidence["count"] != 14.0 || strings.Join(pa.Evidence["paths"].([]string), ",") != "/.env (13 件),/.git/config (1 件)" ||
		pa.Evidence["count_rules"].([]string)[0] != "AWS-AWSManagedRulesKnownBadInputsRuleSet" {
		t.Fatalf("probe: %+v", pa)
	}
	rm := byKind["rate_limit_missing"][0]
	if rm.Stage != StageCountFirst || rm.Evidence["p99_per_5min"] != 20.0 || rm.Evidence["max_per_5min"] != 400.0 || rm.Evidence["proposed_limit"] != 100.0 || rm.Evidence["evaluation_window_sec"] != 300 {
		t.Fatalf("rate missing: %+v", rm)
	}
	rl := byKind["rate_limit_loose"][0]
	if rl.Stage != StageReview || rl.Evidence["current_limit_per_5min"] != 1000.0 || rl.Evidence["max_per_5min"] != 9.0 || rl.Evidence["proposed_limit"] != 100.0 {
		t.Fatalf("rate loose: %+v", rl)
	}
	if u := byKind["unused_rule"][0]; u.Stage != StageReview || u.Evidence["days_without_match"] != 30 {
		t.Fatalf("unused: %+v", u)
	}

	// 重大な候補 (正規の画面での大量ブロック) だけ low の finding
	if len(obs) != 1 || obs[0].Key != fp.FindingKey || obs[0].Severity != Low || obs[0].Check != "waf_review" || strings.Contains(obs[0].Fingerprint, "2026-") ||
		obs[0].Data["distinct_ips_max_per_day"] != 60.0 {
		t.Fatalf("obs: %+v", obs)
	}
}

func TestWAFReviewQuiet(t *testing.T) {
	// 導入直後 (データの日数が足りない) は、使われていないルールを提案しない。COUNT のルールの状況は一致 0 でも毎回載せる
	st := newStore(t)
	snapshot(t, st, record.KindWAFConfig, wafACL("prod-waf"), wafRule("prod-waf", "unused-rule", account.WAFRuleRegular, "BLOCK"),
		wafRule("prod-waf", "count-geo", account.WAFRuleRegular, "COUNT"), wafRule("prod-waf", "count-zero", account.WAFRuleRegular, "COUNT"))
	m := metricSeed{st: st, t: t}
	for _, d := range days("2026-10-21", 3) {
		m.put(d, "waf", cwlogs.MetricWAFRuleAction, "prod-waf|Default_Action|ALLOW", 1000)
		m.put(d, "waf", cwlogs.MetricWAFCountMatch, "prod-waf|count-geo", 50)
		m.put(d, "waf", cwlogs.MetricWAFCountMatchSuspect, "prod-waf|count-geo", 50)
	}
	props, obs := reviewWAF(t, st)
	if len(props) != 2 || len(obs) != 0 || props[0].Rule != "count-geo" || props[0].Evidence["matching_days"] != 3 || props[0].Reason != ReasonInformational ||
		props[1].Rule != "count-zero" || props[1].Summary != "prod-waf: COUNT の count-zero: 直近 7 日で一致なし" || props[1].Evidence["matches"] != 0.0 {
		t.Fatalf("%+v %+v", props, obs)
	}
}

func TestWAFReviewAmbiguousACL(t *testing.T) {
	// 同じ名前の WebACL が 2 つのリージョンにある → 設定と突き合わせられないので設定が要る候補は出さない
	st := seedWAFReview(t)
	items, _ := st.Snapshot(context.Background(), record.KindWAFConfig)
	dup := wafACL("prod-waf")
	dup.Key, dup.Data["region"] = "acl|REGIONAL|us-west-2|prod-waf", "us-west-2"
	snapshot(t, st, record.KindWAFConfig, append(items, dup)...)
	props, obs := reviewWAF(t, st)
	for _, p := range props {
		if p.Kind != ProposalProbeAllowed && p.Kind != ProposalObservation {
			t.Fatalf("unexpected: %+v", p)
		}
		if p.Scope != "" || p.Region != "" {
			t.Fatalf("scope must be unknown: %+v", p)
		}
	}
	if len(obs) != 0 {
		t.Fatalf("obs: %+v", obs)
	}
}

func TestWAFReviewObservations(t *testing.T) {
	st := newStore(t)
	snapshot(t, st, record.KindWAFConfig, wafACL("prod-waf"),
		wafRule("prod-waf", "block-admin", account.WAFRuleRegular, "BLOCK"),
		// scope-down を解釈できないレートベースのルール
		wafRule("prod-waf", "rate-geo", account.WAFRuleRateBased, "BLOCK", "rate_limit", 100, "rate_window_sec", 300, "rate_aggregate", "IP", "rate_scope_paths", "", "rate_scope_parsed", false))
	m := metricSeed{st: st, t: t}
	// 許可された探索が閾値未満
	m.put("2026-10-21", "waf", cwlogs.MetricWAFAllowProbe, "prod-waf|/.env", 3)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFAllowProbeIPs, "prod-waf|/.env", 1)
	// BLOCK が多いが異なり IP が閾値未満 (2 IP 以上・min_count 件以上のときだけ)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|block-admin|GET|/reports", 40)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|block-admin|GET|/reports", 3)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockPath, "prod-waf|block-admin|GET|/one-ip", 400)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockPathIPs, "prod-waf|block-admin|GET|/one-ip", 1)
	// レート制限が /login を受け持つか判断できない
	m.put("2026-10-21", "waf", cwlogs.MetricWAFIPRateP99, "prod-waf|/login", 5)
	m.put("2026-10-21", "waf", cwlogs.MetricWAFIPRateMax, "prod-waf|/login", 600)
	// 位置の上限を超えた
	m.put("2026-10-21", "waf", cwlogs.MetricWAFPositionLimit, "prod-waf|ruleGroupList", 7)
	props, obs := reviewWAF(t, st)
	var got []string
	for _, p := range props {
		got = append(got, p.Kind+":"+p.About+":"+p.Reason+":"+p.Path)
		if p.Summary == "" || len(p.Evidence) == 0 {
			t.Fatalf("incomplete: %+v", p)
		}
	}
	want := "observation:false_positive:below_threshold:/reports,observation:probe_allowed:below_threshold:,observation:rate_limit_missing:undetermined:/login,observation:count_rule_status:position_limit:"
	if strings.Join(got, ",") != want || len(obs) != 0 {
		t.Fatalf("got %s", strings.Join(got, ","))
	}
	if props[3].Evidence["requests"] != 7.0 || props[3].Evidence["field"] != "ruleGroupList" || !strings.Contains(props[2].Summary, "rate-geo") {
		t.Fatalf("%+v", props)
	}
}
