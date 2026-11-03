package cwlogs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
)

func wafSource() config.Source {
	return config.Source{ID: "waf", Kind: config.KindCloudWatchLogs, LogGroup: "aws-waf-logs-prod", Format: config.FormatWAFv2, Yields: config.YieldsWAFAction, ExpectedMatchRate: 0.8}
}

func wafChecks() config.Checks {
	c := checksCfg()
	c.WAFReview.TopPaths = 2
	c.WAFReview.RatePathGroups = []string{"/api/", "/api/v2/", "/login"}
	c.WAFReview.TrustedCIDRs = []string{"203.0.113.0/24"}
	return c
}

func TestNormalizePath(t *testing.T) {
	for in, want := range map[string]string{
		"/users/123/edit": "/users/:id/edit",
		"/orders/550e8400-e29b-41d4-a716-446655440000": "/orders/:id",
		"/search?q=alice@example.com":                  "/search",
		"/a/b#frag":                                    "/a/b",
		"/v2/items/42/":                                "/v2/items/:id/",
		"/":                                            "/",
		"":                                             "/",
		"/mail/alice@example.com":                      "/mail/<email>",
		"/v2/abc123":                                   "/v2/abc123",
	} {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWAFQueries(t *testing.T) {
	c := wafChecks()
	c.ProbePaths.ExcludePaths = []string{"/.env.example"}
	p, _ := ProfileFor(wafSource())
	qs := WAFQueries(p, c)
	names := []string{}
	for _, q := range qs {
		names = append(names, q.Name)
	}
	if strings.Join(names, ",") != "waf_rule_action,waf_block_path,waf_allow_probe,waf_suspect_block_ip,waf_rule_count_match,waf_challenge_issued,waf_challenge_solved,waf_ip_rate" {
		t.Fatalf("names: %v", names)
	}
	acl := `| parse webaclId /webacl\/(?<acl>[^\/]+)\//`
	trusted := `not isIpInSubnet(ip, "203.0.113.0/24")`
	for _, q := range qs {
		if !strings.HasPrefix(q.Query, p.Prelude+"\n"+acl) {
			t.Fatalf("%s: prelude: %s", q.Name, q.Query)
		}
		// 規則の数 (ルールごとの件数) は正規の送信元も数える (使われていないルールの判定に使う)。他は外す
		if (q.Name == "waf_rule_action") == strings.Contains(q.Query, trusted) {
			t.Fatalf("%s: trusted filter: %s", q.Name, q.Query)
		}
		if strings.Contains(q.Query, "headers") || strings.Contains(q.Query, "args") || strings.Contains(q.Query, "@message |") {
			t.Fatalf("%s must not read headers / query strings: %s", q.Name, q.Query)
		}
	}
	bp := qs[1].Query
	for _, want := range []string{
		`filter action = "BLOCK"`,
		`(path not like /^(\/\.env|\/wp-login\.php)/ or path like /^(\/\.env\.example)/)`,
		"| stats count(*) as waf_block_path by bin(1d) as day, acl, rule, terminatingRuleType, ruleGroupList.0.terminatingRule.ruleId, ",
		"ruleGroupList.7.terminatingRule.ruleId, ruleGroupList.8.ruleGroupId, method, path, ip",
		"| limit 10000",
	} {
		if !strings.Contains(bp, want) {
			t.Fatalf("block path query lacks %q:\n%s", want, bp)
		}
	}
	if strings.Contains(bp, "parse @message") {
		t.Fatalf("block path must not parse the raw message: %s", bp)
	}
	if ap := qs[2].Query; !strings.Contains(ap, `filter action = "ALLOW" and path like /^(\/\.env|\/wp-login\.php)/ and path not like /^(\/\.env\.example)/`) ||
		!strings.Contains(ap, "by bin(1d) as day, acl, path, ip") {
		t.Fatalf("allow probe: %s", ap)
	}
	cm := qs[4].Query
	for _, want := range []string{
		"ispresent(nonTerminatingMatchingRules.0.ruleId) or ispresent(nonTerminatingMatchingRules.1.ruleId)",
		"ispresent(ruleGroupList.7.nonTerminatingMatchingRules.0.ruleId)",
		`| parse path /^(?<probe>\/\.env|\/wp-login\.php)/`,
		`| parse path /^(?<probe_ex>\/\.env\.example)/`,
		"by bin(1d) as day, acl, nonTerminatingMatchingRules.0.ruleId, nonTerminatingMatchingRules.1.ruleId, nonTerminatingMatchingRules.2.ruleId, ruleGroupList.0.ruleGroupId, ruleGroupList.0.nonTerminatingMatchingRules.0.ruleId",
		"ruleGroupList.7.nonTerminatingMatchingRules.0.ruleId, nonTerminatingMatchingRules.3.ruleId, ruleGroupList.8.ruleGroupId, probe, probe_ex, ip",
	} {
		if !strings.Contains(cm, want) {
			t.Fatalf("count query lacks %q:\n%s", want, cm)
		}
	}
	sb := qs[3].Query
	for _, want := range []string{
		`filter action = "BLOCK" and terminatingRuleType != "RATE_BASED" and rule != "Default_Action" and path not in ["/users/sign_in"] and ` + trusted,
		"| stats count(*) as waf_suspect_block_ip by bin(1d) as day, ip",
	} {
		if !strings.Contains(sb, want) {
			t.Fatalf("suspect block ip query lacks %q:\n%s", want, sb)
		}
	}
	ci := qs[5].Query
	for _, want := range []string{
		`filter action in ["CHALLENGE", "CAPTCHA"] and ` + trusted,
		"| stats count(*) as waf_challenge_issued by bin(1d) as day, acl, rule, action, terminatingRuleType, ruleGroupList.0.terminatingRule.ruleId, ",
		"ruleGroupList.8.ruleGroupId, method, path, ip",
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("challenge issued query lacks %q:\n%s", want, ci)
		}
	}
	cs := qs[6].Query
	for _, want := range []string{
		// 文書の説明 (トップレベルの challengeResponse / captchaResponse) と例 (nonTerminatingMatchingRules の中) の両方の形を受け付ける
		`challengeResponse.solveTimestamp > 0 or captchaResponse.solveTimestamp > 0 or nonTerminatingMatchingRules.0.action in ["CHALLENGE", "CAPTCHA"]`,
		`ruleGroupList.7.nonTerminatingMatchingRules.0.action in ["CHALLENGE", "CAPTCHA"])`,
		"| stats count(*) as waf_challenge_solved by bin(1d) as day, acl, action, challengeResponse.solveTimestamp, challengeResponse.failureReason, captchaResponse.solveTimestamp, captchaResponse.failureReason, nonTerminatingMatchingRules.0.action, ",
		"ruleGroupList.7.nonTerminatingMatchingRules.0.action, method, path, ip",
	} {
		if !strings.Contains(cs, want) {
			t.Fatalf("challenge solved query lacks %q:\n%s", want, cs)
		}
	}
	rate := qs[7]
	// 長い接頭辞を先に (最長一致)
	if !rate.PerDay || !strings.Contains(rate.Query, `| parse path /^(?<grp>\/api\/v2\/|\/login|\/api\/)/`) ||
		!strings.Contains(rate.Query, "| stats count(*) as n by bin(5m) as t, acl, grp, ip\n| stats pct(n, 50) as waf_ip_rate_p50, pct(n, 99) as waf_ip_rate_p99, max(n) as waf_ip_rate_max by acl, grp") {
		t.Fatalf("rate: %s", rate.Query)
	}
}

// wafLog は WAF のログ 1 行の Insights の結果の行 (公式のログ例の形)。
func row(kv ...string) map[string]string { return cwlogstest.Rows(kv...) }

func wafFake() *cwlogstest.Fake {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", linesResp("2026-10-21", "1000", "1000"))
	day := "2026-10-21 00:00:00.000"
	f.On("as waf_block_ip", cwlogstest.Response{Rows: []map[string]string{
		row("day", day, "ip", "198.51.100.7", "waf_block_ip", "50"),
		row("day", day, "ip", "198.51.100.8", "waf_block_ip", "1"),
		row("day", day, "ip", "198.51.100.20", "waf_block_ip", "40"), // レート制限だけで BLOCK された
	}})
	// 「BLOCK された IP」はレートベースのルール・既定の action・sign-in のパスでの BLOCK を除く (クエリ側で除く)
	f.On("as waf_suspect_block_ip", cwlogstest.Response{Rows: []map[string]string{
		row("day", day, "ip", "198.51.100.7", "waf_suspect_block_ip", "50"),
		row("day", day, "ip", "198.51.100.8", "waf_suspect_block_ip", "1"),
	}})
	f.On("as waf_rule_action", cwlogstest.Response{Rows: []map[string]string{
		row("day", day, "acl", "prod-waf", "rule", "AWS-AWSManagedRulesCommonRuleSet", "action", "BLOCK", "waf_rule_action", "30"),
		row("day", day, "acl", "stg-waf", "rule", "AWS-AWSManagedRulesCommonRuleSet", "action", "BLOCK", "waf_rule_action", "5"),
		row("day", day, "acl", "prod-waf", "rule", "Default_Action", "action", "ALLOW", "waf_rule_action", "900"),
	}})
	var bp []map[string]string
	// 10 人が自分の /users/<id> で同じルールに止められた (正規の画面の誤検知らしい)
	for i := 0; i < 10; i++ {
		// 公式のログの形: 前にある KnownBadInputs (グループ全体を COUNT) も一致して terminatingRule が null でない。止めたのは後ろの CommonRuleSet
		bp = append(bp, row("day", day, "acl", "prod-waf", "rule", "AWS-AWSManagedRulesCommonRuleSet", "terminatingRuleType", "MANAGED_RULE_GROUP",
			"ruleGroupList.0.terminatingRule.ruleId", "Log4JRCE_HEADER", "ruleGroupList.1.terminatingRule.ruleId", "CrossSiteScripting_BODY",
			"method", "POST", "path", fmt.Sprintf("/users/%d", i+1), "ip", fmt.Sprintf("192.0.2.%d", i+1), "waf_block_path", "2"))
	}
	// 1 IP が /items/<id> を 500 個列挙した (異なり IP は 1)
	for i := 0; i < 500; i++ {
		// 普通のルールが止めた。前の COUNT のグループの terminatingRule は中のルール名に使わない
		bp = append(bp, row("day", day, "acl", "prod-waf", "rule", "block-admin", "terminatingRuleType", "REGULAR", "ruleGroupList.0.terminatingRule.ruleId", "Log4JRCE_HEADER",
			"method", "GET", "path", fmt.Sprintf("/items/%d", i), "ip", "198.51.100.7", "waf_block_path", "1"))
	}
	// 位置の上限より後ろにグループがある行は中のルールを決めない (グループ単位)。位置の上限を超えたことを数える
	bp = append(bp, row("day", day, "acl", "prod-waf", "rule", "AWS-AWSManagedRulesCommonRuleSet", "terminatingRuleType", "MANAGED_RULE_GROUP",
		"ruleGroupList.7.terminatingRule.ruleId", "A", "ruleGroupList.8.ruleGroupId", "AWS#X", "method", "GET", "path", "/x", "ip", "192.0.2.99", "waf_block_path", "1"))
	f.On("as waf_block_path", cwlogstest.Response{Rows: bp})
	f.On("as waf_allow_probe", cwlogstest.Response{Rows: []map[string]string{
		row("day", day, "acl", "prod-waf", "path", "/.env", "ip", "198.51.100.9", "waf_allow_probe", "3"),
		row("day", day, "acl", "prod-waf", "path", "/.env", "ip", "198.51.100.10", "waf_allow_probe", "4"),
	}})
	f.On("as waf_rule_count_match", cwlogstest.Response{Rows: []map[string]string{
		// KnownBadInputs を全体 COUNT にしたときのトップレベルの一致。探索パスで
		row("day", day, "acl", "prod-waf", "nonTerminatingMatchingRules.0.ruleId", "AWS-AWSManagedRulesKnownBadInputsRuleSet", "probe", "/.env", "ip", "198.51.100.9", "waf_rule_count_match", "6"),
		// グループの中で COUNT に上書きしたルールと、トップレベルの COUNT の両方に一致。BLOCK された IP から
		row("day", day, "acl", "prod-waf", "nonTerminatingMatchingRules.0.ruleId", "count-geo",
			"ruleGroupList.0.ruleGroupId", "AWS#AWSManagedRulesCommonRuleSet", "ruleGroupList.0.nonTerminatingMatchingRules.0.ruleId", "SizeRestrictions_BODY",
			"ip", "198.51.100.8", "waf_rule_count_match", "4"),
		// レート制限だけで BLOCK された IP (正規の利用者かもしれない) からの一致は suspect にしない
		row("day", day, "acl", "prod-waf", "nonTerminatingMatchingRules.0.ruleId", "count-login", "ip", "198.51.100.20", "waf_rule_count_match", "9"),
		// 正規の IP から。探索パスの除外に当たる
		row("day", day, "acl", "prod-waf", "nonTerminatingMatchingRules.0.ruleId", "AWS-AWSManagedRulesKnownBadInputsRuleSet", "probe", "/.env", "probe_ex", "/.env.example", "ip", "192.0.2.1", "waf_rule_count_match", "2"),
	}})
	// Challenge / CAPTCHA。/search (GET) に 3 IP へ Challenge を出し、うち 2 IP が同じ日・同じパスでトークンを持って来た
	var ci, cs []map[string]string
	for i := 1; i <= 3; i++ {
		ci = append(ci, row("day", day, "acl", "prod-waf", "rule", "challenge-search", "action", "CHALLENGE", "terminatingRuleType", "REGULAR",
			"method", "GET", "path", fmt.Sprintf("/search/%d", i), "ip", fmt.Sprintf("192.0.2.%d", i), "waf_challenge_issued", "2"))
	}
	// グループの中のルール (Bot Control) の CAPTCHA。POST
	ci = append(ci, row("day", day, "acl", "prod-waf", "rule", "AWS-AWSManagedRulesBotControlRuleSet", "action", "CAPTCHA", "terminatingRuleType", "MANAGED_RULE_GROUP",
		"ruleGroupList.0.terminatingRule.ruleId", "CategoryHttpLibrary", "method", "POST", "path", "/api/cart", "ip", "198.51.100.30", "waf_challenge_issued", "5"))
	f.On("as waf_challenge_issued", cwlogstest.Response{Rows: ci})
	cs = []map[string]string{
		// 公式の例の形: nonTerminatingMatchingRules の中にだけ CAPTCHA / CHALLENGE がある
		row("day", day, "acl", "prod-waf", "action", "ALLOW", "nonTerminatingMatchingRules.0.action", "CHALLENGE", "method", "GET", "path", "/search/1", "ip", "192.0.2.1", "waf_challenge_solved", "4"),
		// フィールドの説明の形: トップレベルの challengeResponse に solveTimestamp があり failureReason が無い
		row("day", day, "acl", "prod-waf", "action", "ALLOW", "challengeResponse.solveTimestamp", "1792990000", "method", "GET", "path", "/search/2", "ip", "192.0.2.2", "waf_challenge_solved", "1"),
		// 期限切れ (failureReason がある) は解いたとみなさない
		row("day", day, "acl", "prod-waf", "action", "CHALLENGE", "challengeResponse.solveTimestamp", "1792900000", "challengeResponse.failureReason", "TOKEN_EXPIRED",
			"method", "GET", "path", "/search/3", "ip", "192.0.2.3", "waf_challenge_solved", "1"),
		// 出していない IP がトークンを持って来ても数えない (積集合)
		row("day", day, "acl", "prod-waf", "action", "ALLOW", "nonTerminatingMatchingRules.0.action", "CHALLENGE", "method", "GET", "path", "/search/9", "ip", "192.0.2.50", "waf_challenge_solved", "1"),
		// 種類が違う (CAPTCHA のトークン) は Challenge を解いたことにしない
		row("day", day, "acl", "prod-waf", "action", "ALLOW", "nonTerminatingMatchingRules.0.action", "CAPTCHA", "method", "GET", "path", "/search/3", "ip", "192.0.2.3", "waf_challenge_solved", "1"),
	}
	f.On("as waf_challenge_solved", cwlogstest.Response{Rows: cs})
	f.On("as waf_ip_rate_p50", cwlogstest.Response{RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
		if aws.ToInt64(in.StartTime) == time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).Unix() {
			return []map[string]string{row("acl", "prod-waf", "grp", "/login", "waf_ip_rate_p50", "2", "waf_ip_rate_p99", "8", "waf_ip_rate_max", "300")}
		}
		return []map[string]string{row("acl", "prod-waf", "waf_ip_rate_p50", "1", "waf_ip_rate_p99", "20", "waf_ip_rate_max", "40")}
	}})
	return f
}

func TestCollectWAF(t *testing.T) {
	f := wafFake()
	c, err := New(wafSource(), wafChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	d := "2026-10-21|"
	for k, want := range map[string]float64{
		// 既存の waf_block (rule 別) はルールごとの件数から作る (WebACL をまたいで足す)
		d + "waf_block|AWS-AWSManagedRulesCommonRuleSet":                     35,
		d + "waf_block_ip|198.51.100.7":                                      50,
		d + "waf_rule_action|prod-waf|Default_Action|ALLOW":                  900,
		d + "waf_rule_action|stg-waf|AWS-AWSManagedRulesCommonRuleSet|BLOCK": 5,
		// 正規化して合算し、異なり IP は (パス, IP) で数える
		d + "waf_block_path|prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/users/:id":                  20,
		d + "waf_block_path_ips|prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/users/:id":              10,
		d + "waf_block_path|prod-waf|block-admin|GET|/items/:id":                                                                500,
		d + "waf_block_path_ips|prod-waf|block-admin|GET|/items/:id":                                                            1,
		d + "waf_allow_probe|prod-waf|/.env":                                                                                    7,
		d + "waf_allow_probe_ips|prod-waf|/.env":                                                                                2,
		d + "waf_rule_count_match|prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet":                                            8,
		d + "waf_rule_count_match_suspect|prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet":                                    6,
		d + "waf_rule_count_match|prod-waf|count-geo":                                                                           4,
		d + "waf_rule_count_match_suspect|prod-waf|count-geo":                                                                   4,
		d + "waf_rule_count_match|prod-waf|AWS#AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY":                              4,
		d + "waf_position_limit|prod-waf|ruleGroupList":                                                                         1,
		"2026-10-20|waf_ip_rate_max|prod-waf|/login":                                                                            300,
		"2026-10-20|waf_ip_rate_p99|prod-waf|/login":                                                                            8,
		d + "waf_ip_rate_p99|prod-waf|*":                                                                                        20,
		d + "waf_ip_rate_p50|prod-waf|*":                                                                                        1,
		d + "waf_challenge_issued|prod-waf|challenge|challenge-search|GET|/search/:id":                                          6,
		d + "waf_challenge_issued_ips|prod-waf|challenge|challenge-search|GET|/search/:id":                                      3,
		d + "waf_challenge_solved_ips|prod-waf|challenge|challenge-search|GET|/search/:id":                                      2,
		d + "waf_challenge_issued|prod-waf|captcha|AWS-AWSManagedRulesBotControlRuleSet/CategoryHttpLibrary|POST|/api/cart":     5,
		d + "waf_challenge_solved_ips|prod-waf|captcha|AWS-AWSManagedRulesBotControlRuleSet/CategoryHttpLibrary|POST|/api/cart": 0,
	} {
		if got, ok := m[k]; !ok || got != want {
			t.Errorf("%s = %v (ok=%v), want %v", k, got, ok, want)
		}
	}
	// 上位 top_paths (2) だけ。/x は 3 位なので残らない
	n := 0
	for k := range m {
		if strings.Contains(k, "|waf_block_path|") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("block paths: %d %v", n, m)
	}
	// レートは UTC の 1 日ずつ (窓の始まりの日の 0 時から、終わりまで)
	var rate []*cwl.StartQueryInput
	for _, in := range f.Started {
		if strings.Contains(aws.ToString(in.QueryString), "waf_ip_rate_p50") {
			rate = append(rate, in)
		}
	}
	if len(rate) != 2 || aws.ToInt64(rate[0].EndTime) != time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC).Unix()-1 ||
		aws.ToInt64(rate[1].StartTime) != time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC).Unix() || aws.ToInt64(rate[1].EndTime) != now.Unix()-1 {
		t.Fatalf("rate queries: %+v", rate)
	}
	// waf_block は別のクエリを流さない (lines + waf_block_ip + 7 本 + レート 2 日)
	if len(f.Started) != 11 {
		t.Fatalf("queries: %d", len(f.Started))
	}
	if len(c.FormatStats().Truncated) != 0 {
		t.Fatalf("truncated: %v", c.FormatStats().Truncated)
	}
}

func TestCollectWAFTruncated(t *testing.T) {
	f := wafFake()
	rows := make([]map[string]string, MaxRows)
	for i := range rows {
		rows[i] = row("day", "2026-10-21 00:00:00.000", "acl", "prod-waf", "path", "/.env", "ip", fmt.Sprintf("10.0.%d.%d", i/256, i%256), "waf_allow_probe", "1")
	}
	f.On("as waf_allow_probe", cwlogstest.Response{Rows: rows})
	c, _ := New(wafSource(), wafChecks(), f)
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.FormatStats().Truncated, ","); got != "waf_allow_probe" {
		t.Fatalf("truncated: %q", got)
	}
}

func TestCollectWAFStripPathPrefix(t *testing.T) {
	src := wafSource()
	src.StripPathPrefix = "/sandbox"
	p, _ := ProfileFor(src)
	qs := WAFQueries(p, wafChecks())
	if !strings.Contains(qs[1].Query, `path not like /^\/sandbox(\/\.env|\/wp-login\.php)/`) ||
		!strings.Contains(qs[2].Query, `path like /^\/sandbox(\/\.env|\/wp-login\.php)/`) ||
		!strings.Contains(qs[4].Query, `| parse path /^\/sandbox(?<probe>\/\.env|\/wp-login\.php)/`) ||
		!strings.Contains(qs[7].Query, `| parse path /^\/sandbox(?<grp>\/api\/v2\/|\/login|\/api\/)/`) {
		t.Fatalf("queries:\n%s\n%s\n%s\n%s", qs[1].Query, qs[2].Query, qs[4].Query, qs[7].Query)
	}
	if !strings.Contains(qs[3].Query, `path not in ["/sandbox/users/sign_in"]`) {
		t.Fatalf("suspect: %s", qs[3].Query)
	}
	f := wafFake()
	f.On("as waf_allow_probe", cwlogstest.Response{Rows: []map[string]string{row("day", "2026-10-21 00:00:00.000", "acl", "prod-waf", "path", "/sandbox/.env", "ip", "198.51.100.9", "waf_allow_probe", "3")}})
	c, _ := New(src, wafChecks(), f)
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	if m := sink.metrics(); m["2026-10-21|waf_allow_probe|prod-waf|/.env"] != 3 {
		t.Fatalf("metrics: %v", m)
	}
	if got := StripPrefix("/sandbox", "/sandbox/login"); got != "/login" || StripPrefix("/sandbox", "/sandbox") != "/" || StripPrefix("/sandbox", "/sandboxes/x") != "/sandboxes/x" {
		t.Fatal(got)
	}
}

// resources は前処理で httpSourceId を絞る (lines・解釈率・全集計に効く)。glob の * と ? は正規表現にする
func TestWAFResourcesFilter(t *testing.T) {
	src := wafSource()
	src.Resources = []string{"123456789012:abcde12345:prod", "app-alb/*"}
	p, err := ProfileFor(src)
	if err != nil {
		t.Fatal(err)
	}
	want := wafPrelude + "\n| filter httpSourceId like /^(123456789012:abcde12345:prod|app-alb\\/.*)$/"
	if p.Prelude != want {
		t.Fatalf("prelude:\n%s\nwant:\n%s", p.Prelude, want)
	}
	if !strings.HasPrefix(LinesQuery(p), want) || !strings.HasPrefix(WAFQueries(p, wafChecks())[0].Query, want) {
		t.Fatal("resources filter must be in every query")
	}
	if got := GlobRegex("a?b.c*"); got != `a.b\.c.*` {
		t.Fatal(got)
	}
}
