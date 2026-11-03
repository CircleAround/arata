package cwlogs

import (
	"context"
	"fmt"
	"sort"
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
	if strings.Join(names, ",") != "waf_rule_action,waf_actions,waf_rule_count_match" {
		t.Fatalf("names: %v", names)
	}
	acl := `| parse webaclId /webacl\/(?<acl>[^\/]+)\//`
	trusted := `not isIpInSubnet(ip, "203.0.113.0/24")`
	for _, q := range append(qs, MergedQuery{Name: "rate", Query: WAFRateQuery(p, c)}) {
		if !strings.HasPrefix(q.Query, p.Prelude+"\n"+acl) {
			t.Fatalf("%s: prelude: %s", q.Name, q.Query)
		}
		// 規則の数 (ルールごとの件数) は正規の送信元も数える (使われていないルールの判定に使う)。他は外す (BLOCK の行は Go で外す)
		if (q.Name == "waf_rule_action") == strings.Contains(q.Query, trusted) {
			t.Fatalf("%s: trusted filter: %s", q.Name, q.Query)
		}
		if strings.Contains(q.Query, "headers") || strings.Contains(q.Query, "args") || strings.Contains(q.Query, "@message |") || strings.Contains(q.Query, "parse @message") {
			t.Fatalf("%s must not read headers / query strings / the raw message: %s", q.Name, q.Query)
		}
	}
	// 解釈率とルールごとの件数は 1 本
	if !strings.HasSuffix(qs[0].Query, "| stats count(*) as lines_total, count(action) as lines_matched by bin(1d) as day, acl, rule, action\n| sort lines_total desc\n| limit 10000") {
		t.Fatalf("lines: %s", qs[0].Query)
	}
	ac := qs[1].Query
	for _, want := range []string{
		`| filter action = "BLOCK" or ((action in ["CHALLENGE", "CAPTCHA"] or (action = "ALLOW" and path like /^(\/\.env|\/wp-login\.php)/ and path not like /^(\/\.env\.example)/) or `,
		// 文書の説明 (トップレベルの challengeResponse / captchaResponse) と例 (nonTerminatingMatchingRules の中) の両方の形を受け付ける
		`challengeResponse.solveTimestamp > 0 or captchaResponse.solveTimestamp > 0 or nonTerminatingMatchingRules.0.action in ["CHALLENGE", "CAPTCHA"]`,
		`ruleGroupList.7.nonTerminatingMatchingRules.0.action in ["CHALLENGE", "CAPTCHA"]) and ` + trusted + ")",
		"| stats count(*) as waf_actions by bin(1d) as day, acl, rule, action, terminatingRuleType, ruleGroupList.0.terminatingRule.ruleId, ",
		"ruleGroupList.7.terminatingRule.ruleId, ruleGroupList.8.ruleGroupId, method, path, ip, challengeResponse.solveTimestamp, challengeResponse.failureReason, captchaResponse.solveTimestamp, captchaResponse.failureReason, nonTerminatingMatchingRules.0.action, ",
		"ruleGroupList.7.nonTerminatingMatchingRules.0.action\n| sort waf_actions desc",
		"| limit 10000",
	} {
		if !strings.Contains(ac, want) {
			t.Fatalf("actions query lacks %q:\n%s", want, ac)
		}
	}
	cm := qs[2].Query
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
	// 長い接頭辞を先に (最長一致)
	if rate := WAFRateQuery(p, c); !strings.Contains(rate, `| parse path /^(?<grp>\/api\/v2\/|\/login|\/api\/)/`) ||
		!strings.Contains(rate, "| stats count(*) as n by bin(5m) as t, acl, grp, ip\n| stats pct(n, 50) as waf_ip_rate_p50, pct(n, 99) as waf_ip_rate_p99, max(n) as waf_ip_rate_max by acl, grp") {
		t.Fatalf("rate: %s", rate)
	}
	// trusted_cidrs が無ければ BLOCK 以外の条件も括弧だけで並べる
	c.WAFReview.TrustedCIDRs = nil
	if ac := WAFQueries(p, c)[1].Query; !strings.Contains(ac, `| filter action = "BLOCK" or action in ["CHALLENGE", "CAPTCHA"] or (action = "ALLOW" and `) {
		t.Fatalf("actions without trusted: %s", ac)
	}
}

func row(kv ...string) map[string]string { return cwlogstest.Rows(kv...) }

// 振り分けの値はゴールデン (TestWAFEquivalence) で固定している。ここはクエリの流し方 (本数・範囲) と代表的な値を見る。
func TestCollectWAF(t *testing.T) {
	sink, c, f := runWAFEquiv(t, registerWAF)
	m := sink.metrics()
	d := "2026-10-21|"
	for k, want := range map[string]float64{
		// 既存の waf_block (rule 別) はルールごとの件数から作る (WebACL をまたいで足す)
		d + "waf_block|AWS-AWSManagedRulesCommonRuleSet": 26,
		d + "waf_block_ip|198.51.100.7":                  50,
		// 正規の送信元も BLOCK の IP には数える
		d + "waf_block_ip|203.0.113.5":                                                                             4,
		d + "waf_rule_action|stg-waf|AWS-AWSManagedRulesCommonRuleSet|BLOCK":                                       5,
		d + "waf_block_path|prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/users/:id":     20,
		d + "waf_block_path_ips|prod-waf|AWS-AWSManagedRulesCommonRuleSet/CrossSiteScripting_BODY|POST|/users/:id": 10,
		d + "waf_block_path_ips|prod-waf|block-admin|GET|/items/:id":                                               1,
		d + "waf_allow_probe|prod-waf|/.env":                                                                       13,
		d + "waf_rule_count_match_suspect|prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet":                       8,
		d + "waf_rule_count_match_suspect|prod-waf|count-login":                                                    0,
		d + "waf_challenge_solved_ips|prod-waf|challenge|challenge-search|GET|/search/:id":                         2,
		"2026-10-20|waf_ip_rate_max|prod-waf|/login":                                                               300,
	} {
		if got, ok := m[k]; !ok || got != want {
			t.Errorf("%s = %v (ok=%v), want %v", k, got, ok, want)
		}
	}
	// 上位 top_paths (3) だけ。/y (位置の上限) と探索・正規の送信元の BLOCK は残らない
	for k := range m {
		if strings.Contains(k, "|waf_block_path|") && (strings.HasSuffix(k, "|/y") || strings.HasSuffix(k, "|/.env") || strings.HasSuffix(k, "|/admin")) {
			t.Errorf("unexpected %s", k)
		}
	}
	// 4 本 (解釈率 + ルールごとの件数、止めた・出した系、カウントの一致、レート)。レートだけ UTC の 1 日ずつ
	if len(f.Started) != 3+2 || c.QueryCount() != 4 {
		t.Fatalf("queries: %d, count %d", len(f.Started), c.QueryCount())
	}
	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for i, in := range f.Started[:3] {
		if aws.ToInt64(in.StartTime) != start.Unix() || aws.ToInt64(in.EndTime) != now.Unix()-1 {
			t.Fatalf("query %d range: %d..%d", i, aws.ToInt64(in.StartTime), aws.ToInt64(in.EndTime))
		}
	}
	if r := f.Started[3]; aws.ToInt64(r.EndTime) != start.Add(24*time.Hour).Unix()-1 || aws.ToInt64(f.Started[4].StartTime) != start.Add(24*time.Hour).Unix() {
		t.Fatal("rate must be per UTC day")
	}
}

// 行数の上限に当たったら範囲を半分に分けて引き直す。1h まで分けても当たれば、まとめた集計から作る metric を全部 truncated に残す。
// 決定 (ADR 0031): filter を Go に移した集計は Insights から返る行が増える (読む量は同じ) ので、上限の扱いを確かめる。
func TestCollectWAFTruncated(t *testing.T) {
	full := make([]map[string]string, MaxRows)
	for i := range full {
		full[i] = row("day", "2026-10-21 00:00:00.000", "acl", "prod-waf", "action", "ALLOW", "path", "/.env", "ip", fmt.Sprintf("10.0.%d.%d", i/256, i%256), "waf_actions", "1")
	}
	for _, always := range []bool{false, true} {
		sink, c, f := runWAFEquiv(t, func(f *cwlogstest.Fake, sim *cwlogstest.Sim, p wafPreds) {
			registerWAF(f, sim, p)
			f.On("as waf_actions", cwlogstest.Response{RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
				// 3 時間より長い範囲は上限に当たる
				if always || aws.ToInt64(in.EndTime)+1-aws.ToInt64(in.StartTime) > int64(3*time.Hour/time.Second) {
					return full
				}
				return []map[string]string{row("day", "2026-10-21 00:00:00.000", "acl", "prod-waf", "action", "ALLOW", "path", "/.env", "ip", "198.51.100.9", "waf_actions", "1")}
			}})
		})
		var spans []string
		leaves := 0
		for _, in := range f.Started {
			if strings.Contains(aws.ToString(in.QueryString), "as waf_actions") {
				spans = append(spans, time.Unix(aws.ToInt64(in.StartTime), 0).UTC().Format("02 15:04")+"-"+time.Unix(aws.ToInt64(in.EndTime)+1, 0).UTC().Format("02 15:04"))
				if aws.ToInt64(in.EndTime)+1-aws.ToInt64(in.StartTime) <= int64(3*time.Hour/time.Second) {
					leaves++
				}
			}
		}
		got := strings.Join(c.FormatStats().Truncated, ",")
		if !always {
			// 範囲全体 (33h) → 上限 → 時に揃えて半分ずつ、3h 以下になるまで分ける
			if spans[0] != "20 00:00-21 09:00" || leaves < 11 || got != "" {
				t.Fatalf("spans: %v, truncated %q", spans, got)
			}
			// 分けた範囲の行は足し合わせる (同じ日・同じ key)
			if v := sink.metrics()["2026-10-21|waf_allow_probe|prod-waf|/.env"]; v != float64(leaves) {
				t.Fatalf("allow probe: %v, leaves %d", v, leaves)
			}
			continue
		}
		if got != "waf_block_ip,waf_block_path,waf_allow_probe,waf_suspect_block_ip,waf_challenge_issued,waf_challenge_solved" {
			t.Fatalf("truncated: %q", got)
		}
	}
}

func TestCollectWAFStripPathPrefix(t *testing.T) {
	src := wafSource()
	src.StripPathPrefix = "/sandbox"
	p, _ := ProfileFor(src)
	qs := WAFQueries(p, wafChecks())
	if !strings.Contains(qs[1].Query, `(action = "ALLOW" and path like /^\/sandbox(\/\.env|\/wp-login\.php)/)`) ||
		!strings.Contains(qs[2].Query, `| parse path /^\/sandbox(?<probe>\/\.env|\/wp-login\.php)/`) ||
		!strings.Contains(WAFRateQuery(p, wafChecks()), `| parse path /^\/sandbox(?<grp>\/api\/v2\/|\/login|\/api\/)/`) {
		t.Fatalf("queries:\n%s\n%s", qs[1].Query, qs[2].Query)
	}
	ev := func(action, rule, typ, uri, ip string) cwlogstest.Event {
		return wafEv(21, 5, "prod-waf", action, rule, typ, "GET", uri, ip, 3)
	}
	sim := &cwlogstest.Sim{Events: []cwlogstest.Event{
		ev("ALLOW", "Default_Action", "REGULAR", "/sandbox/.env", "198.51.100.9"),
		// 接頭辞の無い探索パスは探索にしない (BLOCK の行は block_path に入る)
		ev("BLOCK", "block-admin", "REGULAR", "/.env", "198.51.100.8"),
		// sign-in のパスは接頭辞付きで比べる
		ev("BLOCK", "block-geo", "REGULAR", "/sandbox/users/sign_in", "198.51.100.21"),
		ev("ALLOW", "Default_Action", "REGULAR", "/sandbox/login", "198.51.100.21"),
	}}
	f := &cwlogstest.Fake{}
	f.On("as lines_total", sim.Response(nil))
	f.On("as waf_actions", sim.Response(nil))
	f.On("as waf_rule_count_match", sim.Response(func(map[string]string) bool { return false }))
	c, _ := New(src, wafChecks(), f)
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	if m["2026-10-21|waf_allow_probe|prod-waf|/.env"] != 3 || m["2026-10-21|waf_block_path|prod-waf|block-admin|GET|/.env"] != 3 ||
		m["2026-10-21|waf_block_path|prod-waf|block-geo|GET|/users/sign_in"] != 3 {
		t.Fatalf("metrics: %v", m)
	}
	if got := StripPrefix("/sandbox", "/sandbox/login"); got != "/login" || StripPrefix("/sandbox", "/sandbox") != "/" || StripPrefix("/sandbox", "/sandboxes/x") != "/sandboxes/x" {
		t.Fatal(got)
	}
}

// 「BLOCK された IP」はレートベースのルール・既定の action・sign-in のパス (接頭辞付き)・正規の送信元の BLOCK を除く (Go で除く)
func TestSuspectBlockedIPs(t *testing.T) {
	src := wafSource()
	src.StripPathPrefix = "/sandbox"
	c, _ := New(src, wafChecks(), &cwlogstest.Fake{})
	c.stats = &collect.FormatStats{}
	day := "2026-10-21 00:00:00.000"
	b := func(ip, rule, typ, path string) map[string]string {
		return row("day", day, "acl", "prod-waf", "action", "BLOCK", "rule", rule, "terminatingRuleType", typ, "path", path, "ip", ip, "waf_actions", "1")
	}
	blocked, err := c.emitActions(context.Background(), []map[string]string{
		b("198.51.100.1", "block-admin", "REGULAR", "/sandbox/admin"),
		b("198.51.100.2", "rate-login", "RATE_BASED", "/sandbox/api"),
		b("198.51.100.3", "Default_Action", "REGULAR", "/sandbox/x"),
		b("198.51.100.4", "block-geo", "REGULAR", "/sandbox/users/sign_in"),
		b("203.0.113.9", "block-admin", "REGULAR", "/sandbox/admin"),
		b("198.51.100.5", "block-geo", "REGULAR", "/users/sign_in"),
	}, dayCounts{}, &sinkRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for ip := range blocked["2026-10-21"] {
		got = append(got, ip)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "198.51.100.1,198.51.100.5" {
		t.Fatalf("blocked: %v", got)
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
	if !strings.HasPrefix(LinesQuery(p), want) || !strings.HasPrefix(WAFQueries(p, wafChecks())[0].Query, want) || !strings.HasPrefix(WAFRateQuery(p, wafChecks()), want) {
		t.Fatal("resources filter must be in every query")
	}
	if got := GlobRegex("a?b.c*"); got != `a.b\.c.*` {
		t.Fatal(got)
	}
}
