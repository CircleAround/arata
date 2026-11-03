package cwlogs

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

// 値の同一性のテスト (ADR 0031)。ログの行 (cwlogstest.Sim) から各クエリの結果を作り、collector が出す metrics をゴールデンで固定する。
// ゴールデンはクエリをまとめる前の collector で作った。クエリの形が変わっても、同じログからは同じ metrics が出ることを確かめる。
// filter はクエリの filter と同じ意味を Go で書く (Sim はクエリの filter を解釈しない)。

func checkGolden(t *testing.T, name string, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs (go test -run %s -update で更新し、理由を PR に書く):\n--- got\n%s", name, t.Name(), got)
	}
}

func dumpMetrics(sink *sinkRecorder, st *collect.FormatStats) string {
	m := sink.metrics()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, strconv.FormatFloat(m[k], 'f', -1, 64))
	}
	fmt.Fprintf(&b, "lines total=%d matched=%d\n", st.Total, st.Matched)
	return b.String()
}

func inCIDRs(ip string, cidrs []string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s, sp string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, sp+p) {
			return true
		}
	}
	return false
}

func intIn(s string, l []int) bool {
	for _, n := range l {
		if strconv.Itoa(n) == s {
			return true
		}
	}
	return false
}

func strIn(s string, l []string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// ---- wafv2 ----

const testACLArn = "arn:aws:wafv2:ap-northeast-1:123456789012:regional/webacl/%s/0000-1111"

func wafEquivChecks() config.Checks {
	c := wafChecks()
	c.WAFReview.TopPaths = 3
	c.ProbePaths.ExcludePaths = []string{"/.env.example"}
	return c
}

// wafEv は WAF のログ 1 行 (公式のログ例の平坦化した形)。kv は追加のフィールド。
func wafEv(day int, hour int, acl, action, rule, typ, method, uri, ip string, n int, kv ...string) cwlogstest.Event {
	f := map[string]string{
		"webaclId": fmt.Sprintf(testACLArn, acl), "action": action, "terminatingRuleId": rule, "terminatingRuleType": typ,
		"httpRequest.httpMethod": method, "httpRequest.uri": uri, "httpRequest.clientIp": ip,
	}
	for i := 0; i+1 < len(kv); i += 2 {
		f[kv[i]] = kv[i+1]
	}
	return cwlogstest.Event{Time: time.Date(2026, 10, day, hour, 0, 0, 0, time.UTC), Fields: f, N: n}
}

func wafEvents() []cwlogstest.Event {
	var ev []cwlogstest.Event
	for _, day := range []int{20, 21} {
		// 平常の通信
		ev = append(ev, wafEv(day, 1, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/", "192.0.2.200", 600),
			wafEv(day, 2, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/api/items/1", "192.0.2.201", 300),
			wafEv(day, 3, "stg-waf", "BLOCK", "AWS-AWSManagedRulesCommonRuleSet", "MANAGED_RULE_GROUP", "GET", "/x", "198.51.100.40", 5,
				"ruleGroupList.0.terminatingRule.ruleId", "NoUserAgent_HEADER"))
		// 解釈できない行 (WAF のログではない)
		ev = append(ev, cwlogstest.Event{Time: time.Date(2026, 10, day, 4, 0, 0, 0, time.UTC), Fields: map[string]string{"@message": "not a waf log"}, N: 5})
	}
	d := 21
	// 10 人が自分の /users/<id> で同じルールに止められた。前にある KnownBadInputs (グループ全体を COUNT) も terminatingRule が null でない
	for i := 1; i <= 10; i++ {
		ev = append(ev, wafEv(d, 5, "prod-waf", "BLOCK", "AWS-AWSManagedRulesCommonRuleSet", "MANAGED_RULE_GROUP", "POST", fmt.Sprintf("/users/%d", i), fmt.Sprintf("192.0.2.%d", i), 2,
			"ruleGroupList.0.terminatingRule.ruleId", "Log4JRCE_HEADER", "ruleGroupList.1.terminatingRule.ruleId", "CrossSiteScripting_BODY"))
	}
	// 1 IP が /items/<id> を 50 個列挙した
	for i := 0; i < 50; i++ {
		ev = append(ev, wafEv(d, 6, "prod-waf", "BLOCK", "block-admin", "REGULAR", "GET", fmt.Sprintf("/items/%d?q=%d", i, i), "198.51.100.7", 1,
			"ruleGroupList.0.terminatingRule.ruleId", "Log4JRCE_HEADER"))
	}
	ev = append(ev,
		// 位置の上限より後ろにグループがある
		wafEv(d, 6, "prod-waf", "BLOCK", "AWS-AWSManagedRulesCommonRuleSet", "MANAGED_RULE_GROUP", "GET", "/y", "192.0.2.99", 1,
			"ruleGroupList.7.terminatingRule.ruleId", "A", "ruleGroupList.8.ruleGroupId", "AWS#X"),
		// レート制限・既定の action・sign-in のパスでの BLOCK は「BLOCK された IP」にしない
		wafEv(d, 7, "prod-waf", "BLOCK", "rate-login", "RATE_BASED", "POST", "/api/x", "198.51.100.20", 40),
		wafEv(d, 7, "prod-waf", "BLOCK", "block-geo", "REGULAR", "POST", "/users/sign_in", "198.51.100.21", 3),
		wafEv(d, 7, "prod-waf", "BLOCK", "Default_Action", "REGULAR", "GET", "/z", "198.51.100.22", 2),
		// 正規の送信元の BLOCK (block_ip には数え、他からは外す)
		wafEv(d, 7, "prod-waf", "BLOCK", "block-admin", "REGULAR", "GET", "/admin", "203.0.113.5", 4),
		// 探索パスの BLOCK (block_path から外し、BLOCK された IP には数える)
		wafEv(d, 8, "prod-waf", "BLOCK", "block-admin", "REGULAR", "GET", "/.env", "198.51.100.8", 1),
		// 許可された探索
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/.env", "198.51.100.9", 3),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/.env?x=1", "198.51.100.10", 4),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/.env.example", "198.51.100.11", 2),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/.env", "203.0.113.6", 2),
		// カウントの一致
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/.env", "198.51.100.9", 6,
			"nonTerminatingMatchingRules.0.ruleId", "AWS-AWSManagedRulesKnownBadInputsRuleSet", "nonTerminatingMatchingRules.0.action", "COUNT"),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "POST", "/upload", "198.51.100.8", 4,
			"nonTerminatingMatchingRules.0.ruleId", "count-geo", "nonTerminatingMatchingRules.0.action", "COUNT",
			"ruleGroupList.0.ruleGroupId", "AWS#AWSManagedRulesCommonRuleSet", "ruleGroupList.0.nonTerminatingMatchingRules.0.ruleId", "SizeRestrictions_BODY",
			"ruleGroupList.0.nonTerminatingMatchingRules.0.action", "COUNT"),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "POST", "/login", "198.51.100.20", 9,
			"nonTerminatingMatchingRules.0.ruleId", "count-login", "nonTerminatingMatchingRules.0.action", "COUNT"),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/.env.example", "192.0.2.1", 2,
			"nonTerminatingMatchingRules.0.ruleId", "AWS-AWSManagedRulesKnownBadInputsRuleSet", "nonTerminatingMatchingRules.0.action", "COUNT"),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/many", "192.0.2.7", 1,
			"nonTerminatingMatchingRules.0.ruleId", "c0", "nonTerminatingMatchingRules.3.ruleId", "c3"),
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/upload", "203.0.113.7", 3,
			"nonTerminatingMatchingRules.0.ruleId", "count-geo", "nonTerminatingMatchingRules.0.action", "COUNT"),
		// Challenge / CAPTCHA
		wafEv(d, 8, "prod-waf", "CAPTCHA", "AWS-AWSManagedRulesBotControlRuleSet", "MANAGED_RULE_GROUP", "POST", "/api/cart", "198.51.100.30", 5,
			"ruleGroupList.0.terminatingRule.ruleId", "CategoryHttpLibrary"),
		wafEv(d, 8, "prod-waf", "CHALLENGE", "challenge-search", "REGULAR", "GET", "/search/1", "203.0.113.8", 1),
		// 公式の例の形: nonTerminatingMatchingRules の中に CHALLENGE がある
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/search/1", "192.0.2.1", 4,
			"nonTerminatingMatchingRules.0.ruleId", "challenge-search", "nonTerminatingMatchingRules.0.action", "CHALLENGE"),
		// フィールドの説明の形: トップレベルの challengeResponse
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/search/2", "192.0.2.2", 1, "challengeResponse.solveTimestamp", "1792990000"),
		// 期限切れ (failureReason がある) は解いたとみなさない
		wafEv(d, 8, "prod-waf", "CHALLENGE", "challenge-search", "REGULAR", "GET", "/search/3", "192.0.2.3", 1,
			"challengeResponse.solveTimestamp", "1792900000", "challengeResponse.failureReason", "TOKEN_EXPIRED"),
		// 出していない IP
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/search/9", "192.0.2.50", 1,
			"nonTerminatingMatchingRules.0.ruleId", "challenge-search", "nonTerminatingMatchingRules.0.action", "CHALLENGE"),
		// 種類が違う
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/search/3", "192.0.2.3", 1,
			"nonTerminatingMatchingRules.0.ruleId", "captcha-x", "nonTerminatingMatchingRules.0.action", "CAPTCHA"),
		// 正規の送信元のトークン
		wafEv(d, 8, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/search/1", "203.0.113.8", 1, "challengeResponse.solveTimestamp", "1792990000"),
	)
	for i := 1; i <= 3; i++ {
		ev = append(ev, wafEv(d, 8, "prod-waf", "CHALLENGE", "challenge-search", "REGULAR", "GET", fmt.Sprintf("/search/%d", i), fmt.Sprintf("192.0.2.%d", i), 2))
	}
	// 前日にも BLOCK とカウントの一致
	ev = append(ev,
		wafEv(20, 10, "prod-waf", "BLOCK", "block-admin", "REGULAR", "GET", "/admin/1", "198.51.100.50", 7),
		wafEv(20, 10, "prod-waf", "ALLOW", "Default_Action", "REGULAR", "GET", "/", "198.51.100.50", 2,
			"nonTerminatingMatchingRules.0.ruleId", "count-geo", "nonTerminatingMatchingRules.0.action", "COUNT"),
	)
	return ev
}

// wafRateResp はレート (2 段の stats。Sim では作らない) の固定の応答。
func wafRateResp() cwlogstest.Response {
	return cwlogstest.Response{Rows: []map[string]string{row("acl", "prod-waf", "grp", "/login", "waf_ip_rate_p50", "2", "waf_ip_rate_p99", "8", "waf_ip_rate_max", "300")}}
}

// wafPreds は wafv2 のクエリの filter と同じ意味の述語。
type wafPreds struct {
	c  config.Checks
	sp string
}

func (p wafPreds) trusted(f map[string]string) bool { return !inCIDRs(f["ip"], p.c.WAFReview.TrustedCIDRs) }
func (p wafPreds) probe(f map[string]string) bool {
	return hasAnyPrefix(f["path"], p.sp, p.c.ProbePaths.Paths) && !hasAnyPrefix(f["path"], p.sp, p.c.ProbePaths.ExcludePaths)
}
func (p wafPreds) block(f map[string]string) bool { return f["action"] == "BLOCK" }
func (p wafPreds) blockPath(f map[string]string) bool {
	return p.block(f) && !p.probe(f) && p.trusted(f)
}
func (p wafPreds) allowProbe(f map[string]string) bool {
	return f["action"] == "ALLOW" && p.probe(f) && p.trusted(f)
}
func (p wafPreds) suspect(f map[string]string) bool {
	var signIn []string
	for _, s := range p.c.LoginBruteforce.Paths {
		signIn = append(signIn, p.sp+s)
	}
	return p.block(f) && f["terminatingRuleType"] != "RATE_BASED" && f["rule"] != "Default_Action" && !strIn(f["path"], signIn) && p.trusted(f)
}
func (p wafPreds) countMatch(f map[string]string) bool {
	for _, k := range countFields() {
		if strings.HasSuffix(k, ".ruleId") && f[k] != "" {
			return p.trusted(f)
		}
	}
	return false
}
func (p wafPreds) issued(f map[string]string) bool {
	return (f["action"] == "CHALLENGE" || f["action"] == "CAPTCHA") && p.trusted(f)
}
func (p wafPreds) solved(f map[string]string) bool {
	ok := num(f["challengeResponse.solveTimestamp"]) > 0 || num(f["captchaResponse.solveTimestamp"]) > 0
	for _, k := range challengeAcceptedFields() {
		if f[k] == "CHALLENGE" || f[k] == "CAPTCHA" {
			ok = true
		}
	}
	return ok && p.trusted(f)
}

func runWAFEquiv(t *testing.T, register func(f *cwlogstest.Fake, sim *cwlogstest.Sim, p wafPreds)) (*sinkRecorder, *Collector, *cwlogstest.Fake) {
	t.Helper()
	sim := &cwlogstest.Sim{Events: wafEvents()}
	f := &cwlogstest.Fake{}
	register(f, sim, wafPreds{c: wafEquivChecks()})
	f.On("as waf_ip_rate_p50", wafRateResp())
	c, err := New(wafSource(), wafEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	return sink, c, f
}

// registerWAF は collector が流すクエリに Sim の応答を登録する (クエリの形ごとに filter を対応させる)。
func registerWAF(f *cwlogstest.Fake, sim *cwlogstest.Sim, p wafPreds) {
	f.On("as lines_total", sim.Response(nil))
	f.On("as waf_block_ip", sim.Response(p.block))
	f.On("as waf_rule_action", sim.Response(nil))
	f.On("as waf_block_path", sim.Response(p.blockPath))
	f.On("as waf_allow_probe", sim.Response(p.allowProbe))
	f.On("as waf_suspect_block_ip", sim.Response(p.suspect))
	f.On("as waf_rule_count_match", sim.Response(p.countMatch))
	f.On("as waf_challenge_issued", sim.Response(p.issued))
	f.On("as waf_challenge_solved", sim.Response(p.solved))
}

func TestWAFEquivalence(t *testing.T) {
	sink, c, _ := runWAFEquiv(t, registerWAF)
	if tr := c.FormatStats().Truncated; len(tr) != 0 {
		t.Fatalf("truncated: %v", tr)
	}
	checkGolden(t, "equiv_waf.golden", dumpMetrics(sink, c.FormatStats()))
}

// ---- http_access (nginx) ----

func httpEquivChecks() config.Checks {
	c := abuseChecks()
	c.ProbePaths.ExcludePaths = []string{"/.env.example"}
	return c
}

// nginxEv は nginx の combined 形式の 1 行。
func nginxEv(at time.Time, ip, method, uri string, status int, ua string, n int) cwlogstest.Event {
	msg := fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d 512 "-" "%s"`, ip, at.Format("02/Jan/2006:15:04:05 -0700"), method, uri, status, ua)
	return cwlogstest.Event{Time: at, Fields: map[string]string{"@message": msg}, N: n}
}

func httpEvents() []cwlogstest.Event {
	at := func(day, h, m, s int) time.Time { return time.Date(2026, 10, day, h, m, s, 0, time.UTC) }
	var ev []cwlogstest.Event
	for _, day := range []int{20, 21} {
		ev = append(ev, nginxEv(at(day, 0, 30, 0), "192.0.2.200", "GET", "/", 200, "Browser/1", 500),
			cwlogstest.Event{Time: at(day, 0, 31, 0), Fields: map[string]string{"@message": "garbage line"}, N: 3})
	}
	ev = append(ev,
		// sign-in の失敗
		nginxEv(at(20, 5, 0, 0), "198.51.100.7", "POST", "/users/sign_in", 401, "curl/8", 40),
		nginxEv(at(21, 5, 0, 0), "198.51.100.7", "POST", "/users/sign_in", 422, "curl/8", 12),
		nginxEv(at(21, 5, 0, 0), "198.51.100.7", "POST", "/users/sign_in?x=1", 401, "curl/8", 2),
		nginxEv(at(21, 5, 0, 0), "198.51.100.6", "POST", "/users/sign_in", 200, "curl/8", 9),
		nginxEv(at(21, 5, 0, 0), "198.51.100.6", "GET", "/users/sign_in", 401, "curl/8", 4),
		nginxEv(at(21, 5, 0, 0), "198.51.100.6", "POST", "/users/sign_in/x", 401, "curl/8", 4),
		// 探索
		nginxEv(at(21, 6, 0, 0), "198.51.100.8", "GET", "/.env", 404, "scan/1", 3),
		nginxEv(at(21, 6, 0, 0), "198.51.100.8", "GET", "/wp-login.php", 403, "scan/1", 2),
		nginxEv(at(21, 6, 0, 0), "198.51.100.9", "GET", "/.env/alice@example.com", 404, "scan/1", 1),
		nginxEv(at(21, 6, 0, 0), "198.51.100.9", "GET", "/.env", 200, "scan/1", 5),
		nginxEv(at(21, 6, 0, 0), "198.51.100.9", "GET", "/.env.example", 404, "scan/1", 5),
		nginxEv(at(20, 6, 0, 0), "198.51.100.10", "GET", "/.env.bak", 404, "scan/1", 6),
	)
	// endpoint_abuse: 03:20 の幅に 25 IP が登録 (22 IP が同じ UA)、うち 6 IP が 30 分以内にメッセージ送信
	for i := 0; i < 25; i++ {
		ua := botUA
		if i >= 22 {
			ua = fmt.Sprintf("Browser/%d", i)
		}
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		ev = append(ev, nginxEv(at(21, 3, 20, i*10), ip, "POST", "/signup", 200, ua, 1))
		if i < 6 {
			ev = append(ev, nginxEv(at(21, 3, 31, 0), ip, "POST", "/messages/"+strconv.Itoa(i), 302, ua, 1))
		}
	}
	ev = append(ev,
		nginxEv(at(21, 4, 10, 0), "203.0.113.7", "POST", "/messages", 200, botUA, 1),
		nginxEv(at(21, 4, 11, 0), "203.0.113.7", "POST", "/messages/preview", 200, botUA, 1),
		nginxEv(at(21, 4, 12, 0), "203.0.113.7", "POST", "/a/b/messages", 500, botUA, 1),
		nginxEv(at(21, 4, 12, 0), "203.0.113.7", "GET", "/signup", 200, botUA, 1),
		nginxEv(at(21, 1, 0, 0), "198.51.100.1", "POST", "/signup", 200, "-", 2),
		nginxEv(at(21, 1, 0, 5), "198.51.100.2", "POST", "/signup?ref=x", 200, "Browser/1", 1),
		nginxEv(at(20, 23, 55, 0), "198.51.100.3", "POST", "/signup", 200, "Browser/1", 1),
		nginxEv(at(21, 0, 5, 0), "198.51.100.3", "POST", "/messages/1", 200, "Browser/1", 1),
		nginxEv(at(21, 2, 0, 0), "198.51.100.4", "POST", "/x", 200, "Browser/1", 1),
	)
	return ev
}

type httpPreds struct {
	c  config.Checks
	sp string
}

func (p httpPreds) signIn(f map[string]string) bool {
	lb := p.c.LoginBruteforce
	return strIn(f["method"], lb.Methods) && strIn(f["path"], lb.Paths) && intIn(f["status"], lb.FailureStatuses)
}
func (p httpPreds) probe(f map[string]string) bool {
	pp := p.c.ProbePaths
	return intIn(f["status"], pp.Statuses) && hasAnyPrefix(f["path"], "", pp.Paths) && !hasAnyPrefix(f["path"], "", pp.ExcludePaths)
}

// endpoint は画面 ep のクエリの filter と同じ意味。
func (p httpPreds) endpoint(ep config.AbuseEndpoint) func(map[string]string) bool {
	var res []*regexp.Regexp
	for _, g := range ep.Paths {
		res = append(res, regexp.MustCompile(EndpointPathRegex(p.sp, g)))
	}
	var ex []*regexp.Regexp
	for _, g := range p.c.EndpointAbuse.ExcludePaths {
		ex = append(ex, regexp.MustCompile(EndpointPathRegex(p.sp, g)))
	}
	return func(f map[string]string) bool {
		ok := false
		for _, re := range res {
			ok = ok || re.MatchString(f["path"])
		}
		for _, re := range ex {
			if re.MatchString(f["path"]) {
				return false
			}
		}
		return ok && (len(ep.Methods) == 0 || strIn(f["method"], ep.Methods)) && (len(ep.Statuses) == 0 || intIn(f["status"], ep.Statuses))
	}
}

func registerHTTP(f *cwlogstest.Fake, sim *cwlogstest.Sim, p httpPreds) {
	f.On("as lines_total", sim.Response(nil))
	f.On("as sign_in_failures", sim.Response(p.signIn))
	f.On("as probe_hits", sim.Response(p.probe))
	f.On("as probe_paths", sim.Response(p.probe))
	for _, ep := range p.c.EndpointAbuse.Endpoints {
		if len(ep.Paths) > 0 {
			f.On(`path like /`+EndpointPathRegex(p.sp, ep.Paths[0])+`/`, sim.Response(p.endpoint(ep)))
		}
	}
}

func TestHTTPEquivalence(t *testing.T) {
	sim := &cwlogstest.Sim{Events: httpEvents()}
	f := &cwlogstest.Fake{}
	registerHTTP(f, sim, httpPreds{c: httpEquivChecks()})
	c, err := New(nginxSource(), httpEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	if tr := c.FormatStats().Truncated; len(tr) != 0 {
		t.Fatalf("truncated: %v", tr)
	}
	checkGolden(t, "equiv_http.golden", dumpMetrics(sink, c.FormatStats()))
}
