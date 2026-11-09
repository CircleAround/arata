package cwlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/record"
)

// ファズテスト (ADR 0041)。ログの行と Insights の結果は攻撃者が書ける値 (パス・X-Forwarded-For・User-Agent・JSON の項目) を含む。
// パニックしないことと、伏せ字・正規化・クエリへの埋め込みの規則が入力に依らず成り立つことを確かめる。

// fuzzEmail は架空のメールアドレス。入力のどこに置いても、出力に元の形で残ってはいけない。
const fuzzEmail = "alice@example.com"

func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{"/users/123/edit", "/orders/550e8400-e29b-41d4-a716-446655440000", "/search?q=alice@example.com", "/a/b#frag", "/v2/items/42/", "/", "",
		"/mail/alice@example.com", "/mail/alice%40example.com", "/sandbox/users/1", "//", "/a\n/b", "/\xff/1", "?", "#"} {
		f.Add("/sandbox", s)
	}
	f.Fuzz(func(t *testing.T, prefix, p string) {
		got := NormalizePath(p)
		if got == "" || strings.ContainsAny(got, "?#") {
			t.Fatalf("NormalizePath(%q) = %q: 空か、クエリ・フラグメントが残った", p, got)
		}
		if Mask(got) != got {
			t.Fatalf("NormalizePath(%q) = %q: メールアドレスの形が残った", p, got)
		}
		if again := NormalizePath(got); again != got {
			t.Fatalf("NormalizePath が冪等でない: %q → %q → %q", p, got, again)
		}
		// パスのどこにメールアドレスがあっても伏せる (クエリの中なら落ちる)
		for _, with := range []string{p + "/" + fuzzEmail, fuzzEmail + p, p + "/alice%40example.com/x"} {
			if out := NormalizePath(with); strings.Contains(out, fuzzEmail) || strings.Contains(out, "alice%40example.com") {
				t.Fatalf("NormalizePath(%q) = %q: メールアドレスが残った", with, out)
			}
		}
		// 接頭辞を外した結果は、元のパスか、その後ろの部分か、"/"
		if s := StripPrefix(prefix, p); s != p && s != "/" && !(strings.HasSuffix(p, s) && strings.HasPrefix(p, prefix)) {
			t.Fatalf("StripPrefix(%q, %q) = %q", prefix, p, s)
		}
	})
}

func FuzzMaskSample(f *testing.F) {
	for _, s := range []string{`{"msg":"login","email":"alice@example.com"}`, `203.0.113.1 - - [21/Oct/2026:09:00:00 +0000] "GET /mail/alice%40example.com HTTP/1.1" 200 12`,
		strings.Repeat("あ", 199) + fuzzEmail, strings.Repeat("a", 190) + "@example.com", "\xff@\xfe.co", "\x1b[2J\x1b]0;title\x07 GET /\r\n偽の行\u202e", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := MaskSample(s)
		if n := utf8.RuneCountInString(got); n > SampleMaxLen+1 {
			t.Fatalf("MaskSample が %d 文字: %q", n, got)
		}
		// 切った境目でメールアドレスの一部が新しく伏せ字の対象になることはあっても、形が残ることは無い
		if Mask(got) != got {
			t.Fatalf("MaskSample(%q) = %q: メールアドレスの形が残った", s, got)
		}
		if out := MaskSample(fuzzEmail + " " + s); strings.Contains(out, fuzzEmail) {
			t.Fatalf("先頭のメールアドレスが残った: %q", out)
		}
		// サンプル行は doctor が端末に出す。ログの行のエスケープシーケンスや改行で、端末を操作したり偽の行を作ったりさせない
		for _, r := range got {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
				t.Fatalf("MaskSample(%q) = %q: 制御文字 %U が残った", s, got, r)
			}
		}
		// ゼロ幅の文字を挟んだメールアドレスも伏せる
		if out := MaskSample("alice\u200b@exam\u200bple.com " + s); strings.Contains(out, "@example.com") && !strings.Contains(MaskSample(s), "@example.com") {
			t.Fatalf("ゼロ幅の文字を挟んだメールアドレスが残った: %q", out)
		}
	})
}

// unescapedSlash は Insights の /.../ を途中で閉じる、エスケープされていない / があるか。
func unescapedSlash(re string) bool {
	escaped := false
	for _, r := range re {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '/':
			return true
		}
	}
	return false
}

// 設定の値 (glob・接頭辞・正規表現・CIDR) を Insights のクエリに埋め込む部品。どんな文字列でもリテラルを抜け出さない。
func FuzzQueryLiterals(f *testing.F) {
	for _, s := range [][2]string{{"", "/signup"}, {"/sandbox", "/messages/*"}, {"", "/**/messages"}, {"", "/users/:id/edit"}, {"", "/v1/a*b"}, {"/a/b", "/x/123"},
		{"", `/a\/b`}, {"", `/a"b`}, {"", "/a/ | delete"}, {"", "/(?P<x>a)/"}, {"", `\`}, {"", "/[a-z]+$"}, {"/\xff", "/\xfe"}, {"", ""}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, prefix, s string) {
		for name, re := range map[string]string{
			"regexLiteral": regexLiteral(s), "GlobRegex": GlobRegex(s), "insightsRegex": insightsRegex(s), "EndpointPathRegex": EndpointPathRegex(prefix, s),
		} {
			if unescapedSlash(re) {
				t.Fatalf("%s(%q) = %q: エスケープされていない / がある", name, s, re)
			}
		}
		lit := stringLiteral(s)
		inner := strings.TrimSuffix(strings.TrimPrefix(lit, `"`), `"`)
		if len(lit) < 2 || len(inner) != len(lit)-2 || strings.Contains(strings.NewReplacer(`\\`, "", `\"`, "").Replace(inner), `"`) {
			t.Fatalf("stringLiteral(%q) = %q: 文字列リテラルを抜け出せる", s, lit)
		}
		if ref := fieldRef(s); strings.Count(ref, "`") != 0 && (strings.Count(ref, "`") != 2 || !strings.HasPrefix(ref, "`") || !strings.HasSuffix(ref, "`")) {
			t.Fatalf("fieldRef(%q) = %q: バッククォートを抜け出せる", s, ref)
		}
		if !utf8.ValidString(prefix) || !utf8.ValidString(s) {
			return
		}
		// 文字どおりの表現は Go の regexp でも同じ文字列だけに一致する (Insights の filter と Go 側の振り分けが同じ意味。ADR 0031)
		lre, err := regexp.Compile("^" + regexLiteral(s) + "$")
		if err != nil || !lre.MatchString(s) {
			t.Fatalf("regexLiteral(%q) = %q: 自分自身に一致しない (%v)", s, regexLiteral(s), err)
		}
		for name, re := range map[string]string{"GlobRegex": GlobRegex(s), "EndpointPathRegex": EndpointPathRegex(prefix, s)} {
			if _, err := regexp.Compile(re); err != nil {
				t.Fatalf("%s(%q) = %q: 正規表現として読めない: %v", name, s, re, err)
			}
		}
		// 接頭辞の無いパス・別の接頭辞のパスには一致しない (strip_path_prefix は必須で付く)
		if prefix != "" && strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "*") {
			if regexp.MustCompile(EndpointPathRegex(prefix, s)).MatchString(s) && !strings.HasPrefix(s, prefix) {
				t.Fatalf("EndpointPathRegex(%q, %q) が接頭辞の無いパスに一致した", prefix, s)
			}
		}
	})
}

func FuzzParseValues(f *testing.F) {
	for _, s := range []string{"2026-10-21 00:00:00.000", "2026-10-21 03:20:00", "2026-10-21T03:20:00.123456789+09:00", "2026-10-21", "0000-00-00", "9999-12-31 23:59:59.999",
		"987", "1.5e3", "-1", "0x10", "1_000", "NaN", "Inf", "-Inf", "1e999", " 12 ", "404", "401 ", "203.0.113.7", "::ffff:203.0.113.7", "fe80::1%eth0", "203.0.113.0/24", ""} {
		f.Add(s)
	}
	cidrs := parseCIDRs([]string{"203.0.113.0/24", "2001:db8::/32", "not-a-cidr"})
	f.Fuzz(func(t *testing.T, s string) {
		if tm, ok := parseTime(s); ok && (tm.Location() != time.UTC || tm.IsZero() && !strings.HasPrefix(s, "0001")) {
			t.Fatalf("parseTime(%q) = %v", s, tm)
		}
		if day, ok := parseDay(s); ok {
			if _, err := time.Parse(record.DateLayout, day); err != nil {
				t.Fatalf("parseDay(%q) = %q: 日付でない", s, day)
			}
		}
		// 件数は metric の値になり、JSON と SQLite に入る。NaN・無限大・負の値は件数ではない
		if n := num(s); math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
			t.Fatalf("num(%q) = %v", s, n)
		}
		statusIn(s, []int{401, 404})
		if inCIDRs(s, cidrs) && !strings.HasPrefix(s, "203.0.113.") && !strings.HasPrefix(strings.ToLower(s), "2001:db8:") && !strings.Contains(s, "203.0.113.") && !strings.Contains(strings.ToLower(s), "cb00:71") {
			t.Fatalf("inCIDRs(%q) が範囲の外の値を通した", s)
		}
		parseCIDRs([]string{s})
	})
}

// checkRecords は collector が出した record を確かめる。JSON にできる (NaN などが無い)、値が有限で負でない、
// 攻撃者が書ける値 (パス・IP・User-Agent) に入れたメールアドレスと User-Agent の原文が残っていない。
func checkRecords(t *testing.T, recs []record.Record, secrets ...string) {
	t.Helper()
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("record を JSON にできない: %v: %+v", err, r)
		}
		if m, ok := r.(record.Metric); ok {
			if math.IsNaN(m.Value) || math.IsInf(m.Value, 0) || m.Value < 0 {
				t.Fatalf("metric の値が件数でない: %+v", m)
			}
			if _, err := time.Parse(record.DateLayout, m.Date); err != nil {
				t.Fatalf("metric の日付が不正: %+v", m)
			}
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(string(b), s) {
				t.Fatalf("record に %q が残った: %s", s, b)
			}
		}
	}
}

// fuzzUA は User-Agent の原文の印 (metrics にはハッシュだけを残す)。
const fuzzUA = "EvilBot-Fuzz-UA"

// nginx のアクセスログの集計結果 (Insights の行) の値を任意の文字列にして、収集の全体を通す。実 AWS には接続しない (cwlogstest.Fake)。
func FuzzCollectHTTPRows(f *testing.F) {
	f.Add("2026-10-21 00:00:00.000", "/.env", "198.51.100.7", "404", "3", "2026-10-21 03:20:00.000", "POST")
	f.Add("2026-10-20 00:00:00.000", "/users/sign_in", "198.51.100.7, 203.0.113.9", "401", "40", "2026-10-21 03:20:00", "POST")
	f.Add("2026-10-21", "/wp-login.php?u=alice@example.com", "::1", "422", "1e3", "2026-10-21T03:25:00Z", "GET")
	f.Add("x", "\n", "", "", "NaN", "", "")
	f.Add("2026-10-21 00:00:00.000", "/a", "a|b", " 404", "-5", "0001-01-01 00:00:00", "POST")
	f.Fuzz(func(t *testing.T, day, path, ip, status, n, bin, method string) {
		ipv, pathv := ip+fuzzEmail, path+"/"+fuzzEmail
		fake := &cwlogstest.Fake{}
		fake.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "status", "200", "lines_total", "1000", "lines_matched", "1000"),
			cwlogstest.Rows("day", day, "status", status, "probe_path", pathv, "lines_total", n, "lines_matched", n),
		}})
		fake.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("day", day, "ip", ipv, "method", method, "status", status, "sign_in", pathv, "probe", pathv, "http_hits", n),
			cwlogstest.Rows("day", day, "ip", ipv, "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", n),
			cwlogstest.Rows("day", day, "ip", ipv, "method", "GET", "status", "404", "probe", "/.env", "probe_ex", path, "http_hits", n),
		}})
		var hits []map[string]string
		for i := 0; i < 6; i++ {
			for _, flag := range []string{"ep0_0", "ep1_0"} {
				hits = append(hits, cwlogstest.Rows("t", bin, "ip", fmt.Sprintf("%s%d", ipv, i), "ua", fuzzUA+path, "method", "POST", "status", "200", flag, pathv,
					endpointHits, n, "first_seen", bin, "last_seen", day))
			}
		}
		hits = append(hits, cwlogstest.Rows("t", bin, "ip", ipv, "ua", fuzzUA, "method", method, "status", status, "ep0_0", pathv, endpointHits, n, "first_seen", day, "last_seen", bin))
		fake.On(endpointHits, cwlogstest.Response{Rows: hits})
		c, err := New(nginxSource(), abuseChecks(), fake)
		if err != nil {
			t.Fatal(err)
		}
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		sink := &sinkRecorder{}
		if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		checkRecords(t, sink.recs, fuzzEmail, fuzzUA)
	})
}

// WAF のログの集計結果の値を任意の文字列にして、収集の全体を通す。
func FuzzCollectWAFRows(f *testing.F) {
	f.Add("2026-10-21 00:00:00.000", "/.env", "198.51.100.7", "BLOCK", "3", "GET", "AWS-AWSManagedRulesCommonRuleSet")
	f.Add("2026-10-21 00:00:00.000", "/posts/123?x=1", "203.0.113.9", "CHALLENGE", "40", "POST", "challenge-all")
	f.Add("2026-10-20", "/users/sign_in", "::ffff:203.0.113.9", "CAPTCHA", "1e3", "POST", "Default_Action")
	f.Add("2026-10-21 00:00:00.000", "/login", "x", "ALLOW", "NaN", "", "")
	f.Add("x", "", "", "COUNT", "-1", "\n", "a|b")
	f.Fuzz(func(t *testing.T, day, path, ip, action, n, method, rule string) {
		ipv, pathv := ip+fuzzEmail, path+"/"+fuzzEmail
		fake := &cwlogstest.Fake{}
		fake.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "acl", "prod-waf", "rule", "r", "action", "ALLOW", "lines_total", "1000", "lines_matched", "1000"),
			cwlogstest.Rows("day", day, "acl", "prod-waf", "rule", "block-rule", "action", action, "lines_total", n, "lines_matched", n),
			cwlogstest.Rows("day", day, "acl", "prod-waf", "rule", "block-rule", "action", "BLOCK", "lines_total", n, "lines_matched", n),
		}})
		var rows []map[string]string
		for _, a := range []string{action, "BLOCK", "ALLOW", "CHALLENGE", "CAPTCHA"} {
			for _, p := range []string{pathv, "/.env/" + pathv, "/users/sign_in"} {
				rows = append(rows, cwlogstest.Rows("day", day, "acl", "prod-waf", "rule", "block-rule", "action", a, "terminatingRuleType", rule, "path", p, "ip", ipv, "method", "GET",
					wafActions, n, "challengeResponse.solveTimestamp", n, "captchaResponse.solveTimestamp", action,
					"ruleGroupList.0.terminatingRule.ruleId", "inner", "ruleGroupList.0.ruleGroupId", "grp", groupSentinel, method))
			}
		}
		fake.On("as waf_actions", cwlogstest.Response{Rows: rows})
		fake.On("as waf_rule_count_match", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("day", day, "acl", "prod-waf", "ip", ipv, "probe", path, "probe_ex", method, MetricWAFCountMatch, n, topSentinel, method, groupSentinel, action,
				"nonTerminatingMatchingRules.0.ruleId", "count-geo", "nonTerminatingMatchingRules.1.ruleId", "count-geo",
				"ruleGroupList.0.ruleGroupId", "grp", "ruleGroupList.0.nonTerminatingMatchingRules.0.ruleId", "inner"),
		}})
		fake.On("as waf_ip_rate_p50", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("acl", "prod-waf", "grp", "/api/", MetricWAFIPRateP50, n, MetricWAFIPRateP99, action, MetricWAFIPRateMax, day),
		}})
		c, err := New(wafSource(), wafChecks(), fake)
		if err != nil {
			t.Fatal(err)
		}
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		sink := &sinkRecorder{}
		if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		checkRecords(t, sink.recs, fuzzEmail)
	})
}

// 解釈できなかった行の例 (doctor と FORMAT_MISMATCH の details に出る) は、伏せてから切る。
func FuzzMismatchSamples(f *testing.F) {
	f.Add(`{"msg":"login","email":"alice@example.com"}`)
	f.Add(strings.Repeat("x", 195) + " alice@example.com")
	f.Add("\x1b[31malice%40example.com\x1b[0m")
	f.Fuzz(func(t *testing.T, msg string) {
		fake := &cwlogstest.Fake{}
		fake.On("as lines_total", linesResp("2026-10-21", "100", "12"))
		fake.On("ispresent", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("@message", msg), cwlogstest.Rows("@message", fuzzEmail+msg)}})
		c, err := New(nginxSource(), checksCfg(), fake)
		if err != nil {
			t.Fatal(err)
		}
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		err = c.Collect(context.Background(), collect.Window{From: now.Add(-time.Hour), To: now}, &sinkRecorder{})
		ce, ok := err.(*collect.Error)
		if !ok || ce.Code != collect.CodeFormatMismatch {
			t.Fatalf("FORMAT_MISMATCH にならない: %v", err)
		}
		b, err := json.Marshal(ce.Details)
		if err != nil {
			t.Fatalf("details を JSON にできない: %v", err)
		}
		for _, s := range ce.Details["samples"].([]string) {
			if Mask(s) != s || utf8.RuneCountInString(s) > SampleMaxLen+1 {
				t.Fatalf("サンプル行が伏せられていないか長い: %q", s)
			}
		}
		if strings.Contains(string(b), fuzzEmail) {
			t.Fatalf("details にメールアドレスが残った: %s", b)
		}
	})
}
