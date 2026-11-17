package cwlogs

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
)

// 一覧の IP に絞った問い合わせ (ADR 0069 の 4 節): 文は 10,000 文字まで。渡した順に詰め、収まらなければ次の組へ。
// 組は max_queries 本まで。読めない IP は文に入れない (数えない)。
func TestListedQueries(t *testing.T) {
	p, _ := ProfileFor(wafSource())
	var ips []string
	for i := 0; i < 1200; i++ {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	qs, used := ListedQueries(p, wafChecks(), ips, 2, ListedQueryLen)
	if len(qs) != 2 || used < 800 || used >= 1200 {
		t.Fatalf("queries %d, used %d", len(qs), used)
	}
	n := 0
	for _, q := range qs {
		if len(q) > ListedQueryLen {
			t.Errorf("query is %d chars", len(q))
		}
		n += strings.Count(q, `"10.0.`)
	}
	if n != used {
		t.Errorf("IPs in queries %d, used %d", n, used)
	}
	// 渡した順に詰める (上位から)
	if !strings.Contains(qs[0], `["10.0.0.0", "10.0.0.1",`) {
		t.Errorf("first query: %s", qs[0][:200])
	}
	// 1 本に収まれば 1 本
	if qs, used := ListedQueries(p, wafChecks(), ips[:10], 2, ListedQueryLen); len(qs) != 1 || used != 10 {
		t.Errorf("small list: %d queries, used %d", len(qs), used)
	}
	if qs, used := ListedQueries(p, wafChecks(), nil, 2, ListedQueryLen); len(qs) != 0 || used != 0 {
		t.Errorf("empty list: %d queries, used %d", len(qs), used)
	}
	// 読めない値は入れない
	qs, used = ListedQueries(p, wafChecks(), []string{`1"] | filter 1=1 | ["`, "2001:DB8::1"}, 2, ListedQueryLen)
	if used != 1 || !strings.Contains(qs[0], `in ["2001:db8::1"]`) || strings.Contains(qs[0], "1=1") {
		t.Errorf("used %d: %s", used, qs)
	}
}

// 結果の行の振り分け: カウントのルールごとに足す。探索パスの行は数えない ((i) で数え済み)。除外のパスは数える。
func TestCollectListed(t *testing.T) {
	f := &cwlogstest.Fake{}
	day := "2026-10-21 00:00:00.000"
	const cr = "nonTerminatingMatchingRules.0.ruleId"
	f.On("as waf_listed", cwlogstest.Response{Rows: []map[string]string{
		row("day", day, "acl", "prod-waf", cr, "count-geo", "waf_listed", "4"),
		row("day", day, "acl", "prod-waf", cr, "count-geo", "ruleGroupList.0.ruleGroupId", "AWS#X", "ruleGroupList.0.nonTerminatingMatchingRules.0.ruleId", "Size", "waf_listed", "2"),
		row("day", day, "acl", "prod-waf", cr, "count-sqli", "probe", "/.env", "waf_listed", "9"),
		row("day", day, "acl", "prod-waf", cr, "count-sqli", "probe", "/.env", "probe_ex", "/.env.example", "waf_listed", "3"),
	}})
	c, _ := New(wafSource(), wafChecks(), f)
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	d := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	got, used, err := c.CollectListed(context.Background(), d, []string{"198.51.100.8", "198.51.100.9"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"prod-waf|count-geo": 6, "prod-waf|AWS#X/Size": 2, "prod-waf|count-sqli": 3}
	if fmt.Sprint(got) != fmt.Sprint(want) || used != 2 {
		t.Fatalf("listed = %v (used %d), want %v", got, used, want)
	}
	s := f.Started[0]
	if *s.StartTime != d.Unix() || *s.EndTime != d.Add(24*time.Hour).Unix()-1 {
		t.Errorf("range %d..%d", *s.StartTime, *s.EndTime)
	}
}

// 突き合わせ (ADR 0069 の「確かめ方」): その日の BLOCK の IP (waf_block_ip_suspect) を一覧として全部渡すと、
// (i) の suspect + listed は、ADR 0067 の前の suspect (その日 BLOCK された IP からの一致。#119 の前の equiv_waf.golden) と同じ値になる。
func TestListedEquivalence(t *testing.T) {
	sim := &cwlogstest.Sim{Events: wafEvents()}
	f := &cwlogstest.Fake{}
	p := wafPreds{c: wafEquivChecks()}
	registerWAF(f, sim, p)
	f.On("as waf_ip_rate_p50", wafRateResp())
	// 一覧の問い合わせの、IP の並び以外の filter: BLOCK でなく、カウントのルールに一致し、正規の送信元でない
	f.On("as waf_listed", sim.Response(func(r map[string]string) bool { return r["action"] != "BLOCK" && p.countMatch(r) }))
	c, err := New(wafSource(), wafEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.IPList = true
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	got := map[string]float64{}
	for _, d := range []int{20, 21} {
		date := fmt.Sprintf("2026-10-%d", d)
		var ips []string
		for k := range m {
			if ip, ok := strings.CutPrefix(k, date+"|"+MetricWAFBlockIPSuspect+"|"); ok {
				ips = append(ips, ip)
			}
		}
		listed, used, err := c.CollectListed(context.Background(), time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC), ips, 2)
		if err != nil || used != len(ips) {
			t.Fatalf("%s: %v (used %d of %d)", date, err, used, len(ips))
		}
		for k, v := range m {
			// 0 件の行は前の版が出していなかった (値の比べ方としては同じ)
			if key, ok := strings.CutPrefix(k, date+"|"+MetricWAFCountMatchSuspect+"|"); ok && v+listed[key] > 0 {
				got[date+"|"+key] = v + listed[key]
			}
		}
	}
	want := map[string]float64{
		"2026-10-20|prod-waf|count-geo":                                              2,
		"2026-10-21|prod-waf|AWS#AWSManagedRulesCommonRuleSet/SizeRestrictions_BODY": 4,
		"2026-10-21|prod-waf|AWS-AWSManagedRulesKnownBadInputsRuleSet":               8,
		"2026-10-21|prod-waf|c0":                                                     1,
		"2026-10-21|prod-waf|captcha-x":                                              1,
		"2026-10-21|prod-waf|challenge-search":                                       4,
		"2026-10-21|prod-waf|count-geo":                                              4,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("suspect + listed =\n%v\nwant (before ADR 0067)\n%v", got, want)
	}
}

// FuzzListedQueries: 一覧の IP はストアから読む値 (書き換えられていても信用しない。ADR 0041)。
// 守る規則: どの入力でも、文は 10,000 文字以内で、IP の並びの外は固定の部品と同じ。並びの要素はすべて `"<正規の形の IP>"`。数えた IP の数と要素の数が同じ。
func FuzzListedQueries(f *testing.F) {
	for _, s := range []string{"198.51.100.7", "2001:DB8::1", `1"] | filter 1=1 | ["`, "fe80::1%eth0", "::ffff:203.0.113.5", ""} {
		f.Add(s, s, 3)
	}
	p, _ := ProfileFor(wafSource())
	head, tail := listedParts(p, wafChecks())
	f.Fuzz(func(t *testing.T, a, b string, n int) {
		ips := []string{a, b}
		for i := 0; i < n%600; i++ {
			ips = append(ips, a, fmt.Sprintf("2001:db8::%x", i))
		}
		qs, used := ListedQueries(p, wafChecks(), ips, 2, ListedQueryLen)
		elems := 0
		for _, q := range qs {
			if len(q) > ListedQueryLen || !strings.HasPrefix(q, head) || !strings.HasSuffix(q, tail) {
				t.Fatalf("query shape (%d chars): %q", len(q), q)
			}
			for _, lit := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(q, head), tail), ", ") {
				ip, ok := strings.CutPrefix(lit, `"`)
				ip, ok2 := strings.CutSuffix(ip, `"`)
				a, err := netip.ParseAddr(ip)
				if !ok || !ok2 || err != nil || a.Unmap().String() != ip {
					t.Fatalf("element %q is not a canonical IP", lit)
				}
				elems++
			}
		}
		if elems != used || len(qs) > 2 {
			t.Fatalf("elements %d, used %d, queries %d", elems, used, len(qs))
		}
	})
}

// listed を流してよい日 (ADR 0069 の 4 節。実データで直した): 時の単位で読むソースでは、その日の部分の行が 24 時間分そろった日だけ。
// そろっていない日 (読んでいない・部分の行が消えた) に「流した日の印」を書くと、後でその日を集めても listed が流れない。
func TestHourlyDayComplete(t *testing.T) {
	src := wafSource()
	src.Collect = config.CollectHourlyMode
	c, _ := New(src, wafChecks(), &cwlogstest.Fake{})
	parts := &memParts{}
	c.Parts = parts
	d := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for h := 0; h < 23; h++ {
		_ = parts.PutParts(context.Background(), "waf", wafLines, d.Add(time.Duration(h)*time.Hour), nil, 0)
	}
	if ok, err := c.HourlyDayComplete(context.Background(), d); ok || err != nil {
		t.Fatalf("23 hours: %v %v", ok, err)
	}
	_ = parts.PutParts(context.Background(), "waf", wafLines, d.Add(23*time.Hour), nil, 0)
	if ok, err := c.HourlyDayComplete(context.Background(), d); !ok || err != nil {
		t.Fatalf("24 hours: %v %v", ok, err)
	}
	if ok, _ := c.HourlyDayComplete(context.Background(), d.AddDate(0, 0, -1)); ok {
		t.Fatal("a day with no parts is not complete")
	}
}

// 文の長さ (実データで直した): 10,000 文字より短い文 (9,988〜9,993 バイト) が「10,000 以下であること」で断られることがあった。
// 上限まで詰めず ListedQueryLen (9,000) に収め、長さ・形の理由 (QUERY_INVALID) で断られたら、ListedRetryLen (8,000) に短くして 1 度だけ流し直す。
func TestCollectListedRetriesShorter(t *testing.T) {
	var ips []string
	for i := 0; i < 1200; i++ {
		ips = append(ips, fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	d := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for name, times := range map[string]int{"once": 1, "twice": 2} {
		t.Run(name, func(t *testing.T) {
			f := &cwlogstest.Fake{}
			f.On("as waf_listed", cwlogstest.Response{StartErr: cwlogstest.APIError{Code: "InvalidParameterException", Message: "Query string must be less than or equal to 10000"}, StartErrTimes: times})
			c, _ := New(wafSource(), wafChecks(), f)
			c.Sleep = func(context.Context, time.Duration) error { return nil }
			_, used, err := c.CollectListed(context.Background(), d, ips, 2)
			if times == 2 {
				if err == nil {
					t.Fatal("must fail after one retry")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			qs := f.Queries()
			// 偽の API は断った StartQuery を Started に残さない。流し直した 2 本だけが残る
			if len(qs) != 2 || len(qs[0]) > ListedRetryLen || len(qs[1]) > ListedRetryLen {
				t.Fatalf("queries: %d", len(qs))
			}
			if _, want := ListedQueries(c.prof, c.checks, ips, 2, ListedRetryLen); used != want {
				t.Errorf("used %d, want %d (the shorter queries)", used, want)
			}
		})
	}
}
