package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/store"
)

const ipListConfig = `ip_list:
  reasons:
    probe: {}
    sign_in_failure: {}
`

// 怪しい IP の一覧 (ADR 0069): 収集が成功した cloudwatch-logs のソースについて、読んだ日の一覧を日の値から作り直す。
// ip_list: が無ければ作らない。作り直しは置き換え (同じ日を 2 回読んでも行が同じ)。
func TestRunBuildsIPList(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprint(on), func(t *testing.T) {
			extra := ""
			if on {
				extra = ipListConfig
			}
			h := newHarnessWith(t, nginxSource, extra)
			ctx := context.Background()
			h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 950))
			h.logs.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
				cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "30"),
				cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.8", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "3"),
			}})
			e := h.open(t)
			for i := 0; i < 2; i++ {
				if _, err := e.Run(ctx, "daily"); err != nil {
					t.Fatal(err)
				}
				h.now = h.now.Add(1)
			}
			rows, err := e.Store().IPListDays(ctx, "", "")
			if err != nil {
				t.Fatal(err)
			}
			want := []store.IPListRow{{Date: "2026-10-21", Source: "web", Reason: "sign_in_failure", IP: "198.51.100.7", Count: 30}}
			if !on {
				want = nil
			}
			if fmt.Sprint(rows) != fmt.Sprint(want) {
				t.Fatalf("rows = %+v, want %+v", rows, want)
			}
			last, _ := e.Store().RecentRuns(ctx, 1)
			st, ok := last[0].Stats["ip_list"].(map[string]any)
			if ok != on {
				t.Fatalf("stats: %+v", last[0].Stats)
			}
			if on && (st["sign_in_failure"] != float64(1) || st["sign_in_by_day"] != float64(1)) {
				t.Errorf("ip_list stats: %+v", st)
			}
		})
	}
}

const listedConfig = `ip_list:
  reasons:
    waf_block: {}
  count_suspect: {}
`

// count_rule_status の listed (ADR 0069 の 4 節): 確定した UTC の日ごとに 1 回、一覧の IP に絞った問い合わせを流し、
// 一致の件数と、渡した IP の数・割合を日の値に残す。流した日は次の run で流し直さない。一覧が空の日は問い合わせない。
func TestRunListed(t *testing.T) {
	h := newHarnessWith(t, wafSources, listedConfig)
	day := "2026-10-20 00:00:00.000"
	h.logs.On("as lines_total", linesRows("2026-10-20", 1000, 1000))
	h.logs.On("as waf_actions", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", day, "acl", "prod-waf", "action", "BLOCK", "rule", "block-admin", "terminatingRuleType", "REGULAR", "path", "/admin", "method", "GET", "ip", "198.51.100.7", "waf_actions", "5"),
		cwlogstest.Rows("day", day, "acl", "prod-waf", "action", "BLOCK", "rule", "rate-login", "terminatingRuleType", "RATE_BASED", "path", "/api", "method", "POST", "ip", "198.51.100.8", "waf_actions", "50"),
	}})
	h.logs.On("as waf_listed", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", day, "acl", "prod-waf", "nonTerminatingMatchingRules.0.ruleId", "count-geo", "waf_listed", "3"),
	}})
	e := h.open(t)
	ctx := context.Background()
	listedQueries := func() []string {
		var out []string
		for _, s := range h.logs.Started {
			if q := *s.QueryString; strings.Contains(q, "as waf_listed") {
				out = append(out, time.Unix(*s.StartTime, 0).UTC().Format("2006-01-02")+" "+q)
			}
		}
		return out
	}
	for i := 0; i < 2; i++ {
		if res, err := e.Run(ctx, "daily"); err != nil || res.Exit != ExitOK {
			t.Fatalf("daily: %v %+v", err, res)
		}
		h.now = h.now.Add(time.Hour)
	}
	// 窓 [10-20 09:00, 10-21 09:00) を 10-20 の 0 時から読み、確定した日は 10-20。10-19 はこの run で読んでいないので流さない (印も書かない)。
	// 2 回目の run は流し直さない
	qs := listedQueries()
	if len(qs) != 1 || !strings.HasPrefix(qs[0], "2026-10-20 ") || !strings.Contains(qs[0], `filter ip in ["198.51.100.7"]`) {
		t.Fatalf("listed queries: %v", qs)
	}
	got := map[string]float64{}
	for _, m := range []string{cwlogs.MetricWAFCountMatchListed, cwlogs.MetricWAFListedIPsTotal, cwlogs.MetricWAFListedIPsQueried, cwlogs.MetricWAFListedBlockShare, cwlogs.MetricWAFListedCoverageLow} {
		ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: m})
		for _, x := range ms {
			got[x.Date+"|"+x.Metric+"|"+x.Key] = x.Value
		}
	}
	want := map[string]float64{
		"2026-10-20|waf_rule_count_match_listed|prod-waf|count-geo": 3,
		"2026-10-20|waf_listed_ips_total|":                          1,
		"2026-10-20|waf_listed_ips_queried|":                        1,
		"2026-10-20|waf_listed_block_share|":                        1,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("metrics =\n%v\nwant\n%v", got, want)
	}
}

// collect --window で過去を足すときは、読んだ範囲の確定した日の全部について listed を流す (定時の run は直近 2 日だけ)。
func TestCollectListedWholeWindow(t *testing.T) {
	h := newHarnessWith(t, wafSources, listedConfig)
	h.logs.On("as lines_total", linesRows("2026-10-20", 1000, 1000))
	var rows []map[string]string
	for _, d := range []string{"2026-10-16", "2026-10-18", "2026-10-20"} {
		rows = append(rows, cwlogstest.Rows("day", d+" 00:00:00.000", "acl", "prod-waf", "action", "BLOCK", "rule", "block-admin", "terminatingRuleType", "REGULAR", "path", "/admin", "method", "GET", "ip", "198.51.100.7", "waf_actions", "5"))
	}
	h.logs.On("as waf_actions", cwlogstest.Response{Rows: rows})
	h.logs.On("as waf_listed", cwlogstest.Response{})
	e := h.open(t)
	if _, err := e.CollectOnly(context.Background(), 5*24*time.Hour, []string{"waf"}); err != nil {
		t.Fatal(err)
	}
	ms, _ := e.Store().Metrics(context.Background(), store.MetricFilter{Metric: cwlogs.MetricWAFListedIPsTotal})
	var got []string
	for _, m := range ms {
		got = append(got, fmt.Sprintf("%s=%g", m.Date, m.Value))
	}
	// 窓 [10-16 09:00, 10-21 09:00) を 10-16 の 0 時から読み、確定した 10-16〜10-20 を流す。一覧は N (7 日) の中のアクティブな IP
	if strings.Join(got, ",") != "2026-10-16=1,2026-10-17=1,2026-10-18=1,2026-10-19=1,2026-10-20=1" {
		t.Fatalf("listed days: %v", got)
	}
}

// 時の単位で読むソースを、部分の行を残す日数 (3 日) より長い範囲で 1 回に集めても、前の日の値と一覧が作られ、
// 部分の行が 24 時間分そろった日に listed を流す (実データで 8 日を 1 回で集めて、前の日の値が空になり、空の一覧の印が書かれた)。
func TestCollectListedHourlyLongWindow(t *testing.T) {
	h := newHarnessWith(t, strings.Replace(wafSources, "    format: wafv2\n", "    format: wafv2\n    collect: hourly\n    max_collect: 200h\n", 1), listedConfig)
	hourRows := func(in *cwl.StartQueryInput, kv ...string) []map[string]string {
		at := time.Unix(*in.StartTime, 0).UTC()
		return []map[string]string{cwlogstest.Rows(append([]string{"day", at.Format("2006-01-02 15:00:00.000")}, kv...)...)}
	}
	h.logs.On("as lines_total", cwlogstest.Response{RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
		return hourRows(in, "acl", "prod-waf", "rule", "Default_Action", "action", "ALLOW", "lines_total", "10", "lines_matched", "10")
	}})
	h.logs.On("as waf_actions", cwlogstest.Response{RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
		if time.Unix(*in.StartTime, 0).UTC().Hour() != 3 || !strings.Contains(*in.QueryString, `action = "BLOCK" or`) {
			return nil
		}
		return hourRows(in, "acl", "prod-waf", "action", "BLOCK", "rule", "block-admin", "terminatingRuleType", "REGULAR", "path", "/admin", "method", "GET",
			"ip", "198.51.100.7", "waf_actions", "5")
	}})
	h.logs.On("as waf_listed", cwlogstest.Response{})
	e := h.open(t)
	ctx := context.Background()
	if _, err := e.CollectOnly(ctx, 6*24*time.Hour, []string{"waf"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := e.Store().IPListDays(ctx, "", "")
	var days []string
	for _, r := range rows {
		days = append(days, r.Date)
	}
	// 窓 [10-15 09:00, 10-21 09:00) を 10-15 の 0 時から読む。どの日も 03 時に BLOCK がある
	if strings.Join(days, ",") != "2026-10-15,2026-10-16,2026-10-17,2026-10-18,2026-10-19,2026-10-20,2026-10-21" {
		t.Fatalf("ip_list days: %v (the first days must not lose their parts)", days)
	}
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: cwlogs.MetricWAFListedIPsTotal})
	var marked []string
	for _, m := range ms {
		marked = append(marked, fmt.Sprintf("%s=%g", m.Date, m.Value))
	}
	if strings.Join(marked, ",") != "2026-10-15=1,2026-10-16=1,2026-10-17=1,2026-10-18=1,2026-10-19=1,2026-10-20=1" {
		t.Fatalf("listed days: %v", marked)
	}
}
