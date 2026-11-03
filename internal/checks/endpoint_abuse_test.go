package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 窓は appWindow [10-20 09:00, 10-21 09:00)。終わりが (From, To] に入る 10 分幅を評価する。
// 平常帯は評価する最初の日 (10-20) の前日から 14 日 (10-06〜10-19) のうち、ログを収集した日 (lines_total のある日) の全部の幅の p99。

func abuseCheck() EndpointAbuse {
	c := config.DefaultChecks().EndpointAbuse
	c.Endpoints = []config.AbuseEndpoint{
		{Name: "signup", Paths: []string{"/signup"}, Methods: []string{"POST"}},
		{Name: "message", Paths: []string{"/messages"}, Methods: []string{"POST"}},
		{Name: "search", Paths: []string{"/search"}},
		{Name: "busy", Paths: []string{"/busy"}},
	}
	c.FollowUps = []config.FollowUp{{From: "signup", To: "message", Within: "30m", MinIPs: 5}}
	return EndpointAbuse{Config: c}
}

// collected は 10-19 から遡って days 日にログの総行数を入れる (収集した日)。
func collected(m metricSeed, days int) {
	for i := 0; i < days; i++ {
		m.put(time.Date(2026, 10, 19-i, 0, 0, 0, 0, time.UTC).Format(record.DateLayout), "web", cwlogs.MetricLinesTotal, "", 1000)
	}
}

func evalAbuse(t *testing.T, c EndpointAbuse, st *store.Dir) map[string]Observation {
	t.Helper()
	return evaluate(t, c, st, &allowlist.List{})
}

func TestEndpointAbuse(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	collected(m, 14)
	// ふだん: 登録は幅ごとに最大 3 件・2 IP。busy は毎日 30 IP が来る画面 (平常帯が高い)
	// (p99 は全部の幅 (14 日 × 144) の上位 1% なので、1 日 2 幅 (計 28 幅) に入れる)
	for _, hm := range []string{"01:00", "01:10"} {
		m.history("web", cwlogs.MetricEndpointCount, "signup|"+hm, 3)
		m.history("web", cwlogs.MetricEndpointIPs, "signup|"+hm, 2)
		m.history("web", cwlogs.MetricEndpointUAIPs, "signup|"+hm+"|aaaaaaaa", 2)
		m.history("web", cwlogs.MetricEndpointIPs, "busy|12:"+hm[3:], 30)
		m.history("web", cwlogs.MetricEndpointCount, "busy|12:"+hm[3:], 40)
	}
	d := "2026-10-21"
	// 03:20 に 25 IP から 25 件 (同じ UA が 22 IP)、03:30 にも 12 IP
	m.put(d, "web", cwlogs.MetricEndpointCount, "signup|03:20", 25)
	m.put(d, "web", cwlogs.MetricEndpointIPs, "signup|03:20", 25)
	m.put(d, "web", cwlogs.MetricEndpointUAIPs, "signup|03:20|1a2b3c4d", 22)
	m.put(d, "web", cwlogs.MetricEndpointCount, "signup|03:30", 12)
	m.put(d, "web", cwlogs.MetricEndpointIPs, "signup|03:30", 12)
	// そのうち 6 IP が 30 分以内にメッセージ送信
	m.put(d, "web", cwlogs.MetricEndpointFollow, "signup>message|03:20", 6)
	// search: 1 IP から 100 件 (量だけ → low)
	m.put(d, "web", cwlogs.MetricEndpointCount, "search|05:00", 100)
	m.put(d, "web", cwlogs.MetricEndpointIPs, "search|05:00", 1)
	// busy: 40 IP はふだんの上限 30 × 3 以下なので報告しない
	m.put(d, "web", cwlogs.MetricEndpointIPs, "busy|12:00", 40)
	m.put(d, "web", cwlogs.MetricEndpointCount, "busy|12:00", 50)

	obs := evalAbuse(t, abuseCheck(), st)
	if len(obs) != 3 {
		t.Fatalf("obs: %+v", obs)
	}
	s := obs["signup"]
	if s.Severity != Medium || s.Data["bin_start"] != "2026-10-21T03:20:00Z" || s.Data["distinct_ips"] != 25.0 || s.Data["count"] != 25.0 ||
		s.Data["baseline_p99_ips"] != 2.0 || s.Data["ua_ips"] != 22.0 || s.Data["ua_hash"] != "1a2b3c4d" || s.Data["baseline_used"] != true {
		t.Fatalf("signup: %+v", s)
	}
	for _, want := range []string{"signup", "03:20〜03:30", "25 件", "異なり IP 25", "ふだんの上限 2", "同じ UA が 22 IP"} {
		if !strings.Contains(s.Summary, want) {
			t.Errorf("summary lacks %q: %s", want, s.Summary)
		}
	}
	// 03:30 の 12 IP・12 件も平常帯 (2 × 3、3 × 3) と下限を超える
	if bins := s.Data["bins"].([]map[string]any); len(bins) != 2 || bins[1]["start"] != "2026-10-21T03:30:00Z" {
		t.Fatalf("bins: %+v", s.Data["bins"])
	}
	if fmt.Sprint(s.Data["reasons"]) != "[distributed_burst volume same_user_agent]" {
		t.Fatalf("reasons: %v", s.Data["reasons"])
	}
	if sr := obs["search"]; sr.Severity != Low || fmt.Sprint(sr.Data["reasons"]) != "[volume]" {
		t.Fatalf("search: %+v", sr)
	}
	f := obs["signup>message"]
	if f.Severity != Medium || f.Data["ips"] != 6.0 || f.Data["within"] != "30m" {
		t.Fatalf("follow: %+v", f)
	}
	for _, want := range []string{"signup", "message", "6 IP", "30m"} {
		if !strings.Contains(f.Summary, want) {
			t.Errorf("follow summary lacks %q: %s", want, f.Summary)
		}
	}
	// 遮断の提案はしない (事実だけ)
	for _, o := range obs {
		if strings.Contains(o.Summary, "遮断") || strings.Contains(o.Summary, "ブロック") || o.Severity.Rank() > Medium.Rank() {
			t.Fatalf("must state facts only, at most medium: %+v", o)
		}
	}
}

// 評価するのは終わりが (From, To] に入る幅。連鎖は幅の終わり + within が (From, To] に入るもの (to に来るのを待つ)。
func TestEndpointAbuseBinsInWindow(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	collected(m, 14)
	burst := func(date, hm string) {
		m.put(date, "web", cwlogs.MetricEndpointCount, "signup|"+hm, 30)
		m.put(date, "web", cwlogs.MetricEndpointIPs, "signup|"+hm, 30)
	}
	burst("2026-10-20", "08:50")                                                       // 終わり 09:00 = From → 前の run が評価済み
	m.put("2026-10-21", "web", cwlogs.MetricEndpointFollow, "signup>message|08:30", 9) // 08:40 + 30m > To → 次の run
	obs := evalAbuse(t, abuseCheck(), st)
	if len(obs) != 0 {
		t.Fatalf("outside window: %+v", obs)
	}
	burst("2026-10-21", "08:50")                                                       // 終わり 09:00 = To → 評価する
	m.put("2026-10-20", "web", cwlogs.MetricEndpointFollow, "signup>message|08:30", 9) // 08:40 + 30m = 09:10 → 評価する
	obs = evalAbuse(t, abuseCheck(), st)
	if obs["signup"].Data["bin_start"] != "2026-10-21T08:50:00Z" || obs["signup>message"].Data["bin_start"] != "2026-10-20T08:30:00Z" || len(obs) != 2 {
		t.Fatalf("in window: %+v", obs)
	}
}

// 収集した過去日が min_baseline_days 未満の間は平常帯を使わず、絶対の閾値だけで判定する。
func TestEndpointAbuseWithoutBaseline(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	collected(m, 3)
	// 収集した日 (10-17〜10-19) にだけ平常帯の値がある。日数が足りないので使わない
	for _, d := range []string{"2026-10-17", "2026-10-18", "2026-10-19"} {
		m.put(d, "web", cwlogs.MetricEndpointIPs, "signup|01:00", 50)
	}
	m.put("2026-10-21", "web", cwlogs.MetricEndpointIPs, "signup|03:20", 12)
	m.put("2026-10-21", "web", cwlogs.MetricEndpointCount, "signup|03:20", 12)
	// 9 IP は min_distinct_ips (10) 未満
	m.put("2026-10-21", "web", cwlogs.MetricEndpointIPs, "message|03:20", 9)
	obs := evalAbuse(t, abuseCheck(), st)
	s, ok := obs["signup"]
	if !ok || len(obs) != 1 || s.Data["baseline_used"] != false || s.Data["baseline_days_collected"] != 3 || !strings.Contains(s.Summary, "平常帯は未確立") {
		t.Fatalf("obs: %+v", obs)
	}
}

// endpoints が空 (既定) なら何もしない。
func TestEndpointAbuseDefaultIsNoop(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	m.put("2026-10-21", "web", cwlogs.MetricEndpointIPs, "signup|03:20", 100)
	obs, err := EndpointAbuse{Config: config.DefaultChecks().EndpointAbuse}.Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil || len(obs) != 0 {
		t.Fatalf("%v %+v", err, obs)
	}
}

// endpoint_abuse の日次集計が入っても、既存のアプリ層チェックの結果は変わらない。
func TestEndpointAbuseKeepsExistingChecks(t *testing.T) {
	run := func(withAbuse bool) string {
		st := newStore(t)
		m := metricSeed{st: st, t: t}
		m.put("2026-10-21", "web", cwlogs.MetricSignInFailures, "198.51.100.7", 80)
		m.put("2026-10-21", "web", cwlogs.MetricProbeHits, "198.51.100.8", 40)
		m.put("2026-10-21", "web", cwlogs.MetricProbePaths, "/.env", 40)
		if withAbuse {
			collected(m, 14)
			m.put("2026-10-21", "web", cwlogs.MetricEndpointIPs, "signup|03:20", 100)
			m.put("2026-10-21", "web", cwlogs.MetricEndpointCount, "signup|03:20", 100)
		}
		c := config.DefaultChecks()
		var out []string
		for _, ch := range []Check{LoginBruteforce{Config: c.LoginBruteforce}, ProbePaths{Config: c.ProbePaths}} {
			obs, err := ch.Evaluate(context.Background(), st, appWindow, &allowlist.List{})
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, fmt.Sprintf("%+v", obs))
		}
		return strings.Join(out, "\n")
	}
	if a, b := run(false), run(true); a != b || !strings.Contains(a, "198.51.100.7") {
		t.Fatalf("existing checks changed:\n%s\n%s", a, b)
	}
}
