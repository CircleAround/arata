package iplist

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/store"
)

func list() *config.IPList {
	w, p, s := config.DefaultIPListWAFBlock, config.DefaultIPListProbe, config.DefaultIPListSignIn
	return &config.IPList{Active: 7 * 24 * time.Hour, Reasons: config.IPListReasons{WAFBlock: &w, Probe: &p, SignInFailure: &s}}
}

// date から n 日ずらした日。
func day(n int) string {
	return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n).Format("2006-01-02")
}

func (s Series) set(date, metric, ip string, v float64) Series {
	if s[date] == nil {
		s[date] = Day{}
	}
	if s[date][metric] == nil {
		s[date][metric] = map[string]float64{}
	}
	s[date][metric][ip] = v
	return s
}

func reasons(rows []store.IPListRow) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		out[r.IP] += r.Reason + fmt.Sprintf("=%g;", r.Count)
	}
	return out
}

// 1 節の載る条件 (日の件数)。IP は正規の形にし、読めない値は捨てて数える。既知の送信元 (allowlist の source_ips) は載せない。
func TestBuildDayReasons(t *testing.T) {
	s := Series{}
	s.set(day(0), cwlogs.MetricWAFBlockIPSuspect, "198.51.100.7", 1).
		set(day(0), cwlogs.MetricWAFBlockIPSuspect, "not-an-ip", 5).
		set(day(0), cwlogs.MetricWAFAllowProbeIP, "198.51.100.8", 2). // 3 件に足りない
		set(day(0), cwlogs.MetricWAFAllowProbeIP, "198.51.100.9", 3).
		set(day(0), cwlogs.MetricProbeHits, "2001:DB8:0:0::1", 4).    // 正規の形 (2001:db8::1) にする
		set(day(0), cwlogs.MetricProbeHits, "::ffff:203.0.113.5", 3). // IPv4 射影は IPv4 に
		set(day(0), cwlogs.MetricProbeHits, "192.0.2.10", 9)          // 既知の送信元
	known := func(ip string) bool { return ip == "192.0.2.10" }
	res := Build(list(), "src", day(0), s, known)
	want := map[string]string{
		"198.51.100.7": "waf_block=1;",
		"198.51.100.9": "probe=3;",
		"2001:db8::1":  "probe=4;",
		"203.0.113.5":  "probe=3;",
	}
	if got := reasons(res.Rows); !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
	if res.Invalid != 1 || res.Known != 1 {
		t.Errorf("invalid %d known %d", res.Invalid, res.Known)
	}
	for _, r := range res.Rows {
		if r.Date != day(0) || r.Source != "src" {
			t.Errorf("row %+v", r)
		}
	}
	// 書いていない理由では載せない
	l := list()
	l.Reasons.WAFBlock = nil
	if got := reasons(Build(l, "src", day(0), s, known).Rows); got["198.51.100.7"] != "" {
		t.Errorf("waf_block without the reason: %v", got)
	}
}

// sign_in_failure の日の載り方: 件数 (20) 以上、かつ自分の平常帯 (直近 14 日の中央値 × 3) を超えた。過去の日が 7 日に足りなければ件数だけ。
func TestBuildSignInDay(t *testing.T) {
	const ip, shared = "198.51.100.7", "203.0.113.20"
	m := cwlogs.MetricSignInFailures
	base := func() Series {
		s := Series{}
		for i := 1; i <= 14; i++ {
			s.set(day(-i), m, shared, 10) // 共有の IP: 毎日 10 件
			s.set(day(-i), m, "192.0.2.1", 1)
		}
		return s
	}
	for name, tc := range map[string]struct {
		s    Series
		want string
	}{
		"19 is below min_count":  {base().set(day(0), m, ip, 19), ""},
		"20 is listed":           {base().set(day(0), m, ip, 20), "sign_in_failure=20;"},
		"shared within baseline": {base().set(day(0), m, shared, 30), ""},                    // 10 × 3 = 30 を超えない
		"shared above baseline":  {base().set(day(0), m, shared, 31), "sign_in_failure=31;"}, // 超えた
		"no history: count only": {Series{}.set(day(0), m, shared, 20), "sign_in_failure=20;"},
	} {
		t.Run(name, func(t *testing.T) {
			target := ip
			if name == "shared within baseline" || name == "shared above baseline" || name == "no history: count only" {
				target = shared
			}
			got := reasons(Build(list(), "src", day(0), tc.s, nil).Rows)[target]
			if got != tc.want {
				t.Errorf("%s = %q, want %q", target, got, tc.want)
			}
		})
	}
}

// sign_in_failure の窓での載り方 (ゆっくりした総当たり): その日に失敗があり、直近 7 日の合計が 50 以上・失敗のあった日が 3 日以上、
// かつ窓の前の 14 日の中央値 × 7 × 3 を超えた。行の count はその日の件数。
func TestBuildSignInWindow(t *testing.T) {
	const ip = "198.51.100.7"
	m := cwlogs.MetricSignInFailures
	history := func(s Series, ip string, v float64) Series {
		for i := 7; i < 21; i++ { // 窓 (day(-6)〜day(0)) の前の 14 日
			s.set(day(-i), m, ip, v)
		}
		s.set(day(-7), m, "192.0.2.1", 1)
		return s
	}
	spread := func(s Series, ip string, perDay float64, days int) Series {
		for i := 0; i < days; i++ {
			s.set(day(-i), m, ip, perDay)
		}
		return s
	}
	for name, tc := range map[string]struct {
		s    Series
		want string
	}{
		"7 days x 7 = 49":        {spread(history(Series{}, "192.0.2.2", 1), ip, 7, 7), ""},
		"5 days x 10 = 50":       {spread(history(Series{}, "192.0.2.2", 1), ip, 10, 5), "sign_in_failure=10;"},
		"2 days x 25 = 50":       {spread(history(Series{}, "192.0.2.2", 1), ip, 19, 2).set(day(-5), m, ip, 12), "sign_in_failure=19;"}, // 3 日
		"2 days only":            {spread(history(Series{}, "192.0.2.2", 1), ip, 19, 2).set(day(-1), m, ip, 40), ""},
		"no failure on the day":  {spread(history(Series{}, "192.0.2.2", 1), ip, 10, 6).set(day(0), m, ip, 0), ""},
		"steady shared IP":       {spread(history(Series{}, ip, 3), ip, 8, 7), ""},                   // 平常帯 3 × 7 × 3 = 63 > 56
		"new slow attacker":      {spread(history(Series{}, ip, 0), ip, 8, 7), "sign_in_failure=8;"}, // 平常帯 0
		"no history: count only": {spread(Series{}, ip, 10, 5), "sign_in_failure=10;"},
	} {
		t.Run(name, func(t *testing.T) {
			res := Build(list(), "src", day(0), tc.s, nil)
			if got := reasons(res.Rows)[ip]; got != tc.want {
				t.Errorf("%s = %q, want %q", ip, got, tc.want)
			}
			if tc.want != "" && res.SignInByWindow != 1 {
				t.Errorf("by window = %d", res.SignInByWindow)
			}
		})
	}
}

// 読み込む範囲: 窓の前の平常帯まで (N + baseline_days 日前から)。
func TestFrom(t *testing.T) {
	if got := From(list(), day(0)); got != day(-20) {
		t.Errorf("From = %s, want %s", got, day(-20))
	}
	l := list()
	l.Reasons.SignInFailure = nil
	if got := From(l, day(0)); got != day(0) {
		t.Errorf("From without sign_in_failure = %s", got)
	}
}

// ADR 0090: 平常帯の中央値は、そのソースを収集した日 (lines_total か sign_in_failures の値のある日) だけで取る。
// 収集していない日は数えず、収集した日で値の無い日は 0 と数える。
func TestBuildSignInCollectedDays(t *testing.T) {
	const shared = "203.0.113.20"
	m := cwlogs.MetricSignInFailures
	// 共有の IP は day(-8)〜day(-14) に毎日 10 件 (窓の載り方には届かない)。day(-1)〜day(-7) は、all なら収集した日 (失敗 0)、そうでなければ収集していない
	build := func(all bool) Series {
		s := Series{}
		for i := 8; i <= 14; i++ {
			s.set(day(-i), m, shared, 10)
		}
		if all {
			for i := 1; i <= 7; i++ {
				s.set(day(-i), cwlogs.MetricLinesTotal, "", 1000)
			}
		}
		return s.set(day(0), m, shared, 21)
	}
	// 抜けあり: 中央値 10、しきい値 30。以前は 14 日の中央値 5 → しきい値 15 で載った
	if got := reasons(Build(list(), "src", day(0), build(false), nil).Rows)[shared]; got != "" {
		t.Errorf("抜けあり: %q", got)
	}
	// 全部収集: 収集した日の 0 は 0 と数える。中央値 5、しきい値 15
	if got := reasons(Build(list(), "src", day(0), build(true), nil).Rows)[shared]; got != "sign_in_failure=21;" {
		t.Errorf("全部収集: %q", got)
	}
}

// 一覧を作るのに読む日の値に、収集した日を決める lines_total を含める。
func TestMetricsIncludeLinesTotal(t *testing.T) {
	for _, m := range Metrics {
		if m == cwlogs.MetricLinesTotal {
			return
		}
	}
	t.Fatal("Metrics に lines_total が無い")
}
