// Package iplist は怪しい IP の一覧 (ip_list_days。ADR 0069) を、保存済みの日の値 (metrics) から決まった規則で作る。
// Insights のクエリは足さない (載せるのに要る値は、今のクエリの行から作る日の値にある)。
package iplist

import (
	"net/netip"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 一覧に載る理由 (ip_list_days.reason)。
const (
	ReasonWAFBlock      = "waf_block"
	ReasonProbe         = "probe"
	ReasonSignInFailure = "sign_in_failure"
)

// Metrics は一覧を作るのに読む日の値 (lines_total のほかは key = ip)。lines_total (ログの総行数。key は空) は、
// sign_in_failure の平常帯に入れる「収集した日」を決めるのに読む (ADR 0090)。
var Metrics = []string{cwlogs.MetricWAFBlockIPSuspect, cwlogs.MetricWAFAllowProbeIP, cwlogs.MetricProbeHits, cwlogs.MetricSignInFailures, cwlogs.MetricLinesTotal}

// Day は metric → ip → その日の値、Series は date → Day (1 つのソースの分)。
type (
	Day    map[string]map[string]float64
	Series map[string]Day
)

// Result は 1 日・1 ソースの一覧の行と、数えたこと (run の stats に残す)。
type Result struct {
	Rows []store.IPListRow
	// Invalid は IP として読めずに捨てた key の数、Known は既知の送信元 (allowlist の source_ips) として載せなかった IP の数。
	Invalid, Known int
	// SignInByDay / SignInByWindow は sign_in_failure の日の載り方 / 窓の載り方 (日では載らなかったもの) で載った IP の数。
	SignInByDay, SignInByWindow int
}

// Canonical は IP の正規の形 (netip.Addr.String()。IPv4 射影の IPv6 は IPv4)。読めなければ false。
// 決定 (ADR 0069 の 1 節): 一覧の IP は後で Logs Insights の問い合わせの文に入れるので、ログ由来の値はここで読み直したものだけを持つ。
func Canonical(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.Unmap().String(), true
}

// From は date の一覧を作るのに要る、いちばん古い日 (sign_in_failure の窓の前の平常帯まで)。
func From(l *config.IPList, date string) string {
	s := l.Reasons.SignInFailure
	if s == nil {
		return date
	}
	return addDays(date, -(l.ActiveDays() - 1 + s.BaselineDays))
}

// Build は 1 つのソースの date の一覧の行を作る。s はそのソースの日の値 (From(date) から date まで)。
// known が true を返す IP (allowlist の source_ips) は載せない。
func Build(l *config.IPList, source, date string, s Series, known func(string) bool) Result {
	var res Result
	today := s[date]
	counts := map[string]map[string]float64{} // ip → reason → 件数
	add := func(ip, reason string, n float64) {
		if counts[ip] == nil {
			counts[ip] = map[string]float64{}
		}
		counts[ip][reason] += n
	}
	// 日の値の key を正規の形にして足し直す (同じ IP の書き方の違いをまとめる)
	canon := func(metric string) map[string]float64 {
		out := map[string]float64{}
		for k, v := range today[metric] {
			ip, ok := Canonical(k)
			if !ok {
				res.Invalid++
				continue
			}
			out[ip] += v
		}
		return out
	}
	r := l.Reasons
	if r.WAFBlock != nil {
		for ip, n := range canon(cwlogs.MetricWAFBlockIPSuspect) {
			if n >= r.WAFBlock.MinCount {
				add(ip, ReasonWAFBlock, n)
			}
		}
	}
	if r.Probe != nil {
		probe := canon(cwlogs.MetricProbeHits)
		for ip, n := range canon(cwlogs.MetricWAFAllowProbeIP) {
			probe[ip] += n
		}
		for ip, n := range probe {
			if n >= r.Probe.MinCount {
				add(ip, ReasonProbe, n)
			}
		}
	}
	if si := r.SignInFailure; si != nil {
		signIn(l, si, date, s, canon(cwlogs.MetricSignInFailures), add, &res)
	}
	ips := make([]string, 0, len(counts))
	for ip := range counts {
		if known != nil && known(ip) {
			res.Known++
			continue
		}
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		for _, reason := range []string{ReasonProbe, ReasonSignInFailure, ReasonWAFBlock} {
			if n, ok := counts[ip][reason]; ok {
				res.Rows = append(res.Rows, store.IPListRow{Date: date, Source: source, Reason: reason, IP: ip, Count: n})
			}
		}
	}
	return res
}

// signIn は sign_in_failure の 2 つの載り方 (ADR 0069 の 1 節)。
//   - 日: その日の件数が min_count 以上、かつ自分の平常帯 (直近 baseline_days 日の中央値 × factor) を超えた
//   - 窓: その日に失敗があり、直近 N 日の合計が min_count_window 以上・失敗のあった日が min_days 以上、
//     かつ窓の前の baseline_days 日の中央値 × N × factor を超えた (共有の IP の、前から続く失敗を載せない)
//
// 平常帯の過去の日 (その metric の行が 1 つでもある日) が min_baseline_days に足りなければ、件数 (と日数) だけで判定する。
// 中央値は、平常帯の日のうち収集した日 (lines_total か、その metric の行のある日) だけで取る。収集した日で行の無い IP は 0 (ADR 0090)。
func signIn(l *config.IPList, si *config.IPListSignIn, date string, s Series, today map[string]float64, add func(string, string, float64), res *Result) {
	m := cwlogs.MetricSignInFailures
	n := l.ActiveDays()
	// 過去の日の値を正規の形で引く
	cache := map[string]map[string]float64{}
	valuesOn := func(d string) map[string]float64 {
		if v, ok := cache[d]; ok {
			return v
		}
		out := map[string]float64{}
		for k, v := range s[d][m] {
			if ip, ok := Canonical(k); ok {
				out[ip] += v
			}
		}
		cache[d] = out
		return out
	}
	baseline := func(start string) (dates []string, withData int) {
		for i := 0; i < si.BaselineDays; i++ {
			d := addDays(start, -i)
			dates = append(dates, d)
			if len(s[d][m]) > 0 {
				withData++
			}
		}
		return dates, withData
	}
	dayBase, dayWith := baseline(addDays(date, -1))
	winBase, winWith := baseline(addDays(date, -n))
	collected := func(d string) bool {
		if len(s[d][m]) > 0 {
			return true
		}
		for _, v := range s[d][cwlogs.MetricLinesTotal] {
			if v > 0 {
				return true
			}
		}
		return false
	}
	median := func(dates []string, ip string) float64 {
		vals := make([]float64, 0, len(dates))
		for _, d := range dates {
			if collected(d) {
				vals = append(vals, valuesOn(d)[ip])
			}
		}
		return medianOf(vals)
	}
	for ip, v := range today {
		if v <= 0 {
			continue
		}
		if v >= si.MinCount && (dayWith < si.MinBaselineDays || v > median(dayBase, ip)*si.Factor) {
			add(ip, ReasonSignInFailure, v)
			res.SignInByDay++
			continue
		}
		sum, days := 0.0, 0
		for i := 0; i < n; i++ {
			if x := valuesOn(addDays(date, -i))[ip]; x > 0 {
				sum += x
				days++
			}
		}
		if sum >= si.MinCountWindow && days >= si.MinDays && (winWith < si.MinBaselineDays || sum > median(winBase, ip)*float64(n)*si.Factor) {
			add(ip, ReasonSignInFailure, v)
			res.SignInByWindow++
		}
	}
}

func medianOf(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	v := append([]float64(nil), vals...)
	sort.Float64s(v)
	k := len(v)
	if k%2 == 1 {
		return v[k/2]
	}
	return (v[k/2-1] + v[k/2]) / 2
}

func addDays(date string, n int) string {
	t, err := time.Parse(record.DateLayout, date)
	if err != nil {
		return date
	}
	return t.AddDate(0, 0, n).Format(record.DateLayout)
}
