package cwlogs

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
)

// 同じ IP からログインできた利用者の数 (ip_users。ADR 0094 の 2 節)。rate_limited_ip の判断の材料。
//
// U3 (軸は (日, IP)) を、U1・U2 と同じく範囲の中の UTC の 1 日ずつ流す (collectUsers)。
//
//	U3: <1 段目> | filter 利用者 | filter ispresent(ip)
//	    | stats count(*) as u_n by day, ip, user_kind, user_id   … (IP, 利用者) ごとに 1 行
//	    | stats count(*) as ip_users by day, ip                  … IP ごとの異なる利用者の数
//	    | sort ip_users desc | limit 10000
//
// 決定 (ADR 0094 の 2 節の実装):
//   - 流すのは、checks.rate_limited_ip.user_sources に書いたソースで、この run に http_user の要るチェックがあるときだけ (rate_limited_ip は OptionalNeeds で http_user を引かせる)
//   - U1 に IP の軸を足さず、別の 1 本にする (行が (利用者 × IP × 型) に増える)
//   - 代わりにログインした操作 (by の付いたリクエスト) は除く (U1・U2 と同じ userHead)。利用者の ID は Insights の中で数えるだけに使い、結果の列に無い
//   - 2 段目以降は count(*) だけ (earliest・latest・数でない min・max を使わない。本物で確かめた制約。設計書 2-7)
//   - 結果の IP はログ由来の値なので、netip で読めるものだけを残し、正規の形 (IPv4 に写した IPv6 は IPv4、ゾーンは外す) にそろえる。
//     http_access の key (ALB のログの client の IP) と突き合わせるため
//   - 日の値は ip_users_store_min 以上の IP を日ごとに多い順に ip_users_store_top まで。429 の無い IP も残す (人の多い送信元を 429 の前に見つける材料)
//   - 流した日の印 (user_probe_days の key ip_users) は、その日に形に合った IP の行が 1 つでもあったときだけ書く。
//     利用者の ID が取れなくなった日に「どの IP も 0 人」と読み違えないため (印の無い日は、チェックが「数えていない」として扱う)
const (
	// UserProbeIPUsers は U3 の名前 (MetricUserProbeDays の key・Queries の名前)。
	UserProbeIPUsers = "ip_users"
	// MetricIPUsers は (日, IP) ごとの、ログインできた異なる利用者の数 (key = ip。From は http_user)。
	MetricIPUsers = "ip_users"
)

// ipUsersNeeded は、このソースで U3 が要るか (設定だけで決まる)。
func (c *Collector) ipUsersNeeded() bool {
	return c.userConfigured() && !c.hourly() && c.checks.RateLimitedIP.CountsUsers(c.src.ID) && c.prof.Has("ip")
}

// IPUsersQuery は U3。
func IPUsersQuery(p Profile) string {
	var b strings.Builder
	b.WriteString(userHead(p, noPaths))
	b.WriteString("\n| filter ispresent(ip)")
	b.WriteString("\n| stats count(*) as u_n by day, ip, user_kind, user_id")
	b.WriteString("\n| stats count(*) as " + MetricIPUsers + " by day, ip")
	b.WriteString("\n| sort " + MetricIPUsers + " desc\n| limit 10000")
	return b.String()
}

// ipUsersKey は結果の行の IP を key にする (読めなければ ok = false)。
func ipUsersKey(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return a.WithZone("").Unmap().String(), true
}

// emitIPUsers は U3 の 1 日分の結果から ip_users を出す。形に合った IP の行があった日には、流した日の印も書く。
func (c *Collector) emitIPUsers(ctx context.Context, rows []map[string]string, sink collect.RecordSink) error {
	rl := c.checks.RateLimitedIP
	vals := dayValues{}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		ip, okIP := ipUsersKey(r["ip"])
		if !ok || !okIP {
			continue
		}
		vals.add(day, ip, nonNeg(r, MetricIPUsers))
	}
	for _, day := range sortedDays(vals) {
		for _, ip := range topKeysMin(vals[day], float64(rl.IPUsersStoreMin), rl.IPUsersStoreTop) {
			if err := c.emitUser(ctx, sink, day, MetricIPUsers, ip, vals[day][ip]); err != nil {
				return err
			}
		}
		if err := c.emitUser(ctx, sink, day, MetricUserProbeDays, UserProbeIPUsers, 1); err != nil {
			return err
		}
	}
	return nil
}

// ipHits は IPsPresentQuery の件数の列。
const ipHits = "arata_ip_hits"

// IPUsersTop は doctor 用に、[from, to) に U3 を 1 本流し、ログインできた利用者の多い IP を n 個まで返す (store_min で落とさない。読めない IP は捨てる)。
func (c *Collector) IPUsersTop(ctx context.Context, from, to time.Time, n int) ([]string, error) {
	rows, err := c.Query(ctx, IPUsersQuery(c.prof), from, to)
	if err != nil {
		return nil, err
	}
	sum := map[string]float64{}
	for _, r := range rows {
		if ip, ok := ipUsersKey(r["ip"]); ok {
			sum[ip] += nonNeg(r, MetricIPUsers)
		}
	}
	return topKeysMin(sum, 1, n), nil
}

// IPsPresentQuery は、ips のうちこのソースに現れるものを数えるクエリ。ips は netip で読める値だけを入れる (呼ぶ側の値もログ由来)。
func IPsPresentQuery(p Profile, ips []string) string {
	lits := make([]string, 0, len(ips))
	for _, ip := range validIPs(ips) {
		lits = append(lits, stringLiteral(ip))
	}
	return p.head("1d", "day", "ip in ["+strings.Join(lits, ", ")+"]", nil, false, false, false, noPaths) +
		"\n| stats " + p.count() + " as " + ipHits + " by ip\n| limit " + strconv.Itoa(MaxRows)
}

// validIPs は ips のうち netip で読めるものを正規の形にして返す。
func validIPs(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if k, ok := ipUsersKey(ip); ok {
			out = append(out, k)
		}
	}
	return out
}

// IPsPresent は doctor 用に、[from, to) のこのソースに現れた ips (正規の形) を返す。読める IP が無ければ流さない。
func (c *Collector) IPsPresent(ctx context.Context, ips []string, from, to time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	if len(validIPs(ips)) == 0 {
		return out, nil
	}
	rows, err := c.Query(ctx, IPsPresentQuery(c.prof, ips), from, to)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if ip, ok := ipUsersKey(r["ip"]); ok && num(r[ipHits]) > 0 {
			out[ip] = true
		}
	}
	return out, nil
}
