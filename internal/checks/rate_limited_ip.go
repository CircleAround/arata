package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// RateLimitedIP は、アプリの回数の制限 (429) が 1 日に下限以上返った IP を、同じ IP からログインできた利用者の数を添えて報告する (low。ADR 0094 の 2 節)。
// 材料は cwlogs の rate_limited (http_access。http_hits のクエリ) と ip_users (http_user。U3)。Insights は流さず、ストアの日の値だけを読む。
//
// 決定 (ADR 0094 の 2 節の実装):
//   - 平常帯は持たない。その日の rate_limited が下限 (min_count) 以上なら報告する (429 はアプリの制限が働いた結果で、「この日にこれだけ止めた」が判断の単位)
//   - finding は IP ごとに 1 つ。評価する日 (窓に重なる日) のうち件数の多い日 (同じなら新しい日) を出す。複数のソースの件数は足す
//   - source_ips の IP は対象外 (login_bruteforce・probe_paths と同じ)
//   - ip_users を「数えた」のは、user_sources のどれかにその日の U3 の印 (user_probe_days の ip_users) があるとき。数えた日に値の無い IP は 0 人
//     (ip_users_store_min 未満は残らない)。数えていない日は ip_users も理由も添えず、件数だけを報告する
//   - 理由: suggest_shared (ip_users が suggest_min_users 以上。shared_sources に足す候補・アプリの上限の見直しの候補)、
//     few_users (数えていて suggest_min_users 未満。総当たり・機械的な送信の疑い)
//   - 決定 1 (shared_sources) はまだ無い。入れるときは minCount で shared_sources の IP に shared_min_count を返し、data に shared・shared_note を足し、
//     shared_sources の IP には suggest_shared の代わりに shared_heavy を付ける (ADR 0094 の 1 節・2 節)
//   - user_sources を書いたときだけ http_user も引かせる (OptionalNeeds)。ユーザー ID が取れない run でも、429 の報告は止めない (Needs は http_access だけ)
type RateLimitedIP struct {
	Config config.RateLimitedIP
}

const rateLimitedIPName = "rate_limited_ip"

// rate_limited_ip の理由 (Data の reasons と Fingerprint に入る)。
const (
	reasonSuggestShared = "suggest_shared"
	reasonFewUsers      = "few_users"
)

func (RateLimitedIP) Name() string         { return rateLimitedIPName }
func (RateLimitedIP) Cadence() Cadence     { return Daily }
func (RateLimitedIP) Mode() Mode           { return ModeEvent }
func (RateLimitedIP) Needs() []record.Kind { return []record.Kind{record.KindHTTPAccess} }

// OptionalNeeds は、user_sources を書いたときの http_user (U3 を流させる。取れなくても skip しない)。
func (c RateLimitedIP) OptionalNeeds() []record.Kind {
	if len(c.Config.UserSources) == 0 {
		return nil
	}
	return []record.Kind{record.KindHTTPUser}
}

// minCount は ip を報告する 1 日の件数の下限。shared_sources (ADR 0094 の 1 節) を入れるときは、ここで shared_min_count に切り替える。
func (c RateLimitedIP) minCount(string) float64 { return c.Config.MinCount }

type rateHit struct {
	day   string
	count float64
}

func (c RateLimitedIP) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	dates := windowDates(w)
	if len(dates) == 0 {
		return nil, nil
	}
	from, to := dates[0], dates[len(dates)-1]
	rl, err := loadSeries(ctx, q, cwlogs.MetricRateLimited, from, to)
	if err != nil {
		return nil, err
	}
	best := map[string]rateHit{}
	for _, d := range dates {
		for ip, v := range rl[d] {
			if al.SourceIPAllowed(ip) || v < c.minCount(ip) {
				continue
			}
			if cur, ok := best[ip]; !ok || v > cur.count || v == cur.count && d > cur.day {
				best[ip] = rateHit{day: d, count: v}
			}
		}
	}
	if len(best) == 0 {
		return nil, nil
	}
	signIn, err := loadSeries(ctx, q, cwlogs.MetricSignInFailures, from, to)
	if err != nil {
		return nil, err
	}
	users, counted, err := c.ipUsers(ctx, q, from, to)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(best))
	for ip := range best {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	obs := make([]Observation, 0, len(ips))
	for _, ip := range ips {
		h := best[ip]
		data := map[string]any{"ip": ip, "date": h.day, "count": h.count, "min_count": c.minCount(ip), "sign_in_failures": signIn[h.day][ip]}
		summary := fmt.Sprintf("アプリの回数の制限 (%s) が集まった IP: %s から %.0f 件 (%s UTC、下限 %.0f)", statusList(c.Config.Statuses), ip, h.count, h.day, c.minCount(ip))
		var reasons []string
		if counted[h.day] {
			n := users[h.day][ip]
			data["ip_users"] = n
			summary += fmt.Sprintf("。同じ IP からログインできた利用者 %.0f 人", n)
			if n >= c.Config.SuggestMinUsers {
				reasons = append(reasons, reasonSuggestShared)
			} else {
				reasons = append(reasons, reasonFewUsers)
			}
			data["reasons"] = reasons
		}
		obs = append(obs, Observation{Check: c.Name(), Key: ip, Severity: Low, Summary: summary,
			Fingerprint: fingerprint(Low, nil, strings.Join(reasons, ",")), Data: data})
	}
	return obs, nil
}

// ipUsers は user_sources の ip_users と、U3 を流した日 (印のある日)。user_sources が空なら何も読まない。
func (c RateLimitedIP) ipUsers(ctx context.Context, q store.Query, from, to string) (series, map[string]bool, error) {
	counted := map[string]bool{}
	if len(c.Config.UserSources) == 0 {
		return series{}, counted, nil
	}
	ps := &probeSeries{ctx: ctx, q: q, sources: c.Config.UserSources, from: from, to: to}
	ran, err := ps.load(cwlogs.MetricUserProbeDays)
	if err != nil {
		return nil, nil, err
	}
	for d, keys := range ran {
		if keys[cwlogs.UserProbeIPUsers] > 0 {
			counted[d] = true
		}
	}
	users, err := ps.load(cwlogs.MetricIPUsers)
	if err != nil {
		return nil, nil, err
	}
	return users, counted, nil
}

func statusList(l []int) string {
	parts := make([]string, len(l))
	for i, s := range l {
		parts[i] = fmt.Sprint(s)
	}
	return strings.Join(parts, "・")
}
