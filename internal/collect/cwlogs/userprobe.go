package cwlogs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/pathids"
	"github.com/CircleAround/arata/internal/record"
)

// ログインした利用者の総当たり (user_denied・user_id_enumeration・user_path_breadth) の日の値 (ADR 0071 の 6 節・0087 の 1 節)。
//
// U1 (利用者の要約。軸は (日, 利用者)) と U2 (ID の総当たり。軸は (日, 利用者, 型)) の 2 本を、範囲の中の UTC の 1 日ずつ流す。
// request_lines の 1 段目 (request_id のまとめ) の後に、2 段目・3 段目の stats を置く。
//
//	U1: <1 段目> | filter 利用者 | parse status (拒否・2xx・404 の印)
//	    | stats … by day, user_kind, user_id, tpl          … (利用者, 型) ごとの拒否の件数と、型ごとのステータスの印
//	    | stats sum(拒否) as user_denied, count(tpl) as user_templates, … by day, user_kind, user_id
//	    | fields user_denied + user_templates as u_rank | sort u_rank desc | limit 10000
//	U2: <1 段目 (tid を足す)> | filter 利用者 | filter ispresent(tid) | fields concat(method, " ", status) as u_ms | parse u_ms (成功・拒否・3xx・メソッドの印)
//	    | stats … by day, user_kind, user_id, tpl, tid      … (利用者, 型, 対象 ID) ごとの印
//	    | stats count(*) as user_ids, count(成功) as user_ids_ok, … by day, user_kind, user_id, tpl
//	    | sort user_ids desc | limit 10000
//
// 決定 (ADR 0087 の実装。開発リードの判断、2026-11-26):
//   - 流すのは、ユーザー ID を読むソースを 3 つのチェックのどれかの sources に書き、http_user を要るチェックがこの run にあるときだけ。
//     U1 は user_denied か user_path_breadth (path_ids のあるソース)、U2 は user_id_enumeration (path_ids のあるソース) が要るとき
//   - 印は、確かめた形 (parse の名前付きキャプチャ・count(<項目>) が値のある行だけを数えること) で作り、stats の後の if を使わない。
//     「型のうち成功のあったものの数」は、2 段目で max(<印>) を取り (印の無い型は値なし。latest は 2 段目以降の stats で使えない: 行の時刻を暗に使い、本物の Insights が「Unknown symbols found in or after stats: @timestamp」で断った。2026-11-28 に確かめた)、3 段目で count(<その列>) で数える
//   - 3xx は、メソッドが GET か HEAD のときだけ拒否に数える (0087 の 7 節)。メソッドとステータスを 1 つの文字列にして 1 つの parse で決める
//   - メソッドごとの件数は GET・HEAD・POST・PUT・PATCH・DELETE と other に固定する (ログの値で key を増やさない)
//   - part_floor の filter (stats の後の filter) は入れない (Insights で確かめていない)。sort と limit で受け、store_min で落とすのは Go の側
//   - 段をまたいで同じ名前の列を作り直さない (Insights の一時フィールドの扱いに頼らない)。2 段目は u_…、3 段目は別の名前
//   - 代わりにログインした操作 (by の付いたリクエスト) は 1 段目の後で除く (0071 の 7 節)
//   - 利用者の ID・対象 ID は Insights の中で数えるだけに使う。結果に出る利用者の ID は、key に置く前にストアの規則 (ValidUserKind・ValidUserID) で確かめ直す。
//     合わない行は捨てる。対象 ID は結果の列に無い
//   - 日の値は store_min 以上の key を日ごとに値の大きい順に store_top まで残す。根拠の値 (内訳) は残した key の分だけ書く
//   - 分布の行 (user_ids_dist) は、その日に user_ids を残した型の分だけ書く (型の数で行を増やさない。アプリの平常帯は、残した型の最多の利用者の値で足りる)。
//     p50・p99 はその日の U2 が行の上限に当たっていないときだけ
const (
	userSummaryQuery = "user_summary"
	userIDsQuery     = "user_ids"
	rlTargetID       = "tid" // request_lines の 1 段目の列 (最初の行の対象 ID。結果には出さない)
)

// 利用者ごとのチェックの日の値 (From は http_user)。
const (
	MetricUserDenied             = "user_denied"              // key = <kind>:<id>。拒否 (user_denied.statuses) の件数
	MetricUserTemplates          = "user_templates"           // key = <kind>:<id>。触った型の異なりの数
	MetricUserTemplatesOK        = "user_templates_ok"        // そのうち 2xx のあった型の数
	MetricUserTemplatesDenied    = "user_templates_denied"    // そのうち拒否 (user_denied.statuses) のあった型の数
	MetricUserTemplatesNotFound  = "user_templates_not_found" // そのうち 404 のあった型の数
	MetricUserIDs                = "user_ids"                 // key = <kind>:<id>|<型>。開いた異なる対象 ID の数
	MetricUserIDsOK              = "user_ids_ok"              // そのうち成功 (success_statuses) のあった ID の数
	MetricUserIDsDenied          = "user_ids_denied"          // そのうち拒否 (denied_statuses) のあった ID の数
	MetricUserDeniedRedirects    = "user_denied_redirects"    // そのうち 3xx (GET・HEAD) で拒否に数えた ID の数。denied_statuses に 3xx を書いたときだけ
	MetricUserIDsMethods         = "user_ids_methods"         // key = <kind>:<id>|<型>|<メソッド>。メソッドごとの件数
	MetricUserIDsDist            = "user_ids_dist"            // key = <型>|users・|max・|p50・|p99。その日の型ごとの分布
	userIDsDistUsers, userIDsMax = "users", "max"
)

// UserQueryLen は U1・U2 の文の長さの上限。Insights の上限 (MaxQueryLen) より 1 割短くする (上限の近くで断られたことがある。ListedQueryLen と同じ理由)。
//
// 決定: U1・U2 の文は、request_lines の 1 段目 (行の種類の正規表現・ユーザー ID の正規表現) と path_ids の文 (pathids.MaxQueryLen まで) を含む。
// それぞれの上限の和は Insights の上限を超えうるので、組み上げた文の長さを確かめる。超えれば LongQueries が返し、config check と doctor が ng にし、
// run はそのクエリを流さずにソースの誤りにする (断られるクエリを送らない)
const UserQueryLen = ListedQueryLen

// LongQueries は、長さが UserQueryLen を超える U1・U2 の説明 (無ければ空)。
func (c *Collector) LongQueries() []string {
	var out []string
	for _, q := range c.userQueries() {
		if n := len(q.Query); n > UserQueryLen {
			out = append(out, fmt.Sprintf("source %s: the Logs Insights query %s for the user checks is %d characters (at most %d): shorten request.lines / request.user_id regexes or path_ids (fewer templates, lower max_segments)",
				c.src.ID, q.Name, n, UserQueryLen))
		}
	}
	return out
}

// userMethods は数えるメソッド (この順で列にする)。ほかは other。
var userMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

const userMethodOther = "other"

// userNeeds は、このソースで U1・U2 が要るか (設定だけで決まる。この run で http_user が要るかは collectUsers が見る)。
func (c *Collector) userNeeds() (summary, ids bool) {
	if !c.userConfigured() || c.hourly() {
		return false, false
	}
	us := c.checks.UserSources(c.src.ID)
	paths := c.prof.paths != nil
	return us.Denied || us.Breadth && paths, us.IDs && paths
}

// userQueries は U1・U2 (要るものだけ)。
func (c *Collector) userQueries() []MergedQuery {
	summary, ids := c.userNeeds()
	var out []MergedQuery
	if summary {
		out = append(out, MergedQuery{Name: userSummaryQuery, Query: UserSummaryQuery(c.prof, c.checks, c.checks.UserSources(c.src.ID).Breadth),
			Metrics: []string{MetricUserDenied, MetricUserTemplates}, Bin: c.prof.binName("day")})
	}
	if ids {
		out = append(out, MergedQuery{Name: userIDsQuery, Query: UserIDsQuery(c.prof, c.checks), Metrics: []string{MetricUserIDs}, Bin: c.prof.binName("day")})
	}
	return out
}

// userHead は U1・U2 の 1 段目と、ログインした本人のリクエストだけに絞る filter。
func userHead(p Profile, pc pathCols) string {
	var b strings.Builder
	b.WriteString(p.head("1d", "day", "", nil, false, false, true, pc))
	b.WriteString("\n| filter ispresent(user_id)\n| filter ispresent(user_kind)")
	if p.req.hasUserField("by_id") {
		b.WriteString("\n| filter not ispresent(by_id)")
	}
	return b.String()
}

// statusAlt は statuses を正規表現の選択肢にする (数字だけ。config が 3 桁に絞ってある)。
func statusAlt(l []int) string {
	parts := make([]string, len(l))
	for i, s := range l {
		parts[i] = strconv.Itoa(s)
	}
	return strings.Join(parts, "|")
}

// UserSummaryQuery は U1。templates なら型の列 (path_ids のあるソースだけ) も数える。
func UserSummaryQuery(p Profile, ch config.Checks, templates bool) string {
	templates = templates && p.paths != nil
	pc := noPaths
	if templates {
		pc = withTemplate
	}
	var b strings.Builder
	b.WriteString(userHead(p, pc))
	b.WriteString("\n| parse status /^(?<u_dn>" + statusAlt(ch.UserDenied.Statuses) + ")$/")
	if !templates {
		b.WriteString("\n| stats count(u_dn) as " + MetricUserDenied + ", sum(" + rlStarts + ") as u_rq by day, user_kind, user_id")
		b.WriteString("\n| sort " + MetricUserDenied + " desc")
	} else {
		b.WriteString("\n| parse status /^(?<u_ok>2[0-9][0-9])$/\n| parse status /^(?<u_nf>404)$/")
		b.WriteString("\n| stats sum(" + rlStarts + ") as u_n, count(u_dn) as u_d, max(u_ok) as u_tok, max(u_dn) as u_tdn, max(u_nf) as u_tnf by day, user_kind, user_id, " + rlTemplate)
		b.WriteString("\n| stats sum(u_d) as " + MetricUserDenied + ", count(" + rlTemplate + ") as " + MetricUserTemplates +
			", count(u_tok) as " + MetricUserTemplatesOK + ", count(u_tdn) as " + MetricUserTemplatesDenied + ", count(u_tnf) as " + MetricUserTemplatesNotFound +
			", sum(u_n) as u_rq by day, user_kind, user_id")
		b.WriteString("\n| fields " + MetricUserDenied + " + " + MetricUserTemplates + " as u_rank\n| sort u_rank desc")
	}
	b.WriteString("\n| limit " + strconv.Itoa(MaxRows))
	return b.String()
}

// UserIDsQuery は U2 (path_ids のあるソースだけ)。
func UserIDsQuery(p Profile, ch config.Checks) string {
	ue := ch.UserIDEnumeration
	var plain, redirects []int
	for _, s := range ue.DeniedStatuses {
		if config.IsRedirect(s) {
			redirects = append(redirects, s)
		} else {
			plain = append(plain, s)
		}
	}
	method := `""`
	if p.Has("method") {
		method = `coalesce(method, "")`
	}
	var b strings.Builder
	b.WriteString(userHead(p, withTemplateAndID))
	b.WriteString("\n| filter ispresent(" + rlTargetID + ")")
	b.WriteString("\n| fields concat(" + method + `, " ", coalesce(status, "")) as u_ms`)
	b.WriteString("\n| parse u_ms /^[^ ]* (?<u_ok>" + statusAlt(ue.SuccessStatuses) + ")$/")
	denied := []string{}
	if len(plain) > 0 {
		denied = append(denied, "[^ ]* (?:"+statusAlt(plain)+")")
	}
	if len(redirects) > 0 {
		denied = append(denied, "(?:GET|HEAD) (?:"+statusAlt(redirects)+")")
	}
	// 2 段目の max に渡す印は数にする (数でない値の max は値なしになる。2026-11-28 に本物の Insights で確かめた)。メソッドとステータスで決めた印から、ステータスだけを取り出す
	b.WriteString("\n| parse u_ms /^(?<u_dm>" + strings.Join(denied, "|") + ")$/")
	b.WriteString("\n| parse u_dm / (?<u_dn>[0-9]{3})$/")
	if len(redirects) > 0 {
		b.WriteString("\n| parse u_ms /^(?<u_rm>(?:GET|HEAD) (?:" + statusAlt(redirects) + "))$/")
		b.WriteString("\n| parse u_rm / (?<u_rd>[0-9]{3})$/")
	}
	var alts, aggs2, aggs3 []string
	for i, m := range userMethods {
		n := "u_m" + strconv.Itoa(i)
		alts = append(alts, "(?<"+n+">"+m+")")
		aggs2 = append(aggs2, "count("+n+") as u_c"+strconv.Itoa(i))
		aggs3 = append(aggs3, "sum(u_c"+strconv.Itoa(i)+") as u_s"+strconv.Itoa(i))
	}
	b.WriteString("\n| parse u_ms /^(?:" + strings.Join(alts, "|") + ") /")
	two := []string{"count(*) as u_n", "max(u_ok) as u_iok", "max(u_dn) as u_idn"}
	three := []string{"count(*) as " + MetricUserIDs, "count(u_iok) as " + MetricUserIDsOK, "count(u_idn) as " + MetricUserIDsDenied}
	if len(redirects) > 0 {
		two = append(two, "max(u_rd) as u_ird")
		three = append(three, "count(u_ird) as "+MetricUserDeniedRedirects)
	}
	two = append(two, aggs2...)
	three = append(append(three, "sum(u_n) as u_rq"), aggs3...)
	b.WriteString("\n| stats " + strings.Join(two, ", ") + " by day, user_kind, user_id, " + rlTemplate + ", " + rlTargetID)
	b.WriteString("\n| stats " + strings.Join(three, ", ") + " by day, user_kind, user_id, " + rlTemplate)
	b.WriteString("\n| sort " + MetricUserIDs + " desc\n| limit " + strconv.Itoa(MaxRows))
	return b.String()
}

// collectUsers は U1・U2 を範囲の中の UTC の 1 日ずつ流し、日の値を出す。この run に http_user の要るチェックが無ければ流さない。
func (c *Collector) collectUsers(ctx context.Context, from, to time.Time, sink collect.RecordSink) error {
	if c.selected != nil && !c.selected[record.KindHTTPUser] {
		return nil
	}
	if long := c.LongQueries(); len(long) > 0 {
		return errors.New(strings.Join(long, "; "))
	}
	for _, q := range c.userQueries() {
		for d := from; d.Before(to); d = DayStart(d).Add(24 * time.Hour) {
			end := DayStart(d).Add(24 * time.Hour)
			if end.After(to) {
				end = to
			}
			rows, err := c.splitRange(ctx, q, d, end, c.dayAlign())
			if err != nil {
				return err
			}
			truncated := len(rows) >= MaxRows
			if q.Name == userSummaryQuery {
				err = c.emitUserSummary(ctx, rows, sink)
			} else {
				err = c.emitUserIDs(ctx, rows, truncated, sink)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// userKey は結果の行の利用者を key にする。形に合わない値は ok = false (Insights の結果はログ由来の値。ADR 0037・0052)。
func userKey(r map[string]string) (string, bool) {
	kind, id := r["user_kind"], r["user_id"]
	if !ValidUserKind(kind) || !ValidUserID(id) {
		return "", false
	}
	return kind + ":" + id, true
}

// nonNeg は結果の列を 0 以上の整数として読む。
func nonNeg(r map[string]string, col string) float64 {
	return math.Max(0, math.Min(math.Floor(num(r[col])), maxRequestCount))
}

// dayValues は日ごと・key ごとの値。
type dayValues map[string]map[string]float64

func (d dayValues) add(day, key string, v float64) {
	if d[day] == nil {
		d[day] = map[string]float64{}
	}
	d[day][key] += v
}

// topKeysMin は値が min 以上の key を、値の大きい順 (同じなら key の順) に n 個まで返す。
func topKeysMin(m map[string]float64, min float64, n int) []string {
	var keys []string
	for k, v := range m {
		if v >= min {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

func (c *Collector) emitUser(ctx context.Context, sink collect.RecordSink, day, metric, key string, v float64) error {
	return sink.Emit(ctx, record.Metric{Date: day, Source: c.src.ID, From: record.KindHTTPUser, Metric: metric, Key: key, Value: v})
}

// emitUserSummary は U1 の 1 日分の結果から user_denied・user_templates (と内訳) を出す。
func (c *Collector) emitUserSummary(ctx context.Context, rows []map[string]string, sink collect.RecordSink) error {
	us := c.checks.UserSources(c.src.ID)
	cols := []string{MetricUserDenied, MetricUserTemplates, MetricUserTemplatesOK, MetricUserTemplatesDenied, MetricUserTemplatesNotFound}
	vals := map[string]dayValues{}
	for _, m := range cols {
		vals[m] = dayValues{}
	}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		key, okKey := userKey(r)
		if !ok || !okKey {
			continue
		}
		for _, m := range cols {
			vals[m].add(day, key, nonNeg(r, m))
		}
	}
	for _, day := range sortedDays(vals[MetricUserDenied]) {
		if us.Denied {
			ud := c.checks.UserDenied
			for _, k := range topKeysMin(vals[MetricUserDenied][day], float64(ud.StoreMin), ud.StoreTop) {
				if err := c.emitUser(ctx, sink, day, MetricUserDenied, k, vals[MetricUserDenied][day][k]); err != nil {
					return err
				}
			}
		}
		if us.Breadth && c.prof.paths != nil {
			ub := c.checks.UserPathBreadth
			for _, k := range topKeysMin(vals[MetricUserTemplates][day], float64(ub.StoreMin), ub.StoreTop) {
				for _, m := range cols[1:] {
					if err := c.emitUser(ctx, sink, day, m, k, vals[m][day][k]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// emitUserIDs は U2 の 1 日分の結果から user_ids (と内訳・メソッドごとの件数・分布) を出す。
func (c *Collector) emitUserIDs(ctx context.Context, rows []map[string]string, truncated bool, sink collect.RecordSink) error {
	ue := c.checks.UserIDEnumeration
	cols := []string{MetricUserIDs, MetricUserIDsOK, MetricUserIDsDenied}
	if ue.CountsRedirects() {
		cols = append(cols, MetricUserDeniedRedirects)
	}
	vals := map[string]dayValues{}
	for _, m := range append(append([]string{}, cols...), MetricUserIDsMethods) {
		vals[m] = dayValues{}
	}
	tplOf := map[string]string{}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		user, okUser := userKey(r)
		tpl := c.prof.paths.Sanitize(r[rlTemplate])
		if !ok || !okUser || !strings.Contains(tpl, "/"+pathids.ID) {
			continue
		}
		key := user + "|" + tpl
		tplOf[key] = tpl
		for _, m := range cols {
			vals[m].add(day, key, nonNeg(r, m))
		}
		known := 0.0
		for i, m := range userMethods {
			n := nonNeg(r, "u_s"+strconv.Itoa(i))
			known += n
			if n > 0 {
				vals[MetricUserIDsMethods].add(day, key+"|"+m, n)
			}
		}
		if other := nonNeg(r, "u_rq") - known; other > 0 {
			vals[MetricUserIDsMethods].add(day, key+"|"+userMethodOther, other)
		}
	}
	for _, day := range sortedDays(vals[MetricUserIDs]) {
		ids := vals[MetricUserIDs][day]
		kept := topKeysMin(ids, float64(ue.StoreMin), ue.StoreTop)
		dist := map[string][]float64{}
		for k, v := range ids {
			dist[tplOf[k]] = append(dist[tplOf[k]], v)
		}
		keptTpl := map[string]bool{}
		for _, k := range kept {
			keptTpl[tplOf[k]] = true
			for _, m := range cols {
				if err := c.emitUser(ctx, sink, day, m, k, vals[m][day][k]); err != nil {
					return err
				}
			}
			for _, m := range append(append([]string{}, userMethods...), userMethodOther) {
				if v := vals[MetricUserIDsMethods][day][k+"|"+m]; v > 0 {
					if err := c.emitUser(ctx, sink, day, MetricUserIDsMethods, k+"|"+m, v); err != nil {
						return err
					}
				}
			}
		}
		for _, tpl := range sortedDays(keptTpl) {
			hist := map[float64]float64{}
			for _, v := range dist[tpl] {
				hist[v]++
			}
			p50, p99, mx := HistPercentiles(hist)
			out := []struct {
				k string
				v float64
			}{{userIDsDistUsers, float64(len(dist[tpl]))}, {userIDsMax, mx}}
			if !truncated {
				out = append(out, struct {
					k string
					v float64
				}{"p50", p50}, struct {
					k string
					v float64
				}{"p99", p99})
			}
			for _, x := range out {
				if err := c.emitUser(ctx, sink, day, MetricUserIDsDist, tpl+"|"+x.k, x.v); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
