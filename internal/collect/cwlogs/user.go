package cwlogs

import (
	"context"
	"fmt"
	"strings"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// ユーザー ID と auth の行 (ADR 0051 の 4 節・0052): request_lines のソースが、アプリの足した 2 種類の行
// (`actor kind=… id=… [by=…]` と `auth result=… …`) を読み、リクエスト単位の項目にする。
//
// クエリの形 (解釈率のクエリの 1 段目の前後に足す。ほかの集計のクエリは変えない):
//
//	| parse @message /(?<rl_ku><request.user_id.regex>)$/       … rl_user_kind, rl_user_id, rl_by_kind, rl_by_id と、行の印 rl_ku (行末の $ は括弧の外)
//	| parse rl_user_kind /^(?<rl_v_user_kind>[a-z_]{1,32})$/    … 値の形と突き合わせる。合わない値は rl_v_… にならない
//	| parse rl_user_id /^(?<rl_v_user_id>[A-Za-z0-9_-]{1,64})$/
//	| parse @message /(?<rl_ka><request.auth.regex>)$/          … rl_auth_result … と、行の印 rl_ka
//	| parse rl_auth_result /^(?<rl_v_auth_result>success|failure|impersonate)$/
//	…
//	| stats …, count(rl_ku) as rl_user_lines, count(rl_v_user_id) as rl_users, latest(rl_v_user_kind) as user_kind, latest(rl_v_user_id) as user_id, … by rl_request_id
//	| stats … by day, …, user_kind, rl_users, rl_user_lines, rl_bys, auth_result, auth_via, auth_reason, rl_auth_lines
//
// 決定 (ADR 0052):
//   - 値の形は arata が規則で絞る。設定の正規表現がどう書かれていても、形に合わない値 (メールアドレス・長すぎる値など) は
//     クエリの中で捨て、1 段目より後ろには形に合った値 (rl_v_…) だけを渡す。結果を読む Go の側でも同じ規則でもう一度確かめる。
//     捨てた値は数だけ残す (user_id_invalid / auth_invalid)。値そのものは結果にもログにも出さない
//   - 1 つの request_id に行が複数あれば、最後の行の値を使う (ステータスと同じ)
//   - 割合のために専用のクエリは足さない。解釈率のクエリの 2 段目の軸に足す (Insights の費用は本数に比例する。ADR 0031)
//   - ユーザー ID の付いたリクエストが 0 件の run では、http_user を出さなかったものとして扱う (Unavailable。engine が http_user の要るチェックを skip する)
//   - ユーザー ID を key に置く集計は、ここでは作らない (段 1 のチェックが足す)。1 段目の結果には user_id などの列を出してあり、2 段目の軸に使える
const (
	rlUserFlag  = "rl_ku"         // actor の行の印
	rlAuthFlag  = "rl_ka"         // auth の行の印
	rlValid     = "rl_v_"         // 形に合った値の一時フィールドの接頭辞
	rlUserLines = "rl_user_lines" // 1 つの request_id の actor の行の数
	rlUsers     = "rl_users"      // そのうち ID が形に合った行の数
	rlBys       = "rl_bys"        // by の ID が形に合った行の数
	rlAuthLines = "rl_auth_lines" // 1 つの request_id の auth の行の数
	rlKindUser  = "rl_kind_user"  // actor の行の数の和 (doctor の「行の種類」)
	rlKindAuth  = "rl_kind_auth"
)

// request_lines のソースが出す日次の metric (From は http_user)。
const (
	MetricUserRequests    = "user_requests"    // 形に合ったユーザー ID の付いたリクエストの数 (key = 種類)
	MetricUserRequestsBy  = "user_requests_by" // そのうち by (代わりにログインした操作) の付いた数 (key なし)
	MetricUserIDInvalid   = "user_id_invalid"  // actor の行はあるが、値が形に合わず捨てたリクエストの数 (key なし)
	MetricAuthSuccess     = "auth_success"     // auth が success のリクエストの数 (key = 手段。無ければ空)
	MetricAuthFailures    = "auth_failures"    // auth が failure のリクエストの数 (key = 理由。無ければ空)
	MetricAuthImpersonate = "auth_impersonate" // auth が impersonate のリクエストの数 (key なし)
	MetricAuthInvalid     = "auth_invalid"     // auth の行はあるが、結果の値が形に合わず捨てたリクエストの数 (key なし)
)

// 値の形 (ADR 0052 の 4 節の表)。クエリの中の突き合わせ (Insights の正規表現) と Go の判定 (Valid*) は同じものを受ける (FuzzUserValues)。
const (
	userKindPattern   = `[a-z_]{1,32}`
	userIDPattern     = `[A-Za-z0-9_-]{1,64}`
	authResultPattern = `success|failure|impersonate`
	authViaPattern    = `password|remember`
	authReasonPattern = `[a-z_]{1,64}`
)

const (
	authSuccess     = "success"
	authFailure     = "failure"
	authImpersonate = "impersonate"
	// maxUserKeys は種類・手段・理由ごとの数の key の上限。超えた分は otherKey にまとめる (ログ由来の値で key を増やし続けられないように)。
	maxUserKeys = 32
	otherKey    = "other"
)

// valuePatterns は名前付きキャプチャごとの値の形。
// auth_id の `none` (利用者を引けなかった) は ID の形に合うので、列にはそのまま出る。auth_id を軸に使う集計 (段 1 のチェック) は、`none` を ID なしとして除く。
var valuePatterns = map[string]string{
	"user_kind": userKindPattern, "user_id": userIDPattern, "by_kind": userKindPattern, "by_id": userIDPattern,
	"auth_result": authResultPattern, "auth_kind": userKindPattern, "auth_id": userIDPattern, "auth_via": authViaPattern,
	"auth_by_kind": userKindPattern, "auth_by_id": userIDPattern, "auth_reason": authReasonPattern,
}

func lowerWord(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

// ValidUserKind は利用者の種類の形 (小文字と _ の 32 文字まで) か。
func ValidUserKind(s string) bool { return lowerWord(s, 32) }

// ValidUserID はユーザー ID の形 (英数字・_・- の 64 文字まで) か。メールアドレスなど、ほかの文字を含む値は ID として扱わない。
func ValidUserID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func validAuthResult(s string) bool {
	return s == authSuccess || s == authFailure || s == authImpersonate
}
func validAuthVia(s string) bool    { return s == "password" || s == "remember" }
func validAuthReason(s string) bool { return lowerWord(s, 64) }

// userProfile は request.user_id / request.auth から、行の parse と値の突き合わせを作る (どちらも無ければ何もしない)。
func userProfile(st *requestStage, r *config.Request) error {
	ug, err := r.UserGroups()
	if err != nil {
		return err
	}
	ag, err := r.AuthGroups()
	if err != nil {
		return err
	}
	var parts []string
	add := func(flag, expr string, groups []string) {
		// 行の印のために全体を名前付きのキャプチャで包む。行末の $ は括弧の外に置く (config が「$ で終わる」ことを確かめている。
		// 実データで確かめた形 `(?<名前>…)$` に合わせる。意味は同じ)
		parts = append(parts, "parse @message /(?<"+flag+">"+escapeSlashes(prefixCaptures(strings.TrimSuffix(expr, "$"), rlPrefix))+")$/")
		for _, g := range groups {
			parts = append(parts, "parse "+rlPrefix+g+" /^(?<"+rlValid+g+">"+valuePatterns[g]+")$/")
		}
	}
	if len(ug) > 0 {
		st.userFrom, st.userFields = r.UserID.From, ug
		add(rlUserFlag, r.UserID.Regex, ug)
	}
	if len(ag) > 0 {
		st.authFields = ag
		add(rlAuthFlag, r.Auth.Regex, ag)
	}
	st.userPrelude = strings.Join(parts, "\n| ")
	return nil
}

func (st *requestStage) hasUserField(name string) bool { return containsStr(st.userFields, name) }
func (st *requestStage) hasAuthField(name string) bool { return containsStr(st.authFields, name) }

// userAggs は 1 段目に足す集計 (行の数と、形に合った最後の値)。
func (st *requestStage) userAggs() []string {
	var aggs []string
	if len(st.userFields) > 0 {
		aggs = append(aggs, "count("+rlUserFlag+") as "+rlUserLines, "count("+rlValid+"user_id) as "+rlUsers)
		if st.hasUserField("by_id") {
			aggs = append(aggs, "count("+rlValid+"by_id) as "+rlBys)
		}
		for _, g := range st.userFields {
			aggs = append(aggs, "latest("+rlValid+g+") as "+g)
		}
	}
	if len(st.authFields) > 0 {
		aggs = append(aggs, "count("+rlAuthFlag+") as "+rlAuthLines)
		for _, g := range st.authFields {
			aggs = append(aggs, "latest("+rlValid+g+") as "+g)
		}
	}
	return aggs
}

// userLines は解釈率のクエリの 2 段目に足す集計 (行の種類ごとの数) と軸。
func (st *requestStage) userLines() (aggs, group []string) {
	if len(st.userFields) > 0 {
		aggs = append(aggs, "sum("+rlUserLines+") as "+rlKindUser)
		group = append(group, "user_kind", rlUsers, rlUserLines)
		if st.hasUserField("by_id") {
			group = append(group, rlBys)
		}
	}
	if len(st.authFields) > 0 {
		aggs = append(aggs, "sum("+rlAuthLines+") as "+rlKindAuth)
		group = append(group, "auth_result")
		for _, g := range []string{"auth_via", "auth_reason"} {
			if st.hasAuthField(g) {
				group = append(group, g)
			}
		}
		group = append(group, rlAuthLines)
	}
	return aggs, group
}

// newStats はこのソースのリクエスト単位の集計の入れ物 (ユーザー ID・auth を読む設定なら、その分も数える)。st が nil でもよい。
func (st *requestStage) newStats(expected float64) collect.RequestStats {
	rs := collect.RequestStats{Expected: expected}
	if st == nil {
		return rs
	}
	if len(st.userFields) > 0 {
		rs.Users = &collect.UserStats{From: st.userFrom, Kinds: map[string]int64{}}
	}
	if len(st.authFields) > 0 {
		rs.Auth = &collect.AuthStats{Via: map[string]int64{}, Reasons: map[string]int64{}}
	}
	return rs
}

// readUserRow は解釈率のクエリの結果の 1 行のうち、ユーザー ID と auth の列を読む。
//
// 決定 (ADR 0052): クエリの中で形と突き合わせた値を、ここでもう一度確かめる (Insights の結果はログ由来の値)。
// 形に合わない値は項目にせず、行があったことだけを「捨てた」として残す。種類の無い ID・ID の無い種類は ID つきにしない。
// 手段は成功のとき、理由は失敗のときだけ読む (形に合わなければ、手段・理由なしの成功・失敗)。
func readUserRow(r map[string]string, rr *requestRow) {
	if kind := r["user_kind"]; num(r[rlUsers]) > 0 && ValidUserKind(kind) {
		rr.User, rr.UserKind = true, kind
		rr.By = num(r[rlBys]) > 0
	} else if num(r[rlUserLines]) > 0 {
		rr.UserInvalid = true
	}
	switch res := r["auth_result"]; {
	case validAuthResult(res):
		rr.Auth = res
		if via := r["auth_via"]; res == authSuccess && validAuthVia(via) {
			rr.AuthVia = via
		}
		if reason := r["auth_reason"]; res == authFailure && validAuthReason(reason) {
			rr.AuthReason = reason
		}
	case num(r[rlAuthLines]) > 0:
		rr.AuthInvalid = true
	}
}

// addKey は key ごとの数に n を足す。key の数が上限に達していれば otherKey にまとめる。
func addKey(m map[string]int64, key string, n int64) {
	if _, ok := m[key]; !ok && len(m) >= maxUserKeys {
		key = otherKey
	}
	m[key] += n
}

// addUserRow は rr を、ユーザー ID と auth の集計に足す (hits は rr の数えるリクエストの数)。
func addUserRow(st *collect.RequestStats, rr requestRow, hits int64) {
	if hits <= 0 {
		return
	}
	if u := st.Users; u != nil {
		switch {
		case rr.User:
			u.Requests += hits
			addKey(u.Kinds, rr.UserKind, hits)
			if rr.By {
				u.By += hits
			}
		case rr.UserInvalid:
			u.Invalid += hits
		}
	}
	if a := st.Auth; a != nil {
		switch {
		case rr.Auth == authSuccess:
			a.Success += hits
			addKey(a.Via, rr.AuthVia, hits)
		case rr.Auth == authFailure:
			a.Failure += hits
			addKey(a.Reasons, rr.AuthReason, hits)
		case rr.Auth == authImpersonate:
			a.Impersonate += hits
		case rr.AuthInvalid:
			a.Invalid += hits
		}
	}
}

// userConfigured はユーザー ID を取り出す設定のあるソースか (http_user を出す)。
func (c *Collector) userConfigured() bool { return c.prof.req != nil && c.prof.req.userFrom != "" }

var _ collect.AvailabilityReporter = (*Collector)(nil)

// Unavailable は、ユーザー ID を取り出す設定はあるが、直近の Collect で ID の付いたリクエストが 0 件だったときに http_user を返す。
//
// 決定 (ADR 0051 の 2 節・4 節): 「取れなくなった」を「何も起きていない」と取り違えない。engine は http_user を必要とするチェックを skip し、
// coverage.checks_skipped に理由を出す。http_access の集計 (段 0) はそのまま動く。
func (c *Collector) Unavailable() map[record.Kind]string {
	if !c.userConfigured() {
		return nil
	}
	if c.stats != nil && c.stats.Requests != nil && c.stats.Requests.Users != nil && c.stats.Requests.Users.Requests > 0 {
		return nil
	}
	return map[record.Kind]string{record.KindHTTPUser: fmt.Sprintf(
		"ユーザー ID の付いたリクエストがこの run に 0 件 (request.user_id.from: %s)。ユーザー ID の要るチェックは見ていない", c.prof.req.userFrom)}
}

// warnUsers は、ユーザー ID が 0 件・捨てた値があることを WARN に出す。
func (c *Collector) warnUsers() {
	rs := c.stats.Requests
	if rs == nil {
		return
	}
	if u := rs.Users; u != nil {
		if u.Requests == 0 && rs.Starts > 0 {
			c.Logger.Warn("no requests with a user id; checks that need http_user are skipped in this run", "code", codes.UserIDMissing, "source", c.src.ID, "log_group", c.src.LogGroup,
				"from", u.From, "requests", rs.Starts)
		}
		if u.Invalid > 0 {
			c.Logger.Warn("user ids that do not fit the allowed form were dropped (letters, digits, _ and -, up to 64)", "code", codes.UserIDInvalid, "source", c.src.ID, "requests", u.Invalid)
		}
	}
	if a := rs.Auth; a != nil && a.Invalid > 0 {
		c.Logger.Warn("auth results that do not fit the allowed form were dropped", "code", codes.UserIDInvalid, "source", c.src.ID, "requests", a.Invalid)
	}
}

// emitUsers は 1 日分のユーザー ID と auth の集計を日次の metric にする (From は http_user)。
func (c *Collector) emitUsers(ctx context.Context, day string, st *collect.RequestStats, sink collect.RecordSink) error {
	emit := func(name, key string, v int64) error {
		return sink.Emit(ctx, record.Metric{Date: day, Source: c.src.ID, From: record.KindHTTPUser, Metric: name, Key: key, Value: float64(v)})
	}
	keyed := func(name string, m map[string]int64) error {
		for _, k := range sortedDays(m) {
			if err := emit(name, k, m[k]); err != nil {
				return err
			}
		}
		return nil
	}
	if u := st.Users; u != nil {
		if err := keyed(MetricUserRequests, u.Kinds); err != nil {
			return err
		}
		if err := emit(MetricUserRequestsBy, "", u.By); err != nil {
			return err
		}
		if err := emit(MetricUserIDInvalid, "", u.Invalid); err != nil {
			return err
		}
	}
	if a := st.Auth; a != nil {
		if err := keyed(MetricAuthSuccess, a.Via); err != nil {
			return err
		}
		if err := keyed(MetricAuthFailures, a.Reasons); err != nil {
			return err
		}
		if err := emit(MetricAuthImpersonate, "", a.Impersonate); err != nil {
			return err
		}
		if err := emit(MetricAuthInvalid, "", a.Invalid); err != nil {
			return err
		}
	}
	return nil
}
