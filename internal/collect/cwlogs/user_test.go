package cwlogs

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// ユーザー ID と auth の行 (ADR 0052) のテスト。アプリが足す行の見本は架空の値。実 AWS には接続しない (cwlogstest.Sim)。

// 見本の設定 (docs/ai/request_lines.md と同じ)。Logger の前置きの終わり (` -- : `) とタグから、行末まで。
const (
	actorRegex = ` -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})(?: by=(?P<by_kind>[a-z_]{1,32}):(?P<by_id>[A-Za-z0-9_-]{1,64}))?$`
	authRegex  = ` -- : \[[A-Za-z0-9_@-]{1,255}\] auth result=(?P<auth_result>success|failure|impersonate) kind=(?P<auth_kind>[a-z_]{1,32}) id=(?P<auth_id>[A-Za-z0-9_-]{1,64})(?: via=(?P<auth_via>password|remember))?(?: by=(?P<auth_by_kind>[a-z_]{1,32}):(?P<auth_by_id>[A-Za-z0-9_-]{1,64}))?(?: reason=(?P<auth_reason>[a-z_]{1,64}))?$`
	// 緩い設定 (値の形を絞らない)。arata の側の規則が効くことを確かめるのに使う
	looseActor = `\] actor kind=(?P<user_kind>\S*) id=(?P<user_id>.*)$`
	looseAuth  = `\] auth result=(?P<auth_result>\S*)(?: via=(?P<auth_via>\S*))?(?: reason=(?P<auth_reason>\S*))?$`
)

func userSource(actor, auth string) config.Source {
	s := railsSource()
	if actor != "" {
		s.Request.UserID = &config.RequestUserID{From: config.UserIDFromAppLine, Regex: actor}
	}
	if auth != "" {
		s.Request.Auth = &config.RequestAuth{Regex: auth}
	}
	return s
}

// userReq は 1 リクエスト分の行に、アプリが足す行 (extra。本文だけ) を最後の行の前に挟む。
func userReq(at time.Time, id, method, uri, ip string, status int, extra ...string) []cwlogstest.Event {
	ev := railsReq(at, "", id, method, uri, ip, status)
	last := ev[len(ev)-1]
	ev = ev[:len(ev)-1]
	for i, body := range extra {
		ev = append(ev, railsLine(at.Add(time.Duration(5+i)*time.Millisecond), "", id, body))
	}
	return append(ev, last)
}

var userWindow = collect.Window{From: now.Add(-24 * time.Hour), To: now}

func kindsOf(c *Collector) string {
	var out []string
	for _, k := range c.Yields() {
		out = append(out, string(k))
	}
	return strings.Join(out, ",")
}

func TestUserQueries(t *testing.T) {
	c := abuseChecks()
	col, err := New(userSource(actorRegex, authRegex), c, &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, q := range col.queries() {
		fmt.Fprintf(&b, "# %s (bin: %s)\n%s\n\n", q.Name, q.Bin, q.Query)
		(&cwlogstest.Sim{}).Rows(q.Query, now, now, nil) // 同じ一時フィールドを 2 度定義していない
		if len(q.Query) > 10000 {
			t.Fatalf("%s: クエリが Insights の上限 (10000 文字) を超える: %d", q.Name, len(q.Query))
		}
		// actor / auth の行を読むのは解釈率のクエリだけ (ほかの集計は今のまま。本数も増やさない)
		if has := strings.Contains(q.Query, "actor kind="); has != (q.Name == httpLines) {
			t.Fatalf("%s: actor の parse の有無が違う:\n%s", q.Name, q.Query)
		}
	}
	lines := col.queries()[0].Query
	for _, want := range []string{
		// 取り出した値は、設定の正規表現とは別に、決まった形と突き合わせる (合わない値は項目にならない)
		`| parse rl_user_kind /^(?<rl_v_user_kind>[a-z_]{1,32})$/`,
		`| parse rl_user_id /^(?<rl_v_user_id>[A-Za-z0-9_-]{1,64})$/`,
		`| parse rl_by_id /^(?<rl_v_by_id>[A-Za-z0-9_-]{1,64})$/`,
		`| parse rl_auth_result /^(?<rl_v_auth_result>success|failure|impersonate)$/`,
		`| parse rl_auth_via /^(?<rl_v_auth_via>password|remember)$/`,
		`| parse rl_auth_reason /^(?<rl_v_auth_reason>[a-z_]{1,64})$/`,
		// 行末の $ は、行の印の括弧の外 (実データで確かめた形)
		`(?<rl_by_id>[A-Za-z0-9_-]{1,64}))?)$/`, `(?<rl_auth_reason>[a-z_]{1,64}))?)$/`,
		// 最後の行の値を使う
		"latest(rl_v_user_id) as user_id", "latest(rl_v_by_kind) as by_kind", "latest(rl_v_auth_result) as auth_result", "latest(rl_v_auth_id) as auth_id",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("解釈率のクエリに %q が無い:\n%s", want, lines)
		}
	}
	// 形と突き合わせる前の値 (rl_user_id など) は、1 段目より後ろに渡さない
	stage1 := lines[strings.Index(lines, "| stats "):]
	for _, raw := range []string{"(rl_user_id)", "(rl_user_kind)", "(rl_by_id)", "(rl_auth_result)", "(rl_auth_reason)", "(rl_auth_id)"} {
		if strings.Contains(stage1, raw) {
			t.Errorf("形を確かめる前の値 %s を集計に渡している:\n%s", raw, stage1)
		}
	}
	checkGolden(t, "request_user_queries.golden", b.String())
	if col.QueryCount() != 3 {
		t.Fatalf("本数は増やさない: %d", col.QueryCount())
	}
	// 書いていないソースのクエリは変わらない (request_queries.golden が固定している) し、http_user も出さない
	plain, _ := New(railsSource(), c, &cwlogstest.Fake{})
	if kindsOf(plain) != "http_access" || plain.Unavailable() != nil {
		t.Fatalf("user_id の無いソース: %s %v", kindsOf(plain), plain.Unavailable())
	}
	if kindsOf(col) != "http_access,http_user" {
		t.Fatalf("yields: %s", kindsOf(col))
	}
	// auth だけを書いたソースは http_user を出さない
	authOnly, _ := New(userSource("", authRegex), c, &cwlogstest.Fake{})
	if kindsOf(authOnly) != "http_access" {
		t.Fatalf("auth だけ: %s", kindsOf(authOnly))
	}
}

func TestUserCollect(t *testing.T) {
	var ev []cwlogstest.Event
	n := 0
	add := func(count int, method, uri, ip string, status int, extra ...string) {
		for i := 0; i < count; i++ {
			n++
			ev = append(ev, userReq(day21(1, n/60, n%60), rid(n), method, uri, ip, status, extra...)...)
		}
	}
	add(40, "GET", "/", "192.0.2.200", 200)                                         // ログイン前
	add(30, "GET", "/items", "192.0.2.200", 200, "actor kind=user id=42")           // 利用者
	add(10, "GET", "/admin", "192.0.2.201", 200, "actor kind=staff id=5")           // スタッフ
	add(4, "GET", "/items", "192.0.2.201", 200, "actor kind=user id=42 by=staff:5") // 代わりにログインした操作
	add(3, "POST", "/users/sign_in", "198.51.100.7", 302, "auth result=success kind=user id=42 via=password", "actor kind=user id=42")
	add(1, "GET", "/", "198.51.100.7", 200, "auth result=success kind=user id=43 via=remember", "actor kind=user id=43")
	add(5, "POST", "/users/sign_in", "198.51.100.7", 422, "auth result=failure kind=user id=42 reason=invalid")
	add(2, "POST", "/users/sign_in", "198.51.100.7", 422, "auth result=failure kind=user id=none reason=not_found_in_database")
	add(1, "POST", "/staff/impersonate", "192.0.2.201", 302, "auth result=impersonate kind=user id=42 by=staff:5", "actor kind=user id=42 by=staff:5")
	sink, col, f, err := collectRequests(t, userSource(actorRegex, authRegex), checksCfg(), ev, userWindow)
	if err != nil {
		t.Fatal(err)
	}
	rs := col.FormatStats().Requests
	if rs.Starts != 96 || rs.Users == nil || rs.Auth == nil {
		t.Fatalf("requests: %+v", rs)
	}
	u, a := rs.Users, rs.Auth
	if u.From != "app_line" || u.Requests != 49 || u.By != 5 || u.Invalid != 0 || fmt.Sprint(u.Kinds) != "map[staff:10 user:39]" {
		t.Fatalf("users: %+v", u)
	}
	if rate, ok := rs.UserRate(); !ok || round(rate) != 0.51 {
		t.Fatalf("ID の付いた割合: %v %v", rate, ok)
	}
	if a.Success != 4 || fmt.Sprint(a.Via) != "map[password:3 remember:1]" || a.Failure != 7 || fmt.Sprint(a.Reasons) != "map[invalid:5 not_found_in_database:2]" ||
		a.Impersonate != 1 || a.Invalid != 0 {
		t.Fatalf("auth: %+v", a)
	}
	m := sink.metrics()
	for k, want := range map[string]float64{
		"2026-10-21|user_requests|user": 39, "2026-10-21|user_requests|staff": 10, "2026-10-21|user_requests_by|": 5, "2026-10-21|user_id_invalid|": 0,
		"2026-10-21|auth_success|password": 3, "2026-10-21|auth_success|remember": 1, "2026-10-21|auth_failures|invalid": 5,
		"2026-10-21|auth_failures|not_found_in_database": 2, "2026-10-21|auth_impersonate|": 1, "2026-10-21|auth_invalid|": 0,
		// 段 0 の集計は変わらない
		"2026-10-21|sign_in_failures|198.51.100.7": 7, "2026-10-21|requests_total|": 96,
	} {
		if got, ok := m[k]; !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", k, got, ok, want)
		}
	}
	for _, r := range sink.recs {
		mt := r.(record.Metric)
		isUser := strings.HasPrefix(mt.Metric, "user_") || strings.HasPrefix(mt.Metric, "auth_")
		if isUser != (mt.From == record.KindHTTPUser) {
			t.Errorf("%s の From が %s", mt.Metric, mt.From)
		}
	}
	if col.Unavailable() != nil {
		t.Fatalf("ID の付いたリクエストがあるのに http_user が取れない扱い: %v", col.Unavailable())
	}
	// クエリの本数は段 0 と同じ (解釈率 + 集計 1 本。endpoint_abuse は設定に無い)
	if got := len(f.Queries()); got != 3 {
		t.Fatalf("クエリの本数: %d\n%s", got, strings.Join(f.Queries(), "\n---\n"))
	}
	// doctor 用のまとめにも同じ値と、行の種類ごとの数が出る
	s, err := col.RequestSummary(t.Context(), userWindow.From, userWindow.To)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, k := range s.Kinds {
		kinds = append(kinds, fmt.Sprintf("%s=%d", k.Name, k.Lines))
	}
	if got := strings.Join(kinds, " "); got != "started=96 completed=96 no_route=0 user_id=49 auth=12" || s.Stats.Users.Requests != 49 {
		t.Fatalf("summary: %s %+v", got, s.Stats.Users)
	}
}

// 設定に書いていても、ID の付いたリクエストが 0 件の run では http_user を出さなかったものとして扱う (ADR 0051 の 2 節・4 節)。
func TestUserNone(t *testing.T) {
	var ev []cwlogstest.Event
	for i := 0; i < 20; i++ {
		ev = append(ev, userReq(day21(1, 0, i), rid(i), "GET", "/", "192.0.2.200", 200)...)
	}
	for _, from := range []string{config.UserIDFromAppLine, config.UserIDFromDebugSQL} {
		src := userSource(actorRegex, "")
		src.Request.UserID.From = from
		sink, col, _, err := collectRequests(t, src, checksCfg(), ev, userWindow)
		if err != nil {
			t.Fatal(err)
		}
		if kindsOf(col) != "http_access,http_user" {
			t.Fatalf("yields: %s", kindsOf(col))
		}
		reason := col.Unavailable()[record.KindHTTPUser]
		if !strings.Contains(reason, "0 件") || !strings.Contains(reason, "request.user_id.from: "+from) {
			t.Fatalf("%s: 0 件の run の理由: %q", from, reason)
		}
		rs := col.FormatStats().Requests
		if rs.Users == nil || rs.Users.Requests != 0 || rs.Auth != nil {
			t.Fatalf("users: %+v auth: %+v", rs.Users, rs.Auth)
		}
		if rate, ok := rs.UserRate(); !ok || rate != 0 {
			t.Fatalf("rate: %v %v", rate, ok)
		}
		m := sink.metrics()
		// 段 0 は同じに動く。0 件であることも日次で残す (取れなくなった日が後から分かる)
		if m["2026-10-21|requests_total|"] != 20 || len(m) == 0 {
			t.Fatalf("metrics: %v", m)
		}
		if _, ok := m["2026-10-21|user_id_invalid|"]; !ok {
			t.Fatalf("user_id_invalid が無い: %v", m)
		}
		for k := range m {
			if strings.Contains(k, "|user_requests|") || strings.Contains(k, "|auth_") {
				t.Fatalf("0 件なのに %s を出した", k)
			}
		}
	}
	// 収集の前 (まだ測っていない) も「取れている」とは言わない
	col, _ := New(userSource(actorRegex, ""), checksCfg(), &cwlogstest.Fake{})
	if col.Unavailable()[record.KindHTTPUser] == "" {
		t.Fatalf("収集の前: %v", col.Unavailable())
	}
}

// 値の形は arata が規則で絞る。設定の正規表現が緩くても、形に合わない値は捨てて数だけ残す (ADR 0052 の 4 節)。
func TestUserInvalidValues(t *testing.T) {
	var ev []cwlogstest.Event
	n := 0
	add := func(extra ...string) {
		n++
		ev = append(ev, userReq(day21(1, 0, n), rid(n), "GET", "/", "192.0.2.200", 200, extra...)...)
	}
	add("actor kind=user id=42")
	add("actor kind=user id=alice@example.com")          // メールアドレスを ID にしている
	add("actor kind=user id=" + strings.Repeat("9", 65)) // 長すぎる
	add("actor kind=User id=42")                         // 種類の形が違う
	add("actor kind=user id=42 by=staff:5")              // 緩い設定では by まで ID に入る
	add("actor kind=user id=")                           // 空
	add("auth result=success via=password")
	add("auth result=failure reason=invalid")
	add("auth result=failure reason=Bad-Reason") // 理由の形が違う → 理由なしの失敗
	add("auth result=success via=sso")           // 手段の形が違う → 手段なしの成功
	add("auth result=denied")                    // 結果の形が違う
	add("auth result=")
	sink, col, _, err := collectRequests(t, userSource(looseActor, looseAuth), checksCfg(), ev, userWindow)
	if err != nil {
		t.Fatal(err)
	}
	u, a := col.FormatStats().Requests.Users, col.FormatStats().Requests.Auth
	if u.Requests != 1 || u.Invalid != 5 || u.By != 0 || fmt.Sprint(u.Kinds) != "map[user:1]" {
		t.Fatalf("users: %+v", u)
	}
	if a.Success != 2 || a.Failure != 2 || a.Invalid != 2 || fmt.Sprint(a.Via) != "map[:1 password:1]" || fmt.Sprint(a.Reasons) != "map[:1 invalid:1]" {
		t.Fatalf("auth: %+v", a)
	}
	m := sink.metrics()
	if m["2026-10-21|user_id_invalid|"] != 5 || m["2026-10-21|auth_invalid|"] != 2 || m["2026-10-21|auth_failures|"] != 1 || m["2026-10-21|auth_success|"] != 1 {
		t.Fatalf("metrics: %v", m)
	}
	// 捨てた値は、record にも理由にも残らない
	checkRecords(t, sink.recs, "alice@example.com", "Bad-Reason", "sso", "denied", "User", strings.Repeat("9", 65))
}

// 行の途中の同じ並び (利用者の入力) と、入力の改行で作られた続きの行 (Logger の前置きが無い) は、actor / auth の行として読まない。
// 1 つのリクエストに actor の行が複数あれば、最後の行を使う。
func TestUserForgedLines(t *testing.T) {
	cont := func(at time.Time, id, body string) cwlogstest.Event {
		return cwlogstest.Event{Time: at, Fields: map[string]string{"@message": "[" + id + "] " + body}}
	}
	var ev []cwlogstest.Event
	// 1: Parameters の中に同じ並び。2: 続きの行。3: 行末に余分な文字。どれも ID なしのリクエスト
	ev = append(ev, userReq(day21(1, 0, 1), rid(1), "GET", "/search", "198.51.100.7", 200, `  Parameters: {"q"=>"actor kind=staff id=1"}`)...)
	ev = append(ev, userReq(day21(1, 0, 2), rid(2), "GET", "/search", "198.51.100.7", 200, "note: x")...)
	ev = append(ev, cont(day21(1, 0, 2).Add(6*time.Millisecond), rid(2), "actor kind=staff id=1"), cont(day21(1, 0, 2).Add(6*time.Millisecond), rid(2), "auth result=success kind=staff id=1 via=password"))
	ev = append(ev, userReq(day21(1, 0, 3), rid(3), "GET", "/search", "198.51.100.7", 200, "actor kind=staff id=1 extra", "auth result=success kind=staff id=1 via=password x")...)
	// 4: 本物の行が 2 つ (認証の失敗で画面を描き直した)。最後の行を使う
	ev = append(ev, userReq(day21(1, 0, 4), rid(4), "GET", "/items", "192.0.2.200", 200, "actor kind=user id=41", "actor kind=staff id=7 by=staff:5")...)
	src := userSource(actorRegex, authRegex)
	_, col, _, err := collectRequests(t, src, checksCfg(), ev, userWindow)
	if err != nil {
		t.Fatal(err)
	}
	u, a := col.FormatStats().Requests.Users, col.FormatStats().Requests.Auth
	if u.Requests != 1 || u.Invalid != 0 || fmt.Sprint(u.Kinds) != "map[staff:1]" || u.By != 1 || a.Success != 0 || a.Invalid != 0 {
		t.Fatalf("users: %+v auth: %+v", u, a)
	}

	// リクエスト単位の中間の形 (1 段目の結果)。段 1 のチェック (次の PR) は、この列を 2 段目の軸や条件に使う
	q := col.Profile().head("1d", "day", "", nil, false, false, true) +
		"\n| stats sum(rl_starts) as n by day, ip, path, status, user_kind, user_id, by_kind, by_id, auth_result"
	rows := (&cwlogstest.Sim{Events: ev}).Rows(q, userWindow.From, userWindow.To, nil)
	var got []string
	for _, r := range rows {
		got = append(got, fmt.Sprintf("%s %s %s %s|%s:%s by %s:%s|%s n=%s", r["day"][:10], r["ip"], r["path"], r["status"], r["user_kind"], r["user_id"], r["by_kind"], r["by_id"], r["auth_result"], r["n"]))
	}
	want := "2026-10-21 198.51.100.7 /search 200|: by :| n=3\n2026-10-21 192.0.2.200 /items 200|staff:7 by staff:5| n=1"
	if strings.Join(got, "\n") != want {
		t.Fatalf("中間の形:\n%s\nwant:\n%s", strings.Join(got, "\n"), want)
	}
}
