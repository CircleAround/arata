package cwlogs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// ログインした利用者の総当たりの日の値 (U1・U2。ADR 0071 の 6 節・0087 の 1 節)。値はすべて架空。実 AWS には接続しない (cwlogstest.Sim)。

// probeChecks は 3 つのチェックが web を数える設定 (store_min を小さくして、残す・残さないを見る)。
func probeChecks(sources ...string) config.Checks {
	c := config.DefaultChecks()
	c.UserDenied.Sources = sources
	c.UserIDEnumeration.Sources = sources
	c.UserPathBreadth.Sources = sources
	c.UserDenied.StoreMin, c.UserIDEnumeration.StoreMin, c.UserPathBreadth.StoreMin = 2, 3, 2
	return c
}

func probeSource(t *testing.T) config.Source {
	src := userSource(actorRegex, "")
	src.PathIDs = mustPathIDs(t, config.PathIDs{Segments: []string{`[0-9]{1,20}`}, Templates: []string{"/users/:id/orders"}, Formats: []string{"json"}, MaxSegments: 8})
	return src
}

// collectProbe は U1・U2 も Sim で答える Fake で Collect する。
func collectProbe(t *testing.T, src config.Source, c config.Checks, ev []cwlogstest.Event, w collect.Window, needs map[record.Kind]bool) (*sinkRecorder, *cwlogstest.Fake, error) {
	t.Helper()
	f := &cwlogstest.Fake{}
	sim := &cwlogstest.Sim{Events: ev}
	registerRequests(f, sim, c, src.ID)
	f.On("count(u_dn) as", sim.Response(nil))      // U1
	f.On("as "+MetricUserIDsOK, sim.Response(nil)) // U2
	col, err := New(src, c, f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return w.To }
	if needs != nil {
		col.Select(needs)
	}
	sink := &sinkRecorder{}
	return sink, f, col.Collect(t.Context(), w, sink)
}

// userMetrics は利用者ごとのチェックの日の値だけ ("<日>|<metric>|<key>" → 値)。
func userMetrics(s *sinkRecorder) map[string]float64 {
	out := map[string]float64{}
	for k, v := range s.metrics() {
		if m := strings.Split(k, "|")[1]; strings.HasPrefix(m, "user_ids") || strings.HasPrefix(m, "user_templates") || m == MetricUserDenied || m == MetricUserDeniedRedirects || m == MetricUserProbeDays {
			out[k] = v
		}
	}
	return out
}

func dump(m map[string]float64) string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %g\n", k, m[k])
	}
	return b.String()
}

// probeEvents は 1 日分のリクエスト。user:42 は /orders/:id の ID を順に開いて拒否され、1 つだけ開ける。user:43 はふだんの閲覧。
func probeEvents() []cwlogstest.Event {
	var ev []cwlogstest.Event
	n := 0
	req := func(method, uri string, status int, actor string) {
		n++
		var extra []string
		if actor != "" {
			extra = append(extra, actor)
		}
		ev = append(ev, userReq(day21(1, n/60, n%60), rid(n), method, uri, "192.0.2.10", status, extra...)...)
	}
	for id := 100; id < 106; id++ {
		req("GET", fmt.Sprintf("/orders/%d", id), 403, "actor kind=user id=42")
	}
	req("GET", "/orders/106.json", 200, "actor kind=user id=42") // 拡張子を外して同じ型
	req("GET", "/orders/100", 403, "actor kind=user id=42")      // 同じ ID をもう一度 (異なる ID は増えない)
	req("POST", "/orders/107", 404, "actor kind=user id=42")
	req("GET", "/users/taro/orders", 200, "actor kind=user id=42") // templates の :id (名前の区間)
	req("GET", "/items", 200, "actor kind=user id=42")
	req("GET", "/orders/1", 200, "actor kind=user id=43")
	req("GET", "/orders/2", 200, "actor kind=user id=43")
	req("GET", "/missing", 404, "actor kind=user id=43")
	// 代わりにログインした操作・ログイン前・形に合わない利用者は数えない
	for id := 200; id < 210; id++ {
		req("GET", fmt.Sprintf("/orders/%d", id), 403, "actor kind=user id=44 by=staff:5")
		req("GET", fmt.Sprintf("/orders/%d", id), 403, "")
	}
	return ev
}

func TestUserProbeMetrics(t *testing.T) {
	sink, _, err := collectProbe(t, probeSource(t), probeChecks("web"), probeEvents(), userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		// U1: 拒否 (401・403) の件数と型の数。user:43 の拒否は 0 で store_min (2) 未満なので残さない
		"2026-10-21|user_denied|user:42": 7,
		// 型: /orders/:id・/users/:id/orders・/items。2xx は 3 つとも、拒否は /orders/:id、404 も /orders/:id
		"2026-10-21|user_templates|user:42": 3, "2026-10-21|user_templates_ok|user:42": 3, "2026-10-21|user_templates_denied|user:42": 1, "2026-10-21|user_templates_not_found|user:42": 1,
		// user:43 は /orders/:id と /missing
		"2026-10-21|user_templates|user:43": 2, "2026-10-21|user_templates_ok|user:43": 1, "2026-10-21|user_templates_denied|user:43": 0, "2026-10-21|user_templates_not_found|user:43": 1,
		// U2: /orders/:id で 8 つの異なる ID (100〜107)。成功 1 (106)、拒否 7 (100〜105 の 403 と 107 の 404)
		"2026-10-21|user_ids|user:42|/orders/:id": 8, "2026-10-21|user_ids_ok|user:42|/orders/:id": 1, "2026-10-21|user_ids_denied|user:42|/orders/:id": 7,
		"2026-10-21|user_ids_methods|user:42|/orders/:id|GET": 8, "2026-10-21|user_ids_methods|user:42|/orders/:id|POST": 1,
		// 分布は user_ids を残した型だけ。user:43 の 2 (store_min 3 未満) も分布には入る
		"2026-10-21|user_ids_dist|/orders/:id|users": 2, "2026-10-21|user_ids_dist|/orders/:id|max": 8,
		"2026-10-21|user_ids_dist|/orders/:id|p50": 2, "2026-10-21|user_ids_dist|/orders/:id|p99": 8,
		// U1・U2 を流した日の印 (平常帯の蓄積待ちを数える。窓の始まりを含む日から)。値の残らなかった 10-20 にも付く
		"2026-10-20|user_probe_days|user_summary": 1, "2026-10-20|user_probe_days|user_ids": 1,
		"2026-10-21|user_probe_days|user_summary": 1, "2026-10-21|user_probe_days|user_ids": 1,
	}
	if got := userMetrics(sink); dump(got) != dump(want) {
		t.Fatalf("got:\n%swant:\n%s", dump(got), dump(want))
	}
	// key に置く利用者の ID・型には、対象 ID の値も名前の区間も入らない
	for k := range sink.metrics() {
		for _, bad := range []string{"taro", "100", "106", "staff", "user:44"} {
			if strings.Contains(k, bad) && strings.Contains(k, "user_") {
				t.Errorf("key %q contains %q", k, bad)
			}
		}
	}
}

// 3xx を denied_statuses に書けば、GET と HEAD の 3xx だけを拒否に数え、user_denied_redirects を添える (ADR 0087 の 7 節)。
func TestUserProbeRedirects(t *testing.T) {
	var ev []cwlogstest.Event
	n := 0
	req := func(method, uri string, status int) {
		n++
		ev = append(ev, userReq(day21(2, n/60, n%60), rid(n), method, uri, "192.0.2.10", status, "actor kind=user id=42")...)
	}
	for id := 1; id <= 4; id++ {
		req("GET", fmt.Sprintf("/orders/%d", id), 302)
	}
	req("HEAD", "/orders/5", 302)
	req("POST", "/orders/6", 302) // 送信の後の転送はふつうの成功
	req("GET", "/orders/7", 403)
	req("GET", "/orders/8", 200)
	c := probeChecks("web")
	c.UserIDEnumeration.DeniedStatuses = []int{401, 403, 404, 302}
	sink, _, err := collectProbe(t, probeSource(t), c, ev, userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := userMetrics(sink)
	for k, want := range map[string]float64{
		"2026-10-21|user_ids|user:42|/orders/:id": 8, "2026-10-21|user_ids_denied|user:42|/orders/:id": 6,
		"2026-10-21|user_denied_redirects|user:42|/orders/:id": 5, "2026-10-21|user_ids_ok|user:42|/orders/:id": 1,
		"2026-10-21|user_ids_methods|user:42|/orders/:id|HEAD": 1,
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v\n%s", k, m[k], want, dump(m))
		}
	}
	// 3xx を書かなければ、転送の列は出さない
	sink, _, err = collectProbe(t, probeSource(t), probeChecks("web"), ev, userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k := range userMetrics(sink) {
		if strings.Contains(k, MetricUserDeniedRedirects) {
			t.Fatalf("redirects without 3xx: %s", k)
		}
	}
}

// 流す条件 (開発リードの判断、2026-11-26): 3 つのどれかの sources にあるソースで、この run に http_user の要るチェックがあるときだけ。
func TestUserProbeGating(t *testing.T) {
	ran := func(f *cwlogstest.Fake) (u1, u2 int) {
		for _, q := range f.Queries() {
			switch {
			case strings.Contains(q, "count(u_dn) as"):
				u1++
			case strings.Contains(q, "as "+MetricUserIDsOK):
				u2++
			}
		}
		return u1, u2
	}
	ev := probeEvents()
	for _, c := range []struct {
		name      string
		checks    config.Checks
		src       config.Source
		needs     map[record.Kind]bool
		u1, u2    int
		templates bool
	}{
		{"どの sources にも無い", probeChecks(), probeSource(t), nil, 0, 0, false},
		{"別のソースだけ", probeChecks("other"), probeSource(t), nil, 0, 0, false},
		{"http_user の要るチェックが run に無い", probeChecks("web"), probeSource(t), map[record.Kind]bool{record.KindHTTPAccess: true}, 0, 0, false},
		// userWindow は 2 日にまたがるので、流すなら 1 日ずつ 2 本
		{"http_user が要る", probeChecks("web"), probeSource(t), map[record.Kind]bool{record.KindHTTPUser: true}, 2, 2, true},
		{"path_ids が無い: U1 の拒否だけ", probeChecks("web"), userSource(actorRegex, ""), nil, 2, 0, false},
	} {
		sink, f, err := collectProbe(t, c.src, c.checks, ev, userWindow, c.needs)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if u1, u2 := ran(f); u1 != c.u1 || u2 != c.u2 {
			t.Errorf("%s: U1 %d, U2 %d, want %d %d", c.name, u1, u2, c.u1, c.u2)
		}
		hasTpl := false
		for k := range userMetrics(sink) {
			hasTpl = hasTpl || strings.Contains(k, MetricUserTemplates)
		}
		if hasTpl != c.templates {
			t.Errorf("%s: templates %v", c.name, hasTpl)
		}
	}
	// user_id_enumeration だけなら U1 は流さない
	c := probeChecks()
	c.UserIDEnumeration.Sources = []string{"web"}
	_, f, err := collectProbe(t, probeSource(t), c, ev, userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u1, u2 := ran(f); u1 != 0 || u2 != 2 {
		t.Errorf("enumeration only: U1 %d, U2 %d", u1, u2)
	}
}

// 範囲の中の UTC の 1 日ずつ流す (ADR 0087 の 1 節)。2 日にまたがる窓なら U1・U2 を 2 本ずつ流し、日ごとの値になる。
func TestUserProbePerDay(t *testing.T) {
	var ev []cwlogstest.Event
	for i := 0; i < 3; i++ {
		ev = append(ev, userReq(time.Date(2026, 10, 20, 23, 0, i, 0, time.UTC), rid(i), "GET", fmt.Sprintf("/orders/%d", i), "192.0.2.10", 403, "actor kind=user id=42")...)
	}
	for i := 3; i < 8; i++ {
		ev = append(ev, userReq(day21(1, 0, i), rid(i), "GET", fmt.Sprintf("/orders/%d", i), "192.0.2.10", 403, "actor kind=user id=42")...)
	}
	w := collect.Window{From: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), To: now}
	sink, f, err := collectProbe(t, probeSource(t), probeChecks("web"), ev, w, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := 0
	for _, q := range f.Queries() {
		if strings.Contains(q, "count(u_dn) as") || strings.Contains(q, "as "+MetricUserIDsOK) {
			u++
		}
	}
	if u != 4 {
		t.Fatalf("user queries = %d, want 4 (2 days x 2)", u)
	}
	m := userMetrics(sink)
	if m["2026-10-20|user_ids|user:42|/orders/:id"] != 3 || m["2026-10-21|user_ids|user:42|/orders/:id"] != 5 ||
		m["2026-10-20|user_denied|user:42"] != 3 || m["2026-10-21|user_denied|user:42"] != 5 {
		t.Fatalf("per day:\n%s", dump(m))
	}
}

// store_top: 日ごとに値の大きい順に残す。同じ値なら key の順。
func TestUserProbeStoreTop(t *testing.T) {
	var ev []cwlogstest.Event
	n := 0
	for u, k := range []int{5, 3, 4, 3} {
		for i := 0; i < k; i++ {
			n++
			ev = append(ev, userReq(day21(1, n/60, n%60), rid(n), "GET", fmt.Sprintf("/orders/%d", i), "192.0.2.10", 403, fmt.Sprintf("actor kind=user id=%d", 40+u))...)
		}
	}
	c := probeChecks("web")
	c.UserDenied.StoreTop, c.UserIDEnumeration.StoreTop = 2, 3
	sink, _, err := collectProbe(t, probeSource(t), c, ev, userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	var denied, ids []string
	for k := range userMetrics(sink) {
		p := strings.Split(k, "|")
		switch p[1] {
		case MetricUserDenied:
			denied = append(denied, p[2])
		case MetricUserIDs:
			ids = append(ids, p[2])
		}
	}
	sort.Strings(denied)
	sort.Strings(ids)
	if strings.Join(denied, ",") != "user:40,user:42" || strings.Join(ids, ",") != "user:40,user:41,user:42" {
		t.Fatalf("denied %v, ids %v", denied, ids)
	}
}

// U2 が行の上限に当たった日は、分布の p50・p99 を書かない (下の側が欠けているため。0071 の 6 節)。
func TestUserProbeTruncated(t *testing.T) {
	f := &cwlogstest.Fake{}
	sim := &cwlogstest.Sim{Events: probeEvents()}
	c := probeChecks("web")
	registerRequests(f, sim, c, "web")
	f.On("count(u_dn) as", sim.Response(nil))
	rows := make([]map[string]string, MaxRows)
	for i := range rows {
		rows[i] = cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "user_kind", "user", "user_id", fmt.Sprint(i), "tpl", "/orders/?id",
			MetricUserIDs, fmt.Sprint(MaxRows-i), MetricUserIDsOK, "0", MetricUserIDsDenied, "0", "u_rq", "1")
	}
	f.On("as "+MetricUserIDsOK, cwlogstest.Response{Rows: rows})
	col, err := New(probeSource(t), c, f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return now }
	sink := &sinkRecorder{}
	if err := col.Collect(t.Context(), userWindow, sink); err != nil {
		t.Fatal(err)
	}
	m := userMetrics(sink)
	if m["2026-10-21|user_ids_dist|/orders/:id|max"] != MaxRows || m["2026-10-21|user_ids_dist|/orders/:id|users"] != MaxRows {
		t.Fatalf("dist:\n%s", dump(m))
	}
	for _, k := range []string{"p50", "p99"} {
		if _, ok := m["2026-10-21|user_ids_dist|/orders/:id|"+k]; ok {
			t.Errorf("%s written on a truncated day", k)
		}
	}
	if !strings.Contains(strings.Join(col.FormatStats().Truncated, ","), MetricUserIDs) {
		t.Errorf("truncated: %v", col.FormatStats().Truncated)
	}
}

// 結果の行の利用者の ID は、key に置く前にストアの規則 (ADR 0052) で確かめ直す。メールアドレスなど形に合わない値は捨てる。
func TestUserProbeInvalidUserRows(t *testing.T) {
	f := &cwlogstest.Fake{}
	sim := &cwlogstest.Sim{Events: probeEvents()}
	c := probeChecks("web")
	registerRequests(f, sim, c, "web")
	row := func(kind, id string) map[string]string {
		return cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "user_kind", kind, "user_id", id, "tpl", "/orders/?id",
			MetricUserDenied, "9", MetricUserIDs, "9", MetricUserIDsOK, "0", MetricUserIDsDenied, "9", "u_rq", "9")
	}
	bad := []map[string]string{row("user", "a@example.com"), row("User", "42"), row("user", strings.Repeat("x", 65)), row("", "42"), row("user", "4 2")}
	f.On("count(u_dn) as", cwlogstest.Response{Rows: bad})
	f.On("as "+MetricUserIDsOK, cwlogstest.Response{Rows: append(bad, cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "user_kind", "user", "user_id", "42",
		"tpl", "/orders/42", MetricUserIDs, "9"))})
	col, err := New(probeSource(t), c, f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return now }
	sink := &sinkRecorder{}
	if err := col.Collect(t.Context(), userWindow, sink); err != nil {
		t.Fatal(err)
	}
	// 形に合わない利用者の行も、:id を含まない型 (結果の値は信用しない) の行も残さない。残るのは U1・U2 を流した日の印だけ
	m := userMetrics(sink)
	for k := range m {
		if strings.Split(k, "|")[1] == MetricUserProbeDays {
			delete(m, k)
		}
	}
	if len(m) != 0 {
		t.Fatalf("kept:\n%s", dump(m))
	}
}

// クエリ全体の長さ: path_ids と request_lines の上限に近い設定でも、U1・U2 は Insights の上限 (余裕を取った UserQueryLen) に収まるか、
// 収まらなければ LongQueries が名前を返す (config check と doctor が ng にする)。
func TestUserProbeQueryLength(t *testing.T) {
	src := probeSource(t)
	c := probeChecks("web")
	col, err := New(src, c, &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range col.userQueries() {
		t.Logf("%s: %d characters (path_ids %d)", q.Name, len(q.Query), src.PathRules().QueryLen())
		if len(q.Query) > UserQueryLen {
			t.Errorf("%s: %d characters", q.Name, len(q.Query))
		}
	}
	if l := col.LongQueries(); len(l) != 0 {
		t.Fatalf("LongQueries = %v", l)
	}
	// path_ids の文を上限 (pathids.MaxQueryLen) 近くまで長くし、request_lines の正規表現も長くすると、上限を超える
	long := src
	var pi *config.PathIDs
	for i := 0; i < 50; i++ {
		var tpls []string
		for j := 0; j <= i; j++ {
			tpls = append(tpls, fmt.Sprintf("/section%02d/:id/detail/:any/x", j))
		}
		p, err := pathIDsOrErr(config.PathIDs{Segments: []string{`[0-9]{1,20}`, `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`}, Templates: tpls, MaxSegments: 12})
		if err != nil {
			break
		}
		pi = p
	}
	if pi == nil || (config.Source{PathIDs: pi}).PathRules().QueryLen() < 5000 {
		t.Fatalf("path_ids near the limit: %v", pi)
	}
	long.PathIDs = pi
	req := *long.Request
	req.Lines = append([]config.RequestLine{}, req.Lines...)
	// 取り出せる項目のうち、まだ取り出していない ua と duration を、上限 (512 文字) に近い正規表現の行で取り出す
	pad := strings.Repeat(`(?:x)?`, 75)
	req.Lines = append(req.Lines, config.RequestLine{Name: "ua", Regex: "UA " + pad + `(?P<ua>\S+)`}, config.RequestLine{Name: "duration", Regex: "Duration " + pad + `(?P<duration>[0-9.]+)`})
	long.Request = &req
	col, err = New(long, c, &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range col.userQueries() {
		t.Logf("%s: %d characters", q.Name, len(q.Query))
	}
	if l := col.LongQueries(); len(l) == 0 || !strings.Contains(strings.Join(l, "\n"), userIDsQuery) {
		t.Fatalf("LongQueries = %v", l)
	}
}

// pathIDsOrErr は設定の検証を通した path_ids (誤りなら err)。
func pathIDsOrErr(p config.PathIDs) (*config.PathIDs, error) {
	src := config.Source{ID: "web", Kind: config.KindCloudWatchLogs, Format: config.FormatNginxAccess, Yields: config.YieldsHTTPAccess, PathIDs: &p}
	if err := src.CompilePathIDs(); err != nil {
		return nil, err
	}
	return src.PathIDs, nil
}

// FuzzUserProbeRows: U1・U2 の結果の行 (Insights の結果。ログ由来の値) を、どんな値で返されても、日の値の key は
// `<種類>:<ID>` (ストアの規則に合う利用者) と、Sanitize した型 (:id を含む) とメソッドの固定の組だけになり、値は 0 以上の有限の整数になる。
func FuzzUserProbeRows(f *testing.F) {
	f.Add("user", "42", "/orders/?id", "8", "1", "GET 200")
	f.Add("user", "a@example.com", "/u/?id", "-3", "NaN", "")
	f.Add("staff", "5", "/x/?any/?id/?more", "1e400", "2", "x")
	f.Add("user", "42", "/orders/42", "3", "3", "")
	src := userSource(actorRegex, "")
	src.PathIDs = &config.PathIDs{Segments: []string{`[0-9]+`}, Templates: []string{"/x/:any/:id"}, MaxSegments: 4}
	if err := src.CompilePathIDs(); err != nil {
		f.Fatal(err)
	}
	c := probeChecks("web")
	c.UserIDEnumeration.DeniedStatuses = []int{403, 302}
	c.UserDenied.StoreMin, c.UserIDEnumeration.StoreMin, c.UserPathBreadth.StoreMin = 1, 1, 1
	col, err := New(src, c, &cwlogstest.Fake{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, kind, id, tpl, v1, v2, extra string) {
		row := cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "user_kind", kind, "user_id", id, "tpl", tpl,
			MetricUserDenied, v1, MetricUserTemplates, v2, MetricUserTemplatesOK, v1, MetricUserIDs, v1, MetricUserIDsOK, v2, MetricUserIDsDenied, v1,
			MetricUserDeniedRedirects, v2, "u_rq", v2, "u_s0", v1, "u_s5", extra)
		sink := &sinkRecorder{}
		if err := col.emitUserSummary(t.Context(), []map[string]string{row}, sink); err != nil {
			t.Fatal(err)
		}
		if err := col.emitUserIDs(t.Context(), []map[string]string{row, row}, false, sink); err != nil {
			t.Fatal(err)
		}
		for _, r := range sink.recs {
			m := r.(record.Metric)
			if m.Value < 0 || m.Value != m.Value || m.Value > maxRequestCount*2 || m.Value != float64(int64(m.Value)) || m.From != record.KindHTTPUser {
				t.Fatalf("value %+v", m)
			}
			parts := strings.Split(m.Key, "|")
			if m.Metric == MetricUserIDsDist {
				if len(parts) != 2 || !keyTemplate(parts[0]) {
					t.Fatalf("dist key %q", m.Key)
				}
				continue
			}
			k, i, ok := strings.Cut(parts[0], ":")
			if !ok || !ValidUserKind(k) || !ValidUserID(i) {
				t.Fatalf("user in key %q (%q, %q)", m.Key, kind, id)
			}
			switch {
			case len(parts) == 1:
			case len(parts) >= 2 && strings.HasPrefix(m.Metric, "user_ids") || m.Metric == MetricUserDeniedRedirects:
				if !keyTemplate(parts[1]) {
					t.Fatalf("template in key %q", m.Key)
				}
				if m.Metric == MetricUserIDsMethods && (len(parts) != 3 || !strIn(parts[2], append(append([]string{}, userMethods...), userMethodOther))) {
					t.Fatalf("method in key %q", m.Key)
				}
			default:
				t.Fatalf("key %q for %s", m.Key, m.Metric)
			}
		}
	})
}

// keyTemplate は key に置いてよい型の形か (/ で始まり、:id を含み、クエリ・フラグメント・改行・key の区切り | を含まない)。
func keyTemplate(s string) bool {
	return strings.HasPrefix(s, "/") && strings.Contains(s+"/", "/:id/") && !strings.ContainsAny(s, "?#\n|") && utf8.ValidString(s)
}
