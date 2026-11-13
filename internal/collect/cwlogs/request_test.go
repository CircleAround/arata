package cwlogs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
)

// request_lines (ADR 0051) のテスト。ログの行は Rails の既定の形 (Logger の既定の formatter + log_tags = [:request_id]) の架空の見本。
// 実 AWS には接続しない (cwlogstest.Sim が 2 段の stats を解釈する)。

// railsID は見本の設定の鍵。前置きのあと (` -- : `) と行頭 (複数行のメッセージの続きの行) の両方を受ける。
const railsID = `(?:^| -- : )\[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] `

func railsSource() config.Source {
	return config.Source{ID: "web", Kind: config.KindCloudWatchLogs, LogGroup: "prod-app", Format: config.FormatRequestLines, Yields: config.YieldsHTTPAccess,
		ExpectedMatchRate: 0.8, ExpectedCompleteRate: 0.8, SampleLines: true,
		Request: &config.Request{ID: railsID, MaxDuration: 60 * time.Second, Lines: []config.RequestLine{
			{Name: "started", Regex: `Started (?P<method>[A-Z]+) "(?P<path>[^"?]*)[^"]*" for (?P<ip>\S+) at `},
			{Name: "completed", Regex: `Completed (?P<status>\d{3}) `},
			{Name: "no_route", Regex: `ActionController::RoutingError`, Set: map[string]int{"status": 404}},
		}}}
}

// railsLine は既定の formatter の 1 行。prefix は行頭に付く別の角括弧 (独自の formatter の見本。空なら無し)。
func railsLine(at time.Time, prefix, rid, body string) cwlogstest.Event {
	tag := ""
	if rid != "" {
		tag = "[" + rid + "] "
	}
	msg := fmt.Sprintf("%sI, [%s #1]  INFO -- : %s%s", prefix, at.UTC().Format("2006-01-02T15:04:05.000000"), tag, body)
	return cwlogstest.Event{Time: at, Fields: map[string]string{"@message": msg}}
}

// railsReq は 1 リクエスト分の行。status が 0 なら最後の行が出ない (途中のリクエスト)。
func railsReq(at time.Time, prefix, rid, method, uri, ip string, status int) []cwlogstest.Event {
	ev := []cwlogstest.Event{
		railsLine(at, prefix, rid, fmt.Sprintf(`Started %s "%s" for %s at %s`, method, uri, ip, at.UTC().Format("2006-01-02 15:04:05 -0700"))),
		railsLine(at.Add(2*time.Millisecond), prefix, rid, "Processing by PagesController#show as HTML"),
		railsLine(at.Add(3*time.Millisecond), prefix, rid, `  Parameters: {"q"=>"Started GET \"/.env\" for 198.51.100.99 at x"}`),
	}
	if status != 0 {
		ev = append(ev, railsLine(at.Add(12*time.Millisecond), prefix, rid, fmt.Sprintf("Completed %d in 12ms (Views: 3.0ms)", status)))
	}
	return ev
}

// railsNoRoute は経路の無いリクエスト。最後の行は出ず、例外の行は Logger の前置きの無い続きの行になる (行頭が [request_id])。
func railsNoRoute(at time.Time, rid, uri, ip string) []cwlogstest.Event {
	cont := func(d time.Duration, body string) cwlogstest.Event {
		return cwlogstest.Event{Time: at.Add(d), Fields: map[string]string{"@message": "[" + rid + "] " + body}}
	}
	return []cwlogstest.Event{
		railsLine(at, "", rid, fmt.Sprintf(`Started GET "%s" for %s at %s`, uri, ip, at.UTC().Format("2006-01-02 15:04:05 -0700"))),
		railsLine(at.Add(time.Millisecond), "", rid, "  "),
		cont(time.Millisecond, fmt.Sprintf(`ActionController::RoutingError (No route matches [GET] "%s"):`, uri)),
		cont(time.Millisecond, "  "),
	}
}

func rid(i int) string { return fmt.Sprintf("5b0c1d2e-0000-4000-8000-%012d", i) }

// requestPreds は request_lines の集計の、1 段目の後の filter と同じ意味の述語 (httpPreds と同じ条件を、まとめた後の項目に当てる)。
func registerRequests(f *cwlogstest.Fake, sim *cwlogstest.Sim, c config.Checks, srcID string) {
	p := httpPreds{c: c}
	f.On("as lines_total", sim.Response(nil))
	f.On("as http_hits", sim.Response(func(r map[string]string) bool { return p.signIn(r) || p.probe(r) }))
	var eps []func(map[string]string) bool
	for _, ep := range c.EndpointAbuse.Endpoints {
		if len(ep.Sources) == 0 || strIn(srcID, ep.Sources) {
			eps = append(eps, p.endpoint(ep))
		}
	}
	f.On("as "+endpointHits, sim.Response(func(r map[string]string) bool {
		for _, m := range eps {
			if m(r) {
				return true
			}
		}
		return false
	}))
}

func collectRequests(t *testing.T, src config.Source, c config.Checks, ev []cwlogstest.Event, w collect.Window) (*sinkRecorder, *Collector, *cwlogstest.Fake, error) {
	t.Helper()
	f := &cwlogstest.Fake{}
	registerRequests(f, &cwlogstest.Sim{Events: ev}, c, src.ID)
	col, err := New(src, c, f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return w.To }
	sink := &sinkRecorder{}
	return sink, col, f, col.Collect(context.Background(), w, sink)
}

func TestRequestProfile(t *testing.T) {
	p, err := ProfileFor(railsSource())
	if err != nil {
		t.Fatal(err)
	}
	want := `parse @message /(?:^| -- : )\[(?<rl_request_id>[A-Za-z0-9_@-]{1,255})\] /
| parse @message /(?<rl_k0>Started (?<rl_method>[A-Z]+) "(?<rl_path>[^"?]*)[^"]*" for (?<rl_ip>\S+) at )/
| parse @message /(?<rl_k1>Completed (?<rl_status>\d{3}) )/
| parse @message /(?<rl_k2>ActionController::RoutingError)/`
	if p.Prelude != want || p.MatchField != "rl_request_id" || !p.RequestLines() || !p.Has("status") || p.Has("ua") {
		t.Fatalf("prelude:\n%s\n%+v", p.Prelude, p)
	}
	// doctor と FORMAT_MISMATCH のサンプルは 1 行ずつ (まとめる前) を見る
	if got := SampleQuery(p, 3); !strings.HasSuffix(got, "\n| filter not ispresent(rl_request_id)\n| fields @message\n| limit 3") {
		t.Fatalf("sample: %s", got)
	}
}

func TestRequestQueries(t *testing.T) {
	c := abuseChecks()
	c.ProbePaths.ExcludePaths = []string{"/.env.example"}
	col, err := New(railsSource(), c, &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	qs := col.queries()
	for _, q := range qs {
		fmt.Fprintf(&b, "# %s (bin: %s)\n%s\n\n", q.Name, q.Bin, q.Query)
		// Insights の一時フィールドは同じ名前を 2 度定義できない (ADR 0051 の確かめた事実)。Sim は 2 度目の定義でパニックする
		(&cwlogstest.Sim{}).Rows(q.Query, now, now, nil)
		if len(q.Query) > 10000 {
			t.Fatalf("%s: クエリが Insights の上限 (10000 文字) を超える: %d", q.Name, len(q.Query))
		}
		if q.Bin == "" {
			t.Fatalf("%s: 最初の行の時刻の区切りの列が無い", q.Name)
		}
	}
	checkGolden(t, "request_queries.golden", b.String())
	if col.QueryCount() != 3 {
		t.Fatalf("本数は 1 行のログと同じ 3 本: %d", col.QueryCount())
	}
}

// 同じリクエストなら、1 行のログ (nginx) と同じ metrics になる (チェックは変えない。ADR 0051 の 1 節)。
// 違うのは UA (Rails の既定のログに無い) と行数だけ。
func TestRequestEquivalence(t *testing.T) {
	c := httpEquivChecks()
	nginx := httpEvents()
	var ev []cwlogstest.Event
	n := 0
	statusRe := regexp.MustCompile(`" (\d{3}) `)
	reqRe := regexp.MustCompile(`^(\S+) - - \[[^\]]*\] "([A-Z]+) (\S+) HTTP`)
	for _, e := range nginx {
		m := reqRe.FindStringSubmatch(e.Fields["@message"])
		if m == nil {
			// 解釈できない行: request_id の付かない行にする
			for i := 0; i < e.N; i++ {
				ev = append(ev, cwlogstest.Event{Time: e.Time, Fields: map[string]string{"@message": "garbage line"}})
			}
			continue
		}
		status, _ := strconv.Atoi(statusRe.FindStringSubmatch(e.Fields["@message"])[1])
		for i := 0; i < e.N; i++ {
			n++
			if status == 404 && n%2 == 0 {
				ev = append(ev, railsNoRoute(e.Time, rid(n), m[3], m[1])...)
				continue
			}
			ev = append(ev, railsReq(e.Time, "", rid(n), m[2], m[3], m[1], status)...)
		}
	}
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	sink, col, _, err := collectRequests(t, railsSource(), c, ev, w)
	if err != nil {
		t.Fatal(err)
	}

	f := &cwlogstest.Fake{}
	registerHTTP(f, &cwlogstest.Sim{Events: nginx}, httpPreds{c: c})
	ncol, err := New(nginxSource(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	ncol.Sleep = func(context.Context, time.Duration) error { return nil }
	nsink := &sinkRecorder{}
	if err := ncol.Collect(context.Background(), w, nsink); err != nil {
		t.Fatal(err)
	}
	skip := func(k string) bool {
		for _, m := range []string{MetricLinesTotal, MetricLinesMatched, MetricEndpointUAIPs, MetricRequestsTotal, MetricRequestsComplete, MetricRequestIDReused} {
			if strings.Contains(k, "|"+m+"|") {
				return true
			}
		}
		return false
	}
	got, want := sink.metrics(), nsink.metrics()
	for k, v := range want {
		if !skip(k) && got[k] != v {
			t.Errorf("%s: request_lines %v, nginx %v", k, got[k], v)
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok && !skip(k) {
			t.Errorf("%s = %v: nginx に無い metric", k, v)
		}
	}
	rs := col.FormatStats().Requests
	if rs == nil || rs.Total != int64(n) || rs.Complete != int64(n) || rs.Starts != int64(n) || rs.WithStatus != int64(n) || rs.Reused != 0 || rs.StartsUntagged != 0 {
		t.Fatalf("requests (%d): %+v", n, rs)
	}
	if st := col.FormatStats(); st.Total-st.Matched != 6 || st.Matched < int64(4*n) {
		t.Fatalf("lines: %+v", st)
	}
	checkGolden(t, "equiv_request.golden", dumpMetrics(sink, col.FormatStats()))
}

func day21(h, m, s int) time.Time { return time.Date(2026, 10, 21, h, m, s, 0, time.UTC) }

// 同じ request_id を使い回しても、数えたリクエストの数は最初の行の数より減らない (ADR 0051。X-Request-Id は送る側が選べる)。
func TestRequestIDReuse(t *testing.T) {
	c := checksCfg()
	var ev []cwlogstest.Event
	for i := 0; i < 40; i++ {
		ev = append(ev, railsReq(day21(1, 0, i), "", rid(i), "GET", "/", "192.0.2.200", 200)...)
	}
	// 1 つの ID でログインの失敗を 30 回
	for i := 0; i < 30; i++ {
		ev = append(ev, railsReq(day21(2, 0, i), "", "attacker-chosen_id@x", "POST", "/users/sign_in", "198.51.100.7", 422)...)
	}
	sink, col, _, err := collectRequests(t, railsSource(), c, ev, collect.Window{From: now.Add(-24 * time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	if m["2026-10-21|sign_in_failures|198.51.100.7"] != 30 {
		t.Fatalf("使い回した ID のリクエストが減った: %v", m)
	}
	rs := col.FormatStats().Requests
	if rs.Total != 41 || rs.Starts != 70 || rs.Reused != 1 || rs.Complete != 41 {
		t.Fatalf("requests: %+v", rs)
	}
	if m["2026-10-21|request_id_reused|"] != 1 || m["2026-10-21|requests_total|"] != 41 || m["2026-10-21|requests_complete|"] != 41 {
		t.Fatalf("metrics: %v", m)
	}

	// 使い回しが大半を占めると、鍵の取り違えと区別できない。黙って数えずに FORMAT_MISMATCH にする
	for i := 0; i < 60; i++ {
		ev = append(ev, railsReq(day21(3, 0, i), "", "attacker-chosen_id@x", "POST", "/users/sign_in", "198.51.100.7", 422)...)
	}
	sink, col, _, err = collectRequests(t, railsSource(), c, ev, collect.Window{From: now.Add(-24 * time.Hour), To: now})
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch || ce.Details["reason"] != RequestProblemID {
		t.Fatalf("want FORMAT_MISMATCH (%s), got %v", RequestProblemID, err)
	}
	if len(sink.recs) != 0 {
		t.Fatalf("FORMAT_MISMATCH なのに metrics を出した: %v", sink.metrics())
	}
	if rs := col.FormatStats().Requests; rs == nil || rs.Total != 41 || rs.Starts != 130 {
		t.Fatalf("失敗しても計測できた分は残す: %+v", rs)
	}
}

// 見本の設定は、既定の formatter の行でも、行頭に別の角括弧がある行でも、リクエストの数だけ鍵を作る。
// 取り違える設定 (最初の角括弧) は、検査が必ず止める (ADR 0051)。
func TestRequestIDMisparse(t *testing.T) {
	c := checksCfg()
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	for _, prefix := range []string{"", "[web-1] ", "[ip-10-0-1-23] [7f3a9c] "} {
		var ev []cwlogstest.Event
		for i := 0; i < 50; i++ {
			ev = append(ev, railsReq(day21(1, i, 0), prefix, rid(i), "GET", "/items/"+strconv.Itoa(i), "192.0.2.200", 200)...)
		}
		// 行頭に別の角括弧が付く formatter では、見本の「行頭」の選択肢がその角括弧を拾う。前置きのあとだけを受ける形に書く
		good := railsSource()
		if prefix != "" {
			good.Request.ID = ` -- : \[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] `
			_, _, _, err := collectRequests(t, railsSource(), c, ev, w)
			var ce *collect.Error
			if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch || ce.Details["reason"] != RequestProblemID {
				t.Fatalf("prefix %q: 行頭の角括弧を拾う見本の設定を止めなかった: %v", prefix, err)
			}
		}
		_, col, _, err := collectRequests(t, good, c, ev, w)
		if err != nil {
			t.Fatalf("prefix %q: %v", prefix, err)
		}
		if rs := col.FormatStats().Requests; rs.Total != 50 || rs.Complete != 50 || rs.Starts != 50 || rs.Reused != 0 {
			t.Fatalf("prefix %q: 鍵がリクエストの数と違う: %+v", prefix, rs)
		}

		// 最初の角括弧を鍵にする設定
		bad := railsSource()
		bad.Request.ID = `\[(?P<request_id>[^\]]+)\] `
		_, col, _, err = collectRequests(t, bad, c, ev, w)
		var ce *collect.Error
		if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch {
			t.Fatalf("prefix %q: 取り違える設定を止めなかった: %v (%+v)", prefix, err, col.FormatStats().Requests)
		}
		// 行頭の角括弧がホスト名なら少数の鍵にまとまる (request_id)。無ければ時刻が鍵になり、項目が揃わない (complete_rate)
		wantReason := RequestProblemID
		if prefix == "" {
			wantReason = RequestProblemComplete
		}
		if ce.Details["reason"] != wantReason {
			t.Fatalf("prefix %q: reason %v, want %s", prefix, ce.Details["reason"], wantReason)
		}
	}

	// 行頭だけに固定した設定は、既定の formatter では 1 行も当たらない (行の解釈率で気づく)
	anchored := railsSource()
	anchored.Request.ID = `^\[(?P<request_id>[A-Za-z0-9-]{1,255})\] `
	_, _, _, err := collectRequests(t, anchored, c, railsReq(day21(1, 0, 0), "", rid(1), "GET", "/", "192.0.2.200", 200), w)
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch || ce.Details["match_rate"] != 0.0 {
		t.Fatalf("want FORMAT_MISMATCH by match_rate, got %v", err)
	}
}

// タグの無い最初の行 (記号だけの X-Request-Id を送ると、Rails は request_id のタグを出さない) は、リクエストにまとめられない。
// 数には入れず、数を残す (見えない範囲を隠さない)。
func TestRequestUntaggedStarts(t *testing.T) {
	var ev []cwlogstest.Event
	for i := 0; i < 20; i++ {
		ev = append(ev, railsReq(day21(1, 0, i), "", rid(i), "GET", "/", "192.0.2.200", 200)...)
	}
	for i := 0; i < 3; i++ {
		ev = append(ev, railsReq(day21(2, 0, i), "", "", "POST", "/users/sign_in", "198.51.100.7", 422)...)
	}
	sink, col, _, err := collectRequests(t, railsSource(), checksCfg(), ev, collect.Window{From: now.Add(-24 * time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	if rs := col.FormatStats().Requests; rs.Total != 20 || rs.Starts != 20 || rs.StartsUntagged != 3 {
		t.Fatalf("requests: %+v", rs)
	}
	if v, ok := sink.metrics()["2026-10-21|sign_in_failures|198.51.100.7"]; ok {
		t.Fatalf("タグの無い行をリクエストとして数えた: %v", v)
	}
	if st := col.FormatStats(); st.Total != 92 || st.Matched != 80 {
		t.Fatalf("lines: %+v", st)
	}
}

// まとめられた割合 (最初の行のあるリクエスト / request_id の数) が閾値未満なら FORMAT_MISMATCH。
func TestRequestCompleteRate(t *testing.T) {
	var ev []cwlogstest.Event
	for i := 0; i < 10; i++ {
		ev = append(ev, railsReq(day21(1, 0, i), "", rid(i), "GET", "/", "192.0.2.200", 200)...)
	}
	// 最初の行が形に合わないリクエスト (最後の行だけが当たる)
	for i := 10; i < 20; i++ {
		ev = append(ev, railsLine(day21(1, 1, i), "", rid(i), "Started something else"), railsLine(day21(1, 1, i), "", rid(i), "Completed 200 OK in 3ms"))
	}
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	_, col, _, err := collectRequests(t, railsSource(), checksCfg(), ev, w)
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch || ce.Details["reason"] != RequestProblemComplete || ce.Details["complete_rate"] != 0.5 {
		t.Fatalf("want FORMAT_MISMATCH (complete_rate), got %v", err)
	}
	if rs := col.FormatStats().Requests; rs.Total != 20 || rs.Complete != 10 || rs.WithStatus != 20 || rs.Expected != 0.8 {
		t.Fatalf("requests: %+v", rs)
	}
	src := railsSource()
	src.ExpectedCompleteRate = 0.5
	if _, _, _, err := collectRequests(t, src, checksCfg(), ev, w); err != nil {
		t.Fatalf("閾値どおりなら通す: %v", err)
	}
}

// 窓の境界: リクエストは最初の行の時刻の日に数える。問い合わせの範囲は後ろに max_duration だけ広げ、
// 余白の中で始まったリクエストはその範囲では数えない (次の範囲が数える)。
func TestRequestDayBoundary(t *testing.T) {
	c := checksCfg()
	at := func(day, h, m, s int) time.Time { return time.Date(2026, 10, day, h, m, s, 0, time.UTC) }
	var ev []cwlogstest.Event
	// 20 日 23:59:59 に始まり 21 日 00:00:20 に終わるログインの失敗
	ev = append(ev, railsLine(at(20, 23, 59, 59), "", rid(1), `Started POST "/users/sign_in" for 198.51.100.7 at 2026-10-20 23:59:59 +0000`),
		railsLine(at(21, 0, 0, 20), "", rid(1), "Completed 422 Unprocessable Content in 21000ms"))
	// 21 日 00:00:30 (20 日の問い合わせの余白の中) に始まる失敗
	ev = append(ev, railsReq(at(21, 0, 0, 30), "", rid(2), "POST", "/users/sign_in", "198.51.100.7", 422)...)
	for i := 0; i < 5; i++ {
		ev = append(ev, railsReq(at(20, 5, 0, i), "", rid(10+i), "GET", "/", "192.0.2.200", 200)...)
		ev = append(ev, railsReq(at(21, 5, 0, i), "", rid(20+i), "GET", "/", "192.0.2.200", 200)...)
	}
	sink, col, f, err := collectRequests(t, railsSource(), c, ev, collect.Window{From: now.Add(-24 * time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	if m["2026-10-20|sign_in_failures|198.51.100.7"] != 1 || m["2026-10-21|sign_in_failures|198.51.100.7"] != 1 {
		t.Fatalf("境界をまたぐリクエストの日が違う: %v", m)
	}
	if m["2026-10-20|requests_total|"] != 6 || m["2026-10-20|requests_complete|"] != 6 {
		t.Fatalf("20 日: %v", m)
	}
	// 21 日の問い合わせには rid(1) の最後の行だけが入る (最初の行が無い = 前の日の分。数えない)
	if m["2026-10-21|requests_total|"] != 7 || m["2026-10-21|requests_complete|"] != 6 {
		t.Fatalf("21 日: %v", m)
	}
	if rs := col.FormatStats().Requests; rs.Starts != 12 {
		t.Fatalf("最初の行の数: %+v", rs)
	}
	// 解釈率のクエリは 1 日ずつ。20 日の分は終わりを 60 秒広げる。窓の終わり (今) より先には広げない
	var ends []string
	for _, in := range f.Started {
		if strings.Contains(aws.ToString(in.QueryString), "as lines_total") {
			ends = append(ends, time.Unix(aws.ToInt64(in.StartTime), 0).UTC().Format("02T15:04:05")+"-"+time.Unix(aws.ToInt64(in.EndTime), 0).UTC().Format("02T15:04:05"))
		}
	}
	if got := strings.Join(ends, " "); got != "20T00:00:00-21T00:00:59 21T00:00:00-21T08:59:59" {
		t.Fatalf("問い合わせの範囲: %s", got)
	}
}

// 行数の上限に当たったら、1 日ずつに分ける (日より細かくは分けない。最初の行の時刻の区切りが日なので、境目の余白のリクエストを落とせない)。
func TestRequestSplitByDay(t *testing.T) {
	big := make([]map[string]string, MaxRows)
	for i := range big {
		big[i] = row("day", "2026-10-21 00:00:00.000", "ip", fmt.Sprintf("198.51.100.%d", i%250), "method", "POST", "status", "422", "sign_in", "/users/sign_in", httpHits, "1")
	}
	f := &cwlogstest.Fake{}
	f.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{
		row("day", "2026-10-20 00:00:00.000", "status", "200", "rl_starts", "1", "rl_requests", "100", "lines_total", "400", "lines_matched", "400"),
	}})
	f.On("as http_hits", cwlogstest.Response{Rows: big})
	col, err := New(railsSource(), checksCfg(), f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return now }
	if err := col.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	var spans []string
	for _, in := range f.Started {
		if strings.Contains(aws.ToString(in.QueryString), "as http_hits") {
			spans = append(spans, time.Unix(aws.ToInt64(in.StartTime), 0).UTC().Format("02T15")+"-"+time.Unix(aws.ToInt64(in.EndTime), 0).UTC().Format("02T15:04:05"))
		}
	}
	if got := strings.Join(spans, " "); got != "20T00-21T08:59:59 20T00-21T00:00:59 21T00-21T08:59:59" {
		t.Fatalf("分け方: %s", got)
	}
	if tr := col.FormatStats().Truncated; strings.Join(tr, ",") != "sign_in_failures,probe_hits" {
		t.Fatalf("truncated: %v", tr)
	}
}

// doctor 用のまとめ: 行の種類ごとの当たった数が出る (当たらない行の種類を見て設定を直せる)。
func TestRequestSummary(t *testing.T) {
	var ev []cwlogstest.Event
	for i := 0; i < 8; i++ {
		ev = append(ev, railsReq(day21(1, 0, i), "", rid(i), "GET", "/", "192.0.2.200", 200)...)
	}
	ev = append(ev, railsNoRoute(day21(1, 1, 0), rid(100), "/.env", "198.51.100.8")...)
	ev = append(ev, railsReq(day21(1, 2, 0), "", rid(101), "GET", "/slow", "192.0.2.200", 0)...)
	ev = append(ev, cwlogstest.Event{Time: day21(1, 3, 0), Fields: map[string]string{"@message": "untagged"}})
	f := &cwlogstest.Fake{}
	registerRequests(f, &cwlogstest.Sim{Events: ev}, checksCfg(), "web")
	col, err := New(railsSource(), checksCfg(), f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return now }
	s, err := col.RequestSummary(context.Background(), now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Stats.Total != 10 || s.Stats.Complete != 10 || s.Stats.WithStatus != 9 || s.Stats.Starts != 10 || s.Lines != 40 || s.Tagged != 39 {
		t.Fatalf("summary: %+v", s)
	}
	if got := fmt.Sprint(s.Kinds); got != "[{started 10} {completed 8} {no_route 1}]" {
		t.Fatalf("kinds: %s", got)
	}
	if RequestProblem(s.Stats) != "" {
		t.Fatalf("problem: %s", RequestProblem(s.Stats))
	}
	// request_lines でないソースには無い
	ncol, _ := New(nginxSource(), checksCfg(), f)
	if s, err := ncol.RequestSummary(context.Background(), now.Add(-time.Hour), now); s != nil || err != nil {
		t.Fatalf("nginx: %v %v", s, err)
	}
}

func TestParseEpochMillis(t *testing.T) {
	// 1 段目で作った時刻は、2 段目では数 (エポックからのミリ秒) になる
	ms := strconv.FormatInt(day21(3, 20, 0).UnixMilli(), 10)
	if tm, ok := parseTime(ms); !ok || !tm.Equal(day21(3, 20, 0)) {
		t.Fatalf("parseTime(%s) = %v %v", ms, tm, ok)
	}
	if d, ok := parseDay(ms); !ok || d != "2026-10-21" {
		t.Fatalf("parseDay(%s) = %v %v", ms, d, ok)
	}
	for _, s := range []string{"404", "20261021", "99999999999999999999", "-1792540800000", "1792540800000.5"} {
		if _, ok := parseTime(s); ok {
			t.Errorf("parseTime(%q) を時刻として読んだ", s)
		}
	}
}
