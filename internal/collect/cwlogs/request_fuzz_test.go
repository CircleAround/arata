package cwlogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
)

// request_lines のファズテスト (ADR 0041・0051)。設定の正規表現 (利用者のファイル。LLM が書く) と、Insights の結果 (ログ由来の値) を解釈する関数が対象。

// 設定の正規表現のキャプチャの付け替え。
// 守る規則: RE2 で読める正規表現は、付け替えた後も RE2 で読め、キャプチャの数と順番が同じで、名前は rl_ を前に付けたものになり、
// 同じ文字列の同じ位置に一致する (エスケープや文字クラスの中の `(?P<` を書き換えて意味を変えない)。/ はすべてエスケープされる。
func FuzzPrefixCaptures(f *testing.F) {
	for _, s := range []string{railsID, `Started (?P<method>[A-Z]+) "(?P<path>[^"?]*)[^"]*" for (?P<ip>\S+) at `, `Completed (?<status>\d{3}) `,
		`\(?P<ip>x\)`, `[(?P<ip>]+`, `[^](?P<ip>]`, `[[:alpha:](?<ip>]`, `\Q(?P<ip>\E(?P<path>/a)`, `\Q(?P<ip>`, `(?i)(?P<ua>a/b)`, `(?:(?P<ip>a)|b)`, `a\`, `[a`, `/(?P<path>\/x)/`, ""} {
		f.Add(s, `I, [2026-11-01T01:02:03.000000 #1]  INFO -- : [5b0c-e1] Started GET "/a?b" for 203.0.113.10 at x`)
	}
	f.Fuzz(func(t *testing.T, expr, input string) {
		re, err := regexp.Compile(expr)
		if err != nil {
			return
		}
		got := prefixCaptures(expr, rlPrefix)
		pre, err := regexp.Compile(got)
		if err != nil {
			t.Fatalf("prefixCaptures(%q) = %q: RE2 で読めない: %v", expr, got, err)
		}
		a, b := re.SubexpNames(), pre.SubexpNames()
		if len(a) != len(b) {
			t.Fatalf("prefixCaptures(%q) = %q: キャプチャの数が変わった", expr, got)
		}
		for i := range a {
			if (a[i] == "" && b[i] != "") || (a[i] != "" && b[i] != rlPrefix+a[i]) {
				t.Fatalf("prefixCaptures(%q) = %q: キャプチャ %d の名前 %q → %q", expr, got, i, a[i], b[i])
			}
		}
		if x, y := fmt.Sprint(re.FindStringSubmatchIndex(input)), fmt.Sprint(pre.FindStringSubmatchIndex(input)); x != y {
			t.Fatalf("prefixCaptures(%q) = %q: %q への一致が変わった: %s → %s", expr, got, input, x, y)
		}
		if unescapedSlash(escapeSlashes(got)) {
			t.Fatalf("escapeSlashes(%q): エスケープされていない / がある", got)
		}
	})
}

// 解釈率のクエリの結果の 1 行 (Insights の値。任意の文字列) の解釈。
// 守る規則: 件数は有限で負でなく、JSON にできる。まとめた数の関係 (最初の行のある数 ≤ 全体、使い回しの数 ≤ 最初の行のある数、
// ステータスのある数 ≤ 全体) が成り立つ。数えるリクエストの数 (最初の行の数) は、最初の行のあるリクエストの数より小さくならない。
func FuzzRequestRows(f *testing.F) {
	f.Add("100", "1", "400", "400", "200", "3", "0")
	f.Add("1", "30", "120", "120", "422", "1", "2")
	f.Add("2", "3", "12", "0", "", "0", "0")
	f.Add("NaN", "-1", "Inf", "1e999", " ", "1e30", "9223372036854775807")
	f.Add("0.5", "1.9", "x", "", "404", "99999999999", "1")
	f.Fuzz(func(t *testing.T, requests, starts, total, matched, status, requests2, starts2 string) {
		rows := []map[string]string{
			{rlRequests: requests, rlStarts: starts, MetricLinesTotal: total, MetricLinesMatched: matched, "status": status, "day": "2026-10-21 00:00:00.000"},
			{rlRequests: requests2, rlStarts: starts2, MetricLinesTotal: matched, MetricLinesMatched: matched, "day": total},
		}
		for _, r := range rows {
			rr := readRequestRow(r)
			if rr.Requests < 0 || rr.Starts < 0 || rr.Requests > maxRequestCount || rr.Starts > maxRequestCount || rr.Hits() < 0 {
				t.Fatalf("readRequestRow(%v) = %+v", r, rr)
			}
			if rr.Starts >= 1 && rr.Hits() < rr.Requests {
				t.Fatalf("数えるリクエストの数が、最初の行のあるリクエストの数より減った: %+v", rr)
			}
		}
		st := requestStats(rows, 0.8)
		if _, err := json.Marshal(st); err != nil {
			t.Fatalf("JSON にできない: %v", err)
		}
		if st.Total < 0 || st.Complete < 0 || st.Starts < 0 || st.Reused < 0 || st.WithStatus < 0 || st.StartsUntagged < 0 ||
			st.Complete > st.Total || st.Reused > st.Complete || st.WithStatus > st.Total || st.Starts < st.Complete {
			t.Fatalf("requestStats(%v) = %+v", rows, st)
		}
		if rate, ok := st.CompleteRate(); ok && (rate < 0 || rate > 1) {
			t.Fatalf("まとめられた割合が 0〜1 でない: %v", rate)
		}
		// 取り違えの検査は、鍵の数が最初の行の数の半分未満なら必ず止める
		if st.Total > 0 && st.Total*2 < st.Starts && RequestProblem(st) != RequestProblemID {
			t.Fatalf("鍵の取り違えを止めなかった: %+v", st)
		}
	})
}

// ログの行から収集の全体を通す (cwlogstest.Sim が 2 段の stats を解釈する。実 AWS には接続しない)。
// ids の各バイトが 1 リクエストで、値はそのリクエストの request_id (同じ値 = 使い回し。0 はタグなし)。全部がログインの失敗。
// 守る規則 (ADR 0051):
//   - 同じ request_id を何度使っても、数えたリクエストの数は最初の行の数より減らない。収集が通ったなら、
//     ログインの失敗の件数 = request_id の付いた最初の行の数、ちょうど
//   - 鍵の数が最初の行の数の半分未満なら FORMAT_MISMATCH で止まり、metrics を 1 つも出さない (黙って数えない)
//   - 最初の角括弧を鍵にする設定 (取り違え) は、行頭に別の角括弧がある行で必ず止まる
func FuzzRequestCollect(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, byte(1))
	f.Add([]byte{1, 1, 1, 1, 2, 3, 4, 5, 6, 7}, byte(3))
	f.Add([]byte{9, 9, 9, 9, 9, 9, 9, 9}, byte(0))
	f.Add([]byte{0, 0, 1, 2, 3, 0}, byte(2))
	f.Add([]byte{}, byte(0))
	f.Fuzz(func(t *testing.T, ids []byte, statusless byte) {
		if len(ids) > 200 {
			ids = ids[:200]
		}
		c := checksCfg()
		var ev, prefixed []cwlogstest.Event
		// noStatus は、最後の行が出ないリクエストか (その ID の最初のリクエストだけ。途中のリクエストの見本)
		noStatus := func(i int) bool { return statusless != 0 && i%int(statusless) == 1 && firstIndex(ids, ids[i]) == i }
		distinct := map[byte]bool{}
		for i, id := range ids {
			at := day21(1, i/60, i%60)
			status := 422
			if noStatus(i) {
				status = 0
			}
			name := ""
			if id != 0 {
				name = fmt.Sprintf("id_%d@x", id)
				distinct[id] = true
			}
			ev = append(ev, railsReq(at, "", name, "POST", "/users/sign_in", "198.51.100.7", status)...)
			prefixed = append(prefixed, railsReq(at, "[web-1] ", name, "POST", "/users/sign_in", "198.51.100.7", 422)...)
		}
		w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
		sink, col, _, err := collectRequests(t, railsSource(), c, ev, w)
		starts := 0
		for _, id := range ids {
			if id != 0 {
				starts++
			}
		}
		var ce *collect.Error
		switch {
		case err == nil:
			rs := col.FormatStats().Requests
			if rs == nil {
				if len(ids) != 0 {
					t.Fatalf("リクエスト単位の集計が無い")
				}
				return
			}
			if rs.Starts != int64(starts) || rs.Total != int64(len(distinct)) || rs.StartsUntagged != int64(len(ids)-starts) {
				t.Fatalf("最初の行 %d・鍵 %d・タグなし %d のはずが %+v", starts, len(distinct), len(ids)-starts, rs)
			}
			if rs.Total*2 < rs.Starts {
				t.Fatalf("鍵の数が最初の行の数の半分未満なのに通った: %+v", rs)
			}
			// ステータスが 1 つも無い ID は失敗に数えない。それ以外の ID は、最初の行の数だけ数える
			want := 0.0
			for id := range distinct {
				n, has := 0, false
				for i, x := range ids {
					if x == id {
						n++
						has = has || !noStatus(i)
					}
				}
				if has {
					want += float64(n)
				}
			}
			if got := sink.metrics()["2026-10-21|sign_in_failures|198.51.100.7"]; got != want {
				t.Fatalf("ログインの失敗 %v 件のはずが %v 件 (ids=%v statusless=%d)", want, got, ids, statusless)
			}
			checkRecords(t, sink.recs)
		case errors.As(err, &ce) && ce.Code == collect.CodeFormatMismatch:
			if len(sink.recs) != 0 {
				t.Fatalf("FORMAT_MISMATCH なのに metrics を出した")
			}
		default:
			t.Fatalf("Collect: %v", err)
		}

		// 取り違える設定: 行頭の角括弧 (ホスト名) が鍵になり、全部の行が 1 つの鍵にまとまる
		if starts < 3 {
			return
		}
		bad := railsSource()
		bad.Request.ID = `\[(?P<request_id>[^\]]+)\] `
		sink, _, _, err = collectRequests(t, bad, c, prefixed, w)
		if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch || len(sink.recs) != 0 {
			t.Fatalf("取り違える設定を止めなかった: %v", err)
		}
	})
}

func firstIndex(ids []byte, id byte) int {
	for i, x := range ids {
		if x == id {
			return i
		}
	}
	return -1
}

// request_lines のソースの集計結果 (Insights の行) の値を任意の文字列にして、収集の全体を通す。
// 守る規則: パニックしない。通ったなら record は JSON にでき、値は件数で、パスと IP に入れたメールアドレスが残らない。
func FuzzCollectRequestRows(f *testing.F) {
	f.Add("2026-10-21 00:00:00.000", "/.env", "198.51.100.7", "404", "3", "1", "1792552800000", "POST")
	f.Add("1792540800000", "/users/sign_in", "198.51.100.7, 203.0.113.9", "422", "40", "2", "2026-10-21 03:20:00.000", "POST")
	f.Add("2026-10-21", "/wp-login.php?u=alice@example.com", "::1", "", "1e3", "0", "2026-10-21T03:25:00Z", "GET")
	f.Add("x", "\n", "", "", "NaN", "-1", "", "")
	f.Fuzz(func(t *testing.T, day, path, ip, status, n, starts, bin, method string) {
		ipv, pathv := ip+fuzzEmail, path+"/"+fuzzEmail
		fake := &cwlogstest.Fake{}
		fake.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "status", "200", rlStarts, "1", rlRequests, "1000", "lines_total", "4000", "lines_matched", "4000"),
			cwlogstest.Rows("day", day, "status", status, "probe_path", pathv, rlStarts, starts, rlRequests, n, "lines_total", n, "lines_matched", starts, kindTotal(0), n),
		}})
		fake.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
			cwlogstest.Rows("day", day, "ip", ipv, "method", method, "status", status, "sign_in", pathv, "probe", pathv, "http_hits", n),
			cwlogstest.Rows("day", bin, "ip", ipv, "method", "POST", "status", "422", "sign_in", "/users/sign_in", "http_hits", n),
		}})
		var hits []map[string]string
		for i := 0; i < 6; i++ {
			hits = append(hits, cwlogstest.Rows("t", bin, "ip", fmt.Sprintf("%s%d", ipv, i), "method", "POST", "status", "200", "ep0_0", pathv, endpointHits, n, "first_seen", bin, "last_seen", day))
		}
		fake.On(endpointHits, cwlogstest.Response{Rows: hits})
		c, err := New(railsSource(), abuseChecks(), fake)
		if err != nil {
			t.Fatal(err)
		}
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		c.Now = func() time.Time { return now }
		sink := &sinkRecorder{}
		err = c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink)
		var ce *collect.Error
		if err != nil && !(errors.As(err, &ce) && ce.Code == collect.CodeFormatMismatch) {
			t.Fatalf("Collect: %v", err)
		}
		if err != nil && len(sink.recs) != 0 {
			t.Fatalf("FORMAT_MISMATCH なのに metrics を出した")
		}
		checkRecords(t, sink.recs, fuzzEmail)
		if rs := c.FormatStats().Requests; rs == nil || rs.Complete > rs.Total || rs.Starts < rs.Complete {
			t.Fatalf("requests: %+v", rs)
		}
	})
}
