package cwlogs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/pathids"
)

// パスの型 (path_ids。ADR 0071 の 2 節・0087) の doctor 用の集計。値はすべて架空。実 AWS には接続しない (cwlogstest.Sim)。

func pathRules(t *testing.T) *config.PathIDs {
	t.Helper()
	return mustPathIDs(t, config.PathIDs{Segments: []string{`[0-9]{1,20}`}, Templates: []string{"/shops/:id/items/:id"}, Formats: []string{"json"}, MaxSegments: 8})
}

// mustPathIDs は設定を読み込んで検証済みの path_ids を返す (config の検証を通す)。
func mustPathIDs(t *testing.T, p config.PathIDs) *config.PathIDs {
	t.Helper()
	src := config.Source{ID: "web", Kind: config.KindCloudWatchLogs, Format: config.FormatNginxAccess, Yields: config.YieldsHTTPAccess, PathIDs: &p}
	if err := src.CompilePathIDs(); err != nil {
		t.Fatal(err)
	}
	return src.PathIDs
}

func pathCollector(t *testing.T, src config.Source, ev []cwlogstest.Event) *Collector {
	t.Helper()
	f := &cwlogstest.Fake{}
	f.On("as "+pathRequestsCol, (&cwlogstest.Sim{Events: ev}).Response(nil))
	col, err := New(src, checksCfg(), f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	col.Now = func() time.Time { return now }
	return col
}

func TestPathTemplatesUsers(t *testing.T) {
	src := userSource(actorRegex, "")
	src.PathIDs = pathRules(t)
	var ev []cwlogstest.Event
	n := 0
	req := func(at time.Time, uri, actor string) {
		n++
		var extra []string
		if actor != "" {
			extra = append(extra, actor)
		}
		ev = append(ev, userReq(at, rid(n), "GET", uri, "192.0.2.200", 200, extra...)...)
	}
	req(day21(1, 0, 0), "/orders/1", "actor kind=user id=41")
	req(day21(1, 0, 1), "/orders/2.json", "actor kind=user id=42")
	req(day21(1, 0, 2), "/orders/3?page=2", "actor kind=user id=42")
	req(day21(1, 0, 3), "/users/taro/orders", "actor kind=user id=42")
	req(day21(1, 0, 4), "/users/taro/orders", "actor kind=user id=42")
	req(day21(1, 0, 5), "/users/hanako/orders", "actor kind=user id=43")
	req(day21(1, 0, 6), "/shops/7/items/31", "actor kind=user id=41")
	req(day21(1, 0, 7), "/shops/8/items/32", "actor kind=user id=43")
	req(day21(1, 0, 8), "/about", "") // ログインしていない要求は数えない
	req(day21(1, 0, 9), "/users/5/orders", "actor kind=user id=41")
	req(day21(1, 0, 10), "/users/6/orders", "actor kind=user id=43")
	col := pathCollector(t, src, ev)
	s, err := col.PathTemplates(context.Background(), userWindow.From, userWindow.To)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range s.Templates {
		got = append(got, fmt.Sprintf("%s requests=%d users=%d", p.Template, p.Requests, p.MaxUsers))
	}
	want := []string{
		"/orders/:id requests=3 users=2",
		"/shops/:id/items/:id requests=2 users=2",
		"/users/:id/orders requests=2 users=2",
		"/users/taro/orders requests=2 users=1",
		"/users/hanako/orders requests=1 users=1",
	}
	if !s.Users || s.Truncated || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("templates (users=%v truncated=%v):\n%s", s.Users, s.Truncated, strings.Join(got, "\n"))
	}
	// 1 人しか触らなかった型の例は、印と設定の templates の固定の区間 (shops・items) だけを残し、ほかは長さだけにする。
	// users・orders は 2 人以上が触った型 (/users/:id/orders) にあっても、ログ由来の値なので伏せる
	if ex := s.SingleUserExamples(5); strings.Join(ex, ", ") != "/<5>/<4>/<6>, /<5>/<6>/<6>" {
		t.Fatalf("examples: %q", ex)
	}
	// クエリは 1 本で、対象 ID は持ち帰らない (結果の列に無い)
	for _, q := range []string{PathTemplatesQuery(col.Profile())} {
		if strings.Contains(q, "("+pathids.IDField+")") || strings.Contains(q, "by day, tpl, user_kind, user_id, ") {
			t.Fatalf("query:\n%s", q)
		}
		if len(q) > 10000 {
			t.Fatalf("query too long: %d", len(q))
		}
	}
}

// 1 行のログ (利用者の ID なし) では、型ごとの件数だけを数える。
func TestPathTemplatesLines(t *testing.T) {
	src := nginxSource()
	src.PathIDs = pathRules(t)
	var ev []cwlogstest.Event
	for i, p := range []string{"/orders/1", "/orders/2.json", "/users/taro/orders", "/about"} {
		ev = append(ev, cwlogstest.Event{Time: day21(1, 0, i), Fields: map[string]string{"@message": fmt.Sprintf(`192.0.2.1 - - [21/Oct/2026:01:00:0%d +0000] "GET %s HTTP/1.1" 200 1 "-" "x"`, i, p)}})
	}
	col := pathCollector(t, src, ev)
	s, err := col.PathTemplates(context.Background(), userWindow.From, userWindow.To)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range s.Templates {
		got = append(got, fmt.Sprintf("%s %d %d", p.Template, p.Requests, p.MaxUsers))
	}
	if s.Users || strings.Join(got, ", ") != "/orders/:id 2 -1, /about 1 -1, /users/taro/orders 1 -1" {
		t.Fatalf("templates: %v %q", s.Users, got)
	}
	// path_ids の無いソースは nil
	col = pathCollector(t, nginxSource(), ev)
	if s, err := col.PathTemplates(context.Background(), userWindow.From, userWindow.To); s != nil || err != nil {
		t.Fatalf("without path_ids: %v %v", s, err)
	}
}

// FuzzSingleUserExamples: 例 (doctor の行に出す) には、ログ由来の区間の値が出ない。残るのは印 (:id など)・設定の templates の固定の区間・`<長さ>` だけ。
// 2 人以上が触った型の同じ位置の値でも出さない (ログイン名の区間は、まさにほかの人も触る位置。ADR 0071 の 2 節)。
func FuzzSingleUserExamples(f *testing.F) {
	f.Add("/alice/followers", "/alice/settings")
	f.Add("/users/taro/orders", "/shops/x/items/y")
	f.Add("/a/:id", "/a/b")
	rules, err := pathids.Compile(pathids.Rules{Segments: []string{`[0-9]{1,20}`}, Templates: []string{"/shops/:id/items/:id"}, MaxSegments: 8})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, shared, single string) {
		s := &PathSummary{Users: true, fixed: rules, Templates: []PathTemplate{
			{Template: rules.Sanitize(shared), Requests: 2, MaxUsers: 2},
			{Template: rules.Sanitize(single), Requests: 1, MaxUsers: 1},
		}}
		for _, ex := range s.SingleUserExamples(5) {
			for i, seg := range strings.Split(ex, "/") {
				switch {
				case i == 0 && seg == "":
				case strings.HasPrefix(seg, ":") || seg == pathids.More || rules.IsFixed(seg):
				case len(seg) >= 3 && seg[0] == '<' && seg[len(seg)-1] == '>' && strings.Trim(seg[1:len(seg)-1], "0123456789") == "":
				default:
					t.Fatalf("example %q has a value %q (shared %q, single %q)", ex, seg, shared, single)
				}
			}
		}
	})
}
