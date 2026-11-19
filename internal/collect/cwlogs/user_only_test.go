package cwlogs

import (
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// yields: http_user のソース (ADR 0075)。入口のアクセスログを別のソースで読むとき、アプリのログからユーザー ID と auth の行だけを読む。
// http_access の集計 (sign_in_failures・probe_hits・probe_paths・endpoint_abuse) は出さず、クエリも解釈率の 1 本だけにする。

func userOnlySource() config.Source {
	s := userSource(actorRegex, authRegex)
	s.Yields = config.YieldsHTTPUser
	return s
}

func TestUserOnlyQueries(t *testing.T) {
	col, err := New(userOnlySource(), abuseChecks(), &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	if kindsOf(col) != "http_user" {
		t.Fatalf("yields: %s", kindsOf(col))
	}
	qs := col.queries()
	if len(qs) != 1 || qs[0].Name != httpLines || col.QueryCount() != 1 {
		t.Fatalf("クエリは解釈率の 1 本だけ: %d %v", len(qs), qs)
	}
	q := qs[0].Query
	(&cwlogstest.Sim{}).Rows(q, now, now, nil)
	// 探索パスの印は付けない (http_access の集計を作らない)。actor と auth の行は読む
	if strings.Contains(q, "probe_path") || !strings.Contains(q, "actor kind=") || !strings.Contains(q, "auth result=") {
		t.Fatalf("解釈率のクエリ:\n%s", q)
	}
	// http_access だけを求める run は引かない。http_user を求める run は引く
	col.Select(map[record.Kind]bool{record.KindHTTPAccess: true})
	if kindsOf(col) != "" {
		t.Fatalf("http_access の run で: %s", kindsOf(col))
	}
	col.Select(map[record.Kind]bool{record.KindHTTPUser: true})
	if kindsOf(col) != "http_user" {
		t.Fatalf("http_user の run で: %s", kindsOf(col))
	}
}

func TestUserOnlyCollect(t *testing.T) {
	var ev []cwlogstest.Event
	n := 0
	add := func(count int, method, uri, ip string, status int, extra ...string) {
		for i := 0; i < count; i++ {
			n++
			ev = append(ev, userReq(day21(1, n/60, n%60), rid(n), method, uri, ip, status, extra...)...)
		}
	}
	add(10, "GET", "/", "192.0.2.200", 200)
	add(6, "GET", "/items", "192.0.2.200", 200, "actor kind=user id=42")
	add(3, "POST", "/users/sign_in", "198.51.100.7", 422, "auth result=failure kind=user id=42 reason=invalid")
	add(2, "GET", "/.env", "198.51.100.9", 404)
	sink, col, f, err := collectRequests(t, userOnlySource(), checksCfg(), ev, userWindow)
	if err != nil {
		t.Fatal(err)
	}
	// 流すのは解釈率のクエリだけ (窓が UTC の 2 日にかかるので 1 日ずつ 2 回)。http_hits・endpoint_abuse は流さない
	for _, q := range f.Queries() {
		if !strings.Contains(q, "as lines_total") || strings.Contains(q, "as http_hits") || strings.Contains(q, endpointHits) {
			t.Fatalf("解釈率でないクエリを流した:\n%s", q)
		}
	}
	if got := len(f.Queries()); got != 2 {
		t.Fatalf("クエリの回数: %d", got)
	}
	m := sink.metrics()
	for k, want := range map[string]float64{
		"2026-10-21|user_requests|user": 6, "2026-10-21|auth_failures|invalid": 3, "2026-10-21|requests_total|": 21,
	} {
		if got, ok := m[k]; !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", k, got, ok, want)
		}
	}
	// 入口のアクセスログと二重に数えない: http_access の metric は 1 つも出さない (From もすべて http_user)
	for _, r := range sink.recs {
		mt := r.(record.Metric)
		if mt.From != record.KindHTTPUser {
			t.Errorf("%s の From が %s", mt.Metric, mt.From)
		}
		switch mt.Metric {
		case MetricSignInFailures, MetricProbeHits, MetricProbePaths:
			t.Errorf("http_access の集計 %s を出した", mt.Metric)
		}
	}
	if col.Unavailable() != nil || col.FormatStats().Requests.Users.Requests != 6 {
		t.Fatalf("users: %v %+v", col.Unavailable(), col.FormatStats().Requests.Users)
	}
}

// ID の付いたリクエストが 0 件の日も、ソースは失敗にしない (毎日の run を落とさない)。http_user は「取れない」になり、数は 0 として残す。
func TestUserOnlyNone(t *testing.T) {
	var ev []cwlogstest.Event
	for i := 0; i < 20; i++ {
		ev = append(ev, userReq(day21(1, 0, i), rid(i), "GET", "/", "192.0.2.200", 200)...)
	}
	sink, col, _, err := collectRequests(t, userOnlySource(), checksCfg(), ev, userWindow)
	if err != nil {
		t.Fatalf("0 件の日にソースが失敗した: %v", err)
	}
	if !strings.Contains(col.Unavailable()[record.KindHTTPUser], "0 件") {
		t.Fatalf("0 件の run の理由: %v", col.Unavailable())
	}
	m := sink.metrics()
	if m["2026-10-21|requests_total|"] != 20 {
		t.Fatalf("metrics: %v", m)
	}
	if _, ok := m["2026-10-21|user_id_invalid|"]; !ok {
		t.Fatalf("0 件の日の数が残らない: %v", m)
	}
}
