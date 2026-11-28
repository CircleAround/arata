package cwlogs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
)

// rate_limited (ADR 0094 の 2 節): http_hits のクエリの 3 つ目の選択肢。値はすべて架空。実 AWS には接続しない (cwlogstest.Sim)。

func rateChecks(paths ...string) config.Checks {
	c := checksCfg()
	c.RateLimitedIP.Statuses = []int{429}
	c.RateLimitedIP.Paths = paths
	return c
}

func rateEvents() []cwlogstest.Event {
	at := func(h int) time.Time { return time.Date(2026, 10, 21, h, 0, 0, 0, time.UTC) }
	return []cwlogstest.Event{
		nginxEv(at(1), "192.0.2.200", "GET", "/", 200, "Browser/1", 50),
		// 429 はステータスだけで数える (sign-in の失敗のステータスに無くても数える)
		nginxEv(at(2), "198.51.100.20", "POST", "/users/sign_in", 429, "Browser/1", 25),
		nginxEv(at(2), "198.51.100.20", "POST", "/users/sign_in", 401, "Browser/1", 3),
		nginxEv(at(3), "198.51.100.21", "GET", "/api/items", 429, "Browser/1", 4),
		nginxEv(at(3), "198.51.100.21", "GET", "/api/items", 503, "Browser/1", 2),
		// 探索のパスへの 429 は、探索 (403・404) には数えず、429 には数える
		nginxEv(at(4), "198.51.100.22", "GET", "/.env", 429, "scan/1", 1),
	}
}

func collectRate(t *testing.T, c config.Checks) map[string]float64 {
	t.Helper()
	sim := &cwlogstest.Sim{Events: rateEvents()}
	f := &cwlogstest.Fake{}
	registerHTTP(f, sim, httpPreds{c: c})
	col, err := New(nginxSource(), c, f)
	if err != nil {
		t.Fatal(err)
	}
	col.Sleep = func(context.Context, time.Duration) error { return nil }
	sink := &sinkRecorder{}
	if err := col.Collect(t.Context(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for k, v := range sink.metrics() {
		if m := strings.Split(k, "|")[1]; m == MetricRateLimited || m == MetricSignInFailures || m == MetricProbeHits {
			out[k] = v
		}
	}
	return out
}

func TestRateLimitedMetric(t *testing.T) {
	want := map[string]float64{
		"2026-10-21|rate_limited|198.51.100.20":     25,
		"2026-10-21|rate_limited|198.51.100.21":     4,
		"2026-10-21|rate_limited|198.51.100.22":     1,
		"2026-10-21|sign_in_failures|198.51.100.20": 3,
	}
	if got := collectRate(t, rateChecks()); dump(got) != dump(want) {
		t.Fatalf("got:\n%swant:\n%s", dump(got), dump(want))
	}
}

// paths (接頭辞) を書けば、そのパスへの 429 だけを数える。
func TestRateLimitedPaths(t *testing.T) {
	want := map[string]float64{
		"2026-10-21|rate_limited|198.51.100.20":     25,
		"2026-10-21|sign_in_failures|198.51.100.20": 3,
	}
	if got := collectRate(t, rateChecks("/users/")); dump(got) != dump(want) {
		t.Fatalf("got:\n%swant:\n%s", dump(got), dump(want))
	}
}

// クエリは新しく足さず、http_hits の条件の 3 つ目の選択肢にする (ADR 0031)。
func TestRateLimitedQuery(t *testing.T) {
	p, err := ProfileFor(nginxSource())
	if err != nil {
		t.Fatal(err)
	}
	q := HTTPHitsQuery(p, rateChecks("/users/", "/api/"))
	for _, want := range []string{
		` or (status in [429] and path like /^(\/users\/|\/api\/)/)`,
		`parse path /^(?<rate_path>\/users\/|\/api\/)/`,
		`by bin(1d) as day, ip, method, status, sign_in, probe, rate_path`,
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query lacks %q:\n%s", want, q)
		}
	}
	// paths が空なら印を付けない (全パス)
	q = HTTPHitsQuery(p, rateChecks())
	if !strings.Contains(q, ` or (status in [429])`) || strings.Contains(q, "rate_path") {
		t.Errorf("query:\n%s", q)
	}
	col, err := New(nginxSource(), rateChecks(), &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	if n := col.QueryCount(); n != 2 {
		t.Fatalf("QueryCount = %d (http_lines と http_hits の 2 本のまま)", n)
	}
}
