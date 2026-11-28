package cwlogs

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// 同じ IP からログインできた利用者の数 (ip_users。U3。ADR 0094 の 2 節)。値はすべて架空。実 AWS には接続しない (cwlogstest.Sim)。

func ipUsersChecks(sources ...string) config.Checks {
	c := config.DefaultChecks()
	c.RateLimitedIP.UserSources = sources
	c.RateLimitedIP.IPUsersStoreMin = 2
	return c
}

// ipUsersEvents は 1 日分のリクエスト。203.0.113.50 は 12 人がログインした回線、198.51.100.31 は 2 人、198.51.100.30 は 1 人。
func ipUsersEvents() []cwlogstest.Event {
	var ev []cwlogstest.Event
	n := 0
	req := func(ip, actor string) {
		n++
		var extra []string
		if actor != "" {
			extra = append(extra, actor)
		}
		ev = append(ev, userReq(day21(1, n/60, n%60), rid(n), "GET", "/items", ip, 200, extra...)...)
	}
	for u := 1; u <= 12; u++ {
		req("203.0.113.50", fmt.Sprintf("actor kind=user id=%d", u))
		req("203.0.113.50", fmt.Sprintf("actor kind=user id=%d", u)) // 同じ利用者の 2 回目は増えない
	}
	for i := 0; i < 5; i++ {
		req("198.51.100.30", "actor kind=user id=42")
	}
	req("198.51.100.31", "actor kind=user id=50")
	req("198.51.100.31", "actor kind=admin id=50") // 種類が違えば別の利用者
	// 代わりにログインした操作・ログイン前・IP の形に合わない値は数えない
	for u := 70; u < 75; u++ {
		req("203.0.113.60", fmt.Sprintf("actor kind=user id=%d by=staff:5", u))
		req("203.0.113.61", "")
		req("not-an-ip", fmt.Sprintf("actor kind=user id=%d", u))
	}
	return ev
}

func ipUsersMetrics(s *sinkRecorder) map[string]float64 {
	out := map[string]float64{}
	for k, v := range s.metrics() {
		if m := strings.Split(k, "|")[1]; m == MetricIPUsers || m == MetricUserProbeDays {
			out[k] = v
		}
	}
	return out
}

func TestIPUsersMetrics(t *testing.T) {
	sink, _, err := collectProbe(t, userSource(actorRegex, ""), ipUsersChecks("web"), ipUsersEvents(), userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		"2026-10-21|ip_users|203.0.113.50":  12,
		"2026-10-21|ip_users|198.51.100.31": 2,
		// 198.51.100.30 は 1 人で store_min (2) 未満。流した日の印は、利用者の行のあった日だけ (10-20 は行が無い)
		"2026-10-21|user_probe_days|ip_users": 1,
	}
	if got := ipUsersMetrics(sink); dump(got) != dump(want) {
		t.Fatalf("got:\n%swant:\n%s", dump(got), dump(want))
	}
	// 利用者の ID は結果に出さない
	for k := range sink.metrics() {
		if strings.Contains(k, "ip_users") && (strings.Contains(k, "user:") || strings.Contains(k, "staff")) {
			t.Errorf("key %q contains a user", k)
		}
	}
}

// 流す条件: user_sources にあるソースで、この run に http_user の要るチェックがあるときだけ。
func TestIPUsersGating(t *testing.T) {
	ran := func(f *cwlogstest.Fake) int {
		n := 0
		for _, q := range f.Queries() {
			if strings.Contains(q, "as "+MetricIPUsers) {
				n++
			}
		}
		return n
	}
	ev := ipUsersEvents()
	for _, c := range []struct {
		name   string
		checks config.Checks
		needs  map[record.Kind]bool
		want   int
	}{
		{"user_sources が空", ipUsersChecks(), nil, 0},
		{"別のソースだけ", ipUsersChecks("other"), nil, 0},
		{"http_user の要るチェックが run に無い", ipUsersChecks("web"), map[record.Kind]bool{record.KindHTTPAccess: true}, 0},
		{"http_user が要る (2 日にまたがる窓は 1 日ずつ)", ipUsersChecks("web"), map[record.Kind]bool{record.KindHTTPUser: true}, 2},
	} {
		_, f, err := collectProbe(t, userSource(actorRegex, ""), c.checks, ev, userWindow, c.needs)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := ran(f); got != c.want {
			t.Errorf("%s: U3 %d, want %d", c.name, got, c.want)
		}
	}
	// U3 だけなら U1・U2 は流さない
	_, f, err := collectProbe(t, probeSource(t), ipUsersChecks("web"), ev, userWindow, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range f.Queries() {
		if strings.Contains(q, "count(u_dn) as") || strings.Contains(q, "as "+MetricUserIDsOK) {
			t.Fatalf("U1・U2 を流した:\n%s", q)
		}
	}
}

// U3 の文: 1 段目のあと、(日, IP, 利用者) で 1 行にし、(日, IP) で利用者を数える。2 段目以降に earliest・latest・数でない min・max を使わない (Sim が止める)。
func TestIPUsersQuery(t *testing.T) {
	p, err := ProfileFor(userSource(actorRegex, ""))
	if err != nil {
		t.Fatal(err)
	}
	q := IPUsersQuery(p)
	for _, want := range []string{
		"\n| filter not ispresent(by_id)\n| filter ispresent(ip)\n",
		"\n| stats count(*) as u_n by day, ip, user_kind, user_id\n| stats count(*) as ip_users by day, ip\n| sort ip_users desc\n| limit 10000",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query lacks %q:\n%s", want, q)
		}
	}
	if n := len(q); n > UserQueryLen {
		t.Fatalf("len %d", n)
	}
	col, err := New(userSource(actorRegex, ""), ipUsersChecks("web"), &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := col.Queries()[UserProbeIPUsers]; !ok {
		t.Fatalf("doctor の構文の検査に U3 が入らない: %v", col.Queries())
	}
}

// ipUsersKey は結果の行の IP を key にする。形に合わない値は捨て、正規の形にそろえる (ログ由来の値。ADR 0037)。
func TestIPUsersKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.50": "203.0.113.50", " 203.0.113.50 ": "203.0.113.50", "::ffff:203.0.113.50": "203.0.113.50",
		"2001:DB8::1": "2001:db8::1", "fe80::1%eth0": "fe80::1",
		"": "", "not-an-ip": "", "203.0.113.50, 10.0.0.1": "", "alice@example.com": "",
	} {
		got, ok := ipUsersKey(in)
		if got != want || ok != (want != "") {
			t.Errorf("ipUsersKey(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

// FuzzIPUsersRows: U3 の結果の行 (Insights の結果。ログ由来の値) を、どんな値で返されても、
// ip_users の key は netip で読める正規の形の IP (読み直しても同じ文字列) だけになり、値は ip_users_store_min 以上の有限の整数になる。
// 流した日の印は、key を 1 つでも読めた日にだけ付く (読めなかった日を「0 人」と取り違えない)。
func FuzzIPUsersRows(f *testing.F) {
	f.Add("2026-10-21 00:00:00.000", "203.0.113.50", "12")
	f.Add("2026-10-21 00:00:00.000", "::ffff:203.0.113.50", "1e400")
	f.Add("2026-10-21", "alice@example.com", "3")
	f.Add("x", "fe80::1%eth0", "-3")
	f.Add("2026-10-21 00:00:00.000", "203.0.113.50|x", "NaN")
	c := ipUsersChecks("web")
	c.RateLimitedIP.IPUsersStoreMin = 1
	col, err := New(userSource(actorRegex, ""), c, &cwlogstest.Fake{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, day, ip, n string) {
		row := cwlogstest.Rows("day", day, "ip", ip, MetricIPUsers, n)
		sink := &sinkRecorder{}
		if err := col.emitIPUsers(t.Context(), []map[string]string{row, row}, sink); err != nil {
			t.Fatal(err)
		}
		marks, values := 0, 0
		for _, r := range sink.recs {
			m := r.(record.Metric)
			if m.From != record.KindHTTPUser {
				t.Fatalf("from %+v", m)
			}
			switch m.Metric {
			case MetricUserProbeDays:
				if m.Key != UserProbeIPUsers || m.Value != 1 {
					t.Fatalf("mark %+v", m)
				}
				marks++
			case MetricIPUsers:
				a, err := netip.ParseAddr(m.Key)
				if err != nil || a.String() != m.Key || a.Zone() != "" || a.Is4In6() {
					t.Fatalf("key %q (from %q)", m.Key, ip)
				}
				if m.Value < 1 || m.Value != m.Value || m.Value > maxRequestCount*2 || m.Value != float64(int64(m.Value)) {
					t.Fatalf("value %+v", m)
				}
				values++
			default:
				t.Fatalf("metric %+v", m)
			}
		}
		_, okDay := parseDay(day)
		_, okIP := ipUsersKey(ip)
		if wantMark := okDay && okIP; (marks == 1) != wantMark || marks > 1 {
			t.Fatalf("marks %d (day %q ip %q)", marks, day, ip)
		}
		if values > 1 {
			t.Fatalf("同じ IP を 2 つの key にした: %v", sink.recs)
		}
	})
}

// doctor の突き合わせ (ADR 0094 の「確かめが要る点」の 1): U3 の上位の IP と、http_access のソースにその IP が現れるか。
func TestIPUsersDoctorHelpers(t *testing.T) {
	f := &cwlogstest.Fake{}
	sim := &cwlogstest.Sim{Events: ipUsersEvents()}
	f.On("as "+MetricIPUsers, sim.Response(nil))
	col, err := New(userSource(actorRegex, ""), ipUsersChecks("web"), f)
	if err != nil {
		t.Fatal(err)
	}
	top, err := col.IPUsersTop(t.Context(), userWindow.From, userWindow.To, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(top, ",") != "203.0.113.50" {
		t.Fatalf("top = %v", top)
	}
	top, err = col.IPUsersTop(t.Context(), userWindow.From, userWindow.To, 10)
	if err != nil {
		t.Fatal(err)
	}
	// 1 人だけの IP も入る (store_min で落とさない)。読めない IP は入らない
	if strings.Join(top, ",") != "203.0.113.50,198.51.100.31,198.51.100.30" {
		t.Fatalf("top = %v", top)
	}

	at := day21(2, 0, 0)
	alb := &cwlogstest.Sim{Events: []cwlogstest.Event{
		nginxEv(at, "203.0.113.50", "GET", "/items", 200, "Browser/1", 3),
		nginxEv(at, "10.0.0.5", "GET", "/items", 200, "Browser/1", 3),
	}}
	f2 := &cwlogstest.Fake{}
	f2.On("as arata_ip_hits", alb.Response(nil))
	web, err := New(nginxSource(), checksCfg(), f2)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := web.IPsPresent(t.Context(), append(top, `" or 1=1`), userWindow.From, userWindow.To)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || !seen["203.0.113.50"] {
		t.Fatalf("seen = %v", seen)
	}
	q := f2.Queries()[0]
	if !strings.Contains(q, `| filter ip in ["203.0.113.50", "198.51.100.31", "198.51.100.30"]`) || strings.Contains(q, "1=1") {
		t.Fatalf("query:\n%s", q)
	}
}
