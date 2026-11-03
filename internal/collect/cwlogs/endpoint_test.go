package cwlogs

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
)

func abuseChecks() config.Checks {
	c := checksCfg()
	c.EndpointAbuse = config.EndpointAbuse{
		Window: "10m",
		Endpoints: []config.AbuseEndpoint{
			{Name: "signup", Paths: []string{"/signup"}, Methods: []string{"POST"}},
			{Name: "message", Paths: []string{"/messages", "/messages/*", "/**/messages"}, Methods: []string{"POST"}, Statuses: []int{200, 302}},
			{Name: "other_source", Paths: []string{"/x"}, Sources: []string{"api"}},
		},
		FollowUps:    []config.FollowUp{{From: "signup", To: "message", Within: "30m", MinIPs: 5}},
		ExcludePaths: []string{"/messages/preview"},
	}
	return c
}

// glob を Insights の正規表現にする。照合はクエリを落とし、数字・UUID の区間を :id とみなした (NormalizePath と同じ意味の) パスに対して行う。
func TestEndpointPathRegex(t *testing.T) {
	cases := []struct {
		glob     string
		match    []string
		notMatch []string
	}{
		{"/signup", []string{"/signup", "/signup?ref=x"}, []string{"/signup/x", "/signups", "/x/signup"}},
		{"/messages/*", []string{"/messages/123", "/messages/abc"}, []string{"/messages", "/messages/1/2"}},
		{"/**/messages", []string{"/messages", "/users/1/messages", "/a/b/messages"}, []string{"/messagesx", "/users/1/messages/2"}},
		{"/users/:id/messages", []string{"/users/42/messages", "/users/0f8fad5b-d9cb-469f-a165-70867728950e/messages"}, []string{"/users/me/messages"}},
		// パターンの数字の区間も :id とみなす (正規化したパスと比べるのと同じ)
		{"/users/1/messages", []string{"/users/42/messages"}, []string{"/users/me/messages"}},
		{"/a.b", []string{"/a.b"}, []string{"/axb"}},
	}
	for _, tc := range cases {
		re := regexp.MustCompile(EndpointPathRegex("", tc.glob))
		for _, p := range tc.match {
			if !re.MatchString(p) {
				t.Errorf("%s should match %s (%s)", tc.glob, p, re)
			}
		}
		for _, p := range tc.notMatch {
			if re.MatchString(p) {
				t.Errorf("%s should not match %s (%s)", tc.glob, p, re)
			}
		}
	}
	// strip_path_prefix はパターンの前に必須で付く
	re := regexp.MustCompile(EndpointPathRegex("/prod", "/signup"))
	if !re.MatchString("/prod/signup") || re.MatchString("/signup") {
		t.Fatalf("prefix: %s", re)
	}
}

func TestEndpointQueries(t *testing.T) {
	p, _ := ProfileFor(nginxSource())
	qs := EndpointQueries(p, "web", abuseChecks().EndpointAbuse)
	// sources: [api] の endpoint は web では数えない
	if len(qs) != 2 || qs[0].Endpoint != "signup" || qs[1].Endpoint != "message" {
		t.Fatalf("queries: %+v", qs)
	}
	q := qs[1].Query
	for _, want := range []string{
		`path like /^\/messages([?#].*)?$/`, `path like /^\/messages\/[^\/?#]+([?#].*)?$/`,
		`method in ["POST"]`, `status in [200, 302]`, `path not like /^\/messages\/preview([?#].*)?$/`,
		"stats count(*) as " + endpointHits + ", min(@timestamp) as first_seen, max(@timestamp) as last_seen by bin(10m) as t, ip, ua",
		"limit 10000",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query lacks %q:\n%s", want, q)
		}
	}
	// UA を出さない形式 (json で ua の対応が無い) は ua で group by しない
	js := config.Source{ID: "web", Kind: config.KindCloudWatchLogs, LogGroup: "/app/rails", Format: config.FormatJSON, Yields: config.YieldsHTTPAccess,
		Fields: map[string]string{"ip": "remote_ip", "path": "path", "method": "method"}}
	jp, _ := ProfileFor(js)
	if q := EndpointQueries(jp, "web", abuseChecks().EndpointAbuse)[0].Query; !strings.HasSuffix(strings.Split(q, "\n| sort")[0], "as t, ip") {
		t.Fatalf("json without ua:\n%s", q)
	}
	js.Fields["ua"] = "user_agent"
	jp, _ = ProfileFor(js)
	if q := EndpointQueries(jp, "web", abuseChecks().EndpointAbuse)[0].Query; !strings.Contains(q, "as t, ip, ua") {
		t.Fatalf("json with ua:\n%s", q)
	}
	// endpoints が空なら何も流さない
	if qs := EndpointQueries(p, "web", config.DefaultChecks().EndpointAbuse); len(qs) != 0 {
		t.Fatalf("default must be empty: %+v", qs)
	}
}

func ts(hm string, sec int) string {
	t, _ := time.Parse("2006-01-02 15:04", "2026-10-21 "+hm)
	return t.Add(time.Duration(sec) * time.Second).Format("2006-01-02 15:04:05.000")
}

func hit(bin, ip, ua string, n, firstSec, lastSec int) map[string]string {
	return cwlogstest.Rows("t", ts(bin, 0), "ip", ip, "ua", ua, endpointHits, fmt.Sprint(n),
		"first_seen", ts(bin, firstSec), "last_seen", ts(bin, lastSec))
}

const botUA = "Mozilla/5.0 (EvilBot-Test-UA)"

func abuseFake() *cwlogstest.Fake {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", linesResp("2026-10-21", "1000", "1000"))
	var signup, message []map[string]string
	// 03:20 の幅: 25 IP から 1 件ずつ (同じ UA が 22 IP)。うち 6 IP が 30 分以内にメッセージ送信
	for i := 0; i < 25; i++ {
		ua := botUA
		if i >= 22 {
			ua = fmt.Sprintf("Browser/%d", i)
		}
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		signup = append(signup, hit("03:20", ip, ua, 1, i*10, i*10))
		if i < 6 {
			message = append(message, hit("03:30", ip, ua, 1, 60, 60))
		}
	}
	// 1 IP は登録の 40 分後 (within の外) にメッセージ送信
	message = append(message, hit("04:10", "203.0.113.7", botUA, 1, 0, 0))
	// 平常の幅: 2 IP から 3 件。UA は "-" (無い) を数えない
	signup = append(signup, hit("01:00", "198.51.100.1", "-", 2, 0, 30), hit("01:00", "198.51.100.2", "Browser/1", 1, 5, 5))
	f.On(`path like /^\/signup`, cwlogstest.Response{RowsFor: inRange(signup)})
	f.On(`path like /^\/messages`, cwlogstest.Response{RowsFor: inRange(message)})
	return f
}

// inRange は問い合わせの範囲に時間幅の始まりが入る行だけを返す (本物の Insights と同じ)。
func inRange(rows []map[string]string) func(in *cwl.StartQueryInput) []map[string]string {
	return func(in *cwl.StartQueryInput) []map[string]string {
		var out []map[string]string
		for _, r := range rows {
			t, _ := parseTime(r["t"])
			if t.Unix() >= aws.ToInt64(in.StartTime) && t.Unix() <= aws.ToInt64(in.EndTime) {
				out = append(out, r)
			}
		}
		return out
	}
}

func TestCollectEndpoints(t *testing.T) {
	f := abuseFake()
	c, err := New(nginxSource(), abuseChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	var logs bytes.Buffer
	c.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	d := "2026-10-21|"
	h := UAHash(botUA)
	if len(h) != 8 {
		t.Fatalf("hash: %q", h)
	}
	for k, want := range map[string]float64{
		d + MetricEndpointCount + "|signup|03:20":          25,
		d + MetricEndpointIPs + "|signup|03:20":            25,
		d + MetricEndpointUAIPs + "|signup|03:20|" + h:     22,
		d + MetricEndpointCount + "|signup|01:00":          3,
		d + MetricEndpointIPs + "|signup|01:00":            2,
		d + MetricEndpointCount + "|message|03:30":         6,
		d + MetricEndpointFollow + "|signup>message|03:20": 6,
	} {
		if got, ok := m[k]; !ok || got != want {
			t.Errorf("%s = %v (ok=%v), want %v", k, got, ok, want)
		}
	}
	for k := range m {
		// 1 IP しかない UA は残さない。01:00 は連鎖が無いので出さない
		if strings.HasPrefix(k, d+MetricEndpointUAIPs+"|signup|01:00") || strings.HasPrefix(k, d+MetricEndpointFollow+"|signup>message|01:00") {
			t.Errorf("unexpected %s", k)
		}
	}
	// UA の原文は metrics にもログにも出さない
	for _, r := range sink.recs {
		if s := fmt.Sprintf("%+v", r); strings.Contains(s, "EvilBot") || strings.Contains(s, "Browser/") {
			t.Fatalf("raw user agent stored: %s", s)
		}
	}
	if strings.Contains(logs.String(), "EvilBot") {
		t.Fatalf("raw user agent logged: %s", logs.String())
	}
	// 既存の集計 + endpoint 2 本 × 2 日 (UTC の 1 日ずつ。sources が別の endpoint は流さない)
	if len(f.Started) != 4+2*2 {
		t.Fatalf("queries: %d", len(f.Started))
	}
}

// endpoint を足しても既存の集計 (login_bruteforce・probe_paths の metrics とクエリ) は変わらない。
func TestEndpointsKeepExistingAggregates(t *testing.T) {
	run := func(checks config.Checks) (map[string]float64, []string) {
		f := abuseFake()
		f.On("as sign_in_failures", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "sign_in_failures", "40")}})
		f.On("as probe_hits", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.8", "probe_hits", "4")}})
		c, _ := New(nginxSource(), checks, f)
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		sink := &sinkRecorder{}
		if err := c.Collect(context.Background(), collect.Window{From: now.Add(-24 * time.Hour), To: now}, sink); err != nil {
			t.Fatal(err)
		}
		out := map[string]float64{}
		for k, v := range sink.metrics() {
			if !strings.Contains(k, "|endpoint_abuse_") {
				out[k] = v
			}
		}
		var qs []string
		for _, q := range f.Queries() {
			if !strings.Contains(q, endpointHits) {
				qs = append(qs, q)
			}
		}
		return out, qs
	}
	base, baseQ := run(checksCfg())
	with, withQ := run(abuseChecks())
	if fmt.Sprint(base) != fmt.Sprint(with) || strings.Join(baseQ, "\n---\n") != strings.Join(withQ, "\n---\n") {
		t.Fatalf("existing aggregates changed:\n%v\n%v", base, with)
	}
	if len(base) == 0 {
		t.Fatal("no existing metrics")
	}
}

// 行数の上限に当たったら、その範囲を時間で半分に分けて引き直す (スキャン量は増えにくい)。1h まで分けても当たれば truncated に残す。
func TestCollectEndpointsSplitOnTruncation(t *testing.T) {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", linesResp("2026-10-21", "1000", "1000"))
	full := make([]map[string]string, MaxRows)
	for i := range full {
		full[i] = hit("00:00", fmt.Sprintf("10.0.%d.%d", i/256, i%256), "", 1, 0, 0)
	}
	f.On(`path like /^\/signup`, cwlogstest.Response{RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
		// 2 時間より長い範囲は上限に当たる
		if aws.ToInt64(in.EndTime)+1-aws.ToInt64(in.StartTime) > int64(2*time.Hour/time.Second) {
			return full
		}
		return []map[string]string{hit("00:00", "192.0.2.1", "", 1, 0, 0)}
	}})
	c := abuseCollector(t, f, config.EndpointAbuse{Window: "10m", Endpoints: []config.AbuseEndpoint{{Name: "signup", Paths: []string{"/signup"}}}})
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-time.Hour), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	var spans []string
	for _, in := range f.Started {
		if strings.Contains(aws.ToString(in.QueryString), endpointHits) {
			spans = append(spans, time.Unix(aws.ToInt64(in.StartTime), 0).UTC().Format("15:04")+"-"+time.Unix(aws.ToInt64(in.EndTime)+1, 0).UTC().Format("15:04"))
		}
	}
	// [00:00, 09:00) → 上限 → [00:00, 04:30) と [04:30, 09:00) → それぞれ上限 → 2h15m ずつ → さらに半分 (bin に揃える)
	if spans[0] != "00:00-09:00" || len(spans) < 5 {
		t.Fatalf("spans: %v", spans)
	}
	if len(c.FormatStats().Truncated) != 0 {
		t.Fatalf("truncated: %v", c.FormatStats().Truncated)
	}

	// 1h まで分けても当たる
	f.On(`path like /^\/signup`, cwlogstest.Response{Rows: full})
	c = abuseCollector(t, f, config.EndpointAbuse{Window: "10m", Endpoints: []config.AbuseEndpoint{{Name: "signup", Paths: []string{"/signup"}}}})
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-time.Hour), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.FormatStats().Truncated, ","); got != "endpoint_abuse:signup" {
		t.Fatalf("truncated: %q", got)
	}
}

func abuseCollector(t *testing.T, f *cwlogstest.Fake, ea config.EndpointAbuse) *Collector {
	t.Helper()
	ch := checksCfg()
	ch.EndpointAbuse = ea
	c, err := New(nginxSource(), ch, f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}
