package cwlogs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

var now = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

func checksCfg() config.Checks {
	var c config.Checks
	c.LoginBruteforce.Paths = []string{"/users/sign_in"}
	c.LoginBruteforce.Methods = []string{"POST"}
	c.LoginBruteforce.FailureStatuses = []int{401, 422}
	c.ProbePaths.Paths = []string{"/.env", "/wp-login.php"}
	c.ProbePaths.Statuses = []int{403, 404}
	return c
}

func nginxSource() config.Source {
	return config.Source{ID: "web", Kind: config.KindCloudWatchLogs, LogGroup: "/app/nginx", Format: config.FormatNginxAccess, Yields: config.YieldsHTTPAccess, ExpectedMatchRate: 0.8, SampleLines: true}
}

func TestProfiles(t *testing.T) {
	p, err := ProfileFor(nginxSource())
	if err != nil {
		t.Fatal(err)
	}
	if p.MatchField != "path" || !strings.HasPrefix(p.Prelude, "parse @message /^(?<ip>") || p.Yields != record.KindHTTPAccess {
		t.Fatalf("nginx: %+v", p)
	}

	src := nginxSource()
	src.StreamPrefix = "nginx/"
	p, _ = ProfileFor(src)
	if !strings.HasPrefix(p.Prelude, `filter @logStream like /^nginx\//`+"\n| parse") {
		t.Fatalf("stream prefix: %s", p.Prelude)
	}

	src = config.Source{ID: "app", Format: config.FormatJSON, Yields: config.YieldsHTTPAccess, Fields: map[string]string{"ip": "remote_ip", "path": "path", "status": "status", "time": "@timestamp", "user_id": "user-id"}}
	p, _ = ProfileFor(src)
	if p.Prelude != "fields remote_ip as ip, path, status, `user-id` as user_id" {
		t.Fatalf("json: %s", p.Prelude)
	}

	src = config.Source{ID: "rails", Format: config.FormatRegex, Yields: config.YieldsHTTPAccess, Regex: `Started (?P<method>\w+) "(?P<path>/admin/[^"]*)" for (?P<ip>[\d.]+)`}
	p, _ = ProfileFor(src)
	if p.Prelude != `parse @message /Started (?<method>\w+) "(?<path>\/admin\/[^"]*)" for (?<ip>[\d.]+)/` {
		t.Fatalf("regex: %s", p.Prelude)
	}

	p, _ = ProfileFor(config.Source{ID: "waf", Format: config.FormatWAFv2, Yields: config.YieldsWAFAction})
	if p.MatchField != "action" || !strings.Contains(p.Prelude, "terminatingRuleId as rule") {
		t.Fatalf("waf: %+v", p)
	}
	if _, err := ProfileFor(config.Source{Format: "apache"}); err == nil {
		t.Fatal("unknown format must fail")
	}
}

func TestQueryTemplates(t *testing.T) {
	p, _ := ProfileFor(nginxSource())
	if got := LinesQuery(p); !strings.HasSuffix(got, "\n| stats count(*) as lines_total, count(path) as lines_matched by bin(1d) as day") {
		t.Fatalf("lines: %s", got)
	}
	aggs := Aggregates(record.KindHTTPAccess, checksCfg())
	if len(aggs) != 3 {
		t.Fatalf("aggs: %+v", aggs)
	}
	want := p.Prelude + `
| filter method in ["POST"] and path in ["/users/sign_in"] and status in [401, 422]
| stats count(*) as sign_in_failures by bin(1d) as day, ip
| sort sign_in_failures desc
| limit 10000`
	if got := AggregateQuery(p, aggs[0]); got != want {
		t.Fatalf("sign_in query:\n%s\nwant:\n%s", got, want)
	}
	c := checksCfg()
	c.ProbePaths.ExcludePaths = []string{"/admin/ok"}
	probe := AggregateQuery(p, Aggregates(record.KindHTTPAccess, c)[1])
	if !strings.Contains(probe, `| filter status in [403, 404] and path like /^(\/\.env|\/wp-login\.php)/ and path not like /^(\/admin\/ok)/`) {
		t.Fatalf("probe query: %s", probe)
	}
	waf := Aggregates(record.KindWAFAction, c)
	if len(waf) != 2 || waf[0].Filter != `action = "BLOCK"` || waf[0].KeyField != "rule" {
		t.Fatalf("waf aggs: %+v", waf)
	}
	if !strings.HasSuffix(SampleQuery(p, 3), "| filter not ispresent(path)\n| fields @message\n| limit 3") {
		t.Fatal(SampleQuery(p, 3))
	}
	// 判定フィールド (parse で定義済み) を fields で列挙し直さない
	if got := DoctorQuery(p, 100); !strings.HasSuffix(got, "\n| fields @timestamp, @message, ispresent(path) as arata_matched\n| sort @timestamp desc\n| limit 100") {
		t.Fatalf("doctor query: %s", got)
	}
	if !Matched(p, map[string]string{"arata_matched": "1"}) || Matched(p, map[string]string{"arata_matched": "0", "path": "/"}) || !Matched(p, map[string]string{"path": "/"}) {
		t.Fatal("Matched")
	}
	if stringLiteral(`a"b\c`) != `"a\"b\\c"` {
		t.Fatal(stringLiteral(`a"b\c`))
	}
}

func TestMask(t *testing.T) {
	in := `203.0.113.1 - - [21/Oct/2026] "GET /users?email=alice%40example.com&to=bob@example.co.jp HTTP/1.1" 200`
	got := Mask(in)
	if strings.Contains(got, "alice") || strings.Contains(got, "bob@") || strings.Count(got, "<email>") != 2 {
		t.Fatalf("mask: %s", got)
	}
	long := strings.Repeat("あ", 300) + " carol@example.com"
	if s := MaskSample(long); len([]rune(s)) != SampleMaxLen+1 || strings.Contains(s, "carol") {
		t.Fatalf("sample len %d", len([]rune(s)))
	}
	if s := MaskSample(strings.Repeat("x", 190) + "dave@example.com"); strings.Contains(s, "dave") {
		t.Fatalf("mask before truncate: %s", s)
	}
}

type sinkRecorder struct{ recs []record.Record }

func (s *sinkRecorder) Emit(_ context.Context, r record.Record) error {
	s.recs = append(s.recs, r)
	return nil
}

func (s *sinkRecorder) metrics() map[string]float64 {
	out := map[string]float64{}
	for _, r := range s.recs {
		m := r.(record.Metric)
		out[m.Date+"|"+m.Metric+"|"+m.Key] = m.Value
	}
	return out
}

func newCollector(t *testing.T, src config.Source, f *cwlogstest.Fake) *Collector {
	t.Helper()
	c, err := New(src, checksCfg(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func linesResp(day string, total, matched string) cwlogstest.Response {
	return cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", day+" 00:00:00.000", "lines_total", total, "lines_matched", matched)}, BytesScanned: 1e6}
}

func TestCollect(t *testing.T) {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", linesResp("2026-10-21", "1000", "990"))
	f.On("as sign_in_failures", cwlogstest.Response{Polls: 2, Rows: []map[string]string{
		cwlogstest.Rows("day", "2026-10-20 00:00:00.000", "ip", "198.51.100.7", "sign_in_failures", "40"),
		cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "sign_in_failures", "12"),
	}})
	f.On("as probe_paths", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "path", "/.env/alice@example.com", "probe_paths", "3")}})
	c := newCollector(t, nginxSource(), f)
	sink := &sinkRecorder{}
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	m := sink.metrics()
	if m["2026-10-21|lines_total|"] != 1000 || m["2026-10-20|sign_in_failures|198.51.100.7"] != 40 || m["2026-10-21|probe_paths|/.env/<email>"] != 3 {
		t.Fatalf("metrics: %v", m)
	}
	// 窓の始まりの日の 0 時から、窓の終わり (含まない) まで
	in := f.Started[0]
	if aws.ToInt64(in.StartTime) != time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).Unix() || aws.ToInt64(in.EndTime) != now.Unix()-1 || aws.ToString(in.LogGroupName) != "/app/nginx" {
		t.Fatalf("query range: %d..%d", aws.ToInt64(in.StartTime), aws.ToInt64(in.EndTime))
	}
	if len(f.Started) != 4 {
		t.Fatalf("queries: %d", len(f.Started))
	}
	st := c.FormatStats()
	if rate, ok := st.Rate(); !ok || rate != 0.99 || st.BytesScanned != 1e6 {
		t.Fatalf("stats: %+v", st)
	}
	for _, r := range sink.recs {
		if r.(record.Metric).From != record.KindHTTPAccess || r.(record.Metric).Source != "web" {
			t.Fatalf("record: %+v", r)
		}
	}
}

func TestCollectFormatMismatch(t *testing.T) {
	for _, samples := range []bool{true, false} {
		f := &cwlogstest.Fake{}
		f.On("as lines_total", linesResp("2026-10-21", "100", "12"))
		f.On("ispresent", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("@message", `{"msg":"login","email":"alice@example.com"}`)}})
		src := nginxSource()
		src.SampleLines = samples
		c := newCollector(t, src, f)
		sink := &sinkRecorder{}
		err := c.Collect(context.Background(), collect.Window{From: now.Add(-time.Hour), To: now}, sink)
		var ce *collect.Error
		if !errors.As(err, &ce) || ce.Code != collect.CodeFormatMismatch {
			t.Fatalf("want FORMAT_MISMATCH, got %v", err)
		}
		if len(sink.recs) != 0 {
			t.Fatal("mismatched source must not store metrics")
		}
		if ce.Details["match_rate"] != 0.12 || ce.Details["expected"] != 0.8 || ce.Details["log_group"] != "/app/nginx" {
			t.Fatalf("details: %v", ce.Details)
		}
		got, ok := ce.Details["samples"].([]string)
		if samples {
			if !ok || len(got) != 1 || strings.Contains(got[0], "alice") {
				t.Fatalf("samples: %v", ce.Details["samples"])
			}
			if len(f.Started) != 2 {
				t.Fatalf("queries: %d", len(f.Started))
			}
		} else if ok || len(f.Started) != 1 {
			t.Fatalf("sample_lines: false must not fetch samples: %v", ce.Details)
		}
	}
}

func TestCollectNoLines(t *testing.T) {
	f := &cwlogstest.Fake{}
	c := newCollector(t, nginxSource(), f)
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-time.Hour), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.Started) != 1 {
		t.Fatalf("no lines: aggregate queries must be skipped, got %d", len(f.Started))
	}
	if _, ok := c.FormatStats().Rate(); ok {
		t.Fatal("rate must be undefined")
	}
}

func TestCollectErrors(t *testing.T) {
	w := collect.Window{From: now.Add(-time.Hour), To: now}
	code := func(err error) string {
		var ce *collect.Error
		if !errors.As(err, &ce) {
			return ""
		}
		return ce.Code + "|" + ce.Action
	}
	t.Run("concurrency limit retried then ok", func(t *testing.T) {
		f := &cwlogstest.Fake{}
		r := linesResp("2026-10-21", "10", "10")
		r.StartErr, r.StartErrTimes = cwlogstest.APIError{Code: "LimitExceededException"}, 2
		f.On("as lines_total", r)
		if err := newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("concurrency limit exhausted", func(t *testing.T) {
		f := &cwlogstest.Fake{StartErr: cwlogstest.APIError{Code: "LimitExceededException"}}
		if got := code(newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{})); got != "QUERY_LIMIT|" {
			t.Fatal(got)
		}
	})
	t.Run("access denied", func(t *testing.T) {
		f := &cwlogstest.Fake{StartErr: cwlogstest.APIError{Code: "AccessDeniedException"}}
		if got := code(newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{})); got != "ACCESS_DENIED|logs:StartQuery" {
			t.Fatal(got)
		}
	})
	t.Run("log group missing", func(t *testing.T) {
		f := &cwlogstest.Fake{StartErr: cwlogstest.APIError{Code: "ResourceNotFoundException"}}
		if got := code(newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{})); got != "LOG_GROUP_MISSING|" {
			t.Fatal(got)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		f := &cwlogstest.Fake{StartErr: cwlogstest.APIError{Code: "MalformedQueryException"}}
		if got := code(newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{})); got != "QUERY_INVALID|" {
			t.Fatal(got)
		}
	})
	t.Run("insights timeout", func(t *testing.T) {
		f := &cwlogstest.Fake{}
		f.On("as lines_total", cwlogstest.Response{Status: types.QueryStatusTimeout})
		if got := code(newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{})); got != "QUERY_LIMIT|" {
			t.Fatal(got)
		}
	})
	t.Run("wait limit stops query", func(t *testing.T) {
		f := &cwlogstest.Fake{}
		f.On("as lines_total", cwlogstest.Response{Polls: 1000})
		c := newCollector(t, nginxSource(), f)
		c.MaxWait = 10 * time.Second
		if got := code(c.Collect(context.Background(), w, &sinkRecorder{})); got != "QUERY_LIMIT|" || len(f.Stopped) != 1 {
			t.Fatalf("%s stopped=%v", got, f.Stopped)
		}
	})
	t.Run("max_scan_gb", func(t *testing.T) {
		f := &cwlogstest.Fake{}
		f.On("as lines_total", linesResp("2026-10-21", "10", "10"))
		f.On("as sign_in_failures", cwlogstest.Response{Polls: 3, BytesScanned: 3e9})
		src := nginxSource()
		src.MaxScanGB = 2
		c := newCollector(t, src, f)
		err := c.Collect(context.Background(), w, &sinkRecorder{})
		if got := code(err); got != "QUERY_LIMIT|" || len(f.Stopped) != 1 {
			t.Fatalf("%s stopped=%v", got, f.Stopped)
		}
		if c.FormatStats().BytesScanned < 3e9 {
			t.Fatalf("scanned: %v", c.FormatStats().BytesScanned)
		}
	})
	t.Run("query failed", func(t *testing.T) {
		f := &cwlogstest.Fake{}
		f.On("as lines_total", cwlogstest.Response{Status: types.QueryStatusFailed})
		if got := code(newCollector(t, nginxSource(), f).Collect(context.Background(), w, &sinkRecorder{})); got != "COLLECT_FAILED|" {
			t.Fatal(got)
		}
	})
}

// 再走査 (ADR 0013) が日をまたぐと、前日の 0 時から引き直して前日分を丸ごと置き換える。
func TestCollectRescanCrossesDay(t *testing.T) {
	from := time.Date(2026, 10, 21, 0, 2, 0, 0, time.UTC)
	f := &cwlogstest.Fake{}
	f.On("as lines_total", linesResp("2026-10-21", "100", "99"))
	c := newCollector(t, nginxSource(), f)
	w := collect.Window{From: from, To: from.Add(time.Hour), ScanFrom: from.Add(-5 * time.Minute)}
	if err := c.Collect(context.Background(), w, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if got := aws.ToInt64(f.Started[0].StartTime); got != time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("query must start at the day start of ScanFrom: %v", time.Unix(got, 0).UTC())
	}
}

// Logs Insights は問い合わせの終わりがロググループの作成時刻より前、または保持期間より古いと MalformedQueryException で拒否する。
// 範囲が丸ごと外れる日は問い合わせずに「データなし」とする。
func TestCollectBeforeLogGroupCreation(t *testing.T) {
	created := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	newFake := func() *cwlogstest.Fake {
		f := &cwlogstest.Fake{Groups: map[string]cwlogstest.Group{"/app/nginx": {Created: created}}, Now: func() time.Time { return now }}
		f.On("as lines_total", linesResp("2026-10-21", "10", "10"))
		return f
	}
	day := func(d int) collect.Window {
		return collect.Window{From: time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, d+1, 0, 0, 0, 0, time.UTC)}
	}

	// 作成より前の日: 問い合わせず、エラーにもしない
	f := newFake()
	c := newCollector(t, nginxSource(), f)
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), day(19), sink); err != nil {
		t.Fatalf("day before creation must not fail: %v", err)
	}
	if len(f.Started) != 0 || len(sink.recs) != 0 {
		t.Fatalf("no queries and no metrics: %d %d", len(f.Started), len(sink.recs))
	}
	if st := c.FormatStats(); st.OutOfRange != OutOfRangeBeforeCreation || st.Total != 0 {
		t.Fatalf("stats: %+v", st)
	}

	// 作成をまたぐ窓: 始まりを作成時刻に寄せて問い合わせる
	f = newFake()
	c = newCollector(t, nginxSource(), f)
	if err := c.Collect(context.Background(), collect.Window{From: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.Started) == 0 || aws.ToInt64(f.Started[0].StartTime) != created.Unix() || aws.ToInt64(f.Started[0].EndTime) != now.Unix()-1 {
		t.Fatalf("query range: %+v", f.Started)
	}
	if st := c.FormatStats(); st.OutOfRange != "" {
		t.Fatalf("stats: %+v", st)
	}

	// 作成時刻ちょうどに終わる窓 (EndTime = 作成の 1 秒前) も範囲外
	f = newFake()
	c = newCollector(t, nginxSource(), f)
	if err := c.Collect(context.Background(), collect.Window{From: created.Add(-time.Hour), To: created}, &sinkRecorder{}); err != nil || len(f.Started) != 0 {
		t.Fatalf("window ending at creation: %v %d", err, len(f.Started))
	}
}

func TestCollectBeyondRetention(t *testing.T) {
	f := &cwlogstest.Fake{Groups: map[string]cwlogstest.Group{"/app/nginx": {Created: now.AddDate(-1, 0, 0), RetentionDays: 1}}, Now: func() time.Time { return now }}
	f.On("as lines_total", linesResp("2026-10-20", "10", "10"))
	c := newCollector(t, nginxSource(), f)
	c.Now = func() time.Time { return now }
	// 終わりが保持期間 (今 - 1 日) より古い
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-72 * time.Hour), To: now.Add(-48 * time.Hour)}, &sinkRecorder{}); err != nil {
		t.Fatalf("expired range must not fail: %v", err)
	}
	if len(f.Started) != 0 || c.FormatStats().OutOfRange != OutOfRangeRetention {
		t.Fatalf("expired range must be skipped: %d %+v", len(f.Started), c.FormatStats())
	}
	// 終わりが保持期間内なら、始まりが保持期間より前でも切り詰めない (日次集計を一部だけの値で置き換えないため)
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-25 * time.Hour), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.Started) == 0 || aws.ToInt64(f.Started[0].StartTime) != time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("start must stay at the day start: %+v", f.Started)
	}
}

func TestQueryOutOfRange(t *testing.T) {
	created := now.Add(-30 * time.Second)
	f := &cwlogstest.Fake{Groups: map[string]cwlogstest.Group{"/app/nginx": {Created: created}}, Now: func() time.Time { return now }}
	c := newCollector(t, nginxSource(), f)
	if _, err := c.Query(context.Background(), "fields @message", now.Add(-time.Hour), now.Add(-time.Minute)); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("query: %v", err)
	}
	if err := c.Validate(context.Background(), "fields @message", now.Add(-2*time.Minute), now.Add(-time.Minute)); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("validate: %v", err)
	}
	if len(f.Started) != 0 {
		t.Fatalf("must not start queries: %d", len(f.Started))
	}
}

// DescribeLogGroups が使えない / グループが見つからないときは、範囲を判定せず今までどおり問い合わせる。
func TestCollectWithoutLogGroupInfo(t *testing.T) {
	for _, f := range []*cwlogstest.Fake{{DescribeErr: cwlogstest.APIError{Code: "AccessDeniedException"}}, {}} {
		f.On("as lines_total", linesResp("2026-10-21", "10", "10"))
		c := newCollector(t, nginxSource(), f)
		if err := c.Collect(context.Background(), collect.Window{From: now.Add(-time.Hour), To: now}, &sinkRecorder{}); err != nil {
			t.Fatal(err)
		}
		if len(f.Started) == 0 {
			t.Fatal("must query as before")
		}
	}
}
