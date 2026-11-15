package cwlogs

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// memParts は部分の行の置き場所の偽物 (ストアと同じく、(ソース, クエリ, 時) ごとに丸ごと置き換える)。
type memParts struct {
	m map[string]map[time.Time][]map[string]string
}

func (p *memParts) PutParts(_ context.Context, source, query string, hour time.Time, rows []map[string]string, _ int) error {
	if p.m == nil {
		p.m = map[string]map[time.Time][]map[string]string{}
	}
	k := source + "|" + query
	if p.m[k] == nil {
		p.m[k] = map[time.Time][]map[string]string{}
	}
	p.m[k][hour.UTC().Truncate(time.Hour)] = append([]map[string]string{}, rows...)
	return nil
}

func (p *memParts) Parts(_ context.Context, source, query string, from, to time.Time) ([]map[string]string, int, error) {
	var hours []time.Time
	for h := range p.m[source+"|"+query] {
		if !h.Before(from) && h.Before(to) {
			hours = append(hours, h)
		}
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i].Before(hours[j]) })
	var out []map[string]string
	for _, h := range hours {
		out = append(out, p.m[source+"|"+query][h]...)
	}
	return out, len(hours), nil
}

// goldenMetrics は同値のゴールデンの metric の行 (date|metric|key → 値)。skip の metric は除く。
func goldenMetrics(t *testing.T, name string, skip ...string) map[string]float64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, ok := strings.Cut(l, " = ")
		if !ok || skipMetric(k, skip) {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			t.Fatalf("golden %s: %q", name, l)
		}
		out[k] = f
	}
	return out
}

func skipMetric(key string, skip []string) bool {
	parts := strings.SplitN(key, "|", 3)
	return len(parts) < 2 || strIn(parts[1], skip)
}

// runHourly は時の単位で読むソースを、窓の終わりを ends の順に変えて何回か流す (各回は前の回の CoveredTo から)。
// 戻り値は最後に出た値 (同じ date|metric|key は後の値で置き換える。ストアと同じ)。
func runHourly(t *testing.T, c *Collector, from time.Time, ends []time.Time) (map[string]float64, *sinkRecorder) {
	t.Helper()
	sink := &sinkRecorder{}
	for _, end := range ends {
		if err := c.Collect(context.Background(), collect.Window{From: from, To: end, ScanFrom: from.Add(-c.src.IngestDelay)}, sink); err != nil {
			t.Fatal(err)
		}
		if c.CoveredTo().IsZero() {
			t.Fatalf("CoveredTo is zero after collecting to %v", end)
		}
		from = c.CoveredTo()
	}
	out := map[string]float64{}
	for _, r := range sink.recs {
		if m := r.(record.Metric); m.Hour == "" {
			out[m.Date+"|"+m.Metric+"|"+m.Key] = m.Value
		}
	}
	return out, sink
}

// 決定 (ADR 0065): 時の単位で何回かに分けて読み、部分の行から日の値を作ると、1 日分を 1 本で引いた値 (同値のゴールデン) と同じになる。
// レートは度数から Go で分位数を取るので、別に確かめる (TestHistPercentiles)。
func TestWAFHourlyEquivalence(t *testing.T) {
	sim := &cwlogstest.Sim{Events: wafEvents()}
	f := &cwlogstest.Fake{}
	registerWAF(f, sim, wafPreds{c: wafEquivChecks()})
	f.On("as k by acl, grp, n", sim.Response(nil))
	src := wafSource()
	src.Collect, src.IngestDelay = config.CollectHourlyMode, 5*time.Minute
	c, err := New(src, wafEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.Parts = &memParts{}
	got, _ := runHourly(t, c, now.Add(-24*time.Hour), []time.Time{now.Add(-19*time.Hour + 5*time.Minute), now.Add(-6*time.Hour + 5*time.Minute), now.Add(5 * time.Minute)})
	rate := []string{MetricWAFIPRateP50, MetricWAFIPRateP99, MetricWAFIPRateMax}
	for k := range got {
		if skipMetric(k, rate) {
			delete(got, k)
		}
	}
	if want := goldenMetrics(t, "equiv_waf.golden", rate...); !reflect.DeepEqual(got, want) {
		t.Fatalf("hourly WAF metrics differ from the daily golden:\n got %v\nwant %v", got, want)
	}
	// 時の軸のクエリを流し、同じ時を 2 度読まない (各回の始まりは前の回の終わり)
	for _, q := range f.Queries() {
		if strings.Contains(q, "bin(1d)") {
			t.Fatalf("an hourly source must not query by day: %s", q)
		}
	}
}

func TestHTTPHourlyEquivalence(t *testing.T) {
	sim := &cwlogstest.Sim{Events: httpEvents()}
	f := &cwlogstest.Fake{}
	registerHTTP(f, sim, httpPreds{c: httpEquivChecks()})
	src := nginxSource()
	src.Collect, src.IngestDelay = config.CollectHourlyMode, 5*time.Minute
	c, err := New(src, httpEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.Parts = &memParts{}
	got, sink := runHourly(t, c, now.Add(-24*time.Hour), []time.Time{now.Add(-28*time.Hour + 5*time.Minute), now.Add(-5*time.Hour + 35*time.Minute), now.Add(5 * time.Minute)})
	if want := goldenMetrics(t, "equiv_http.golden"); !reflect.DeepEqual(got, want) {
		t.Fatalf("hourly HTTP metrics differ from the daily golden:\n got %v\nwant %v", got, want)
	}
	// 時ごとの sign-in の失敗の和 (sign_in_failures_hourly)。日の和は sign_in_failures の日の和と同じ
	hourly, daily := map[string]float64{}, map[string]float64{}
	for _, r := range sink.recs {
		m := r.(record.Metric)
		if m.Metric == MetricSignInFailuresHourly {
			if m.Hour == "" || m.Key != "" {
				t.Fatalf("sign_in_failures_hourly: %+v", m)
			}
			hourly[m.Hour] = m.Value
		}
	}
	for k, v := range got {
		if p := strings.SplitN(k, "|", 3); p[1] == MetricSignInFailures {
			daily[p[0]] += v
		}
	}
	sums := map[string]float64{}
	for h, v := range hourly {
		sums[h[:10]] += v
	}
	if len(hourly) == 0 || !reflect.DeepEqual(sums, daily) {
		t.Fatalf("hourly sign-in failures %v do not add up to the daily %v", hourly, daily)
	}
}

// 時の単位で読み始める日にその日の 0 時からの部分の行が無ければ、日の頭から読む。終わっていない時は読まない。
func TestHourlyRange(t *testing.T) {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", cwlogstest.Response{})
	src := wafSource()
	src.Collect, src.IngestDelay = config.CollectHourlyMode, 5*time.Minute
	c, err := New(src, wafEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Parts = &memParts{}
	c.Now = func() time.Time { return now.Add(3 * time.Minute) }
	w := collect.Window{From: now.Add(-90 * time.Minute), To: now.Add(3 * time.Minute)} // 07:30 〜 09:03
	if err := c.Collect(context.Background(), w, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if !c.CoveredTo().Equal(now.Add(-time.Hour)) { // 09:03 − 5m を切り捨てた 08:00
		t.Fatalf("covered to %v", c.CoveredTo())
	}
	in := f.Started[0]
	if got := time.Unix(*in.StartTime, 0).UTC(); !got.Equal(DayStart(now)) {
		t.Fatalf("first query starts at %v, want the start of the day", got)
	}
	// 次の回は続きから。終わった時がまだ無ければ何も読まず、位置も変えない
	n := len(f.Started)
	if err := c.Collect(context.Background(), collect.Window{From: c.CoveredTo(), To: now.Add(-time.Hour + 30*time.Minute)}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.Started) != n || !c.CoveredTo().IsZero() {
		t.Fatalf("calls %d → %d, covered to %v", n, len(f.Started), c.CoveredTo())
	}
}

func TestHistPercentiles(t *testing.T) {
	// 1 が 98 回、5 が 1 回、300 が 1 回 (100 件): p50 = 1、p99 = 5 (99 番目)、max = 300
	p50, p99, mx := HistPercentiles(map[float64]float64{1: 98, 5: 1, 300: 1})
	if p50 != 1 || p99 != 5 || mx != 300 {
		t.Fatalf("p50=%v p99=%v max=%v", p50, p99, mx)
	}
	if a, b, c := HistPercentiles(nil); a != 0 || b != 0 || c != 0 {
		t.Fatal("empty histogram")
	}
	// 2 段目を度数にしたクエリ
	q := WAFRateHistQuery(WAFRateQuery(wafProfile(t), wafEquivChecks()))
	if !strings.HasSuffix(q, "\n| stats count(*) as k by acl, grp, n") || strings.Contains(q, "pct(") {
		t.Fatalf("hist query: %s", q)
	}
}

func wafProfile(t *testing.T) Profile {
	t.Helper()
	p, err := ProfileFor(wafSource())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// FuzzHistPercentiles: レートの度数は Insights の結果 (信用できない入力。ADR 0041) から作る。
// 規則: パニックしない。p50 ≤ p99 ≤ max で、どれも度数の値 (件数が正のもの) のどれか。件数が無ければ全部 0。
func FuzzHistPercentiles(f *testing.F) {
	f.Add("1", "98", "5", "1", "300", "1")
	f.Add("NaN", "1", "-1", "2", "1e308", "1e308")
	f.Add("0", "0", "", "", "x", "y")
	f.Fuzz(func(t *testing.T, v1, k1, v2, k2, v3, k3 string) {
		h := map[float64]float64{}
		for _, p := range [][2]string{{v1, k1}, {v2, k2}, {v3, k3}} {
			h[num(p[0])] += num(p[1])
		}
		p50, p99, mx := HistPercentiles(h)
		seen := map[float64]bool{}
		for v, k := range h {
			if k > 0 {
				seen[v] = true
			}
		}
		if len(seen) == 0 {
			if p50 != 0 || p99 != 0 || mx != 0 {
				t.Fatalf("empty: %v %v %v", p50, p99, mx)
			}
			return
		}
		if !seen[p50] || !seen[p99] || !seen[mx] || p50 > p99 || p99 > mx {
			t.Fatalf("h=%v → p50=%v p99=%v max=%v", h, p50, p99, mx)
		}
	})
}

// 決定 (ADR 0065。実データで直した): 時の単位で読むソースは、初めから 1 時間ずつ流す (各時を 1 回だけ読む)。
// 1 時間でも行数の上限に当たったら割らず、上位の行だけを残して truncated (下限) にする。範囲を半分に割り直すと、同じ範囲を何度も読む。
func TestHourlyQueriesEachHourOnce(t *testing.T) {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{row("day", "2026-10-21 05:00:00.000", "acl", "prod-waf", "rule", "Default_Action", "action", "ALLOW", "lines_total", "10", "lines_matched", "10")}})
	full := make([]map[string]string, MaxRows)
	for i := range full {
		full[i] = row("day", "2026-10-21 05:00:00.000", "acl", "prod-waf", "rule", "block-all", "action", "BLOCK", "ip", "198.51.100."+strconv.Itoa(i%250), "waf_actions", "1")
	}
	f.On("as waf_actions", cwlogstest.Response{Rows: full}) // どの時も上限
	f.On("as waf_rule_count_match", cwlogstest.Response{})
	f.On("as k by acl, grp, n", cwlogstest.Response{})
	src := wafSource()
	src.Collect, src.IngestDelay = config.CollectHourlyMode, 5*time.Minute
	c, err := New(src, wafEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.Parts = &memParts{}
	// 00:00 〜 06:00 の 6 時間
	if err := c.Collect(context.Background(), collect.Window{From: DayStart(now), To: DayStart(now).Add(6*time.Hour + 5*time.Minute)}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]map[int64]int{}
	for _, in := range f.Started {
		q := aws.ToString(in.QueryString)
		name := "other"
		for _, n := range []string{"as lines_total", "as waf_actions", "as waf_rule_count_match", "as k by acl"} {
			if strings.Contains(q, n) {
				name = n
			}
		}
		if got := aws.ToInt64(in.EndTime) + 1 - aws.ToInt64(in.StartTime); got != 3600 {
			t.Fatalf("%s: a query must cover exactly one hour, got %ds", name, got)
		}
		if seen[name] == nil {
			seen[name] = map[int64]int{}
		}
		seen[name][aws.ToInt64(in.StartTime)]++
	}
	for name, hours := range seen {
		if len(hours) != 6 {
			t.Fatalf("%s: %d hours, want 6", name, len(hours))
		}
		for h, n := range hours {
			if n != 1 {
				t.Fatalf("%s: hour %d read %d times", name, h, n)
			}
		}
	}
	if tr := c.FormatStats().Truncated; len(tr) == 0 {
		t.Fatal("the hours at the row limit must be marked truncated")
	}
}

// max_collect (ADR 0064) は collect: hourly の cloudwatch-logs にも効く。古い側から決めた時間の分だけ読み、位置をそこまで進める (初回の日の頭からの読み直しを含む)。
func TestHourlyMaxCollect(t *testing.T) {
	f := &cwlogstest.Fake{}
	f.On("as lines_total", cwlogstest.Response{})
	src := wafSource()
	src.Collect, src.IngestDelay, src.MaxCollect = config.CollectHourlyMode, 5*time.Minute, 4*time.Hour
	c, err := New(src, wafEquivChecks(), f)
	if err != nil {
		t.Fatal(err)
	}
	c.Parts = &memParts{}
	c.Now = func() time.Time { return now }
	if err := c.Collect(context.Background(), collect.Window{From: now.Add(-2 * time.Hour), To: now}, &sinkRecorder{}); err != nil { // 位置なし: 日の頭 (00:00) から
		t.Fatal(err)
	}
	if !c.CoveredTo().Equal(DayStart(now).Add(4*time.Hour)) || !c.Limited() {
		t.Fatalf("covered to %v (limited %v), want 04:00", c.CoveredTo(), c.Limited())
	}
	if err := c.Collect(context.Background(), collect.Window{From: c.CoveredTo(), To: now}, &sinkRecorder{}); err != nil {
		t.Fatal(err)
	}
	if !c.CoveredTo().Equal(now.Add(-time.Hour)) || c.Limited() { // 04:00 〜 08:00 (09:00 − 5m を切り捨て)
		t.Fatalf("covered to %v (limited %v), want 08:00", c.CoveredTo(), c.Limited())
	}
}
