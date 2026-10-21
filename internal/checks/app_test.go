package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 窓は [10-20 09:00, 10-21 09:00) なので評価する日は 10-20 と 10-21。平常帯は各日の前日から 14 日。
var appWindow = collect.Window{From: now.Add(-24 * time.Hour), To: now}

type metricSeed struct {
	st *store.Dir
	t  *testing.T
}

func (m metricSeed) put(date, source, metric, key string, v float64) {
	m.t.Helper()
	if err := m.st.UpsertMetric(context.Background(), record.Metric{Date: date, Source: source, From: record.KindHTTPAccess, Metric: metric, Key: key, Value: v}); err != nil {
		m.t.Fatal(err)
	}
}

// history は 10-06〜10-19 の 14 日に毎日 v を入れる。
func (m metricSeed) history(source, metric, key string, v float64) {
	for d := 6; d <= 19; d++ {
		m.put(time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC).Format(record.DateLayout), source, metric, key, v)
	}
}

func appAllowlist(t *testing.T) *allowlist.List {
	al, err := allowlist.Parse([]byte("source_ips:\n  - cidr: 203.0.113.0/24\n    note: 本社\n"))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

func evaluate(t *testing.T, c Check, st *store.Dir, al *allowlist.List) map[string]Observation {
	t.Helper()
	obs, err := c.Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Observation{}
	for _, o := range obs {
		if o.Check != c.Name() || o.Summary == "" || o.Fingerprint == "" || o.Severity == "" {
			t.Fatalf("observation incomplete: %+v", o)
		}
		if strings.Contains(o.Fingerprint, "2026-") {
			t.Fatalf("fingerprint must not contain dates or counts: %q", o.Fingerprint)
		}
		out[o.Key] = o
	}
	return out
}

func TestLoginBruteforce(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.history("nginx", cwlogs.MetricSignInFailures, "192.0.2.10", 30) // 毎日 30 件失敗する NAT (平常帯 90)
	m.put("2026-10-20", "nginx", cwlogs.MetricSignInFailures, "192.0.2.10", 50)
	m.put("2026-10-20", "nginx", cwlogs.MetricSignInFailures, "198.51.100.7", 30) // 2 ソースの合算で 52 > 20
	m.put("2026-10-20", "alb", cwlogs.MetricSignInFailures, "198.51.100.7", 22)
	m.put("2026-10-20", "nginx", cwlogs.MetricSignInFailures, "203.0.113.5", 500) // source_ips は対象外
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "192.0.2.10", 5)
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "198.51.100.9", 8) // 閾値未満だがその日の最多で初出
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "198.51.100.10", 2)

	obs := evaluate(t, LoginBruteforce{Config: config.DefaultChecks().LoginBruteforce}, st, appAllowlist(t))
	if len(obs) != 2 {
		t.Fatalf("obs: %v", obs)
	}
	a := obs["198.51.100.7"]
	if a.Severity != Medium || a.Data["reason"] != "above_baseline" || a.Data["count"] != 52.0 || a.Data["threshold"] != 20.0 || a.Data["date"] != "2026-10-20" {
		t.Fatalf("above baseline: %+v", a)
	}
	n := obs["198.51.100.9"]
	if n.Data["reason"] != "new_top_ip" || n.Data["baseline_days_with_data"] != 14 || !strings.Contains(n.Summary, "初出") {
		t.Fatalf("new top ip: %+v", n)
	}
	if a.Fingerprint == n.Fingerprint {
		t.Fatal("reason must be part of the fingerprint")
	}
}

func TestLoginBruteforceWithoutHistory(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "198.51.100.7", 25)
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "198.51.100.8", 10)
	obs := evaluate(t, LoginBruteforce{Config: config.DefaultChecks().LoginBruteforce}, st, appAllowlist(t))
	// 導入直後: 閾値 (min_count) 超えは報告するが、「初出」は過去データが min_baseline_days 日に満たないので判定しない
	if len(obs) != 1 || obs["198.51.100.7"].Data["reason"] != "above_baseline" || obs["198.51.100.7"].Data["baseline_median"] != 0.0 {
		t.Fatalf("obs: %v", obs)
	}
}

func TestProbePaths(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.history("nginx", cwlogs.MetricProbeHits, "192.0.2.20", 2)
	m.put("2026-10-21", "nginx", cwlogs.MetricProbeHits, "198.51.100.20", 15)
	m.put("2026-10-21", "nginx", cwlogs.MetricProbeHits, "192.0.2.20", 3)
	m.put("2026-10-21", "nginx", cwlogs.MetricProbePaths, "/.env", 12)
	m.put("2026-10-21", "nginx", cwlogs.MetricProbePaths, "/.git/config", 6)
	obs := evaluate(t, ProbePaths{Config: config.DefaultChecks().ProbePaths}, st, appAllowlist(t))
	o, ok := obs["198.51.100.20"]
	if len(obs) != 1 || !ok || o.Severity != Low || o.Data["reason"] != "above_baseline" {
		t.Fatalf("obs: %v", obs)
	}
	if got := strings.Join(o.Data["top_paths_of_day"].([]string), ","); got != "/.env (12),/.git/config (6)" {
		t.Fatalf("top paths: %s", got)
	}
}

func TestWAFBlockTrend(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.history("waf", cwlogs.MetricWAFBlock, "AWSManagedRulesCommonRuleSet", 50)
	m.history("waf", cwlogs.MetricWAFBlockIP, "192.0.2.1", 40)
	m.history("waf", cwlogs.MetricWAFBlockIP, "192.0.2.2", 10)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlock, "AWSManagedRulesCommonRuleSet", 60)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlock, "RateLimit", 5)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockIP, "192.0.2.1", 30)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockIP, "198.51.100.30", 25)
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockIP, "198.51.100.31", 5)  // min_count 未満
	m.put("2026-10-20", "waf", cwlogs.MetricWAFBlockIP, "203.0.113.9", 100)  // source_ips は対象外
	m.put("2026-10-21", "waf", cwlogs.MetricWAFBlockIP, "198.51.100.30", 40) // 10-21 から見ると 10-20 の分が過去 Top に入るので新顔ではない
	obs := evaluate(t, WAFBlockTrend{Config: config.DefaultChecks().WAFBlockTrend}, st, appAllowlist(t))
	if len(obs) != 2 {
		t.Fatalf("obs: %v", obs)
	}
	r := obs["rule|RateLimit"]
	if r.Severity != Low || r.Data["reason"] != "new_rule" || r.Data["count"] != 5.0 {
		t.Fatalf("new rule: %+v", r)
	}
	ip := obs["top_ip|198.51.100.30"]
	if ip.Data["reason"] != "new_top_ip" || ip.Data["count"] != 25.0 || ip.Data["date"] != "2026-10-20" {
		t.Fatalf("new top ip: %+v", ip)
	}

	// 導入直後 (過去データが無い) は何も出さない
	fresh := newStore(t)
	metricSeed{fresh, t}.put("2026-10-21", "waf", cwlogs.MetricWAFBlock, "RateLimit", 100)
	if obs := evaluate(t, WAFBlockTrend{Config: config.DefaultChecks().WAFBlockTrend}, fresh, appAllowlist(t)); len(obs) != 0 {
		t.Fatalf("without history: %v", obs)
	}
}

func TestWindowDates(t *testing.T) {
	if got := strings.Join(windowDates(appWindow), ","); got != "2026-10-20,2026-10-21" {
		t.Fatal(got)
	}
	// 0 時ちょうどに終わる窓は終わりの日を含まない
	w := collect.Window{From: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}
	if got := strings.Join(windowDates(w), ","); got != "2026-10-20" {
		t.Fatal(got)
	}
	if median([]float64{3, 1, 2}) != 2 || median([]float64{4, 1, 2, 3}) != 2.5 || median(nil) != 0 {
		t.Fatal("median")
	}
}
