package checks

import (
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// rate_limited_ip (ADR 0094 の 2 節)。値はすべて架空。窓は appWindow (評価する日は 10-20 と 10-21)。
// 429 は ALB のソース (alb)、ip_users はアプリのソース (app) から来る。

func rateConfig(userSources ...string) config.RateLimitedIP {
	c := config.DefaultChecks().RateLimitedIP
	c.UserSources = userSources
	return c
}

func TestRateLimitedIPWithoutUsers(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.put("2026-10-20", "alb", cwlogs.MetricRateLimited, "198.51.100.7", 30)
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.7", 45) // 多い日を出す
	m.put("2026-10-21", "alb", cwlogs.MetricSignInFailures, "198.51.100.7", 12)
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.8", 19)  // 下限 (20) 未満
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "203.0.113.5", 500)  // source_ips は対象外
	m.put("2026-10-19", "alb", cwlogs.MetricRateLimited, "198.51.100.9", 900) // 窓の外
	// ip_users があっても、user_sources を書いていなければ添えない
	m.put("2026-10-21", "app", cwlogs.MetricIPUsers, "198.51.100.7", 40)
	m.put("2026-10-21", "app", cwlogs.MetricUserProbeDays, cwlogs.UserProbeIPUsers, 1)

	obs := evaluate(t, RateLimitedIP{Config: rateConfig()}, st, appAllowlist(t))
	if keysOf(obs) != "198.51.100.7" {
		t.Fatalf("obs: %v", obs)
	}
	o := obs["198.51.100.7"]
	if o.Severity != Low || o.Data["date"] != "2026-10-21" || o.Data["count"] != 45.0 || o.Data["min_count"] != 20.0 || o.Data["sign_in_failures"] != 12.0 {
		t.Fatalf("%+v", o)
	}
	if _, ok := o.Data["ip_users"]; ok {
		t.Fatalf("数えていない ip_users を添えた: %+v", o.Data)
	}
	if _, ok := o.Data["reasons"]; ok {
		t.Fatalf("理由は付かない (件数だけ): %+v", o.Data)
	}
	if !strings.Contains(o.Summary, "198.51.100.7") || !strings.Contains(o.Summary, "45") {
		t.Fatalf("summary: %s", o.Summary)
	}
}

func TestRateLimitedIPReasons(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	// 学校の回線のような送信元: 429 と同時に 35 人がログインできた
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.20", 120)
	m.put("2026-10-21", "app", cwlogs.MetricIPUsers, "198.51.100.20", 35)
	// 総当たりのような送信元: ログインできた利用者は store_min 未満で残らない (0 人として数える)
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.21", 80)
	m.put("2026-10-21", "alb", cwlogs.MetricSignInFailures, "198.51.100.21", 300)
	m.put("2026-10-21", "app", cwlogs.MetricUserProbeDays, cwlogs.UserProbeIPUsers, 1)
	// 10-20 は U3 を流していない (印が無い): 数えていないので理由を付けない
	m.put("2026-10-20", "alb", cwlogs.MetricRateLimited, "198.51.100.22", 50)
	// user_sources に無いソースの印・値は読まない
	m.put("2026-10-20", "other", cwlogs.MetricUserProbeDays, cwlogs.UserProbeIPUsers, 1)
	m.put("2026-10-20", "other", cwlogs.MetricIPUsers, "198.51.100.22", 99)

	obs := evaluate(t, RateLimitedIP{Config: rateConfig("app")}, st, appAllowlist(t))
	if keysOf(obs) != "198.51.100.20,198.51.100.21,198.51.100.22" {
		t.Fatalf("obs: %v", obs)
	}
	school, brute, unknown := obs["198.51.100.20"], obs["198.51.100.21"], obs["198.51.100.22"]
	if school.Data["ip_users"] != 35.0 || strings.Join(school.Data["reasons"].([]string), ",") != reasonSuggestShared || school.Data["sign_in_failures"] != 0.0 {
		t.Fatalf("school: %+v", school.Data)
	}
	if brute.Data["ip_users"] != 0.0 || strings.Join(brute.Data["reasons"].([]string), ",") != reasonFewUsers || brute.Data["sign_in_failures"] != 300.0 {
		t.Fatalf("brute: %+v", brute.Data)
	}
	if _, ok := unknown.Data["ip_users"]; ok {
		t.Fatalf("unknown: %+v", unknown.Data)
	}
	if school.Fingerprint == brute.Fingerprint {
		t.Fatalf("理由が違えば fingerprint も違う: %q", school.Fingerprint)
	}
	if !strings.Contains(school.Summary, "35 人") || !strings.Contains(brute.Summary, "0 人") {
		t.Fatalf("summary: %s / %s", school.Summary, brute.Summary)
	}
}

// 下限は判定の閾値で、overrides で変えられる。suggest_min_users ちょうどは suggest_shared。
func TestRateLimitedIPThresholds(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.30", 5)
	m.put("2026-10-21", "app", cwlogs.MetricIPUsers, "198.51.100.30", 10)
	m.put("2026-10-21", "app", cwlogs.MetricUserProbeDays, cwlogs.UserProbeIPUsers, 1)
	c := rateConfig("app")
	c.MinCount = 5
	obs := evaluate(t, RateLimitedIP{Config: c}, st, appAllowlist(t))
	if o := obs["198.51.100.30"]; strings.Join(o.Data["reasons"].([]string), ",") != reasonSuggestShared {
		t.Fatalf("%+v", obs)
	}
}

// user_sources を書けば http_user も引かせるが、取れない run でもチェックは skip しない (429 は ALB のログだけで報告する)。
func TestRateLimitedIPNeeds(t *testing.T) {
	c := RateLimitedIP{Config: rateConfig()}
	if kinds(c.Needs()) != "http_access" || kinds(c.OptionalNeeds()) != "" {
		t.Fatalf("needs %v optional %v", c.Needs(), c.OptionalNeeds())
	}
	c = RateLimitedIP{Config: rateConfig("app")}
	if kinds(c.Needs()) != "http_access" || kinds(c.OptionalNeeds()) != "http_user" {
		t.Fatalf("needs %v optional %v", c.Needs(), c.OptionalNeeds())
	}
	if c.Cadence() != Daily || c.Mode() != ModeEvent {
		t.Fatal(c.Cadence(), c.Mode())
	}
	if _, ok := NewRegistry().Get("rate_limited_ip"); !ok {
		t.Fatal("not registered")
	}
}

func kinds(l []record.Kind) string {
	var out []string
	for _, k := range l {
		out = append(out, string(k))
	}
	return strings.Join(out, ",")
}
