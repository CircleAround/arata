package checks

import (
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
)

// shared_sources (ADR 0094 の 1 節)。値はすべて架空。窓は appWindow (評価する日は 10-20 と 10-21)。
//   - 198.51.100.0/24: 試験の会場 (期限なし)
//   - 192.0.2.0/24: 10-20 の終わりまでの期限付き (10-21 は普通の送信元)
//   - 203.0.113.0/28: source_ips (203.0.113.0/24) とも当たる。source_ips が優先して丸ごと外す
func sharedAllowlist(t *testing.T) *allowlist.List {
	t.Helper()
	al, err := allowlist.Parse([]byte(`source_ips:
  - cidr: 203.0.113.0/24
    note: 本社
shared_sources:
  - cidr: 198.51.100.0/24
    note: 試験の会場
    approved_by: alice
    approved_at: 2026-10-01
  - cidr: 192.0.2.0/24
    note: 説明会の会場
    expires: 2026-10-20
  - cidr: 203.0.113.0/28
    note: 本社と重なる
`))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

func TestLoginBruteforceSharedSources(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.history("nginx", cwlogs.MetricSignInFailures, "192.0.2.50", 1)               // 過去の記録 (初出の判定に要る日数を満たす)
	m.put("2026-10-20", "nginx", cwlogs.MetricSignInFailures, "198.51.100.7", 90)  // shared: 下限 100 以下なので出ない
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "198.51.100.8", 101) // shared: 下限 100 を超える
	m.put("2026-10-20", "nginx", cwlogs.MetricSignInFailures, "192.0.2.10", 60)    // 期限内は shared (出ない)
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "192.0.2.11", 60)    // 期限の翌日は普通の下限 20
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "203.0.113.5", 500)  // source_ips が優先 (対象外)

	c := LoginBruteforce{Config: config.DefaultChecks().LoginBruteforce}
	obs := evaluate(t, c, st, sharedAllowlist(t))
	if keysOf(obs) != "192.0.2.11,198.51.100.8" {
		t.Fatalf("obs: %v", obs)
	}
	s := obs["198.51.100.8"]
	if s.Data["reason"] != reasonAboveBaseline || s.Data["threshold"] != 100.0 || s.Data["shared"] != true || s.Data["shared_note"] != "試験の会場" {
		t.Fatalf("shared: %+v", s.Data)
	}
	if !strings.Contains(s.Summary, "人の多い送信元") {
		t.Fatalf("summary: %s", s.Summary)
	}
	n := obs["192.0.2.11"]
	if n.Data["threshold"] != 20.0 || n.Data["shared"] != nil || n.Data["shared_note"] != nil {
		t.Fatalf("期限切れは普通の送信元: %+v", n.Data)
	}
	// shared_sources が無ければ今までどおり (どれも下限 20 を超える)
	obs = evaluate(t, c, st, appAllowlist(t))
	if keysOf(obs) != "192.0.2.10,192.0.2.11,198.51.100.7,198.51.100.8" {
		t.Fatalf("without shared_sources: %v", obs)
	}
}

// shared_sources の IP が初出で最多のときに new_top_ip を出さない (ADR 0094 の 1 節)。
func TestLoginBruteforceSharedNoNewTopIP(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.history("nginx", cwlogs.MetricSignInFailures, "192.0.2.50", 1)
	m.put("2026-10-21", "nginx", cwlogs.MetricSignInFailures, "198.51.100.7", 15) // 下限未満・その日の最多・初出
	c := LoginBruteforce{Config: config.DefaultChecks().LoginBruteforce}
	if obs := evaluate(t, c, st, sharedAllowlist(t)); len(obs) != 0 {
		t.Fatalf("shared の IP に new_top_ip を出した: %v", obs)
	}
	if obs := evaluate(t, c, st, appAllowlist(t)); obs["198.51.100.7"].Data["reason"] != reasonNewTopIP {
		t.Fatalf("shared でなければ new_top_ip: %v", obs)
	}
}

func TestRateLimitedIPSharedSources(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st, t}
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.7", 199) // shared: 下限 200 未満
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.8", 200) // shared: 下限ちょうどで報告 (min_count と同じく以上)
	m.put("2026-10-21", "app", cwlogs.MetricIPUsers, "198.51.100.8", 60)
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "198.51.100.9", 300) // shared で、ログインできた利用者が少ない
	m.put("2026-10-21", "app", cwlogs.MetricIPUsers, "198.51.100.9", 3)
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "192.0.2.11", 30) // 期限切れは普通の下限 20
	m.put("2026-10-21", "app", cwlogs.MetricIPUsers, "192.0.2.11", 40)
	m.put("2026-10-21", "alb", cwlogs.MetricRateLimited, "203.0.113.5", 900) // source_ips が優先
	m.put("2026-10-21", "app", cwlogs.MetricUserProbeDays, cwlogs.UserProbeIPUsers, 1)

	obs := evaluate(t, RateLimitedIP{Config: rateConfig("app")}, st, sharedAllowlist(t))
	if keysOf(obs) != "192.0.2.11,198.51.100.8,198.51.100.9" {
		t.Fatalf("obs: %v", obs)
	}
	heavy, few, expired := obs["198.51.100.8"], obs["198.51.100.9"], obs["192.0.2.11"]
	if heavy.Data["min_count"] != 200.0 || heavy.Data["shared"] != true || heavy.Data["shared_note"] != "試験の会場" ||
		strings.Join(heavy.Data["reasons"].([]string), ",") != reasonSharedHeavy {
		t.Fatalf("heavy: %+v", heavy.Data)
	}
	// 人の多い送信元でも、ログインできた利用者が少なければ few_users も添える (suggest_shared は付けない)
	if strings.Join(few.Data["reasons"].([]string), ",") != reasonSharedHeavy+","+reasonFewUsers {
		t.Fatalf("few: %+v", few.Data)
	}
	if expired.Data["min_count"] != 20.0 || expired.Data["shared"] != nil || strings.Join(expired.Data["reasons"].([]string), ",") != reasonSuggestShared {
		t.Fatalf("expired: %+v", expired.Data)
	}
	if heavy.Fingerprint == expired.Fingerprint || !strings.Contains(heavy.Summary, "人の多い送信元") {
		t.Fatalf("fingerprint / summary: %+v", heavy)
	}
	// ip_users を数えていなくても、shared の IP には shared_heavy を付ける
	obs = evaluate(t, RateLimitedIP{Config: rateConfig()}, st, sharedAllowlist(t))
	if strings.Join(obs["198.51.100.8"].Data["reasons"].([]string), ",") != reasonSharedHeavy {
		t.Fatalf("without users: %+v", obs["198.51.100.8"].Data)
	}
	if _, ok := obs["192.0.2.11"].Data["reasons"]; ok {
		t.Fatalf("shared でなく数えていなければ理由は無い: %+v", obs["192.0.2.11"].Data)
	}
}
