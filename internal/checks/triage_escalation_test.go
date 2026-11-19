package checks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 片付けの表 (TriageRows) で「上がる余地あり」とした行は、同じ Key のまま、より重い重大度で観測されうること (ADR 0068 の 6 節)。
// ack 中に出直すのは重大度が上がったときだけ (ADR 0022) なので、上がる余地の無い行の ack は最後になる。ここでは、余地ありの行ごとに、
// 同じ Key で軽い観測と重い観測を作って確かめる。余地ありの行を足したら、ここにも足す (TestTriageEscalationCovered が確かめる)。
var escalationCases = map[string]map[Severity]func(t *testing.T) (key string, light, heavy Observation){
	"access_denied": {
		Medium: func(t *testing.T) (string, Observation, Observation) {
			const p = "arn:aws:iam::123456789012:role/example-scanner"
			light := deniedObs(t, p, 6)
			heavy := deniedObs(t, p, 20)
			return p, light[p], heavy[p]
		},
	},
	"secret_access": {
		Low: func(t *testing.T) (string, Observation, Observation) {
			light := secretObs(t, secApp, 1)
			heavy := secretObs(t, secApp, 13)
			return secApp, light[secApp], heavy[secApp]
		},
		Medium: func(t *testing.T) (string, Observation, Observation) {
			light := secretObs(t, secWorker, 1) // 秘匿値を読むのが初めて
			heavy := secretObs(t, secWorker, 13)
			return secWorker, light[secWorker], heavy[secWorker]
		},
	},
	"principal_new_source": {
		Low: func(t *testing.T) (string, Observation, Observation) {
			const p = "arn:aws:iam::123456789012:user/alice"
			light := newSourceObs(t, p, 1, false)
			heavy := newSourceObs(t, p, 1, true) // 新しい送信元 + 同じ窓の拒否の急増
			return p, light[p], heavy[p]
		},
		Medium: func(t *testing.T) (string, Observation, Observation) {
			const p = "arn:aws:iam::123456789012:user/alice"
			light := newSourceObs(t, p, 6, false) // 新しい送信元からの書き込みが min_writes 以上
			heavy := newSourceObs(t, p, 6, true)
			return p, light[p], heavy[p]
		},
	},
	"unused_region_activity": {
		Medium: func(t *testing.T) (string, Observation, Observation) {
			key := "eu-west-1|" + secUser
			light := unusedRegionObs(t, "AccessDeniedException") // 計算資源の作成の試行 (拒否)
			heavy := unusedRegionObs(t, "")                      // 作成の成功
			return key, light[key], heavy[key]
		},
	},
	"endpoint_abuse": {
		Low: func(t *testing.T) (string, Observation, Observation) {
			light := abuseObs(t, 1)  // 1 IP から多数 (量だけ)
			heavy := abuseObs(t, 25) // 多数の IP に分散
			return "search", light["search"], heavy["search"]
		},
	},
	"ecs_exec": {
		Medium: func(t *testing.T) (string, Observation, Observation) {
			light := ecsExecObs(t, "principals:\n  - arn: "+execAlice+"\n", "")                          // 承認済みの主体
			heavy := ecsExecObs(t, "principals:\n  - arn: "+execAlice+"\n    expires: 2026-10-01\n", "") // 承認の期限が切れた
			return execKeyAlice, light[execKeyAlice], heavy[execKeyAlice]
		},
		Low: func(t *testing.T) (string, Observation, Observation) {
			light := ecsExecObs(t, "principals:\n  - arn: "+execAlice+"\n", "TargetNotConnectedException") // 全部失敗した試行
			heavy := ecsExecObs(t, "principals:\n  - arn: "+execAlice+"\n", "")                            // 同じ日に成功
			return execKeyAlice, light[execKeyAlice], heavy[execKeyAlice]
		},
	},
	"oidc_assume_role": {
		Low: func(t *testing.T) (string, Observation, Observation) {
			light := oidcUnknownObs(t, "AccessDenied") // 全部が拒否された引き受け
			heavy := oidcUnknownObs(t, "")             // 成功した引き受け
			return oidcUnknownKey, light[oidcUnknownKey], heavy[oidcUnknownKey]
		},
	},
}

func TestTriageEscalation(t *testing.T) {
	for check, bySev := range escalationCases {
		for sev, f := range bySev {
			t.Run(fmt.Sprintf("%s/%s", check, sev), func(t *testing.T) {
				key, light, heavy := f(t)
				if light.Key != key || heavy.Key != key {
					t.Fatalf("both observations must have the key %q: %q / %q", key, light.Key, heavy.Key)
				}
				if light.Severity != sev || heavy.Severity.Rank() <= sev.Rank() {
					t.Fatalf("want %s then heavier, got %s then %s", sev, light.Severity, heavy.Severity)
				}
			})
		}
	}
}

// 表の「余地あり」の行と、上の確かめの組が一致する (片方だけを足させない)。
func TestTriageEscalationCovered(t *testing.T) {
	for _, check := range TriageChecks() {
		for _, r := range TriageRows(check) {
			if r.KeyPrefix != "" {
				continue // 接頭辞の行は上がる余地「なし」だけ (TestTriageTableRules)
			}
			for _, sev := range r.Severities {
				_, tested := escalationCases[check][sev]
				if r.Escalates != tested {
					t.Errorf("%s %s: escalates %v in the table, but tested %v", check, sev, r.Escalates, tested)
				}
			}
		}
	}
	for check, bySev := range escalationCases {
		for sev := range bySev {
			if r, ok := TriageRowOf(check, "", sev); !ok || !r.Escalates {
				t.Errorf("%s %s is tested as escalating but the table says otherwise", check, sev)
			}
		}
	}
}

func deniedObs(t *testing.T, p string, n int) map[string]Observation {
	st := newStore(t)
	d := &deniedSeed{st: st, t: t}
	d.put(p, record.PrincipalAssumedRole, now.Add(-3*time.Hour), "AccessDenied", "198.51.100.1", apis("iam", n)...)
	return evaluate(t, deniedCheck(), st, &allowlist.List{})
}

func secretObs(t *testing.T, p string, n int) map[string]Observation {
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	seedSecretHistory(s)
	coverage(t, st, 14)
	for i := 0; i < n; i++ {
		s.secret(p, record.PrincipalAssumedRole, now.Add(-3*time.Hour), fmt.Sprintf("prod/new%02d", i))
	}
	obs, err := secretCheck().Evaluate(context.Background(), st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	return obsByKey(obs)
}

func newSourceObs(t *testing.T, p string, writes float64, denied bool) map[string]Observation {
	st := newStore(t)
	a := activitySeed{st: st, t: t}
	coverage(t, st, 30)
	a.principal(p, record.PrincipalUser, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), store.PrincipalBaseline)
	a.history(p, "203.0.113.0/24", "ap-northeast-1", 30)
	a.source("2026-10-21", p, "198.51.100.0/24", 10, writes)
	if denied {
		d := &deniedSeed{st: st, t: t}
		d.put(p, record.PrincipalUser, now.Add(-2*time.Hour), "AccessDenied", "198.51.100.9", apis("iam", 6)...)
	}
	return evaluate(t, newSourceCheck(), st, &allowlist.List{})
}

func unusedRegionObs(t *testing.T, code string) map[string]Observation {
	st := newStore(t)
	e := record.TrailEvent{EventID: "run", Time: now.Add(-time.Hour), Source: "unused", Name: "RunInstances", EventSource: "ec2.amazonaws.com", Region: "eu-west-1",
		PrincipalARN: secUser, PrincipalKind: record.PrincipalUser, IP: "198.51.100.7", ErrorCode: code, Data: map[string]any{}}
	if err := st.InsertEvent(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	obs, err := unusedRegionCheck().Evaluate(context.Background(), st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	return byKeyObs(obs)
}

func abuseObs(t *testing.T, ips float64) map[string]Observation {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	collected(m, 14)
	m.put("2026-10-21", "web", cwlogs.MetricEndpointCount, "search|05:00", 100)
	m.put("2026-10-21", "web", cwlogs.MetricEndpointIPs, "search|05:00", ips)
	return evalAbuse(t, abuseCheck(), st)
}

// oidcUnknownKey は既知でない入り口 (refs の違うブランチ) から、oidc_subjects に無いロールへの引き受けの Key。
const oidcUnknownKey = oidcGH + "|repo:example-org/example-repo:ref:refs/heads/topic|" + oidcAdmin

func oidcUnknownObs(t *testing.T, code string) map[string]Observation {
	st := newStore(t)
	s := &oidcSeed{t: t, st: st}
	s.gh(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC), oidcAdmin, "repo:example-org/example-repo:ref:refs/heads/topic", "203.0.113.5", code)
	return oidcEval(t, st, collect.Window{From: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)}, oidcAllowlist)
}

// ecsExecObs は既知の人 (alice) の ExecuteCommand を 1 件 (code が空でなければ失敗) 置いて評価する。
func ecsExecObs(t *testing.T, yaml, code string) map[string]Observation {
	s := execSeed{t: t, st: newStore(t)}
	s.principal(execAlice, record.PrincipalUser, store.PrincipalUnknown)
	s.exec("e1", now.Add(-2*time.Hour), execAlice, record.PrincipalUser, code, execData("t1", "/bin/sh", ""))
	al, err := allowlist.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return execEval(t, s.st, al, execWindow)
}
