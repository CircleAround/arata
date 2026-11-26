package checks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// ADR 0090: 平常帯の中央値は、そのソースを収集した日だけで取る。収集していない日 (導入の前・収集の抜け) は数えず、
// 収集した日で値の無い日は 0 と数える。
//
// どのテストも窓は [10-20 09:00, 10-21 09:00)、平常帯は 10-06〜10-19 の 14 日。
// 「抜けあり」は 10-13〜10-19 の 7 日だけを収集し、10-06〜10-12 は収集していない (記録も無い)。
// 「全部収集」は 14 日を収集し、値は 10-13〜10-19 の 7 日だけにある (残りの 7 日は収集した日の 0)。

// gapDays は収集した 7 日 (10-13〜10-19)。
func gapDays() []time.Time {
	var out []time.Time
	for d := 13; d <= 19; d++ {
		out = append(out, time.Date(2026, 10, d, 0, 0, 0, 0, time.UTC))
	}
	return out
}

func TestOIDCAssumeRoleVolumeCollectedDays(t *testing.T) {
	const main = "repo:example-org/example-repo:ref:refs/heads/main"
	w := collect.Window{From: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	vol := "volume:" + oidcGH + "|" + main + "|" + oidcDeploy
	for _, tc := range []struct {
		name      string
		collected int // coverage の日数 (10-19 から遡る)
		today     int
		want      bool
		median    float64
	}{
		// 中央値 10 (収集した 7 日)、しきい値 30。以前は 14 日 (うち 7 日は収集していない 0) の中央値 5 → しきい値 20 で鳴った
		{"抜けあり: ふだんの回数は鳴らさない", 7, 30, false, 0},
		{"抜けあり: 平常帯を超えたら鳴らす", 7, 31, true, 10},
		// 収集した日の 0 は 0 と数える: 中央値 5、しきい値 20
		{"全部収集: 0 の日も数える", 14, 21, true, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			s := &oidcSeed{t: t, st: st}
			for _, d := range gapDays() {
				for i := 0; i < 10; i++ {
					s.gh(d.Add(time.Hour+time.Duration(i)*time.Minute), oidcDeploy, main, "203.0.113.5", "")
				}
			}
			for i := 0; i < tc.today; i++ {
				s.gh(time.Date(2026, 10, 20, 10, 0, i, 0, time.UTC), oidcDeploy, main, "203.0.113.5", "")
			}
			coverage(t, st, tc.collected)
			by := oidcEval(t, st, w, oidcAllowlist)
			o, ok := by[vol]
			if ok != tc.want {
				t.Fatalf("volume の行: %v, want %v (%v)", ok, tc.want, o.Data)
			}
			if ok && o.Data["baseline_median"] != tc.median {
				t.Errorf("baseline_median = %v, want %v", o.Data["baseline_median"], tc.median)
			}
		})
	}
}

func TestAccessDeniedCollectedDays(t *testing.T) {
	const noisy = "arn:aws:iam::123456789012:role/example-noisy"
	for _, tc := range []struct {
		name      string
		collected int
		want      bool
		median    float64
	}{
		// 中央値 20 件 (収集した 7 日)、しきい値 60。以前は 14 日の中央値 10 → しきい値 50 (min_count) で 55 件が鳴った
		{"抜けあり: ふだんの件数は鳴らさない", 7, false, 0},
		// 収集した日の 0 は 0 と数える: 中央値 10、しきい値 50
		{"全部収集: 0 の日も数える", 14, true, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			d := &deniedSeed{st: st, t: t}
			for _, day := range gapDays() {
				d.put(noisy, record.PrincipalAssumedRole, day.Add(12*time.Hour), "AccessDenied", "", append(apis("kms", 6), repeat("kms:List00", 14)...)...)
			}
			d.put(noisy, record.PrincipalAssumedRole, now.Add(-3*time.Hour), "AccessDenied", "", append(apis("kms", 7), repeat("kms:List00", 48)...)...) // 7 種類・55 件
			coverage(t, st, tc.collected)
			obs := evaluate(t, deniedCheck(), st, &allowlist.List{})
			o, ok := obs[noisy]
			if ok != tc.want {
				t.Fatalf("報告: %v, want %v (%v)", ok, tc.want, o.Data)
			}
			if ok && (o.Data["baseline_median_count"] != tc.median || o.Data["baseline_days_collected"] != tc.collected) {
				t.Errorf("data: %v", o.Data)
			}
		})
	}
}

func TestSecretAccessCollectedDays(t *testing.T) {
	for _, tc := range []struct {
		name      string
		collected int
		want      Severity
		median    float64
	}{
		// 中央値 20 個 (収集した 7 日)、しきい値 60。新しい 15 個だけ low。以前は 14 日の中央値 10 → しきい値 30 で 35 個が high
		{"抜けあり: ふだんの数は一括読み出しにしない", 7, Low, 20},
		// 収集した日の 0 は 0 と数える: 中央値 10、しきい値 30
		{"全部収集: 0 の日も数える", 14, High, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			s := &secretSeed{st: st, t: t}
			for _, d := range gapDays() {
				for i := 0; i < 20; i++ {
					s.secret(secBusy, record.PrincipalAssumedRole, d.Add(12*time.Hour), fmt.Sprintf("busy/%02d", i))
				}
			}
			for i := 0; i < 35; i++ {
				s.secret(secBusy, record.PrincipalAssumedRole, now.Add(-3*time.Hour), fmt.Sprintf("busy/%02d", i))
			}
			coverage(t, st, tc.collected)
			obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
			if err != nil {
				t.Fatal(err)
			}
			o, ok := obsByKey(obs)[secBusy]
			if !ok || o.Severity != tc.want || o.Data["baseline_median_distinct"] != tc.median {
				t.Fatalf("got %v %s %v", ok, o.Severity, o.Data)
			}
		})
	}
}

// login_bruteforce と probe_paths (detectSpikes): 収集した日は http_access のソースの lines_total のある日 (と、その metric の値のある日)。
func TestLoginBruteforceCollectedDays(t *testing.T) {
	const nat = "192.0.2.10"
	for _, tc := range []struct {
		name      string
		collected int
		want      bool
		median    float64
	}{
		// 中央値 10 (収集した 7 日)、しきい値 30。以前は 14 日の中央値 5 → しきい値 20 (min_count) で 25 件が鳴った
		{"抜けあり: ふだんの件数は鳴らさない", 7, false, 0},
		// 収集した日 (lines_total のある日) の 0 は 0 と数える: 中央値 5、しきい値 20
		{"全部収集: 0 の日も数える", 14, true, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			m := metricSeed{st, t}
			for _, d := range gapDays() {
				m.put(d.Format(record.DateLayout), "nginx", cwlogs.MetricSignInFailures, nat, 10)
			}
			for i := 1; i <= tc.collected; i++ {
				m.put(time.Date(2026, 10, 20-i, 0, 0, 0, 0, time.UTC).Format(record.DateLayout), "nginx", cwlogs.MetricLinesTotal, "", 1000)
			}
			m.put("2026-10-20", "nginx", cwlogs.MetricSignInFailures, nat, 25)
			obs := evaluate(t, LoginBruteforce{Config: config.DefaultChecks().LoginBruteforce}, st, &allowlist.List{})
			o, ok := obs[nat]
			if ok != tc.want {
				t.Fatalf("報告: %v, want %v (%v)", ok, tc.want, o.Data)
			}
			if ok && (o.Data["baseline_median"] != tc.median || o.Data["baseline_days_collected"] != tc.collected) {
				t.Errorf("data: %v", o.Data)
			}
		})
	}
}
