package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 窓は appWindow [10-20 09:00, 10-21 09:00) なので評価する日は 10-20 と 10-21。過去は 10-20 の前日から 30 日 (09-20〜10-19)。

type activitySeed struct {
	st *store.Dir
	t  *testing.T
}

func (a activitySeed) put(date, metric, arn, v string, n float64) {
	a.t.Helper()
	if err := a.st.UpsertMetric(context.Background(), record.Metric{Date: date, Source: "trail", From: record.KindTrailEvent,
		Metric: metric, Key: record.ActivityKey(arn, v), Value: n}); err != nil {
		a.t.Fatal(err)
	}
}

// source は date に arn が prefix から events 件 (うち書き込み writes 件) 使われたことを入れる。
func (a activitySeed) source(date, arn, prefix string, events, writes float64) {
	a.put(date, record.MetricPrincipalSource, arn, prefix, events)
	if writes > 0 {
		a.put(date, record.MetricPrincipalSourceWrites, arn, prefix, writes)
	}
}

// history は 09-20〜10-19 の days 日 (10-19 から遡って) に、毎日 prefix から書き込み 1 件 (region) を入れる。
func (a activitySeed) history(arn, prefix, region string, days int) {
	for i := 0; i < days; i++ {
		d := time.Date(2026, 10, 19-i, 0, 0, 0, 0, time.UTC).Format(record.DateLayout)
		a.source(d, arn, prefix, 10, 1)
		a.put(d, record.MetricPrincipalWriteRegion, arn, region, 1)
	}
}

func (a activitySeed) principal(arn string, kind record.PrincipalKind, first time.Time, status string, ips ...string) {
	a.t.Helper()
	if err := a.st.UpsertPrincipalSeen(context.Background(), record.PrincipalSeen{ARN: arn, Kind: kind, FirstTime: first, Time: first, Count: 1}, status); err != nil {
		a.t.Fatal(err)
	}
	for _, ip := range ips {
		if err := a.st.UpsertPrincipalSeen(context.Background(), record.PrincipalSeen{ARN: arn, Kind: kind, IP: ip, FirstTime: now.Add(-2 * time.Hour), Time: now.Add(-time.Hour), Count: 1}, status); err != nil {
			a.t.Fatal(err)
		}
	}
}

func newSourceCheck() PrincipalNewSource {
	c := config.DefaultChecks()
	return PrincipalNewSource{Config: c.PrincipalNewSource, AccessDenied: c.AccessDenied}
}

const newSourceAllowlist = `
principals:
  - arn_pattern: arn:aws:iam::123456789012:role/example-ci-*
    dynamic_source: true
  - arn: arn:aws:iam::123456789012:role/example-approved
source_ips:
  - cidr: 192.0.2.0/24
    note: 本社
`

func TestPrincipalNewSource(t *testing.T) {
	st := newStore(t)
	a := activitySeed{st: st, t: t}
	old := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	const (
		alice    = "arn:aws:iam::123456789012:user/alice"
		deploy   = "arn:aws:iam::123456789012:role/example-deploy"
		ci       = "arn:aws:iam::123456789012:role/example-ci-runner"
		ciBusy   = "arn:aws:iam::123456789012:role/example-ci-busy"
		ops      = "arn:aws:iam::123456789012:user/example-ops"
		scanner  = "arn:aws:iam::123456789012:role/example-scanner"
		stranger = "arn:aws:iam::123456789012:role/example-unknown"
		fresh    = "arn:aws:iam::123456789012:role/example-approved"
		dormant  = "arn:aws:iam::123456789012:user/example-dormant"
		office   = "arn:aws:iam::123456789012:user/example-office"
		v6       = "arn:aws:iam::123456789012:user/example-v6"
		fn       = "arn:aws:iam::123456789012:role/example-fn"
		fnBusy   = "arn:aws:iam::123456789012:role/example-fn-busy"
	)
	const home, day1, day2 = "203.0.113.0/24", "2026-10-20", "2026-10-21"
	// alice: いつもの /24 の別の IP は新しくない。新しい /24 から読み取りと書き込み 1 件 → low
	a.principal(alice, record.PrincipalUser, old, store.PrincipalBaseline, "198.51.100.7", "203.0.113.99")
	a.history(alice, home, "ap-northeast-1", 30)
	a.source(day1, alice, home, 5, 0)
	a.source(day2, alice, "198.51.100.0/24", 3, 1)
	a.put(day2, record.MetricPrincipalWriteRegion, alice, "ap-northeast-1", 1)
	// deploy: 新しい送信元からの書き込みが 2 日で計 6 件 (min_writes 5 以上) → medium
	a.principal(deploy, record.PrincipalAssumedRole, old, store.PrincipalApproved)
	a.history(deploy, home, "ap-northeast-1", 30)
	a.source(day1, deploy, "198.51.100.0/24", 4, 3)
	a.source(day2, deploy, "198.51.100.0/24", 4, 3)
	// ci (dynamic_source): 新しい送信元だけ (low) は出さない
	a.principal(ci, record.PrincipalAssumedRole, old, store.PrincipalApproved)
	a.history(ci, home, "ap-northeast-1", 30)
	a.source(day2, ci, "198.51.100.0/24", 3, 1)
	// ci-busy (dynamic_source): 書き込みが多ければ medium は出す
	a.principal(ciBusy, record.PrincipalAssumedRole, old, store.PrincipalApproved)
	a.history(ciBusy, home, "ap-northeast-1", 30)
	a.source(day2, ciBusy, "198.51.100.0/24", 20, 10)
	// ops: いつもの送信元から、初めてのリージョンで書き込み → medium
	a.principal(ops, record.PrincipalUser, old, store.PrincipalBaseline)
	a.history(ops, home, "ap-northeast-1", 30)
	a.source(day2, ops, home, 5, 2)
	a.put(day2, record.MetricPrincipalWriteRegion, ops, "us-west-2", 2)
	// scanner: 新しい送信元 + 同じ窓で拒否の急増 (access_denied) → high
	a.principal(scanner, record.PrincipalAssumedRole, old, store.PrincipalBaseline)
	a.history(scanner, home, "ap-northeast-1", 30)
	a.source(day2, scanner, "198.51.100.0/24", 30, 0)
	d := &deniedSeed{st: st, t: t}
	d.put(scanner, record.PrincipalAssumedRole, now.Add(-2*time.Hour), "AccessDenied", "198.51.100.9", apis("iam", 6)...)
	// stranger: 未承認の主体は new_principal が扱う
	a.principal(stranger, record.PrincipalAssumedRole, old, store.PrincipalUnknown)
	a.source(day2, stranger, "198.51.100.0/24", 3, 3)
	// fresh: 過去 30 日の間に現れたばかりの主体 (過去の活動が無い) は、すべてが初めてなので報告しない
	a.principal(fresh, record.PrincipalAssumedRole, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), store.PrincipalApproved)
	a.source(day2, fresh, "198.51.100.0/24", 3, 3)
	a.put(day2, record.MetricPrincipalWriteRegion, fresh, "ap-northeast-1", 3)
	// dormant: 30 日以上使われていなかった主体が新しい送信元から使われた → low (dormant)
	a.principal(dormant, record.PrincipalUser, old, store.PrincipalBaseline)
	a.source(day2, dormant, "198.51.100.0/24", 1, 0)
	// office: 新しい /24 でも allowlist の source_ips の内なら新しい送信元にしない
	a.principal(office, record.PrincipalUser, old, store.PrincipalBaseline)
	a.history(office, home, "ap-northeast-1", 30)
	a.source(day2, office, "192.0.2.0/24", 3, 3)
	// v6: /48 で比べる
	a.principal(v6, record.PrincipalUser, old, store.PrincipalBaseline)
	a.history(v6, "2001:db8:1::/48", "ap-northeast-1", 30)
	a.source(day2, v6, "2001:db8:2::/48", 1, 0)
	// fn / fn-busy: サービス (Lambda など) が引き受けるロールは送信元が毎回変わるので dynamic_source と同じ扱い (low は出さない、medium 以上は出す)
	for i, role := range []string{fn, fnBusy} {
		a.principal(role, record.PrincipalAssumedRole, old, store.PrincipalBaseline)
		a.history(role, home, "ap-northeast-1", 30)
		if err := st.InsertEvent(context.Background(), record.TrailEvent{EventID: fmt.Sprintf("svc-assume-%d", i), Time: now.Add(-10 * 24 * time.Hour), Source: "trail",
			Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: "lambda.amazonaws.com", PrincipalKind: record.PrincipalService, ReadOnly: true,
			Data: map[string]any{"role_arn": role}}); err != nil {
			t.Fatal(err)
		}
	}
	a.source(day2, fn, "198.51.100.0/24", 3, 1)
	a.source(day2, fnBusy, "198.51.100.0/24", 30, 8)

	al, err := allowlist.Parse([]byte(newSourceAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := newSourceCheck().Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Severity{alice: Low, deploy: Medium, ciBusy: Medium, ops: Medium, scanner: High, dormant: Low, v6: Low, fnBusy: Medium}
	if fmt.Sprint(bySev(obs)) != fmt.Sprint(want) {
		t.Fatalf("severities:\n got  %v\n want %v", bySev(obs), want)
	}
	got := obsByKey(obs)
	al1 := got[alice]
	if fmt.Sprint(al1.Data["new_sources"]) != "[map[events:3 ips:[198.51.100.7] prefix:198.51.100.0/24 writes:1]]" || al1.Data["new_regions"] != nil ||
		!strings.Contains(al1.Summary, "198.51.100.0/24") {
		t.Fatalf("alice: %+v %s", al1.Data, al1.Summary)
	}
	if got[deploy].Data["writes_from_new_sources"] != 6.0 || !strings.Contains(fmt.Sprint(got[deploy].Data["reasons"]), "writes") {
		t.Fatalf("deploy: %+v", got[deploy].Data)
	}
	if got[ciBusy].Data["dynamic_source"] != true {
		t.Fatalf("ci-busy: %+v", got[ciBusy].Data)
	}
	if got[fnBusy].Data["service_assumed"] != true {
		t.Fatalf("fn-busy: %+v", got[fnBusy].Data)
	}
	if fmt.Sprint(got[ops].Data["new_regions"]) != "[map[region:us-west-2 writes:2]]" || got[ops].Data["new_sources"] != nil || !strings.Contains(got[ops].Summary, "us-west-2") {
		t.Fatalf("ops: %+v %s", got[ops].Data, got[ops].Summary)
	}
	if got[scanner].Data["access_denied"] != true || !strings.Contains(got[scanner].Summary, "拒否") {
		t.Fatalf("scanner: %+v %s", got[scanner].Data, got[scanner].Summary)
	}
	if got[dormant].Data["active_in_baseline"] != false {
		t.Fatalf("dormant: %+v", got[dormant].Data)
	}
	if fmt.Sprint(got[v6].Data["new_sources"]) != "[map[events:1 prefix:2001:db8:2::/48 writes:0]]" {
		t.Fatalf("v6: %+v", got[v6].Data)
	}
	for _, o := range obs {
		if o.Data["baseline_days_with_data"] != 30 {
			t.Fatalf("baseline days: %+v", o.Data)
		}
	}
}

// 導入直後 (CloudTrail のデータのある過去日が min_baseline_days 未満) は報告しない。
func TestPrincipalNewSourceWarmup(t *testing.T) {
	st := newStore(t)
	a := activitySeed{st: st, t: t}
	const alice = "arn:aws:iam::123456789012:user/alice"
	a.principal(alice, record.PrincipalUser, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), store.PrincipalBaseline)
	a.history(alice, "203.0.113.0/24", "ap-northeast-1", 14)
	a.source("2026-10-21", alice, "198.51.100.0/24", 30, 30)
	obs, err := newSourceCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 0 {
		t.Fatalf("warmup must not report: %+v", obs)
	}
	a.history(alice, "203.0.113.0/24", "ap-northeast-1", 15)
	obs, err = newSourceCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Severity != Medium {
		t.Fatalf("after warmup: %+v", obs)
	}
}

// 主体の活動の日次集計と秘匿値の読み取りの events を足しても、既存のチェック (日次集計を読む login_bruteforce・probe_paths・
// waf_block_trend・waf_review を含む) の結果は変わらない (ADR 0027)。
func TestActivityDoesNotAffectExistingChecks(t *testing.T) {
	st := newStore(t)
	a := activitySeed{st: st, t: t}
	const alice = "arn:aws:iam::123456789012:user/alice"
	a.principal(alice, record.PrincipalUser, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), store.PrincipalBaseline, "198.51.100.7")
	a.history(alice, "203.0.113.0/24", "ap-northeast-1", 30)
	a.source("2026-10-21", alice, "198.51.100.0/24", 100, 100)
	a.put("2026-10-21", record.MetricPrincipalWriteRegion, alice, "us-west-2", 50)
	s := &secretSeed{st: st, t: t}
	for i := 0; i < 30; i++ {
		s.secret(alice, record.PrincipalUser, now.Add(-time.Hour), fmt.Sprintf("prod/s%02d", i))
	}
	al, err := allowlist.Parse([]byte("principals:\n  - arn: " + alice + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry()
	for _, name := range reg.Names() {
		if name == "principal_new_source" || name == "secret_access" {
			continue
		}
		c, _ := reg.Get(name)
		obs, err := c.Evaluate(context.Background(), st, appWindow, al)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(obs) != 0 {
			t.Errorf("%s must not react to activity metrics or secret reads: %+v", name, obs)
		}
	}
	// 新しい 2 つは鳴る (前提の確認)
	for _, name := range []string{"principal_new_source", "secret_access"} {
		c, _ := reg.Get(name)
		if obs, err := c.Evaluate(context.Background(), st, appWindow, al); err != nil || len(obs) != 1 {
			t.Errorf("%s: %+v %v", name, obs, err)
		}
	}
}
