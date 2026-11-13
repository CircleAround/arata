package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 窓は appWindow [10-20 09:00, 10-21 09:00)。平常帯は窓の始まりの日 (10-20) の前日から 14 日 (10-06〜10-19)。

const deniedAllowlist = `
principals:
  - account: "111122223333"
    note: 外部 SaaS
`

type deniedSeed struct {
	st *store.Dir
	t  *testing.T
	n  int
}

// put は主体 arn の拒否された呼び出しを apis (eventSource の短縮形:eventName) ごとに 1 件ずつ at に入れる。
func (d *deniedSeed) put(arn string, kind record.PrincipalKind, at time.Time, code, ip string, apis ...string) {
	d.t.Helper()
	for _, api := range apis {
		svc, name, _ := strings.Cut(api, ":")
		d.n++
		e := record.TrailEvent{EventID: fmt.Sprintf("d%05d", d.n), Time: at, Source: "trail", Name: name, EventSource: svc + ".amazonaws.com",
			PrincipalARN: arn, PrincipalKind: kind, IP: ip, ErrorCode: code, ReadOnly: true, Data: map[string]any{}}
		if err := d.st.InsertEvent(context.Background(), e); err != nil {
			d.t.Fatal(err)
		}
	}
}

// apis は service:Name0..Name{n-1} を返す。
func apis(service string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s:List%02d", service, i)
	}
	return out
}

func repeat(api string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = api
	}
	return out
}

func deniedCheck() AccessDenied { return AccessDenied{Config: config.DefaultChecks().AccessDenied} }

func TestAccessDenied(t *testing.T) {
	st := newStore(t)
	d := &deniedSeed{st: st, t: t}
	in := now.Add(-3 * time.Hour)
	const (
		scanner  = "arn:aws:iam::123456789012:role/example-scanner"
		external = "arn:aws:iam::111122223333:role/saas-reader" // allowlist の account: で承認済み
		app      = "arn:aws:iam::123456789012:role/example-app"
		noisy    = "arn:aws:iam::123456789012:role/example-noisy"
		quiet    = "arn:aws:iam::123456789012:user/example-quiet"
		extRoot  = "arn:aws:iam::444455556666:root"
	)
	// 幅 (medium): 6 種類。同じ API の拒否を重ねても種類は増えない
	d.put(scanner, record.PrincipalAssumedRole, in, "AccessDenied", "198.51.100.1", "iam:ListUsers", "iam:ListUsers", "s3:ListBuckets", "secretsmanager:ListSecrets", "iam:CreateUser")
	d.put(scanner, record.PrincipalAssumedRole, in.Add(time.Minute), "Client.UnauthorizedOperation", "198.51.100.2", "ec2:DescribeInstances", "ec2:DescribeVpcs")
	// 幅 (high): 20 種類。承認済みでも報告する
	d.put(external, record.PrincipalAssumedRole, in, "AccessDeniedException", "198.51.100.3", apis("ssm", 20)...)
	// 量 (medium): 同じ API を 60 件
	d.put(app, record.PrincipalAssumedRole, in, "AccessDenied", "", repeat("s3:GetObject", 60)...)
	// 平常帯で吸収: 毎日 6 種類・20 件拒否される主体 (平常帯 18 種類・60 件)
	for day := 6; day <= 19; day++ {
		d.put(noisy, record.PrincipalAssumedRole, time.Date(2026, 10, day, 12, 0, 0, 0, time.UTC), "AccessDenied", "", append(apis("kms", 6), repeat("kms:List00", 14)...)...)
	}
	d.put(noisy, record.PrincipalAssumedRole, in, "AccessDenied", "", append(apis("kms", 7), repeat("kms:List00", 48)...)...) // 7 種類・55 件 (min_count 50 は超えるが平常帯 60 以下)
	// 閾値未満: 拒否 4 種類 + 拒否でないエラー 3 種類 (数えない)
	d.put(quiet, record.PrincipalUser, in, "AccessDenied", "", apis("iam", 4)...)
	d.put(quiet, record.PrincipalUser, in, "NoSuchEntity", "", "iam:GetRole", "iam:GetUser", "iam:GetPolicy")
	// サービス主体と root は対象外
	d.put("ec2.amazonaws.com", record.PrincipalService, in, "AccessDenied", "", apis("s3", 10)...)
	d.put("arn:aws:iam::123456789012:root", record.PrincipalRoot, in, "AccessDenied", "203.0.113.1", apis("s3", 10)...)
	// 外部アカウントの root (承認されていない)
	d.put(extRoot, record.PrincipalUnknown, in, "AccessDenied", "198.51.100.4", apis("sts", 5)...)
	// 窓外 (平常帯の前) は数えない
	d.put(quiet, record.PrincipalUser, now.Add(-30*24*time.Hour), "AccessDenied", "", apis("ec2", 10)...)

	al, err := allowlist.Parse([]byte(deniedAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	obs := evaluate(t, deniedCheck(), st, al)
	if got := strings.Join(sortedObsKeys(obs), ";"); got != sortedJoin(external, scanner, app, extRoot) {
		t.Fatalf("keys: %s", got)
	}

	s := obs[scanner]
	if s.Severity != Medium || s.Data["threshold"] != "breadth" || s.Data["distinct_apis"] != 6 || s.Data["count"] != 7 ||
		s.Data["allowlist_status"] != "unknown" || s.Data["principal"] != scanner || s.Data["principal_kind"] != "assumed-role" {
		t.Fatalf("scanner: %+v", s)
	}
	if s.Summary != "拒否された API 呼び出し: "+scanner+" が 6 種類 (7 件) で拒否 (列挙の兆候)" {
		t.Fatalf("summary: %s", s.Summary)
	}
	if got := strings.Join(s.Data["apis"].([]string), ","); got != "iam:ListUsers × 2,ec2:DescribeInstances × 1,ec2:DescribeVpcs × 1,iam:CreateUser × 1,s3:ListBuckets × 1,secretsmanager:ListSecrets × 1" {
		t.Fatalf("apis: %s", got)
	}
	if got := strings.Join(s.Data["error_codes"].([]string), ","); got != "AccessDenied,Client.UnauthorizedOperation" {
		t.Fatalf("error codes: %s", got)
	}
	if got := strings.Join(s.Data["ips"].([]string), ","); got != "198.51.100.1,198.51.100.2" {
		t.Fatalf("ips: %s", got)
	}
	if s.Data["first_time"] != "2026-10-21T06:00:00Z" || s.Data["last_time"] != "2026-10-21T06:01:00Z" || s.Data["baseline_median_count"] != 0.0 || s.Data["baseline_median_distinct"] != 0.0 {
		t.Fatalf("scanner data: %+v", s.Data)
	}

	e := obs[external]
	if e.Severity != High || e.Data["allowlist_status"] != "approved" || e.Data["distinct_apis"] != 20 || len(e.Data["apis"].([]string)) != 10 {
		t.Fatalf("external: %+v", e)
	}

	a := obs[app]
	if a.Severity != Medium || a.Data["threshold"] != "volume" || a.Data["count"] != 60 || a.Data["distinct_apis"] != 1 || a.Data["volume_threshold"] != 50.0 {
		t.Fatalf("app: %+v", a)
	}
	if !strings.Contains(a.Summary, "60 件") {
		t.Fatalf("app summary: %s", a.Summary)
	}

	r := obs[extRoot]
	if r.Data["external_account"] != "444455556666" || r.Data["principal_identity"] != "account_only" || !strings.Contains(r.Summary, "外部アカウント 444455556666 が") {
		t.Fatalf("external root: %+v", r)
	}

	// Fingerprint は重大度と IP 集合だけ (件数や API の並びは入れない)
	if s.Fingerprint != fingerprint(Medium, map[string]bool{"198.51.100.1": true, "198.51.100.2": true}) {
		t.Fatalf("fingerprint: %q", s.Fingerprint)
	}
}

// 導入直後 (データのある過去日が min_baseline_days 未満) は平常帯を 0 とみなし、絶対の閾値だけで判定する。
func TestAccessDeniedWithoutBaseline(t *testing.T) {
	st := newStore(t)
	d := &deniedSeed{st: st, t: t}
	const p = "arn:aws:iam::123456789012:role/example-batch"
	// 過去 3 日だけ毎日 6 種類拒否 (平常帯を使えば 18 種類まで吸収されるが、3 日 < 7 日なので使わない)
	for day := 17; day <= 19; day++ {
		d.put(p, record.PrincipalAssumedRole, time.Date(2026, 10, day, 12, 0, 0, 0, time.UTC), "AccessDenied", "", apis("kms", 6)...)
	}
	d.put(p, record.PrincipalAssumedRole, now.Add(-time.Hour), "AccessDenied", "", apis("kms", 6)...)
	obs := evaluate(t, deniedCheck(), st, &allowlist.List{})
	o, ok := obs[p]
	if len(obs) != 1 || !ok || o.Data["baseline_median_distinct"] != 0.0 || o.Data["baseline_days_with_data"] != 3 {
		t.Fatalf("obs: %+v", obs)
	}

	// 7 日以上データがあれば平常帯で吸収する
	for day := 10; day <= 16; day++ {
		d.put(p, record.PrincipalAssumedRole, time.Date(2026, 10, day, 12, 0, 0, 0, time.UTC), "AccessDenied", "", apis("kms", 6)...)
	}
	if obs := evaluate(t, deniedCheck(), st, &allowlist.List{}); len(obs) != 0 {
		t.Fatalf("absorbed by baseline: %+v", obs)
	}
}

// 再走査の重なり区間のうち前回収集済みのイベントは数えず、遅れて届いたものだけ数える (ADR 0013)。
func TestAccessDeniedRescan(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	const p = "arn:aws:iam::123456789012:role/example-scanner"
	from := now.Add(-24 * time.Hour)
	ev := func(id, api string, at, collected time.Time) record.TrailEvent {
		svc, name, _ := strings.Cut(api, ":")
		return record.TrailEvent{EventID: id, Time: at, Source: "trail", Name: name, EventSource: svc + ".amazonaws.com", PrincipalARN: p,
			PrincipalKind: record.PrincipalAssumedRole, ErrorCode: "AccessDenied", ReadOnly: true, CollectedAt: collected}
	}
	for _, e := range []record.TrailEvent{
		ev("seen1", "iam:ListUsers", from.Add(-10*time.Minute), from), // 前回収集済み (前回の窓で評価済み)
		ev("seen2", "iam:ListRoles", from.Add(-9*time.Minute), from),
		ev("late", "s3:ListBuckets", from.Add(-5*time.Minute), now), // 遅れて届いた
		ev("w1", "ec2:DescribeInstances", from.Add(time.Hour), now),
		ev("w2", "ec2:DescribeVpcs", from.Add(time.Hour), now),
		ev("w3", "secretsmanager:ListSecrets", from.Add(time.Hour), now),
		ev("w4", "kms:ListKeys", from.Add(time.Hour), now),
	} {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	w := collect.Window{From: from, To: now, ScanFrom: from.Add(-15 * time.Minute), CollectedAt: now}
	obs, err := deniedCheck().Evaluate(ctx, st, w, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Data["distinct_apis"] != 5 || obs[0].Data["count"] != 5 {
		t.Fatalf("obs: %+v", obs)
	}
}

func TestAccessDeniedCustomErrorCodes(t *testing.T) {
	st := newStore(t)
	d := &deniedSeed{st: st, t: t}
	const p = "arn:aws:iam::123456789012:role/example-scanner"
	d.put(p, record.PrincipalAssumedRole, now.Add(-time.Hour), "AccessDenied", "", apis("iam", 5)...)
	c := deniedCheck()
	c.Config.ErrorCodes = []string{"UnauthorizedOperation"}
	if obs := evaluate(t, c, st, &allowlist.List{}); len(obs) != 0 {
		t.Fatalf("error codes are matched exactly: %+v", obs)
	}
}

func sortedObsKeys(m map[string]Observation) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return sortStrings(out)
}

func sortedJoin(ss ...string) string { return strings.Join(sortStrings(ss), ";") }

func sortStrings(ss []string) []string {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return sortedKeys(m)
}

// 想定済みの拒否 (allowlist の expected_denied) は数える前に除く。窓にも平常帯にも同じく適用し、除いた件数は Data に残す (ADR 0022)。
func TestAccessDeniedExpectedDenied(t *testing.T) {
	const (
		ai     = "arn:aws:iam::123456789012:role/ai-investigation-readonly"
		legacy = "arn:aws:iam::123456789012:role/legacy-batch"
		batch  = "arn:aws:iam::123456789012:role/example-batch"
	)
	al, err := allowlist.Parse([]byte(`
principals:
  - arn: ` + ai + `
    note: 個人情報を含むロググループは IAM で Deny している
    expected_denied: ["logs:StartQuery", "logs:Get*", "logs:FilterLogEvents"]
  - arn: ` + legacy + `
    note: 移行中の旧ロール
    expires: 2026-10-20
    expected_denied: ["s3:*"]
  - arn: ` + batch + `
    note: 定期処理。kms の列挙は拒否される
    expected_denied: ["kms:*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	in := now.Add(-3 * time.Hour)

	t.Run("excluded below threshold", func(t *testing.T) {
		st := newStore(t)
		d := &deniedSeed{st: st, t: t}
		// 想定内 3 種類 (32 件) + 想定外 3 種類 → 除けば 3 種類・3 件で閾値未満
		d.put(ai, record.PrincipalAssumedRole, in, "AccessDenied", "", append(repeat("logs:StartQuery", 30), "logs:GetLogEvents", "logs:FilterLogEvents")...)
		d.put(ai, record.PrincipalAssumedRole, in, "AccessDenied", "", "iam:ListUsers", "s3:ListBuckets", "kms:ListKeys")
		if obs := evaluate(t, deniedCheck(), st, al); len(obs) != 0 {
			t.Fatalf("expected denials should be excluded: %+v", obs)
		}
		// 想定外が 6 種類になれば報告し、除いた件数を残す
		d.put(ai, record.PrincipalAssumedRole, in, "AccessDenied", "", "ec2:DescribeVpcs", "sts:GetCallerIdentity", "secretsmanager:ListSecrets")
		obs := evaluate(t, deniedCheck(), st, al)
		o := obs[ai]
		if len(obs) != 1 || o.Severity != Medium || o.Data["distinct_apis"] != 6 || o.Data["count"] != 6 || o.Data["expected_denied_excluded"] != 32 {
			t.Fatalf("obs: %+v", obs)
		}
		if strings.Contains(strings.Join(o.Data["apis"].([]string), ","), "logs:") {
			t.Fatalf("apis should not list expected denials: %v", o.Data["apis"])
		}
	})

	t.Run("expired entry is counted again", func(t *testing.T) {
		st := newStore(t)
		d := &deniedSeed{st: st, t: t}
		d.put(legacy, record.PrincipalAssumedRole, in, "AccessDenied", "", apis("s3", 6)...)
		obs := evaluate(t, deniedCheck(), st, al)
		if o, ok := obs[legacy]; !ok || o.Data["distinct_apis"] != 6 || o.Data["expected_denied_excluded"] != 0 {
			t.Fatalf("expired expected_denied must not exclude: %+v", obs)
		}
	})

	t.Run("baseline excludes too", func(t *testing.T) {
		st := newStore(t)
		d := &deniedSeed{st: st, t: t}
		// 平常帯に毎日 kms の想定内の拒否 6 種類。除かなければ平常帯 6 × 3 = 18 種類に吸収されるが、除くので平常帯は 0
		for day := 6; day <= 19; day++ {
			d.put(batch, record.PrincipalAssumedRole, time.Date(2026, 10, day, 12, 0, 0, 0, time.UTC), "AccessDenied", "", apis("kms", 6)...)
		}
		d.put(batch, record.PrincipalAssumedRole, in, "AccessDenied", "", apis("iam", 6)...)
		obs := evaluate(t, deniedCheck(), st, al)
		if o, ok := obs[batch]; !ok || o.Data["baseline_median_distinct"] != 0.0 || o.Data["distinct_apis"] != 6 {
			t.Fatalf("baseline should exclude expected denials: %+v", obs)
		}
		// 同じ平常帯でも、allowlist に expected_denied が無ければ吸収される (比較)
		if obs := evaluate(t, deniedCheck(), st, &allowlist.List{}); len(obs) != 0 {
			t.Fatalf("without expected_denied the baseline absorbs: %+v", obs)
		}
	})
}

// サービスリンクロール (パスが /aws-service-role/) の拒否は、窓にも平常帯にも数えない。
// 普通のロールは従来どおり報告する。
func TestAccessDeniedSkipsServiceLinkedRole(t *testing.T) {
	st := newStore(t)
	d := &deniedSeed{st: st, t: t}
	in := now.Add(-3 * time.Hour)
	const (
		slr    = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
		plain  = "arn:aws:iam::123456789012:role/example-scanner"
		lookal = "arn:aws:iam::123456789012:role/service-role/example-aws-service-role-like"
	)
	// 幅・量のどちらも超える数
	d.put(slr, record.PrincipalAssumedRole, in, "AccessDenied", "", apis("config", 25)...)
	d.put(slr, record.PrincipalAssumedRole, in, "AccessDenied", "", repeat("s3:GetObject", 80)...)
	d.put(plain, record.PrincipalAssumedRole, in, "AccessDenied", "", apis("ssm", 6)...)
	// 名前に似ているだけのロールは除かない
	d.put(lookal, record.PrincipalAssumedRole, in, "AccessDenied", "", apis("kms", 6)...)

	al, err := allowlist.Parse([]byte(deniedAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	obs := evaluate(t, deniedCheck(), st, al)
	if got := strings.Join(sortedObsKeys(obs), ";"); got != sortedJoin(plain, lookal) {
		t.Fatalf("keys: %s", got)
	}
}

func TestIsServiceLinkedRole(t *testing.T) {
	for arn, want := range map[string]bool{
		"arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig": true,
		"arn:aws:iam::123456789012:role/example-app":                                                   false,
		"arn:aws:iam::123456789012:role/service-role/example":                                          false,
		"arn:aws:iam::123456789012:user/aws-service-role/x":                                            false,
	} {
		if got := isServiceLinkedRole(arn); got != want {
			t.Errorf("%s: %v", arn, got)
		}
	}
}
