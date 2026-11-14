package checks

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

const (
	oidcGH      = "token.actions.githubusercontent.com"
	oidcDeploy  = "arn:aws:iam::123456789012:role/gha-deploy"
	oidcNightly = "arn:aws:iam::123456789012:role/gha-nightly"
	oidcAdmin   = "arn:aws:iam::123456789012:role/admin"
	oidcIRSA    = "arn:aws:iam::123456789012:role/app-irsa"
	oidcEKS     = "oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789"
)

const oidcAllowlist = `
principals:
  - arn: arn:aws:iam::123456789012:role/admin
    note: 主体として承認済みでも、OIDC の入り口は既知にならない
oidc_subjects:
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-deploy
    repo: example-org/example-repo
    refs: ["refs/heads/main"]
    environments: ["production"]
    note: 本番のデプロイ
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-nightly
    repo: example-org/example-repo
    refs: ["refs/heads/main"]
    hours: ["18:00-19:00"]
    source_ips: ["203.0.113.0/24"]
    note: 夜間の定期実行
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-old
    repo: example-org/example-repo
    refs: ["refs/heads/main"]
    note: 期限切れ
    expires: 2026-09-30
  - provider: oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789
    role: arn:aws:iam::123456789012:role/app-irsa
    note: クラスタのサービスアカウント
`

type oidcSeed struct {
	t  *testing.T
	st *store.Dir
	n  int
}

// gh は GitHub の sub を読めた引き受けを 1 件入れる。sub は正規化した形 (repo:…)。
func (s *oidcSeed) gh(at time.Time, role, sub, ip, code string, extra ...string) {
	s.t.Helper()
	g, ok := record.ParseGitHubSub(sub)
	d := map[string]any{"oidc_provider": oidcGH, "oidc_provider_account": "123456789012", "role_arn": role, "oidc_sub_form": record.OIDCSubUnparsed}
	if ok {
		d["oidc_sub_form"], d["oidc_repo"], d["oidc_sub_kind"] = record.OIDCSubGitHub, g.Repo, g.Kind
		for k, v := range map[string]string{"oidc_ref": g.Ref, "oidc_environment": g.Environment, "oidc_owner_id": g.OwnerID, "oidc_repo_id": g.RepoID} {
			if v != "" {
				d[k] = v
			}
		}
	}
	for i := 0; i+1 < len(extra); i += 2 {
		d[extra[i]] = extra[i+1]
	}
	s.put(at, ip, code, d)
}

func (s *oidcSeed) other(at time.Time, provider, role, ip string) {
	s.put(at, ip, "", map[string]any{"oidc_provider": provider, "role_arn": role, "oidc_sub_form": record.OIDCSubNotRead})
}

func (s *oidcSeed) put(at time.Time, ip, code string, d map[string]any) {
	s.t.Helper()
	s.n++
	e := record.TrailEvent{EventID: fmt.Sprintf("oidc-%d", s.n), Time: at, Source: "trail", Name: "AssumeRoleWithWebIdentity", EventSource: "sts.amazonaws.com",
		PrincipalKind: record.PrincipalAssumedRole, IP: ip, ErrorCode: code, Data: d, ReadOnly: true}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

func oidcCheck() OIDCAssumeRole { return OIDCAssumeRole{Config: config.DefaultChecks().OIDCAssumeRole} }

func oidcEval(t *testing.T, st *store.Dir, w collect.Window, yaml string) map[string]Observation {
	t.Helper()
	al, err := allowlist.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := oidcCheck().Evaluate(context.Background(), st, w, al)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Observation{}
	for _, o := range obs {
		if o.Check != "oidc_assume_role" {
			t.Fatalf("check: %q", o.Check)
		}
		by[o.Key] = o
	}
	return by
}

func TestOIDCAssumeRole(t *testing.T) {
	st := newStore(t)
	s := &oidcSeed{t: t, st: st}
	at := func(h, m int) time.Time { return time.Date(2026, 10, 20, h, m, 0, 0, time.UTC) }
	const main = "repo:example-org/example-repo:ref:refs/heads/main"
	// 既知の組 (ID 入りの形も同じ組)。報告しない
	s.gh(at(10, 0), oidcDeploy, main, "203.0.113.5", "", "gha_run_id", "111")
	s.gh(at(11, 0), oidcDeploy, "repo:example-org@1234567/example-repo@7654321:ref:refs/heads/main", "203.0.113.6", "")
	s.gh(at(12, 0), oidcDeploy, "repo:example-org/example-repo:environment:production", "203.0.113.7", "")
	s.other(at(12, 30), oidcEKS, oidcIRSA, "198.51.100.9")
	// 既知のロールに、知らないブランチ・リポジトリ・environment・pull_request・読めない sub・別のプロバイダ → high
	s.gh(at(13, 0), oidcDeploy, "repo:example-org/example-repo:ref:refs/heads/feature", "203.0.113.8", "", "gha_run_id", "222")
	s.gh(at(13, 5), oidcDeploy, "repo:example-org@1234567/example-repo@7654321:ref:refs/heads/feature", "203.0.113.9", "", "gha_run_id", "333")
	s.gh(at(13, 10), oidcDeploy, "repo:example-org/other-repo:ref:refs/heads/main", "203.0.113.8", "")
	s.gh(at(13, 20), oidcDeploy, "repo:example-org/example-repo:environment:staging", "203.0.113.8", "")
	s.gh(at(13, 30), oidcDeploy, "repo:example-org/example-repo:pull_request", "203.0.113.8", "")
	s.gh(at(13, 40), oidcDeploy, "", "203.0.113.8", "")
	s.other(at(13, 50), "cognito-identity.amazonaws.com", oidcDeploy, "198.51.100.9")
	// どの項目にも無いロール → medium (principals で承認済みでも)
	s.gh(at(14, 0), oidcAdmin, main, "203.0.113.8", "")
	s.other(at(14, 10), "cognito-identity.amazonaws.com", "arn:aws:iam::123456789012:role/web", "198.51.100.9")
	// 期限切れの項目 → 無いものとして扱う (ロールはほかの期限内の項目に無いので medium)
	s.gh(at(14, 20), "arn:aws:iam::123456789012:role/gha-old", main, "203.0.113.8", "")
	// 全部失敗 (信頼ポリシーが止めた) → low
	s.gh(at(14, 30), oidcDeploy, "repo:mallory/fork:ref:refs/heads/main", "198.51.100.66", "AccessDenied")
	s.gh(at(14, 31), oidcDeploy, "repo:mallory/fork:ref:refs/heads/main", "198.51.100.66", "AccessDenied")
	// 既知の組だが、時間帯・送信元の外 → medium
	s.gh(at(18, 30), oidcNightly, main, "203.0.113.20", "")
	s.gh(at(20, 0), oidcNightly, main, "198.51.100.77", "")
	// 形の崩れた値 (ストアから読み戻した値を信用しない)
	s.put(at(15, 0), "203.0.113.8", "", map[string]any{"oidc_provider": oidcGH, "role_arn": "arn:aws:iam::123456789012:role/gha-deploy\n", "oidc_sub_form": "github", "oidc_repo": "a/b <!here>", "oidc_sub_kind": "ref", "oidc_ref": "refs/heads/main"})

	w := collect.Window{From: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	by := oidcEval(t, st, w, oidcAllowlist)

	type want struct {
		sev     Severity
		reasons []string
		summary string
		data    map[string]any
	}
	cases := map[string]want{
		oidcGH + "|repo:example-org/example-repo:ref:refs/heads/feature|" + oidcDeploy: {High, []string{"unknown_subject"},
			"既知のロール gha-deploy を、既知リストに無い入り口 (example-org/example-repo のブランチ・タグ refs/heads/feature) から OIDC で 2 回引き受け",
			map[string]any{"count": 2, "role_known": true, "repo": "example-org/example-repo", "sub_kind": "ref", "ref": "refs/heads/feature", "provider": oidcGH, "provider_account": "123456789012",
				"role_arn": oidcDeploy, "allowlist_status": "unknown", "owner_id": "1234567", "repo_id": "7654321", "run_ids": []string{"222", "333"}, "sub_form": "github"}},
		oidcGH + "|repo:example-org/other-repo:ref:refs/heads/main|" + oidcDeploy:                            {High, []string{"unknown_subject"}, "example-org/other-repo", nil},
		oidcGH + "|repo:example-org/example-repo:environment:staging|" + oidcDeploy:                          {High, []string{"unknown_subject"}, "example-org/example-repo の environment staging", map[string]any{"environment": "staging"}},
		oidcGH + "|repo:example-org/example-repo:pull_request|" + oidcDeploy:                                 {High, []string{"unknown_subject"}, "example-org/example-repo の pull_request", nil},
		oidcGH + "|unparsed|" + oidcDeploy:                                                                   {High, []string{"unknown_subject"}, "sub を読めない", map[string]any{"sub_form": "unparsed"}},
		"cognito-identity.amazonaws.com|-|" + oidcDeploy:                                                     {High, []string{"unknown_subject"}, "プロバイダ cognito-identity.amazonaws.com", map[string]any{"sub_form": "not_read"}},
		oidcGH + "|repo:example-org/example-repo:ref:refs/heads/main|" + oidcAdmin:                           {Medium, []string{"unknown_subject"}, "既知リストに無いロール admin を", map[string]any{"role_known": false}},
		"cognito-identity.amazonaws.com|-|arn:aws:iam::123456789012:role/web":                                {Medium, []string{"unknown_subject"}, "既知リストに無いロール web を", nil},
		oidcGH + "|repo:example-org/example-repo:ref:refs/heads/main|arn:aws:iam::123456789012:role/gha-old": {Medium, []string{"unknown_subject"}, "入り口の承認は期限切れ", map[string]any{"allowlist_status": "expired"}},
		oidcGH + "|repo:mallory/fork:ref:refs/heads/main|" + oidcDeploy:                                      {Low, []string{"unknown_subject"}, "2 回試みて全部失敗", map[string]any{"denied": true, "has_errors": true, "role_known": true}},
		oidcGH + "|repo:example-org/example-repo:ref:refs/heads/main|" + oidcNightly:                         {Medium, []string{"outside_hours", "unexpected_source"}, "既知の入り口だが、項目の時間帯の外・項目の送信元の外", map[string]any{"allowlist_status": "approved", "outside_count": 1}},
		oidcGH + "|unparsed|unparsed":                                                                        {Medium, []string{"unknown_subject"}, "ロール (読めない) を", nil},
		"known:" + oidcDeploy: {Info, nil, "既知の入り口からの OIDC の引き受け 3 回は報告していない (ロール gha-deploy、入り口 2)",
			map[string]any{"known_oidc": true, "count": 3, "subjects_total": 2,
				"subjects": []string{oidcGH + "|repo:example-org/example-repo:environment:production", oidcGH + "|repo:example-org/example-repo:ref:refs/heads/main"}}},
		"known:" + oidcIRSA:    {Info, nil, "", map[string]any{"count": 1}},
		"known:" + oidcNightly: {Info, nil, "1 回", nil},
	}
	for k, w := range cases {
		o, ok := by[k]
		if !ok {
			t.Errorf("%s: 無い", k)
			continue
		}
		if o.Severity != w.sev {
			t.Errorf("%s: severity %s, want %s", k, o.Severity, w.sev)
		}
		var reasons []string
		if v, ok := o.Data["reasons"].([]string); ok {
			reasons = v
		}
		if !reflect.DeepEqual(reasons, w.reasons) {
			t.Errorf("%s: reasons %v", k, reasons)
		}
		if !strings.Contains(o.Summary, w.summary) {
			t.Errorf("%s: summary %q", k, o.Summary)
		}
		for dk, dv := range w.data {
			if !reflect.DeepEqual(o.Data[dk], dv) {
				t.Errorf("%s: data.%s = %#v, want %#v", k, dk, o.Data[dk], dv)
			}
		}
		// 見出しと data に、形の崩れた値をそのまま出さない
		if strings.Contains(o.Summary+fmt.Sprint(o.Data), "here") || strings.ContainsAny(o.Summary, "\n<>") {
			t.Errorf("%s: ログ由来の値がそのまま出た: %q %v", k, o.Summary, o.Data)
		}
	}
	if len(by) != len(cases) {
		keys := []string{}
		for k := range by {
			keys = append(keys, k)
		}
		t.Errorf("%d 件, want %d: %q", len(by), len(cases), keys)
	}
	// Fingerprint に IP を入れない (GitHub の実行環境の IP は毎回変わる)
	for k, o := range by {
		if strings.Contains(o.Fingerprint, "203.0.113") || strings.Contains(o.Fingerprint, "198.51.100") {
			t.Errorf("%s: fingerprint に IP: %q", k, o.Fingerprint)
		}
	}

	// 既知リストが空なら、全部が「無いロール」(medium) で、info の行は出ない
	for k, o := range oidcEval(t, st, w, "") {
		if o.Severity != Medium && o.Severity != Low || strings.HasPrefix(k, "known:") {
			t.Errorf("空の既知リスト: %s %s", k, o.Severity)
		}
	}
	// 既知になったかの判定 (engine の一括解消が使う)
	al, _ := allowlist.Parse([]byte(oidcAllowlist))
	feature := by[oidcGH+"|repo:example-org/example-repo:ref:refs/heads/feature|"+oidcDeploy]
	if _, ok := KnownOIDCSubjectOf(al, feature.Key, feature.Data, w.To); ok {
		t.Error("知らないブランチが既知と判定された")
	}
	al2, _ := allowlist.Parse([]byte(strings.Replace(oidcAllowlist, `refs: ["refs/heads/main"]`, `refs: ["refs/heads/*"]`, 1)))
	if e, ok := KnownOIDCSubjectOf(al2, feature.Key, feature.Data, w.To); !ok || e.Role != oidcDeploy {
		t.Error("既知リストに足した入り口が既知と判定されない")
	}
	// 時間帯の外の finding・平常帯の行・info の行は、入り口が既知でも解消しない
	night := by[oidcGH+"|repo:example-org/example-repo:ref:refs/heads/main|"+oidcNightly]
	if _, ok := KnownOIDCSubjectOf(al, night.Key, night.Data, w.To); ok {
		t.Error("時間帯の外の finding が既知として解消される")
	}
	info := by["known:"+oidcDeploy]
	if _, ok := KnownOIDCSubjectOf(al, info.Key, info.Data, w.To); ok {
		t.Error("info の行が解消される")
	}
	if role, ok := IsKnownOIDCLine(info.Key, info.Data); !ok || role != oidcDeploy {
		t.Errorf("IsKnownOIDCLine: %q %v", role, ok)
	}
	if _, ok := IsKnownOIDCLine(feature.Key, feature.Data); ok {
		t.Error("finding を info の行と判定した")
	}
}

// 既知の組でも、その日の回数が平常帯 (その組自身の過去の日次の回数の中央値 × factor。下限 min_count) を超えたら low、大きく超えたら medium。
func TestOIDCAssumeRoleVolume(t *testing.T) {
	const main = "repo:example-org/example-repo:ref:refs/heads/main"
	const env = "repo:example-org/example-repo:environment:production"
	seed := func(t *testing.T, today, envToday int) *store.Dir {
		st := newStore(t)
		s := &oidcSeed{t: t, st: st}
		// 過去 14 日 (10-06〜10-19): main は毎日 10 回、production は毎日 1 回
		for d := 6; d <= 19; d++ {
			for i := 0; i < 10; i++ {
				s.gh(time.Date(2026, 10, d, 1, i, 0, 0, time.UTC), oidcDeploy, main, "203.0.113.5", "")
			}
			s.gh(time.Date(2026, 10, d, 2, 0, 0, 0, time.UTC), oidcDeploy, env, "203.0.113.5", "")
		}
		for i := 0; i < today; i++ {
			s.gh(time.Date(2026, 10, 20, 10, 0, i, 0, time.UTC), oidcDeploy, main, "203.0.113.5", "")
		}
		for i := 0; i < envToday; i++ {
			s.gh(time.Date(2026, 10, 20, 11, 0, i, 0, time.UTC), oidcDeploy, env, "203.0.113.5", "")
		}
		// 失敗した引き受けは回数に数えない
		for i := 0; i < 200; i++ {
			s.gh(time.Date(2026, 10, 20, 12, 0, i, 0, time.UTC), oidcDeploy, env, "203.0.113.5", "AccessDenied")
		}
		return st
	}
	w := collect.Window{From: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	vol := "volume:" + oidcGH + "|" + main + "|" + oidcDeploy
	volEnv := "volume:" + oidcGH + "|" + env + "|" + oidcDeploy
	for _, tc := range []struct {
		name            string
		today, envToday int
		covered         bool
		want            map[string]Severity
	}{
		{"平常どおり", 30, 20, true, map[string]Severity{}},                             // main: 30 = 10×3 (超えていない)。production: 20 = 下限 min_count
		{"超えた", 31, 21, true, map[string]Severity{vol: Low, volEnv: Low}},          // production は中央値 1 でも下限 20 までは鳴らさない
		{"大きく超えた", 91, 61, true, map[string]Severity{vol: Medium, volEnv: Medium}}, // 30×3 = 90、20×3 = 60 を超えた
		{"導入直後は判定しない", 500, 500, false, map[string]Severity{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := seed(t, tc.today, tc.envToday)
			if tc.covered {
				coverage(t, st, 30)
			}
			by := oidcEval(t, st, w, oidcAllowlist)
			got := map[string]Severity{}
			for k, o := range by {
				if strings.HasPrefix(k, "volume:") {
					got[k] = o.Severity
				} else if k != "known:"+oidcDeploy {
					t.Errorf("余分な観測: %s", k)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if o, ok := by[vol]; ok {
				d := o.Data
				if d["date"] != "2026-10-20" || d["count"] != float64(tc.today) || d["baseline_median"] != float64(10) || d["threshold"] != float64(30) ||
					!reflect.DeepEqual(d["reasons"], []string{"above_baseline"}) || d["role_arn"] != oidcDeploy || d["repo"] != "example-org/example-repo" {
					t.Errorf("data: %v", d)
				}
				if !strings.Contains(o.Summary, fmt.Sprintf("2026-10-20 に %d 回", tc.today)) || !strings.Contains(o.Summary, "ふだんは 1 日 10 回") {
					t.Errorf("summary: %q", o.Summary)
				}
			}
		})
	}
	// 既知リストに無い組は平常帯を見ない (知らない組として出ている)
	st := seed(t, 500, 0)
	coverage(t, st, 30)
	for k := range oidcEval(t, st, w, "") {
		if strings.HasPrefix(k, "volume:") {
			t.Errorf("既知でない組に平常帯の行: %s", k)
		}
	}
}

// OIDC の引き受けを出すのは oidc_assume_role だけ (unknown_assume_role は名前で外す。ADR 0055)。
func TestUnknownAssumeRoleSkipsWebIdentity(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	// 主体の ARN が入っていても (将来、記録の形が変わっても) 対象にしない
	for i, arn := range []string{"", "arn:aws:iam::123456789012:role/gha-deploy"} {
		e := record.TrailEvent{EventID: fmt.Sprintf("w%d", i), Time: now.Add(-time.Hour), Source: "trail", Name: "AssumeRoleWithWebIdentity", EventSource: "sts.amazonaws.com",
			PrincipalARN: arn, PrincipalKind: record.PrincipalAssumedRole, IP: "203.0.113.5", Data: map[string]any{"role_arn": oidcDeploy, "recipient_account": "123456789012"}, ReadOnly: true}
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	obs, err := UnknownAssumeRole{}.Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, &allowlist.List{})
	if err != nil || len(obs) != 0 {
		t.Fatalf("%+v %v", obs, err)
	}
}

// ファズテスト (ADR 0041・0055)。イベントの data はストアから読み戻した値 (元はログ由来)。守る規則:
//   - パニックしない。組の各部分は決まった形か、まとめた値 (unparsed / -)。見出しの表記に改行・制御文字・`<` `>` を出さない
//   - GitHub 以外・読めない sub の組は、リポジトリの値を持たない
//   - 既知になるのは、既知リストに書いたプロバイダ・ロール・リポジトリ・入り口に一致するときだけ。data の値で既知の範囲を広げられない
func FuzzOIDCTuple(f *testing.F) {
	for _, s := range [][6]string{
		{oidcGH, oidcDeploy, "github", "example-org/example-repo", "ref", "refs/heads/main"},
		{oidcGH, oidcDeploy, "github", "example-org/example-repo", "environment", "production"},
		{oidcGH, oidcDeploy, "github", "Example-Org/Example-Repo", "ref", "refs/heads/feature"},
		{oidcGH, oidcDeploy, "github", "example-org/example-repo", "pull_request", ""},
		{oidcGH, oidcDeploy, "unparsed", "", "", ""}, {oidcEKS, oidcIRSA, "not_read", "", "", ""},
		{oidcGH, oidcDeploy + "\n", "github", "example-org/example-repo <!here>", "ref", "refs/heads/main"},
		{"x <!here>", "arn:aws:iam::123456789012:role/*", "github", "example-org/*", "ref", "*"},
		{oidcGH, oidcDeploy, "github", "example-org/example-repo", "ref", "refs/heads/main:environment:production"}, {"", "", "", "", "", ""},
	} {
		f.Add(s[0], s[1], s[2], s[3], s[4], s[5])
	}
	al, err := allowlist.Parse([]byte(oidcAllowlist))
	if err != nil {
		f.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, provider, role, form, repo, kind, value string) {
		data := map[string]any{"oidc_provider": provider, "role_arn": role, "oidc_sub_form": form, "oidc_repo": repo, "oidc_sub_kind": kind, "oidc_ref": value}
		if kind == record.OIDCKindEnvironment {
			delete(data, "oidc_ref")
			data["oidc_environment"] = value
		}
		tu := oidcTupleOf(data)
		if tu.provider != oidcUnparsed && (!record.ValidOIDCProvider(tu.provider) || tu.provider != provider) {
			t.Fatalf("プロバイダ: %q", tu.provider)
		}
		if tu.role != oidcUnparsed && (tu.role != role || !strings.HasPrefix(role, "arn:aws") || strings.ContainsAny(role, "*?\n ")) {
			t.Fatalf("ロール: %q", tu.role)
		}
		switch tu.form {
		case record.OIDCSubGitHub:
			if tu.provider != record.GitHubOIDCProvider || tu.sub != tu.gh.Normalized() || tu.gh.Repo != repo || !record.ValidGitHubRepo(repo) {
				t.Fatalf("GitHub の組: %+v", tu)
			}
		case record.OIDCSubUnparsed:
			if tu.provider != record.GitHubOIDCProvider || tu.sub != oidcUnparsed || tu.gh != (record.GitHubSub{}) {
				t.Fatalf("読めない sub の組: %+v", tu)
			}
		case record.OIDCSubNotRead:
			if tu.provider == record.GitHubOIDCProvider || tu.sub != oidcNoSub || tu.gh != (record.GitHubSub{}) {
				t.Fatalf("GitHub 以外の組: %+v", tu)
			}
		default:
			t.Fatalf("sub の形: %q", tu.form)
		}
		for _, s := range []string{tu.key(), tu.entrance(), tu.roleLabel, oidcUnknownSummary(tu, true, false, true, 1)} {
			if strings.ContainsAny(s, "\n\r\t<>\x00") {
				t.Fatalf("表記に出してはいけない文字: %q", s)
			}
		}
		entries, st := al.OIDCSubject(tu.assume(), at)
		if (len(entries) == 0) != (st == allowlist.StatusUnknown) {
			t.Fatalf("状態と項目が合わない: %s %d", st, len(entries))
		}
		if st == allowlist.StatusApproved {
			switch {
			case role == oidcDeploy && provider == oidcGH:
				if !strings.EqualFold(repo, "example-org/example-repo") || !(kind == "ref" && value == "refs/heads/main" || kind == "environment" && value == "production") {
					t.Fatalf("書いていない入り口を既知にした: %v", data)
				}
			case role == oidcNightly && provider == oidcGH:
				if !strings.EqualFold(repo, "example-org/example-repo") || kind != "ref" || value != "refs/heads/main" {
					t.Fatalf("書いていない入り口を既知にした: %v", data)
				}
			case role == oidcIRSA && provider == oidcEKS:
			default:
				t.Fatalf("書いていないロール・プロバイダを既知にした: %v", data)
			}
		}
		// finding の data からの判定 (engine の解消) も同じ規則: 既知でない組は解消しない
		d := map[string]any{"reasons": []any{reasonUnknownSubject}}
		tu.data(d)
		if _, ok := KnownOIDCSubjectOf(al, tu.key(), d, at); ok != (st == allowlist.StatusApproved) {
			t.Fatalf("finding の data からの判定が食い違う: %v (%s)", ok, st)
		}
	})
}
