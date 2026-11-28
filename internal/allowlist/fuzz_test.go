package allowlist

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ファズテスト (ADR 0041)。allowlist.yaml は利用者が書くファイル。壊れた YAML でもパニックせず、
// 読めたものは「誰を承認するか」の規則 (主体の指定は 1 つだけ・arn_pattern はアカウントを固定。ADR 0037) を守る。
func FuzzParse(f *testing.F) {
	b, err := os.ReadFile("../../examples/allowlist.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	for _, s := range []string{
		"principals:\n  - arn_pattern: \"arn:*\"\n",
		"principals:\n  - arn_pattern: arn:aws:iam::*:role/x\n",
		"principals:\n  - arn_pattern: arn:aws:iam::123456789012:role/ci-*\n    expires: 2026-12-31\n    expected_denied: [\"logs:Get*\"]\n    note: n\n",
		"principals:\n  - account: \"111122223333\"\n  - arn: arn:aws:iam::123456789012:user/alice\n    account: \"123456789012\"\n",
		"principals:\n  - arn: x\n    expected_denied: []\n",
		"principals: [{arn: a, expires: 2026-13-01}]\n",
		"source_ips:\n  - cidr: 203.0.113.0/24\n  - cidr: ::/0\n",
		"secrets_access:\n  - principal: arn:aws:iam::123456789012:role/app\n    secrets: [\"prod/*\", \"[\", \"\\xff\"]\n",
		"principals: &a [*a]\n", "unknown: 1\n", "principals: 1\n", "- x\n", "\t", "",
		"assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    expires: 2026-12-31\n  - account: \"111122223333\"\n    roles: [\"ops-*\", \"a/b\"]\n    note: n\n",
		"assume_destinations:\n  - account: \"*\"\n    note: n\n", "assume_destinations:\n  - account: \"111122223333\"\n    roles: [\"*\"]\n",
		"assume_destinations: [{account: 111122223333, note: n, roles: [\"arn:aws:iam::999999999999:role/x\"]}]\n", "assume_destinations: &d [*d]\n",
		"principals:\n  - account: \"111122223333\"\nassume_destinations:\n  - account: \"123456789012\"\n    note: n\n    roles: [\"\\xff\"]\n",
		oidcYAML,
		"oidc_subjects:\n  - provider: token.actions.githubusercontent.com\n    role: arn:aws:iam::123456789012:role/*\n    repo: example-org/*\n    refs: [\"*\"]\n    note: n\n",
		"oidc_subjects:\n  - provider: token.actions.githubusercontent.com\n    role: arn:aws:iam::123456789012:role/x\n    repo: example-org/example-repo\n    note: n\n",
		"oidc_subjects:\n  - provider: cognito-identity.amazonaws.com\n    role: arn:aws:iam::123456789012:role/x\n    note: n\n    hours: [\"23:30-00:30\", \"\\xff\"]\n    source_ips: [\"::/0\"]\n",
		"secrets_access:\n  - principal: arn:aws:iam::123456789012:role/app\n    secrets: [\"/example-app/prod/*\", \"prod/*\"]\n    bulk: exempt\n    note: n\n",
		"secrets_access:\n  - principal: arn:aws:iam::123456789012:role/app\n    secrets: [\"/example-app/prod/*\", \"x\"]\n    bulk: exempt\n    note: n\n",
		"secrets_access:\n  - principal: arn:aws:iam::123456789012:user/alice\n    secrets: [\"/a/b/*\"]\n    bulk: exempt\n    note: n\n",
		"secrets_access: [{principal: x, secrets: [\"*\"], bulk: \"\"}]\n",
		"secrets_access:\n  - principal_pattern: arn:aws:iam::123456789012:role/example-app-prod-AppTaskDefExecutionRole1A2B3C4D-*\n    secrets: [\"/example-app/prod/secrets/*\"]\n    bulk: exempt\n    note: n\n",
		"secrets_access:\n  - principal_pattern: arn:aws:iam::123456789012:role/example-app-*\n    principal: arn:aws:iam::123456789012:role/x\n    secrets: [\"*\"]\n",
		"secrets_access:\n  - principal_pattern: arn:aws:iam::999999999999:role/a-fuzz-*\n    secrets: [\"*\"]\n  - principal_pattern: \"arn:aws:iam::123456789012:role/a/b-c-*\"\n    secrets: [\"x\"]\n",
		"shared_sources:\n  - cidr: 198.51.100.0/24\n    note: n\n    expires: 2026-11-08\n  - cidr: ::ffff:0.0.0.0/96\n    note: n\nsource_ips:\n  - cidr: 198.51.100.0/25\n",
		"shared_sources: [{cidr: 2001:db8::/48, note: n}, {cidr: 0.0.0.0/0, note: \" \"}]\n", "shared_sources: &s [*s]\n",
		"oidc_subjects: &o [*o]\n", "principals:\n  - arn: arn:aws:iam::123456789012:role/gha-deploy\n    tags: [deploy]\noidc_subjects: []\n",
	} {
		f.Add([]byte(s))
	}
	const (
		// どの seed にも書いていない架空の 3 つ目のアカウント
		outsider = "arn:aws:iam::999999999999:role/fuzz-outsider"
		acct     = "999999999999"
	)
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := Parse(b)
		if err != nil {
			if l != nil {
				t.Fatal("エラーなのに List を返した")
			}
			return
		}
		for i := range l.Principals {
			e := &l.Principals[i]
			n := 0
			for _, v := range []string{e.ARN, e.Account, e.ARNPattern} {
				if v != "" {
					n++
				}
			}
			if n != 1 || e.Subject() == "" {
				t.Fatalf("principals[%d]: 主体の指定が %d 個: %+v", i, n, e)
			}
			if e.ARNPattern != "" && (e.pattern == nil || !accountRe.MatchString(AccountOf(e.ARNPattern))) {
				t.Fatalf("principals[%d]: アカウントを固定していない arn_pattern を受け入れた: %q", i, e.ARNPattern)
			}
			if len(e.ExpectedDenied) != len(e.denied) || (e.ExpectedDenied != nil && strings.TrimSpace(e.Note) == "") {
				t.Fatalf("principals[%d]: expected_denied の検証が抜けた: %+v", i, e)
			}
			e.HasTag("deploy")
		}
		// 書いていないアカウントの主体は承認されない (広すぎるパターンで全部を止めさせない)
		if e, st := l.Principal(outsider, at); st != StatusUnknown {
			if e == nil || !(e.ARN == outsider || e.Account == acct || AccountOf(e.ARNPattern) == acct) {
				t.Fatalf("書いていないアカウントの主体が %s になった: %+v", st, e)
			}
		}
		if l.DeniedExpected(outsider, "logs:StartQuery", at) {
			if e, st := l.Principal(outsider, at); st == StatusUnknown || e == nil {
				t.Fatal("承認していない主体の拒否を想定済みとした")
			}
		}
		// 行き先 (assume_destinations。ADR 0047): アカウントは 12 桁の数字だけ (glob やパターンでアカウントを広げられない)、note は必須、
		// roles は決まった文字だけで、照合に使う正規表現が項目の数だけある
		for i := range l.AssumeDestinations {
			e := &l.AssumeDestinations[i]
			if !accountRe.MatchString(e.Account) || strings.TrimSpace(e.Note) == "" || len(e.roles) != len(e.Roles) || (e.Roles != nil && len(e.Roles) == 0) {
				t.Fatalf("assume_destinations[%d]: 検証が抜けた: %+v", i, e)
			}
			for _, g := range e.Roles {
				if CheckDestinationRole(g) != nil || strings.ContainsAny(g, ": \t\n") {
					t.Fatalf("assume_destinations[%d]: roles に書けない値を受け入れた: %q", i, g)
				}
			}
			// 書いたアカウントは、期限が無ければ (どのロールかはともかく) 行き先として既知になる。別のアカウントは既知にしない
			if e.Expires == "" && !l.HasAssumeDestination(e.Account, at) {
				t.Fatalf("assume_destinations[%d]: 期限の無い項目が既知にならない", i)
			}
		}
		// 書いていないアカウントは、行き先として既知にならない。principals に書いたアカウントも (呼び出し元の承認は行き先を既知にしない)
		if de, st := l.AssumeDestination(acct, "fuzz-outsider", at); st != StatusUnknown || l.HasAssumeDestination(acct, at) {
			if de == nil || de.Account != acct {
				t.Fatalf("書いていないアカウントが行き先として %s になった: %+v", st, de)
			}
		}
		for i := range l.Principals {
			a := l.Principals[i].Account
			if a == "" {
				continue
			}
			listed := false
			for j := range l.AssumeDestinations {
				listed = listed || l.AssumeDestinations[j].Account == a
			}
			if _, st := l.AssumeDestination(a, "x", at); st != StatusUnknown && !listed {
				t.Fatalf("principals の account: %s が行き先として %s になった", a, st)
			}
		}
		// 逆も同じ: 行き先に書いたアカウントの主体は、principals に無ければ承認されない
		for i := range l.AssumeDestinations {
			arn := "arn:aws:iam::" + l.AssumeDestinations[i].Account + ":role/fuzz-destination"
			if e, st := l.Principal(arn, at); st != StatusUnknown && e == nil {
				t.Fatalf("行き先のアカウントの主体が %s になった", st)
			}
			if _, st := l.Principal(arn, at); st != StatusUnknown && len(l.Principals) == 0 {
				t.Fatalf("principals が空なのに、行き先のアカウントの主体が %s になった", st)
			}
		}
		// OIDC の入り口 (oidc_subjects。ADR 0055): プロバイダは名前 (ARN でない)、ロールは glob の無い ARN、note は必須。
		// GitHub の項目はリポジトリ (glob なし) と、refs / environments / pull_request のどれかを必ず持つ。GitHub 以外は持たない
		const gh = "token.actions.githubusercontent.com"
		for i := range l.OIDCSubjects {
			e := &l.OIDCSubjects[i]
			if strings.HasPrefix(e.Provider, "arn:") || !oidcRoleRe.MatchString(e.Role) || strings.ContainsAny(e.Role+e.Repo, "*? \t\n") || strings.TrimSpace(e.Note) == "" ||
				len(e.refs) != len(e.Refs) || len(e.hours) != len(e.Hours) || len(e.nets) != len(e.SourceIPs) {
				t.Fatalf("oidc_subjects[%d]: 検証が抜けた: %+v", i, e)
			}
			entry := len(e.Refs) > 0 || len(e.Environments) > 0 || e.PullRequest
			if (e.Provider == gh) != entry || (e.Provider == gh) != (e.Repo != "") {
				t.Fatalf("oidc_subjects[%d]: 入り口の書き方が規則に合わない: %+v", i, e)
			}
			// 既知のロールでも、書いていないリポジトリからの引き受けは既知にならない
			never := OIDCAssume{Provider: e.Provider, Role: e.Role, Repo: "fuzz-org/never-written", Kind: "ref", Ref: "refs/heads/main"}
			if es, st := l.OIDCSubject(never, at); st != StatusUnknown && e.Provider == gh {
				for _, x := range es {
					if !strings.EqualFold(x.Repo, never.Repo) {
						t.Fatalf("書いていないリポジトリからの引き受けが %s になった: %+v", st, x)
					}
				}
			}
			// 読めない sub (リポジトリが空) は、GitHub の項目では既知にならない
			if _, st := l.OIDCSubject(OIDCAssume{Provider: gh, Role: e.Role}, at); st != StatusUnknown {
				t.Fatalf("読めない sub の引き受けが %s になった", st)
			}
		}
		// 書いていないロールへの引き受けは既知にならない。principals での承認 (ロールを主体として承認) も入り口を既知にしない
		out := OIDCAssume{Provider: gh, Role: outsider, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}
		if es, st := l.OIDCSubject(out, at); st != StatusUnknown || l.OIDCRoleKnown(outsider, at) {
			found := false
			for i := range l.OIDCSubjects {
				found = found || l.OIDCSubjects[i].Role == outsider
			}
			if !found {
				t.Fatalf("書いていないロールが %s になった: %+v", st, es)
			}
		}
		if len(l.OIDCSubjects) == 0 {
			for i := range l.Principals {
				a := OIDCAssume{Provider: gh, Role: l.Principals[i].ARN, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}
				if _, st := l.OIDCSubject(a, at); st != StatusUnknown || l.OIDCRoleKnown(a.Role, at) {
					t.Fatalf("principals の承認が OIDC の入り口を既知にした: %s", a.Role)
				}
			}
		}
		// bulk: exempt (ADR 0073): 値は空か exempt だけ。exempt の項目は note・ロールの主体・狭い glob を必ず持ち、
		// 一致する名前は glob の固定の部分 (区切り 2 つ以上) で始まる。書いていない主体の秘匿値は外さない
		for i := range l.SecretsAccess {
			e := &l.SecretsAccess[i]
			if e.Bulk != "" && e.Bulk != BulkExempt {
				t.Fatalf("secrets_access[%d]: bulk に書けない値を受け入れた: %q", i, e.Bulk)
			}
			// principal_pattern (ADR 0079): 主体は principal と排他。読めた pattern は必ず CheckPrincipalPattern の形
			if (e.Principal == "") == (e.PrincipalPattern == "") {
				t.Fatalf("secrets_access[%d]: principal と principal_pattern の排他が抜けた: %+v", i, e)
			}
			subject := e.Principal
			if e.PrincipalPattern != "" {
				if err := CheckPrincipalPattern(e.PrincipalPattern); err != nil {
					t.Fatalf("secrets_access[%d]: 書けない principal_pattern を受け入れた: %v", i, err)
				}
				subject = strings.TrimSuffix(e.PrincipalPattern, "*") + "Ab1"
				for _, bad := range []string{"", "-x", "/x", ":x", "_x", "x y"} {
					if MatchPrincipalPattern(e.PrincipalPattern, strings.TrimSuffix(e.PrincipalPattern, "*")+bad) {
						t.Fatalf("secrets_access[%d]: %q が英数字でない乱数 %q に一致した", i, e.PrincipalPattern, bad)
					}
				}
				if !MatchPrincipalPattern(e.PrincipalPattern, subject) {
					t.Fatalf("secrets_access[%d]: %q が乱数の形の %q に一致しない", i, e.PrincipalPattern, subject)
				}
			}
			if e.Bulk != BulkExempt {
				continue
			}
			if strings.TrimSpace(e.Note) == "" || !strings.Contains(subject, ":role/") || !strings.HasPrefix(subject, "arn:") {
				t.Fatalf("secrets_access[%d]: bulk: exempt の検証が抜けた: %+v", i, e)
			}
			for _, g := range e.Secrets {
				if CheckBulkExemptPattern(g) != nil {
					t.Fatalf("secrets_access[%d]: 広すぎる glob を受け入れた: %q", i, g)
				}
				fixed := g
				if k := strings.IndexAny(g, "*?"); k >= 0 {
					fixed = g[:k]
				}
				for _, c := range []string{"x", "/x", "/x/y", "x/y/z", "/", ""} {
					if p, ok := l.SecretBulkExempt(subject, c); ok && p == g && !strings.HasPrefix(c, fixed) {
						t.Fatalf("secrets_access[%d]: %q が固定の部分の外の %q に当たった", i, g, c)
					}
				}
			}
		}
		if _, ok := l.SecretBulkExempt(outsider, "/example-app/prod/secrets/X"); ok {
			found := false
			for i := range l.SecretsAccess {
				found = found || l.SecretsAccess[i].Principal == outsider || MatchPrincipalPattern(l.SecretsAccess[i].PrincipalPattern, outsider)
			}
			if !found {
				t.Fatal("書いていない主体の秘匿値を一括読み出しの数から外した")
			}
		}
		l.SecretExpected(outsider, "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:prod/db-AbCdEf")
		l.HasExpectedDenied()
		for _, ip := range []string{"203.0.113.7", "::1", "x", ""} {
			if l.SourceIPAllowed(ip) && len(l.SourceIPs) == 0 {
				t.Fatalf("source_ips が無いのに %q を許可した", ip)
			}
		}
		// shared_sources (ADR 0094 の 1 節): note は必須。当たるのは、期限内で、その IP を含み、source_ips に無い IP だけ
		for i := range l.SharedSources {
			if strings.TrimSpace(l.SharedSources[i].Note) == "" || l.SharedSources[i].net == nil {
				t.Fatalf("shared_sources[%d]: note か範囲の無い項目を受け付けた", i)
			}
		}
		for _, ip := range []string{"198.51.100.7", "203.0.113.7", "2001:db8::1", "::ffff:198.51.100.7", "x", ""} {
			e, ok := l.SharedSource(ip, at)
			if !ok {
				continue
			}
			if l.SourceIPAllowed(ip) || !e.active(at) || !e.net.Contains(net.ParseIP(ip)) {
				t.Fatalf("%q に当たってはいけない項目 %+v が当たった", ip, e)
			}
		}
	})
}

func FuzzMatchPattern(f *testing.F) {
	for _, s := range [][2]string{{"arn:aws:iam::123456789012:role/ci-*", "arn:aws:iam::123456789012:role/ci-deploy"}, {"a?c", "abc"}, {"*", ""}, {"a.b", "aXb"}, {"[a-z]+(", "x"}, {"\xff*", "\xff\xfe"}, {"a\\*", "a\\b"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, s string) {
		ok, err := MatchPattern(pattern, s)
		if err != nil {
			return
		}
		// UTF-8 として不正なパターンは拒否する (不正なバイト列どうしが同じものとして一致してしまう)
		if !utf8.ValidString(pattern) {
			t.Fatalf("MatchPattern(%q) が不正な UTF-8 のパターンを受け入れた", pattern)
		}
		// 照合する値 (ARN・API 名・秘匿値の名前) は JSON から読むので、不正な UTF-8 にはならない
		if !utf8.ValidString(s) {
			return
		}
		// glob の特別な文字は * と ? だけ。それ以外は文字どおり (正規表現として働かない)
		if !strings.ContainsAny(pattern, "*?") && ok != (pattern == s) {
			t.Fatalf("MatchPattern(%q, %q) = %v: 文字どおりの一致でない", pattern, s, ok)
		}
		if self, err := MatchPattern(pattern, pattern); err == nil && !self && !strings.Contains(pattern, "?") {
			t.Fatalf("MatchPattern(%q) が自分自身に一致しない", pattern)
		}
		CheckDeniedGlob(pattern)
		AccountOf(s)
	})
}

// principal_pattern の形と照合 (ADR 0079。照合の相手はログ由来の主体の ARN)。守る規則:
//   - CheckPrincipalPattern を通った値は、arn:<パーティション>:iam::<12 桁>:role/ で始まり、ワイルドカードは末尾の -* の 1 つだけ
//   - 一致したなら、ARN は固定の部分 (末尾の * の前) で始まり、残りは英数字 (ASCII) の 1 文字以上だけ (/・:・- を含まない)
//   - 一致したなら、ARN のアカウントは pattern のアカウントと同じ
//   - CheckPrincipalPattern を通らない値は何にも一致しない
func FuzzPrincipalPattern(f *testing.F) {
	for _, s := range [][2]string{
		{"arn:aws:iam::123456789012:role/example-app-prod-AppTaskDefExecutionRole1A2B3C4D-*", "arn:aws:iam::123456789012:role/example-app-prod-AppTaskDefExecutionRole1A2B3C4D-AbcDef123Ghi"},
		{"arn:aws:iam::123456789012:role/example-app-*", "arn:aws:iam::123456789012:role/example-app-x/evil"},
		{"arn:aws:iam::123456789012:role/example-app-*", "arn:aws:iam::123456789012:role/example-app-a-b"},
		{"arn:aws:iam::123456789012:role/*", "arn:aws:iam::123456789012:role/x"},
		{"arn:aws:iam::123456789012:role/a/b-c-*", "arn:aws:iam::123456789012:role/a/b-c-\xff"},
		{"arn:aws:iam::123456789012:role/a-b-*", "arn:aws:iam::123456789012:role/a-b-Ａ"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, arn string) {
		ok := MatchPrincipalPattern(pattern, arn)
		if err := CheckPrincipalPattern(pattern); err != nil {
			if ok {
				t.Fatalf("書けない %q が %q に一致した", pattern, arn)
			}
			return
		}
		if !strings.HasPrefix(pattern, "arn:") || !strings.Contains(pattern, ":iam::") || !strings.Contains(pattern, ":role/") ||
			!strings.HasSuffix(pattern, "-*") || strings.Count(pattern, "*") != 1 || strings.Contains(pattern, "?") || !accountRe.MatchString(AccountOf(pattern)) {
			t.Fatalf("CheckPrincipalPattern が %q を受け入れた", pattern)
		}
		if !ok {
			return
		}
		fixed := strings.TrimSuffix(pattern, "*")
		rest, has := strings.CutPrefix(arn, fixed)
		if !has || rest == "" {
			t.Fatalf("%q が固定の部分の外の %q に一致した", pattern, arn)
		}
		for _, r := range rest {
			if !('A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9') {
				t.Fatalf("%q が英数字でない乱数の %q に一致した", pattern, arn)
			}
		}
		if AccountOf(arn) != AccountOf(pattern) {
			t.Fatalf("%q がアカウントの違う %q に一致した", pattern, arn)
		}
	})
}

// approve --destination が既知リストに書く行き先 (ADR 0047)。アカウントは finding の data (ログ由来の値)、ロールと note は人の入力。守る規則:
//   - 書けたなら、結果は Parse でき、assume_destinations がちょうど 1 件増え、その項目のアカウントは渡した 12 桁の数字そのもの
//   - principals・source_ips・secrets_access の件数は変わらない (ほかの節に項目を足せない。YAML の記法を埋め込めない)
//   - 元のテキストの行は、順序も中身もそのまま残る
//   - 12 桁の数字でないアカウント・空の note は書かない
func FuzzAppendDestination(f *testing.F) {
	srcs := []string{
		"", "principals:\n  - arn: arn:aws:iam::123456789012:role/Deploy\n", "assume_destinations: []\n",
		"# c\nassume_destinations:\n  - account: \"444455556666\"\n    note: n\n\n# next\nsource_ips:\n  - cidr: 203.0.113.0/24\n",
		"assume_destinations:\n    - account: \"444455556666\"\n      roles: [ReadOnly]\n      note: n\nprincipals: []\n",
	}
	for i := range srcs {
		f.Add(uint8(i), "111122223333", "ReadOnly", "受託")
		f.Add(uint8(i), "111122223333\"\n  - account: \"999999999999", "", "n")
		f.Add(uint8(i), "111122223333", "x\"]\nprincipals:\n  - account: \"999999999999\"\n#", "n\nprincipals:\n  - arn: a")
		f.Add(uint8(i), "１１１１２２２２３３３３", "ops-*", " ")
		f.Add(uint8(i), "444455556666", "", "- a: b # c")
	}
	f.Fuzz(func(t *testing.T, i uint8, account, role, note string) {
		src := srcs[int(i)%len(srcs)]
		d := NewDestination{Account: account, Note: note, ApprovedBy: "alice", ApprovedAt: "2026-11-13"}
		if role != "" {
			d.Roles = []string{role}
		}
		out, added, err := AppendDestinationBytes([]byte(src), d)
		if err != nil {
			if out != nil || added != "" {
				t.Fatal("エラーなのに結果を返した")
			}
			return
		}
		if !accountRe.MatchString(account) || strings.TrimSpace(note) == "" {
			t.Fatalf("書いてはいけない値を書いた: account %q note %q", account, note)
		}
		before, _ := Parse([]byte(src))
		after, err := Parse(out)
		if err != nil {
			t.Fatalf("書いた結果が読めない: %v\n%s", err, out)
		}
		n := len(after.AssumeDestinations)
		if n != len(before.AssumeDestinations)+1 || after.AssumeDestinations[n-1].Account != account || strings.Join(after.AssumeDestinations[n-1].Roles, "\x00") != strings.Join(d.Roles, "\x00") {
			t.Fatalf("足した項目が違う: %+v\n%s", after.AssumeDestinations, out)
		}
		if len(after.Principals) != len(before.Principals) || len(after.SourceIPs) != len(before.SourceIPs) || len(after.SecretsAccess) != len(before.SecretsAccess) {
			t.Fatalf("ほかの節が変わった:\n%s", out)
		}
		rest := string(out)
		for _, line := range strings.Split(strings.TrimSuffix(src, "\n"), "\n") {
			if line == "assume_destinations: []" {
				continue // この行だけは `assume_destinations:` に書き換える
			}
			j := strings.Index(rest, line)
			if j < 0 {
				t.Fatalf("元の行が消えた・順序が変わった: %q\n%s", line, out)
			}
			rest = rest[j+len(line):]
		}
	})
}

// approve --shared が既知リストに書く人の多い送信元 (ADR 0094 の 1 節)。範囲は finding の IP (ログ由来の値) か人の入力、note は人の入力。守る規則:
//   - 書けたなら、結果は Parse でき、shared_sources がちょうど 1 件増え、その項目の cidr は渡した値そのもの (ネットワークの形)
//   - 広すぎる範囲・空の note・source_ips と重なる範囲は書かない
//   - ほかの節の件数は変わらず、元のテキストの行は順序も中身もそのまま残る
func FuzzAppendShared(f *testing.F) {
	srcs := []string{
		"", "shared_sources: []\n", "source_ips:\n  - cidr: 203.0.113.0/24\n",
		"# c\nshared_sources:\n  - cidr: 192.0.2.0/24\n    note: n\n\n# next\nprincipals: []\n",
	}
	for i := range srcs {
		f.Add(uint8(i), "198.51.100.0/24", "試験の会場")
		f.Add(uint8(i), "198.51.100.0/24\n  - cidr: 0.0.0.0/0", "n")
		f.Add(uint8(i), "203.0.113.0/28", "n\nprincipals:\n  - arn: a")
		f.Add(uint8(i), "::ffff:0.0.0.0/96", "x")
		f.Add(uint8(i), "2001:db8::/48", "- a: b # c")
	}
	f.Fuzz(func(t *testing.T, i uint8, cidr, note string) {
		src := srcs[int(i)%len(srcs)]
		out, added, err := AppendSharedBytes([]byte(src), NewSharedSource{CIDR: cidr, Note: note, ApprovedBy: "alice", ApprovedAt: "2026-11-28"})
		if err != nil {
			if out != nil || added != "" {
				t.Fatal("エラーなのに結果を返した")
			}
			return
		}
		if SharedCIDRTooBroad(cidr) || strings.TrimSpace(note) == "" {
			t.Fatalf("書いてはいけない値を書いた: cidr %q note %q", cidr, note)
		}
		before, _ := Parse([]byte(src))
		after, err := Parse(out)
		if err != nil {
			t.Fatalf("書いた結果が読めない: %v\n%s", err, out)
		}
		n := len(after.SharedSources)
		if n != len(before.SharedSources)+1 || after.SharedSources[n-1].CIDR != cidr || after.SharedSources[n-1].net.String() != cidr {
			t.Fatalf("足した項目が違う: %+v\n%s", after.SharedSources, out)
		}
		for j := range after.SourceIPs {
			if netsOverlap(after.SourceIPs[j].net, after.SharedSources[n-1].net) {
				t.Fatalf("source_ips と重なる範囲を書いた: %s", cidr)
			}
		}
		if len(after.Principals) != len(before.Principals) || len(after.SourceIPs) != len(before.SourceIPs) || len(after.AssumeDestinations) != len(before.AssumeDestinations) {
			t.Fatalf("ほかの節が変わった:\n%s", out)
		}
		rest := string(out)
		for _, line := range strings.Split(strings.TrimSuffix(src, "\n"), "\n") {
			if line == "shared_sources: []" {
				continue
			}
			j := strings.Index(rest, line)
			if j < 0 {
				t.Fatalf("元の行が消えた・順序が変わった: %q\n%s", line, out)
			}
			rest = rest[j+len(line):]
		}
	})
}
