package allowlist

import (
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
		l.SecretExpected(outsider, "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:prod/db-AbCdEf")
		l.HasExpectedDenied()
		for _, ip := range []string{"203.0.113.7", "::1", "x", ""} {
			if l.SourceIPAllowed(ip) && len(l.SourceIPs) == 0 {
				t.Fatalf("source_ips が無いのに %q を許可した", ip)
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
