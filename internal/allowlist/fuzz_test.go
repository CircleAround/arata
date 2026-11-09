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
