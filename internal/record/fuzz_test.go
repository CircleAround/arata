package record

import (
	"strings"
	"testing"
)

// ファズテスト (ADR 0040)。伏せ字はレポートと通知に個人を特定できる値を出さないための最後の守り (ADR 0037)。
// 架空のメールアドレス・セッション名を任意の文字列の間に置き、出力に元の形で残らないことを確かめる。
func FuzzMask(f *testing.F) {
	for _, s := range [][2]string{{"", ""}, {"user ", " logged in"}, {"/mail/", "/inbox?x=1"}, {"a@b.", ".c"}, {"x%40y.", "@z.io"}, {"q@", "%40"},
		{"arn:aws:sts::123456789012:assumed-role/", "/x"}, {"assumed-role/r/", ","}, {"\xff", "\xfe"}, {"<email>", "<session>"}} {
		f.Add(s[0], s[1])
	}
	const (
		email   = "alice@example.com"
		encoded = "alice%40example.com"
		session = "alice-session"
		arn     = "arn:aws:sts::123456789012:assumed-role/audit-role/" + session
	)
	f.Fuzz(func(t *testing.T, pre, post string) {
		for _, in := range []string{pre + email + post, pre + encoded + post, pre + post} {
			out := MaskEmail(in)
			if strings.Contains(out, email) || strings.Contains(out, encoded) {
				t.Fatalf("MaskEmail(%q) = %q: メールアドレスが残った", in, out)
			}
			if emailRe.MatchString(out) || encodedEmailRe.MatchString(out) {
				t.Fatalf("MaskEmail(%q) = %q: メールアドレスの形が残った", in, out)
			}
			if again := MaskEmail(out); again != out {
				t.Fatalf("MaskEmail が冪等でない: %q → %q → %q", in, out, again)
			}
		}
		for _, in := range []string{pre + arn + post, pre + arn + " " + email + post, pre + post} {
			out := MaskIdentity(in)
			if strings.Contains(out, "/audit-role/"+session) || strings.Contains(out, email) {
				t.Fatalf("MaskIdentity(%q) = %q: セッション名かメールアドレスが残った", in, out)
			}
			if emailRe.MatchString(out) || encodedEmailRe.MatchString(out) {
				t.Fatalf("MaskIdentity(%q) = %q: メールアドレスの形が残った", in, out)
			}
			if again := MaskIdentity(out); again != out {
				t.Fatalf("MaskIdentity が冪等でない: %q → %q → %q", in, out, again)
			}
		}
	})
}
