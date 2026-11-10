package record

import (
	"strings"
	"testing"
)

// ファズテスト (ADR 0041)。伏せ字はレポートと通知に個人を特定できる値を出さないための最後の守り (ADR 0037)。
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

// serviceNameSafe は ServiceName / ServiceLinkedRole が返してよい形か: "AWS Internal" か、小文字の英数字・`.`・`-` だけの `<名前>.amazonaws.com` (64 文字まで)。
func serviceNameSafe(s string, allowInternal bool) bool {
	if s == "AWS Internal" {
		return allowInternal
	}
	if len(s) > 64 || !strings.HasSuffix(s, ".amazonaws.com") || len(s) == len(".amazonaws.com") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return s[0] != '.' && s[0] != '-'
}

// CloudTrail の sourceIPAddress・userIdentity.invokedBy・主体の ARN は、ログ由来の信用できない値。
// サービス名として見出しと data に出すのは、決まった形のものだけ (ADR 0037・0041):
//   - 受け入れた値は入力そのもので、"AWS Internal" か `<名前>.amazonaws.com` (小文字の英数字・`.`・`-`、64 文字まで)。
//     空白・改行・制御文字・Markdown や Slack の記法の文字 (`<>()[]|*_`) を含む値は受け入れない
//   - サービスリンクロールは `arn:<パーティション>:iam::<12 桁>:role/aws-service-role/<サービス名>/<ロール名>` の形だけ。
//     返すサービス名は ARN のその区間そのもので、同じ規則を満たす ("AWS Internal" は返さない)
func FuzzServiceName(f *testing.F) {
	for _, s := range []string{"sso.amazonaws.com", "AWS Internal", "", "198.51.100.7", ".amazonaws.com", "a b.amazonaws.com", "x\n.amazonaws.com", "<!here>.amazonaws.com",
		"ａ.amazonaws.com", "sso.amazonaws.com\x00", "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
		"arn:aws:iam::123456789012:role/aws-service-role/AWS Internal/x", "arn:aws:iam::123456789012:role/aws-service-role//x", "arn:aws:iam::123456789012:role/aws-service-role/a.amazonaws.com/x/y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		name, ok := ServiceName(s)
		if ok != (name != "") || (ok && (name != s || !serviceNameSafe(name, true))) {
			t.Fatalf("ServiceName(%q) = %q, %v", s, name, ok)
		}
		if !ok && serviceNameSafe(s, true) {
			t.Fatalf("ServiceName(%q): 規則どおりの名前を捨てた", s)
		}
		svc, ok := ServiceLinkedRole(s)
		if ok != (svc != "") {
			t.Fatalf("ServiceLinkedRole(%q) = %q, %v", s, svc, ok)
		}
		if ok {
			if !serviceNameSafe(svc, false) {
				t.Fatalf("ServiceLinkedRole(%q) = %q: サービス名の形でない", s, svc)
			}
			i := strings.Index(s, ":role/aws-service-role/"+svc+"/")
			if !strings.HasPrefix(s, "arn:aws") || i < 0 || strings.ContainsAny(s, " \t\r\n") || strings.Count(s[i:], "/") != 3 {
				t.Fatalf("ServiceLinkedRole(%q) = %q: サービスリンクロールの ARN の形でない", s, svc)
			}
		}
		// 形が合う ARN を任意の値から作ったときは、サービス名が規則どおりのときだけ受け入れる
		arn := "arn:aws:iam::123456789012:role/aws-service-role/" + s + "/AWSServiceRoleForExample"
		if got, ok := ServiceLinkedRole(arn); ok != serviceNameSafe(s, false) || (ok && got != s) {
			t.Fatalf("ServiceLinkedRole(%q) = %q, %v", arn, got, ok)
		}
	})
}
