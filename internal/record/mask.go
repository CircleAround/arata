package record

import "regexp"

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// URL エンコードされたメールアドレス (foo%40example.com)
	encodedEmailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+%40[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// assumed-role の ARN のセッション名 (個人名やメールアドレスが入る)
	sessionRe = regexp.MustCompile(`(assumed-role/[^/\s]+/)[^\s"',]+`)
)

// MaskEmail はメールアドレスらしき文字列を伏せる。
func MaskEmail(s string) string {
	s = encodedEmailRe.ReplaceAllString(s, "<email>")
	return emailRe.ReplaceAllString(s, "<email>")
}

// MaskIdentity はレポートに出す文字列から個人を特定できる値を伏せる (assumed-role のセッション名とメールアドレス)。ADR 0037
func MaskIdentity(s string) string {
	return MaskEmail(sessionRe.ReplaceAllString(s, "${1}<session>"))
}
