package engine

import (
	"errors"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// 片付けの理由と操作した人の形 (ADR 0068 の 1 節)。

const (
	// maxByLen は --by の上限 (バイト。ASCII だけなので文字数と同じ)。
	maxByLen = 64
	// maxReasonRunes は --reason の上限 (文字数)。見本のワークフローの入力の上限と同じ。
	maxReasonRunes = 300
)

// byPattern は --by の形。メールアドレス (@) と氏名 (空白) を受け付けない (レポートに個人を特定できる値を書かない)。
// GitHub のハンドルと OS のユーザー名はこの形に収まる。
var byPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateBy は操作した人 (--by、approve の approved_by) の形を確かめる。
func ValidateBy(by string) error {
	if !byPattern.MatchString(by) {
		return fmt.Errorf("--by %q: want a handle of letters, digits, '.', '_' or '-' (up to %d, starting with a letter or digit; no e-mail address or name)", by, maxByLen)
	}
	return nil
}

// ValidateReason は片付けの理由 (--reason、approve の --note) の形を確かめる。空は「理由なし」として受け付ける。
// 1 行・300 文字まで。制御文字 (Cc)・書式の文字 (Cf)・行と段落の区切り (U+2028・U+2029) を受け付けない
// (報告・review・Actions の Summary に 1 行で出し、見えない文字で読み違えさせない)。
func ValidateReason(reason string) error {
	if !utf8.ValidString(reason) {
		return errors.New("--reason: not valid UTF-8")
	}
	if n := utf8.RuneCountInString(reason); n > maxReasonRunes {
		return fmt.Errorf("--reason: %d characters (up to %d, one line)", n, maxReasonRunes)
	}
	for _, r := range reason {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return fmt.Errorf("--reason: control or invisible character %U is not allowed (one line of visible text)", r)
		}
	}
	return nil
}
