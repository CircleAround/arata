package cwlogs

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/record"
)

// SampleMaxLen はサンプル行 1 行の最大文字数 (設計書 2-2)。
const SampleMaxLen = 200

// Mask はメールアドレスらしき文字列を伏せる。metrics の key (パスなど) にも使う。
func Mask(s string) string { return record.MaskEmail(s) }

// MaskSample はサンプル行をマスクし SampleMaxLen 文字に切る。
// 決定: マスクしてから切る (切った境界でメールアドレスの一部が残らないように)。
//
// 決定 (ADR 0040。ファズで見つけた): 先に制御文字・向きの制御・ゼロ幅の文字を除き、空白類は空白にする。
// サンプル行は doctor が端末に出すので、ログの行のエスケープシーケンスで端末を操作させない。ゼロ幅の文字を挟んだメールアドレスも伏せられる。
func MaskSample(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	s = Mask(s)
	if utf8.RuneCountInString(s) <= SampleMaxLen {
		return s
	}
	r := []rune(s)
	return string(r[:SampleMaxLen]) + "…"
}
