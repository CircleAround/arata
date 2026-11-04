package cwlogs

import (
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/record"
)

// SampleMaxLen はサンプル行 1 行の最大文字数 (設計書 2-2)。
const SampleMaxLen = 200

// Mask はメールアドレスらしき文字列を伏せる。metrics の key (パスなど) にも使う。
func Mask(s string) string { return record.MaskEmail(s) }

// MaskSample はサンプル行をマスクし SampleMaxLen 文字に切る。
// 決定: マスクしてから切る (切った境界でメールアドレスの一部が残らないように)。
func MaskSample(s string) string {
	s = Mask(s)
	if utf8.RuneCountInString(s) <= SampleMaxLen {
		return s
	}
	r := []rune(s)
	return string(r[:SampleMaxLen]) + "…"
}
