// Package aratamscaffold は aratam の設定の雛形 (`aratam config init` が書き出すもの) の本文を持つ。
//
// 決定 (ADR 0059): 監査を回すリポジトリの一式 (`arata repo init`) も同じ雛形を書き出す。arata を internal/notify (LLM と通知) に
// つながないために、本文だけを標準ライブラリにしか依存しないこのパッケージに出し、arata と aratam の両方から使う。
package aratamscaffold

import (
	"bytes"
	_ "embed"
	"fmt"
)

//go:embed scaffold.yaml
var scaffold []byte

// nameLine は雛形の name の行の先頭。Named が差し替える (雛形に 1 回だけ現れることをテストで固定する)。
const nameLine = "name: example "

// Scaffold は雛形 (全項目を明示する) の写しを返す。
func Scaffold() []byte { return append([]byte(nil), scaffold...) }

// Named は name を差し替えた雛形を返す。name は呼び出し側が形 (小文字の英数字とハイフン) を確かめてから渡す。
// 行のコメントは、短い名前なら雛形と同じ桁に、長い名前なら空白 1 つの後に置く。
func Named(name string) []byte {
	start := bytes.Index(scaffold, []byte(nameLine))
	if start < 0 {
		return Scaffold()
	}
	width := bytes.IndexByte(scaffold[start:], '#') // name の行の、コメントまでの桁数
	if width < 0 {
		return Scaffold()
	}
	field := fmt.Sprintf("%-*s", width, "name: "+name)
	if len(field) > width {
		field += " "
	}
	out := append([]byte(nil), scaffold[:start]...)
	out = append(out, field...)
	return append(out, scaffold[start+width:]...)
}
