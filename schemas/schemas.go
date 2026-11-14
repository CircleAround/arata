// Package schemas は、機械が読む出力の JSON Schema (draft 2020-12) をバイナリに埋め込む。
//
// 決定 (ADR 0054): スキーマのファイルは Go の型から作り (internal/jsonschema)、ここにゴールデンとして置く。手で編集しない。
// 直すときは型を直し、その型のパッケージのテストを -update で流す。
// このパッケージは標準ライブラリだけに依存し、型のパッケージを import しない (aratam に監査用の依存をつながない。ADR 0018)。
// arata と aratam のどちらも、全部のスキーマを `schema [名前]` で出す。
package schemas

import (
	"embed"
	"fmt"
	"io"
	"sort"
	"strings"
)

//go:embed *.schema.json
var files embed.FS

const suffix = ".schema.json"

// IDPrefix は各スキーマの $id の接頭辞。$id は IDPrefix + 名前 + ":" + 版。取りに行ける URL にはしない。
const IDPrefix = "urn:arata:schema:"

// ID は名前と版から $id を作る。
func ID(name string, version int) string {
	return fmt.Sprintf("%s%s:%d", IDPrefix, name, version)
}

// Names はスキーマの名前の一覧 (名前の順)。
func Names() []string {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), suffix); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// Lookup は名前のスキーマ (ファイルの中身そのもの) を返す。
func Lookup(name string) ([]byte, bool) {
	// 名前はファイル名の一部になる。一覧にあるものだけを読む
	for _, n := range Names() {
		if n == name {
			b, err := files.ReadFile(n + suffix)
			return b, err == nil
		}
	}
	return nil, false
}

// Write は `schema [名前]` の出力。名前が空なら一覧 (1 行に 1 つ)、あればそのスキーマを書く。
func Write(w io.Writer, name string) error {
	if name == "" {
		_, err := io.WriteString(w, strings.Join(Names(), "\n")+"\n")
		return err
	}
	b, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("no schema named %q (%s)", name, strings.Join(Names(), ", "))
	}
	_, err := w.Write(b)
	return err
}

// Long は `schema` コマンドのヘルプの本文 (arata と aratam で同じ)。
const Long = `機械が読む出力 (--format json、report.json) の JSON Schema (draft 2020-12) を出す。引数なしで名前の一覧、名前を渡すとそのスキーマ。

スキーマに書いた項目が、外から読んでよい項目のすべて。人向けの出力 (table / text / md、ログの msg の文言) は版をまたいで変わるので、
機械で読まない。読む側の決まり:

  - 知らない項目は無視する (項目は版を上げずに足される)
  - enum のある項目 (閉じた語彙) で知らない値を見たら止める
  - schema_version が自分の知る版より大きければ止める (項目を消す・名前や型や意味を変えるときに上がり、Release の本文に書かれる)

スキーマは開いた形 (additionalProperties を縛らない) なので、古いスキーマで新しい出力を確かめても、足した項目では落ちない。`
