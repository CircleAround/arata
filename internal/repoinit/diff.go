package repoinit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// repo init --diff --format json のスキーマの名前と版 (ADR 0054)。名前は `arata schema <名前>` の名前。
const (
	DiffSchema        = "repo-diff"
	DiffSchemaVersion = 1
)

// DiffFile.Status の値。
const (
	StatusSame    = "same"    // 生成物が、この版の一式と同じ
	StatusDiffers = "differs" // 生成物が、この版の一式と違う
	StatusMissing = "missing" // 一式にあるファイルが無い
	StatusExtra   = "extra"   // この版の一式に無いファイルがある (.github/workflows・.github/scripts の arata- で始まるファイル、github・github/secrets の .tf)
	StatusPresent = "present" // 利用者が育てるファイルがある (中身は比べない。arata config init --diff の役目)
)

// DiffOutput は repo init --diff --format json の出力。
type DiffOutput struct {
	Schema        string     `json:"schema" jsonschema:"const=repo-diff"`
	SchemaVersion int        `json:"schema_version" jsonschema:"const=1"`
	OK            bool       `json:"ok" desc:"differs・missing・extra が 1 つも無い (終了コード 0)。1 つでもあれば false (終了コード 1)"`
	Files         []DiffFile `json:"files" desc:"一式のファイルと、この版の一式に無いファイル (status が extra)。path の順"`
}

// DiffFile は 1 つのファイルの比べた結果。
type DiffFile struct {
	Path   string `json:"path" desc:"リポジトリの根からの相対パス (区切りは /)"`
	Kind   string `json:"kind" jsonschema:"enum=generated|seed" desc:"generated = 生成物 (手で直さない。--force で書き直す)、seed = 利用者が育てるファイル (aws/ の下。書き直さない)"`
	Status string `json:"status" jsonschema:"enum=same|differs|missing|extra|present" desc:"same = この版の一式と同じ、differs = 違う、missing = 無い、extra = この版の一式に無いファイル (ワークフローとスクリプトの置き場所の arata- で始まるもの、Terraform の宣言の置き場所の .tf)、present = 利用者が育てるファイルがある (中身は比べない)"`

	lines []string // text の出力に添える行の差分 (differs のときだけ。機械向けには出さない)
}

// Diff は dir にある一式と、この版の一式 (files) を比べる。何も書かない。
func Diff(dir string, files []File) (DiffOutput, error) {
	out := DiffOutput{Schema: DiffSchema, SchemaVersion: DiffSchemaVersion, OK: true, Files: []DiffFile{}}
	known := map[string]bool{}
	for _, f := range files {
		known[f.Path] = true
		cur, exists, err := readTarget(dir, f.Path)
		if err != nil {
			return DiffOutput{}, err
		}
		d := DiffFile{Path: f.Path, Kind: string(f.Kind)}
		switch {
		case !exists:
			d.Status = StatusMissing
		case f.Kind == Seed:
			d.Status = StatusPresent
		case cur != nil && bytes.Equal(cur, f.Body):
			d.Status = StatusSame
		default:
			d.Status = StatusDiffers
			if cur == nil {
				d.lines = []string{"(今のファイルが大きすぎるので、行の差分は出さない)"}
			} else {
				d.lines = lineDiff(string(cur), string(f.Body))
			}
		}
		out.Files = append(out.Files, d)
	}
	for _, md := range managedDirs {
		ents, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(md.dir)))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return DiffOutput{}, err
		}
		for _, e := range ents {
			p := md.dir + "/" + e.Name()
			if !e.IsDir() && md.match(e.Name()) && !known[p] {
				out.Files = append(out.Files, DiffFile{Path: p, Kind: string(Generated), Status: StatusExtra})
			}
		}
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	for _, f := range out.Files {
		if f.Status == StatusDiffers || f.Status == StatusMissing || f.Status == StatusExtra {
			out.OK = false
		}
	}
	return out, nil
}

// WriteDiff は人向けの出力 (text)。文言と並びは固定しない (機械で読むのは --format json)。
func WriteDiff(w io.Writer, out DiffOutput) error {
	var b strings.Builder
	label := map[string]string{
		StatusDiffers: "違う (この版の一式と中身が違う。--force で書き直す)",
		StatusMissing: "無い (arata repo init で作る)",
		StatusExtra:   "この版の一式に無い (古い版の残りや、手で作った Terraform の宣言。要らなければ消す。github/ の .tf は、残すと一緒に当たる)",
	}
	same, present := 0, 0
	for _, f := range out.Files {
		switch f.Status {
		case StatusSame:
			same++
		case StatusPresent:
			present++
		default:
			fmt.Fprintf(&b, "%s: %s\n", printable(f.Path), label[f.Status])
			for _, l := range f.lines {
				fmt.Fprintf(&b, "  %s\n", l)
			}
		}
	}
	fmt.Fprintf(&b, "同じ: %d / 利用者が育てるファイル (中身は比べない。arata config init --diff -c <arata.yaml> で比べる): %d\n", same, present)
	if out.OK {
		b.WriteString("この版の一式と揃っています。\n")
	} else {
		b.WriteString("この版の一式と違いがあります (終了コード 1)。\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// 行の差分の上限。超えるときは行を出さない (今のファイルは利用者のもので、大きさを決められない)。
const maxDiffCells = 4_000_000

// lineDiff は old から new への行の差分を返す。変わった行の前後 2 行を添え、離れた変更は「@@ 行 @@」で区切る。
// 行は端末にそのまま出すので、制御文字を置き換える (printable)。
func lineDiff(oldText, newText string) []string {
	a, b := splitLines(oldText), splitLines(newText)
	if len(a)*len(b) > maxDiffCells {
		return []string{"(違いが大きいので、行の差分は出さない)"}
	}
	// 最長共通部分列 (後ろから)
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				lcs[i][j] = lcs[i+1][j+1] + 1
			case lcs[i+1][j] >= lcs[i][j+1]:
				lcs[i][j] = lcs[i+1][j]
			default:
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	type op struct {
		kind byte // ' ' '-' '+'
		text string
		old  int // old の行番号 (1 始まり。+ の行は直前の位置)
	}
	var ops []op
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], i + 1})
			i, j = i+1, j+1
		case j < len(b) && (i == len(a) || lcs[i][j+1] > lcs[i+1][j]):
			ops = append(ops, op{'+', b[j], i + 1})
			j++
		default:
			ops = append(ops, op{'-', a[i], i + 1})
			i++
		}
	}
	const context = 2
	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.kind == ' ' {
			continue
		}
		for c := max(0, k-context); c <= min(len(ops)-1, k+context); c++ {
			keep[c] = true
		}
	}
	var out []string
	for k, o := range ops {
		if !keep[k] {
			continue
		}
		if k == 0 || !keep[k-1] {
			out = append(out, fmt.Sprintf("@@ %d 行目 @@", o.old))
		}
		out = append(out, string(o.kind)+printable(o.text))
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// printable は、端末に出す前に制御文字 (タブ以外) と不正な UTF-8 を U+FFFD に置き換える。
// 今のファイルの中身と名前は利用者のもので、端末の制御列が入り得る。
func printable(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, isControl) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s { // 不正なバイトは range が U+FFFD にする
		if isControl(r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isControl は、端末に出さない文字: C0・C1 の制御文字 (タブ以外)、行と段落の区切り、文字の向きを変える制御文字 (表示の並びを偽れる)。
func isControl(r rune) bool {
	switch {
	case r < 0x20 && r != 0x09, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028, r == 0x2029, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
