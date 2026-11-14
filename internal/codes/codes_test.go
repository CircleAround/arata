package codes

import (
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

var update = flag.Bool("update", false, "スキーマのゴールデン (schemas/log.schema.json) を更新する")

const root = "../.."

func TestRegistry(t *testing.T) {
	form := regexp.MustCompile(Pattern)
	seen := map[string]bool{}
	for _, c := range All {
		if !form.MatchString(c.Name) || seen[c.Name] || c.Meaning == "" || len(c.Tools) == 0 {
			t.Errorf("bad entry: %+v", c)
		}
		seen[c.Name] = true
		for _, tool := range c.Tools {
			if tool != Arata && tool != Aratam {
				t.Errorf("%s: unknown tool %q", c.Name, tool)
			}
		}
	}
	if !Known(Arata, ConfigInvalid) || !Known(Aratam, ConfigInvalid) || Known(Arata, SendFailed) || Known(Aratam, StoreLocked) || Known("", "NONE") {
		t.Error("Known")
	}
	if len(Names("")) != len(All) || !sort.StringsAreSorted(Sorted()) || len(Sorted()) != len(All) {
		t.Error("Names / Sorted")
	}
}

// parse はリポジトリの Go のファイル (テストを除く) を読む。
func parse(t *testing.T, dirs ...string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			files[filepath.ToSlash(rel)] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatalf("no Go files under %v; is the test running in internal/codes?", dirs)
	}
	return files
}

func stringLit(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(b.Value)
	return s, err == nil
}

// このパッケージの定数と一覧が 1 対 1 であること (定数を足して一覧に書き忘れない)。
func TestEveryConstantIsListed(t *testing.T) {
	listed := map[string]bool{}
	for _, c := range All {
		listed[c.Name] = true
	}
	form := regexp.MustCompile(Pattern)
	consts := map[string]bool{}
	for name, f := range parse(t, "internal/codes") {
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, v := range vs.Values {
				if s, ok := stringLit(v); ok && form.MatchString(s) && len(s) > 3 && i < len(vs.Names) && vs.Names[i].IsExported() {
					consts[s] = true
					if !listed[s] {
						t.Errorf("%s: %s = %q is not in All", name, vs.Names[i].Name, s)
					}
				}
			}
			return true
		})
	}
	for name := range listed {
		if !consts[name] {
			t.Errorf("%s is in All but has no constant", name)
		}
	}
}

// コードの中で code として渡す値は、このパッケージの定数から来る。文字列の直書きと、別の場所での定義をしない。
// ERROR のログには必ず code を付ける。
func TestCodeValuesComeFromThisPackage(t *testing.T) {
	form := regexp.MustCompile(Pattern)
	used := map[string]bool{}
	for name, f := range parse(t, "cmd", "internal") {
		if strings.HasPrefix(name, "internal/codes/") {
			continue
		}
		// このファイルの中で "code" を並びに入れているか (attrs := []any{"code", ...} を Error(msg, attrs...) に渡す形)
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "codes" {
					used[x.Sel.Name] = true
				}
			case *ast.ValueSpec:
				// Code* / code* という名前の文字列の定数・変数を、ここ以外で文字列から作らない
				for i, v := range x.Values {
					if i >= len(x.Names) || !regexp.MustCompile(`^[cC]ode[A-Z]`).MatchString(x.Names[i].Name) {
						continue
					}
					if s, ok := stringLit(v); ok && form.MatchString(s) {
						t.Errorf("%s: %s = %q must point to a constant of internal/codes", name, x.Names[i].Name, s)
					}
				}
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Code" {
					if s, ok := stringLit(x.Value); ok && form.MatchString(s) {
						t.Errorf("%s: Code: %q must use a constant of internal/codes", name, s)
					}
				}
			case *ast.CompositeLit:
				checkCodePairs(t, name, x.Elts)
			case *ast.CallExpr:
				checkCodePairs(t, name, x.Args)
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Error" || len(x.Args) == 0 {
					return true // err.Error() は引数が無い
				}
				hasCode := false
				for _, a := range x.Args {
					if s, ok := stringLit(a); ok && s == "code" {
						hasCode = true
					}
				}
				if !hasCode && x.Ellipsis == token.NoPos {
					t.Errorf("%s: an ERROR log needs a code (line of %q)", name, exprText(x.Args[0]))
				}
				if !hasCode && x.Ellipsis != token.NoPos && !attrsCarryCode(f, x.Args[len(x.Args)-1]) {
					t.Errorf("%s: an ERROR log needs a code: the spread attributes do not start from a list with \"code\" (%q)", name, exprText(x.Args[0]))
				}
			}
			return true
		})
	}
	for _, c := range All {
		// 定数の名前 (codes.X の X) を、値から引く
		if !used[constName(t, c.Name)] {
			t.Errorf("%s is listed but no code uses it (remove it from All, with a note in the release)", c.Name)
		}
	}
}

// checkCodePairs は「"code", 値」の並びの値が文字列の直書きでないことを確かめる。
func checkCodePairs(t *testing.T, name string, list []ast.Expr) {
	t.Helper()
	for i := 0; i+1 < len(list); i++ {
		if k, ok := stringLit(list[i]); !ok || k != "code" {
			continue
		}
		if s, ok := stringLit(list[i+1]); ok {
			t.Errorf("%s: \"code\", %q must use a constant of internal/codes", name, s)
		}
	}
}

// attrsCarryCode は、Error(msg, attrs...) の attrs が、このファイルで「"code" を含む並び」として作られているか。
func attrsCarryCode(f *ast.File, arg ast.Expr) bool {
	hasCode := func(e ast.Expr) bool {
		cl, ok := e.(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, el := range cl.Elts {
			if s, ok := stringLit(el); ok && s == "code" {
				return true
			}
		}
		return false
	}
	// Error(msg, append([]any{"code", ...}, more...)...) の形
	if call, ok := arg.(*ast.CallExpr); ok {
		if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "append" && len(call.Args) > 0 {
			return hasCode(call.Args[0])
		}
		return false
	}
	id, ok := arg.(*ast.Ident)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if l, ok := as.Lhs[0].(*ast.Ident); !ok || l.Name != id.Name || l.Obj != id.Obj {
			return true
		}
		found = found || hasCode(as.Rhs[0])
		return true
	})
	return found
}

func exprText(e ast.Expr) string {
	if s, ok := stringLit(e); ok {
		return s
	}
	return "…"
}

var constNames map[string]string

func constName(t *testing.T, value string) string {
	t.Helper()
	if constNames == nil {
		constNames = map[string]string{}
		for _, f := range parse(t, "internal/codes") {
			ast.Inspect(f, func(n ast.Node) bool {
				if vs, ok := n.(*ast.ValueSpec); ok {
					for i, v := range vs.Values {
						if s, ok := stringLit(v); ok && i < len(vs.Names) {
							constNames[s] = vs.Names[i].Name
						}
					}
				}
				return true
			})
		}
	}
	return constNames[value]
}

// tableCodes は、文書の「| `CODE` | …」の表の最初の列の code を、出てくる順に返す (1 つの欄に `A` / `B` と並べたものも拾う)。
func tableCodes(t *testing.T, file, heading string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), heading)
	if !ok {
		t.Fatalf("%s: no %q", file, heading)
	}
	var out []string
	inTable := false
	cell := regexp.MustCompile("`([A-Z][A-Z0-9_]*)`")
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cols := strings.Split(line, "|")
		if len(cols) < 3 {
			continue
		}
		for _, m := range cell.FindAllStringSubmatch(cols[1], -1) {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no code table after %q", file, heading)
	}
	return out
}

func sameSet(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}

// 文書の code の表は、この一覧と一致する (code を足したら表にも足す。表にだけある code を残さない)。
func TestDocumentedTablesMatch(t *testing.T) {
	for _, tc := range []struct {
		file, heading, tool string
	}{
		{"docs/ai/index.md", "## 標準エラーのログと code", Arata}, // arata help ai (バイナリに埋め込む)
		{"docs/design.md", "| code | 意味 |", Arata},       // 設計書 2-2
		{"docs/aratam.md", "### 標準エラーのログと code", Aratam}, // aratam 設計書
	} {
		if got, want := tableCodes(t, tc.file, tc.heading), Names(tc.tool); !sameSet(got, want) {
			t.Errorf("%s: the code table differs from codes.Names(%q)\n got %v\nwant %v", tc.file, tc.tool, got, want)
		}
	}
}

// log スキーマを、Line の型と一覧から作ったもので固定する。code を足すと、既知の値が 1 つ増える (互換)。
func TestLogSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{
		Name: LogSchema, Version: LogSchemaVersion,
		Description: "標準エラーの構造化ログの 1 行 (arata と aratam で共通)。ここにある項目だけが安定。ほかの属性は人向けで、名前も中身も固定しない。行ごとに schema の項目は出さない",
		Type:        Line{},
		Open:        map[string]jsonschema.Vocabulary{"code": {Values: Names(""), Pattern: Pattern}},
	}, *update)
}
