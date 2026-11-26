package pathids

import (
	"reflect"
	"strings"
	"testing"
)

// 例の値はすべて架空 (ADR 0071・0087)。
var testRules = Rules{
	Segments: []string{
		`[0-9]{1,20}`,
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	},
	Templates: []string{
		"/users/:id/profile",
		"/shops/:id/items/:id",
		"/billing/charges/:id/:any",
		"/reports/:any",
	},
	Formats:     []string{"json", "csv", "gz"},
	MaxSegments: 4,
}

func mustCompile(t testing.TB, r Rules) *Compiled {
	t.Helper()
	c, err := Compile(r)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func TestNormalize(t *testing.T) {
	c := mustCompile(t, testRules)
	for _, tc := range []struct {
		path string
		tpl  string
		ids  []string
	}{
		{"/orders/42", "/orders/:id", []string{"42"}},
		{"/orders/42.json", "/orders/:id", []string{"42"}},
		{"/orders/42.json?page=2", "/orders/:id", []string{"42"}},
		{"/orders/42?x=1.json", "/orders/:id", []string{"42"}},
		{"/orders/42#frag", "/orders/:id", []string{"42"}},
		{"/orders", "/orders", nil},
		{"/orders/", "/orders/", nil},
		{"/", "/", nil},
		{"/orders/.json", "/orders/", nil},
		{"/files/a.tar.gz", "/files/a.tar", nil},
		{"/files/a.xml", "/files/a.xml", nil},   // 一覧に無い拡張子は外さない
		{"/files/a.JSON", "/files/a.JSON", nil}, // 大文字は一覧に当たらない (ADR 0087 の 6 節)
		{"/orders/42/items/7", "/orders/:id/items/:id", []string{"42", "7"}},
		{"/orders/0d9c1e2a-1111-4222-8333-444455556666", "/orders/:id", []string{"0d9c1e2a-1111-4222-8333-444455556666"}},
		{"/orders/42abc", "/orders/42abc", nil},
		{"/users/taro/profile", "/users/:id/profile", []string{"taro"}},
		{"/users/taro/profile.json", "/users/:id/profile", []string{"taro"}},
		{"/users/taro", "/users/taro", nil}, // 型に当たらない
		{"/shops/7/items/31", "/shops/:id/items/:id", []string{"7", "31"}},
		{"/billing/charges/42/202611", "/billing/charges/:id/:any", []string{"42"}},
		{"/billing/charges/42/2026-11", "/billing/charges/:id/:any", []string{"42"}},
		{"/reports/weekly", "/reports/:any", nil},
		// 深いパスは max_segments の後ろを … にまとめる
		{"/a/b/c/d", "/a/b/c/d", nil},
		{"/a/b/c/d/e", "/a/b/c/d/…", nil},
		{"/a/1/c/2/3/4", "/a/:id/c/:id/…", []string{"1", "2"}},
		// 個人に結び付きうる区間は :x に伏せる (ADR 0071 の 2 節)
		{"/u/alice@example.com/orders", "/u/:x/orders", nil},
		{"/t/abcdefgh12345678", "/t/:x", nil},
		{"/t/abcdefghijklmnopqrstuvwxyzabcdefg", "/t/:x", nil},
		{"/t/abcdefghijklmnopqrstuvwxyzabcdef", "/t/abcdefghijklmnopqrstuvwxyzabcdef", nil},
		// ログの値で印を偽れない
		{"/orders/:id", "/orders/:x", nil},
		{"/orders/?id", "/orders/", nil}, // ? の後ろはクエリ
		{"/orders/…", "/orders/:x", nil},
		// / で始まらないパスは型を持たない
		{"", "", nil},
		{"orders/42", "", nil},
		{"?x=1", "", nil},
		{".json", "", nil},
		{"/orders//42", "/orders//:id", []string{"42"}},
	} {
		tpl, ids := c.Normalize(tc.path)
		if tpl != tc.tpl || !reflect.DeepEqual(ids, tc.ids) {
			t.Errorf("Normalize(%q) = %q %q, want %q %q", tc.path, tpl, ids, tc.tpl, tc.ids)
		}
	}
}

func TestNormalizeWithoutFormatsAndTemplates(t *testing.T) {
	c := mustCompile(t, Rules{Segments: []string{`[0-9]+`}, MaxSegments: 8})
	for path, want := range map[string]string{
		"/orders/42.json":    "/orders/42.json",
		"/orders/42":         "/orders/:id",
		"/users/taro/orders": "/users/taro/orders",
	} {
		if got, _ := c.Normalize(path); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIDKey(t *testing.T) {
	if got := IDKey(nil); got != "" {
		t.Errorf("IDKey(nil) = %q", got)
	}
	if got := IDKey([]string{"7", "31"}); got != "/7/31" {
		t.Errorf("IDKey = %q", got)
	}
}

func TestSanitize(t *testing.T) {
	c := mustCompile(t, testRules)
	for raw, want := range map[string]string{
		"":                        "",
		"orders":                  "",
		"/orders/?id":             "/orders/:id",
		"/billing/?id/?any":       "/billing/:id/:any",
		"/a/b/c/d/?more":          "/a/b/c/d/…",
		"/a/?more/c":              "/a/:x/c",
		"/a/b/c/d/e/f":            "/a/b/c/d/…", // Insights の結果は信用しない。区間の数を絞る
		"/orders/:id":             "/orders/:x",
		"/orders/?x":              "/orders/:x",
		"/orders/a\x1bb":          "/orders/:x",
		"/orders/a b":             "/orders/:x",
		"/orders/\xff":            "/orders/:x",
		"/orders/a%40example.com": "/orders/:x",
		"/orders/ok-name_1.v2~x":  "/orders/ok-name_1.v2~x",
	} {
		if got := c.Sanitize(raw); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	base := func() Rules {
		return Rules{Segments: []string{`[0-9]+`}, MaxSegments: 8}
	}
	for _, tc := range []struct {
		name string
		mod  func(r *Rules)
		want string
	}{
		{"max_segments 0", func(r *Rules) { r.MaxSegments = 0 }, "max_segments"},
		{"max_segments 13", func(r *Rules) { r.MaxSegments = 13 }, "max_segments"},
		{"no rules", func(r *Rules) { r.Segments = nil }, "segments or templates"},
		{"too many segments", func(r *Rules) {
			r.Segments = strings.Split("a,b,c,d,e,f,g,h,i", ",")
		}, "at most 8"},
		{"bad regex", func(r *Rules) { r.Segments = []string{`[0-9`} }, "segments"},
		{"slash", func(r *Rules) { r.Segments = []string{`a/b`} }, "/"},
		{"named capture", func(r *Rules) { r.Segments = []string{`(?P<x>[0-9]+)`} }, "named"},
		{"unnamed capture", func(r *Rules) { r.Segments = []string{`([0-9]+)`} }, "(?:...)"},
		{"unnamed capture inside", func(r *Rules) { r.Segments = []string{`a(b|c)[0-9]`} }, "(?:...)"},
		{"anchor", func(r *Rules) { r.Segments = []string{`^[0-9]+$`} }, "anchor"},
		{"matches empty", func(r *Rules) { r.Segments = []string{`[0-9]*`} }, "empty"},
		{"quote", func(r *Rules) { r.Segments = []string{`\Q`} }, `\Q`},
		{"quote closed", func(r *Rules) { r.Segments = []string{`\Qa.b\E`} }, `\Q`},
		{"newline", func(r *Rules) { r.Segments = []string{"[0-9]+\n"} }, "newline"},
		{"long regex", func(r *Rules) { r.Segments = []string{strings.Repeat("a", 257)} }, "long"},
		{"dup segment", func(r *Rules) { r.Segments = []string{`[0-9]+`, `[0-9]+`} }, "duplicate"},
		{"template without slash", func(r *Rules) { r.Templates = []string{"users/:id"} }, "start with /"},
		{"template no placeholder", func(r *Rules) { r.Templates = []string{"/users/me"} }, ":id or :any"},
		{"template only placeholders", func(r *Rules) { r.Templates = []string{"/:any/:id"} }, "fixed"},
		{"template empty segment", func(r *Rules) { r.Templates = []string{"/users//:id"} }, "segment"},
		{"template bad char", func(r *Rules) { r.Templates = []string{"/us\"ers/:id"} }, "segment"},
		{"template unknown placeholder", func(r *Rules) { r.Templates = []string{"/users/:name"} }, "segment"},
		{"template glob", func(r *Rules) { r.Templates = []string{"/users/*"} }, "segment"},
		{"template long literal", func(r *Rules) { r.Templates = []string{"/" + strings.Repeat("a", 33) + "/:id"} }, "segment"},
		{"template dup", func(r *Rules) { r.Templates = []string{"/u/:id", "/u/:id"} }, "duplicate"},
		{"too many templates", func(r *Rules) {
			for i := 0; i < 51; i++ {
				r.Templates = append(r.Templates, "/t"+strings.Repeat("x", i%30)+string(rune('a'+i%26))+"/:id")
			}
		}, "at most 50"},
		{"bad format", func(r *Rules) { r.Formats = []string{"JSON"} }, "formats"},
		{"format dot", func(r *Rules) { r.Formats = []string{"tar.gz"} }, "formats"},
		{"format long", func(r *Rules) { r.Formats = []string{"abcdefghi"} }, "formats"},
		{"dup format", func(r *Rules) { r.Formats = []string{"json", "json"} }, "duplicate"},
		{"too many formats", func(r *Rules) {
			for i := 0; i < 21; i++ {
				r.Formats = append(r.Formats, "f"+string(rune('a'+i)))
			}
		}, "at most 20"},
	} {
		r := base()
		tc.mod(&r)
		_, err := Compile(r)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
		}
	}
	// :any だけの型と、templates だけの規則は書ける (ADR 0087 の 5 節)
	if _, err := Compile(Rules{Templates: []string{"/reports/:any"}, MaxSegments: 8}); err != nil {
		t.Errorf("templates only: %v", err)
	}
}

// 組み立てたクエリの長さが上限を超える規則は誤り (ADR 0087 の 5 節)。
func TestCompileQueryTooLong(t *testing.T) {
	r := Rules{MaxSegments: 12}
	for i := 0; i < 8; i++ {
		r.Segments = append(r.Segments, strings.Repeat("[0-9a-f]", 30)+strings.Repeat("x", i))
	}
	for i := 0; i < 50; i++ {
		r.Templates = append(r.Templates, "/"+strings.Repeat("a", 20)+string(rune('a'+i%26))+string(rune('a'+i/26))+"/:id/"+strings.Repeat("b", 20)+"/:id")
	}
	if _, err := Compile(r); err == nil || !strings.Contains(err.Error(), "query") {
		t.Fatalf("err = %v, want query too long", err)
	}
}
