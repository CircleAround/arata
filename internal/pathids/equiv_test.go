package pathids

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
)

// insights は偽の Insights (cwlogstest.Sim) に Query を流し、各パスの (Sanitize した型, 対象 ID) を返す。
func insights(t testing.TB, c *Compiled, paths []string) [][2]string {
	t.Helper()
	at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	sim := &cwlogstest.Sim{}
	for i, p := range paths {
		// 行の順を保つため、1 行ずつ時刻をずらす。path の無い行 (ほかの行の種類) も混ぜ、型も ID も作らないことを確かめる
		sim.Events = append(sim.Events,
			cwlogstest.Event{Time: at.Add(time.Duration(2*i) * time.Second), Fields: map[string]string{"path": p, "n": "1"}},
			cwlogstest.Event{Time: at.Add(time.Duration(2*i+1) * time.Second), Fields: map[string]string{"n": "0"}})
	}
	rows := sim.Rows(c.Query("path"), at, at.Add(time.Duration(2*len(paths)+1)*time.Second), nil)
	if len(rows) != 2*len(paths) {
		t.Fatalf("rows = %d, want %d", len(rows), 2*len(paths))
	}
	out := make([][2]string, len(paths))
	for i := range paths {
		r, other := rows[2*i], rows[2*i+1]
		if _, ok := other[TemplateField]; ok {
			t.Fatalf("a line without path got a template: %v", other)
		}
		if _, ok := other[IDField]; ok {
			t.Fatalf("a line without path got an id: %v", other)
		}
		out[i] = [2]string{c.Sanitize(r[TemplateField]), r[IDField]}
	}
	return out
}

func assertSame(t testing.TB, c *Compiled, paths []string) {
	t.Helper()
	got := insights(t, c, paths)
	for i, p := range paths {
		tpl, ids := c.Normalize(p)
		if got[i] != [2]string{tpl, IDKey(ids)} {
			t.Errorf("path %q: insights %q, go %q %q", p, got[i], tpl, IDKey(ids))
		}
	}
}

var equivPaths = []string{
	"/orders/42", "/orders/42.json", "/orders/42.json?page=2", "/orders/42?x=1.json", "/orders/42#f",
	"/orders", "/orders/", "/", "", "orders/42", "?x", ".json", "/.json", "/orders/.json", "/files/a.tar.gz", "/files/a.JSON",
	"/orders/42/items/7", "/orders/0d9c1e2a-1111-4222-8333-444455556666", "/orders/42abc",
	"/users/taro/profile", "/users/taro/profile.json", "/users/taro", "/users//profile",
	"/shops/7/items/31", "/shops/7/items/31/x", "/billing/charges/42/202611", "/billing/charges/42/2026-11",
	"/reports/weekly", "/reports/", "/a/b/c/d", "/a/b/c/d/e", "/a/1/c/2/3/4", "/a/b/c/d/", "//", "///1",
	"/u/alice@example.com/orders", "/t/abcdefgh12345678", "/orders/:id", "/orders/?id", "/orders/…", "/a|b/1",
	"/orders//42", "/orders/42\n/x", "/o\x00/1", "/日本/42",
}

func TestQueryMatchesNormalize(t *testing.T) {
	for name, r := range map[string]Rules{
		"full":           testRules,
		"no formats":     {Segments: testRules.Segments, Templates: testRules.Templates, MaxSegments: 4},
		"no templates":   {Segments: testRules.Segments, Formats: []string{"json"}, MaxSegments: 3},
		"templates only": {Templates: testRules.Templates, Formats: []string{"json"}, MaxSegments: 4},
		"max 1":          {Segments: []string{`[0-9]+`}, MaxSegments: 1},
		"max 12":         {Segments: testRules.Segments, Templates: testRules.Templates, Formats: testRules.Formats, MaxSegments: 12},
	} {
		t.Run(name, func(t *testing.T) { assertSame(t, mustCompile(t, r), equivPaths) })
	}
}

// FuzzQueryMatchesNormalize: ログ由来のパス (任意の文字列) で、Insights の中の組み立て (偽の Insights) と Go の正規化が、同じ型・同じ対象 ID になる (ADR 0071 の 2 節・0087 の 5・6 節)。
// あわせて、型は置いてよい形だけで (印・伏せた区間・32 文字以下の区間)、`:id` の数と対象 ID の数が同じ。
func FuzzQueryMatchesNormalize(f *testing.F) {
	for _, p := range equivPaths {
		f.Add(p)
	}
	full := mustCompile(f, testRules)
	noTpl := mustCompile(f, Rules{Segments: []string{`[0-9]+`, `[a-z]{2}[0-9]`}, Formats: []string{"json", "csv"}, MaxSegments: 3})
	f.Fuzz(func(t *testing.T, p string) {
		for _, c := range []*Compiled{full, noTpl} {
			assertSame(t, c, []string{p})
			tpl, ids := c.Normalize(p)
			checkTemplate(t, c, p, tpl, ids)
		}
	})
}

// checkTemplate は型の守る規則を確かめる。
func checkTemplate(t testing.TB, c *Compiled, p, tpl string, ids []string) {
	t.Helper()
	if tpl == "" {
		if len(ids) > 0 {
			t.Fatalf("%q: ids without a template: %q", p, ids)
		}
		return
	}
	if !strings.HasPrefix(tpl, "/") || strings.ContainsAny(tpl, "?#|") {
		t.Fatalf("%q: template %q", p, tpl)
	}
	segs := strings.Split(tpl[1:], "/")
	if len(segs) > c.rules.MaxSegments+1 {
		t.Fatalf("%q: template %q deeper than max_segments", p, tpl)
	}
	nID := 0
	for i, s := range segs {
		switch {
		case s == ID:
			nID++
		case s == Any || s == X:
		case s == More:
			if i != len(segs)-1 {
				t.Fatalf("%q: … not last in %q", p, tpl)
			}
		default:
			if !utf8.ValidString(s) || len(s) > maxLiteralLen || strings.HasPrefix(s, ":") || strings.Contains(s, "@") || digitLong(s) {
				t.Fatalf("%q: segment %q left in %q", p, s, tpl)
			}
		}
	}
	if nID != len(ids) {
		t.Fatalf("%q: %d :id in %q, %d ids %q", p, nID, tpl, len(ids), ids)
	}
	for _, id := range ids {
		if id == "" || strings.Contains(id, "/") {
			t.Fatalf("%q: id %q", p, id)
		}
	}
}

// FuzzTemplateAny: 型に当たったパスでは、`:any` の位置の値は型にも対象 ID にも現れず、`:id` の位置の値がちょうど対象 ID になる (ADR 0087 の 5 節)。
// 拡張子は一覧のものだけを最後の区間の末尾から外し、/ を足さない・消さない (6 節)。
func FuzzTemplateAny(f *testing.F) {
	f.Add("42", "202611", "json")
	f.Add("7", "2026-11", "")
	f.Add("a.b", "c.json", "csv")
	c := mustCompile(f, Rules{
		Segments:    []string{`[0-9]+`},
		Templates:   []string{"/billing/charges/:id/:any", "/x/:any/y/:id"},
		Formats:     []string{"json", "csv"},
		MaxSegments: 6,
	})
	f.Fuzz(func(t *testing.T, id, any, ext string) {
		if id == "" || any == "" || strings.ContainsAny(id+any+ext, "/?#") {
			return
		}
		suffix := ""
		if ext != "" {
			suffix = "." + ext
		}
		// 拡張子を外すのは最後の区間の末尾の、一覧の拡張子 1 つだけ
		strip := func(last string) string {
			for _, f := range []string{"json", "csv"} {
				if strings.HasSuffix(last, "."+f) {
					return last[:len(last)-len(f)-1]
				}
			}
			return last
		}
		for _, tc := range []struct {
			path, tpl string
			lastIsID  bool
		}{
			{"/billing/charges/" + id + "/" + any + suffix, "/billing/charges/:id/:any", false},
			{"/x/" + any + "/y/" + id + suffix, "/x/:any/y/:id", true},
		} {
			wantID, last := id, any+suffix
			if tc.lastIsID {
				last = id + suffix
			}
			if strip(last) == "" {
				continue // 最後の区間が空になれば型に当たらない (別の表のテストが見る)
			}
			if tc.lastIsID {
				wantID = strip(last)
			}
			assertSame(t, c, []string{tc.path})
			tpl, ids := c.Normalize(tc.path)
			if tpl != tc.tpl {
				t.Fatalf("%q: template %q, want %q", tc.path, tpl, tc.tpl)
			}
			// 型は設定の文字列そのもの (:any の値は現れない)。対象 ID は :id の位置の値だけ
			if len(ids) != 1 || ids[0] != wantID {
				t.Fatalf("%q: ids %q, want [%q]", tc.path, ids, wantID)
			}
			if strings.Count(tc.path, "/") != strings.Count(tc.tpl, "/") {
				t.Fatalf("%q: / added or removed", tc.path)
			}
		}
	})
}

// FuzzSanitize: Insights の結果の型 (信用しない入力) は、置いてよい形にしかならない。/ で始まらない値は空。
func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"/orders/?id", "/a/?more", "/a/?more/b", "/x/:id", "/u/a@example.com", "", "x", "/\xff", "/a/b/c/d/e/f/g"} {
		f.Add(s)
	}
	c := mustCompile(f, testRules)
	f.Fuzz(func(t *testing.T, raw string) {
		got := c.Sanitize(raw)
		if !strings.HasPrefix(raw, "/") {
			if got != "" {
				t.Fatalf("%q → %q", raw, got)
			}
			return
		}
		ids := make([]string, strings.Count(got, "/"+ID))
		for i := range ids {
			ids[i] = "1"
		}
		checkTemplate(t, c, raw, got, ids)
	})
}

// FuzzCompile: 利用者の設定 (segments・templates・formats) が検証を通れば、組み立てた文は Insights の /.../ と "..." を抜け出さず
// (偽の Insights が文の形どおりに読める)、段の数が規則の数だけで決まり、Go の正規化と同じ結果になる。
func FuzzCompile(f *testing.F) {
	f.Add(`[0-9]{1,20}`, "/users/:id/profile", "json", 8)
	f.Add(`(?i)[a-f]{4}`, "/a/:any", "csv", 2)
	f.Add(`x|y"`, `/"/:id`, "", 3)
	f.Fuzz(func(t *testing.T, seg, tpl, format string, max int) {
		r := Rules{Segments: []string{seg}, Templates: []string{tpl}, Formats: []string{format}, MaxSegments: max}
		if format == "" {
			r.Formats = nil
		}
		c, err := Compile(r)
		if err != nil {
			return
		}
		q := c.Query("path")
		if got, want := strings.Count(q, "\n"), 2+1+max+2+2-1; got != want {
			t.Fatalf("query has %d lines, want %d:\n%s", got+1, want+1, q)
		}
		assertSame(t, c, []string{"/users/42/profile", "/a/b", "/x.json", tpl, strings.ReplaceAll(tpl, ":id", "7")})
	})
}
