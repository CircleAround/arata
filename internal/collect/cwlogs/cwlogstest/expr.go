package cwlogstest

import (
	"strconv"
	"strings"
)

// fields の式 (ADR 0087 のパスの型の組み立て。pathids.Query の形)。
//
// 決定: 確かめていない振る舞いに頼るクエリは受け付けない (panic。テストで止める)。
//   - if の分岐は定数の文字列か、分岐が定数の if だけ (本物は stats の後で else の項目を null にした。stats の前でも頼らない)。条件は ispresent(<項目>) だけ
//   - concat に無い項目を渡さない (本物の null の扱いを確かめていない)。coalesce か if を通す
//   - coalesce は最初の「ある」値 (空の文字列もある値)
//   - `<項目> + <項目>` は数の和 (U1 の sort の順。片方が無ければ値なし)
type simExpr struct {
	fn   string // "" なら lit / field
	lit  *string
	fld  string
	args []*simExpr
}

func parseExpr(s string) *simExpr {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, `"`) {
		if len(s) < 2 || !strings.HasSuffix(s, `"`) || strings.ContainsAny(s[1:len(s)-1], `"\`) {
			panic("sim: unsupported string literal: " + s)
		}
		v := s[1 : len(s)-1]
		return &simExpr{lit: &v}
	}
	if a, b, ok := strings.Cut(s, " + "); ok && !strings.Contains(s, "(") {
		return &simExpr{fn: "+", args: []*simExpr{parseExpr(a), parseExpr(b)}}
	}
	open := strings.IndexByte(s, '(')
	if open < 0 {
		if !isIdent(s) {
			panic("sim: unsupported expression: " + s)
		}
		return &simExpr{fld: s}
	}
	if !strings.HasSuffix(s, ")") {
		panic("sim: unsupported expression: " + s)
	}
	e := &simExpr{fn: s[:open]}
	for _, a := range splitTop(s[open+1 : len(s)-1]) {
		e.args = append(e.args, parseExpr(a))
	}
	switch e.fn {
	case "concat", "coalesce":
		if len(e.args) == 0 {
			panic("sim: " + e.fn + " needs arguments: " + s)
		}
	case "ispresent":
		if len(e.args) != 1 || e.args[0].fld == "" {
			panic("sim: ispresent takes one field: " + s)
		}
	case "if":
		if len(e.args) != 3 || e.args[0].fn != "ispresent" {
			panic("sim: if must be if(ispresent(<field>), <const>, <const>): " + s)
		}
		for _, b := range e.args[1:] {
			if !b.constant() {
				panic("sim: if() with a field in a branch is not relied on (else returns null after stats); use coalesce(<field>, if(<cond>, \"<value>\", \"\")): " + s)
			}
		}
	default:
		panic("sim: unsupported function: " + s)
	}
	return e
}

// constant は値が項目によらず決まる (文字列か、分岐が定数の if) か。
func (e *simExpr) constant() bool {
	switch {
	case e.lit != nil:
		return true
	case e.fn == "if":
		return e.args[1].constant() && e.args[2].constant()
	}
	return false
}

func (e *simExpr) eval(f map[string]string) (string, bool) {
	switch {
	case e.lit != nil:
		return *e.lit, true
	case e.fn == "":
		v, ok := f[e.fld]
		return v, ok
	}
	switch e.fn {
	case "+":
		a, okA := e.args[0].eval(f)
		b, okB := e.args[1].eval(f)
		if !okA || !okB {
			return "", false
		}
		x, _ := strconv.ParseFloat(a, 64)
		y, _ := strconv.ParseFloat(b, 64)
		return strconv.FormatFloat(x+y, 'f', -1, 64), true
	case "concat":
		var b strings.Builder
		for _, a := range e.args {
			v, ok := a.eval(f)
			if !ok {
				panic("sim: concat() of a missing field is not relied on; wrap it in coalesce(<field>, \"\")")
			}
			b.WriteString(v)
		}
		return b.String(), true
	case "coalesce":
		for _, a := range e.args {
			if v, ok := a.eval(f); ok {
				return v, true
			}
		}
		return "", false
	case "ispresent":
		if _, ok := f[e.args[0].fld]; ok {
			return "1", true
		}
		return "", true
	case "if":
		c, _ := e.args[0].eval(f)
		if c != "" {
			return e.args[1].eval(f)
		}
		return e.args[2].eval(f)
	}
	panic("sim: unsupported function " + e.fn)
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if !(c == '_' || c == '@' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// splitTop は括弧と引用符の外の ", " で分ける。
func splitTop(s string) []string {
	var out []string
	depth, quoted, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// cutLast は最後の sep で分ける (式の中の " as " を拾わない)。
func cutLast(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
