package account_test

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/CircleAround/arata/internal/collect/account"
)

func geo() waftypes.Statement {
	return waftypes.Statement{GeoMatchStatement: &waftypes.GeoMatchStatement{CountryCodes: []waftypes.CountryCode{"JP"}}}
}

func ipSet() waftypes.Statement {
	return waftypes.Statement{IPSetReferenceStatement: &waftypes.IPSetReferenceStatement{ARN: aws.String("arn:aws:wafv2:ap-northeast-1:123456789012:regional/ipset/example/abc")}}
}

func hostMatch(name string) waftypes.Statement {
	return waftypes.Statement{ByteMatchStatement: &waftypes.ByteMatchStatement{FieldToMatch: &waftypes.FieldToMatch{SingleHeader: &waftypes.SingleHeader{Name: aws.String(name)}},
		PositionalConstraint: waftypes.PositionalConstraintExactly, SearchString: []byte("example.com")}}
}

func pathMatch(p string) waftypes.Statement {
	return waftypes.Statement{ByteMatchStatement: &waftypes.ByteMatchStatement{FieldToMatch: &waftypes.FieldToMatch{UriPath: &waftypes.UriPath{}},
		PositionalConstraint: waftypes.PositionalConstraintStartsWith, SearchString: []byte(p)}}
}

func pathRegex() waftypes.Statement {
	return waftypes.Statement{RegexMatchStatement: &waftypes.RegexMatchStatement{FieldToMatch: &waftypes.FieldToMatch{UriPath: &waftypes.UriPath{}}, RegexString: aws.String("^/wp-")}}
}

func pathRegexSet() waftypes.Statement {
	return waftypes.Statement{RegexPatternSetReferenceStatement: &waftypes.RegexPatternSetReferenceStatement{FieldToMatch: &waftypes.FieldToMatch{UriPath: &waftypes.UriPath{}}}}
}

func sqli() waftypes.Statement {
	return waftypes.Statement{SqliMatchStatement: &waftypes.SqliMatchStatement{FieldToMatch: &waftypes.FieldToMatch{Body: &waftypes.Body{}}}}
}

func queryMatch() waftypes.Statement {
	return waftypes.Statement{ByteMatchStatement: &waftypes.ByteMatchStatement{FieldToMatch: &waftypes.FieldToMatch{QueryString: &waftypes.QueryString{}},
		PositionalConstraint: waftypes.PositionalConstraintContains, SearchString: []byte("debug")}}
}

func and(s ...waftypes.Statement) waftypes.Statement {
	return waftypes.Statement{AndStatement: &waftypes.AndStatement{Statements: s}}
}

func or(s ...waftypes.Statement) waftypes.Statement {
	return waftypes.Statement{OrStatement: &waftypes.OrStatement{Statements: s}}
}

func not(s waftypes.Statement) waftypes.Statement {
	return waftypes.Statement{NotStatement: &waftypes.NotStatement{Statement: &s}}
}

// 決定 (ADR 0084): 自作のルールの文を、前提で止めるもの (国・IP セット・Host 名) か、パスだけで止めるものか、それ以外かに分ける。
// And・Or・Not は De Morgan で見る (Not の下の Or は And、Not の下の And は Or)。
func TestWAFStatementBasis(t *testing.T) {
	for _, tc := range []struct {
		name  string
		st    *waftypes.Statement
		basis string
		kinds string
	}{
		{"国", ptr(geo()), account.WAFBasisPremise, "geo_match"},
		{"IP セット", ptr(ipSet()), account.WAFBasisPremise, "ip_set"},
		{"Host ヘッダー", ptr(hostMatch("host")), account.WAFBasisPremise, "host_match"},
		{"Host ヘッダー (大文字)", ptr(hostMatch("Host")), account.WAFBasisPremise, "host_match"},
		{"Host 以外のヘッダー", ptr(hostMatch("x-forwarded-host")), account.WAFBasisOther, "byte_match"},
		{"パス (ByteMatch)", ptr(pathMatch("/admin")), account.WAFBasisPath, "uri_path_match"},
		{"パス (RegexMatch)", ptr(pathRegex()), account.WAFBasisPath, "uri_path_match"},
		{"パス (RegexPatternSet)", ptr(pathRegexSet()), account.WAFBasisPath, "uri_path_match"},
		{"パスの組み合わせ", ptr(or(pathMatch("/admin"), and(pathRegex(), not(pathMatch("/admin/health"))))), account.WAFBasisPath, "uri_path_match"},
		{"SQLi", ptr(sqli()), account.WAFBasisOther, "sqli_match"},
		{"パスと SQLi", ptr(and(pathMatch("/api/"), sqli())), account.WAFBasisOther, "sqli_match,uri_path_match"},
		{"クエリ", ptr(queryMatch()), account.WAFBasisOther, "byte_match"},
		// And の中に前提が 1 つでもあれば前提 (前提の条件が当たらなければ止めない)
		{"And(国, パス)", ptr(and(geo(), pathMatch("/admin"))), account.WAFBasisPremise, "geo_match,uri_path_match"},
		{"And(パス, Not(IP セット))", ptr(and(pathMatch("/admin"), not(ipSet()))), account.WAFBasisPremise, "ip_set,uri_path_match"},
		{"Not(Host)", ptr(not(hostMatch("host"))), account.WAFBasisPremise, "host_match"},
		// Or の中で前提が一部だけ: パスの照合で止めた可能性がある → 前提の一部 (提案しない。判断できない)
		{"Or(国, パス)", ptr(or(geo(), pathMatch("/admin"))), account.WAFBasisPremisePartial, "geo_match,uri_path_match"},
		{"Or(国, IP セット)", ptr(or(geo(), ipSet())), account.WAFBasisPremise, "geo_match,ip_set"},
		// Not(And(国, パス)) = Or(Not 国, Not パス) → 一部
		{"Not(And(国, パス))", ptr(not(and(geo(), pathMatch("/admin")))), account.WAFBasisPremisePartial, "geo_match,uri_path_match"},
		// Not(Or(国, パス)) = And(Not 国, Not パス) → 前提
		{"Not(Or(国, パス))", ptr(not(or(geo(), pathMatch("/admin")))), account.WAFBasisPremise, "geo_match,uri_path_match"},
		{"And(Or(国, パス), SQLi)", ptr(and(or(geo(), pathMatch("/x")), sqli())), account.WAFBasisPremisePartial, "geo_match,sqli_match,uri_path_match"},
		{"And(Or(国, パス), IP セット)", ptr(and(or(geo(), pathMatch("/x")), ipSet())), account.WAFBasisPremise, "geo_match,ip_set,uri_path_match"},
		// 読めない文は不明 (提案しない側)
		{"空の文", &waftypes.Statement{}, account.WAFBasisUnknown, "unknown"},
		{"文が無い", nil, account.WAFBasisUnknown, "unknown"},
		{"空の And", ptr(and()), account.WAFBasisUnknown, "unknown"},
		{"中身の無い Not", &waftypes.Statement{NotStatement: &waftypes.NotStatement{}}, account.WAFBasisUnknown, "unknown"},
		{"FieldToMatch が無い", &waftypes.Statement{ByteMatchStatement: &waftypes.ByteMatchStatement{}}, account.WAFBasisUnknown, "unknown"},
		{"And(パス, 不明)", ptr(and(pathMatch("/x"), waftypes.Statement{})), account.WAFBasisUnknown, "unknown,uri_path_match"},
		{"And(国, 不明)", ptr(and(geo(), waftypes.Statement{})), account.WAFBasisPremise, "geo_match,unknown"},
		{"Or(国, 不明)", ptr(or(geo(), waftypes.Statement{})), account.WAFBasisPremisePartial, "geo_match,unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			basis, kinds := account.WAFStatementBasis(tc.st)
			if basis != tc.basis || strings.Join(kinds, ",") != tc.kinds {
				t.Fatalf("got %s %v, want %s %s", basis, kinds, tc.basis, tc.kinds)
			}
		})
	}
}

// 深すぎる入れ子は読まずに不明にする (スタックを使い切らない)。
func TestWAFStatementBasisDeep(t *testing.T) {
	st := geo()
	for i := 0; i < 1000; i++ {
		st = not(st)
	}
	if basis, _ := account.WAFStatementBasis(&st); basis != account.WAFBasisUnknown {
		t.Fatalf("got %s", basis)
	}
}

// wafTree はファズの入力のバイト列から文の木を作る。葉の分類 (前提を含むか・すべてパスか) も返す。
type wafTree struct {
	data []byte
	pos  int
}

func (w *wafTree) next() byte {
	if w.pos >= len(w.data) {
		return 0
	}
	b := w.data[w.pos]
	w.pos++
	return b
}

func (w *wafTree) build(depth int) (st waftypes.Statement, premise, allPath bool) {
	b := w.next()
	if depth < 8 {
		switch b % 12 {
		case 9, 10:
			n := int(w.next()%4) + 1
			var children []waftypes.Statement
			allPath = true
			for i := 0; i < n; i++ {
				c, p, a := w.build(depth + 1)
				children = append(children, c)
				premise = premise || p
				allPath = allPath && a
			}
			if b%12 == 9 {
				return and(children...), premise, allPath
			}
			return or(children...), premise, allPath
		case 11:
			c, p, a := w.build(depth + 1)
			return not(c), p, a
		}
	}
	switch b % 9 {
	case 0:
		return geo(), true, false
	case 1:
		return ipSet(), true, false
	case 2:
		return hostMatch("Host"), true, false
	case 3:
		return pathMatch("/x"), false, true
	case 4:
		return pathRegex(), false, true
	case 5:
		return sqli(), false, false
	case 6:
		return queryMatch(), false, false
	case 7:
		return waftypes.Statement{}, false, false
	}
	name := string(w.data[w.pos:])
	return hostMatch(name), strings.EqualFold(strings.TrimSpace(name), "host"), false
}

// ファズテスト (ADR 0041・0084)。ルールの文は利用者が決める (WebACL の設定)。どんな木でもパニックせず、決まった値を返し、
// 規則を守る: 前提の葉を含む木だけが前提 (か一部)、パスの葉だけの木はパス、Not を 2 つ重ねても変わらない。
func FuzzWAFStatementBasis(f *testing.F) {
	for _, s := range []string{"", "\x00", "\x09\x02\x00\x03", "\x0a\x02\x00\x03", "\x0b\x09\x01\x00\x03", "\x0b\x0b\x0a\x03\x00\x01\x02\x07", "\x08host", "\x08 HOST ", "\x08x-host"} {
		f.Add([]byte(s))
	}
	valid := map[string]bool{account.WAFBasisPremise: true, account.WAFBasisPremisePartial: true, account.WAFBasisPath: true, account.WAFBasisOther: true, account.WAFBasisUnknown: true}
	f.Fuzz(func(t *testing.T, data []byte) {
		w := &wafTree{data: data}
		st, premise, allPath := w.build(0)
		basis, kinds := account.WAFStatementBasis(&st)
		if !valid[basis] || len(kinds) == 0 {
			t.Fatalf("basis %q kinds %v", basis, kinds)
		}
		isPremise := basis == account.WAFBasisPremise || basis == account.WAFBasisPremisePartial
		if isPremise != premise {
			t.Fatalf("前提の葉 %v なのに %s (%v)", premise, basis, kinds)
		}
		if allPath != (basis == account.WAFBasisPath) {
			t.Fatalf("パスだけ %v なのに %s (%v)", allPath, basis, kinds)
		}
		if b2, _ := account.WAFStatementBasis(ptr(not(not(st)))); b2 != basis {
			t.Fatalf("Not Not で %s → %s", basis, b2)
		}
	})
}
