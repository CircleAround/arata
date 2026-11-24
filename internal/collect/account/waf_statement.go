package account

import (
	"sort"
	"strings"

	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// 自作のルール (regular) が何を根拠に止めるか (waf_config の rule 項目の block_basis。ADR 0084)。
const (
	// WAFBasisPremise は前提で止めるルール (国・IP セット・Host 名の照合が、止める条件に必ず効く)。多数の IP を止めるのが意図
	WAFBasisPremise = "premise"
	// WAFBasisPremisePartial は Or の一部だけが前提の条件のルール。パスなどの照合だけで止めた可能性があり、どちらで止めたかは分からない
	WAFBasisPremisePartial = "premise_partial"
	// WAFBasisPath はパス (UriPath の ByteMatch・RegexMatch・RegexPatternSet) の照合だけで止めるルール
	WAFBasisPath = "path"
	// WAFBasisOther はそれ以外 (SQLi・ヘッダー・クエリ・本文・ラベルの照合など、前提の条件を含まないもの)
	WAFBasisOther = "other"
	// WAFBasisUnknown は文を読めなかった (知らない文・欠けた文・深すぎる入れ子)。提案しない側に倒す
	WAFBasisUnknown = "unknown"
)

// 葉の文の種類 (statement_kinds)。
const (
	wafKindGeo      = "geo_match"
	wafKindIPSet    = "ip_set"
	wafKindHost     = "host_match"
	wafKindURIPath  = "uri_path_match"
	wafKindByte     = "byte_match"
	wafKindRegex    = "regex_match"
	wafKindRegexSet = "regex_pattern_set"
	wafKindSize     = "size_constraint"
	wafKindSqli     = "sqli_match"
	wafKindXSS      = "xss_match"
	wafKindLabel    = "label_match"
	wafKindASN      = "asn_match"
	wafKindUnknown  = "unknown"
)

// wafStatementMaxDepth は読む入れ子の深さの上限。超えたら不明にする (AWS の WebACL の容量の上限で実際には浅い)。
const wafStatementMaxDepth = 20

// WAFStatementBasis は自作のルールの文が何を根拠に止めるか (WAFBasis*) と、葉の文の種類 (重複なし・並べ替え済み) を返す。
//
// 決定 (ADR 0084):
//   - 前提の条件 = GeoMatch・IPSetReference・SingleHeader の host (大小文字を問わない) への ByteMatch / RegexMatch / RegexPatternSet。
//     パス = UriPath への ByteMatch / RegexMatch / RegexPatternSet。それ以外の読める葉は other、読めない葉は unknown
//   - And (と Not の下の Or) は、子のどれかが前提なら前提 (前提の条件が当たらなければ止めない)
//   - Or (と Not の下の And) は、子のすべてが前提なら前提、一部なら premise_partial (パスの照合だけで止めた可能性がある)
//   - Not は中の文の And・Or を入れ替えて見る (De Morgan)。葉の分類は Not で変わらない (Not 国も国で止める)
//   - 前提を含まない組み合わせは、不明を含めば不明、すべてパスならパス、他は other
func WAFStatementBasis(st *waftypes.Statement) (string, []string) {
	kinds := map[string]bool{}
	basis := statementBasis(st, false, 0, kinds)
	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return basis, out
}

func statementBasis(st *waftypes.Statement, negated bool, depth int, kinds map[string]bool) string {
	if st == nil || depth > wafStatementMaxDepth {
		kinds[wafKindUnknown] = true
		return WAFBasisUnknown
	}
	var children []waftypes.Statement
	conjunctive := !negated
	switch {
	case st.AndStatement != nil:
		children = st.AndStatement.Statements
	case st.OrStatement != nil:
		children, conjunctive = st.OrStatement.Statements, negated
	case st.NotStatement != nil:
		return statementBasis(st.NotStatement.Statement, !negated, depth+1, kinds)
	default:
		kind, basis := leafBasis(st)
		kinds[kind] = true
		return basis
	}
	if len(children) == 0 {
		kinds[wafKindUnknown] = true
		return WAFBasisUnknown
	}
	got := map[string]int{}
	for i := range children {
		got[statementBasis(&children[i], negated, depth+1, kinds)]++
	}
	switch {
	case conjunctive && got[WAFBasisPremise] > 0, !conjunctive && got[WAFBasisPremise] == len(children):
		return WAFBasisPremise
	case got[WAFBasisPremise] > 0 || got[WAFBasisPremisePartial] > 0:
		return WAFBasisPremisePartial
	case got[WAFBasisUnknown] > 0:
		return WAFBasisUnknown
	case got[WAFBasisPath] == len(children):
		return WAFBasisPath
	}
	return WAFBasisOther
}

// leafBasis は葉の文の種類と分類。
func leafBasis(st *waftypes.Statement) (string, string) {
	switch {
	case st.GeoMatchStatement != nil:
		return wafKindGeo, WAFBasisPremise
	case st.IPSetReferenceStatement != nil:
		return wafKindIPSet, WAFBasisPremise
	case st.ByteMatchStatement != nil:
		return fieldBasis(st.ByteMatchStatement.FieldToMatch, wafKindByte)
	case st.RegexMatchStatement != nil:
		return fieldBasis(st.RegexMatchStatement.FieldToMatch, wafKindRegex)
	case st.RegexPatternSetReferenceStatement != nil:
		return fieldBasis(st.RegexPatternSetReferenceStatement.FieldToMatch, wafKindRegexSet)
	case st.SizeConstraintStatement != nil:
		return wafKindSize, WAFBasisOther
	case st.SqliMatchStatement != nil:
		return wafKindSqli, WAFBasisOther
	case st.XssMatchStatement != nil:
		return wafKindXSS, WAFBasisOther
	case st.LabelMatchStatement != nil:
		return wafKindLabel, WAFBasisOther
	case st.AsnMatchStatement != nil:
		// 決定 (ADR 0084): ASN は前提の対象に入れていない (オーナーの決定の一覧に無い)。意図した BLOCK なら intended_block_rules に書く
		return wafKindASN, WAFBasisOther
	}
	// 知らない文 (SDK が新しい文を足した・レートベースやグループの文が入れ子に現れた) は読めない
	return wafKindUnknown, WAFBasisUnknown
}

// fieldBasis は照合の文の対象 (FieldToMatch) で分ける。UriPath はパス、SingleHeader の host は前提、他は other。
func fieldBasis(f *waftypes.FieldToMatch, other string) (string, string) {
	switch {
	case f == nil:
		return wafKindUnknown, WAFBasisUnknown
	case f.UriPath != nil:
		return wafKindURIPath, WAFBasisPath
	case f.SingleHeader != nil && f.SingleHeader.Name != nil && strings.EqualFold(strings.TrimSpace(*f.SingleHeader.Name), "host"):
		return wafKindHost, WAFBasisPremise
	}
	return other, WAFBasisOther
}
