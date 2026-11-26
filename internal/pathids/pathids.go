// Package pathids はパスの型 (ID の位置をまとめたパスの形) の規則 (ソースの設定 `path_ids`。ADR 0071 の 2 節・0087 の 5・6 節) を持つ。
//
// 同じ規則を 2 か所で使う。
//   - Normalize: Go の正規化 (テストの基準・doctor)。パスから型と対象 ID を作る
//   - Query: Logs Insights の中で同じ型と対象 ID を組み立てる文 (Insights には正規表現の置換が無いので、parse・coalesce・if・concat で組む)
//
// 2 つが同じ結果になることは、偽の Insights (cwlogstest.Sim) で表のテストとファズが固定する (equiv_test.go)。
//
// 型を作る順:
//  1. クエリ (`?`) とフラグメント (`#`) から後ろを落とす
//  2. 最後の区間の末尾の `.<拡張子>` を、拡張子が formats にあるときだけ 1 つ外す
//  3. / で始まらないパスは型を持たない (空の型)
//  4. templates に当たれば、その型 (先頭から試し、最初に当たったもの)。`:id` の位置の値が対象 ID、`:any` の位置の値は捨てる
//  5. 当たらなければ、区間ごとに segments のどれかに全体が当たれば `:id`、当たらなければそのまま。max_segments より深い区間は `/…` にまとめる
//  6. ID でない区間が個人に結び付きうる形 (メールアドレスらしい・数字を含み 16 文字以上・32 文字より長い・印に紛れる形) なら `:x` に伏せる (Sanitize)
//
// 決定: Insights の中では、型の印を `?id`・`?any`・`?more` で書き、Go の側 (Sanitize) で `:id`・`:any`・`…` に直す。
// `?` は 1 でクエリとして落ちるので、ログのパスの区間に現れない。ログの値 (攻撃者が作れる) で印を偽れない (`/orders/:id` という生のパスは `/orders/:x` になる)。
package pathids

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/record"
)

// 上限 (ADR 0071 の 2 節・0087 の 5・6 節。Insights のクエリの文の長さ 10,000 文字に収める)。
const (
	MaxSegmentRules = 8
	MaxTemplates    = 50
	MaxMaxSegments  = 12
	MaxFormats      = 20
	// MaxRegexLen は segments の正規表現 1 つの長さの上限。
	MaxRegexLen = 256
	// MaxQueryLen は Query が組み立てる文の長さの上限。残り (request_lines の 1 段目と集計) のために 4,000 文字を空けておく。
	// 決定: 型 13・区間の規則 2 つ (数字と UUID)・max_segments 12・formats 5 つで約 5,200 文字。組み上げたクエリ全体の長さは、そのクエリを作る側も確かめる
	MaxQueryLen = 6000
	// maxLiteralLen は型に残す (伏せない) 区間の長さの上限。
	maxLiteralLen = 32
	// maxDigitLiteralLen は数字を含む区間を伏せない長さの上限 (これ以上は :x)。
	maxDigitLiteralLen = 15
)

// 型の印。
const (
	ID   = ":id"
	Any  = ":any"
	X    = ":x" // 伏せた区間
	More = "…"  // max_segments より深い区間
)

// Insights の中で使う印 (Sanitize が上の印に直す)。
const (
	rawID   = "?id"
	rawAny  = "?any"
	rawMore = "?more"
)

// Rules は設定の path_ids。
type Rules struct {
	Segments    []string
	Templates   []string
	Formats     []string
	MaxSegments int
}

// Compiled は検証済みの規則。
type Compiled struct {
	rules     Rules
	segRes    []*regexp.Regexp // ^(?:<re>)$
	templates [][]string       // 区間 (`:id`・`:any`・固定の文字)
	query     string
}

var (
	formatRe          = regexp.MustCompile(`^[a-z0-9]{1,8}$`)
	templateLiteralRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,32}$`)
)

// Compile は規則を検証する。誤りの文は設定の項目の名前で始まる。
func Compile(r Rules) (*Compiled, error) {
	if r.MaxSegments < 1 || r.MaxSegments > MaxMaxSegments {
		return nil, fmt.Errorf("max_segments %d: want 1 to %d (required)", r.MaxSegments, MaxMaxSegments)
	}
	if len(r.Segments) == 0 && len(r.Templates) == 0 {
		return nil, fmt.Errorf("write segments or templates (or both)")
	}
	if len(r.Segments) > MaxSegmentRules {
		return nil, fmt.Errorf("segments: at most %d, got %d", MaxSegmentRules, len(r.Segments))
	}
	if len(r.Templates) > MaxTemplates {
		return nil, fmt.Errorf("templates: at most %d, got %d", MaxTemplates, len(r.Templates))
	}
	if len(r.Formats) > MaxFormats {
		return nil, fmt.Errorf("formats: at most %d, got %d", MaxFormats, len(r.Formats))
	}
	c := &Compiled{rules: r}
	seen := map[string]bool{}
	for _, s := range r.Segments {
		if err := checkSegmentRegex(s); err != nil {
			return nil, fmt.Errorf("segments %q: %w", s, err)
		}
		if seen[s] {
			return nil, fmt.Errorf("segments %q: duplicate", s)
		}
		seen[s] = true
		c.segRes = append(c.segRes, regexp.MustCompile(`^(?:`+s+`)$`))
	}
	seen = map[string]bool{}
	for _, t := range r.Templates {
		segs, err := parseTemplate(t)
		if err != nil {
			return nil, fmt.Errorf("templates %q: %w", t, err)
		}
		if len(segs) > r.MaxSegments {
			return nil, fmt.Errorf("templates %q: %d segments, deeper than max_segments %d", t, len(segs), r.MaxSegments)
		}
		if seen[t] {
			return nil, fmt.Errorf("templates %q: duplicate", t)
		}
		seen[t] = true
		c.templates = append(c.templates, segs)
	}
	seen = map[string]bool{}
	for _, f := range r.Formats {
		if !formatRe.MatchString(f) {
			return nil, fmt.Errorf("formats %q: want 1 to 8 lowercase letters or digits (no dot)", f)
		}
		if seen[f] {
			return nil, fmt.Errorf("formats %q: duplicate", f)
		}
		seen[f] = true
	}
	c.query = c.buildQuery()
	if n := len(c.query); n > MaxQueryLen {
		return nil, fmt.Errorf("the Logs Insights query built from path_ids is %d characters (at most %d): write fewer or shorter segments / templates, or lower max_segments", n, MaxQueryLen)
	}
	return c, nil
}

// checkSegmentRegex は segments の正規表現 1 つを確かめる。
// 決定: `/` と改行は書けない (区間は / を含まず、Insights の /.../ の区切りを抜け出させない)。名前付きキャプチャは書けない (一時フィールドと紛れる)。
// ^ $ は arata が付けるので書けない (中に書くと、付けた ^ $ と合わせて何にも当たらない)。空の文字列に当たる正規表現は誤り (空の区間を ID にしない)。
func checkSegmentRegex(s string) error {
	switch {
	case len(s) > MaxRegexLen:
		return fmt.Errorf("too long (at most %d characters)", MaxRegexLen)
	case strings.ContainsAny(s, "\r\n"):
		return fmt.Errorf("must not contain a newline")
	case strings.Contains(s, "/"):
		return fmt.Errorf("must not contain / (a segment never contains /)")
	case strings.Contains(s, `\Q`):
		// ファズで見つけた: \Q は \E が無ければ終わりまでを文字どおりにし、arata が包む括弧と ^ $ を飲み込む
		return fmt.Errorf(`must not contain \Q (write the characters escaped instead)`)
	}
	tree, err := syntax.Parse(s, syntax.Perl)
	if err != nil {
		return fmt.Errorf("not RE2: %w", err)
	}
	var bad error
	var walk func(*syntax.Regexp)
	walk = func(re *syntax.Regexp) {
		switch re.Op {
		case syntax.OpCapture:
			// 決定: 名前の無いキャプチャも禁止する。Insights の parse が名前の無いグループをどう扱うかは確かめていない (まとめるだけなら (?:...) で書ける)
			switch {
			case bad != nil:
			case re.Name != "":
				bad = fmt.Errorf("named captures are not allowed")
			default:
				bad = fmt.Errorf("capturing groups ( ) are not allowed: write (?:...) to group")
			}
		case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
			if bad == nil {
				bad = fmt.Errorf("anchors (^ $ \\A \\z \\b) are not allowed: arata matches the whole segment")
			}
		}
		for _, sub := range re.Sub {
			walk(sub)
		}
	}
	walk(tree)
	if bad != nil {
		return bad
	}
	wrapped, err := regexp.Compile(`^(?:` + s + `)$`)
	if err != nil {
		return fmt.Errorf("not RE2 inside (?:...): %w", err)
	}
	if wrapped.MatchString("") {
		return fmt.Errorf("matches the empty string (an empty segment is never an ID)")
	}
	return nil
}

// parseTemplate は型 1 つを区間に分ける。
// 決定 (ADR 0087 の 5 節): `:id` か `:any` が 1 つ以上要る。固定の区間も 1 つ以上要る (`/:any/:any` はその深さのパスをすべて 1 つにまとめる)。
// 固定の区間は英数字と `._~-` の 32 文字まで (Insights の文に入れる。数字を含む 16 文字以上は Sanitize が伏せる形なので書けない)。
func parseTemplate(t string) ([]string, error) {
	if !strings.HasPrefix(t, "/") {
		return nil, fmt.Errorf("must start with /")
	}
	segs := strings.Split(t[1:], "/")
	holes, fixed := 0, 0
	for _, s := range segs {
		switch {
		case s == ID || s == Any:
			holes++
		case templateLiteralRe.MatchString(s) && !digitLong(s):
			fixed++
		default:
			return nil, fmt.Errorf("segment %q: want :id, :any or a fixed segment (letters, digits and ._~-, up to 32; with a digit, up to 15)", s)
		}
	}
	if holes == 0 {
		return nil, fmt.Errorf("needs :id or :any (a template without them changes nothing)")
	}
	if fixed == 0 {
		return nil, fmt.Errorf("needs a fixed segment (a template of only :id / :any merges every path of that depth)")
	}
	return segs, nil
}

func digitLong(s string) bool {
	return len(s) > maxDigitLiteralLen && strings.ContainsAny(s, "0123456789")
}

// Rules は検証した規則。
func (c *Compiled) Rules() Rules { return c.rules }

// IsFixed は s が設定の templates のどれかの固定の区間か (`:id`・`:any` は含まない)。設定の値なので、ログ由来の値と違い、出してよい。
func (c *Compiled) IsFixed(s string) bool {
	if c == nil || s == "" {
		return false
	}
	for _, t := range c.templates {
		for _, seg := range t {
			if seg == s && seg != ID && seg != Any {
				return true
			}
		}
	}
	return false
}

// Normalize はパスの型と対象 ID (`:id` の位置の値。順に) を返す。型を持たないパスは空の型。
func (c *Compiled) Normalize(p string) (string, []string) {
	raw, ids := c.raw(p)
	return c.Sanitize(raw), ids
}

// raw は Insights の中と同じ印 (?id・?any・?more) の型と対象 ID を作る。
func (c *Compiled) raw(p string) (string, []string) {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for _, f := range c.rules.Formats {
		if strings.HasSuffix(p, "."+f) {
			p = p[:len(p)-len(f)-1]
			break
		}
	}
	if !strings.HasPrefix(p, "/") {
		return "", nil
	}
	segs := strings.Split(p[1:], "/")
	for _, t := range c.templates {
		if ids, ok := matchTemplate(t, segs); ok {
			out := make([]string, len(t))
			for i, s := range t {
				switch s {
				case ID:
					out[i] = rawID
				case Any:
					out[i] = rawAny
				default:
					out[i] = s
				}
			}
			return "/" + strings.Join(out, "/"), ids
		}
	}
	var ids []string
	more := false
	if len(segs) > c.rules.MaxSegments {
		segs, more = segs[:c.rules.MaxSegments], true
	}
	out := make([]string, 0, len(segs)+1)
	for _, s := range segs {
		if c.isID(s) {
			out = append(out, rawID)
			ids = append(ids, s)
			continue
		}
		out = append(out, s)
	}
	if more {
		out = append(out, rawMore)
	}
	return "/" + strings.Join(out, "/"), ids
}

func (c *Compiled) isID(s string) bool {
	for _, re := range c.segRes {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func matchTemplate(t, segs []string) ([]string, bool) {
	if len(t) != len(segs) {
		return nil, false
	}
	var ids []string
	for i, s := range t {
		switch s {
		case ID, Any:
			if segs[i] == "" {
				return nil, false
			}
			if s == ID {
				ids = append(ids, segs[i])
			}
		default:
			if segs[i] != s {
				return nil, false
			}
		}
	}
	return ids, true
}

// IDKey は対象 ID を、Insights の中の対象 ID (区間ごとに / を前に付けてつないだもの) と同じ形にする。ID が無ければ空。
func IDKey(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return "/" + strings.Join(ids, "/")
}

// Sanitize は Insights の中の印の型 (Query の結果。信用しない入力) を、ストアと報告に置ける型にする。
// / で始まらない値は空 (型なし)。区間は max_segments まで (超えた分は … にまとめる)。印でない区間は、置いてよい形でなければ :x に伏せる。
func (c *Compiled) Sanitize(raw string) string {
	if !strings.HasPrefix(raw, "/") {
		return ""
	}
	segs := strings.Split(raw[1:], "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		if i == c.rules.MaxSegments {
			out = append(out, More)
			break
		}
		switch {
		case s == rawID:
			out = append(out, ID)
		case s == rawAny:
			out = append(out, Any)
		case s == rawMore && i == len(segs)-1:
			out = append(out, More)
		case safeLiteral(s):
			out = append(out, s)
		default:
			out = append(out, X)
		}
	}
	return "/" + strings.Join(out, "/")
}

// safeLiteral は ID でない区間を、型にそのまま残してよいか (ADR 0071 の 2 節の規則)。
func safeLiteral(s string) bool {
	if len(s) > maxLiteralLen || digitLong(s) || !utf8.ValidString(s) {
		return false
	}
	if strings.HasPrefix(s, ":") || strings.ContainsAny(s, "?#") || s == More {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return record.MaskEmail(s) == s && !strings.Contains(s, "@")
}

// Insights の一時フィールド。Query が作り、集計が使う (1 段目の earliest など)。
const (
	prefix = "pi_"
	// TemplateField は型 (印は ?id・?any・?more。Sanitize に通してから使う) のフィールド。型を持たない行には無い。
	TemplateField = prefix + "tpl"
	// IDField は対象 ID (IDKey と同じ形) のフィールド。ID の無い型の行には無い。値は Insights の中で異なりを数えるだけに使い、結果に出さない (ADR 0071 の 2 節)。
	IDField = prefix + "id"
)

// Query は、フィールド in (パス) から TemplateField と IDField を作る Insights の文 (`parse …` から始まり、行を "\n| " でつなぐ)。
// 集計の stats の前に置く (request_lines では 1 段目の前。最初の行のパスから作る)。
func (c *Compiled) Query(in string) string {
	return strings.Replace(c.query, inPlaceholder, in, 1)
}

// QueryLen は Query の文の長さ (in の名前を除く)。
func (c *Compiled) QueryLen() int { return len(c.query) - len(inPlaceholder) }

const inPlaceholder = "\x00in\x00"

// buildQuery は Query の文を組み立てる。
//
// 決定 (確かめた事実に合わせる。設計書 2-4・2-5):
//   - 値の分かれ道は parse の名前付きキャプチャで作る (合わない行ではその項目だけが空になる)。選択肢は先頭から試す
//   - if の分岐は定数の文字列だけにする (else に項目を置く if は stats の後で null を返した。stats の前でも頼らない)。
//     取れた値と補いは coalesce(<項目>, if(<条件>, "<値>", "")) の形で書く
//   - concat には空でありうる項目を直に渡さない (無い項目の扱いを確かめていない)。すべて coalesce か if を通す
//   - 最後に、空の型・空の ID を parse で「項目なし」にする (パスの無い行では型も ID も無く、earliest がその行を飛ばす)
//   - 正規表現に . を使わない (改行の扱いが方言で違う)。区間は [^\/]、パスの残りは [^?#] (1 で ? と # の後ろは落ちている)
func (c *Compiled) buildQuery() string {
	var lines []string
	// 1. クエリ・フラグメントと、末尾の形式の拡張子
	if len(c.rules.Formats) > 0 {
		lines = append(lines, "parse "+inPlaceholder+` /^(?<pi_b>[^?#]*?)(?:\.(?:`+strings.Join(c.rules.Formats, "|")+`))?(?:[?#][\s\S]*)?$/`)
	} else {
		lines = append(lines, "parse "+inPlaceholder+` /^(?<pi_b>[^?#]*)/`)
	}
	// 2. templates (当たらなければ pi_r にパス全体)
	var alts, tplParts, idParts []string
	for k, t := range c.templates {
		var re, lit strings.Builder
		j := 0
		for _, s := range t {
			switch s {
			case ID:
				fmt.Fprintf(&re, `(?<%st%d_%d>\/[^\/]+)`, prefix, k, j)
				idParts = append(idParts, fmt.Sprintf(`coalesce(%st%d_%d, "")`, prefix, k, j))
				j++
				lit.WriteString("/" + rawID)
			case Any:
				re.WriteString(`\/[^\/]+`)
				lit.WriteString("/" + rawAny)
			default:
				re.WriteString(`\/` + regexp.QuoteMeta(s))
				lit.WriteString("/" + s)
			}
		}
		alts = append(alts, fmt.Sprintf(`(?<%st%d>%s)`, prefix, k, re.String()))
		tplParts = append(tplParts, fmt.Sprintf(`if(ispresent(%st%d), "%s", "")`, prefix, k, lit.String()))
	}
	alts = append(alts, `(?<pi_r>\/[^?#]*)`)
	lines = append(lines, `parse pi_b /^(?:`+strings.Join(alts, "|")+`)$/`)
	// 3. 区間 (max_segments まで) と、その後ろ
	var split strings.Builder
	for i := 0; i < c.rules.MaxSegments; i++ {
		fmt.Fprintf(&split, `(?<%ss%d>\/[^\/]*)?`, prefix, i)
	}
	lines = append(lines, "parse pi_r /^"+split.String()+`(?<pi_more>\/[^?#]*)?$/`)
	// 4. 区間ごとに ID か
	var segFields []string
	for i := 0; i < c.rules.MaxSegments; i++ {
		if len(c.rules.Segments) == 0 {
			segFields = append(segFields, fmt.Sprintf(`coalesce(%ss%d, "") as %sg%d`, prefix, i, prefix, i))
			continue
		}
		lines = append(lines, fmt.Sprintf(`parse %ss%d /^(?:(?<%sd%d>\/(?:%s))|(?<%sl%d>\/[^\/]*))$/`, prefix, i, prefix, i, strings.Join(c.rules.Segments, "|"), prefix, i))
		segFields = append(segFields, fmt.Sprintf(`coalesce(%sl%d, if(ispresent(%sd%d), "/%s", "")) as %sg%d`, prefix, i, prefix, i, rawID, prefix, i))
		idParts = append(idParts, fmt.Sprintf(`coalesce(%sd%d, "")`, prefix, i))
	}
	lines = append(lines, "fields "+strings.Join(segFields, ", "))
	// 5. 型と対象 ID
	for i := 0; i < c.rules.MaxSegments; i++ {
		tplParts = append(tplParts, fmt.Sprintf("%sg%d", prefix, i))
	}
	tplParts = append(tplParts, `if(ispresent(pi_more), "/`+rawMore+`", "")`)
	if len(idParts) == 0 {
		idParts = append(idParts, `""`)
	}
	lines = append(lines, "fields concat("+strings.Join(tplParts, ", ")+") as pi_tpl0, concat("+strings.Join(idParts, ", ")+") as pi_id0")
	lines = append(lines, `parse pi_tpl0 /^(?<`+TemplateField+`>\/[\s\S]*)$/`, `parse pi_id0 /^(?<`+IDField+`>\/[\s\S]*)$/`)
	return strings.Join(lines, "\n| ")
}
