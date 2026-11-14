package config

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"time"
)

// request_lines 形式 (ADR 0051): 1 リクエストが複数行に分かれるアプリのログを、request_id でリクエスト単位にまとめてから集計する。
// 設定には「まとめる鍵の取り出し方」(request.id) と「行の種類ごとの取り出し方」(request.lines) を書く。
//
// 決定:
//   - 取り出せる項目は決まった名前だけ (RequestLineFields)。知らない名前のキャプチャは CONFIG_INVALID。
//     利用者の入力が入る行 (Parameters など) から任意の値を取り出す設定は書けない
//   - ip と path は同じ行の種類で取り出す。その行を「最初の行」と呼び、リクエストの数はこの行の数で数える
//     (同じ request_id を使い回しても数が減らない。ADR 0051 の 1 節)
//   - 同じ項目を 2 つの行の種類が取り出すことはできない (Insights の一時フィールドは同じ名前を 2 度定義できず、
//     どちらの値を使うかの規則も要る)。行に値が出ないときの補いは set で書く
//   - set で補えるのは status (100〜599) だけで、書ける行の種類は 1 つ。status を取り出す行が別にあり、その値が無いリクエストにだけ効く
//     (経路の無いリクエストは最後の行が出ない)
//   - 行の種類の数と正規表現の長さに上限を置く (Insights のクエリの長さの上限 10000 文字に収める)
const (
	FormatRequestLines = "request_lines"
	// RequestIDCapture は request.id の正規表現が持つ、ただ 1 つの名前付きキャプチャ。
	RequestIDCapture = "request_id"
	// DefaultExpectedCompleteRate は expected_complete_rate (最初の行のあるリクエスト / request_id の数) の既定値。
	DefaultExpectedCompleteRate = 0.8
	// DefaultRequestMaxDuration は request.max_duration (問い合わせ範囲の後ろに足す余白) の既定値。
	DefaultRequestMaxDuration = 60 * time.Second
	// MaxRequestMaxDuration は request.max_duration の上限。
	MaxRequestMaxDuration = time.Hour
	// MaxRequestLines は request.lines に書ける行の種類の数。
	MaxRequestLines = 8
	// MaxRequestRegexLen は request.id と request.lines[].regex の長さの上限。
	MaxRequestRegexLen = 512
)

// RequestLineFields は request.lines の正規表現で取り出せる項目 (名前付きキャプチャの名前)。
var RequestLineFields = []string{"ip", "method", "path", "status", "ua", "duration"}

// Request は request_lines 形式のまとめ方。
type Request struct {
	// ID はまとめる鍵 (request_id) を取り出す正規表現。名前付きキャプチャは (?P<request_id>...) だけ。
	ID string `yaml:"id"`
	// MaxDuration は 1 リクエストの行が出終わるまでの長さの見込み。問い合わせ範囲の後ろにこの長さの余白を足す (既定 60s。0 で足さない)。
	MaxDuration    time.Duration `yaml:"-"`
	MaxDurationRaw string        `yaml:"max_duration"`
	Lines          []RequestLine `yaml:"lines"`
	// UserID はユーザー ID の取り方 (ADR 0051 の 4 節・0052)。書かなければ取らない (from: none と同じ)。
	UserID *RequestUserID `yaml:"user_id"`
	// Auth はログインの結果の行 (auth) の読み方 (ADR 0052)。書かなければ読まない。
	Auth *RequestAuth `yaml:"auth"`
}

// request.user_id.from の値。
const (
	UserIDFromNone = "none"
	// UserIDFromAppLine はアプリが意図して出す 1 行 (actor) を読む。勧める形。
	UserIDFromAppLine = "app_line"
	// UserIDFromDebugSQL は debug レベルの SQL の行を読む。本番の debug のログは誤設定で、直されれば予告なく 0 件になる (doctor が warn を出し続ける)。
	UserIDFromDebugSQL = "debug_sql"
)

// YieldsHTTPUser は、ユーザー ID を取り出す設定のあるソースが http_access に加えて出す種類 (record.KindHTTPUser と同じ文字列)。
const YieldsHTTPUser = "http_user"

// RequestUserFields は request.user_id.regex の名前付きキャプチャ。user_kind と user_id は必須、by_kind と by_id は 2 つとも書くか書かないか。
var RequestUserFields = []string{"user_kind", "user_id", "by_kind", "by_id"}

// RequestAuthFields は request.auth.regex の名前付きキャプチャ。auth_result は必須。
// 決定 (ADR 0052): actor と名前を分ける。2 つの正規表現は同じクエリの中の別の parse になり、Insights は同じ名前の一時フィールドを 2 度定義できない。
var RequestAuthFields = []string{"auth_result", "auth_kind", "auth_id", "auth_via", "auth_by_kind", "auth_by_id", "auth_reason"}

// RequestUserID は request.user_id。
//
// 決定 (ADR 0052):
//   - 正規表現は $ で終える (行の途中の同じ並び = 利用者の入力を、アプリが出した行として読まない)。config check が確かめる
//   - 取り出した値の形 (種類は小文字と _、ID は英数字と _ - の 64 文字まで) は、設定の正規表現がどう書かれていても collector が絞る (cwlogs の user.go)
type RequestUserID struct {
	From  string `yaml:"from"`
	Regex string `yaml:"regex"`
}

// RequestAuth は request.auth。
type RequestAuth struct {
	Regex string `yaml:"regex"`
}

// RequestLine は行の種類 1 つ。
type RequestLine struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
	// Set はこの行があり、項目の値がほかの行から取れなかったリクエストに補う値 (status だけ)。
	Set map[string]int `yaml:"set"`
}

var requestLineName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func (s *Source) applyRequestDefaults() error {
	s.ExpectedCompleteRate = DefaultExpectedCompleteRate
	if s.ExpectedCompleteRateRaw != nil {
		s.ExpectedCompleteRate = *s.ExpectedCompleteRateRaw
	}
	if s.Request == nil {
		return nil
	}
	s.Request.MaxDuration = DefaultRequestMaxDuration
	if raw := s.Request.MaxDurationRaw; raw != "" {
		d, err := parseDelay(raw)
		if err != nil || d > MaxRequestMaxDuration {
			return fmt.Errorf("request.max_duration %q: want a duration from 0s to %s", raw, MaxRequestMaxDuration)
		}
		s.Request.MaxDuration = d
	}
	return nil
}

func (s *Source) validateRequest() error {
	if s.Format != FormatRequestLines {
		if s.Request != nil {
			return fmt.Errorf("request is only for format %s", FormatRequestLines)
		}
		if s.ExpectedCompleteRateRaw != nil {
			return fmt.Errorf("expected_complete_rate is only for format %s", FormatRequestLines)
		}
		return nil
	}
	if s.Request == nil {
		return fmt.Errorf("request is required for format %s", FormatRequestLines)
	}
	if s.ExpectedCompleteRate <= 0 || s.ExpectedCompleteRate > 1 {
		return fmt.Errorf("expected_complete_rate %v: want 0 < rate <= 1", s.ExpectedCompleteRate)
	}
	if _, err := s.Request.Groups(); err != nil {
		return err
	}
	if _, err := s.Request.UserGroups(); err != nil {
		return err
	}
	_, err := s.Request.AuthGroups()
	return err
}

// UserIDFrom はユーザー ID の取り方 (UserIDFrom*)。request_lines でない・書いていないソースは none。
func (s Source) UserIDFrom() string {
	if s.Format != FormatRequestLines || s.Request == nil || s.Request.UserID == nil {
		return UserIDFromNone
	}
	return s.Request.UserID.From
}

// UserGroups は request.user_id を検証し、正規表現の名前付きキャプチャ (正規表現の中の順) を返す。取らない設定 (書いていない・from: none) なら nil。
func (r *Request) UserGroups() ([]string, error) {
	u := r.UserID
	if u == nil {
		return nil, nil
	}
	switch u.From {
	case UserIDFromNone:
		if u.Regex != "" {
			return nil, fmt.Errorf("request.user_id: regex cannot be set with from: none")
		}
		return nil, nil
	case UserIDFromAppLine, UserIDFromDebugSQL:
	default:
		return nil, fmt.Errorf("request.user_id.from %q: want %s, %s or %s", u.From, UserIDFromNone, UserIDFromAppLine, UserIDFromDebugSQL)
	}
	return anchoredGroups("request.user_id", u.Regex, RequestUserFields, []string{"user_kind", "user_id"}, "by_kind", "by_id")
}

// AuthGroups は request.auth を検証し、正規表現の名前付きキャプチャを返す。書いていなければ nil。
func (r *Request) AuthGroups() ([]string, error) {
	if r.Auth == nil {
		return nil, nil
	}
	return anchoredGroups("request.auth", r.Auth.Regex, RequestAuthFields, []string{"auth_result"}, "auth_by_kind", "auth_by_id")
}

// anchoredGroups は、行末まで固定した正規表現を検証する。known 以外の名前は拒否し、required は必ず要り、pairA と pairB は 2 つとも書くか書かないか。
func anchoredGroups(at, expr string, known, required []string, pairA, pairB string) ([]string, error) {
	groups, err := requestRegexNames(at, expr)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if !contains(known, g) {
			return nil, fmt.Errorf("%s: unknown capture %q (want %s)", at, g, strings.Join(known, ", "))
		}
	}
	for _, g := range required {
		if !contains(groups, g) {
			return nil, fmt.Errorf("%s: named capture (?P<%s>...) is required", at, g)
		}
	}
	if contains(groups, pairA) != contains(groups, pairB) {
		return nil, fmt.Errorf("%s: %s and %s must be captured together (or neither)", at, pairA, pairB)
	}
	if !endsAtLineEnd(expr) {
		return nil, fmt.Errorf("%s: regex must end with $ (the whole pattern up to the end of the line; a line that merely contains the same text, e.g. user input, must not match)", at)
	}
	return groups, nil
}

// endsAtLineEnd は、正規表現のどの一致も入力の終わりで終わるか (全体が「…$」の並びで、最後が入力の終わりの $)。
// `\$` (文字の $)・選択の片方だけの $ (`a$|b`)・複数行のフラグ (?m) の $ (行ごとの終わり)・括弧の中の $ は受け付けない。
func endsAtLineEnd(expr string) bool {
	if !strings.HasSuffix(expr, "$") {
		return false
	}
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return false
	}
	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		re = re.Sub[len(re.Sub)-1]
	}
	return re.Op == syntax.OpEndText
}

// Groups は request: を検証し、行の種類ごとの名前付きキャプチャ (正規表現の中の順) を返す。
func (r *Request) Groups() ([][]string, error) {
	names, err := requestRegexNames("request.id", r.ID)
	if err != nil {
		return nil, err
	}
	if len(names) != 1 || names[0] != RequestIDCapture {
		return nil, fmt.Errorf("request.id: want only (?P<%s>...) as a named capture, got %v", RequestIDCapture, names)
	}
	if len(r.Lines) == 0 {
		return nil, fmt.Errorf("request.lines: at least one line is required")
	}
	if len(r.Lines) > MaxRequestLines {
		return nil, fmt.Errorf("request.lines: at most %d lines", MaxRequestLines)
	}
	out := make([][]string, len(r.Lines))
	lineNames := map[string]bool{}
	owner := map[string]int{}
	for i, l := range r.Lines {
		at := fmt.Sprintf("request.lines[%d]", i)
		if !requestLineName.MatchString(l.Name) {
			return nil, fmt.Errorf("%s: name %q: want lower-case letters, digits and _ (up to 32, starting with a letter)", at, l.Name)
		}
		if lineNames[l.Name] {
			return nil, fmt.Errorf("%s: duplicate name %q", at, l.Name)
		}
		lineNames[l.Name] = true
		at = "request.lines." + l.Name
		groups, err := requestRegexNames(at, l.Regex)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			if !contains(RequestLineFields, g) {
				return nil, fmt.Errorf("%s: unknown capture %q (want %s)", at, g, strings.Join(RequestLineFields, ", "))
			}
			if j, dup := owner[g]; dup {
				return nil, fmt.Errorf("%s: %s is captured by both %s and %s (one line per field; use set for a fallback)", at, g, r.Lines[j].Name, l.Name)
			}
			owner[g] = i
		}
		for k, v := range l.Set {
			if k != "status" {
				return nil, fmt.Errorf("%s: set: only status can be set, got %q", at, k)
			}
			if v < 100 || v > 599 {
				return nil, fmt.Errorf("%s: set: status %d: want 100-599", at, v)
			}
		}
		if len(groups) == 0 && len(l.Set) == 0 {
			return nil, fmt.Errorf("%s: the line captures nothing and sets nothing", at)
		}
		out[i] = groups
	}
	ip, okIP := owner["ip"]
	path, okPath := owner["path"]
	if !okIP || !okPath {
		return nil, fmt.Errorf("request.lines: named captures (?P<ip>...) and (?P<path>...) are required for %s", YieldsHTTPAccess)
	}
	if ip != path {
		return nil, fmt.Errorf("request.lines: ip and path must be captured by the same line (the first line of a request; requests are counted by it), got %s and %s",
			r.Lines[ip].Name, r.Lines[path].Name)
	}
	sets := 0
	for _, l := range r.Lines {
		if len(l.Set) == 0 {
			continue
		}
		if _, ok := owner["status"]; !ok {
			return nil, fmt.Errorf("request.lines.%s: set: status needs a line that captures status (set only fills requests that lack it)", l.Name)
		}
		if sets++; sets > 1 {
			return nil, fmt.Errorf("request.lines.%s: set: only one line can set status", l.Name)
		}
	}
	return out, nil
}

// requestRegexNames は正規表現を RE2 で検証し、名前付きキャプチャの名前を返す (同じ名前を 2 度使う表現は拒否する)。
func requestRegexNames(at, expr string) ([]string, error) {
	if expr == "" {
		return nil, fmt.Errorf("%s: regex is required", at)
	}
	if len(expr) > MaxRequestRegexLen {
		return nil, fmt.Errorf("%s: regex is too long (%d > %d)", at, len(expr), MaxRequestRegexLen)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("%s: regex: %w", at, err)
	}
	var names []string
	for _, n := range re.SubexpNames() {
		if n == "" {
			continue
		}
		if contains(names, n) {
			return nil, fmt.Errorf("%s: regex: capture %q is defined twice", at, n)
		}
		names = append(names, n)
	}
	return names, nil
}
