package config

import (
	"fmt"
	"regexp"
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
	_, err := s.Request.Groups()
	return err
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
