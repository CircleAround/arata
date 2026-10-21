package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 形式プロファイル名 (設計書 2-1、ADR 0006)。
const (
	FormatNginxAccess = "nginx_access"
	FormatALBAccess   = "alb_access"
	FormatWAFv2       = "wafv2"
	FormatJSON        = "json"
	FormatRegex       = "regex"
)

// 正規化レコードの種類のうち cloudwatch-logs が出せるもの。record パッケージの Kind と同じ文字列。
const (
	YieldsHTTPAccess = "http_access"
	YieldsWAFAction  = "waf_action"
)

// formatYields は形式プロファイルが出せる正規化レコードの種類。先頭が既定。
var formatYields = map[string][]string{
	FormatNginxAccess: {YieldsHTTPAccess},
	FormatALBAccess:   {YieldsHTTPAccess},
	FormatWAFv2:       {YieldsWAFAction},
	FormatJSON:        {YieldsHTTPAccess},
	FormatRegex:       {YieldsHTTPAccess},
}

// RequiredFields は正規化レコードごとの必須フィールド。json の fields と regex の名前付きキャプチャはこれを含む必要がある。
// 決定: http_access は ip と path を必須、method / status / ua / duration は任意 (無ければそのフィールドを使う集計が 0 件になる)。
var RequiredFields = map[string][]string{
	YieldsHTTPAccess: {"ip", "path"},
	YieldsWAFAction:  {"action", "rule", "ip"},
}

// OptionalFields は必須以外に使うフィールド。
var OptionalFields = map[string][]string{
	YieldsHTTPAccess: {"method", "status", "ua", "duration", "time", "user_id"},
}

// DefaultExpectedMatchRate は expected_match_rate の既定値。
const DefaultExpectedMatchRate = 0.8

// Formats は受け付ける形式プロファイル名 (ソート済み)。
func Formats() []string {
	out := make([]string, 0, len(formatYields))
	for f := range formatYields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func (s *Source) applyLogsDefaults() {
	if s.Yields == "" {
		if y := formatYields[s.Format]; len(y) > 0 {
			s.Yields = y[0]
		}
	}
	s.ExpectedMatchRate = DefaultExpectedMatchRate
	if s.ExpectedMatchRateRaw != nil {
		s.ExpectedMatchRate = *s.ExpectedMatchRateRaw
	}
	s.SampleLines = true
	if s.SampleLinesRaw != nil {
		s.SampleLines = *s.SampleLinesRaw
	}
}

func (s *Source) validateLogs() error {
	if s.LogGroup == "" {
		return fmt.Errorf("log_group is required for kind %s", KindCloudWatchLogs)
	}
	if len(s.Regions) != 1 {
		return fmt.Errorf("kind %s takes a single region (region:), got %v", KindCloudWatchLogs, s.Regions)
	}
	ys, ok := formatYields[s.Format]
	if !ok {
		return fmt.Errorf("format %q: want one of %s", s.Format, strings.Join(Formats(), ", "))
	}
	if !contains(ys, s.Yields) {
		return fmt.Errorf("format %s cannot yield %q (want %s)", s.Format, s.Yields, strings.Join(ys, ", "))
	}
	if s.ExpectedMatchRate <= 0 || s.ExpectedMatchRate > 1 {
		return fmt.Errorf("expected_match_rate %v: want 0 < rate <= 1", s.ExpectedMatchRate)
	}
	if s.MaxScanGB < 0 {
		return fmt.Errorf("max_scan_gb must not be negative")
	}
	if s.Format != FormatRegex && s.Regex != "" {
		return fmt.Errorf("regex is only for format regex")
	}
	if s.Format != FormatJSON && len(s.Fields) > 0 {
		return fmt.Errorf("fields is only for format json")
	}
	switch s.Format {
	case FormatJSON:
		known := append(append([]string{}, RequiredFields[s.Yields]...), OptionalFields[s.Yields]...)
		for k := range s.Fields {
			if !contains(known, k) {
				return fmt.Errorf("fields: unknown normalized field %q (want %s)", k, strings.Join(known, ", "))
			}
		}
		for _, f := range RequiredFields[s.Yields] {
			if s.Fields[f] == "" {
				return fmt.Errorf("fields: %s is required for %s", f, s.Yields)
			}
		}
	case FormatRegex:
		if _, err := RegexGroups(s.Regex, s.Yields); err != nil {
			return err
		}
	}
	return nil
}

// RegexGroups は regex プロファイルの正規表現を検証し、名前付きキャプチャの一覧を返す。
// Python 形式 (?P<name>...) と (?<name>...) の両方を受ける。Go (RE2) で解釈できない表現 (後方参照・先読みなど) は
// Logs Insights でも使えないことが多いので、ここで弾く。Insights 側の方言の差は doctor のサンプルクエリで検出する。
func RegexGroups(expr, yields string) ([]string, error) {
	if expr == "" {
		return nil, fmt.Errorf("regex is required for format regex")
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("regex: %w", err)
	}
	var groups []string
	for _, n := range re.SubexpNames() {
		if n != "" {
			groups = append(groups, n)
		}
	}
	for _, f := range RequiredFields[yields] {
		if !contains(groups, f) {
			return nil, fmt.Errorf("regex: named capture (?P<%s>...) is required for %s", f, yields)
		}
	}
	return groups, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
