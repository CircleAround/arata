package config

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// railsRequest は Rails の既定のログ (Logger の既定の formatter + log_tags = [:request_id]) の見本の設定。docs/ai/logs.md と同じ。
const railsRequest = `    format: request_lines
    request:
      id: '(?:^| -- : )\[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] '
      lines:
        - name: started
          regex: 'Started (?P<method>[A-Z]+) "(?P<path>[^"?]*)[^"]*" for (?P<ip>\S+) at '
        - name: completed
          regex: 'Completed (?P<status>\d{3}) '
        - name: no_route
          regex: 'ActionController::RoutingError'
          set: { status: 404 }
`

func TestRequestLinesSource(t *testing.T) {
	cfg, err := Load(write(t, logsSource(railsRequest)))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Sources[len(cfg.Sources)-1]
	if s.Format != FormatRequestLines || s.Yields != YieldsHTTPAccess {
		t.Fatalf("format / yields: %+v", s)
	}
	// 既定値: 余白 60 秒、まとめられた割合の下限 0.8
	if s.Request.MaxDuration != 60*time.Second || s.ExpectedCompleteRate != 0.8 || s.ExpectedMatchRate != 0.8 {
		t.Fatalf("defaults: max_duration=%s complete=%v match=%v", s.Request.MaxDuration, s.ExpectedCompleteRate, s.ExpectedMatchRate)
	}
	groups, err := s.Request.Groups()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(groups[0], ","); got != "method,path,ip" || len(groups[1]) != 1 || len(groups[2]) != 0 {
		t.Fatalf("groups: %v", groups)
	}

	cfg, err = Load(write(t, logsSource(railsRequest+"      max_duration: 5m\n    expected_complete_rate: 0.5\n")))
	if err != nil {
		t.Fatal(err)
	}
	s = cfg.Sources[len(cfg.Sources)-1]
	if s.Request.MaxDuration != 5*time.Minute || s.ExpectedCompleteRate != 0.5 {
		t.Fatalf("explicit: %+v", s)
	}
	if cfg, err = Load(write(t, logsSource(railsRequest+"      max_duration: 0s\n"))); err != nil || cfg.Sources[len(cfg.Sources)-1].Request.MaxDuration != 0 {
		t.Fatalf("max_duration 0: %v", err)
	}
}

func TestRequestLinesInvalid(t *testing.T) {
	id := `      id: ' -- : \[(?P<request_id>[A-Za-z0-9-]{1,255})\] '` + "\n"
	started := `        - { name: started, regex: 'Started (?P<method>[A-Z]+) "(?P<path>[^"]*)" for (?P<ip>\S+) at ' }` + "\n"
	head := "    format: request_lines\n    request:\n"
	cases := []struct{ name, body, want string }{
		{"request が無い", "    format: request_lines\n", "request is required"},
		{"別の形式に request", "    format: nginx_access\n    request:\n" + id + "      lines:\n" + started, "only for format request_lines"},
		{"別の形式に expected_complete_rate", "    format: nginx_access\n    expected_complete_rate: 0.5\n", "only for format request_lines"},
		{"regex と併用", head + id + "      lines:\n" + started + "    regex: '(?P<ip>\\S+) (?P<path>\\S+)'\n", "regex is only for format regex"},
		{"id が無い", head + "      lines:\n" + started, "request.id"},
		{"id に request_id が無い", head + "      id: '\\[(?P<rid>\\w+)\\]'\n      lines:\n" + started, "request_id"},
		{"id に別のキャプチャ", head + "      id: '\\[(?P<request_id>\\w+)\\] (?P<ip>\\S+)'\n      lines:\n" + started, "only (?P<request_id>"},
		{"id が RE2 で読めない", head + "      id: '(?<=x)\\[(?P<request_id>\\w+)\\]'\n      lines:\n" + started, "request.id"},
		{"lines が無い", head + id, "request.lines"},
		{"知らないキャプチャ", head + id + "      lines:\n" + started + "        - { name: params, regex: 'Parameters: (?P<params>.*)' }\n", `unknown capture "params"`},
		{"ユーザー ID は lines に書けない (request.user_id に書く)", head + id + "      lines:\n" + started + "        - { name: actor, regex: 'actor id=(?P<user_id>\\d+)' }\n", `unknown capture "user_id"`},
		{"lines に request_id", head + id + "      lines:\n" + started + "        - { name: x, regex: '\\[(?P<request_id>\\w+)\\]' }\n", `unknown capture "request_id"`},
		{"同じ項目を 2 つの行で", head + id + "      lines:\n" + started + "        - { name: again, regex: 'Processing (?P<method>[A-Z]+)' }\n", "method is captured by both"},
		{"ip と path が別の行", head + id + "      lines:\n        - { name: a, regex: 'for (?P<ip>\\S+)' }\n        - { name: b, regex: 'path=(?P<path>\\S+)' }\n", "same line"},
		{"ip が無い", head + id + "      lines:\n        - { name: a, regex: 'Started \"(?P<path>[^\"]*)\"' }\n", "ip"},
		{"名前の重複", head + id + "      lines:\n" + started + "        - { name: started, regex: 'Completed (?P<status>\\d{3})' }\n", "duplicate"},
		{"名前の形", head + id + "      lines:\n" + started + "        - { name: 'a b', regex: 'Completed (?P<status>\\d{3})' }\n", "name"},
		{"何も取り出さない行", head + id + "      lines:\n" + started + "        - { name: noop, regex: 'Rendered' }\n", "captures nothing"},
		{"set に status 以外", head + id + "      lines:\n" + started + "        - { name: c, regex: 'Completed (?P<status>\\d{3})' }\n        - { name: x, regex: 'RoutingError', set: { path: 1 } }\n", "set: only status"},
		{"set の status の範囲", head + id + "      lines:\n" + started + "        - { name: c, regex: 'Completed (?P<status>\\d{3})' }\n        - { name: x, regex: 'RoutingError', set: { status: 99 } }\n", "100-599"},
		{"set が 2 つの行に", head + id + "      lines:\n" + started + "        - { name: c, regex: 'Completed (?P<status>\\d{3})' }\n        - { name: x, regex: 'RoutingError', set: { status: 404 } }\n        - { name: y, regex: 'Timeout', set: { status: 504 } }\n", "only one line can set status"},
		{"set だけで status の行が無い", head + id + "      lines:\n" + started + "        - { name: x, regex: 'RoutingError', set: { status: 404 } }\n", "needs a line that captures status"},
		{"行の正規表現が読めない", head + id + "      lines:\n" + started + "        - { name: c, regex: 'Completed (?P<status>\\d{3}' }\n", "regex"},
		{"max_duration が長い", head + id + "      max_duration: 2h\n      lines:\n" + started, "max_duration"},
		{"max_duration が負", head + id + "      max_duration: -1s\n      lines:\n" + started, "max_duration"},
		{"expected_complete_rate の範囲", head + id + "      lines:\n" + started + "    expected_complete_rate: 1.5\n", "expected_complete_rate"},
		{"yields", head + id + "      lines:\n" + started + "    yields: waf_action\n", "cannot yield"},
	}
	for _, c := range cases {
		_, err := Load(write(t, logsSource(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
	// 行の種類の数と正規表現の長さの上限 (Insights のクエリの長さに収める)
	var many strings.Builder
	many.WriteString(head + id + "      lines:\n" + started)
	for i := 0; i < MaxRequestLines; i++ {
		many.WriteString("        - { name: x" + string(rune('a'+i)) + ", regex: 'Completed (?P<status>\\d{3})' }\n")
	}
	if _, err := Load(write(t, logsSource(many.String()))); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many lines: %v", err)
	}
	long := head + "      id: '\\[(?P<request_id>" + strings.Repeat("a", MaxRequestRegexLen) + ")\\]'\n      lines:\n" + started
	if _, err := Load(write(t, logsSource(long))); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long regex: %v", err)
	}
}

// 設定の request: (利用者のファイル。LLM が書く) の検証 (ADR 0041・0051)。
// 守る規則: 受け付けた設定は、鍵の正規表現に request_id だけ、行の正規表現に決まった名前のキャプチャだけを持ち、どれも RE2 で読め、
// ip と path は同じ行にあり、同じ項目を 2 つの行が取り出さず、set は 100〜599 の status だけ。
func FuzzRequestValidate(f *testing.F) {
	f.Add(`(?:^| -- : )\[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] `, `Started (?P<method>[A-Z]+) "(?P<path>[^"?]*)[^"]*" for (?P<ip>\S+) at `, `Completed (?P<status>\d{3}) `, `ActionController::RoutingError`, 404)
	f.Add(`\[(?<request_id>\w+)\]`, `(?<ip>\S+) (?<path>\S+)`, `(?P<status>\d+)`, `x`, 99)
	f.Add(`\[(?P<request_id>\w+)\] (?P<ip>\S+)`, `(?P<ip>\S+) (?P<path>\S+) (?P<params>.*)`, `(?P<ip>\d+)`, `(`, 600)
	f.Add(`(?P<request_id>`, `\(?P<ip>\S+) (?P<path>/)`, `[(?P<status>x)]`, `(?P<request_id>a)`, 0)
	f.Add("", "", "", "", -1)
	f.Fuzz(func(t *testing.T, id, first, second, third string, status int) {
		r := &Request{ID: id, Lines: []RequestLine{{Name: "a", Regex: first}, {Name: "b", Regex: second}, {Name: "c", Regex: third, Set: map[string]int{"status": status}}}}
		groups, err := r.Groups()
		if err != nil {
			return
		}
		re, cerr := regexp.Compile(id)
		if cerr != nil {
			t.Fatalf("RE2 で読めない鍵を受け付けた: %q", id)
		}
		var names []string
		for _, n := range re.SubexpNames() {
			if n != "" {
				names = append(names, n)
			}
		}
		if len(names) != 1 || names[0] != RequestIDCapture {
			t.Fatalf("鍵のキャプチャが request_id だけでない: %q %v", id, names)
		}
		if len(id) > MaxRequestRegexLen || len(first) > MaxRequestRegexLen {
			t.Fatalf("長すぎる正規表現を受け付けた")
		}
		seen := map[string]int{}
		for i, g := range groups {
			if _, err := regexp.Compile(r.Lines[i].Regex); err != nil {
				t.Fatalf("RE2 で読めない行を受け付けた: %q", r.Lines[i].Regex)
			}
			for _, n := range g {
				if !contains(RequestLineFields, n) {
					t.Fatalf("知らないキャプチャ %q を受け付けた", n)
				}
				if j, dup := seen[n]; dup {
					t.Fatalf("項目 %s を行 %d と %d の両方が取り出す設定を受け付けた", n, j, i)
				}
				seen[n] = i
			}
		}
		ip, okIP := seen["ip"]
		path, okPath := seen["path"]
		if !okIP || !okPath || ip != path {
			t.Fatalf("ip と path が同じ行に無い設定を受け付けた: %v", groups)
		}
		if _, ok := seen["status"]; !ok || status < 100 || status > 599 {
			t.Fatalf("set の status を検証せずに受け付けた: status=%d %v", status, groups)
		}
	})
}
