package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ファズテスト (ADR 0040)。report.json は arata が書いて aratam と人が読む。壊れた・想定外の形の JSON でもパニックせず、
// 読めたものは書き直しても同じになる。ログ由来の値 (summary・data・evidence) は report.md の行を増やせない (ADR 0037)。

func seedFiles(f *testing.F) {
	f.Helper()
	for _, name := range []string{"report.json", "period.json"} {
		b, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, s := range []string{
		`{"findings":{"new":[{"id":"f1","check":"c","severity":"high","summary":"s","data":{"date":"2026-10-21","n":1,"l":[1,"a",null],"m":{"k":"v"}}}]},"proposals":[{"kind":"observation","evidence":{"a":null}},{"kind":"x","evidence":{"b":[1]}}],"coverage":{"formats":[{"match_rate":0.5,"recent_average":null,"truncated":["a"]}],"sources_failed":[{}],"checks_skipped":[{}]},"summary":{"collect_errors":[{"partial":true},{"covered_from":"x"},{}]}}`,
		`{"kind":"period","summary":{"by_severity":{"high":1,"x":-1}},"events":{"new":[{}],"resolved":[{"profile":"daily"}]},"new_principals":[{}],"open":[{}],"metrics":{"metrics":["a","b"],"rows":[{"date":"d","values":[1,1e308,-0]},{"values":null}]},"profiles":[{}],"runs_missing":[{"until":"u","detail":"d"}],"notes":["n"]}`,
		`{"findings":null,"coverage":null}`, `{"findings":{"new":[null]}}`, `[]`, `null`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
}

func FuzzParse(f *testing.F) {
	seedFiles(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := Parse(b); err == nil && r != nil {
			_ = r.Markdown()
			out, err := r.JSON()
			if err != nil {
				t.Fatalf("読めたレポートを書けない: %v", err)
			}
			r2, err := Parse(out)
			if err != nil {
				t.Fatalf("書いたレポートを読めない: %v", err)
			}
			if out2, err := r2.JSON(); err != nil || !bytes.Equal(out, out2) {
				t.Fatalf("書き直すと変わる (%v):\n%s\n---\n%s", err, out, out2)
			}
		}
		var p PeriodReport
		if json.Unmarshal(b, &p) == nil {
			_ = p.Markdown()
			out, err := p.JSON()
			if err != nil {
				t.Fatalf("読めた期間レポートを書けない: %v", err)
			}
			var p2 PeriodReport
			if err := json.Unmarshal(out, &p2); err != nil {
				t.Fatalf("書いた期間レポートを読めない: %v", err)
			}
		}
	})
}

// ログ由来の値がどんな文字列でも、report.md の行数は変わらない (改行で偽の見出しや行を作れない)。
func FuzzMarkdownLogValues(f *testing.F) {
	for _, s := range []string{"x", "/a\n## 偽の見出し", "a\r\n- **[critical]** 偽の指摘", "a\rb", "| a | b |", "`x`", "", "\n"} {
		f.Add(s)
	}
	run := func(v string) string {
		r := &Report{Name: "acme", Profile: "daily"}
		fd := Finding{ID: "f1", Check: "probe_paths", Key: v, Severity: "low", Summary: v, Data: map[string]any{"ip": v, "date": v, "paths": []any{v, v}}}
		r.Findings.New, r.Findings.StillOpen, r.Info = []Finding{fd}, []Finding{fd}, []Finding{fd}
		r.Proposals = []Proposal{{Kind: "false_positive", Stage: "count_first", Path: v, Summary: v, Evidence: map[string]any{"path_group": v, "paths": []any{v}}},
			{Kind: "observation", About: "false_positive", Reason: "below_threshold", Summary: v, Evidence: map[string]any{"p": v}}}
		return r.Markdown()
	}
	period := func(v string) string {
		p := &PeriodReport{Kind: "period", Name: "acme"}
		e := EventRow{At: "2026-10-21T09:00:00Z", FindingID: "f1", Check: "probe_paths", Key: v, Severity: "low", Summary: v}
		p.Events.New, p.Events.Resolved = []EventRow{e}, []EventRow{e}
		p.Open = []Finding{{ID: "f1", Check: "probe_paths", Key: v, Severity: "low", Summary: v}}
		return p.Markdown()
	}
	baseRun, basePeriod := strings.Count(run("x"), "\n"), strings.Count(period("x"), "\n")
	f.Fuzz(func(t *testing.T, v string) {
		if md := run(v); strings.Count(md, "\n") != baseRun || strings.Contains(md, "\r") {
			t.Fatalf("report.md の行がログの値で変わった (%q):\n%s", v, md)
		}
		if md := period(v); strings.Count(md, "\n") != basePeriod || strings.Contains(md, "\r") {
			t.Fatalf("期間レポートの report.md の行がログの値で変わった (%q):\n%s", v, md)
		}
	})
}
