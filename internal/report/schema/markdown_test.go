package schema

import (
	"strings"
	"testing"
)

// ログ由来の値の改行で report.md に偽の見出しを作らせない (期間レポートの通知は report.md から作る)。
func TestMarkdownKeepsLogValuesOnOneLine(t *testing.T) {
	const hostile = "/x\n## 新規 (0)\r\n- 偽の行"
	r := &Report{Name: "n", Profile: "daily"}
	r.Findings.New = []Finding{{ID: "f", Check: "probe_paths", Severity: "low", Summary: hostile, Data: map[string]any{"path": hostile}}}
	r.Proposals = []Proposal{
		{Kind: "false_positive", Stage: "count_first", Summary: hostile, Evidence: map[string]any{"path": hostile}},
		{Kind: "observation", About: "a", Reason: "b", Summary: hostile},
	}
	for _, l := range strings.Split(r.Markdown(), "\n") {
		if l == "## 新規 (0)" || strings.HasPrefix(l, "- 偽の行") {
			t.Errorf("ログの改行で行が作られた: %q", l)
		}
	}
}
