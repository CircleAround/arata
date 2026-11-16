package schema

import (
	"strings"
	"testing"
)

// 理由は利用者の入力。report.md では 1 つのコードの中に収まり、行を増やさない (ADR 0068)。
func FuzzSilencedReasonStaysInCode(f *testing.F) {
	for _, s := range []string{"", "known", "a`b", "```", "x\ny", "\r\n## 偽の見出し", "**太字** <!here>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, reason string) {
		var b strings.Builder
		silencedMarkdown(&b, &Silenced{Summary: SilencedSummary{Acked: 1}, Findings: []SilencedFinding{{ID: "f1", Check: "posture", Severity: "low", Status: "acked",
			LastAction: &SilencedAction{Action: "ack", By: "alice", Reason: reason, At: "2026-10-21T00:00:00Z"}}}})
		var line string
		for _, l := range strings.Split(b.String(), "\n") {
			if strings.Contains(l, "理由: ") {
				line = l
			}
		}
		if line == "" {
			t.Fatalf("no reason line:\n%s", b.String())
		}
		got := line[strings.Index(line, "理由: ")+len("理由: "):]
		if !strings.HasPrefix(got, "`") || !strings.HasSuffix(got, "`") || strings.Count(got, "`") != 2 {
			t.Fatalf("the reason must stay inside one code span: %q", got)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("the reason must stay on one line: %q", got)
		}
	})
}
