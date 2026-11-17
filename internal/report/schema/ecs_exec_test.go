package schema

import (
	"strings"
	"testing"
)

// ecs_exec の commands は利用者が打った文字列なので、report.md ではコマンドごとにコードの囲みに入れ、Markdown として解釈させない (ADR 0072 の 5 節)。
func TestMarkdownECSExecCommandsInCode(t *testing.T) {
	r := &Report{Findings: Findings{New: []Finding{{ID: "a1", Check: "ecs_exec", Severity: "medium", Summary: "ECS Exec",
		Data: map[string]any{"commands": []any{"sh -c 'echo **x** `id`'", "[link](http://example.invalid)"}, "cluster": "prod-cluster"}}}}}
	md := r.Markdown()
	want := "  - commands: `sh -c 'echo **x** 'id''`, `[link](http://example.invalid)`\n"
	if !strings.Contains(md, want) {
		t.Fatalf("want %q in:\n%s", want, md)
	}
	r.Findings.New[0].Data["commands"] = []string{"sh -c 'echo **x** `id`'", "[link](http://example.invalid)"}
	if md := r.Markdown(); !strings.Contains(md, want) {
		t.Fatalf("[]string: want %q in:\n%s", want, md)
	}
	// ほかのチェックの配列の表記は変えない
	r.Findings.New[0].Check = "root_usage"
	if md := r.Markdown(); !strings.Contains(md, "  - commands: [sh -c") {
		t.Fatalf("other checks must keep the format:\n%s", md)
	}
}
