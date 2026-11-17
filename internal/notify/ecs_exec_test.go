package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/report/schema"
)

// ecs_exec の commands (作業者が打った秘匿値が入りうる。攻撃者も書ける) は、LLM にも Slack にも渡さない (ADR 0072 の 5 節)。
const execSecret = "PGPASSWORD=hunter2 psql"

func execReport(t *testing.T) ([]byte, *schema.Report) {
	t.Helper()
	data := map[string]any{"principal": "arn:aws:iam::123456789012:user/alice", "cluster": "prod-cluster", "container": "app",
		"commands": []any{"sh -c '" + execSecret + "'"}, "commands_more": 1, "command_kinds": []any{"shell_c"}, "count": 2, "ips": []any{"203.0.113.1"}}
	r := &schema.Report{Findings: schema.Findings{
		New:       []schema.Finding{{ID: "a1", Check: "ecs_exec", Severity: "high", Summary: "ECS Exec: 知らない主体 ...", Data: data}},
		StillOpen: []schema.Finding{{ID: "b2", Check: "root_usage", Severity: "critical", Summary: "root", Data: map[string]any{"commands": []any{"keep"}}}},
	}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b, r
}

func TestLLMInputDropsECSExecCommands(t *testing.T) {
	b, r := execReport(t)
	out := string(llmInput(b, r))
	if strings.Contains(out, execSecret) || strings.Contains(out, "commands_more") {
		t.Fatalf("commands reached the LLM input: %s", out)
	}
	for _, want := range []string{`"command_kinds":["shell_c"]`, `"cluster":"prod-cluster"`, `"keep"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
}

func TestDetailOmitsECSExecCommands(t *testing.T) {
	_, r := execReport(t)
	got := detail(r.Findings.New[0], Zone{})
	if strings.Contains(got, execSecret) || strings.Contains(got, "commands ") {
		t.Fatalf("commands in the notification: %s", got)
	}
	for _, want := range []string{"command_kinds shell_c", "cluster prod-cluster", "container app"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

// 期間レポートの open も同じ (ReadInput が LLM に渡す JSON を作る)。
func TestPeriodLLMInputDropsECSExecCommands(t *testing.T) {
	p := &schema.PeriodReport{Kind: "period", Open: []schema.Finding{{ID: "a1", Check: "ecs_exec", Data: map[string]any{"commands": []any{execSecret}, "command_kinds": []any{"other"}}}}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	out := string(periodLLMInput(b, p))
	if strings.Contains(out, execSecret) || !strings.Contains(out, `"command_kinds":["other"]`) || !strings.Contains(out, `"kind":"period"`) {
		t.Fatalf("%s", out)
	}
}
