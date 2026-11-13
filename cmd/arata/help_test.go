package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/engine"
)

// TestRootHelp は引数なしの arata の出力を固定する。人向けの 5 行手順 (config init → doctor → init → run → review) と AI 向けの入口が最初に見えること。
func TestRootHelp(t *testing.T) {
	c := newCLI(t)
	if code := c.run(); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	compareGolden(t, "root_help.txt", c.stdout.Bytes())
	out := c.stdout.String()
	for _, want := range []string{"arata help ai", "1. arata config init", "2. arata doctor", "3. arata init", "4. arata run", "5. arata review", "arata help ai onboarding", "\n  ai          AI (LLM) 向けの使い方"} {
		if !strings.Contains(out, want) {
			t.Fatalf("root help lacks %q", want)
		}
	}
	if code := c.run("--help"); code != 0 || c.stdout.String() != out {
		t.Fatal("--help must print the same")
	}
}

func TestHelpAI(t *testing.T) {
	c := newCLI(t)
	for _, tc := range []struct {
		args []string
		sub  string
	}{
		{[]string{"help", "ai"}, ""},
		{[]string{"ai"}, ""},
		{[]string{"help", "ai", "report"}, "report"},
		{[]string{"ai", "approve"}, "approve"},
		{[]string{"help", "ai", "runtime"}, "runtime"},
		{[]string{"ai", "runtime"}, "runtime"},
		{[]string{"help", "ai", "onboarding"}, "onboarding"},
		{[]string{"ai", "onboarding"}, "onboarding"},
		{[]string{"help", "ai", "playbook"}, "playbook"},
		{[]string{"ai", "playbook"}, "playbook"},
		{[]string{"help", "ai", "playbook", "root_usage"}, "playbook root_usage"},
		{[]string{"ai", "playbook", "access_denied"}, "playbook access_denied"},
	} {
		if code := c.run(tc.args...); code != 0 {
			t.Fatalf("%v: exit %d %s", tc.args, code, c.stderr)
		}
		tp, _ := ai.Lookup(tc.sub)
		if c.stdout.String() != tp.Markdown() {
			t.Fatalf("%v: output differs from docs/ai/%s", tc.args, tp.File)
		}
	}
	if code := c.run("help", "ai", "report", "--format", "json"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Topic    string
		Sections []struct{ Title, Body string }
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &doc); err != nil || doc.Topic != "ai report" || len(doc.Sections) == 0 || strings.Contains(c.stdout.String(), `<`) {
		t.Fatalf("json: %v %s", err, c.stdout)
	}
	if code := c.run("help", "ai", "nope"); code != 2 || !strings.Contains(c.stderr.String(), "arata help ai report") {
		t.Fatalf("unknown topic exit %d: %s", code, c.stderr)
	}
	if code := c.run("help", "ai", "playbook", "nope"); code != 2 || !strings.Contains(c.stderr.String(), "root_usage") {
		t.Fatalf("unknown playbook exit %d: %s", code, c.stderr)
	}
	if code := c.run("help", "ai", "playbook", "root_usage", "extra"); code != 2 {
		t.Fatalf("too many args exit %d", code)
	}
	if code := c.run("help", "ai", "playbook", "root_usage", "--format", "json"); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &doc); err != nil || doc.Topic != "ai playbook root_usage" || len(doc.Sections) != len(ai.PlaybookSections) {
		t.Fatalf("playbook json: %v %s", err, c.stdout)
	}
	if code := c.run("help", "run"); code != 0 || !strings.Contains(c.stdout.String(), "--profile") {
		t.Fatalf("help run: %d %s", code, c.stdout)
	}
	// 標準エラーの code の固定語彙は全部 help ai に書かれている
	idx, _ := ai.Lookup("")
	for _, code := range engine.Codes {
		if !strings.Contains(idx.Markdown(), "`"+code+"`") {
			t.Errorf("help ai lacks code %s", code)
		}
	}
	c.assertCodesInVocabulary()
}

// TestHelpAIPlaybookIndex は playbook の一覧 (arata help ai playbook) を固定する。チェックを足したら一覧も変わる。
func TestHelpAIPlaybookIndex(t *testing.T) {
	c := newCLI(t)
	if code := c.run("help", "ai", "playbook"); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	compareGolden(t, "help_ai_playbook.txt", c.stdout.Bytes())
}
