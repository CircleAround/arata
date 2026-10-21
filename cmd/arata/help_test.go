package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/engine"
)

// TestRootHelp は引数なしの arata の出力を固定する。人向けの 4 行手順 (config init → doctor → init → run) と AI 向けの入口が最初に見えること。
func TestRootHelp(t *testing.T) {
	c := newCLI(t)
	if code := c.run(); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	compareGolden(t, "root_help.txt", c.stdout.Bytes())
	out := c.stdout.String()
	for _, want := range []string{"arata help ai", "1. arata config init", "2. arata doctor", "3. arata init", "4. arata run", "\n  ai          AI (LLM) 向けの使い方"} {
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
