package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type payload struct {
	Text   string `json:"text"`
	Blocks []struct {
		Type string `json:"type"`
		Text *struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"text"`
	} `json:"blocks"`
}

func (c *cli) useBlocks() { c.setConfig("format: text", "format: blocks") }

// slack.format: blocks なら Webhook に text (通知用) と blocks を送る。
func TestNotifyBlocksSendsBlockKit(t *testing.T) {
	c := newCLI(t)
	c.useBlocks()
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	raw := c.hook.raw[urgentPath]
	if len(raw) != 1 {
		t.Fatalf("%v", c.hook.got)
	}
	var p payload
	if err := json.Unmarshal(raw[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.Text != "arata daily (acme): 新規 3 件、最大 critical" || len(p.Blocks) == 0 || p.Blocks[0].Type != "header" {
		t.Fatalf("%s", raw[0])
	}
	if !strings.Contains(string(raw[0]), "まず対応") {
		t.Fatalf("%s", raw[0])
	}
}

// --dry-run は既定で人が読む簡易表示、--format json で送る payload そのものを出す。
func TestNotifyDryRunFormat(t *testing.T) {
	c := newCLI(t)
	c.useBlocks()
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--dry-run"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	out := c.stdout.String()
	if !strings.HasPrefix(out, "--- route: urgent → urgent webhook ---\n[通知] arata daily (acme)") || !strings.Contains(out, "\n# 🚨 arata daily — acme\n") {
		t.Fatalf("%s", out)
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--dry-run", "--format", "json"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	_, body, ok := strings.Cut(c.stdout.String(), "---\n")
	var p payload
	if !ok || json.Unmarshal([]byte(body), &p) != nil || len(p.Blocks) == 0 {
		t.Fatalf("%s", c.stdout)
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--dry-run", "--format", "html"); code != 2 {
		t.Fatalf("bad --format: exit %d", code)
	}
	// --format は --dry-run のときだけ意味を持つ
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--format", "json"); code != 2 {
		t.Fatalf("--format without --dry-run: exit %d", code)
	}
	if len(c.hook.got) != 0 {
		t.Fatal("dry-run must not send")
	}
}

// slack.format が無い設定 (v0.3.0) は設定エラーで、直し方を出す。
func TestNotifyRequiresFormat(t *testing.T) {
	c := newCLI(t)
	c.setConfig("  format: text", "")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 2 || !strings.Contains(c.stderr.String(), "slack.format is required since v0.4.0") {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
}

// claude-cli + blocks: 偽の claude (PATH には偽物だけ) が blocks の契約で返した要約と「→」を載せる。
func TestNotifyBlocksClaudeCLI(t *testing.T) {
	c := newCLI(t)
	c.useBlocks()
	c.useClaude()
	c.claudeOut = claudeOutput(t, `{"summary": "ルートの利用が続いている。", "next": [{"finding_id": "f-002", "action": "利用した人を確かめる"}]}`)
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	raw := c.hook.raw[urgentPath]
	if len(raw) != 1 || !strings.Contains(string(raw[0]), "ルートの利用が続いている。") || !strings.Contains(string(raw[0]), "→ 利用した人を確かめる") {
		t.Fatalf("%v", c.hook.got)
	}
	args, _ := os.ReadFile(filepath.Join(c.rec, "args"))
	if !strings.Contains(string(args), `"next"`) {
		t.Fatal("the fake claude must have been called with the blocks contract")
	}
}
