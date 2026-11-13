package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/notify"
)

// dryRunInputDir は arata の試しの実行 (run --dry-run) の報告を置いた出力ディレクトリ (ゴールデンの報告に dry_run: true を足したもの)。
func (c *cli) dryRunInputDir() string {
	c.t.Helper()
	dir := c.inputDir()
	p := filepath.Join(dir, notify.ReportJSON)
	b, err := os.ReadFile(p)
	if err != nil {
		c.t.Fatal(err)
	}
	out := strings.Replace(string(b), "{", "{\n  \"dry_run\": true,", 1)
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		c.t.Fatal(err)
	}
	return dir
}

// arata の試しの実行の報告は、定時の経路 (aratam notify) に流れても Slack に届かない (ADR 0049)。LLM も呼ばない。
func TestNotifyDoesNotSendDryRunReport(t *testing.T) {
	for _, args := range [][]string{nil, {"--force"}} {
		c := newCLI(t)
		c.setConfig("provider: none", "provider: claude-cli")
		dir := c.dryRunInputDir()
		if code := c.run(append([]string{"notify", "-c", c.cfg, "--in", dir}, args...)...); code != notify.ExitOK {
			t.Fatalf("%v: exit %d\n%s", args, code, c.stderr)
		}
		if n := len(c.hook.got[normalPath]) + len(c.hook.got[urgentPath]); n != 0 {
			t.Fatalf("%v: %d messages reached Slack", args, n)
		}
		if !strings.Contains(strings.Join(c.codes(), ","), notify.CodeDryRunReport) {
			t.Fatalf("%v: codes %v", args, c.codes())
		}
		// 偽の claude は呼ばれると標準入力を rec/stdin に残す
		if _, err := os.Stat(filepath.Join(c.rec, "stdin")); !os.IsNotExist(err) {
			t.Fatalf("%v: the LLM was called: %v", args, err)
		}
		if _, err := os.Stat(filepath.Join(dir, notify.NotifiedFile)); !os.IsNotExist(err) {
			t.Fatalf("%v: marked as notified: %v", args, err)
		}
	}
}

// aratam notify --dry-run では、試しの実行の報告であることを冒頭に書いて文面を表示する (送らない)。
func TestNotifyDryRunShowsDryRunReport(t *testing.T) {
	c := newCLI(t)
	dir := c.dryRunInputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", dir, "--dry-run"); code != notify.ExitOK {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "試しの実行") {
		t.Fatalf("the output must say it is a dry-run report:\n%s", c.stdout)
	}
	if n := len(c.hook.got[normalPath]) + len(c.hook.got[urgentPath]); n != 0 {
		t.Fatalf("%d messages reached Slack", n)
	}
}
