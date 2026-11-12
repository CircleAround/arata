package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs from golden (review, then `go test ./cmd/aratam -update`):\n--- got ---\n%s", name, got)
	}
}

func (c *cli) checkOut() []byte {
	return []byte(strings.ReplaceAll(c.stdout.String(), c.dir, "<dir>"))
}

func (c *cli) editConfig(old, new string) {
	c.t.Helper()
	b, err := os.ReadFile(c.cfg)
	if err != nil {
		c.t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		c.t.Fatalf("config lacks %q", old)
	}
	if err := os.WriteFile(c.cfg, []byte(strings.Replace(string(b), old, new, 1)), 0o600); err != nil {
		c.t.Fatal(err)
	}
}

// offline は Slack・LLM に触れていないことを確かめる。Webhook の環境変数は無い (PR の CI には秘密が無い)。
func (c *cli) offline() {
	c.env = map[string]string{}
	c.t.Cleanup(func() {
		c.hook.mu.Lock()
		defer c.hook.mu.Unlock()
		if len(c.hook.got) != 0 {
			c.t.Fatal("config check must not send to Slack")
		}
		if n := len(c.api.all()); n != 0 {
			c.t.Fatalf("config check must not call the Slack API: %d calls", n)
		}
		if ents, _ := os.ReadDir(c.rec); len(ents) != 0 {
			c.t.Fatalf("config check must not start claude: %v", ents)
		}
	})
}

func TestConfigCheckOK(t *testing.T) {
	c := newCLI(t)
	c.offline()
	// claude-cli でも claude を起動しない。context_file は読めるかだけを見る
	c.editConfig("provider: none", "provider: claude-cli")
	c.editConfig(`context_file: ""`, "context_file: context.md")
	if err := os.WriteFile(filepath.Join(c.dir, "context.md"), []byte("決済画面はリクエストが多い。\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := c.run("config", "check", "-c", c.cfg); code != 0 || len(c.codes()) != 0 {
		t.Fatalf("exit %d %v\n%s%s", code, c.codes(), c.stdout, c.stderr)
	}
	compareGolden(t, "config_check.txt", c.checkOut())
}

func TestConfigCheckProblems(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.editConfig("on_quiet: short", "on_quiet: loud")
	c.editConfig("format: text", "format: fancy")
	if code := c.run("config", "check", "-c", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("exit %d %v\n%s%s", code, c.codes(), c.stdout, c.stderr)
	}
	compareGolden(t, "config_check_ng.txt", c.checkOut())
}

func TestConfigCheckRules(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *cli)
		exit  int
		want  []string
	}{
		{"unknown key with line", func(c *cli) { c.editConfig("max_age: 26h", "max_agee: 26h") }, 2, []string{"ng    <dir>/aratam.yaml: ", "line 5: field max_agee not found"}},
		{"webhook url in the config", func(c *cli) {
			c.editConfig("webhook_env: ARATAM_SLACK_WEBHOOK ", "webhook_env: https://hooks.slack.example/services/T000/B000/secret ")
		}, 2,
			[]string{"slack.webhook_env must be the name of an environment variable"}},
		{"bedrock needs model and region", func(c *cli) { c.editConfig("provider: none", "provider: bedrock") }, 2, []string{"llm.model is required", "llm.region is required"}},
		// context_file が無いのは notify でも警告 (前提なしで続ける) なので、check でも警告
		{"missing context_file is a warning", func(c *cli) {
			c.editConfig("provider: none", "provider: claude-cli")
			c.editConfig(`context_file: ""`, "context_file: none.md")
		}, 0, []string{"ok    <dir>/aratam.yaml", "warn  llm.context_file: "}},
		{"no file", func(c *cli) { c.cfg = filepath.Join(c.dir, "none.yaml") }, 2, []string{"ng    <dir>/none.yaml: "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCLI(t)
			c.offline()
			tc.setup(c)
			code := c.run("config", "check", "-c", c.cfg)
			out := string(c.checkOut())
			if code != tc.exit {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.exit, out, c.stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Fatalf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}
}
