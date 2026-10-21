package llm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClaude は claude の偽の実行ファイル。引数・作業ディレクトリ・その中身・標準入力・環境変数を記録し、FAKE_MODE に従って応答する。
// 実際の claude には接続しない。
const fakeClaude = `#!/bin/sh
for a in "$@"; do printf '%s\0' "$a"; done > "$REC/args"
pwd > "$REC/pwd"
ls -A > "$REC/ls"
env > "$REC/env"
cat > "$REC/stdin"
case "$FAKE_MODE" in
ok) printf '%s' '{"type":"result","subtype":"success","is_error":false,"result":"{\"headline\":\"ok\"}"}' ;;
is_error) printf '%s' '{"type":"result","subtype":"error_during_execution","is_error":true,"result":"Not logged in"}' ;;
text) printf 'plain text' ;;
fail) echo "boom" >&2; exit 3 ;;
sleep) exec sleep 10 ;;
esac
`

func setup(t *testing.T, mode string) (*ClaudeCLI, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte(fakeClaude), 0o700); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(dir, "rec")
	if err := os.Mkdir(rec, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "REC=" + rec, "FAKE_MODE=" + mode}
	return &ClaudeCLI{Command: bin, Model: "sonnet", Env: env}, rec
}

func read(t *testing.T, rec, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rec, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClaudeCLI(t *testing.T) {
	t.Setenv("ARATAM_SLACK_WEBHOOK", "https://hooks.slack.example/secret")
	c, rec := setup(t, "ok")
	out, err := c.Summarize(context.Background(), "SYSTEM\n2 行目", []byte(`{"name":"acme"}`))
	if err != nil || string(out) != `{"headline":"ok"}` {
		t.Fatalf("%q %v", out, err)
	}
	args := strings.Split(strings.TrimSuffix(read(t, rec, "args"), "\x00"), "\x00")
	want := []string{"-p", "--output-format", "json", "--tools", "", "--strict-mcp-config", "--no-session-persistence", "--system-prompt", "SYSTEM\n2 行目", "--model", "sonnet"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("args %q", args)
	}
	// プロンプト (report.json) は標準入力で渡す
	if read(t, rec, "stdin") != `{"name":"acme"}` {
		t.Fatalf("stdin %q", read(t, rec, "stdin"))
	}
	// 作業ディレクトリは空の一時ディレクトリで、終わったら消す
	pwd := strings.TrimSpace(read(t, rec, "pwd"))
	if !strings.Contains(filepath.Base(pwd), "aratam-claude-") || read(t, rec, "ls") != "" {
		t.Fatalf("pwd %s ls %q", pwd, read(t, rec, "ls"))
	}
	if _, err := os.Stat(pwd); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp dir must be removed: %v", err)
	}
	// 環境変数は渡したものだけ (aratam のプロセスの Webhook の URL は渡らない)
	if strings.Contains(read(t, rec, "env"), "secret") || !strings.Contains(read(t, rec, "env"), "FAKE_MODE=ok") {
		t.Fatalf("env:\n%s", read(t, rec, "env"))
	}
}

func TestClaudeCLIErrors(t *testing.T) {
	for mode, want := range map[string]string{
		"is_error": "claude-cli: error_during_execution: Not logged in",
		"text":     "unexpected output",
		"fail":     "exit status 3: boom",
	} {
		c, _ := setup(t, mode)
		if _, err := c.Summarize(context.Background(), "s", []byte("{}")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", mode, err)
		}
	}
	c := &ClaudeCLI{Command: filepath.Join(t.TempDir(), "missing")}
	if _, err := c.Summarize(context.Background(), "s", []byte("{}")); err == nil {
		t.Error("missing command must fail")
	}
}

func TestClaudeCLITimeout(t *testing.T) {
	c, _ := setup(t, "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Summarize(ctx, "s", []byte("{}"))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}

func TestFilterEnv(t *testing.T) {
	got := FilterEnv([]string{"HOME=/h", "ARATAM_SLACK_WEBHOOK=https://x", "ARATAM_SLACK_URGENT_WEBHOOK=https://y", "PATH=/bin"}, "ARATAM_SLACK_WEBHOOK", "ARATAM_SLACK_URGENT_WEBHOOK", "")
	if strings.Join(got, ",") != "HOME=/h,PATH=/bin" {
		t.Fatalf("%v", got)
	}
}
