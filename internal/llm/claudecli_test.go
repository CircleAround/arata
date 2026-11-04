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
prev=""
for a in "$@"; do
  if [ "$prev" = "--system-prompt-file" ]; then cp "$a" "$REC/system"; ls -l "$a" > "$REC/system_mode"; echo "$a" > "$REC/system_path"; fi
  prev="$a"
done
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
	return &ClaudeCLI{Command: bin, Model: "sonnet", Env: env, WorkRoot: filepath.Join(dir, "work-root")}, rec
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
	path := strings.TrimSpace(read(t, rec, "system_path"))
	want := []string{"-p", "--output-format", "json", "--tools", "", "--strict-mcp-config", "--no-session-persistence", "--setting-sources", "project", "--system-prompt-file", path, "--model", "sonnet"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("args %q", args)
	}
	// system は ps から見える引数に出さず、本人だけが読めるファイルで渡す
	if read(t, rec, "system") != "SYSTEM\n2 行目" || !strings.HasPrefix(read(t, rec, "system_mode"), "-rw-------") {
		t.Fatalf("system %q mode %q", read(t, rec, "system"), read(t, rec, "system_mode"))
	}
	// プロンプト (report.json) は標準入力で渡す
	if read(t, rec, "stdin") != `{"name":"acme"}` {
		t.Fatalf("stdin %q", read(t, rec, "stdin"))
	}
	// 作業ディレクトリは空の一時ディレクトリで、終わったら消す
	pwd := strings.TrimSpace(read(t, rec, "pwd"))
	if !strings.Contains(pwd, filepath.Join("work-root", "aratam-claude-")) || read(t, rec, "ls") != "" {
		t.Fatalf("pwd %s ls %q", pwd, read(t, rec, "ls"))
	}
	if _, err := os.Stat(pwd); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp dir must be removed: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("system prompt file must be removed: %v", err)
	}
	// どの親ディレクトリの CLAUDE.md も読ませない
	if !strings.Contains(read(t, rec, "env"), "CLAUDE_CODE_DISABLE_CLAUDE_MDS=1") {
		t.Fatalf("env:\n%s", read(t, rec, "env"))
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

// 子プロセスには claude が動くのに要るものだけを渡す。AWS の認証情報、GitHub のトークン、Webhook の URL などは渡さない。
func TestClaudeEnvIsMinimal(t *testing.T) {
	in := []string{
		"PATH=/bin", "HOME=/h", "LANG=C.UTF-8", "LC_ALL=C", "HTTPS_PROXY=http://proxy", "ANTHROPIC_API_KEY=k", "CLAUDE_CODE_OAUTH_TOKEN=t", "CLAUDE_CONFIG_DIR=/c",
		"AWS_ACCESS_KEY_ID=a", "AWS_SECRET_ACCESS_KEY=s", "AWS_SESSION_TOKEN=x", "GH_TOKEN=g", "GITHUB_TOKEN=g", "DATABASE_URL=d", "MY_SECRET=m",
		"ARATAM_SLACK_WEBHOOK=https://x", "ANTHROPIC_BASE_URL=https://y",
	}
	got := strings.Join(ClaudeEnv(in, "ARATAM_SLACK_WEBHOOK", "ANTHROPIC_BASE_URL", ""), "\n") + "\n"
	for _, keep := range []string{"PATH=/bin", "HOME=/h", "LANG=C.UTF-8", "LC_ALL=C", "HTTPS_PROXY=http://proxy", "ANTHROPIC_API_KEY=k", "CLAUDE_CODE_OAUTH_TOKEN=t", "CLAUDE_CONFIG_DIR=/c"} {
		if !strings.Contains(got, keep+"\n") {
			t.Errorf("%s が渡らない", keep)
		}
	}
	for _, drop := range []string{"AWS_", "GH_TOKEN", "GITHUB_TOKEN", "DATABASE_URL", "MY_SECRET", "ARATAM_SLACK_WEBHOOK", "ANTHROPIC_BASE_URL"} {
		if strings.Contains(got, drop) {
			t.Errorf("%s が渡った:\n%s", drop, got)
		}
	}
}
