package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/notify"
)

// fakeClaude は claude の偽の実行ファイル (実際の claude には接続しない)。標準入力・環境変数・作業ディレクトリを記録し、
// FAKE_MODE が空なら $REC/response をそのまま出す。引数 (--system-prompt を含む) は呼び出しごとに $REC/args に足す。
// 標準入力が JSON の配列 (提案の書き起こし) で $REC/response_proposals があれば、そちらを出す。
const fakeClaude = `#!/bin/sh
cat > "$REC/stdin"
env > "$REC/env"
pwd > "$REC/pwd"
printf '%s\n' "$@" >> "$REC/args"
echo "--- end of call ---" >> "$REC/args"
case "$FAKE_MODE" in
fail) echo "Not logged in" >&2; exit 1 ;;
sleep) exec sleep 10 ;;
esac
if [ "$(head -c 1 "$REC/stdin")" = "[" ] && [ -f "$REC/response_proposals" ]; then
  cp "$REC/stdin" "$REC/stdin_proposals"
  cat "$REC/response_proposals"
  exit 0
fi
cat "$REC/response"
`

// claudeOutput は claude -p --output-format json の形で result を包む。
func claudeOutput(t *testing.T, result string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": "result", "subtype": "success", "is_error": false, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func llmFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "notify", "testdata", "llm", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (c *cli) useClaude() {
	c.setConfig("provider: none", "provider: claude-cli")
	c.setConfig("timeout: 120s", "timeout: 2s")
}

// claude-cli: report.json だけを標準入力で渡し、Webhook の URL は子プロセスの環境変数に渡さない。
func TestNotifyClaudeCLI(t *testing.T) {
	c := newCLI(t)
	c.useClaude()
	c.claudeOut = claudeOutput(t, llmFixture(t, "ok.json"))
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	got := c.hook.got[urgentPath]
	if len(got) != 1 || !strings.Contains(got[0], "\n*要対処*\n") || !strings.Contains(got[0], "`arata approve f-001 --note \"...\"`") {
		t.Fatalf("got %v", c.hook.got)
	}
	stdin, _ := os.ReadFile(filepath.Join(c.rec, "stdin"))
	report, _ := os.ReadFile(filepath.Join(in, "report.json"))
	if string(stdin) != string(report) {
		t.Fatal("claude must receive report.json only")
	}
	env, _ := os.ReadFile(filepath.Join(c.rec, "env"))
	if strings.Contains(string(env), "secret") || strings.Contains(string(env), "ARATAM_SLACK") {
		t.Fatalf("webhook URLs must not reach the child process:\n%s", env)
	}
}

// LLM が使えなければ (時間切れを含む) 原文を送って終了コード 3。
func TestNotifyClaudeCLIFallback(t *testing.T) {
	for _, mode := range []string{"fail", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			c := newCLI(t)
			c.useClaude()
			c.setConfig("timeout: 2s", "timeout: 300ms")
			c.fakeMode = mode
			if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 3 || !strings.Contains(strings.Join(c.codes(), ","), notify.CodeLLMFailed) {
				t.Fatalf("exit %d %s", code, c.stderr)
			}
			if got := c.hook.got[urgentPath]; len(got) != 1 || !strings.HasPrefix(got[0], notify.FallbackNotice+"\n*arata daily (acme)*") {
				t.Fatalf("got %v", c.hook.got)
			}
		})
	}
	// 形が不正な応答も原文で送る
	c := newCLI(t)
	c.useClaude()
	c.claudeOut = claudeOutput(t, llmFixture(t, "malformed.txt"))
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 3 {
		t.Fatalf("malformed: exit %d %s", code, c.stderr)
	}
}

func fakeBedrockServer(t *testing.T, result string, calls *int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"output":     map[string]any{"message": map[string]any{"role": "assistant", "content": []map[string]string{{"text": result}}}},
			"stopReason": "end_turn", "usage": map[string]int{"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}, "metrics": map[string]int{"latencyMs": 1},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNotifyBedrock(t *testing.T) {
	c := newCLI(t)
	c.setConfig("provider: none", "provider: bedrock")
	c.setConfig(`model: ""`, "model: us.example.model-v1")
	c.setConfig(`region: ""`, "region: us-east-1")
	calls := 0
	c.bedrock = fakeBedrockServer(t, llmFixture(t, "ok.json"), &calls)
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 || calls != 1 {
		t.Fatalf("exit %d calls %d %s", code, calls, c.stderr)
	}
	if got := c.hook.got[urgentPath]; len(got) != 1 || !strings.Contains(got[0], "*インシデント候補*") {
		t.Fatalf("got %v", c.hook.got)
	}
}

func TestDoctor(t *testing.T) {
	c := newCLI(t)
	if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "skip    llm") {
		t.Fatalf("none: exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	c.useClaude()
	c.claudeOut = claudeOutput(t, "ok")
	if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), `claude-cli が応答しました`) {
		t.Fatalf("claude-cli: exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	stdin, _ := os.ReadFile(filepath.Join(c.rec, "stdin"))
	if string(stdin) != "ok" {
		t.Fatalf("doctor must not send report data: %q", stdin)
	}
	// 緊急用が無い → warn (終了コード 0)、通常用が無い・LLM が失敗 → ng (終了コード 2)
	delete(c.env, "ARATAM_SLACK_URGENT_WEBHOOK")
	if code := c.run("doctor", "-c", c.cfg); code != 0 || strings.Join(c.codes(), ",") != "URGENT_WEBHOOK_UNSET" {
		t.Fatalf("urgent unset: exit %d %s", code, c.stderr)
	}
	delete(c.env, "ARATAM_SLACK_WEBHOOK")
	c.fakeMode = "fail"
	if code := c.run("doctor", "-c", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "WEBHOOK_UNSET,URGENT_WEBHOOK_UNSET,LLM_UNAVAILABLE" {
		t.Fatalf("ng: exit %d %s\n%s", code, c.stderr, c.stdout)
	}
	c.setConfig(`command: ""`, `command: /nonexistent/claude`)
	if code := c.run("doctor", "-c", c.cfg); code != 2 || !strings.Contains(c.stdout.String(), "/nonexistent/claude が見つかりません") {
		t.Fatalf("missing command: exit %d\n%s", code, c.stdout)
	}
}

func TestTestNotify(t *testing.T) {
	c := newCLI(t)
	if code := c.run("test-notify", "-c", c.cfg); code != 0 || len(c.hook.got[normalPath]) != 1 || !strings.Contains(c.hook.got[normalPath][0], "aratam の試験通知です (acme、通常用)") {
		t.Fatalf("exit %d %v", code, c.hook.got)
	}
	if code := c.run("test-notify", "-c", c.cfg, "--urgent"); code != 0 || len(c.hook.got[urgentPath]) != 1 || strings.HasPrefix(c.hook.got[urgentPath][0], "<!channel>") {
		t.Fatalf("--urgent: exit %d %v", code, c.hook.got)
	}
	delete(c.env, "ARATAM_SLACK_URGENT_WEBHOOK")
	if code := c.run("test-notify", "-c", c.cfg, "--urgent"); code != 0 || len(c.hook.got[normalPath]) != 2 || !strings.HasPrefix(c.hook.got[normalPath][1], "<!channel>\n") {
		t.Fatalf("--urgent fallback: exit %d %v", code, c.hook.got)
	}
	c.hook.status = http.StatusNotFound
	if code := c.run("test-notify", "-c", c.cfg); code != 5 || strings.Join(c.codes(), ",") != "URGENT_WEBHOOK_UNSET,SEND_FAILED" {
		t.Fatalf("failure: exit %d %s", code, c.stderr)
	}
}

// --dry-run の標準出力まで通して、長い日本語の要約がマルチバイト文字の途中で切れないこと。
func TestDryRunOutputIsValidUTF8(t *testing.T) {
	c := newCLI(t)
	c.useClaude()
	long := strings.Repeat("同じ主体からの呼び出しが続いている", 40)
	resp, _ := json.Marshal(map[string]any{"headline": long,
		"items":               []map[string]string{{"finding_id": "f-002", "class": "action", "reason": long}},
		"incidents":           []map[string]any{{"finding_ids": []string{"f-002", "f-001"}, "summary": long}},
		"approve_suggestions": []map[string]string{{"finding_id": "f-001", "reason": long}}})
	c.claudeOut = claudeOutput(t, string(resp))
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir(), "--dry-run"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	out := c.stdout.String()
	if !utf8.ValidString(out) || !strings.Contains(out, "• f-002, f-001: 同じ主体") {
		t.Fatalf("invalid UTF-8 or missing incident:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "• f-002, f-001: ") && utf8.RuneCountInString(strings.TrimPrefix(l, "• f-002, f-001: ")) != 241 {
			t.Fatalf("incident summary must be 240 runes + …: %d", utf8.RuneCountInString(l))
		}
	}
}

// proposalsInputDir は arata のゴールデンの report.json に proposals (aratam のテストの固定値) を足した出力ディレクトリ。
func (c *cli) proposalsInputDir() string {
	c.t.Helper()
	in := c.inputDir()
	var m map[string]any
	b, _ := os.ReadFile(filepath.Join(in, "report.json"))
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatal(err)
	}
	var ps []any
	if err := json.Unmarshal([]byte(llmFixture(c.t, "../proposals.json")), &ps); err != nil {
		c.t.Fatal(err)
	}
	m["proposals"] = ps
	b, _ = json.Marshal(m)
	if err := os.WriteFile(filepath.Join(in, "report.json"), b, 0o600); err != nil {
		c.t.Fatal(err)
	}
	return in
}

// claude-cli: 本文は要約、WAF の改善提案は別の呼び出しで書き起こして通常用に送る。
// context_file (設定ファイル基準の相対パス) は両方の呼び出しの system に入る。提案の呼び出しには observation を渡さない。
func TestNotifyClaudeCLIProposalsAndContext(t *testing.T) {
	c := newCLI(t)
	c.useClaude()
	c.claudeOut = claudeOutput(t, llmFixture(t, "ok.json"))
	c.claudeProposalsOut = claudeOutput(t, llmFixture(t, "proposals_ok.json"))
	if err := os.WriteFile(filepath.Join(c.dir, "context.md"), []byte("- 決済画面 /checkout/* はリクエストが多いのが仕様\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.setConfig(`context_file: ""`, "context_file: context.md")
	if code := c.run("notify", "-c", c.cfg, "--in", c.proposalsInputDir()); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.hook.got[urgentPath]; len(got) != 1 || strings.Contains(got[0], "WAF の改善提案") {
		t.Fatalf("urgent: %v", got)
	}
	if got := c.hook.got[normalPath]; len(got) != 1 || !strings.HasPrefix(got[0], "*WAF の改善提案*") || !strings.Contains(got[0], "何を: CrossSiteScripting_BODY") {
		t.Fatalf("normal: %v", got)
	}
	args, _ := os.ReadFile(filepath.Join(c.rec, "args"))
	if n := strings.Count(string(args), "決済画面 /checkout/* はリクエストが多いのが仕様"); n != 2 {
		t.Fatalf("the context must be in both system prompts, got %d:\n%s", n, args)
	}
	// 対処手順 (ADR 0025): 要約の呼び出しには run に出たチェックの、提案の呼び出しには waf_review の playbook が system に入る (偽の claude が受け取った引数で確かめる)
	for _, want := range []string{`<playbook check="root_usage">`, `<playbook check="waf_review">`} {
		if n := strings.Count(string(args), want); n != 1 {
			t.Fatalf("%s must appear once in the system prompts, got %d", want, n)
		}
	}
	stdin, _ := os.ReadFile(filepath.Join(c.rec, "stdin_proposals"))
	if !strings.Contains(string(stdin), `"id": "p1"`) || strings.Contains(string(stdin), "observation") || strings.Contains(string(stdin), "findings") {
		t.Fatalf("the proposals call gets the proposals only:\n%s", stdin)
	}
}

// context_file が読めなければ WARN を出して前提なしで続ける (設定エラーにしない)。provider: none では読まない。
func TestNotifyContextUnreadable(t *testing.T) {
	c := newCLI(t)
	c.useClaude()
	c.claudeOut = claudeOutput(t, llmFixture(t, "ok.json"))
	c.setConfig(`context_file: ""`, "context_file: missing.md")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 || !strings.Contains(strings.Join(c.codes(), ","), notify.CodeContextUnreadable) {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	args, _ := os.ReadFile(filepath.Join(c.rec, "args"))
	if strings.Contains(string(args), "この監査対象の前提") {
		t.Fatal("no context section without a readable file")
	}

	c = newCLI(t)
	c.setConfig(`context_file: ""`, "context_file: missing.md")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 || strings.Contains(strings.Join(c.codes(), ","), notify.CodeContextUnreadable) {
		t.Fatalf("provider none must not read the context: exit %d %s", code, c.stderr)
	}
}

// doctor は context_file を読めるかを表に出す (読めなければ warn)。
func TestDoctorContext(t *testing.T) {
	c := newCLI(t)
	c.useClaude()
	c.claudeOut = claudeOutput(t, "ok")
	c.setConfig(`context_file: ""`, "context_file: missing.md")
	if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "warn    context") || !strings.Contains(strings.Join(c.codes(), ","), notify.CodeContextUnreadable) {
		t.Fatalf("exit %d\n%s\n%s", code, c.stdout, c.stderr)
	}
	if err := os.WriteFile(filepath.Join(c.dir, "missing.md"), []byte("前提"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "ok      context") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
}
