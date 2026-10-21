// Package llm は aratam の LLM プロバイダ (aratam 設計書 3-1)。各プロバイダは notify.Summarizer を満たし、
// LLM の出力をそのまま返す (JSON の検証と組み立ては notify で行う)。
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ClaudeCLI は `claude -p` を子プロセスで起動するプロバイダ (provider: claude-cli)。認証は claude 側のログイン状態を使う。
type ClaudeCLI struct {
	// Command は claude の実行ファイル (llm.command。空なら PATH から claude を探す)。
	Command string
	// Model は --model に渡す (空なら claude の既定)。
	Model string
	// Env は子プロセスの環境変数。呼び出し側が Webhook の URL などを除いて渡す (nil なら空の環境)。
	Env []string
}

// claudeArgs は claude に渡す引数。
// 決定:
//   - ツールは使わせない (--tools "")。MCP サーバーも読まない (--strict-mcp-config。--mcp-config を渡さないので 0 個)。
//   - セッションをディスクに残さない (--no-session-persistence)。
//   - 出力は --output-format json (1 つの JSON。本文は result)。プロンプト (report.json) は標準入力で渡す。
func (c *ClaudeCLI) claudeArgs(system string) []string {
	args := []string{"-p", "--output-format", "json", "--tools", "", "--strict-mcp-config", "--no-session-persistence", "--system-prompt", system}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	return args
}

// claudeResult は --output-format json の出力のうち使う項目。
type claudeResult struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
}

// Summarize は claude -p を 1 回起動する。作業ディレクトリは空の一時ディレクトリにし、終わったら消す。
// ctx が終わったら子プロセスを止める (時間切れは呼び出し側が ctx で与える)。
func (c *ClaudeCLI) Summarize(ctx context.Context, system string, reportJSON []byte) ([]byte, error) {
	command := c.Command
	if command == "" {
		command = "claude"
	}
	dir, err := os.MkdirTemp("", "aratam-claude-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	cmd := exec.CommandContext(ctx, command, c.claudeArgs(system)...)
	cmd.Dir = dir
	cmd.Env = c.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Stdin = bytes.NewReader(reportJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// 子プロセスが出力を開いたまま残っても Wait が返るようにする
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("claude-cli: %w", ctx.Err())
		}
		return nil, fmt.Errorf("claude-cli: %v: %s", err, clip(stderr.String(), 300))
	}
	var res claudeResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("claude-cli: unexpected output (not --output-format json): %s", clip(stdout.String(), 200))
	}
	if res.IsError {
		return nil, fmt.Errorf("claude-cli: %s: %s", res.Subtype, clip(res.Result, 300))
	}
	if strings.TrimSpace(res.Result) == "" {
		return nil, errors.New("claude-cli: empty result")
	}
	return []byte(res.Result), nil
}

// FilterEnv は環境変数の一覧から names の変数を除く (子プロセスに Webhook の URL を渡さないため)。
func FilterEnv(env []string, names ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, n := range names {
			if n != "" && k == n {
				drop = true
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
