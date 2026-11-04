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
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ClaudeCLI は `claude -p` を子プロセスで起動するプロバイダ (provider: claude-cli)。認証は claude 側のログイン状態を使う。
type ClaudeCLI struct {
	// Command は claude の実行ファイル (llm.command。空なら PATH から claude を探す)。
	Command string
	// Model は --model に渡す (空なら claude の既定)。
	Model string
	// Env は子プロセスの環境変数。呼び出し側が ClaudeEnv で絞って渡す (nil なら空の環境)。
	Env []string
	// WorkRoot は作業用の一時ディレクトリを作る親 (空なら workRoot が決める)。
	WorkRoot string
}

// claudeArgs は claude に渡す引数。
// 決定:
//   - ツールは使わせない (--tools "")。MCP サーバーも読まない (--strict-mcp-config。--mcp-config を渡さないので 0 個)。
//   - セッションをディスクに残さない (--no-session-persistence)。
//   - 設定は project だけを読む (--setting-sources project)。作業ディレクトリは空なので project 設定は無く、ユーザー設定の
//     hooks・権限設定・プラグインを読ませないことになる。--bare は OAuth のログイン状態を読まなくなるので使わない。
//   - 出力は --output-format json (1 つの JSON。本文は result)。プロンプト (report.json) は標準入力で渡す。
//   - system はファイルで渡す (--system-prompt-file)。引数は同じホストの他のユーザーに ps で見え、context_file の中身が載るため。
func (c *ClaudeCLI) claudeArgs(systemFile string) []string {
	args := []string{"-p", "--output-format", "json", "--tools", "", "--strict-mcp-config", "--no-session-persistence", "--setting-sources", "project", "--system-prompt-file", systemFile}
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
	root, err := os.MkdirTemp(c.workRoot(), "aratam-claude-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "work")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	systemFile := filepath.Join(root, "system-prompt.md")
	if err := os.WriteFile(systemFile, []byte(system), 0o600); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, command, c.claudeArgs(systemFile)...) // #nosec G204 -- シェルを通さない。command は利用者の設定 (llm.command)。ログ由来の値は標準入力でだけ渡す
	cmd.Dir = dir
	// 決定: 親のディレクトリの CLAUDE.md を読ませない (/tmp/CLAUDE.md は同じホストの誰でも置ける)
	cmd.Env = append(append([]string{}, c.Env...), "CLAUDE_CODE_DISABLE_CLAUDE_MDS=1")
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

// workRoot は作業用の一時ディレクトリの親。
// 決定: 誰でも書ける /tmp の下を避け、利用者のキャッシュの下に作る (上の環境変数を無視する版の claude でも、親の CLAUDE.md を他人に置かせない)。
// HOME が無ければ OS の一時ディレクトリを使う。
func (c *ClaudeCLI) workRoot() string {
	if c.WorkRoot != "" {
		if err := os.MkdirAll(c.WorkRoot, 0o700); err == nil {
			return c.WorkRoot
		}
		return ""
	}
	var cache string
	for _, kv := range c.Env {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case k == "XDG_CACHE_HOME" && v != "":
			cache = v
		case k == "HOME" && v != "" && cache == "":
			cache = filepath.Join(v, ".cache")
		}
	}
	if cache == "" {
		return ""
	}
	dir := filepath.Join(cache, "aratam")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	return dir
}

// claudeEnvNames は claude の子プロセスに渡す環境変数 (動くのに要るものだけ)。
var claudeEnvNames = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "LANG": true, "LANGUAGE": true, "TZ": true, "TMPDIR": true, "TERM": true,
	"XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true, "XDG_DATA_HOME": true, "XDG_STATE_HOME": true, "XDG_RUNTIME_DIR": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true, "http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
	"CLAUDE_CONFIG_DIR": true, "CLAUDE_CODE_OAUTH_TOKEN": true, "ANTHROPIC_API_KEY": true, "ANTHROPIC_AUTH_TOKEN": true, "ANTHROPIC_BASE_URL": true,
}

// ClaudeEnv は環境変数の一覧から claude に渡すものだけを残す。exclude (Webhook の環境変数の名前) は一覧にあっても渡さない。
// 決定: 除くものを列挙せず、渡すものを列挙する。AWS の認証情報やトークンの名前は利用者ごとに違い、列挙しきれないため。
// claude を Bedrock・Vertex で使う設定 (CLAUDE_CODE_USE_BEDROCK など) は渡さない。Bedrock は provider: bedrock を使う。
func ClaudeEnv(env []string, exclude ...string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if (claudeEnvNames[k] || strings.HasPrefix(k, "LC_")) && !slices.Contains(exclude, k) {
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
