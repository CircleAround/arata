package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aratam.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// 雛形はそのまま読めて、全項目を明示している。
func TestScaffoldLoads(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, string(Scaffold())))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "example" || c.MaxAge != "26h" || c.UrgentSeverity != "high" || c.OnQuiet != "short" || c.LLM.Provider != ProviderNone || c.LLM.Timeout != "120s" ||
		c.Slack.WebhookEnv != "ARATAM_SLACK_WEBHOOK" || c.Slack.UrgentWebhookEnv != "ARATAM_SLACK_URGENT_WEBHOOK" || c.Slack.UrgentMention != "<!channel>" || c.Slack.Format != FormatBlocks {
		t.Fatalf("%+v", c)
	}
	for _, key := range []string{"name:", "max_age:", "urgent_severity:", "on_quiet:", "provider:", "model:", "region:", "profile:", "timeout:", "command:", "context_file:", "webhook_env:", "urgent_webhook_env:", "urgent_mention:", "format:"} {
		if !strings.Contains(string(Scaffold()), "\n"+key) && !strings.Contains(string(Scaffold()), " "+key) {
			t.Errorf("scaffold must state %s", key)
		}
	}
	r := c.Rules(false)
	if r.MaxAge != 26*time.Hour || r.UrgentMention != "<!channel>" {
		t.Fatalf("%+v", r)
	}
	if c.Rules(true).UrgentMention != "" {
		t.Fatal("mention is only for the fallback to the normal webhook")
	}
}

func TestConfigErrors(t *testing.T) {
	base := string(Scaffold())
	cases := []struct {
		name, from, to, want string
	}{
		{"未知のキー", "on_quiet: short", "on_quiet: short\nonquiet: short", "field onquiet not found"},
		{"name 無し", "name: example", "name: \"\"", "name is required"},
		{"max_age 不正", "max_age: 26h", "max_age: 1 day", "max_age: invalid duration"},
		{"urgent_severity 不正", "urgent_severity: high", "urgent_severity: info", "urgent_severity must be one of"},
		{"on_quiet 不正", "on_quiet: short", "on_quiet: loud", "on_quiet must be short or silent"},
		{"provider 不正", "provider: none", "provider: gpt", "llm.provider must be one of"},
		{"openai-api は後続", "provider: none", "provider: openai-api", `"openai-api" is not supported yet`},
		{"bedrock は model と region が要る", "provider: none", "provider: bedrock", "llm.model is required"},
		{"bedrock は region が要る", "provider: none", "provider: bedrock", "llm.region is required"},
		{"claude-cli は model 省略可", "provider: none", "provider: claude-cli", ""},
		{"webhook_env 無し", "webhook_env: ARATAM_SLACK_WEBHOOK", "webhook_env: \"\"", "slack.webhook_env is required"},
		{"format 無し (v0.3.0 からの更新)", "format: blocks", "format: \"\"", "slack.format is required since v0.4.0"},
		{"format 無しは text で従来どおりと案内", "format: blocks", "format: \"\"", "slack.format: text"},
		{"format 不正", "format: blocks", "format: html", "slack.format must be blocks or text"},
		{"format text", "format: blocks", "format: text", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, strings.Replace(base, tc.from, tc.to, 1)))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	// claude-cli でも timeout は要る
	body := strings.Replace(strings.Replace(base, "provider: none", "provider: claude-cli", 1), "timeout: 120s", "timeout: \"\"", 1)
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "llm.timeout") {
		t.Fatalf("timeout: %v", err)
	}
}

// Webhook の URL を設定ファイルに貼った誤りは弾き、エラーに URL を出さない。
func TestWebhookURLInConfigIsRejectedWithoutEcho(t *testing.T) {
	url := "https://hooks.slack.example/services/T000/B000/secret-token"
	body := strings.Replace(string(Scaffold()), "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK", "urgent_webhook_env: "+url, 1)
	_, err := LoadConfig(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "slack.urgent_webhook_env must be the name of an environment variable") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("%v", err)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"26h": 26 * time.Hour, "2d": 48 * time.Hour, "90s": 90 * time.Second} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0s", "-1h", "xd", "1 day"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
}

// llm.context_file (利用者が書いた「この監査対象の前提」)。相対パスは設定ファイルのディレクトリ基準。
// 決定 (ADR 0024): 無い・読めない・16 KiB を超えるときは設定エラーにせず、WARN を出して前提なしで続ける (超えたら切り詰めずに使わない)。
func TestLoadContext(t *testing.T) {
	load := func(t *testing.T, contextFile string, files map[string]string) (string, string, error) {
		t.Helper()
		p := writeConfig(t, strings.Replace(string(Scaffold()), `context_file: ""`, "context_file: "+contextFile, 1))
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(filepath.Dir(p), name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return c.LoadContext()
	}
	if text, code, err := load(t, `""`, nil); text != "" || code != "" || err != nil {
		t.Fatalf("empty: %q %q %v", text, code, err)
	}
	if text, code, err := load(t, "context.md", map[string]string{"context.md": "- 決済画面はリクエストが多い\n"}); text != "- 決済画面はリクエストが多い\n" || code != "" || err != nil {
		t.Fatalf("relative to the config file: %q %q %v", text, code, err)
	}
	abs := filepath.Join(t.TempDir(), "ctx.md")
	if err := os.WriteFile(abs, []byte("abs"), 0o600); err != nil {
		t.Fatal(err)
	}
	if text, _, err := load(t, abs, nil); text != "abs" || err != nil {
		t.Fatalf("absolute: %q %v", text, err)
	}
	if text, code, err := load(t, "missing.md", nil); text != "" || code != CodeContextUnreadable || err == nil {
		t.Fatalf("missing: %q %q %v", text, code, err)
	}
	if text, code, err := load(t, "big.md", map[string]string{"big.md": strings.Repeat("a", MaxContextBytes+1)}); text != "" || code != CodeContextTooLarge || err == nil {
		t.Fatalf("too large: %d %q %v", len(text), code, err)
	}
	if text, _, err := load(t, "edge.md", map[string]string{"edge.md": strings.Repeat("a", MaxContextBytes)}); len(text) != MaxContextBytes || err != nil {
		t.Fatalf("exactly the limit is accepted: %d %v", len(text), err)
	}
	if text, code, err := load(t, "bin.md", map[string]string{"bin.md": "\xff\xfe"}); text != "" || code != CodeContextUnreadable || err == nil {
		t.Fatalf("not UTF-8: %q %q %v", text, code, err)
	}
}

// botScaffold は雛形を bot トークンの方式に書き換えたもの (Webhook の 2 つを空にし、トークンの環境変数とチャンネル ID を書く)。
func botScaffold(t *testing.T) string {
	t.Helper()
	body := string(Scaffold())
	for _, r := range [][2]string{
		{"webhook_env: ARATAM_SLACK_WEBHOOK ", `webhook_env: "" `},
		{"urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ", `urgent_webhook_env: "" `},
		{`bot_token_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN"},
		{`  channel: ""`, "  channel: C0123456789"},
		{`urgent_channel: ""`, "urgent_channel: C0123456780"},
	} {
		if !strings.Contains(body, r[0]) {
			t.Fatalf("scaffold lacks %q", r[0])
		}
		body = strings.Replace(body, r[0], r[1], 1)
	}
	return body
}

// 雛形は新しいキー (bot トークンの方式) も明示する。空のままなら Webhook の方式。
func TestScaffoldStatesBotKeys(t *testing.T) {
	for _, key := range []string{"bot_token_env:", "channel:", "urgent_channel:"} {
		if !strings.Contains(string(Scaffold()), "\n  "+key) {
			t.Errorf("scaffold must state %s", key)
		}
	}
	c, err := LoadConfig(writeConfig(t, string(Scaffold())))
	if err != nil || c.Slack.Method() != SlackWebhook || c.Slack.BotTokenEnv != "" || c.Slack.Channel != "" || c.Slack.UrgentChannel != "" {
		t.Fatalf("%+v %v", c, err)
	}
}

// v0.5 までの設定 (新しいキーが無い) は変更なしで読める (後方互換)。
func TestConfigWithoutBotKeysStillLoads(t *testing.T) {
	var kept []string
	for _, line := range strings.Split(string(Scaffold()), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "bot_token_env:") || strings.HasPrefix(t, "channel:") || strings.HasPrefix(t, "urgent_channel:") {
			continue
		}
		kept = append(kept, line)
	}
	body := strings.Join(kept, "\n")
	if strings.Contains(body, "bot_token_env:") {
		t.Fatal("the keys must be removed")
	}
	c, err := LoadConfig(writeConfig(t, body))
	if err != nil || c.Slack.Method() != SlackWebhook {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestBotConfig(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, botScaffold(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Slack.Method() != SlackBot || c.Slack.BotTokenEnv != "ARATAM_SLACK_BOT_TOKEN" || c.Slack.Channel != "C0123456789" || c.Slack.UrgentChannel != "C0123456780" {
		t.Fatalf("%+v", c.Slack)
	}
	cases := []struct {
		name, from, to, want string
	}{
		{"urgent_channel は省略可", "urgent_channel: C0123456780", `urgent_channel: ""`, ""},
		{"古い形式の非公開チャンネル", "  channel: C0123456789", "  channel: G0123ABCD", ""},
		{"両方の方式", `webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ", "choose one"},
		{"緊急用だけ Webhook でも両方の方式", `urgent_webhook_env: "" `, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ", "choose one"},
		{"トークンの環境変数が無い", "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`, "slack.bot_token_env is required"},
		{"channel が無い", "  channel: C0123456789", `  channel: ""`, "slack.channel is required"},
		{"channel が名前", "  channel: C0123456789", `  channel: "#general"`, "slack.channel must be a channel ID"},
		{"channel が小文字", "  channel: C0123456789", "  channel: c0123456789", "slack.channel must be a channel ID"},
		{"channel がユーザー ID", "  channel: C0123456789", "  channel: U0123456789", "slack.channel must be a channel ID"},
		{"urgent_channel が名前", "urgent_channel: C0123456780", "urgent_channel: alerts", "slack.urgent_channel must be a channel ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, strings.Replace(botScaffold(t), tc.from, tc.to, 1)))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

// どちらの方式も書いていなければ、両方の書き方を案内する。
func TestNoSlackMethod(t *testing.T) {
	body := strings.Replace(string(Scaffold()), "webhook_env: ARATAM_SLACK_WEBHOOK ", `webhook_env: "" `, 1)
	body = strings.Replace(body, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ", `urgent_webhook_env: "" `, 1)
	_, err := LoadConfig(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "slack.webhook_env is required") || !strings.Contains(err.Error(), "slack.bot_token_env") {
		t.Fatalf("%v", err)
	}
}

// トークンやチャンネルの欄にトークンを貼った誤りは弾き、エラーに値を出さない。
func TestBotTokenInConfigIsRejectedWithoutEcho(t *testing.T) {
	token := "xoxb-fake-secret-token"
	for _, r := range [][2]string{
		{"bot_token_env: ARATAM_SLACK_BOT_TOKEN", "bot_token_env: " + token},
		{"  channel: C0123456789", "  channel: " + token},
		{"urgent_channel: C0123456780", "urgent_channel: " + token},
	} {
		_, err := LoadConfig(writeConfig(t, strings.Replace(botScaffold(t), r[0], r[1], 1)))
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "xoxb-fake") {
			t.Fatalf("%s: %v", r[1], err)
		}
	}
	_, err := LoadConfig(writeConfig(t, strings.Replace(botScaffold(t), "bot_token_env: ARATAM_SLACK_BOT_TOKEN", "bot_token_env: "+token, 1)))
	if err == nil || !strings.Contains(err.Error(), "slack.bot_token_env must be the name of an environment variable") {
		t.Fatalf("%v", err)
	}
}
