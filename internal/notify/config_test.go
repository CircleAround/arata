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
		c.Slack.WebhookEnv != "ARATAM_SLACK_WEBHOOK" || c.Slack.UrgentWebhookEnv != "ARATAM_SLACK_URGENT_WEBHOOK" || c.Slack.UrgentMention != "<!channel>" {
		t.Fatalf("%+v", c)
	}
	for _, key := range []string{"name:", "max_age:", "urgent_severity:", "on_quiet:", "provider:", "model:", "region:", "profile:", "timeout:", "webhook_env:", "urgent_webhook_env:", "urgent_mention:"} {
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
