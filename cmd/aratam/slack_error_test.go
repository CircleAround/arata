package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// slackErrors は、SEND_FAILED の行の slack_error の値 (無い行は "")。
func (c *cli) slackErrors() []string {
	c.t.Helper()
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(c.stderr.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["code"] != "SEND_FAILED" {
			continue
		}
		s, _ := m["slack_error"].(string)
		out = append(out, s)
	}
	return out
}

// SEND_FAILED の行には、Slack が返した error コードを slack_error として付ける (ADR 0054)。
// 機械 (GitHub Actions の見本) は、人向けの error の文からコードを切り出さずに、この項目を読む。
func TestSendFailedCarriesTheSlackErrorCode(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	in := c.inputDir()
	for _, tc := range []struct {
		name, body, want string
		cmd              []string
	}{
		{"notify", `{"ok":false,"error":"not_in_channel"}`, "not_in_channel", []string{"notify", "-c", c.cfg, "--in", in, "--force"}},
		{"test-notify", `{"ok":false,"error":"channel_not_found"}`, "channel_not_found", []string{"test-notify", "-c", c.cfg}},
		// Slack の応答の値を、そのままログの項目にしない: 形に合わない値は、slack パッケージが unknown_error に置き換えている
		{"odd code", `{"ok":false,"error":"Not In Channel <!channel>"}`, "unknown_error", []string{"test-notify", "-c", c.cfg}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.api.reply(apiReply{body: tc.body})
			if code := c.run(tc.cmd...); code != 5 {
				t.Fatalf("exit %d\n%s", code, c.stderr)
			}
			if got := c.slackErrors(); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("slack_error %q, want %q\n%s", got, tc.want, c.stderr)
			}
		})
	}
}

// Webhook の方式の失敗には、Slack の error コードが無いので付かない。
func TestSendFailedWithoutSlackErrorOnWebhook(t *testing.T) {
	c := newCLI(t)
	c.hook.status = 500
	if code := c.run("test-notify", "-c", c.cfg); code != 5 {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	if got := c.slackErrors(); len(got) != 1 || got[0] != "" || strings.Contains(c.stderr.String(), "slack_error") {
		t.Fatalf("slack_error %q\n%s", got, c.stderr)
	}
}
