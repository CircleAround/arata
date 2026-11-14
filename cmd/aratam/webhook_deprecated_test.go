package main

import (
	"strings"
	"testing"
)

const codeWebhookDeprecatedWant = "SLACK_WEBHOOK_DEPRECATED"

// Webhook の方式は非推奨 (ADR 0061)。config check は warn の行を足すが、終了コードは 0 のまま (動き続ける)。
// Slack が非推奨にしたとは書かない (arata の判断)。
func TestConfigCheckWarnsOnWebhook(t *testing.T) {
	c := newCLI(t)
	c.offline()
	out := c.checkJSON(0)
	if !out.OK || out.Slack.Method != "webhook" || len(out.Rows) != 2 {
		t.Fatalf("%+v", out)
	}
	r := out.Rows[1]
	if r.Status != "warn" || r.Item != "slack" || r.Code != codeWebhookDeprecatedWant || !strings.Contains(r.Message, "bot") || !strings.Contains(r.Message, "docs/aratam.md") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.Message, "Slack が非推奨") {
		t.Fatalf("the message must not say that Slack deprecated webhooks: %s", r.Message)
	}
	if code := c.run("config", "check", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "warn  slack: ") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
}

// bot トークンの方式には出さない。
func TestConfigCheckDoesNotWarnOnBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.offline()
	if out := c.checkJSON(0); len(out.Rows) != 1 || strings.Contains(c.stdout.String(), codeWebhookDeprecatedWant) {
		t.Fatalf("%+v", out)
	}
}

// doctor は warn の行を足し、標準エラーにも code 付きで出す。ng にはしない (終了コード 0)。
func TestDoctorWarnsOnWebhook(t *testing.T) {
	c := newCLI(t)
	out := c.doctorJSON(0)
	if !out.OK || !hasRow(out, "warn", "slack", codeWebhookDeprecatedWant) || strings.Join(c.codes(), ",") != codeWebhookDeprecatedWant {
		t.Fatalf("%+v %v", out, c.codes())
	}
	c = newCLI(t)
	c.useBot()
	c.api.reply(apiReply{body: `{"ok":true,"team_id":"T0123ABCD"}`, scopes: "chat:write"})
	if out := c.doctorJSON(0); hasRow(out, "warn", "slack", codeWebhookDeprecatedWant) || len(c.codes()) != 0 {
		t.Fatalf("bot must not warn: %+v %v", out, c.codes())
	}
}

// notify と test-notify は警告を出さない (定時の実行のたびに同じ行が出て、ほかの警告が埋もれる)。送信は、これまでどおり。
func TestNotifyDoesNotWarnOnWebhook(t *testing.T) {
	c := newCLI(t)
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 || strings.Contains(c.stderr.String(), codeWebhookDeprecatedWant) {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	if code := c.run("test-notify", "-c", c.cfg); code != 0 || strings.Contains(c.stderr.String(), codeWebhookDeprecatedWant) {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	c.hook.mu.Lock()
	defer c.hook.mu.Unlock()
	if len(c.hook.got) == 0 {
		t.Fatal("the webhook method must keep sending")
	}
}
