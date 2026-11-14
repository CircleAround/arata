package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/schemas"
)

// config check --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestConfigCheckSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: configCheckSchema, Version: configCheckSchemaVersion, Versioned: true, Type: configCheckOutput{},
		Description: "aratam config check --format json の出力。設定の形の検査の結果と、設定から決まる値 (Slack への送り方など)。Slack にも LLM にも繋がずに出す"}, *update)
}

// checkJSON は config check --format json を流し、出力がスキーマと型に合うことを確かめて返す。
func (c *cli) checkJSON(wantExit int) configCheckOutput {
	c.t.Helper()
	if code := c.run("config", "check", "-c", c.cfg, "--format", "json"); code != wantExit {
		c.t.Fatalf("exit %d, want %d\n%s%s", code, wantExit, c.stdout, c.stderr)
	}
	var out configCheckOutput
	schematest.Conforms(c.t, configCheckSchema, c.stdout.Bytes(), &out)
	return out
}

// 機械が読む値は --format json で出す。Webhook の方式。
func TestConfigCheckJSON(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.editConfig("provider: none", "provider: claude-cli")
	c.editConfig(`context_file: ""`, "context_file: context.md")
	c.editConfig("timezone: UTC", "timezone: Asia/Tokyo")
	if err := os.WriteFile(filepath.Join(c.dir, "context.md"), []byte("決済画面はリクエストが多い。\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := c.checkJSON(0)
	compareGolden(t, "config_check.json", c.checkOut())
	// 雛形は緊急用の Webhook を別に持つ (urgent_webhook_env が空でない)
	if !out.Slack.UrgentWebhook {
		t.Errorf("urgent_webhook must be true when slack.urgent_webhook_env is set: %+v", out.Slack)
	}
	if !out.OK || out.Name != "acme" || out.Slack == nil || out.Slack.Method != "webhook" || out.Slack.Format != "text" ||
		out.LLM == nil || out.LLM.Provider != "claude-cli" || out.Timezone != "Asia/Tokyo" || len(c.codes()) != 0 {
		t.Fatalf("%+v %v", out, c.codes())
	}
}

// bot トークンの方式。秘密 (トークン) が無くても判別できる (PR の CI には秘密を渡さない)。
func TestConfigCheckJSONBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.offline()
	out := c.checkJSON(0)
	if !out.OK || out.Slack == nil || out.Slack.Method != "bot" || out.Slack.UrgentWebhook || out.Timezone != "UTC" || out.LLM.Provider != "none" {
		t.Fatalf("%+v", out)
	}
	// チャンネル ID・環境変数の名前は出さない (送り方の判別に要らない)
	for _, s := range []string{normalChannel, urgentChannel, "ARATAM_SLACK_BOT_TOKEN", botToken} {
		if strings.Contains(c.stdout.String(), s) {
			t.Errorf("output must not carry %q:\n%s", s, c.stdout)
		}
	}
}

// 設定を読めないときは ok: false と ng の行だけを出し、設定から決まる値は出さない。
// `jq -r .slack.method` は null になり、「bot / webhook 以外なら止める」と書いた側は止まる。終了コードは text と同じ 2。
func TestConfigCheckJSONProblems(t *testing.T) {
	cases := map[string]func(c *cli){
		"invalid value": func(c *cli) { c.editConfig("on_quiet: short", "on_quiet: loud") },
		"unknown key":   func(c *cli) { c.editConfig("max_age: 26h", "max_agee: 26h") },
		"no file":       func(c *cli) { c.cfg = filepath.Join(c.dir, "none.yaml") },
		// 送り方が 2 つとも書いてある設定は、どちらとも言わない
		"both methods": func(c *cli) { c.editConfig(`bot_token_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			c := newCLI(t)
			c.offline()
			setup(c)
			out := c.checkJSON(2)
			if out.OK || out.Slack != nil || out.LLM != nil || out.Name != "" || out.Timezone != "" {
				t.Fatalf("a config that does not load must not report its values: %+v", out)
			}
			if len(out.Rows) != 1 || out.Rows[0].Status != "ng" || out.Rows[0].Item != "config" || out.Rows[0].Message == "" {
				t.Fatalf("rows: %+v", out.Rows)
			}
			if strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
				t.Fatalf("codes: %v", c.codes())
			}
			if strings.Contains(c.stdout.String(), `"slack"`) {
				t.Fatalf("no slack key:\n%s", c.stdout)
			}
		})
	}
}

// warn だけなら ok: true で終了コード 0 (text と同じ)。行に code が付く。
func TestConfigCheckJSONWarning(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.editConfig("provider: none", "provider: claude-cli")
	c.editConfig(`context_file: ""`, "context_file: none.md")
	out := c.checkJSON(0)
	// Webhook の方式なので、非推奨の警告の行 (ADR 0061) が先にある
	if !out.OK || len(out.Rows) != 3 || out.Rows[2].Status != "warn" || out.Rows[2].Item != "context" || out.Rows[2].Code != "CONTEXT_UNREADABLE" {
		t.Fatalf("%+v", out)
	}
}

func TestConfigCheckRejectsUnknownFormat(t *testing.T) {
	c := newCLI(t)
	c.offline()
	if code := c.run("config", "check", "-c", c.cfg, "--format", "yaml"); code != 2 || c.stdout.Len() != 0 ||
		!strings.Contains(c.stderr.String(), "text|json") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
}

// aratam schema: 引数なしで名前の一覧、名前を渡すと埋め込んだスキーマそのもの。
func TestSchemaCommand(t *testing.T) {
	c := newCLI(t)
	c.offline()
	if code := c.run("schema"); code != 0 || c.stdout.String() != strings.Join(schemas.Names(), "\n")+"\n" {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	for _, name := range schemas.Names() {
		c.stdout.Reset()
		want, _ := schemas.Lookup(name)
		if code := c.run("schema", name); code != 0 || c.stdout.String() != string(want) {
			t.Fatalf("%s: exit %d\n%s%s", name, code, c.stdout, c.stderr)
		}
	}
	c.stdout.Reset()
	if code := c.run("schema", "none"); code != 2 || c.stdout.Len() != 0 || !strings.Contains(c.stderr.String(), "aratam-config-check") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
}

// 緊急用の Webhook を使わない設定 (urgent_webhook_env が空) では、urgent_webhook は false。
// 書き出したワークフローは、これを見て「使う秘密」だけを仮の値と比べる (arata repo init。ADR 0059)。環境変数の名前は出さない。
func TestConfigCheckJSONWithoutUrgentWebhook(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.editConfig("urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK", `urgent_webhook_env: ""`)
	out := c.checkJSON(0)
	if !out.OK || out.Slack == nil || out.Slack.Method != "webhook" || out.Slack.UrgentWebhook {
		t.Fatalf("%+v", out.Slack)
	}
	if !strings.Contains(c.stdout.String(), `"urgent_webhook": false`) {
		t.Errorf("urgent_webhook must be present even when false (readers tell an old aratam by its absence):\n%s", c.stdout)
	}
}
