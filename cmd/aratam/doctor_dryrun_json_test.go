package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

// doctor / notify --dry-run の --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestDoctorAndDryRunSchemasAreFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: doctorSchema, Version: doctorSchemaVersion, Versioned: true, Type: doctorOutput{},
		Description: "aratam doctor --format json の出力。Slack の環境変数 (bot トークンなら auth.test) と LLM の疎通の検査の行。送信はしない"}, *update)
	schematest.Golden(t, schematest.Spec{Name: dryRunSchema, Version: dryRunSchemaVersion, Versioned: true, Type: dryRunOutput{},
		Description: "aratam notify --dry-run --format json の出力。送らずに、送るはずだった通知を順に並べたもの。payload は Slack に送る中身そのもので、形は Slack の仕様に従う (このスキーマでは縛らない)"}, *update)
}

func (c *cli) doctorJSON(wantExit int) doctorOutput {
	c.t.Helper()
	if code := c.run("doctor", "-c", c.cfg, "--format", "json"); code != wantExit {
		c.t.Fatalf("exit %d, want %d\n%s%s", code, wantExit, c.stdout, c.stderr)
	}
	var out doctorOutput
	schematest.Conforms(c.t, doctorSchema, c.stdout.Bytes(), &out)
	return out
}

// doctor --format json: 行は table と同じ内容。ng があれば ok: false で終了コード 2 (table と同じ)。秘密は出さない (run が確かめる)。
func TestDoctorJSON(t *testing.T) {
	c := newCLI(t)
	out := c.doctorJSON(0)
	if !out.OK || len(out.Rows) < 3 || out.Rows[0].Item != "config" || out.Rows[0].Status != "ok" {
		t.Fatalf("%+v", out)
	}
	var llm *doctorJSONRow
	for i := range out.Rows {
		if out.Rows[i].Item == "llm" {
			llm = &out.Rows[i]
		}
	}
	if llm == nil || llm.Status != "skip" || llm.Code != "" {
		t.Fatalf("llm row: %+v", llm)
	}
	// 緊急用が無い → warn (ok のまま)。通常用も無い → ng
	delete(c.env, "ARATAM_SLACK_URGENT_WEBHOOK")
	if out := c.doctorJSON(0); !out.OK || !hasRow(out, "warn", "webhook", "URGENT_WEBHOOK_UNSET") {
		t.Fatalf("%+v", out)
	}
	delete(c.env, "ARATAM_SLACK_WEBHOOK")
	out = c.doctorJSON(2)
	if out.OK || !hasRow(out, "ng", "webhook", "WEBHOOK_UNSET") || strings.Join(c.codes(), ",") != "SLACK_WEBHOOK_DEPRECATED,WEBHOOK_UNSET,URGENT_WEBHOOK_UNSET" {
		t.Fatalf("%+v %v", out, c.codes())
	}
	if code := c.run("doctor", "-c", c.cfg, "--format", "yaml"); code != 2 || c.stdout.Len() != 0 {
		t.Fatalf("bad format: exit %d\n%s", code, c.stdout)
	}
}

func hasRow(out doctorOutput, status, item, code string) bool {
	for _, r := range out.Rows {
		if r.Status == status && r.Item == item && r.Code == code && r.Detail != "" {
			return true
		}
	}
	return false
}

// bot トークンの方式の doctor も同じ形 (auth.test の結果の行)。
func TestDoctorJSONBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.api.reply(apiReply{body: `{"ok":true,"team_id":"T0123456789"}`})
	out := c.doctorJSON(0)
	if !out.OK || !hasRow(out, "ok", "slack", "") {
		t.Fatalf("%+v", out)
	}
	delete(c.env, "ARATAM_SLACK_BOT_TOKEN")
	if out := c.doctorJSON(2); out.OK || !hasRow(out, "ng", "slack", "BOT_TOKEN_UNSET") {
		t.Fatalf("%+v", out)
	}
}

func (c *cli) dryRunJSON(wantExit int, args ...string) dryRunOutput {
	c.t.Helper()
	if code := c.run(append([]string{"notify", "-c", c.cfg, "--dry-run", "--format", "json"}, args...)...); code != wantExit {
		c.t.Fatalf("exit %d, want %d\n%s%s", code, wantExit, c.stdout, c.stderr)
	}
	var out dryRunOutput
	schematest.Conforms(c.t, dryRunSchema, c.stdout.Bytes(), &out)
	if strings.Contains(c.stdout.String(), "--- route") {
		c.t.Fatalf("the JSON output must be one JSON document, without the separator lines:\n%s", c.stdout)
	}
	return out
}

// notify --dry-run --format json は、全体が 1 つの JSON (ADR 0054)。以前は「--- route: … ---」の行と payload が交互に並び、jq に渡せなかった。
// payload は Slack に送る中身そのもの (text と blocks)。
func TestDryRunJSON(t *testing.T) {
	c := newCLI(t)
	c.useBlocks()
	out := c.dryRunJSON(0, "--in", c.inputDir())
	if len(out.Messages) != 1 {
		t.Fatalf("%+v", out)
	}
	m := out.Messages[0]
	if m.Route != "urgent" || m.Destination.Kind != "webhook" || m.Destination.Target != "urgent" || m.Destination.Channel != "" {
		t.Fatalf("%+v", m)
	}
	b, _ := json.Marshal(m.Payload)
	var p struct {
		Text   string
		Blocks []map[string]any
	}
	if err := json.Unmarshal(b, &p); err != nil || p.Text == "" || len(p.Blocks) == 0 {
		t.Fatalf("payload: %v\n%s", err, b)
	}
	if len(c.hook.got) != 0 {
		t.Fatal("dry-run must not send")
	}
	// 緊急用の Webhook が無ければ、緊急の通知は通常用に送る (target で分かる)
	delete(c.env, "ARATAM_SLACK_URGENT_WEBHOOK")
	if m := c.dryRunJSON(0, "--in", c.inputDir()).Messages[0]; m.Route != "urgent" || m.Destination.Kind != "webhook" || m.Destination.Target != "normal" {
		t.Fatalf("%+v", m)
	}
}

// bot トークンの方式では、送り先のチャンネル ID (秘密ではない) も出す。トークンは出さない (run が確かめる)。
func TestDryRunJSONBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	m := c.dryRunJSON(0, "--in", c.inputDir()).Messages[0]
	if m.Route != "urgent" || m.Destination.Kind != "channel" || m.Destination.Target != "urgent" || m.Destination.Channel != urgentChannel {
		t.Fatalf("%+v", m)
	}
	c.editConfig("urgent_channel: "+urgentChannel, `urgent_channel: ""`)
	if m := c.dryRunJSON(0, "--in", c.inputDir()).Messages[0]; m.Destination.Target != "normal" || m.Destination.Channel != normalChannel {
		t.Fatalf("%+v", m)
	}
	if n := len(c.api.all()); n != 0 {
		t.Fatalf("dry-run must not call the Slack API: %d", n)
	}
}

// 入力が無いときも 1 つの JSON (「実行されていない」の通知が 1 通。終了コード 4)。送るものが無ければ messages は空の配列。
func TestDryRunJSONInputProblemAndQuiet(t *testing.T) {
	c := newCLI(t)
	out := c.dryRunJSON(4, "--in", c.t.TempDir())
	if len(out.Messages) != 1 || out.Messages[0].Route != "urgent" {
		t.Fatalf("%+v", out)
	}
	// 設定の誤りでは、何も出さない (終了コード 2)
	c.editConfig("on_quiet: short", "on_quiet: loud")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir(), "--dry-run", "--format", "json"); code != 2 || c.stdout.Len() != 0 {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
}
