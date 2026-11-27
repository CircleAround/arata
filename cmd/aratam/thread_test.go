package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/notify"
)

// slack.details: thread (ADR 0093)。実 Slack には繋がず、偽の Web API (slackAPI) で確かめる。

const parentTS = "1700000000.000100"

func (c *cli) useThread() {
	c.t.Helper()
	c.useBot()
	c.editConfig("details: inline", "details: thread")
}

// 1 通目の応答の ts に thread_ts を付けて、同じチャンネルに返信する。返信はチャンネルに出さない。メンションは 1 通目だけ。
func TestNotifyThreadRepliesToParent(t *testing.T) {
	c := newCLI(t)
	c.useThread()
	c.api.reply(apiReply{body: `{"ok":true,"ts":"` + parentTS + `"}`})
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	calls := c.api.all()
	if len(calls) != 2 {
		t.Fatalf("calls %d", len(calls))
	}
	p, r := calls[0].body, calls[1].body
	if _, ok := p["thread_ts"]; ok || p["channel"] != urgentChannel || r["channel"] != urgentChannel || r["thread_ts"] != parentTS {
		t.Fatalf("parent %s\nreply %s", calls[0].raw, calls[1].raw)
	}
	if _, ok := r["reply_broadcast"]; ok {
		t.Fatalf("reply must not be broadcast: %s", calls[1].raw)
	}
	if !strings.Contains(string(calls[0].raw), "詳細はスレッド") || strings.Contains(string(calls[1].raw), "<!channel>") {
		t.Fatalf("parent %s\nreply %s", calls[0].raw, calls[1].raw)
	}
	// 通知済みなので 2 回目は送らない
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 || len(c.api.all()) != 2 {
		t.Fatalf("exit %d calls %d", code, len(c.api.all()))
	}
}

// 返信に失敗したら終了コード 5。1 通目は送れているので .aratam-notified は書く。返信だけの送り直しはしない。
func TestNotifyThreadReplyFailure(t *testing.T) {
	c := newCLI(t)
	c.useThread()
	c.api.reply(apiReply{body: `{"ok":true,"ts":"` + parentTS + `"}`}, apiReply{body: `{"ok":false,"error":"msg_too_long"}`})
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != notify.ExitSend || !strings.Contains(c.stderr.String(), notify.CodeSendFailed) || !strings.Contains(c.stderr.String(), "msg_too_long") {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if _, err := os.Stat(filepath.Join(in, notify.NotifiedFile)); err != nil {
		t.Fatalf("must mark notified: %v", err)
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 || len(c.api.all()) != 2 {
		t.Fatalf("must not resend: exit %d calls %d", code, len(c.api.all()))
	}
}

// 1 通目の応答に ts が無い (形が合わない) ときは、返信せず終了コード 5。
func TestNotifyThreadParentWithoutTS(t *testing.T) {
	c := newCLI(t)
	c.useThread()
	c.api.reply(apiReply{body: `{"ok":true,"ts":"<!channel>"}`})
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != notify.ExitSend || len(c.api.all()) != 1 {
		t.Fatalf("exit %d calls %d %s", code, len(c.api.all()), c.stderr)
	}
}

// --dry-run: 1 通目と返信を、区切りの行を挟んで標準出力に書く。json は messages[].thread_reply で返信を見分ける。
func TestNotifyThreadDryRun(t *testing.T) {
	c := newCLI(t)
	c.useThread()
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--dry-run"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	out := c.stdout.String()
	if strings.Count(out, "--- route: urgent") != 2 || !strings.Contains(out, "--- route: urgent → urgent channel "+urgentChannel+" (1 通目のスレッドへの返信) ---") {
		t.Fatalf("%s", out)
	}
	if len(c.api.all()) != 0 {
		t.Fatal("dry-run must not post")
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--dry-run", "--format", "json"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	var got struct {
		Messages []struct {
			Route       string         `json:"route"`
			ThreadReply *bool          `json:"thread_reply"`
			Payload     map[string]any `json:"payload"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 2 || got.Messages[0].ThreadReply == nil || *got.Messages[0].ThreadReply || !*got.Messages[1].ThreadReply {
		t.Fatalf("%s", c.stdout)
	}
	if _, ok := got.Messages[1].Payload["thread_ts"]; ok {
		t.Fatalf("payload must stay what is sent besides channel and thread_ts: %s", c.stdout)
	}
}

// test-notify: thread のとき、試しの 1 通目にスレッドの返信を 1 通付ける (受け口の転送を含めて、返信が届くことを本番の前に確かめる)。
func TestTestNotifyThread(t *testing.T) {
	c := newCLI(t)
	c.useThread()
	c.api.reply(apiReply{body: `{"ok":true,"ts":"` + parentTS + `"}`})
	if code := c.run("test-notify", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	calls := c.api.all()
	if len(calls) != 2 || calls[1].body["thread_ts"] != parentTS || calls[1].body["channel"] != normalChannel || !strings.Contains(c.stdout.String(), "スレッド") {
		t.Fatalf("%+v\n%s", calls, c.stdout)
	}
	// 返信に失敗したら終了コード 5
	c.api.reply(apiReply{body: `{"ok":true,"ts":"` + parentTS + `"}`}, apiReply{body: `{"ok":false,"error":"not_in_channel"}`})
	if code := c.run("test-notify", "-c", c.cfg); code != notify.ExitSend {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	// inline なら 1 通
	c.editConfig("details: thread", "details: inline")
	n := len(c.api.all())
	if code := c.run("test-notify", "-c", c.cfg); code != 0 || len(c.api.all()) != n+1 {
		t.Fatalf("exit %d calls %d", code, len(c.api.all())-n)
	}
}

// Webhook の方式と thread の組は設定エラー (終了コード 2)。
func TestNotifyThreadWithWebhookIsConfigError(t *testing.T) {
	c := newCLI(t)
	c.editConfig("details: inline", "details: thread")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != notify.ExitConfig || !strings.Contains(c.stderr.String(), "slack.details: thread") {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if len(c.hook.got) != 0 {
		t.Fatal("must not send")
	}
}
