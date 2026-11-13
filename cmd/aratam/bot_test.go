package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/CircleAround/arata/internal/notify"
)

// 架空の値。トークンは実在の形にしない (cli.run が "secret" とトークンそのものを出力に探す)。
const (
	botToken      = "xoxb-fake-secret-token"
	normalChannel = "C0123456789"
	urgentChannel = "C0123456780"
)

// slackAPI は Slack の Web API の偽物 (実 Slack には接続しない)。呼び出しごとに replies の先頭から返す (尽きたら {"ok":true})。
type slackAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	replies []apiReply
	calls   []apiCall
}

type apiReply struct {
	status     int
	body       string
	retryAfter string
	scopes     string
}

type apiCall struct {
	method, auth string
	raw          []byte
	body         map[string]any
}

func newSlackAPI(t *testing.T) *slackAPI {
	a := &slackAPI{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		a.mu.Lock()
		a.calls = append(a.calls, apiCall{method: strings.TrimPrefix(r.URL.Path, "/api/"), auth: r.Header.Get("Authorization"), raw: b, body: m})
		rep := apiReply{body: `{"ok":true}`}
		if len(a.replies) > 0 {
			rep, a.replies = a.replies[0], a.replies[1:]
		}
		a.mu.Unlock()
		if rep.retryAfter != "" {
			w.Header().Set("Retry-After", rep.retryAfter)
		}
		if rep.scopes != "" {
			w.Header().Set("X-OAuth-Scopes", rep.scopes)
		}
		if rep.status == 0 {
			rep.status = http.StatusOK
		}
		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *slackAPI) all() []apiCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]apiCall(nil), a.calls...)
}

// posts は chat.postMessage の呼び出しのうち、channel へのものの text。
func (a *slackAPI) posts(channel string) []string {
	var out []string
	for _, c := range a.all() {
		if c.method == "chat.postMessage" && c.body["channel"] == channel {
			text, _ := c.body["text"].(string)
			out = append(out, text)
		}
	}
	return out
}

func (a *slackAPI) reply(r ...apiReply) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.replies = append(a.replies, r...)
}

// useBot は設定を bot トークンの方式に書き換える。Webhook の環境変数は無い (秘密はトークン 1 つ)。
func (c *cli) useBot() {
	c.t.Helper()
	c.editConfig("webhook_env: ARATAM_SLACK_WEBHOOK ", `webhook_env: "" `)
	c.editConfig("urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ", `urgent_webhook_env: "" `)
	c.editConfig(`bot_token_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN")
	c.editConfig(`  channel: ""`, "  channel: "+normalChannel)
	c.editConfig(`urgent_channel: ""`, "urgent_channel: "+urgentChannel)
	c.env = map[string]string{"ARATAM_SLACK_BOT_TOKEN": botToken}
}

// bot トークンの方式: chat.postMessage に Bearer でチャンネル ID を付けて送る。Webhook には送らない。
func TestNotifyBotSendsToUrgentChannelOnce(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.api.posts(urgentChannel); len(got) != 1 || !strings.HasPrefix(got[0], "*arata daily (acme)*") || len(c.api.posts(normalChannel)) != 0 {
		t.Fatalf("got %+v", c.api.all())
	}
	call := c.api.all()[0]
	if call.auth != "Bearer "+botToken || call.body["unfurl_links"] != false || call.body["unfurl_media"] != false {
		t.Fatalf("%s %s", call.auth, call.raw)
	}
	if len(c.hook.got) != 0 {
		t.Fatalf("must not use the webhook: %v", c.hook.got)
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 || len(c.api.all()) != 1 || strings.Join(c.codes(), ",") != notify.CodeAlreadyNotified {
		t.Fatalf("second notify must not send: exit %d %s", code, c.stderr)
	}
}

// 緊急用のチャンネルが無ければ通常用に送り、冒頭にメンションを付ける (urgent_webhook_env と同じ考え方)。
func TestNotifyBotUrgentFallsBackToChannelWithMention(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.editConfig("urgent_channel: "+urgentChannel, `urgent_channel: ""`)
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.api.posts(normalChannel); len(got) != 1 || !strings.HasPrefix(got[0], "<!channel>\n*arata daily") {
		t.Fatalf("got %+v", c.api.all())
	}
}

// blocks でも Webhook と同じ payload (text と blocks) に channel を足して送る。
func TestNotifyBotBlocks(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.useBlocks()
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	calls := c.api.all()
	if len(calls) != 1 {
		t.Fatalf("%+v", calls)
	}
	var p payload
	if err := json.Unmarshal(calls[0].raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.Text != "arata daily (acme): 新規 3 件、最大 critical" || len(p.Blocks) == 0 || p.Blocks[0].Type != "header" || calls[0].body["channel"] != urgentChannel {
		t.Fatalf("%s", calls[0].raw)
	}

	// 同じ入力を Webhook の方式で送ったものと、channel 以外は同じ
	w := newCLI(t)
	w.useBlocks()
	if code := w.run("notify", "-c", w.cfg, "--in", in, "--force"); code != 0 {
		t.Fatalf("exit %d %s", code, w.stderr)
	}
	var viaHook, viaBot map[string]any
	if err := json.Unmarshal(w.hook.raw[urgentPath][0], &viaHook); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(calls[0].raw, &viaBot)
	delete(viaBot, "channel")
	a, _ := json.Marshal(viaHook)
	b, _ := json.Marshal(viaBot)
	if string(a) != string(b) {
		t.Fatalf("payload differs:\n%s\n%s", a, b)
	}
}

// --dry-run はトークンの環境変数が無くても動き、送らない。送り先はチャンネル ID で出す。
func TestNotifyBotDryRun(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.env = map[string]string{}
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir(), "--dry-run"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if !strings.HasPrefix(c.stdout.String(), "--- route: urgent → urgent channel "+urgentChannel+" ---\n*arata daily") || len(c.api.all()) != 0 {
		t.Fatalf("stdout:\n%s", c.stdout)
	}
	c.editConfig("urgent_channel: "+urgentChannel, `urgent_channel: ""`)
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir(), "--dry-run"); code != 0 ||
		!strings.HasPrefix(c.stdout.String(), "--- route: urgent → channel "+normalChannel+" (no urgent channel) ---\n<!channel>\n") {
		t.Fatalf("exit %d stdout:\n%s", code, c.stdout)
	}
}

// Slack は HTTP 200 で {"ok": false} を返す。失敗 (終了コード 5) にし、何をすればよいかをログに書く。トークンは出さない (run が確かめる)。
func TestNotifyBotFailures(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	in := c.inputDir()
	c.api.reply(apiReply{body: `{"ok":false,"error":"not_in_channel"}`})
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 5 || strings.Join(c.codes(), ",") != notify.CodeSendFailed {
		t.Fatalf("not_in_channel: exit %d %s", code, c.stderr)
	}
	for _, want := range []string{"not_in_channel", "bot をチャンネルに招待", urgentChannel} {
		if !strings.Contains(c.stderr.String(), want) {
			t.Errorf("stderr lacks %q: %s", want, c.stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(in, ".aratam-notified")); err == nil {
		t.Fatal("a failed send must not be marked as notified")
	}

	// ratelimited は Retry-After だけ待って送り直す (テストは 0 秒)
	c.api.reply(apiReply{status: http.StatusTooManyRequests, body: `{"ok":false,"error":"ratelimited"}`, retryAfter: "0"})
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 || len(c.api.posts(urgentChannel)) != 3 {
		t.Fatalf("ratelimited: exit %d %s (%d posts)", code, c.stderr, len(c.api.posts(urgentChannel)))
	}

	// トークンの環境変数が無い → 2
	c.env = map[string]string{}
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 2 || !strings.Contains(c.stderr.String(), "ARATAM_SLACK_BOT_TOKEN (slack.bot_token_env) is not set") {
		t.Fatalf("missing token env: exit %d %s", code, c.stderr)
	}
	// トークンに空白や改行が混じっている → 2 (値は出さない)
	c.env = map[string]string{"ARATAM_SLACK_BOT_TOKEN": "xoxb-fake secret"}
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 2 || !strings.Contains(c.stderr.String(), "ARATAM_SLACK_BOT_TOKEN") {
		t.Fatalf("broken token: exit %d %s", code, c.stderr)
	}
	// 末尾の改行 (secret を貼ったときに付きやすい) は除いて使う
	c.env = map[string]string{"ARATAM_SLACK_BOT_TOKEN": botToken + "\n"}
	before := len(c.api.all())
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 || c.api.all()[before].auth != "Bearer "+botToken {
		t.Fatalf("trailing newline: exit %d %s", code, c.stderr)
	}
}

// LLM が使えないときの原文の送信 (終了コード 3) も同じ規則で、bot トークンは子プロセスに渡さない。
func TestNotifyBotClaudeCLIFallbackAndEnv(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.useClaude()
	c.fakeMode = "fail"
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 3 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.api.posts(urgentChannel); len(got) != 1 || !strings.Contains(got[0], notify.FallbackNotice) {
		t.Fatalf("%+v", c.api.all())
	}
	env, _ := os.ReadFile(filepath.Join(c.rec, "env"))
	if len(env) == 0 || strings.Contains(string(env), "xoxb-") || strings.Contains(string(env), "ARATAM_SLACK") {
		t.Fatalf("the bot token must not reach the child process:\n%s", env)
	}
}

// doctor は投稿せず、auth.test でトークンが有効かだけを確かめる。
func TestDoctorBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.api.reply(apiReply{body: `{"ok":true,"team_id":"T0123ABCD","user_id":"U0123ABCD"}`, scopes: "chat:write"})
	if code := c.run("doctor", "-c", c.cfg); code != 0 || len(c.codes()) != 0 {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	for _, want := range []string{"auth.test", "T0123ABCD", normalChannel, urgentChannel, "test-notify"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, c.stdout)
		}
	}
	calls := c.api.all()
	if len(calls) != 1 || calls[0].method != "auth.test" || calls[0].auth != "Bearer "+botToken {
		t.Fatalf("doctor must call auth.test only: %+v", calls)
	}

	// chat:write が無いと分かった → warn。トークンが無効 → ng
	c.api.reply(apiReply{body: `{"ok":true}`, scopes: "channels:read"})
	if code := c.run("doctor", "-c", c.cfg); code != 0 || strings.Join(c.codes(), ",") != "SLACK_SCOPE_MISSING" {
		t.Fatalf("scope: exit %d %s\n%s", code, c.stderr, c.stdout)
	}
	c.api.reply(apiReply{body: `{"ok":false,"error":"invalid_auth"}`})
	if code := c.run("doctor", "-c", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "SLACK_AUTH_FAILED" || !strings.Contains(c.stdout.String(), "invalid_auth") {
		t.Fatalf("invalid_auth: exit %d %s\n%s", code, c.stderr, c.stdout)
	}
	// トークンの環境変数が無い → ng (API は呼ばない)
	n := len(c.api.all())
	c.env = map[string]string{}
	if code := c.run("doctor", "-c", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "BOT_TOKEN_UNSET" || len(c.api.all()) != n {
		t.Fatalf("unset: exit %d %s\n%s", code, c.stderr, c.stdout)
	}
	for _, call := range c.api.all() {
		if call.method != "auth.test" {
			t.Fatalf("doctor must not post: %s", call.method)
		}
	}
}

func TestTestNotifyBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	if code := c.run("test-notify", "-c", c.cfg); code != 0 || len(c.api.posts(normalChannel)) != 1 || !strings.Contains(c.api.posts(normalChannel)[0], "aratam の試験通知です (acme、通常用)") ||
		!strings.Contains(c.stdout.String(), normalChannel) {
		t.Fatalf("exit %d %+v\n%s", code, c.api.all(), c.stdout)
	}
	if code := c.run("test-notify", "-c", c.cfg, "--urgent"); code != 0 || len(c.api.posts(urgentChannel)) != 1 || strings.HasPrefix(c.api.posts(urgentChannel)[0], "<!channel>") {
		t.Fatalf("--urgent: exit %d %+v", code, c.api.all())
	}
	c.editConfig("urgent_channel: "+urgentChannel, `urgent_channel: ""`)
	if code := c.run("test-notify", "-c", c.cfg, "--urgent"); code != 0 || len(c.api.posts(normalChannel)) != 2 || !strings.HasPrefix(c.api.posts(normalChannel)[1], "<!channel>\n") {
		t.Fatalf("--urgent fallback: exit %d %+v", code, c.api.all())
	}
	c.api.reply(apiReply{body: `{"ok":false,"error":"channel_not_found"}`})
	if code := c.run("test-notify", "-c", c.cfg); code != 5 || strings.Join(c.codes(), ",") != notify.CodeSendFailed || !strings.Contains(c.stderr.String(), "channel_not_found") {
		t.Fatalf("failure: exit %d %s", code, c.stderr)
	}
}

// config check は bot トークンの方式でも Slack に繋がず、トークンの環境変数も要らない。使う方式を ok の行に出す。
func TestConfigCheckBot(t *testing.T) {
	c := newCLI(t)
	c.useBot()
	c.offline()
	if code := c.run("config", "check", "-c", c.cfg); code != 0 || len(c.codes()) != 0 {
		t.Fatalf("exit %d %v\n%s%s", code, c.codes(), c.stdout, c.stderr)
	}
	if got := string(c.checkOut()); got != "ok    <dir>/aratam.yaml: name acme, provider none, format text, slack bot, timezone UTC\n" {
		t.Fatalf("%q", got)
	}
	for _, tc := range []struct{ from, to, want string }{
		{`webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ", "choose one"},
		{"  channel: " + normalChannel, `  channel: "#general"`, "slack.channel must be a channel ID"},
		{"bot_token_env: ARATAM_SLACK_BOT_TOKEN", "bot_token_env: " + botToken, "slack.bot_token_env must be the name of an environment variable"},
	} {
		c := newCLI(t)
		c.useBot()
		c.offline()
		c.editConfig(tc.from, tc.to)
		if code := c.run("config", "check", "-c", c.cfg); code != 2 || !strings.Contains(c.stdout.String(), tc.want) {
			t.Fatalf("%s: exit %d\n%s", tc.to, code, c.stdout)
		}
	}
}
