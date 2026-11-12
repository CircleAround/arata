package slack

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// 架空のトークン (実在の形にしない。秘密の検査に掛からないように数字の並びを避ける)。
const fakeToken = "xoxb-fake-secret-token"

// fakeAPI は Slack の Web API の偽物。呼び出しごとに replies の先頭から返す (尽きたら {"ok":true})。
type fakeAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	replies []reply
	calls   []call
}

type reply struct {
	status     int
	body       string
	retryAfter string
	scopes     string
}

type call struct {
	path, auth, ctype string
	body              map[string]any
}

func newFakeAPI(t *testing.T, replies ...reply) *fakeAPI {
	a := &fakeAPI{replies: replies}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		a.mu.Lock()
		a.calls = append(a.calls, call{path: r.URL.Path, auth: r.Header.Get("Authorization"), ctype: r.Header.Get("Content-Type"), body: m})
		rep := reply{status: http.StatusOK, body: `{"ok":true}`}
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

// bot は偽の API に向けた Bot。待ち時間は記録するだけで眠らない。
func (a *fakeAPI) bot(slept *[]time.Duration) *Bot {
	b := NewBot(a.srv.Client(), fakeToken, a.srv.URL+"/api")
	b.sleep = func(_ context.Context, d time.Duration) error {
		if slept != nil {
			*slept = append(*slept, d)
		}
		return nil
	}
	return b
}

func TestPostMessageSendsChannelAndBearer(t *testing.T) {
	a := newFakeAPI(t)
	payload := map[string]any{"text": "通知", "blocks": []map[string]any{{"type": "divider"}}, "unfurl_links": false}
	if err := a.bot(nil).PostMessage(context.Background(), "C0123456789", payload); err != nil {
		t.Fatal(err)
	}
	if len(a.calls) != 1 {
		t.Fatalf("calls %d", len(a.calls))
	}
	c := a.calls[0]
	if c.path != "/api/chat.postMessage" || c.auth != "Bearer "+fakeToken || !strings.HasPrefix(c.ctype, "application/json") {
		t.Fatalf("%+v", c)
	}
	if c.body["channel"] != "C0123456789" || c.body["text"] != "通知" || len(c.body["blocks"].([]any)) != 1 || c.body["unfurl_links"] != false {
		t.Fatalf("%v", c.body)
	}
}

// Slack は HTTP 200 でも {"ok": false} を返す。ok を見て失敗にし、何をすればよいかを書く。
func TestPostMessageChecksOK(t *testing.T) {
	cases := []struct{ code, want string }{
		{"not_in_channel", "招待"},
		{"channel_not_found", "チャンネル ID"},
		{"invalid_auth", "トークン"},
		{"token_revoked", "トークン"},
		{"missing_scope", "chat:write"},
		{"is_archived", "アーカイブ"},
		{"some_new_error", "some_new_error"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			a := newFakeAPI(t, reply{body: `{"ok":false,"error":"` + tc.code + `"}`})
			err := a.bot(nil).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
			var ae *APIError
			if !errors.As(err, &ae) || ae.Code != tc.code || ae.Method != "chat.postMessage" {
				t.Fatalf("want APIError %s, got %v", tc.code, err)
			}
			for _, w := range []string{tc.code, tc.want, "C0123456789"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error lacks %q: %v", w, err)
				}
			}
			if strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), "\n") {
				t.Fatalf("error must be one line without the token: %v", err)
			}
			if len(a.calls) != 1 {
				t.Fatalf("must not retry %s: %d calls", tc.code, len(a.calls))
			}
		})
	}
}

// chat:write.public には頼らない。not_in_channel は「bot を招待する」と分かる文にする。
func TestNotInChannelTellsToInvite(t *testing.T) {
	a := newFakeAPI(t, reply{body: `{"ok":false,"error":"not_in_channel"}`})
	err := a.bot(nil).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
	if err == nil || !strings.Contains(err.Error(), "bot をチャンネルに招待") || !strings.Contains(err.Error(), "/invite") {
		t.Fatalf("%v", err)
	}
}

// ratelimited は Slack が受け取っていないので、Retry-After だけ待って限られた回数だけ再試行する。
func TestRateLimitedRetriesHonoringRetryAfter(t *testing.T) {
	limited := reply{status: http.StatusTooManyRequests, body: `{"ok":false,"error":"ratelimited"}`, retryAfter: "3"}
	var slept []time.Duration
	a := newFakeAPI(t, limited, limited)
	if err := a.bot(&slept).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"}); err != nil {
		t.Fatal(err)
	}
	if len(a.calls) != 3 || len(slept) != 2 || slept[0] != 3*time.Second || slept[1] != 3*time.Second {
		t.Fatalf("calls %d slept %v", len(a.calls), slept)
	}

	// 回数の上限 (再試行は 2 回まで)
	slept = nil
	a = newFakeAPI(t, limited, limited, limited, limited)
	err := a.bot(&slept).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "ratelimited" || len(a.calls) != 1+MaxRateLimitRetries || len(slept) != MaxRateLimitRetries {
		t.Fatalf("err %v calls %d slept %v", err, len(a.calls), slept)
	}

	// 待ち時間が上限より長ければ、短く待って送り直すことはしない (Retry-After を破らない)
	slept = nil
	a = newFakeAPI(t, reply{status: http.StatusTooManyRequests, body: `{"ok":false,"error":"ratelimited"}`, retryAfter: "3600"})
	err = a.bot(&slept).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
	if !errors.As(err, &ae) || ae.Code != "ratelimited" || len(a.calls) != 1 || len(slept) != 0 || !strings.Contains(err.Error(), "3600") {
		t.Fatalf("err %v calls %d slept %v", err, len(a.calls), slept)
	}

	// HTTP 200 の本文で ratelimited と返っても同じ扱い。Retry-After が無ければ 1 秒
	slept = nil
	a = newFakeAPI(t, reply{body: `{"ok":false,"error":"ratelimited"}`})
	if err := a.bot(&slept).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"}); err != nil {
		t.Fatal(err)
	}
	if len(a.calls) != 2 || len(slept) != 1 || slept[0] != time.Second {
		t.Fatalf("calls %d slept %v", len(a.calls), slept)
	}
}

// 待っている間に打ち切られたら、送り直さずに返す。
func TestRateLimitWaitHonorsContext(t *testing.T) {
	a := newFakeAPI(t, reply{status: http.StatusTooManyRequests, body: `{"ok":false,"error":"ratelimited"}`, retryAfter: "20"})
	b := NewBot(a.srv.Client(), fakeToken, a.srv.URL+"/api")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := b.PostMessage(ctx, "C0123456789", map[string]string{"text": "x"})
	if !errors.Is(err, context.DeadlineExceeded) || len(a.calls) != 1 {
		t.Fatalf("err %v calls %d", err, len(a.calls))
	}
}

// 応答の本文は信用しない。エラーの文に写すのは [a-z0-9_] の error コードだけで、トークンも本文も出さない。
func TestErrorsDoNotLeakTokenOrBody(t *testing.T) {
	bodies := []reply{
		{status: http.StatusInternalServerError, body: "<html>" + fakeToken + " internal</html>"},
		{status: http.StatusForbidden, body: `{"ok":false,"error":"echo ` + fakeToken + `"}`},
		{body: "not json " + fakeToken},
		{body: `{"ok":false,"error":"<!channel> ` + fakeToken + `\nsecond line"}`},
		{body: `{"ok":"true"}`},
		{body: `[]`},
		{body: ``},
		{body: `{"ok":false}`},
		{body: strings.Repeat(" ", maxResponseBytes) + `{"ok":true}`},
	}
	for _, rep := range bodies {
		a := newFakeAPI(t, rep)
		err := a.bot(nil).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
		if err == nil {
			t.Fatalf("%q must fail", rep.body)
		}
		for _, bad := range []string{fakeToken, "html", "<!channel>", "\n", "second line"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%q: error contains %q: %v", rep.body, bad, err)
			}
		}
	}

	// 接続できない
	a := newFakeAPI(t)
	b := a.bot(nil)
	a.srv.Close()
	err := b.PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
	if err == nil || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("network error: %v", err)
	}
	if len(a.calls) != 0 {
		t.Fatal("unexpected call")
	}
}

// 接続の失敗や 5xx では送り直さない (Slack が受け取っていた場合の二重送信を避ける。Webhook と同じ)。
func TestServerErrorIsNotRetried(t *testing.T) {
	a := newFakeAPI(t, reply{status: http.StatusBadGateway, body: "bad gateway"})
	err := a.bot(nil).PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
	if err == nil || !strings.Contains(err.Error(), "502") || len(a.calls) != 1 {
		t.Fatalf("err %v calls %d", err, len(a.calls))
	}
}

func TestAuthTest(t *testing.T) {
	a := newFakeAPI(t, reply{body: `{"ok":true,"team_id":"T0123ABCD","user_id":"U0123ABCD","url":"https://example.invalid/"}`, scopes: "chat:write, <bad scope>,channels:read"})
	got, err := a.bot(nil).AuthTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.TeamID != "T0123ABCD" || got.UserID != "U0123ABCD" || !got.ScopesKnown || strings.Join(got.Scopes, ",") != "chat:write,channels:read" || !got.HasScope("chat:write") {
		t.Fatalf("%+v", got)
	}
	if c := a.calls[0]; c.path != "/api/auth.test" || c.auth != "Bearer "+fakeToken {
		t.Fatalf("%+v", c)
	}

	// scope のヘッダーが無ければ「分からない」(無いとは言わない)。ID の形でない値は捨てる
	a = newFakeAPI(t, reply{body: `{"ok":true,"team_id":"<!channel>","user_id":12}`})
	got, err = a.bot(nil).AuthTest(context.Background())
	if err != nil || got.TeamID != "" || got.UserID != "" || got.ScopesKnown || got.HasScope("chat:write") {
		t.Fatalf("%+v %v", got, err)
	}

	a = newFakeAPI(t, reply{body: `{"ok":false,"error":"invalid_auth"}`})
	_, err = a.bot(nil).AuthTest(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "invalid_auth" || ae.Method != "auth.test" || strings.Contains(err.Error(), fakeToken) {
		t.Fatalf("%v", err)
	}
}

func TestValidToken(t *testing.T) {
	for _, ok := range []string{fakeToken, "xoxb-0-a"} {
		if !ValidToken(ok) {
			t.Errorf("%q must be accepted", ok)
		}
	}
	for _, ng := range []string{"", "xoxb fake", "xoxb-fake\n", "xoxb-fake\r\nX-Injected: 1", "トークン", "xoxb-\x00"} {
		if ValidToken(ng) {
			t.Errorf("%q must be rejected", ng)
		}
	}
}

func TestValidChannelID(t *testing.T) {
	for _, ok := range []string{"C0123456789", "G0123ABCD", "D0123ABCDEF"} {
		if !ValidChannelID(ok) {
			t.Errorf("%q must be accepted", ok)
		}
	}
	for _, ng := range []string{"", "#general", "general", "c0123456789", "C012", "U0123456789", "C0123456789 ", "C0123-56789", fakeToken, "C" + strings.Repeat("0", 40)} {
		if ValidChannelID(ng) {
			t.Errorf("%q must be rejected", ng)
		}
	}
}

func TestPostMessageRejectsBadArguments(t *testing.T) {
	a := newFakeAPI(t)
	if err := a.bot(nil).PostMessage(context.Background(), "#general", map[string]string{"text": "x"}); err == nil {
		t.Fatal("channel name must be rejected")
	}
	if err := a.bot(nil).PostMessage(context.Background(), "C0123456789", []string{"not an object"}); err == nil {
		t.Fatal("payload must be a JSON object")
	}
	b := NewBot(a.srv.Client(), "bad token\n", a.srv.URL+"/api")
	if err := b.PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"}); err == nil || strings.Contains(err.Error(), "bad token") {
		t.Fatalf("invalid token: %v", err)
	}
	if len(a.calls) != 0 {
		t.Fatalf("nothing must be sent: %d", len(a.calls))
	}
}
