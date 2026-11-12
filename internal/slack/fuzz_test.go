package slack

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ファズテスト (ADR 0041)。Slack の Web API の応答 (本文とヘッダー) を信用しない入力として与える。
// ふだんの `go test` は seed だけを走らせる。探索は tools/fuzz.sh。

var (
	fuzzCode  = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	fuzzID    = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)
	fuzzScope = regexp.MustCompile(`^[a-z0-9:._-]{1,64}$`)
)

// 応答の本文。守る規則:
//   - 成功とみなすのは、JSON のオブジェクトで "ok" が真偽値の true のときだけ
//   - error コードは [a-z0-9_] で 64 字まで (それ以外は unknown_error)。成功のときは空
//   - team_id / user_id は [A-Z0-9] で 32 字まで (それ以外は空)
//   - エラーの文は固定で、本文を写さない
func FuzzParseResponse(f *testing.F) {
	for _, s := range []string{
		`{"ok":true}`, `{"ok":false,"error":"not_in_channel"}`, `{"ok":true,"team_id":"T0123ABCD","user_id":"U0123ABCD"}`,
		`{"ok":"true"}`, `{"OK":true}`, `{"ok":true,"ok":false}`, `{"ok":false,"error":"<!channel>\nx"}`, `{"ok":false,"error":{"a":1}}`,
		`{"ok":false}`, `[]`, `null`, `true`, ``, `{"ok":1}`, `{"ok":false,"error":"` + strings.Repeat("a", 65) + `"}`, "{\"ok\":true}\x00",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseResponse(body)
		if err != nil {
			if r != (Response{}) {
				t.Fatalf("error with a value: %+v", r)
			}
			if msg := err.Error(); msg != errNotObject.Error() && msg != errNoOK.Error() {
				t.Fatalf("error must be one of the fixed texts: %q", msg)
			}
			return
		}
		if r.OK {
			// 別の読み方でも ok が true であること (大文字小文字の違うキーを ok とみなさない)
			var m map[string]json.RawMessage
			if json.Unmarshal(body, &m) != nil || strings.TrimSpace(string(m["ok"])) != "true" {
				t.Fatalf("accepted as ok: %q", body)
			}
			if r.Error != "" {
				t.Fatalf("ok with an error code: %+v", r)
			}
		} else if !fuzzCode.MatchString(r.Error) {
			t.Fatalf("error code %q", r.Error)
		}
		for _, id := range []string{r.TeamID, r.UserID} {
			if id != "" && !fuzzID.MatchString(id) {
				t.Fatalf("id %q", id)
			}
		}
	})
}

// Retry-After。守る規則: 0 以上 24 時間以下。秒の整数として読めたらその値 (24 時間で頭打ち)、読めなければ 1 秒。
func FuzzRetryAfter(f *testing.F) {
	for _, s := range []string{"", "0", "1", "30", "86400", "86401", "-1", "1.5", " 7 ", "99999999999999999999", "Wed, 21 Oct 2026 07:28:00 GMT", "1\n2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		d := retryAfter(v)
		if d < 0 || d > maxRetryAfterValue {
			t.Fatalf("%q → %v", v, d)
		}
		if d%time.Second != 0 {
			t.Fatalf("%q → %v is not whole seconds", v, d)
		}
	})
}

// X-OAuth-Scopes。守る規則: 残るのは [a-z0-9:._-] で 64 字までの名前だけ、100 個まで、重複なし。
func FuzzParseScopes(f *testing.F) {
	for _, s := range []string{"chat:write", "chat:write,channels:read", " chat:write , chat:write ", "<!channel>,chat:write", "", ",,,", strings.Repeat("a,", 300), "CHAT:WRITE"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := ParseScopes(v)
		if len(got) > maxScopes {
			t.Fatalf("%d scopes", len(got))
		}
		seen := map[string]bool{}
		for _, s := range got {
			if !fuzzScope.MatchString(s) || seen[s] {
				t.Fatalf("scope %q in %q", s, got)
			}
			seen[s] = true
			if !strings.Contains(v, s) {
				t.Fatalf("scope %q is not in the header", s)
			}
		}
	})
}

// 送信の全体 (偽の API)。守る規則:
//   - 成功を返すのは、HTTP 2xx で本文の "ok" が true のときだけ
//   - エラーの文は 1 行で、トークンも、応答の本文の断片 (目印の文字列) も含まない。長さに上限がある
//   - 呼び出しは 1 + MaxRateLimitRetries 回まで
func FuzzPostMessageResponse(f *testing.F) {
	f.Add(200, `{"ok":true}`, "")
	f.Add(200, `{"ok":false,"error":"not_in_channel"}`, "")
	f.Add(429, `{"ok":false,"error":"ratelimited"}`, "1")
	f.Add(429, ``, "99999")
	f.Add(200, `{"ok":false,"error":"ratelimited"}`, "-5")
	f.Add(500, `<html>MARKER</html>`, "")
	f.Add(200, `{"ok":false,"error":"MARKER xoxb-fake-secret-token"}`, "")
	f.Add(204, ``, "")
	f.Add(302, `{"ok":true}`, "")
	f.Fuzz(func(t *testing.T, status int, body, retry string) {
		if status < 200 || status > 599 || status == http.StatusNotModified {
			t.Skip()
		}
		// ヘッダーに書けない値は net/http が送れない
		for _, r := range retry {
			if r < 0x20 || r > 0x7e {
				t.Skip()
			}
		}
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if retry != "" {
				w.Header().Set("Retry-After", retry)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		defer srv.Close()
		b := NewBot(srv.Client(), fakeToken, srv.URL)
		b.sleep = func(context.Context, time.Duration) error { return nil }
		err := b.PostMessage(context.Background(), "C0123456789", map[string]string{"text": "x"})
		if calls > 1+MaxRateLimitRetries {
			t.Fatalf("%d calls", calls)
		}
		if err == nil {
			var m map[string]json.RawMessage
			if status/100 != 2 || json.Unmarshal([]byte(body), &m) != nil || strings.TrimSpace(string(m["ok"])) != "true" {
				t.Fatalf("accepted status %d body %q", status, body)
			}
			return
		}
		msg := err.Error()
		if strings.Contains(msg, fakeToken) || strings.ContainsAny(msg, "\r\n") || !utf8.ValidString(msg) || utf8.RuneCountInString(msg) > 600 {
			t.Fatalf("error text: %q", msg)
		}
		if strings.Contains(body, "MARKER") && strings.Contains(msg, "MARKER") {
			t.Fatalf("error text copies the body: %q", msg)
		}
		var ae *APIError
		if errors.As(err, &ae) && ae.Code != "" && !fuzzCode.MatchString(ae.Code) {
			t.Fatalf("code %q", ae.Code)
		}
	})
}
