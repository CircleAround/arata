package slack

import (
	"context"
	"strings"
	"testing"
)

// ADR 0093 の 3 節: chat.postMessage の応答の ts を返し、thread_ts を付けてスレッドに返信できる。
// ts は信用しない入力で、`^[0-9]{1,16}\.[0-9]{1,16}$` の形だけを受け付ける (それ以外は空)。

func TestPostMessageReturnsTS(t *testing.T) {
	a := newFakeAPI(t, reply{body: `{"ok":true,"channel":"C0123456789","ts":"1700000000.123456"}`})
	ts, err := a.bot(nil).PostMessage(context.Background(), "C0123456789", "", map[string]string{"text": "x"})
	if err != nil || ts != "1700000000.123456" {
		t.Fatalf("ts %q err %v", ts, err)
	}
	if _, ok := a.calls[0].body["thread_ts"]; ok {
		t.Fatalf("thread_ts must not be sent for the parent: %v", a.calls[0].body)
	}
}

func TestPostMessageIgnoresMalformedTS(t *testing.T) {
	for _, body := range []string{
		`{"ok":true}`, `{"ok":true,"ts":1700000000.123456}`, `{"ok":true,"ts":"1700000000"}`, `{"ok":true,"ts":"<!channel>"}`,
		`{"ok":true,"ts":"1700000000.123456\n"}`, `{"ok":true,"ts":"12345678901234567.1"}`, `{"ok":true,"ts":"-1.2"}`,
	} {
		a := newFakeAPI(t, reply{body: body})
		ts, err := a.bot(nil).PostMessage(context.Background(), "C0123456789", "", map[string]string{"text": "x"})
		if err != nil || ts != "" {
			t.Fatalf("%s: ts %q err %v", body, ts, err)
		}
	}
}

func TestPostMessageReplyInThread(t *testing.T) {
	a := newFakeAPI(t)
	if _, err := a.bot(nil).PostMessage(context.Background(), "C0123456789", "1700000000.123456", map[string]any{"text": "詳細", "thread_ts": "9.9", "reply_broadcast": true}); err != nil {
		t.Fatal(err)
	}
	b := a.calls[0].body
	// 引数の thread_ts で上書きし、reply_broadcast は送らない (返信をチャンネルに出さない)
	if b["thread_ts"] != "1700000000.123456" || b["channel"] != "C0123456789" || b["text"] != "詳細" {
		t.Fatalf("%v", b)
	}
	if _, ok := b["reply_broadcast"]; ok {
		t.Fatalf("reply_broadcast must not be sent: %v", b)
	}
}

func TestPostMessageRejectsBadThreadTS(t *testing.T) {
	a := newFakeAPI(t)
	for _, ts := range []string{"x", "1700000000", "1.2.3", "<!channel>", strings.Repeat("1", 17) + ".1"} {
		if _, err := a.bot(nil).PostMessage(context.Background(), "C0123456789", ts, map[string]string{"text": "x"}); err == nil || strings.Contains(err.Error(), ts) {
			t.Fatalf("%q: %v", ts, err)
		}
	}
	if len(a.calls) != 0 {
		t.Fatalf("sent %d", len(a.calls))
	}
}

func TestValidTS(t *testing.T) {
	for s, want := range map[string]bool{"1.2": true, "1700000000.123456": true, "": false, ".1": false, "1.": false, "1,2": false, " 1.2": false} {
		if ValidTS(s) != want {
			t.Fatalf("%q", s)
		}
	}
}
