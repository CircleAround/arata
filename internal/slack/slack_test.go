package slack

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendPostsTextAsJSON(t *testing.T) {
	var got map[string]string
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctype = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	if err := New(srv.Client()).Send(context.Background(), srv.URL+"/services/T000/B000/XXXX", "こんにちは <!channel>"); err != nil {
		t.Fatal(err)
	}
	if ctype != "application/json" || got["text"] != "こんにちは <!channel>" || len(got) != 1 {
		t.Fatalf("content-type %q body %v", ctype, got)
	}
}

// Webhook の URL は秘密なので、エラーの文言に出さない。
func TestSendErrorsDoNotLeakURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "no_service")
	}))
	secret := srv.URL + "/services/T000/B000/secret-token"
	err := New(srv.Client()).Send(context.Background(), secret, "x")
	if err == nil || !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "no_service") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("status error: %v", err)
	}

	srv.Close() // 接続できない
	err = New(srv.Client()).Send(context.Background(), secret, "x")
	if err == nil || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("network error must not contain the URL: %v", err)
	}

	err = New(nil).Send(context.Background(), "http://exa mple.invalid/secret-token", "x")
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("invalid URL error must not contain the URL: %v", err)
	}
}

func TestSendHonorsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := New(srv.Client()).Send(ctx, srv.URL, "x")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

// Post は payload (text と blocks) をそのまま JSON で送る (Block Kit)。
func TestPostSendsPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	payload := map[string]any{"text": "通知", "blocks": []map[string]any{{"type": "divider"}}}
	if err := New(srv.Client()).Post(context.Background(), srv.URL+"/services/T000/B000/XXXX", payload); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "通知" || len(got["blocks"].([]any)) != 1 {
		t.Fatalf("%v", got)
	}
}
