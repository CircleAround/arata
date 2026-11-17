package llm

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// fakeBedrock は Converse API の偽物 (実 AWS には接続しない)。
func fakeBedrock(t *testing.T, handler http.HandlerFunc) *Bedrock {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := bedrockruntime.New(bedrockruntime.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		HTTPClient:       srv.Client(),
		RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "example"}, nil
		}),
	})
	return &Bedrock{Client: client, Model: "us.example.model-v1"}
}

func reply(w http.ResponseWriter, stop string, texts ...string) {
	var content []map[string]string
	for _, t := range texts {
		content = append(content, map[string]string{"text": t})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"output":     map[string]any{"message": map[string]any{"role": "assistant", "content": content}},
		"stopReason": stop,
		"usage":      map[string]int{"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
		"metrics":    map[string]int{"latencyMs": 1},
	})
}

func TestBedrockConverse(t *testing.T) {
	var path string
	var body map[string]any
	b := fakeBedrock(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		reply(w, "end_turn", `{"headline":`, `"ok"}`)
	})
	out, err := b.Summarize(context.Background(), "SYSTEM", []byte(`{"name":"acme"}`))
	if err != nil || string(out) != `{"headline":"ok"}` {
		t.Fatalf("%q %v", out, err)
	}
	if path != "/model/us.example.model-v1/converse" {
		t.Fatalf("path %s", path)
	}
	got, _ := json.Marshal(map[string]any{"system": body["system"], "messages": body["messages"], "inferenceConfig": body["inferenceConfig"]})
	want := `{"inferenceConfig":{"maxTokens":4096},"messages":[{"content":[{"text":"{\"name\":\"acme\"}"}],"role":"user"}],"system":[{"text":"SYSTEM"}]}`
	if string(got) != want {
		t.Fatalf("request:\n%s\nwant\n%s", got, want)
	}
}

func TestBedrockErrors(t *testing.T) {
	b := fakeBedrock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"not authorized to perform bedrock:InvokeModel"}`)
	})
	if _, err := b.Summarize(context.Background(), "s", []byte("{}")); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("%v", err)
	}

	b = fakeBedrock(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, "max_tokens", `{"headline": "途中`) })
	if _, err := b.Summarize(context.Background(), "s", []byte("{}")); err == nil || !strings.Contains(err.Error(), "cut at 4096 tokens") {
		t.Fatalf("max_tokens: %v", err)
	}

	b = fakeBedrock(t, func(w http.ResponseWriter, _ *http.Request) { reply(w, "end_turn", "  ") })
	if _, err := b.Summarize(context.Background(), "s", []byte("{}")); err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Fatalf("empty: %v", err)
	}
}

func TestBedrockTimeout(t *testing.T) {
	release := make(chan struct{})
	b := fakeBedrock(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := b.Summarize(ctx, "s", []byte("{}")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// Anthropic などのモデルは、アカウントで最初の呼び出しのときに AWS Marketplace の手続きが行われる。その権限が無い主体の呼び出しは
// AccessDeniedException で、文に aws-marketplace が入る (利用者の環境で起きた)。doctor と notify の案内のために見分ける。
func TestMarketplaceAccessDenied(t *testing.T) {
	deny := func(msg string) error {
		b := fakeBedrock(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"message":"`+msg+`"}`)
		})
		_, err := b.Summarize(context.Background(), "s", []byte("{}"))
		return err
	}
	err := deny("Model access is denied due to IAM user or service role is not authorized to perform the required AWS Marketplace actions (aws-marketplace:ViewSubscriptions, aws-marketplace:Subscribe) to enable access to this model.")
	if !MarketplaceAccessDenied(err) {
		t.Fatalf("marketplace: %v", err)
	}
	// エラーの文に案内が載る (doctor の ng の行と、notify の LLM_FAILED のログに出る)
	if !strings.Contains(err.Error(), MarketplaceHint) {
		t.Fatalf("the error must carry the hint: %v", err)
	}
	if err := deny("not authorized to perform bedrock:InvokeModel"); MarketplaceAccessDenied(err) {
		t.Fatalf("plain access denied must not be the marketplace case: %v", err)
	}
	if MarketplaceAccessDenied(nil) {
		t.Fatal("nil")
	}
}
