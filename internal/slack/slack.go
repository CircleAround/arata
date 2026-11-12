// Package slack は Slack への送信 (Incoming Webhook と、bot トークンの chat.postMessage。標準の net/http だけで書く。ADR 0018)。
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client は Incoming Webhook の送信者。
type Client struct {
	http *http.Client
}

// New は送信者を作る。hc が nil なら 30 秒で打ち切る http.Client を使う。
func New(hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{http: hc}
}

// Send は text だけを webhookURL へ 1 通送る。
// 決定: Webhook の URL は秘密なので、返すエラーに URL を含めない (net/http のエラーは URL を含むため、中身だけを取り出す)。
// 再送はしない (Slack が受け取ったのに応答が届かなかった場合に二重に送らないため)。
func (c *Client) Send(ctx context.Context, webhookURL, text string) error {
	return c.Post(ctx, webhookURL, map[string]string{"text": text})
}

// Post は payload (text と blocks など。Incoming Webhook が受け付ける形) を JSON にして webhookURL へ 1 通送る。
// URL をエラーに含めないこと・再送しないことは Send と同じ。
func (c *Client) Post(ctx context.Context, webhookURL string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("slack: invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("slack: post webhook: %w", err)
	}
	defer res.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("slack: webhook returned %d: %s", res.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
