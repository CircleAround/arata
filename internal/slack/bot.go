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
	"regexp"
	"strconv"
	"strings"
	"time"
)

// bot トークンでの送信 (Web API の chat.postMessage。標準の net/http だけで書く)。
//
// 決定 (docs/aratam.md 4-1 章):
//   - 要る scope は chat:write だけ。chat:write.public には頼らず、bot がいないチャンネルへは送れない前提にする
//     (not_in_channel は「bot を招待する」と分かるエラーにする)。チャンネルの一覧や参加の API は呼ばない
//   - Slack は HTTP 200 でも {"ok": false, "error": "..."} を返すので、ok を必ず見る
//   - 応答は信用しない。エラーの文に写すのは [a-z0-9_] の error コードだけで、本文もトークンも写さない
//   - ratelimited は Slack が受け取っていないので、Retry-After だけ待って限られた回数だけ送り直す。
//     接続の失敗や 5xx では送り直さない (受け取られていた場合の二重送信を避ける。Webhook と同じ)

// APIURL は Slack の Web API の場所。
const APIURL = "https://slack.com/api"

const (
	// MaxRateLimitRetries は ratelimited のときに送り直す回数の上限。
	MaxRateLimitRetries = 2
	// MaxRetryWait は 1 回に待つ上限。Retry-After がこれより長ければ、短く待って送り直すことはせずに失敗にする。
	MaxRetryWait = 30 * time.Second
	// defaultRetryWait は Retry-After が無い・読めないときの待ち時間。
	defaultRetryWait = time.Second
	// maxRetryAfterValue は Retry-After として受け取る最大の値 (桁あふれを避ける頭打ち)。
	maxRetryAfterValue = 24 * time.Hour
	// maxResponseBytes は応答の本文を読む上限。超えたら解釈しない。
	maxResponseBytes = 64 << 10
	maxScopes        = 100
)

var (
	// チャンネル ID (C = チャンネル、G = 古い形式の非公開チャンネル、D = DM)。名前 (#general) は受け付けない。
	channelID = regexp.MustCompile(`^[CGD][A-Z0-9]{8,20}$`)
	errorCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	slackID   = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)
	scopeName = regexp.MustCompile(`^[a-z0-9:._-]{1,64}$`)

	errNotObject = errors.New("response is not a JSON object")
	errNoOK      = errors.New(`response has no boolean "ok"`)
)

// ValidChannelID は s がチャンネル ID の形かを返す。
func ValidChannelID(s string) bool { return channelID.MatchString(s) }

// ValidToken は s がヘッダーに書けるトークンの形 (空白・制御文字の無い ASCII) かを返す。
// 前後の空白 (secret の末尾の改行など) は呼び出し側で除いてから渡す。
func ValidToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// Bot は bot トークンでの送信者。
type Bot struct {
	http  *http.Client
	token string
	base  string
	sleep func(context.Context, time.Duration) error
}

// NewBot は送信者を作る。hc が nil なら 30 秒で打ち切る http.Client、apiURL が空なら APIURL を使う (テストは httptest に向ける)。
func NewBot(hc *http.Client, token, apiURL string) *Bot {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if apiURL == "" {
		apiURL = APIURL
	}
	return &Bot{http: hc, token: token, base: strings.TrimRight(apiURL, "/"), sleep: sleepContext}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// APIError は Slack の Web API が返した失敗。Code は応答の error (形を確かめたもの)。HTTP の状態だけで失敗したときは空。
type APIError struct {
	Method     string
	Code       string
	Status     int
	Channel    string
	RetryAfter time.Duration
}

// hints は error コードごとの「何をすればよいか」。
var hints = map[string]string{ // #nosec G101 -- Slack の error コード (token_revoked など) と案内の文の対応表で、秘密の値ではない
	"not_in_channel":         "bot がこのチャンネルにいません。bot をチャンネルに招待してください (チャンネルで /invite @<bot の名前>)。aratam は chat:write.public を使いません",
	"channel_not_found":      "チャンネル ID が違うか、bot を招待していない非公開チャンネルです。slack.channel / slack.urgent_channel のチャンネル ID を確かめ、bot をチャンネルに招待してください",
	"is_archived":            "チャンネルがアーカイブされています。slack.channel / slack.urgent_channel を見直してください",
	"invalid_auth":           "トークンが無効です。slack.bot_token_env の環境変数の値 (xoxb- で始まる bot トークン) を確かめてください",
	"not_authed":             "トークンが無効です。slack.bot_token_env の環境変数の値 (xoxb- で始まる bot トークン) を確かめてください",
	"token_revoked":          "トークンが取り消されています。Slack アプリを入れ直し、新しいトークンを設定してください",
	"token_expired":          "トークンの期限が切れています。Slack アプリのトークンのローテーションを無効にしてください (aratam はトークンを更新しません)",
	"account_inactive":       "トークンの持ち主が無効になっています。Slack アプリを入れ直し、新しいトークンを設定してください",
	"missing_scope":          "bot に chat:write の scope がありません。Slack アプリの Bot Token Scopes に chat:write を足し、ワークスペースに入れ直してください",
	"not_allowed_token_type": "bot トークン (xoxb- で始まる) を使ってください",
	"msg_too_long":           "本文が Slack の上限を超えました (aratam notify --dry-run --format json で送る内容を確かめてください)",
	"invalid_blocks":         "blocks の形を Slack が受け付けませんでした (aratam notify --dry-run --format json で送る内容を確かめてください)",
	"invalid_blocks_format":  "blocks の形を Slack が受け付けませんでした (aratam notify --dry-run --format json で送る内容を確かめてください)",
}

func (e *APIError) Error() string {
	var b strings.Builder
	b.WriteString("slack: " + e.Method)
	switch {
	case e.Code == "ratelimited":
		fmt.Fprintf(&b, " failed: ratelimited (Retry-After %d 秒)", int(e.RetryAfter/time.Second))
	case e.Code != "" && e.Status/100 != 2:
		fmt.Fprintf(&b, " returned HTTP %d: %s", e.Status, e.Code)
	case e.Code != "":
		b.WriteString(" failed: " + e.Code)
	default:
		fmt.Fprintf(&b, " returned HTTP %d", e.Status)
	}
	if e.Channel != "" {
		b.WriteString(" (channel " + e.Channel + ")")
	}
	if e.Code == "ratelimited" {
		b.WriteString(": Slack の送信の制限に達しました。時間を置いて実行し直してください")
	} else if h := hints[e.Code]; h != "" {
		b.WriteString(": " + h)
	}
	return b.String()
}

// Response は Web API の応答から aratam が使う項目。
type Response struct {
	OK bool
	// Error は ok が false のときの error コード。[a-z0-9_] で 64 字までの形でなければ unknown_error。
	Error string
	// TeamID / UserID は auth.test の値。[A-Z0-9] で 32 字までの形でなければ空。
	TeamID, UserID string
}

// ParseResponse は Web API の応答の本文を解釈する。応答は信用できない入力として扱う (ADR 0041)。
//
//   - 成功とみなすのは、JSON のオブジェクトで "ok" (小文字のキー) が真偽値の true のときだけ
//   - error コードと ID は形を確かめ、合わなければ固定の値か空にする (ログやエラーの文に任意の文字列を写さない)
//   - 返すエラーは固定の文 (本文を写さない)
func ParseResponse(body []byte) (Response, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return Response{}, errNotObject
	}
	var r Response
	switch strings.TrimSpace(string(m["ok"])) {
	case "true":
		r.OK = true
	case "false":
	default:
		return Response{}, errNoOK
	}
	str := func(key string, re *regexp.Regexp) string {
		var s string
		if json.Unmarshal(m[key], &s) != nil || !re.MatchString(s) {
			return ""
		}
		return s
	}
	if !r.OK {
		if r.Error = str("error", errorCode); r.Error == "" {
			r.Error = "unknown_error"
		}
	}
	r.TeamID, r.UserID = str("team_id", slackID), str("user_id", slackID)
	return r, nil
}

// retryAfter は Retry-After (秒の整数) を待ち時間にする。読めなければ defaultRetryWait、長すぎる値は maxRetryAfterValue で頭打ち。
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) && !strings.HasPrefix(strings.TrimSpace(v), "-") {
			return maxRetryAfterValue
		}
		return defaultRetryWait
	}
	if n > int(maxRetryAfterValue/time.Second) {
		return maxRetryAfterValue
	}
	return time.Duration(n) * time.Second
}

// ParseScopes は X-OAuth-Scopes (カンマ区切り) から scope の名前を取り出す。形の合わないものは捨て、重複を除き、100 個まで。
func ParseScopes(header string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range strings.Split(header, ",") {
		s = strings.TrimSpace(s)
		if len(out) >= maxScopes {
			break
		}
		if scopeName.MatchString(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// call は method を呼ぶ。成功 (ok: true) なら応答とヘッダーを返す。
func (b *Bot) call(ctx context.Context, method, channel string, body []byte) (Response, http.Header, error) {
	if !ValidToken(b.token) {
		return Response{}, nil, errors.New("slack: the bot token is empty or contains spaces or control characters")
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+"/"+method, bytes.NewReader(body))
		if err != nil {
			return Response{}, nil, errors.New("slack: invalid API URL")
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+b.token)
		res, err := b.http.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return Response{}, nil, fmt.Errorf("slack: %s: %w", method, err)
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
		_ = res.Body.Close()
		r, perr := ParseResponse(raw)
		if len(raw) > maxResponseBytes {
			r, perr = Response{}, errNotObject
		}
		failed := perr == nil && !r.OK
		if res.StatusCode == http.StatusTooManyRequests || (failed && r.Error == "ratelimited") {
			wait := retryAfter(res.Header.Get("Retry-After"))
			if attempt < MaxRateLimitRetries && wait <= MaxRetryWait {
				if err := b.sleep(ctx, wait); err != nil {
					return Response{}, nil, fmt.Errorf("slack: %s: ratelimited: %w", method, err)
				}
				continue
			}
			return Response{}, nil, &APIError{Method: method, Code: "ratelimited", Status: res.StatusCode, Channel: channel, RetryAfter: wait}
		}
		switch {
		case res.StatusCode/100 != 2:
			e := &APIError{Method: method, Status: res.StatusCode, Channel: channel}
			if failed {
				e.Code = r.Error
			}
			return Response{}, nil, e
		case perr != nil:
			return Response{}, nil, fmt.Errorf("slack: %s: %w", method, perr)
		case failed:
			return Response{}, nil, &APIError{Method: method, Code: r.Error, Status: res.StatusCode, Channel: channel}
		}
		return r, res.Header, nil
	}
}

// PostMessage は payload (text と blocks など。Incoming Webhook に送るのと同じ形の JSON のオブジェクト) に channel を足して chat.postMessage で 1 通送る。
func (b *Bot) PostMessage(ctx context.Context, channel string, payload any) error {
	if !ValidChannelID(channel) {
		return errors.New("slack: channel must be a channel ID such as C0123456789")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return errors.New("slack: payload must be a JSON object")
	}
	id, _ := json.Marshal(channel)
	m["channel"] = id
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, _, err = b.call(ctx, "chat.postMessage", channel, body)
	return err
}

// Auth は auth.test の結果。
type Auth struct {
	TeamID, UserID string
	// Scopes は応答の X-OAuth-Scopes。ScopesKnown が false ならヘッダーが無く、分からない。
	Scopes      []string
	ScopesKnown bool
}

// HasScope は scope を持つと分かっているかを返す。
func (a Auth) HasScope(scope string) bool {
	for _, s := range a.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AuthTest は auth.test でトークンが有効かを確かめる (投稿はしない。scope は要らない)。
func (b *Bot) AuthTest(ctx context.Context) (Auth, error) {
	r, h, err := b.call(ctx, "auth.test", "", []byte("{}"))
	if err != nil {
		return Auth{}, err
	}
	a := Auth{TeamID: r.TeamID, UserID: r.UserID}
	if v := h.Values("X-OAuth-Scopes"); len(v) > 0 {
		a.ScopesKnown = true
		a.Scopes = ParseScopes(strings.Join(v, ","))
	}
	return a, nil
}
