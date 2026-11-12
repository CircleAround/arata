package notify

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Config は aratam.yaml (aratam 設計書 4 章)。arata と同じく暗黙の既定を持たず、`aratam config init` の雛形で全項目を明示する。
type Config struct {
	Name           string      `yaml:"name"`
	MaxAge         string      `yaml:"max_age"`
	UrgentSeverity string      `yaml:"urgent_severity"`
	OnQuiet        string      `yaml:"on_quiet"`
	LLM            LLMConfig   `yaml:"llm"`
	Slack          SlackConfig `yaml:"slack"`

	path string // 読んだ設定ファイルのパス (context_file の相対パスの基準)
}

// LLMConfig は要約に使う LLM。
type LLMConfig struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
	Region   string `yaml:"region"`
	Profile  string `yaml:"profile"`
	Timeout  string `yaml:"timeout"`
	// Command は claude-cli の実行ファイル (空なら PATH から claude を探す。cron の PATH が狭いときに絶対パスで書く)。
	Command string `yaml:"command"`
	// ContextFile は利用者が書いた「この監査対象の前提」(Markdown) のパス。LLM の system に足す (provider: none では使わない)。
	// 相対パスは設定ファイルのディレクトリ基準。空なら使わない (ADR 0024)。
	ContextFile string `yaml:"context_file"`
}

// SlackConfig は通知先。送り方は Incoming Webhook か bot トークン (chat.postMessage) のどちらか 1 つ (aratam 設計書 4-1 章)。
// Webhook の URL と bot トークンは秘密なので、設定ファイルには環境変数の名前だけを書く。チャンネル ID は秘密ではないので値を書く。
type SlackConfig struct {
	WebhookEnv       string `yaml:"webhook_env"`
	UrgentWebhookEnv string `yaml:"urgent_webhook_env"`
	// BotTokenEnv は bot トークン (xoxb-...) を入れる環境変数の名前。
	BotTokenEnv string `yaml:"bot_token_env"`
	// Channel / UrgentChannel は通常用・緊急用のチャンネル ID (名前ではない)。UrgentChannel が空なら Channel に送り、冒頭に UrgentMention を付ける。
	Channel       string `yaml:"channel"`
	UrgentChannel string `yaml:"urgent_channel"`
	UrgentMention string `yaml:"urgent_mention"`
	// Format は通知の書式。blocks = Block Kit / text = mrkdwn の本文だけ (v0.3.0 までの書式)。ADR 0029
	Format string `yaml:"format"`
}

// Slack への送り方。
const (
	SlackWebhook = "webhook" // Incoming Webhook (webhook_env / urgent_webhook_env)
	SlackBot     = "bot"     // bot トークンとチャンネル ID (bot_token_env / channel / urgent_channel)
)

// Method は設定に書かれた送り方を返す。bot の項目が 1 つでもあれば bot、無ければ webhook
// (両方が書かれた設定は Validate がエラーにする)。
func (s SlackConfig) Method() string {
	if s.BotTokenEnv != "" || s.Channel != "" || s.UrgentChannel != "" {
		return SlackBot
	}
	return SlackWebhook
}

// プロバイダ名 (呼び方を表す。aratam 設計書 5 章)。
const (
	ProviderBedrock   = "bedrock"
	ProviderClaudeCLI = "claude-cli"
	ProviderOpenAIAPI = "openai-api"
	ProviderNone      = "none"
)

// 重大度の順位 (arata の checks と同じ)。aratam は checks を import しない (ストアや AWS SDK を持ち込まないため)。
var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// slackChannelID はチャンネル ID の形 (internal/slack の ValidChannelID と同じ。notify はネットワークの層を import しない)。
var slackChannelID = regexp.MustCompile(`^[CGD][A-Z0-9]{8,20}$`)

// LoadConfig は設定を読み、検証する。未知のキーは誤記とみなしてエラーにする。
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	return &c, nil
}

// MaxContextBytes は context_file の上限 (16 KiB)。
const MaxContextBytes = 16 << 10

// context_file を使えないときの code (WARN)。
const (
	CodeContextUnreadable = "CONTEXT_UNREADABLE"
	CodeContextTooLarge   = "CONTEXT_TOO_LARGE"
)

// ContextPath は context_file のパス (相対なら設定ファイルのディレクトリ基準)。空なら空。
func (c *Config) ContextPath() string {
	p := c.LLM.ContextFile
	if p == "" || filepath.IsAbs(p) || c.path == "" {
		return p
	}
	return filepath.Join(filepath.Dir(c.path), p)
}

// LoadContext は context_file を読む。空なら ("", "", nil)。
//
// 決定 (ADR 0024): 無い・読めない・UTF-8 でない・16 KiB を超えるときは設定エラーにせず、code を返す (呼び出し側が WARN を出して前提なしで続ける)。
// 超えたときは切り詰めずに使わない (途中で切った前提は誤解を招くため)。
func (c *Config) LoadContext() (string, string, error) {
	p := c.ContextPath()
	if p == "" {
		return "", "", nil
	}
	f, err := os.Open(p)
	if err != nil {
		return "", CodeContextUnreadable, fmt.Errorf("llm.context_file %s を読めません: %w", p, errors.Unwrap(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxContextBytes+1))
	if err != nil {
		return "", CodeContextUnreadable, fmt.Errorf("llm.context_file %s を読めません: %w", p, err)
	}
	if len(b) > MaxContextBytes {
		return "", CodeContextTooLarge, fmt.Errorf("llm.context_file %s が上限 %d バイトを超えるため使いません", p, MaxContextBytes)
	}
	if !utf8.Valid(b) {
		return "", CodeContextUnreadable, fmt.Errorf("llm.context_file %s が UTF-8 のテキストではありません", p)
	}
	return string(b), "", nil
}

// Validate は設定を検証する。llm の項目は provider に応じて要るものだけを見る (--llm none で上書きした後にも呼ぶ)。
//
// 決定:
//   - 必須: name, max_age, urgent_severity, on_quiet, llm.provider、Slack への送り方 (slack.webhook_env か、slack.bot_token_env と slack.channel)。
//     provider が none 以外なら llm.timeout も必須、bedrock なら llm.model と llm.region も必須 (設計書 3-1 で「設定で明示する」)。
//     claude-cli の model と command は省略可 (claude 側の既定のモデル、PATH の claude を使う)。
//   - slack.urgent_webhook_env と slack.urgent_mention は省略可 (4 章)。
//   - *_env は環境変数の名前でなければならない。URL やトークンを貼った誤りを弾き、そのときエラーに値を出さない (秘密を漏らさない)。
//   - 送り方は 1 つだけ。Webhook の項目と bot の項目の両方があれば設定エラー (どちらに送るかを曖昧にしない。4-1 章)。
//     新しい項目 (bot_token_env / channel / urgent_channel) は省略可で、無ければ Webhook の方式 (v0.5 までの設定は変更なしで動く)。
//   - slack.channel / urgent_channel はチャンネル ID の形 (C0123456789) でなければならない。名前 (#general) は受け付けない。エラーに値を出さない (トークンを貼った誤りのため)。
func (c *Config) Validate() error {
	var errs []error
	req := func(name, v string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	req("name", c.Name)
	if _, err := ParseDuration(c.MaxAge); err != nil {
		errs = append(errs, fmt.Errorf("max_age: %w", err))
	}
	if r := severityRank[c.UrgentSeverity]; r < severityRank["low"] {
		errs = append(errs, fmt.Errorf("urgent_severity must be one of critical, high, medium, low (got %q)", c.UrgentSeverity))
	}
	if c.OnQuiet != "short" && c.OnQuiet != "silent" {
		errs = append(errs, fmt.Errorf("on_quiet must be short or silent (got %q)", c.OnQuiet))
	}
	switch c.LLM.Provider {
	case ProviderNone:
	case ProviderBedrock, ProviderClaudeCLI:
		if _, err := ParseDuration(c.LLM.Timeout); err != nil {
			errs = append(errs, fmt.Errorf("llm.timeout: %w", err))
		}
		if c.LLM.Provider == ProviderBedrock {
			req("llm.model", c.LLM.Model)
			req("llm.region", c.LLM.Region)
		}
	case ProviderOpenAIAPI:
		errs = append(errs, fmt.Errorf("llm.provider %q is not supported yet (bedrock, claude-cli, none)", c.LLM.Provider))
	default:
		errs = append(errs, fmt.Errorf("llm.provider must be one of bedrock, claude-cli, none (got %q)", c.LLM.Provider))
	}
	webhookKeys := c.Slack.WebhookEnv != "" || c.Slack.UrgentWebhookEnv != ""
	switch {
	case webhookKeys && c.Slack.Method() == SlackBot:
		errs = append(errs, errors.New("slack: both the webhook keys (webhook_env / urgent_webhook_env) and the bot token keys (bot_token_env / channel / urgent_channel) are set; choose one and leave the other empty"))
	case c.Slack.Method() == SlackBot:
		req("slack.bot_token_env", c.Slack.BotTokenEnv)
		req("slack.channel", c.Slack.Channel)
	case webhookKeys:
		req("slack.webhook_env", c.Slack.WebhookEnv)
	default:
		errs = append(errs, errors.New("slack.webhook_env is required (Incoming Webhook), or slack.bot_token_env and slack.channel (bot token)"))
	}
	// 決定 (ADR 0029): slack.format は必須 (暗黙の既定を持たない。ADR 0014)。v0.3.0 の設定には無いので、更新の手順をエラーに書く
	switch c.Slack.Format {
	case FormatBlocks, FormatText:
	case "":
		errs = append(errs, errors.New("slack.format is required since v0.4.0: write `slack.format: blocks` for Block Kit, or `slack.format: text` to keep the previous mrkdwn body"))
	default:
		errs = append(errs, fmt.Errorf("slack.format must be blocks or text (got %q)", c.Slack.Format))
	}
	for _, f := range []struct{ name, v, secret string }{
		{"slack.webhook_env", c.Slack.WebhookEnv, "webhook URL"},
		{"slack.urgent_webhook_env", c.Slack.UrgentWebhookEnv, "webhook URL"},
		{"slack.bot_token_env", c.Slack.BotTokenEnv, "bot token"},
	} {
		if f.v != "" && !envName.MatchString(f.v) {
			errs = append(errs, fmt.Errorf("%s must be the name of an environment variable (do not put the %s in the config file)", f.name, f.secret))
		}
	}
	for _, f := range []struct{ name, v string }{{"slack.channel", c.Slack.Channel}, {"slack.urgent_channel", c.Slack.UrgentChannel}} {
		if f.v != "" && !slackChannelID.MatchString(f.v) {
			errs = append(errs, fmt.Errorf("%s must be a channel ID such as C0123456789 (not a channel name such as #general; open the channel details in Slack to copy the ID)", f.name))
		}
	}
	return errors.Join(errs...)
}

// Rules は設定から規則の部分を取り出す。urgentMention は緊急用の送り先 (Webhook かチャンネル) が無く通常用へ送るときだけ付ける (4 章)。
func (c *Config) Rules(urgentSet bool) Rules {
	maxAge, _ := ParseDuration(c.MaxAge)
	r := Rules{Name: c.Name, MaxAge: maxAge, UrgentSeverity: c.UrgentSeverity, OnQuiet: c.OnQuiet}
	if !urgentSet {
		r.UrgentMention = c.Slack.UrgentMention
	}
	return r
}

// maxDurationDays は `d` (日) で書ける上限 (time.Duration に収まる日数)。
const maxDurationDays = int(math.MaxInt64 / (24 * time.Hour))

// ParseDuration は time.ParseDuration に `d` (日) を加えた形式を解釈する。正の値だけを受ける (arata の設定と同じ書式)。
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		// time.Duration に収まらない日数は桁あふれで別の長さになるので、エラーにする (arata の設定と同じ。ADR 0041)
		if err != nil || days > maxDurationDays || days < -maxDurationDays {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}
	return d, nil
}

//go:embed scaffold.yaml
var scaffold []byte

// Scaffold は `aratam config init` が書き出す雛形 (全項目を明示する)。
func Scaffold() []byte { return append([]byte(nil), scaffold...) }
