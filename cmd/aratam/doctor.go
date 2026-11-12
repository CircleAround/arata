package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/CircleAround/arata/internal/notify"
	"github.com/CircleAround/arata/internal/slack"
	"github.com/CircleAround/arata/internal/subcmd"
)

// doctor の code (固定語彙)。
const (
	codeWebhookUnset       = "WEBHOOK_UNSET"
	codeUrgentWebhookUnset = "URGENT_WEBHOOK_UNSET"
	codeLLMUnavailable     = "LLM_UNAVAILABLE"
	codeSlackBotUnset      = "BOT_TOKEN_UNSET"
	codeSlackAuthFailed    = "SLACK_AUTH_FAILED"
	codeSlackScopeMissing  = "SLACK_SCOPE_MISSING"
)

// doctorPrompt は LLM の疎通確認の問い合わせ。report のデータは渡さない。
const doctorPrompt = "疎通確認です。ok とだけ返してください。"

type doctorRow struct {
	status, item, detail, code string
}

func newDoctorCmd(d *Deps, g *globalFlags) *subcmd.Command {
	return &subcmd.Command{
		Use:   "doctor",
		Short: "Slack の環境変数 (bot トークンなら auth.test も) と LLM の疎通を確かめる (送信はしない。問題があれば終了コード 2)",
		Long: `設定を読み、次を確かめて表で出す。Slack には送らない (送って確かめるのは aratam test-notify)。

  - config   設定ファイルを読めて、検証を通るか
  - webhook  (Webhook の方式) slack.webhook_env / urgent_webhook_env の環境変数があるか (URL は表示しない)
  - slack    (bot トークンの方式) slack.bot_token_env の環境変数があり、auth.test でトークンが有効か (トークンは表示しない)。
             投稿はしないので、bot がチャンネルにいるかは分からない (chat:write だけでは調べられない。aratam test-notify で確かめる)
  - llm      LLM に短い問い合わせを 1 回送り、応答があるか (provider: none なら skip)
  - context  llm.context_file を書いたとき、読めるか (読めない・16 KiB を超えるなら warn。notify は前提なしで続ける)

ng が 1 つでもあれば終了コード 2。ng の行は標準エラーにも固定語彙の code 付きで出す。`,
		Args: subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			path, err := configPath(d, g)
			if err != nil {
				return err
			}
			cfg, err := loadConfig(d, g)
			if err != nil {
				return err
			}
			rows := []doctorRow{{status: "ok", item: "config", detail: fmt.Sprintf("%s (name %s、provider %s)", path, cfg.Name, cfg.LLM.Provider)}}
			if cfg.Slack.Method() == notify.SlackBot {
				rows = append(rows, botRows(ctx, d, cfg)...)
			} else {
				rows = append(rows, webhookRows(d, cfg)...)
			}
			rows = append(rows, llmRow(ctx, d, cfg))
			if r, ok := contextRow(cfg); ok {
				rows = append(rows, r)
			}

			tw := tabwriter.NewWriter(d.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "STATUS\tITEM\tDETAIL")
			ng := false
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.status, r.item, r.detail)
				switch r.status {
				case "ng":
					ng = true
					d.Logger.Error(r.detail, "code", r.code, "item", r.item)
				case "warn":
					d.Logger.Warn(r.detail, "code", r.code, "item", r.item)
				}
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if ng {
				return &exitError{code: notify.ExitConfig}
			}
			return nil
		},
	}
}

// webhookRows は Webhook の環境変数の有無。URL そのものは出さない。
func webhookRows(d *Deps, cfg *notify.Config) []doctorRow {
	rows := []doctorRow{}
	if d.Getenv(cfg.Slack.WebhookEnv) == "" {
		rows = append(rows, doctorRow{"ng", "webhook", fmt.Sprintf("環境変数 %s (slack.webhook_env) がありません", cfg.Slack.WebhookEnv), codeWebhookUnset})
	} else {
		rows = append(rows, doctorRow{"ok", "webhook", fmt.Sprintf("環境変数 %s (通常用) があります", cfg.Slack.WebhookEnv), ""})
	}
	fallback := "緊急の通知は通常用に送ります"
	if cfg.Slack.UrgentMention != "" {
		fallback += " (冒頭に " + cfg.Slack.UrgentMention + ")"
	}
	switch env := cfg.Slack.UrgentWebhookEnv; {
	case env == "":
		rows = append(rows, doctorRow{"ok", "webhook", "緊急用の Webhook は設定していません。" + fallback, ""})
	case d.Getenv(env) == "":
		rows = append(rows, doctorRow{"warn", "webhook", fmt.Sprintf("環境変数 %s (slack.urgent_webhook_env) がありません。%s", env, fallback), codeUrgentWebhookUnset})
	default:
		rows = append(rows, doctorRow{"ok", "webhook", fmt.Sprintf("環境変数 %s (緊急用) があります", env), ""})
	}
	return rows
}

// botRows は bot トークンの方式の確認。auth.test でトークンが有効かだけを確かめ、投稿はしない。
//
// 決定 (aratam 設計書 4-1 章): doctor は chat.postMessage を呼ばない (届く通知で確かめるのは test-notify だけ)。
// bot がチャンネルにいるかは、chat:write だけでは調べられないので確かめない (channels:read などの scope を足さない)。
// 応答の X-OAuth-Scopes に chat:write が無いと分かったときは warn (ヘッダーが無ければ判断しない)。
func botRows(ctx context.Context, d *Deps, cfg *notify.Config) []doctorRow {
	env := cfg.Slack.BotTokenEnv
	var rows []doctorRow
	token := strings.TrimSpace(d.Getenv(env))
	switch {
	case token == "":
		rows = append(rows, doctorRow{"ng", "slack", fmt.Sprintf("環境変数 %s (slack.bot_token_env) がありません", env), codeSlackBotUnset})
	case !slack.ValidToken(token):
		rows = append(rows, doctorRow{"ng", "slack", fmt.Sprintf("環境変数 %s (slack.bot_token_env) の値に空白か制御文字があります", env), codeSlackAuthFailed})
	default:
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		auth, err := slack.NewBot(d.HTTPClient, token, d.SlackAPIURL).AuthTest(cctx)
		cancel()
		if err != nil {
			rows = append(rows, doctorRow{"ng", "slack", fmt.Sprintf("環境変数 %s のトークンを確かめられません: %v", env, err), codeSlackAuthFailed})
			break
		}
		who := ""
		if auth.TeamID != "" {
			who = "、team " + auth.TeamID
		}
		rows = append(rows, doctorRow{"ok", "slack", fmt.Sprintf("環境変数 %s のトークンは有効です (auth.test%s。投稿はしていません)", env, who), ""})
		if auth.ScopesKnown && !auth.HasScope("chat:write") {
			rows = append(rows, doctorRow{"warn", "slack", "トークンの scope に chat:write がありません。Slack アプリの Bot Token Scopes に chat:write を足し、ワークスペースに入れ直してください", codeSlackScopeMissing})
		}
	}
	rows = append(rows, doctorRow{"ok", "slack", fmt.Sprintf("通常用のチャンネル %s。bot がチャンネルにいるかは aratam test-notify で確かめてください (doctor は投稿しません)", cfg.Slack.Channel), ""})
	if cfg.Slack.UrgentChannel != "" {
		rows = append(rows, doctorRow{"ok", "slack", fmt.Sprintf("緊急用のチャンネル %s (aratam test-notify --urgent で確かめる)", cfg.Slack.UrgentChannel), ""})
	} else {
		fallback := "緊急用のチャンネルは設定していません。緊急の通知は通常用に送ります"
		if cfg.Slack.UrgentMention != "" {
			fallback += " (冒頭に " + cfg.Slack.UrgentMention + ")"
		}
		rows = append(rows, doctorRow{"ok", "slack", fallback, ""})
	}
	return rows
}

// llmRow は LLM に短い問い合わせを 1 回送る (再試行しない)。
func llmRow(ctx context.Context, d *Deps, cfg *notify.Config) doctorRow {
	if cfg.LLM.Provider == notify.ProviderNone {
		return doctorRow{"skip", "llm", "provider: none (LLM を呼ばない)", ""}
	}
	if cfg.LLM.Provider == notify.ProviderClaudeCLI {
		command := cfg.LLM.Command
		if command == "" {
			command = "claude"
		}
		if _, err := exec.LookPath(command); err != nil {
			return doctorRow{"ng", "llm", fmt.Sprintf("claude-cli: %s が見つかりません (llm.command に絶対パスを書く)", command), codeLLMUnavailable}
		}
	}
	s, err := newSummarizer(ctx, d, cfg)
	if err != nil {
		return doctorRow{"ng", "llm", err.Error(), codeLLMUnavailable}
	}
	timeout, _ := notify.ParseDuration(cfg.LLM.Timeout)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	out, err := s.Summarize(cctx, doctorPrompt, []byte("ok"))
	if err != nil {
		return doctorRow{"ng", "llm", fmt.Sprintf("%s: %v", cfg.LLM.Provider, err), codeLLMUnavailable}
	}
	reply := strings.Join(strings.Fields(string(out)), " ")
	if r := []rune(reply); len(r) > 40 {
		reply = string(r[:40]) + "…"
	}
	return doctorRow{"ok", "llm", fmt.Sprintf("%s が応答しました (%.1fs、%q)", cfg.LLM.Provider, time.Since(start).Seconds(), reply), ""}
}

func newTestNotifyCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var urgent bool
	cmd := &subcmd.Command{
		Use:   "test-notify",
		Short: "Slack に試験メッセージを 1 通送る",
		Long: `Slack に試験メッセージを 1 通送る (既定は通常用。--urgent で緊急用)。
緊急用の Webhook (bot トークンの方式なら緊急用のチャンネル) が無ければ、notify と同じく通常用に送り urgent_mention を付ける。
送信に失敗したら終了コード 5。bot トークンの方式で not_in_channel になったら、bot をそのチャンネルに招待する。`,
		Args: subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			cfg, err := loadConfig(d, g)
			if err != nil {
				return err
			}
			hooks, err := readTargets(d, cfg, true)
			if err != nil {
				return err
			}
			route, label := notify.RouteNormal, "通常用"
			if urgent {
				route, label = notify.RouteUrgent, "緊急用"
			}
			var lines []string
			if r := cfg.Rules(hooks.urgent != ""); route == notify.RouteUrgent && r.UrgentMention != "" {
				lines = append(lines, r.UrgentMention)
			}
			what, sent := "Webhook", label+" の Webhook"
			if hooks.bot {
				what, sent = "bot トークンとチャンネル", label+" のチャンネル ("+hooks.dest(route)+")"
			}
			lines = append(lines, fmt.Sprintf("aratam の試験通知です (%s、%s)。この通知が届いていれば %s の設定は正しく動いています。", notify.Escape(cfg.Name), label, what))
			sender := newSlackSender(d, hooks)
			if err := sender.Send(ctx, route, notify.Message{Text: strings.Join(lines, "\n")}); err != nil {
				d.Logger.Error("試験通知の送信に失敗しました", "code", notify.CodeSendFailed, "route", string(route), "error", err.Error())
				return &exitError{code: notify.ExitSend}
			}
			fmt.Fprintf(d.Stdout, "%s に試験通知を送りました。\n", sent)
			return nil
		},
	}
	cmd.BoolVar(&urgent, "urgent", false, "緊急用の Webhook (bot トークンの方式なら緊急用のチャンネル) に送る")
	return cmd
}

// contextRow は llm.context_file を読めるか。書いていなければ行を出さない。
func contextRow(cfg *notify.Config) (doctorRow, bool) {
	if cfg.LLM.ContextFile == "" {
		return doctorRow{}, false
	}
	if cfg.LLM.Provider == notify.ProviderNone {
		return doctorRow{"skip", "context", "provider: none では context_file を使わない", ""}, true
	}
	text, code, err := cfg.LoadContext()
	if err != nil {
		return doctorRow{"warn", "context", err.Error() + " (notify は前提なしで続ける)", code}, true
	}
	return doctorRow{"ok", "context", fmt.Sprintf("%s (%d バイト)", cfg.ContextPath(), len(text)), ""}, true
}
