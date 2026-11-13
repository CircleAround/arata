package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CircleAround/arata/internal/llm"
	"github.com/CircleAround/arata/internal/notify"
	"github.com/CircleAround/arata/internal/slack"
	"github.com/CircleAround/arata/internal/subcmd"
)

// Deps は CLI の差し替え可能な依存。テストは固定時計、出力バッファ、環境変数の表、httptest に向けた http.Client を渡す。
type Deps struct {
	Stdout io.Writer
	Stderr io.Writer
	// Getenv は環境変数 (ARATAM_CONFIG と、Webhook の URL か bot トークン) の読み取り。
	Getenv func(string) string
	Now    func() time.Time
	// HTTPClient は Slack への送信に使う。nil なら slack.New の既定。
	HTTPClient *http.Client
	// SlackAPIURL は Slack の Web API の場所 (bot トークンの方式)。空なら slack.APIURL。テストは httptest に向ける。
	// 設定や環境変数からは変えられない (トークンを別の場所へ送らせないため)。
	SlackAPIURL string
	Logger      *slog.Logger
	// Environ は claude-cli の子プロセスに渡す環境変数の元 (Webhook の環境変数は除いてから渡す)。
	Environ func() []string
	// NewBedrock は bedrock プロバイダを作る。テストは httptest に向けたものに差し替える。
	NewBedrock func(ctx context.Context, region, profile, model string) (notify.Summarizer, error)
}

// DefaultDeps は実行時の依存。
func DefaultDeps() Deps {
	return Deps{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Now: time.Now, Environ: os.Environ}
}

// exitError は終了コードを運ぶ。ログは返す前に出しておく。
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// Execute は引数で CLI を実行し終了コードを返す (aratam 設計書 5 章)。
func Execute(args []string, d Deps) int {
	if d.Stdout == nil {
		d.Stdout = os.Stdout
	}
	if d.Stderr == nil {
		d.Stderr = os.Stderr
	}
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Environ == nil {
		d.Environ = os.Environ
	}
	if d.NewBedrock == nil {
		d.NewBedrock = func(ctx context.Context, region, profile, model string) (notify.Summarizer, error) {
			return llm.NewBedrock(ctx, region, profile, model)
		}
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewJSONHandler(d.Stderr, nil))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := NewRootCmd(&d).Execute(ctx, args); err != nil {
		var xe *exitError
		if errors.As(err, &xe) {
			return xe.code
		}
		// フラグ / 引数のエラーや予期しない失敗は設定エラー扱い
		d.Logger.Error(err.Error(), "code", notify.CodeConfigInvalid)
		return notify.ExitConfig
	}
	return notify.ExitOK
}

type globalFlags struct {
	config string
}

const rootLong = `arata の出力 (report.json / report.md) を読み、要約して Slack に通知する。
arata とは出力ディレクトリだけで連携する (arata を呼ばず、AWS の監査ロールもストアも使わない)。

はじめに:
  1. aratam config init                    設定の雛形を ./aratam.yaml に書き出す (name・llm・slack を確認する)
     aratam config check                   設定の形だけを確かめる (Slack にも LLM にも繋がない。PR の CI 向け)
  2. aratam doctor                         Slack の環境変数 (bot トークンなら auth.test も) と LLM の疎通を確かめる (送信はしない)
  3. aratam test-notify                    Slack に試験メッセージを 1 通送る
  4. aratam notify --in <dir> --dry-run    送らずに、送る内容を標準出力に出す
  5. cron で arata run --out <dir> の後に aratam notify --in <dir> をつなぐ

Slack への送り方は Incoming Webhook (slack.webhook_env) か bot トークン (slack.bot_token_env と slack.channel) のどちらか 1 つ。
Webhook の URL と bot トークンは設定ファイルに書かず、設定に書いた名前の環境変数で渡す (チャンネル ID は設定に書く)。`

// NewRootCmd はルートコマンドを組み立てる。
func NewRootCmd(d *Deps) *subcmd.Command {
	g := &globalFlags{}
	root := &subcmd.Command{
		Use:     "aratam",
		Short:   "arata の出力を要約して通知する",
		Long:    rootLong,
		Version: version,
		Stdout:  d.Stdout,
	}
	root.PersistentStringVarP(&g.config, "config", "c", "", "設定ファイル (YAML)。省略時は環境変数 "+envConfig+"、無ければ ./"+defaultConfigFile)
	root.AddCommand(newConfigCmd(d, g), newNotifyCmd(d, g), newDoctorCmd(d, g), newTestNotifyCmd(d, g))
	return root
}

// --dry-run の出力の形。
const (
	dryRunText = "text"
	dryRunJSON = "json"
)

const (
	envConfig         = "ARATAM_CONFIG"
	defaultConfigFile = "aratam.yaml"
)

// configPath は設定ファイルの場所を決める。
// 決定: -c > 環境変数 ARATAM_CONFIG > カレントディレクトリの ./aratam.yaml の順 (aratam 設計書 5 章。arata と同じ)。
// 指定された (-c / ARATAM_CONFIG) ファイルが無いときは次へ落ちず、読み込みで設定エラーにする。
func configPath(d *Deps, g *globalFlags) (string, error) {
	if g.config != "" {
		return g.config, nil
	}
	if p := d.Getenv(envConfig); p != "" {
		return p, nil
	}
	if _, err := os.Stat(defaultConfigFile); err == nil {
		return defaultConfigFile, nil
	}
	return "", configErr(d, fmt.Errorf("config file not found: tried -c/--config (not given), $%s (not set), ./%s (not found)", envConfig, defaultConfigFile))
}

func loadConfig(d *Deps, g *globalFlags) (*notify.Config, error) {
	path, err := configPath(d, g)
	if err != nil {
		return nil, err
	}
	cfg, err := notify.LoadConfig(path)
	if err != nil {
		return nil, configErr(d, err)
	}
	return cfg, nil
}

func configErr(d *Deps, err error) error {
	d.Logger.Error(err.Error(), "code", notify.CodeConfigInvalid)
	return &exitError{code: notify.ExitConfig}
}

func newConfigCmd(d *Deps, g *globalFlags) *subcmd.Command {
	cmd := &subcmd.Command{Use: "config", Short: "設定の雛形を書き出す (config init)、設定をオフラインで検査する (config check)"}
	var out string
	var force bool
	initCmd := &subcmd.Command{
		Use:   "init",
		Short: "全項目を明示した設定の雛形を書き出す",
		Long: `全項目を明示した設定の雛形を YAML で書き出す。aratam は暗黙の既定を持たない。

  aratam config init              ./aratam.yaml に書き出す (既存ファイルは --force が無ければ上書きしない)
  aratam config init --out -      標準出力に出す`,
		Args: subcmd.NoArgs,
		Run: func(context.Context, []string) error {
			body := notify.Scaffold()
			if out == "-" {
				_, err := d.Stdout.Write(body)
				return err
			}
			if _, err := os.Stat(out); err == nil && !force {
				return configErr(d, fmt.Errorf("%s already exists; use --force to overwrite", out))
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o640); err != nil {
				return err
			}
			cfgFlag := ""
			if out != defaultConfigFile && out != "./"+defaultConfigFile {
				cfgFlag = " -c " + out
			}
			fmt.Fprintf(d.Stdout, "%s を書き出しました。name と slack の環境変数名を確認してから aratam notify%s --in <arata の出力ディレクトリ> --dry-run で試してください。\n", out, cfgFlag)
			return nil
		},
	}
	initCmd.StringVar(&out, "out", defaultConfigFile, "書き出すファイル (- で標準出力)")
	initCmd.BoolVar(&force, "force", false, "既存のファイルを上書きする")
	cmd.AddCommand(initCmd, newConfigCheckCmd(d, g))
	return cmd
}

func newConfigCheckCmd(d *Deps, g *globalFlags) *subcmd.Command {
	return &subcmd.Command{
		Use:   "check",
		Short: "設定の形をオフラインで検査する (Slack にも LLM にも繋がない。問題があれば終了コード 2)",
		Long: `設定 (-c、省略時は ARATAM_CONFIG か ./aratam.yaml) の形を検査する: 未知のキー、型、必須項目、値の選択肢
(notify / doctor が起動時にする検証と同じ規則)。Slack にも LLM にも繋がず、秘密も要らない。PR の CI で使う。

  - Webhook・bot トークンの環境変数 (slack.webhook_env / slack.bot_token_env の名前の環境変数) があるかは見ない。
    PR の CI には秘密を渡さないため (aratam doctor が見る)
  - Slack への送り方 (webhook か bot) は 1 つだけ。bot なら slack.channel / urgent_channel がチャンネル ID の形かを見る
  - llm.context_file は、書いてあれば読めるかを見る (読めない・16 KiB を超えるなら warn。notify は前提なしで続ける)

行ごとに ok / warn / ng / skip を出す。ng が 1 つでもあれば終了コード 2 (warn だけなら 0)。`,
		Args: subcmd.NoArgs,
		Run: func(context.Context, []string) error {
			path, err := configPath(d, g)
			if err != nil {
				return err
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if wd, err := os.Getwd(); err == nil {
				// カレントディレクトリの下なら相対で出す (CI のログで読みやすい)
				if rel, err := filepath.Rel(wd, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					abs = rel
				}
			}
			row := func(status, where, msg string) {
				fmt.Fprintf(d.Stdout, "%-4s  %s: %s\n", status, where, strings.ReplaceAll(msg, "\n", "\n      "))
			}
			cfg, err := notify.LoadConfig(path)
			if err != nil {
				row("ng", abs, err.Error())
				return configErr(d, err)
			}
			row("ok", abs, fmt.Sprintf("name %s, provider %s, format %s, slack %s, timezone %s", cfg.Name, cfg.LLM.Provider, cfg.Slack.Format, cfg.Slack.Method(), cfg.Rules(false).Zone.Name()))
			if r, ok := contextRow(cfg); ok {
				row(r.status, "llm.context_file", r.detail)
			}
			return nil
		},
	}
}

// targets は Slack の送り先。Webhook の方式なら normal / urgent は URL (秘密)、bot の方式ならチャンネル ID (秘密ではない) と token (秘密)。
// URL とトークンはログにも標準出力にも出さない。
type targets struct {
	bot            bool
	normal, urgent string
	token          string
}

// readTargets は設定に書いた名前の環境変数から Webhook の URL か bot トークンを読む。require が false (--dry-run) なら無くてもよい。
// 決定: urgent_webhook_env を書いたのに環境変数が空なら、通常用に送り urgent_mention を付ける (警告を出す)。緊急の通知を落とさないため。
// 決定: bot トークンは前後の空白 (secret の末尾の改行など) を除いて使う。途中に空白や制御文字があれば設定エラー (値は出さない)。
func readTargets(d *Deps, cfg *notify.Config, require bool) (targets, error) {
	if cfg.Slack.Method() == notify.SlackBot {
		t := targets{bot: true, normal: cfg.Slack.Channel, urgent: cfg.Slack.UrgentChannel, token: strings.TrimSpace(d.Getenv(cfg.Slack.BotTokenEnv))}
		switch {
		case t.token == "" && require:
			return t, configErr(d, fmt.Errorf("environment variable %s (slack.bot_token_env) is not set", cfg.Slack.BotTokenEnv))
		case t.token != "" && !slack.ValidToken(t.token):
			return t, configErr(d, fmt.Errorf("environment variable %s (slack.bot_token_env) is not a token: it contains spaces or control characters", cfg.Slack.BotTokenEnv))
		}
		return t, nil
	}
	w := targets{normal: d.Getenv(cfg.Slack.WebhookEnv)}
	if w.normal == "" && require {
		return w, configErr(d, fmt.Errorf("environment variable %s (slack.webhook_env) is not set", cfg.Slack.WebhookEnv))
	}
	if env := cfg.Slack.UrgentWebhookEnv; env != "" {
		if w.urgent = d.Getenv(env); w.urgent == "" {
			d.Logger.Warn(fmt.Sprintf("environment variable %s (slack.urgent_webhook_env) is not set; urgent notifications go to the normal webhook with urgent_mention", env), "code", "URGENT_WEBHOOK_UNSET")
		}
	}
	return w, nil
}

// slackSender は送り先ごとの Webhook かチャンネルに送る。緊急用が無ければ通常用に送る。
// 決定: 送る中身 (notify.Message) はどちらの方式でも同じ。bot の方式は channel を足して chat.postMessage に送るだけで、
// 分割・長さ・LLM 失敗時の扱いは notify の規則のまま。
type slackSender struct {
	t    targets
	post func(ctx context.Context, dest string, payload any) error
}

func newSlackSender(d *Deps, t targets) *slackSender {
	if t.bot {
		return &slackSender{t: t, post: slack.NewBot(d.HTTPClient, t.token, d.SlackAPIURL).PostMessage}
	}
	return &slackSender{t: t, post: slack.New(d.HTTPClient).Post}
}

func (s *slackSender) Send(ctx context.Context, route notify.Route, m notify.Message) error {
	return s.post(ctx, s.t.dest(route), m)
}

// dest は route の送り先 (Webhook の URL かチャンネル ID)。緊急用が無ければ通常用。
func (t targets) dest(route notify.Route) string {
	if route == notify.RouteUrgent && t.urgent != "" {
		return t.urgent
	}
	return t.normal
}

// label は送り先の表示。Webhook は種類だけ (URL は秘密)、bot はチャンネル ID も出す (秘密ではない)。
func (t targets) label(route notify.Route) string {
	urgent := route == notify.RouteUrgent
	switch {
	case t.bot && urgent && t.urgent != "":
		return "urgent channel " + t.urgent
	case t.bot && urgent:
		return "channel " + t.normal + " (no urgent channel)"
	case t.bot:
		return "channel " + t.normal
	case urgent && t.urgent != "":
		return "urgent webhook"
	case urgent:
		return "normal webhook (no urgent webhook)"
	}
	return "normal webhook"
}

// stdoutSender は --dry-run の送り先。送り先の種類を添えて標準出力に出す。
// 決定 (ADR 0029): format が text なら人が読む簡易表示 (Block Kit は見出し・区切りを記号にしたもの)、json なら Slack に送る payload そのもの
// (bot の方式では、これに channel を足して送る)。
type stdoutSender struct {
	w      io.Writer
	t      targets
	format string
}

func (s *stdoutSender) Send(_ context.Context, route notify.Route, m notify.Message) error {
	body := notify.PlainText(m)
	if s.format == dryRunJSON {
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		body = string(b)
	}
	_, err := fmt.Fprintf(s.w, "--- route: %s → %s ---\n%s\n", route, s.t.label(route), body)
	return err
}

func newNotifyCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var in, llmFlag, format string
	var dryRun, force bool
	cmd := &subcmd.Command{
		Use:   "notify",
		Short: "arata の出力ディレクトリを読み、規則で振り分けて通知する",
		Long: `arata の出力ディレクトリ (--in) の report.json を読み、規則で送り先を決めて Slack に送る。

  - report.json が無い・読めない・max_age より古い → 「arata が実行されていない / 失敗した」と緊急用に送る (終了コード 4)
  - max_severity が urgent_severity 以上、または取れなかったソースがある → 緊急用。それ以外は通常用
  - 新規・変化・再発が無く、取れなかったソースも無い → on_quiet (short = 1 行 / silent = 送らない)
  - 送り方は Incoming Webhook か bot トークン (chat.postMessage。要る scope は chat:write だけ)。bot は、送り先のチャンネルに招待しておく
  - 送ったら入力ディレクトリの .aratam-notified に run_id を書き、同じ run は二度送らない (--force で再送)
  - report.json に WAF の修正提案の候補 (proposals) があれば、「WAF の改善提案」を 2 通目として通常用に送る (on_quiet: silent でも送る)。
    slack.format: blocks では、提案の全文 (設定例を含む) を入力ディレクトリの waf-proposals.md に書く (--dry-run では書かない)

終了コード: 0 = 送った (または送る必要が無かった)、2 = 設定エラー、3 = LLM が使えず report.md で送った、
4 = 入力が無い・古い (その旨は送った)、5 = 送信に失敗した。

書式は slack.format (blocks = Block Kit / text = mrkdwn の本文)。--dry-run の出力は --format text (既定。人が読む簡易表示) か
--format json (Slack に送る payload そのもの)。`,
		Args: subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			if format != dryRunText && format != dryRunJSON {
				return configErr(d, fmt.Errorf("--format must be text or json (got %q)", format))
			}
			if format != dryRunText && !dryRun {
				return configErr(d, errors.New("--format is for --dry-run only"))
			}
			cfg, err := loadConfig(d, g)
			if err != nil {
				return err
			}
			if llmFlag != "" {
				cfg.LLM.Provider = llmFlag
				if err := cfg.Validate(); err != nil {
					return configErr(d, fmt.Errorf("--llm: %w", err))
				}
			}
			hooks, err := readTargets(d, cfg, !dryRun)
			if err != nil {
				return err
			}
			summarizer, err := newSummarizer(ctx, d, cfg)
			if err != nil {
				return err
			}
			timeout, _ := notify.ParseDuration(cfg.LLM.Timeout)
			// 決定 (ADR 0024): context_file は LLM を使うときだけ読む。読めない・大きすぎるときは WARN を出して前提なしで続ける
			var contextText string
			if summarizer != nil {
				text, code, err := cfg.LoadContext()
				if err != nil {
					d.Logger.Warn(err.Error()+" (前提なしで続けます)", "code", code)
				}
				contextText = text
			}
			var sender notify.Sender = &stdoutSender{w: d.Stdout, t: hooks, format: format}
			if !dryRun {
				sender = newSlackSender(d, hooks)
			}
			res := notify.Run(ctx, notify.Options{
				Dir: in, Now: d.Now(), Rules: cfg.Rules(hooks.urgent != ""),
				Force: force, DryRun: dryRun, Sender: sender, Logger: d.Logger,
				Summarizer: summarizer, LLMTimeout: timeout, Context: contextText, Format: cfg.Slack.Format,
			})
			if res.Exit != notify.ExitOK {
				return &exitError{code: res.Exit}
			}
			return nil
		},
	}
	cmd.StringVar(&in, "in", "", "arata の出力ディレクトリ (arata run --out に渡したもの)")
	cmd.MarkFlagRequired("in")
	cmd.BoolVar(&dryRun, "dry-run", false, "送らずに標準出力へ出す (.aratam-notified も書かない)")
	cmd.BoolVar(&force, "force", false, "通知済みの run でも送る")
	cmd.StringVar(&llmFlag, "llm", "", "llm.provider を上書きする (none で LLM を呼ばない)")
	cmd.StringVar(&format, "format", dryRunText, "--dry-run の出力: text (人が読む簡易表示) | json (送る payload)")
	return cmd
}

// newSummarizer は設定のプロバイダを作る。provider: none なら nil (LLM を呼ばない)。
func newSummarizer(ctx context.Context, d *Deps, cfg *notify.Config) (notify.Summarizer, error) {
	switch cfg.LLM.Provider {
	case notify.ProviderClaudeCLI:
		// 決定: 子プロセスには claude が動くのに要る環境変数だけを渡す。Webhook の URL と bot トークンは名前が何であっても渡さない (LLM に渡すのは report.json だけ)
		env := llm.ClaudeEnv(d.Environ(), cfg.Slack.WebhookEnv, cfg.Slack.UrgentWebhookEnv, cfg.Slack.BotTokenEnv)
		return &llm.ClaudeCLI{Command: cfg.LLM.Command, Model: cfg.LLM.Model, Env: env}, nil
	case notify.ProviderBedrock:
		s, err := d.NewBedrock(ctx, cfg.LLM.Region, cfg.LLM.Profile, cfg.LLM.Model)
		if err != nil {
			return nil, configErr(d, err)
		}
		return s, nil
	}
	return nil, nil
}
