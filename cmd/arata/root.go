package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/subcmd"
)

// Deps は CLI の差し替え可能な依存。テストはフェイクの AWS クライアントと固定時計、出力バッファを渡す。
type Deps struct {
	Engine engine.Deps
	Stdout io.Writer
	Stderr io.Writer
	// Getenv は環境変数 (ARATA_CONFIG) の読み取り。テストはテストを動かす環境に左右されないよう差し替える。
	Getenv func(string) string
}

// DefaultDeps は実行時の依存 (実 AWS SDK、現在時刻、標準出力 / 標準エラー)。
func DefaultDeps() Deps {
	return Deps{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv}
}

// Execute は引数で CLI を実行し終了コードを返す (設計書 8: 0 / 2 / 3)。
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
	if d.Engine.Logger == nil {
		d.Engine.Logger = slog.New(slog.NewJSONHandler(d.Stderr, nil))
	}
	root := NewRootCmd(&d)
	// SIGINT / SIGTERM で context を止める。init はそこまでの進捗を記録して終わる (init --resume で再開)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := root.Execute(ctx, args); err != nil {
		var xe *engine.ExitError
		if errors.As(err, &xe) {
			return xe.Exit
		}
		if errors.Is(err, errPartial) {
			return engine.ExitPartial
		}
		// フラグ / 引数のエラーや予期しない失敗は設定エラー扱い
		d.Engine.Logger.Error(err.Error(), "code", engine.CodeConfigInvalid)
		return engine.ExitConfig
	}
	return engine.ExitOK
}

var errPartial = errors.New("collection partially failed")

type globalFlags struct {
	config string
}

// NewRootCmd はルートコマンドを組み立てる。ヘルプとバージョンは d.Stdout に出し、エラーは Execute がログに出す。
func NewRootCmd(d *Deps) *subcmd.Command {
	g := &globalFlags{}
	root := &subcmd.Command{
		Use:     "arata",
		Short:   "AWS のログを改め、前回から新しく発生したものを報せる監査エンジン",
		Long:    rootLong,
		Version: version,
		Stdout:  d.Stdout,
	}
	root.PersistentStringVarP(&g.config, "config", "c", "", "設定ファイル (YAML)。省略時は環境変数 "+envConfig+"、無ければ ./"+defaultConfigFile)
	root.AddCommand(newConfigCmd(d, g), newProfilesCmd(d, g), newInitCmd(d, g), newDoctorCmd(d, g), newRunCmd(d, g), newCollectCmd(d, g), newEvaluateCmd(d, g), newReportCmd(d, g))
	root.AddCommand(reviewCommands(d, g)...)
	root.AddCommand(newAICmd(d))
	root.AddCommand(newHelpCmd(d, root))
	return root
}

const (
	envConfig         = "ARATA_CONFIG"
	defaultConfigFile = "arata.yaml"
)

// configPath は設定ファイルの場所を決める。
// 決定: -c > 環境変数 ARATA_CONFIG > カレントディレクトリの ./arata.yaml の順 (設計書 8 章)。
// 指定された (-c / ARATA_CONFIG) ファイルが無いときは次へ落ちず、読み込みで設定エラーにする。どれも無ければ探した場所を並べて設定エラー。
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

// loadConfig は設定を読む。設定エラーは CONFIG_INVALID (exit 2)。
func loadConfig(d *Deps, g *globalFlags) (*config.Config, error) {
	path, err := configPath(d, g)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		d.Engine.Logger.Error("invalid configuration", "code", engine.CodeConfigInvalid, "path", path, "error", err.Error())
		return nil, &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: err}
	}
	return cfg, nil
}

// openEngine は設定を読み、エンジンを開く。設定エラーは CONFIG_INVALID (exit 2)。
func openEngine(d *Deps, g *globalFlags) (*engine.Engine, *config.Config, error) {
	cfg, err := loadConfig(d, g)
	if err != nil {
		return nil, nil, err
	}
	e, err := engine.Open(cfg, d.Engine)
	if err != nil {
		return nil, nil, err
	}
	return e, cfg, nil
}

func newInitCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var window string
	var resume bool
	cmd := &subcmd.Command{
		Use:   "init",
		Short: "ストアを作り、設定を検証し、ベースラインを収集する (findings は出さない)",
		Long: `ストアを作り、ベースラインを収集する。findings は出さない。

窓 (--window、既定 7d) を UTC の日の境界で区切り、古い順に 1 日ずつ収集して進捗を記録する。
LookupEvents は毎秒 2 リクエストが上限なので、7 日分で数時間かかることがある。
途中で失敗・中断した場合は終了コード 3 で止まり、arata init --resume でその日の頭から再開できる (窓の終わりは再開時点まで延びる)。`,
		Run: func(ctx context.Context, _ []string) error {
			w, err := config.ParseDuration(window)
			if err != nil {
				d.Engine.Logger.Error("invalid --window", "code", engine.CodeConfigInvalid, "error", err.Error())
				return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: err}
			}
			e, cfg, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			res, err := e.Init(ctx, engine.InitOptions{Window: w, Resume: resume})
			if err != nil {
				return err
			}
			if res.NothingToResume {
				fmt.Fprintln(d.Stdout, "再開する init はありません (直近の init は完了しています)。")
				return nil
			}
			fmt.Fprintf(d.Stdout, "store: %s\ndays: %d/%d (until %s)\nsources ok: %s\nsources failed: %s\nrecords: %d\n",
				cfg.Store.Dir, res.ChunksDone, res.ChunksTotal, res.DoneUntil.UTC().Format(time.RFC3339), orNone(res.SourcesOK), orNone(res.SourcesFailed), res.Records)
			if !res.Complete {
				fmt.Fprintln(d.Stdout, "init は途中で止まりました。原因を直してから arata init --resume で続きから再開してください。")
				return errPartial
			}
			return nil
		},
	}
	cmd.StringVar(&window, "window", "7d", "ベースラインとして収集する期間 (例: 7d, 24h)。--resume では使わない")
	cmd.BoolVar(&resume, "resume", false, "途中で止まった init を続きから再開する")
	return cmd
}

func newDoctorCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var window, format string
	cmd := &subcmd.Command{
		Use:   "doctor",
		Short: "権限・ロググループ・形式プロファイルの解釈率を検査する (問題があれば終了コード 2)",
		Long: `設定のソースごとに次を実際に問い合わせて検査し、表で出す。ストアは開かない。

  - permission  必要な IAM action が許可されているか (拒否されたら ACCESS_DENIED)
  - log_group   ロググループがあるか (LOG_GROUP_MISSING)
  - match_rate  直近 100 行を形式プロファイルで解釈できた割合 (閾値未満なら FORMAT_MISMATCH)
  - queries     集計クエリのテンプレートを Logs Insights が受理するか (QUERY_INVALID。regex の方言違いもここで分かる)
  - check       必要なレコードを出すソースが無く skip されるチェック (warn)`,
		Run: func(ctx context.Context, _ []string) error {
			w, err := config.ParseDuration(window)
			if err != nil {
				d.Engine.Logger.Error("invalid --window", "code", engine.CodeConfigInvalid, "error", err.Error())
				return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: err}
			}
			cfg, err := loadConfig(d, g)
			if err != nil {
				return err
			}
			res := engine.Doctor(ctx, cfg, d.Engine, w)
			switch format {
			case "table":
				err = res.WriteTable(d.Stdout)
			case "json":
				var b []byte
				b, err = json.MarshalIndent(res, "", "  ")
				if err == nil {
					_, err = d.Stdout.Write(append(b, '\n'))
				}
			default:
				return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("unknown format %q (table|json)", format)}
			}
			if err != nil {
				return err
			}
			if res.Problems() {
				// 問題の code (ACCESS_DENIED など) は行ごとに標準エラーへ出してある
				return &engine.ExitError{Exit: engine.ExitConfig, Err: engine.ErrDoctorProblems}
			}
			return nil
		},
	}
	cmd.StringVar(&window, "window", "24h", "解釈率のサンプル (直近 100 行) を探す期間")
	cmd.StringVar(&format, "format", "table", "出力形式 (table|json)")
	return cmd
}

type outputFlags struct {
	out    string
	format string
}

func (o *outputFlags) bind(cmd *subcmd.Command) {
	cmd.StringVar(&o.out, "out", "", "report.json と report.md を書き出すディレクトリ (省略時は標準出力)")
	cmd.StringVar(&o.format, "format", "json", "標準出力の形式 (json|md)")
}

func (o *outputFlags) emit(d *Deps, rep *report.Report) error {
	if o.out != "" {
		if err := os.MkdirAll(o.out, 0o750); err != nil {
			return err
		}
		return engine.WriteReport(o.out, "report", rep)
	}
	switch o.format {
	case "json":
		b, err := rep.JSON()
		if err != nil {
			return err
		}
		_, err = d.Stdout.Write(b)
		return err
	case "md":
		_, err := io.WriteString(d.Stdout, rep.Markdown())
		return err
	}
	return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("unknown format %q (json|md)", o.format)}
}

func newRunCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var profile string
	o := &outputFlags{}
	cmd := &subcmd.Command{
		Use:   "run",
		Short: "collect → evaluate → report を実行する",
		Run: func(ctx context.Context, _ []string) error {
			e, _, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			res, err := e.Run(ctx, profile)
			if err != nil {
				return err
			}
			if err := o.emit(d, res.Report); err != nil {
				return err
			}
			if res.Exit == engine.ExitPartial {
				return errPartial
			}
			return nil
		},
	}
	cmd.StringVar(&profile, "profile", "daily", "プロファイル名 (profiles のキー)")
	o.bind(cmd)
	return cmd
}

func newCollectCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var window string
	var sources []string
	cmd := &subcmd.Command{
		Use:   "collect",
		Short: "収集だけを行いストアへ反映する",
		Run: func(ctx context.Context, _ []string) error {
			w, err := config.ParseDuration(window)
			if err != nil {
				d.Engine.Logger.Error("invalid --window", "code", engine.CodeConfigInvalid, "error", err.Error())
				return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: err}
			}
			e, _, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			cr, err := e.CollectOnly(ctx, w, sources)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Stdout, "sources ok: %s\nsources failed: %s\nrecords: %d\n", orNone(cr.SourcesOK), orNone(cr.SourcesFailed), cr.Records)
			if len(cr.SourcesFailed) > 0 {
				return errPartial
			}
			return nil
		},
	}
	cmd.StringVar(&window, "window", "24h", "収集する期間 (例: 24h, 7d)")
	cmd.StringArrayVar(&sources, "source", "対象ソース ID (複数可。省略時は全部)")
	return cmd
}

func newEvaluateCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var profile string
	o := &outputFlags{}
	cmd := &subcmd.Command{
		Use:   "evaluate",
		Short: "収集せずにチェックを走らせ、レポートを出す",
		Run: func(ctx context.Context, _ []string) error {
			e, _, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			res, err := e.EvaluateOnly(ctx, profile)
			if err != nil {
				return err
			}
			return o.emit(d, res.Report)
		},
	}
	cmd.StringVar(&profile, "profile", "daily", "プロファイル名 (profiles のキー)")
	o.bind(cmd)
	return cmd
}

func newReportCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var profile, from, to, month string
	o := &outputFlags{}
	cmd := &subcmd.Command{
		Use:   "report",
		Short: "最後の run / evaluate のレポートを出す。--from / --to (または --month) で期間レポート",
		Long: `期間を指定しなければ、プロファイルの最後の run / evaluate のレポートを再表示する。

--from YYYY-MM-DD --to YYYY-MM-DD (UTC、両端を含む) を指定すると、ストアだけから期間レポートを作る (収集しない):
期間内の new / recurred / changed / resolved の一覧、重大度別件数、新規主体、未対応の残存、アプリ層の日次推移、
取れなかった run (partial / failed / RUN_MISSED)。--month 2026-10 はその月の初日〜末日の糖衣。`,
		Run: func(ctx context.Context, _ []string) error {
			if month != "" {
				if from != "" || to != "" {
					return configErr(d, fmt.Errorf("use either --month or --from/--to"))
				}
				var err error
				if from, to, err = engine.MonthRange(month); err != nil {
					return configErr(d, err)
				}
			}
			if (from == "") != (to == "") {
				return configErr(d, fmt.Errorf("--from and --to must be given together"))
			}
			e, _, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			if from != "" {
				rep, err := e.PeriodReport(ctx, from, to)
				if err != nil {
					return err
				}
				return o.emitPeriod(d, rep)
			}
			b, err := e.LastReport(profile)
			if err != nil {
				return err
			}
			if b == nil {
				// 決定: 終了コードは従来どおり 2。標準エラーに固定語彙の code 付きで 1 行出す (何も出さずに 2 で終わると原因が分からないため)
				err := fmt.Errorf("プロファイル %s の run がまだありません。先に arata run --profile %s を実行してください", profile, profile)
				d.Engine.Logger.Error(err.Error(), "code", engine.CodeReportNotFound, "profile", profile)
				return &engine.ExitError{Code: engine.CodeReportNotFound, Exit: engine.ExitConfig, Err: err}
			}
			rep, err := report.Parse(b)
			if err != nil {
				return err
			}
			return o.emit(d, rep)
		},
	}
	cmd.StringVar(&profile, "profile", "daily", "プロファイル名 (profiles のキー。期間レポートでは使わない)")
	cmd.StringVar(&from, "from", "", "期間レポートの初日 (YYYY-MM-DD、UTC)")
	cmd.StringVar(&to, "to", "", "期間レポートの末日 (YYYY-MM-DD、UTC、その日を含む)")
	cmd.StringVar(&month, "month", "", "月次の期間レポート (YYYY-MM。--from/--to の糖衣)")
	o.bind(cmd)
	return cmd
}

// emitPeriod は期間レポートを出す (--out なら report.json と report.md)。
func (o *outputFlags) emitPeriod(d *Deps, rep *report.PeriodReport) error {
	j, err := rep.JSON()
	if err != nil {
		return err
	}
	if o.out != "" {
		if err := os.MkdirAll(o.out, 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(o.out, "report.json"), j, 0o640); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(o.out, "report.md"), []byte(rep.Markdown()), 0o640)
	}
	switch o.format {
	case "json":
		_, err = d.Stdout.Write(j)
		return err
	case "md":
		_, err = io.WriteString(d.Stdout, rep.Markdown())
		return err
	}
	return configErr(d, fmt.Errorf("unknown format %q (json|md)", o.format))
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "-"
	}
	return strings.Join(l, ", ")
}
