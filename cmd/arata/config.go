package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/scaffold"
	"github.com/CircleAround/arata/internal/subcmd"
)

// newConfigCmd は設定の雛形と検査を扱う config コマンド (サブコマンド init / check)。
func newConfigCmd(d *Deps, g *globalFlags) *subcmd.Command {
	cmd := &subcmd.Command{
		Use:   "config",
		Short: "設定の雛形を書き出す / 雛形と比べる (config init)、設定と allowlist をオフラインで検査する (config check)",
	}
	cmd.AddCommand(newConfigInitCmd(d, g), newConfigCheckCmd(d, g))
	return cmd
}

func newConfigInitCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var out, format string
	var force, diff bool
	cmd := &subcmd.Command{
		Use:   "init",
		Short: "推奨設定の雛形 (全プロファイル・全チェック・既定パラメータを明示) を書き出す",
		Long: `推奨設定の雛形を YAML で書き出す。全プロファイル (hourly / daily / weekly)、全チェック、各チェックの既定パラメータを
コメント付きで明示する (default-* の省略記法は使わない)。arata は実行時に暗黙の既定を持たず、設定に書いたチェックだけを実行する。

  arata config init                  雛形を ./arata.yaml に書き出す (既存ファイルは --force が無ければ上書きしない)
  arata config init --out -          雛形を標準出力に出す
  arata config init --diff           今の設定 (-c、省略時は ARATA_CONFIG か ./arata.yaml) とこの版の雛形の差分
                                     (どのプロファイルにも入っていないチェック、既定値と違うパラメータ、未知のキー) を表示する`,
		Args: subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			reg := checks.NewRegistry()
			if diff {
				return configDiff(d, g, reg, format)
			}
			body := scaffold.Generate(reg)
			if out == "-" {
				_, err := d.Stdout.Write(body)
				return err
			}
			cfgFlag := "" // 既定の場所なら -c を付けずに案内する
			if out != defaultConfigFile && out != "./"+defaultConfigFile {
				cfgFlag = " -c " + out
			}
			if _, err := os.Stat(out); err == nil && !force {
				return configErr(d, fmt.Errorf("%s already exists; use --force to overwrite, or --diff%s to compare", out, cfgFlag))
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o640); err != nil {
				return err
			}
			fmt.Fprintf(d.Stdout, "%s を書き出しました。name / store / sources を編集してから arata doctor%s を実行してください。\n", out, cfgFlag)
			return nil
		},
	}
	cmd.StringVar(&out, "out", defaultConfigFile, "書き出すファイル (- で標準出力)")
	cmd.BoolVar(&force, "force", false, "既存のファイルを上書きする")
	cmd.BoolVar(&diff, "diff", false, "設定 (-c、省略時は "+envConfig+" か ./"+defaultConfigFile+") とこの版の雛形の差分を表示する")
	cmd.StringVar(&format, "format", "text", "--diff の出力形式 (text|json)")
	return cmd
}

func configDiff(d *Deps, g *globalFlags, reg *checks.Registry, format string) error {
	path, err := configPath(d, g)
	if err != nil {
		return err
	}
	// 決定: 未知のキーがあると Load は失敗するので、差分は設定ファイルを直接読む (読み込めない設定の直し方を探す用途を含む)
	b, err := os.ReadFile(path)
	if err != nil {
		return configErr(d, err)
	}
	items, err := scaffold.Diff(b, reg)
	if err != nil {
		return configErr(d, err)
	}
	switch format {
	case "text":
		return scaffold.WriteDiff(d.Stdout, items)
	case "json":
		return writeJSON(d, items)
	}
	return configErr(d, fmt.Errorf("unknown format %q (text|json)", format))
}

func newConfigCheckCmd(d *Deps, g *globalFlags) *subcmd.Command {
	return &subcmd.Command{
		Use:   "check",
		Short: "設定と allowlist.yaml の形をオフラインで検査する (AWS にもストアにも繋がない。問題があれば終了コード 2)",
		Long: `設定 (-c、省略時は ARATA_CONFIG か ./arata.yaml) と、それが指す allowlist.yaml の形を検査する。
AWS にもストアにも繋がず、認証も要らない。PR の CI で allowlist.yaml の書き間違いをマージの前に止めるのに使う。

  - 設定      未知のキー、型、必須項目、値の範囲、profiles に書いたチェックの名前 (run / doctor が起動時にする検証と同じ規則)
  - allowlist 未知のキー、主体の指定 (arn / account / arn_pattern のどれか 1 つ)、expires の日付、expected_denied の書式など
              (run / doctor と同じ規則)。同じ主体の項目の重複は warn (run は受け付けるが、expires や tags は片方しか使われない)

行ごとに ok / warn / ng / skip を出す。分かるときは「ファイル:行」を添える。ng が 1 つでもあれば終了コード 2 (warn だけなら 0)。
権限・ロググループ・ログの形式は見ない (arata doctor)。雛形との差分は見ない (arata config init --diff)。`,
		Args: subcmd.NoArgs,
		Run: func(context.Context, []string) error {
			path, err := configPath(d, g)
			if err != nil {
				return err
			}
			ng := false
			row := func(status, where, msg string) {
				// 複数行の文言 (YAML の型の誤りの一覧) は字下げして続ける
				fmt.Fprintf(d.Stdout, "%-4s  %s: %s\n", status, where, strings.ReplaceAll(msg, "\n", "\n      "))
				if status == "ng" {
					ng = true
					d.Engine.Logger.Error(msg, "code", engine.CodeConfigInvalid, "path", where)
				}
			}
			fail := func() error {
				return &engine.ExitError{Exit: engine.ExitConfig, Err: errors.New("config check found problems")}
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			abs = displayPath(abs)
			cfg, err := config.Load(path)
			if err != nil {
				row("ng", abs, err.Error())
				// 設定が読めなければ allowlist の場所 (allowlist:) が決まらない
				fmt.Fprintln(d.Stdout, "skip  allowlist: 設定を読めないので検査していません (設定を直してからもう一度)")
				return fail()
			}
			if unknown := engine.UnknownChecks(cfg, checks.NewRegistryFor(cfg.Checks)); len(unknown) > 0 {
				for _, u := range unknown {
					row("ng", abs, u)
				}
			} else {
				row("ok", abs, fmt.Sprintf("name %s, sources %d, profiles %d", cfg.Name, len(cfg.Sources), len(cfg.Profiles)))
			}
			b, err := os.ReadFile(cfg.Allowlist)
			alPath := displayPath(cfg.Allowlist)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				// run は allowlist が無ければ空として動く (init の直後を許す) ので、エラーにはしない
				row("warn", alPath, "file not found (arata treats it as an empty allowlist)")
			case err != nil:
				row("ng", alPath, err.Error())
			default:
				l, problems := allowlist.Check(b)
				for _, p := range problems {
					where, status := alPath, "ng"
					if p.Line > 0 {
						where = fmt.Sprintf("%s:%d", where, p.Line)
					}
					if p.Warn {
						status = "warn"
					}
					row(status, where, p.Msg)
				}
				if l != nil {
					row("ok", alPath, fmt.Sprintf("principals %d, source_ips %d, admin_users %d, secrets_access %d", len(l.Principals), len(l.SourceIPs), len(l.AdminUsers), len(l.SecretsAccess)))
				}
			}
			if ng {
				return fail()
			}
			return nil
		},
	}
}

// displayPath は検査の出力に書くパス。カレントディレクトリの下なら相対にする (CI のログで「aws/prod/allowlist.yaml:12」と読める)。
func displayPath(abs string) string {
	wd, err := os.Getwd()
	if err != nil {
		return abs
	}
	if rel, err := filepath.Rel(wd, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return rel
	}
	return abs
}

func newProfilesCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var format string
	cmd := &subcmd.Command{
		Use:   "profiles",
		Short: "プロファイルごとに実際に効いているチェックとパラメータ (由来: overrides / checks: / 既定値) を表示する",
		Args:  subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			cfg, err := loadConfig(d, g)
			if err != nil {
				return err
			}
			v := engine.Profiles(cfg, checks.NewRegistryFor(cfg.Checks))
			switch format {
			case "table":
				return v.WriteTable(d.Stdout)
			case "json":
				return writeJSON(d, v)
			}
			return configErr(d, fmt.Errorf("unknown format %q (table|json)", format))
		},
	}
	cmd.StringVar(&format, "format", "table", "出力形式 (table|json)")
	return cmd
}

func configErr(d *Deps, err error) error {
	d.Engine.Logger.Error(err.Error(), "code", engine.CodeConfigInvalid)
	return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: err}
}

func writeJSON(d *Deps, v any) error {
	enc := json.NewEncoder(d.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
