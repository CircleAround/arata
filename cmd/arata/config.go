package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/scaffold"
)

// newConfigCmd は設定の雛形を扱う config コマンド (サブコマンド init)。
func newConfigCmd(d *Deps, g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "設定の雛形を書き出す / 雛形と比べる (config init)",
	}
	cmd.AddCommand(newConfigInitCmd(d, g))
	return cmd
}

func newConfigInitCmd(d *Deps, g *globalFlags) *cobra.Command {
	var out, format string
	var force, diff bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "推奨設定の雛形 (全プロファイル・全チェック・既定パラメータを明示) を書き出す",
		Long: `推奨設定の雛形を YAML で書き出す。全プロファイル (hourly / daily / weekly)、全チェック、各チェックの既定パラメータを
コメント付きで明示する (default-* の省略記法は使わない)。arata は実行時に暗黙の既定を持たず、設定に書いたチェックだけを実行する。

  arata config init --out config.yaml          雛形を書き出す (既存ファイルは --force が無ければ上書きしない)
  arata config init --diff -c config.yaml      今の設定とこの版の雛形の差分 (どのプロファイルにも入っていないチェック、
                                               既定値と違うパラメータ、未知のキー) を表示する`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			reg := checks.NewRegistry()
			if diff {
				return configDiff(d, g, reg, format)
			}
			body := scaffold.Generate(reg)
			if out == "" {
				_, err := d.Stdout.Write(body)
				return err
			}
			if _, err := os.Stat(out); err == nil && !force {
				return configErr(d, fmt.Errorf("%s already exists; use --force to overwrite, or --diff -c %s to compare", out, out))
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o640); err != nil {
				return err
			}
			fmt.Fprintf(d.Stdout, "%s を書き出しました。name / store / sources を編集してから arata doctor -c %s を実行してください。\n", out, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "書き出すファイル (省略時は標準出力)")
	cmd.Flags().BoolVar(&force, "force", false, "既存のファイルを上書きする")
	cmd.Flags().BoolVar(&diff, "diff", false, "-c の設定とこの版の雛形の差分を表示する")
	cmd.Flags().StringVar(&format, "format", "text", "--diff の出力形式 (text|json)")
	return cmd
}

func configDiff(d *Deps, g *globalFlags, reg *checks.Registry, format string) error {
	if g.config == "" {
		return configErr(d, errors.New("--diff needs --config"))
	}
	// 決定: 未知のキーがあると Load は失敗するので、差分は設定ファイルを直接読む (読み込めない設定の直し方を探す用途を含む)
	b, err := os.ReadFile(g.config)
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

func newProfilesCmd(d *Deps, g *globalFlags) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "プロファイルごとに実際に効いているチェックとパラメータ (由来: overrides / checks: / 既定値) を表示する",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
	cmd.Flags().StringVar(&format, "format", "table", "出力形式 (table|json)")
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
