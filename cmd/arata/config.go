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
	"time"

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
	var out, format, auditAccount, by string
	var force, diff bool
	cmd := &subcmd.Command{
		Use:   "init",
		Short: "推奨設定の雛形 (全プロファイル・全チェック・既定パラメータを明示) を書き出す",
		Long: `推奨設定の雛形を YAML で書き出す。全プロファイル (hourly / daily / weekly)、全チェック、各チェックの既定パラメータを
コメント付きで明示する (default-* の省略記法は使わない)。arata は実行時に暗黙の既定を持たず、設定に書いたチェックだけを実行する。

監査する側のアカウントを --audit-account で必ず選ぶ (既定は無い。選ばなければエラー)。選んだ結果は設定の audit_account に残る:

  --audit-account <12 桁の ID>  別のアカウントのロールが、監査対象の読み取り専用ロールを引き受けて監査する
                                (deploy/github-actions/runner.yaml を別のアカウントに置く構成など)。そのアカウントを既知リスト
                                (--out と同じ場所の allowlist.yaml) に account: で書く。書かないと、監査そのものの AssumeRole を
                                unknown_assume_role が high で報告する。既知リストが既にあれば末尾に足す (ほかの行は変えない)
  --audit-account none          外から監査しない (監査対象と同じアカウントの中で動かす・手元の認証で直接動かす)。既知リストには書かない。
                                監査対象のアカウント自身の ID を書いてはいけない (account: がそのアカウントの全主体を承認してしまう。
                                arata doctor が確かめる)。同じアカウントの中の実行用ロールが読み取り専用ロールを引き受けるなら、
                                その実行用ロールを arn: で既知リストに書く

  arata config init --audit-account none                  雛形を ./arata.yaml に書き出す (既存ファイルは --force が無ければ上書きしない)
  arata config init --audit-account 111122223333          ./arata.yaml と ./allowlist.yaml (監査する側のアカウントの項目)
  arata config init --audit-account none --out -          雛形を標準出力に出す (ID を選んでも既知リストは書かず、足す項目を標準エラーに出す)
  arata config init --diff           今の設定 (-c、省略時は ARATA_CONFIG か ./arata.yaml) とこの版の雛形の差分
                                     (どのプロファイルにも入っていないチェック、既定値と違うパラメータ、未知のキー) を表示する`,
		Args: subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			reg := checks.NewRegistry()
			if diff {
				return configDiff(d, g, reg, format)
			}
			id, none, err := config.ParseAuditAccount(auditAccount)
			if err != nil {
				reason := "--audit-account is required"
				if auditAccount != "" {
					reason = "--" + err.Error()
				}
				return configErr(d, fmt.Errorf("%s. Choose who runs the audit of this target (there is no default): "+
					"--audit-account <12-digit AWS account ID> = a role in another account assumes this target's read-only role (for example the GitHub Actions runner role in a separate account); "+
					"init writes audit_account to the config and the account to the allowlist (account:), so that unknown_assume_role does not report the audit itself as high. "+
					"--audit-account none = the audit runs inside the target account or directly with your own credentials; nothing is written to the allowlist", reason))
			}
			body := scaffold.Generate(reg, auditAccount)
			now := time.Now
			if d.Engine.Now != nil {
				now = d.Engine.Now
			}
			if out == "-" {
				if !none {
					_, entry, err := scaffold.AuditAllowlist(nil, id, by, now())
					if err != nil {
						return configErr(d, err)
					}
					// 決定 (ADR 0054): これは打った人への案内で、運用で拾うログではない。ログの行 (JSON) にせず、標準エラーに文で出す
					// (標準出力は雛形そのものなので、案内は混ぜない)
					fmt.Fprintf(d.Stderr, "--out - は既知リスト (allowlist.yaml) を書きません。監査する側のアカウント %s の次の項目を、allowlist.yaml の principals に足してください (arata config check が確かめます):\n%s\n", id, entry)
				}
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
			// 既知リストは雛形の allowlist: allowlist.yaml (設定と同じ場所)。設定を書く前に中身を作り、既知リストを直せないなら何も書かない
			alPath := filepath.Join(filepath.Dir(out), "allowlist.yaml")
			var alBody []byte
			alMsg := "監査する側のアカウントは none (外から監査しない) です。既知リストには何も書いていません。" +
				"同じアカウントの中の実行用ロールが読み取り専用ロールを引き受けるなら、その実行用ロールを arn: で既知リストに書いてください。"
			if !none {
				src, err := os.ReadFile(alPath)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return configErr(d, err)
				}
				alBody, _, err = scaffold.AuditAllowlist(src, id, by, now())
				switch {
				case errors.Is(err, allowlist.ErrAlreadyListed):
					alBody = nil
					alMsg = fmt.Sprintf("%s には監査する側のアカウント %s が既に書いてあります (変更していません)。", alPath, id)
				case err != nil:
					return configErr(d, fmt.Errorf("%s: %w", alPath, err))
				default:
					alMsg = fmt.Sprintf("%s に監査する側のアカウント %s を書きました (account:。監査そのものの AssumeRole を unknown_assume_role が報告しないように)。", alPath, id)
				}
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
				return err
			}
			if err := os.WriteFile(out, body, 0o640); err != nil {
				return err
			}
			if alBody != nil {
				if err := allowlist.Write(alPath, alBody); err != nil {
					return err
				}
			}
			fmt.Fprintf(d.Stdout, "%s を書き出しました。name / store / sources を編集してから arata doctor%s を実行してください。\n%s\n", out, cfgFlag, alMsg)
			return nil
		},
	}
	cmd.StringVar(&out, "out", defaultConfigFile, "書き出すファイル (- で標準出力)")
	cmd.StringVar(&auditAccount, "audit-account", "", "監査する側のアカウント (必須): 別のアカウントから監査するならその 12 桁の ID、外から監査しないなら none")
	cmd.StringVar(&by, "by", "", "既知リストの項目の approved_by (省略時は書かない。--audit-account に ID を選んだときだけ)")
	cmd.BoolVar(&force, "force", false, "既存の設定ファイルを上書きする (既知リストは上書きせず、無ければ末尾に足す)")
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

// config check --format json のスキーマの名前と版 (ADR 0054)。名前は `arata schema <名前>` の名前。
const (
	configCheckSchema        = "arata-config-check"
	configCheckSchemaVersion = 1
)

// configCheckOutput は config check --format json の出力。行は text の出力の行と同じ内容。
type configCheckOutput struct {
	Schema        string           `json:"schema" jsonschema:"const=arata-config-check"`
	SchemaVersion int              `json:"schema_version" jsonschema:"const=1"`
	OK            bool             `json:"ok" desc:"ng の行が無い (終了コード 0)。warn だけなら true"`
	Rows          []configCheckRow `json:"rows"`
}

type configCheckRow struct {
	Status  string `json:"status" jsonschema:"enum=ok|warn|ng|skip" desc:"ng が 1 つでもあれば終了コード 2"`
	Item    string `json:"item" desc:"検査した項目 (config = 設定ファイル、allowlist = 既知リスト、audit_account = 監査する側のアカウントと既知リストの食い違い)。開いた語彙"`
	Path    string `json:"path,omitempty" desc:"その行が指すファイル (カレントディレクトリの下なら相対パス)。検査していない行 (skip) には無い"`
	Line    int    `json:"line,omitempty" desc:"ファイルの中の行 (分かるときだけ)"`
	Message string `json:"message" desc:"人向けの文。文言は固定しない (機械で読まない)"`
}

func newConfigCheckCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var format string
	cmd := &subcmd.Command{
		Use:   "check",
		Short: "設定と allowlist.yaml の形をオフラインで検査する (AWS にもストアにも繋がない。問題があれば終了コード 2)",
		Long: `設定 (-c、省略時は ARATA_CONFIG か ./arata.yaml) と、それが指す allowlist.yaml の形を検査する。
AWS にもストアにも繋がず、認証も要らない。PR の CI で allowlist.yaml の書き間違いをマージの前に止めるのに使う。

  - 設定      未知のキー、型、必須項目、値の範囲、profiles に書いたチェックの名前 (run / doctor が起動時にする検証と同じ規則)
  - audit_account  監査する側のアカウント (config init --audit-account の選択)。12 桁の ID を書いたのに、期限内の account: の項目が
              allowlist に無ければ ng (監査そのものの AssumeRole を unknown_assume_role が high で報告する)。選んでいない設定は warn
  - allowlist 未知のキー、主体の指定 (arn / account / arn_pattern のどれか 1 つ)、expires の日付、expected_denied の書式など
              (run / doctor と同じ規則)。同じ主体の項目の重複は warn (run は受け付けるが、expires や tags は片方しか使われない)

行ごとに ok / warn / ng / skip を出す。分かるときは「ファイル:行」を添える。ng が 1 つでもあれば終了コード 2 (warn だけなら 0)。
権限・ロググループ・ログの形式は見ない (arata doctor)。雛形との差分は見ない (arata config init --diff)。

機械で読むときは --format json (スキーマは arata schema arata-config-check)。行は同じ内容で、ファイルと行は path / line に分かれる。
text の出力は人向けで、文言と並びは版をまたいで変わるので、機械で読まない。`,
		Args: subcmd.NoArgs,
		Run: func(context.Context, []string) error {
			if format != "text" && format != "json" {
				return configErr(d, fmt.Errorf("unknown format %q (text|json)", format))
			}
			path, err := configPath(d, g)
			if err != nil {
				return err
			}
			out := configCheckOutput{Schema: configCheckSchema, SchemaVersion: configCheckSchemaVersion, OK: true, Rows: []configCheckRow{}}
			// where は人向けの行の頭と、ログの path (「ファイル:行」。ファイルの無い行は項目の名前)
			where := func(r configCheckRow) string {
				switch {
				case r.Path == "":
					return r.Item
				case r.Line > 0:
					return fmt.Sprintf("%s:%d", r.Path, r.Line)
				}
				return r.Path
			}
			row := func(status, item, file string, line int, msg string) {
				r := configCheckRow{Status: status, Item: item, Path: file, Line: line, Message: msg}
				out.Rows = append(out.Rows, r)
				if status == "ng" {
					out.OK = false
					d.Engine.Logger.Error(msg, "code", engine.CodeConfigInvalid, "path", where(r))
				}
			}
			// finish は結果を書き出す。ng が 1 つでもあれば終了コード 2
			finish := func() error {
				if format == "json" {
					if err := writeJSON(d, out); err != nil {
						return err
					}
				} else {
					for _, r := range out.Rows {
						// 複数行の文言 (YAML の型の誤りの一覧) は字下げして続ける
						fmt.Fprintf(d.Stdout, "%-4s  %s: %s\n", r.Status, where(r), strings.ReplaceAll(r.Message, "\n", "\n      "))
					}
				}
				if !out.OK {
					return &engine.ExitError{Exit: engine.ExitConfig, Err: errors.New("config check found problems")}
				}
				return nil
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			abs = displayPath(abs)
			cfg, err := config.Load(path)
			if err != nil {
				row("ng", "config", abs, 0, err.Error())
				// 設定が読めなければ allowlist の場所 (allowlist:) が決まらない
				row("skip", "allowlist", "", 0, "設定を読めないので検査していません (設定を直してからもう一度)")
				return finish()
			}
			if unknown := engine.UnknownChecks(cfg, checks.NewRegistryFor(cfg.Checks)); len(unknown) > 0 {
				for _, u := range unknown {
					row("ng", "config", abs, 0, u)
				}
			} else {
				row("ok", "config", abs, 0, fmt.Sprintf("name %s, sources %d, profiles %d", cfg.Name, len(cfg.Sources), len(cfg.Profiles)))
			}
			b, err := os.ReadFile(cfg.Allowlist)
			alPath := displayPath(cfg.Allowlist)
			var list *allowlist.List // 読めた既知リスト (無ければ空として audit_account と突き合わせる)
			alOK := true
			switch {
			case errors.Is(err, fs.ErrNotExist):
				// run は allowlist が無ければ空として動く (init の直後を許す) ので、エラーにはしない
				row("warn", "allowlist", alPath, 0, "file not found (arata treats it as an empty allowlist)")
			case err != nil:
				alOK = false
				row("ng", "allowlist", alPath, 0, err.Error())
			default:
				checkNow := time.Now
				if d.Engine.Now != nil {
					checkNow = d.Engine.Now
				}
				l, problems := allowlist.Check(b, checkNow())
				for _, p := range problems {
					status := "ng"
					if p.Warn {
						status = "warn"
					}
					row(status, "allowlist", alPath, p.Line, p.Msg)
				}
				list, alOK = l, l != nil
				if l != nil {
					row("ok", "allowlist", alPath, 0, fmt.Sprintf("principals %d, source_ips %d, admin_users %d, secrets_access %d, assume_destinations %d", len(l.Principals), len(l.SourceIPs), len(l.AdminUsers), len(l.SecretsAccess), len(l.AssumeDestinations)))
				}
			}
			// 決定 (ADR 0045): 監査する側のアカウント (audit_account) と既知リストの食い違い。既知リストが読めないときは上の ng に任せる
			if alOK {
				now := time.Now
				if d.Engine.Now != nil {
					now = d.Engine.Now
				}
				if status, msg := engine.CheckAuditAccount(cfg, list, now()); status != "" {
					row(status, "audit_account", abs, 0, msg)
				}
			}
			return finish()
		},
	}
	cmd.StringVar(&format, "format", "text", "出力形式 (text|json)。json は機械が読む形 (arata schema arata-config-check)")
	return cmd
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
