package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/repoinit"
	"github.com/CircleAround/arata/internal/subcmd"
)

// exitRepoDiffers は repo init の「一式がこの版と揃っていない」の終了コード。設定の誤り (2) とは分ける。
// 決定 (ADR 0059): --diff で差があるとき、または --force なしで違う生成物があるとき。エラーのログは出さない (誤りではない)。
// 版を上げる PR の CI が、この終了コードで「一式が揃っている」を確かめられる。
const exitRepoDiffers = 1

var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func newRepoCmd(d *Deps) *subcmd.Command {
	cmd := &subcmd.Command{
		Use:   "repo",
		Short: "監査を回すリポジトリ (GitHub Actions で arata と aratam を定時に動かす) の一式を書き出す / この版の一式と比べる (repo init)",
	}
	cmd.AddCommand(newRepoInitCmd(d))
	return cmd
}

func newRepoInitCmd(d *Deps) *subcmd.Command {
	var p repoinit.Params
	var accounts, out, format, arataVersion string
	var force, diff bool
	cmd := &subcmd.Command{
		Use:   "init",
		Short: "監査を回すリポジトリの一式 (ワークフロー・GitHub の設定の Terraform・アカウントごとの設定の雛形・README) を書き出す",
		Long: `GitHub Actions で arata と aratam を定時に動かすリポジトリの一式を、引数から書き出す (ADR 0059)。
ワークフローの ARATA_VERSION には、このバイナリの版が入る。引数に既定値は無い (書かなければエラー)。

  .github/workflows/   定時の監査 (アカウントの matrix)、finding の片付け、試しの通知、PR の検査
  .github/scripts/     Slack への送り方の判別、秘密が仮の値のままでないことの検査
  github/              GitHub の設定の Terraform (非公開、fork の禁止、main の保護、Actions の許可、environment audit)
  github/secrets/      秘密の箱の Terraform (秘密の名前を仮の値で作る。既にある秘密には書かない)
  aws/<アカウント>/     arata.yaml・allowlist.yaml・aratam.yaml の雛形 (config init と同じ)
  README.md            置く順番

  arata repo init --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 \
    --store-bucket example-arata-store --region ap-northeast-1 --out ./security-audit

既にあるファイルは上書きしない。無いファイルだけを作り、中身の違う生成物があれば一覧を出して終了コード 1。

  --diff     何も書かずに、今ある一式とこの版の一式を比べる。差があれば終了コード 1。
             機械で読むときは --format json (スキーマは arata schema repo-diff)。text の出力は人向けで、機械で読まない
  --force    生成物 (.github/、github/、README.md、.gitignore) だけを書き直す。aws/<アカウント>/ は、どの指定でも書き直さない
             (版を上げる・アカウントを足す・定時を有効にするときに使い、結果を PR の差分で確かめる)
  --schedule 監査のワークフローに定時 (schedule) を入れる。付けなければ手動実行だけ。
             導入の流れ (arata help ai onboarding) が済んでから、--schedule --force で入れる

GitHub にも AWS にも繋がない。Terraform を当てるのは人 (書き出す README.md の手順)。`,
		Args: subcmd.NoArgs,
		Run: func(context.Context, []string) error {
			if format != "text" && format != "json" {
				return configErr(d, fmt.Errorf("unknown format %q (text|json)", format))
			}
			if diff && force {
				return configErr(d, errors.New("--diff and --force cannot be used together (--diff writes nothing)"))
			}
			if out == "" {
				return configErr(d, errors.New("--out is required: the directory of the audit repository (there is no default)"))
			}
			v, err := repoVersion(arataVersion)
			if err != nil {
				return configErr(d, err)
			}
			p.Version = v
			if accounts != "" {
				p.Accounts = strings.Split(accounts, ",")
			}
			now := time.Now
			if d.Engine.Now != nil {
				now = d.Engine.Now
			}
			files, err := repoinit.Files(p, checks.NewRegistry(), now())
			if err != nil {
				return configErr(d, err)
			}
			if diff {
				res, err := repoinit.Diff(out, files)
				if err != nil {
					return configErr(d, err)
				}
				if format == "json" {
					err = writeJSON(d, res)
				} else {
					err = repoinit.WriteDiff(d.Stdout, res)
				}
				if err != nil {
					return err
				}
				if !res.OK {
					return &engine.ExitError{Exit: exitRepoDiffers, Err: errors.New("the set differs from this version")}
				}
				return nil
			}
			results, err := repoinit.Apply(out, files, force)
			if err != nil {
				return configErr(d, err)
			}
			return reportRepoInit(d, out, p, results)
		},
	}
	cmd.StringVar(&p.Owner, "owner", "", "GitHub の組織 (か利用者) の名前 (必須)")
	cmd.StringVar(&p.Repo, "repo", "", "リポジトリの名前 (必須)")
	cmd.StringVar(&accounts, "accounts", "", "監査対象の名前。カンマ区切り (必須。小文字の英数字とハイフン。aws/<名前>/・matrix・ストアの prefix に使う)")
	cmd.StringVar(&p.AuditAccount, "audit-account", "", "監査する側のアカウント (必須): 実行の仕組み (runner.yaml) を置いたアカウントの 12 桁の ID。監査対象と同じアカウントなら none (config init と同じ)")
	cmd.StringVar(&p.StoreBucket, "store-bucket", "", "ストアのバケットの名前 (必須。runner.yaml の出力 StoreUrl のバケット。s3:// は付けない)")
	cmd.StringVar(&p.Region, "region", "", "AWS のリージョン (必須。ワークフローの AWS_REGION と arata.yaml の aws.region)")
	cmd.StringVar(&out, "out", "", "書き出す先のディレクトリ (必須)")
	cmd.BoolVar(&p.Schedule, "schedule", false, "監査のワークフローに定時 (schedule) を入れる")
	cmd.BoolVar(&force, "force", false, "生成物だけを書き直す (aws/<アカウント>/ は書き直さない)")
	cmd.BoolVar(&diff, "diff", false, "何も書かずに、今ある一式とこの版の一式を比べる (差があれば終了コード 1)")
	cmd.StringVar(&format, "format", "text", "--diff の出力形式 (text|json)。json は機械が読む形 (arata schema repo-diff)")
	cmd.StringVar(&arataVersion, "arata-version", "", "ワークフローに入れる arata の版 (vX.Y.Z)。版の付かないビルド (開発・テスト) のときだけ要る。リリース版では、そのバイナリの版と違う値を指定できない")
	return cmd
}

// repoVersion はワークフローに入れる arata の版を決める。
// 決定 (ADR 0059): リリース版ならそのバイナリの版 (ほかの版は指定できない: 一式はこの版の雛形で、ほかの版のバイナリとは合わない)。
// 版の付かないビルド (dev) では止まり、--arata-version を書いたときだけ進む。
func repoVersion(flag string) (string, error) {
	if releaseVersion.MatchString(version) {
		if flag != "" && flag != version {
			return "", fmt.Errorf("--arata-version %s differs from this binary (%s): the set is the one of this binary; use the arata of the version you want", flag, version)
		}
		return version, nil
	}
	if flag == "" {
		return "", fmt.Errorf("this arata is not a release build (version %q), so the set cannot pin its own version: pass --arata-version vX.Y.Z (the release whose binaries the workflows download), or use a release build", version)
	}
	return flag, nil
}

// reportRepoInit は書き出しの結果を出す (人向け。文言は固定しない)。違う生成物が残っていれば終了コード 1。
func reportRepoInit(d *Deps, out string, p repoinit.Params, results []repoinit.Result) error {
	var b strings.Builder
	counts := map[repoinit.Action]int{}
	var differs []string
	for _, r := range results {
		counts[r.Action]++
		switch r.Action {
		case repoinit.Created:
			fmt.Fprintf(&b, "作った: %s\n", r.Path)
		case repoinit.Overwritten:
			fmt.Fprintf(&b, "書き直した: %s\n", r.Path)
		case repoinit.Differs:
			differs = append(differs, r.Path)
		}
	}
	fmt.Fprintf(&b, "%s: 作った %d / 書き直した %d / 同じ %d / 利用者が育てるファイルはそのまま %d / 違うので書かなかった %d\n",
		out, counts[repoinit.Created], counts[repoinit.Overwritten], counts[repoinit.Unchanged], counts[repoinit.Kept], len(differs))
	if len(differs) > 0 {
		b.WriteString("次の生成物は、この版の一式と中身が違うので書いていません。違いは --diff で見られ、--force で書き直せます (aws/<アカウント>/ は書き直しません):\n")
		for _, path := range differs {
			fmt.Fprintf(&b, "  %s\n", path)
		}
	} else if counts[repoinit.Created] > 0 {
		fmt.Fprintf(&b, "次は %s/README.md の「置く順番」です (GitHub の設定を当てる → 秘密の箱 → 最初の PR)。\n", out)
		if !p.Schedule {
			b.WriteString("定時はまだ入っていません。導入の流れ (arata help ai onboarding) が済んでから、同じ引数に --schedule --force を足します。\n")
		}
	}
	if _, err := d.Stdout.Write([]byte(b.String())); err != nil {
		return err
	}
	if len(differs) > 0 {
		return &engine.ExitError{Exit: exitRepoDiffers, Err: errors.New("some generated files differ from this version")}
	}
	return nil
}
