package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
		Short: "監査を回すリポジトリ (GitHub Actions で arata と aratam を定時に動かす) の一式を書き出す (repo init) / 一式と GitHub の設定を、読むだけで確かめる (repo check)",
	}
	cmd.AddCommand(newRepoInitCmd(d), newRepoCheckCmd(d))
	return cmd
}

// repoFlags は repo init と repo check に共通の引数 (一式を決めるもの)。README のコマンドの init を check に替えれば打てるように、同じ名前にする。
type repoFlags struct {
	p                 repoinit.Params
	out, arataVersion string
	// カンマ区切りの引数。繰り返して渡されたら、つなげて受け取る (下の register)
	accounts, channels, urgent []string
}

func (f *repoFlags) register(cmd *subcmd.Command, outUsage string) {
	cmd.StringVar(&f.p.Owner, "owner", "", "GitHub の組織 (か利用者) の名前 (必須)")
	cmd.StringVar(&f.p.Repo, "repo", "", "リポジトリの名前 (必須)")
	// 決定: カンマ区切りの引数 (--accounts・--channel・--urgent-channel) は、繰り返して渡してもよく、つなげて受け取る
	// (--channel prod=C… --channel staging=C… は --channel prod=C…,staging=C… と同じ)。文字列のフラグのままだと、標準の flag は最後の 1 つだけを残し、
	// ほかを黙って捨てる (「--channel prod が足りない」のような、打ったものと合わないエラーになる。アカウントは、片方だけで書き出してしまう)。
	// 同じアカウントを 2 度書いたとき・空の項目は、片方を選ばずに止める (Validate と ParseAssignmentList)。
	cmd.StringSliceVar(&f.accounts, "accounts", "監査対象の名前。カンマ区切り (繰り返してもよい。必須。小文字の英数字とハイフン。aws/<名前>/・matrix・ストアの prefix に使う)")
	cmd.StringVar(&f.p.AuditAccount, "audit-account", "", "監査する側のアカウント (必須): 実行の仕組み (runner.yaml) を置いたアカウントの 12 桁の ID。監査対象と同じアカウントなら none (config init と同じ)")
	cmd.StringVar(&f.p.StoreBucket, "store-bucket", "", "ストアのバケットの名前 (必須。runner.yaml の出力 StoreUrl のバケット。s3:// は付けない)")
	cmd.StringVar(&f.p.Region, "region", "", "AWS のリージョン (必須。ワークフローの AWS_REGION と arata.yaml の aws.region)")
	cmd.StringVar(&f.p.AlertChannel, "alert-channel", "", "定時の通知が送れなかったことを知らせる Slack のチャンネル ID (必須。C0123456789 の形)。知らせないなら none。ワークフローに入る")
	cmd.StringSliceVar(&f.channels, "channel", "通常用の Slack のチャンネル ID。<アカウント>=<ID> のカンマ区切り (繰り返してもよい。例 prod=C0123456789,staging=C0123456781)。aws/<アカウント>/aratam.yaml を新しく作るアカウントに必須。書き出した後は aratam.yaml だけが持つ")
	cmd.StringSliceVar(&f.urgent, "urgent-channel", "緊急用の Slack のチャンネル ID。<アカウント>=<ID>|same のカンマ区切り (繰り返してもよい)。same は「分けない」(通常用に、メンション付きで送る)。aratam.yaml を新しく作るアカウントに必須")
	cmd.StringVar(&f.out, "out", "", outUsage)
	cmd.BoolVar(&f.p.Schedule, "schedule", false, "監査のワークフローに定時 (schedule) を入れる")
	cmd.StringVar(&f.arataVersion, "arata-version", "", "ワークフローに入れる arata の版 (vX.Y.Z)。版の付かないビルド (開発・テスト) のときだけ要る。リリース版では、そのバイナリの版と違う値を指定できない")
}

// parse は、引数を Params に入れる (形の検査は Validate)。
func (f *repoFlags) parse() error {
	if f.out == "" {
		return errors.New("--out is required: the directory of the audit repository (there is no default)")
	}
	v, err := repoVersion(f.arataVersion)
	if err != nil {
		return err
	}
	f.p.Version = v
	f.p.Accounts = f.accounts
	if f.p.Channels, err = repoinit.ParseAssignmentList("--channel", f.channels); err != nil {
		return err
	}
	f.p.UrgentChannels, err = repoinit.ParseAssignmentList("--urgent-channel", f.urgent)
	return err
}

func repoNow(d *Deps) time.Time {
	if d.Engine.Now != nil {
		return d.Engine.Now()
	}
	return time.Now()
}

func newRepoInitCmd(d *Deps) *subcmd.Command {
	var f repoFlags
	var format string
	var force, diff bool
	cmd := &subcmd.Command{
		Use:   "init",
		Short: "監査を回すリポジトリの一式 (ワークフロー・GitHub の設定の Terraform・アカウントごとの設定の雛形・README) を書き出す",
		Long: `GitHub Actions で arata と aratam を定時に動かすリポジトリの一式を、引数から書き出す (ADR 0059・0060)。
ワークフローの ARATA_VERSION には、このバイナリの版が入る。引数に既定値は無い (書かなければエラー)。

  .github/workflows/   定時の監査 (アカウントの matrix)、finding の片付け、試しの通知、PR の検査
  github/              GitHub の設定の Terraform (非公開、fork の禁止、main の保護、Actions の許可、environment audit)。秘密には触れない
  aws/<アカウント>/     arata.yaml・allowlist.yaml・aratam.yaml の雛形 (config init と同じ。aratam.yaml は bot トークンの方式で、チャンネル ID を書き入れる)
  README.md            置く順番

  arata repo init --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 \
    --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 \
    --channel prod=C0123456789,staging=C0123456781 --urgent-channel prod=C0123456780,staging=same --out ./security-audit

Slack へは bot トークンで送る (ADR 0061)。決めるのはチャンネル ID だけ (秘密ではない):

  --alert-channel   定時の通知が送れなかったことを知らせるチャンネル。知らせないなら none。ワークフローに入る
  --channel         アカウントごとの通常用のチャンネル。aratam.yaml を新しく作るアカウントに要る
  --urgent-channel  アカウントごとの緊急用のチャンネル。分けないなら same。aratam.yaml を新しく作るアカウントに要る

端末から打って、この 3 つが足りないときだけ、対話で聞く。端末でなければ (CI・LLM)、足りない引数の名前を出して終了コード 2 (CONFIG_INVALID)。
既にある aratam.yaml は、どの指定でも書き直さない (チャンネルを変えるときは、aratam.yaml の slack.channel の行を直す。書き出す README.md)。

既にあるファイルは上書きしない。無いファイルだけを作り、中身の違う生成物があれば一覧を出して終了コード 1。

  --diff     何も書かずに、今ある一式とこの版の一式を比べる。差があれば終了コード 1。
             機械で読むときは --format json (スキーマは arata schema repo-diff)。text の出力は人向けで、機械で読まない
  --force    生成物 (.github/、github/、README.md、.gitignore) だけを書き直す。aws/<アカウント>/ は、どの指定でも書き直さない
             (版を上げる・アカウントを足す・定時を有効にするときに使い、結果を PR の差分で確かめる)
  --schedule 監査のワークフローに定時 (schedule) を入れる。付けなければ手動実行だけ。
             導入の流れ (arata help ai onboarding) が済んでから、--schedule --force で入れる

秘密は書き出さないし、登録もしない。足りない秘密の名前と、そのまま打てる登録のコマンドは arata repo check --github が出す。
GitHub にも AWS にも繋がない。Terraform を当てるのは人 (書き出す README.md の手順)。`,
		Args: subcmd.NoArgs,
		Run: func(context.Context, []string) error {
			if format != "text" && format != "json" {
				return configErr(d, fmt.Errorf("unknown format %q (text|json)", format))
			}
			if diff && force {
				return configErr(d, errors.New("--diff and --force cannot be used together (--diff writes nothing)"))
			}
			if err := f.parse(); err != nil {
				return configErr(d, err)
			}
			asked := false
			if !diff {
				// 端末から打って、チャンネル ID が足りないときだけ聞く (ADR 0060)
				var err error
				if asked, err = askChannels(d, &f.p, f.out); err != nil {
					return configErr(d, err)
				}
			}
			files, err := repoinit.Files(f.p, checks.NewRegistry(), repoNow(d))
			if err != nil {
				return configErr(d, err)
			}
			if diff {
				res, err := repoinit.Diff(f.out, files)
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
			results, err := repoinit.Apply(f.out, files, force)
			if err != nil {
				return configErr(d, err)
			}
			return reportRepoInit(d, f.out, f.p, results, asked)
		},
	}
	f.register(cmd, "書き出す先のディレクトリ (必須)")
	cmd.BoolVar(&force, "force", false, "生成物だけを書き直す (aws/<アカウント>/ は書き直さない)")
	cmd.BoolVar(&diff, "diff", false, "何も書かずに、今ある一式とこの版の一式を比べる (差があれば終了コード 1)")
	cmd.StringVar(&format, "format", "text", "--diff の出力形式 (text|json)。json は機械が読む形 (arata schema repo-diff)")
	return cmd
}

// maxAskTries は、対話で 1 つの値を聞き直す回数の上限 (端末でない入力を、端末と見誤ったときに回り続けない)。
const maxAskTries = 3

// askChannels は、端末から打って、チャンネル ID の引数が足りないときだけ、対話で聞いて p に入れる (ADR 0060)。
// 端末でなければ何も聞かない (足りないことは、Validate と Apply が CONFIG_INVALID にする。黙って既定で進まない)。
// 聞くのは、知らせのチャンネルと、aratam.yaml を新しく作るアカウントのチャンネルだけ。
// 問いは標準出力に出す (repo init の標準出力は人向け。標準エラーは JSON のログだけにする。機械が読む --diff --format json では聞かない)。
func askChannels(d *Deps, p *repoinit.Params, out string) (asked bool, err error) {
	if d.IsTerminal == nil || !d.IsTerminal() || d.Stdin == nil {
		return false, nil
	}
	// ほかの引数の誤りを先に出す (聞いた後で止めない)
	if err := p.ValidateBase(); err != nil {
		return false, err
	}
	fresh, err := repoinit.NewAccounts(out, p.Accounts)
	if err != nil {
		return false, err
	}
	in := bufio.NewReader(io.LimitReader(d.Stdin, 1<<16))
	ask := func(prompt, keyword string) (string, error) {
		for try := 0; try < maxAskTries; try++ {
			fmt.Fprint(d.Stdout, prompt)
			line, err := in.ReadString('\n')
			v := strings.TrimSpace(line)
			if repoinit.ValidChannel(v) || (keyword != "" && v == keyword) {
				return v, nil
			}
			if err != nil {
				break // 入力が終わった
			}
			// 入力した値は写さない (トークンを貼った誤りのため)
			fmt.Fprintln(d.Stdout, "  チャンネル ID の形 (C0123456789 のような、C・G・D で始まる英大文字と数字) ではありません。チャンネルの名前 (#general) ではなく、チャンネルの詳細の一番下にある ID です。")
		}
		return "", errors.New("no valid Slack channel ID was entered; pass the channel arguments instead (--alert-channel, --channel, --urgent-channel)")
	}
	if p.AlertChannel == "" {
		asked = true
		fmt.Fprintln(d.Stdout, "Slack へは bot トークンで送ります。決めるのはチャンネル ID だけです (秘密ではありません。bot を、そのチャンネルに招待しておきます)。")
		if p.AlertChannel, err = ask("定時の通知が送れなかったことを知らせるチャンネル ID (知らせないなら "+repoinit.NoAlert+"): ", repoinit.NoAlert); err != nil {
			return asked, err
		}
	}
	for _, a := range fresh {
		if p.Channels[a] == "" {
			asked = true
			v, err := ask(a+" の通常用のチャンネル ID: ", "")
			if err != nil {
				return asked, err
			}
			if p.Channels == nil {
				p.Channels = map[string]string{}
			}
			p.Channels[a] = v
		}
		if p.UrgentChannels[a] == "" {
			asked = true
			v, err := ask(a+" の緊急用のチャンネル ID (通常用と分けないなら "+repoinit.SameChannel+"): ", repoinit.SameChannel)
			if err != nil {
				return asked, err
			}
			if p.UrgentChannels == nil {
				p.UrgentChannels = map[string]string{}
			}
			p.UrgentChannels[a] = v
		}
	}
	return asked, nil
}

// channelArgs は、チャンネル ID の引数を、コマンドの引数の形で返す (対話で聞いた答えを、次から引数で打てるように出す)。
func channelArgs(p repoinit.Params) string {
	join := func(m map[string]string) string {
		var parts []string
		for _, a := range p.Accounts {
			if v := m[a]; v != "" {
				parts = append(parts, a+"="+v)
			}
		}
		return strings.Join(parts, ",")
	}
	s := ""
	if c := join(p.Channels); c != "" {
		s += " --channel " + c
	}
	if u := join(p.UrgentChannels); u != "" {
		s += " --urgent-channel " + u
	}
	return s
}

func newRepoCheckCmd(d *Deps) *subcmd.Command {
	var f repoFlags
	var format string
	var github bool
	cmd := &subcmd.Command{
		Use:   "check",
		Short: "監査を回すリポジトリの一式と、GitHub の environment・秘密の名前を、読むだけで確かめる (問題があれば終了コード 2)",
		Long: `repo init が書き出した一式を確かめ、表で出す (ADR 0060)。引数は repo init と同じ (書き出した README.md のコマンドの init を check に替える)。
何も書かない。秘密の値は扱わない。

ファイルの検査 (いつも行う。手元のファイルだけを読む。秘密も GitHub も要らない。PR の検査で流す):

  - files             生成物が、この版・この引数の一式と同じか。古い版の残り (.github/ の arata- で始まるファイル) が無いか
  - terraform         github/ の Terraform が、この版の形と同じか。ほかの .tf や、これまでの版の「秘密の箱」(github/secrets/) が残っていないか
  - workflow_secrets  ワークフローが参照する秘密が、この一式の 3 つ (ARATA_RUNNER_ROLE_ARN・ARATA_AUDIT_ROLE_ARNS・ARATAM_SLACK_BOT_TOKEN) だけか
  - notify            アカウントごとの aratam.yaml が、bot トークンの方式 (ARATAM_SLACK_BOT_TOKEN) か。違えば、slack の節に書く行を出す
  - accounts          aws/<アカウント>/ の arata.yaml と aratam.yaml があるか (中身の形は config check が見る)

GitHub の検査 (--github を付けたときだけ。GitHub の API を GET で読むだけ。認証は環境変数 GITHUB_TOKEN。無ければ GH_TOKEN):

  - environment             environment audit があるか
  - deployment_branches     デプロイできるブランチが、既定のブランチ 1 つだけか
  - environment_protection  レビュー担当・待ち時間が付いていないか (定時の実行が止まる。warn)
  - secret                  この一式の使う秘密が、environment にあるか。無ければ、そのまま打てる登録のコマンドと、値の形・取得元を出す
  - secret_unused           この一式の使わない秘密が、environment に残っていないか (warn。消すコマンドを出す)
  - repository_secret       リポジトリの (environment でない) 秘密が残っていないか (この一式の名前なら ng。ほかは warn)

  GITHUB_TOKEN="$(gh auth token)" arata repo check --owner example-org --repo security-audit --accounts prod,staging \
    --audit-account 111122223333 --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 --out . --github

GitHub は、秘密の名前と更新日時しか返さない。値は読めないし、読まない (値が正しいかは、試しの通知と試しの実行で確かめる)。
arata は秘密を登録しない。出たコマンド (gh secret set <名前> --env audit -R <owner>/<repo>) を人が打つ (値は gh が端末で聞く)。
arata は gh を起動しない。向き先は https://api.github.com に固定 (GitHub Enterprise Server は対象外)。

行ごとに ok / warn / ng / skip を出す。ng が 1 つでもあれば終了コード 2 (warn だけなら 0)。ng と warn の行は、標準エラーにも固定語彙の code 付きで出す。
機械で読むときは --format json (スキーマは arata schema repo-check)。table の出力は人向けで、文言と並びは版をまたいで変わるので、機械で読まない。`,
		Args: subcmd.NoArgs,
		Run: func(ctx context.Context, _ []string) error {
			if format != "table" && format != "json" {
				return configErr(d, fmt.Errorf("unknown format %q (table|json)", format))
			}
			if err := f.parse(); err != nil {
				return configErr(d, err)
			}
			files, err := repoinit.Files(f.p, checks.NewRegistry(), repoNow(d))
			if err != nil {
				return configErr(d, err)
			}
			gh := repoinit.GitHub{Client: d.GitHubClient, BaseURL: d.GitHubAPIURL}
			if github {
				// 鍵は環境変数だけから受け取る (引数・ファイルに書かせない)。gh は起動しない
				gh.Token = strings.TrimSpace(d.Getenv("GITHUB_TOKEN"))
				if gh.Token == "" {
					gh.Token = strings.TrimSpace(d.Getenv("GH_TOKEN"))
				}
				if gh.Token == "" {
					return configErr(d, errors.New(`--github needs a token in the environment variable GITHUB_TOKEN (or GH_TOKEN), for example: GITHUB_TOKEN="$(gh auth token)" arata repo check ... --github`))
				}
				if strings.IndexFunc(gh.Token, func(r rune) bool { return r <= 0x20 || r >= 0x7f }) >= 0 {
					// 値は出さない
					return configErr(d, errors.New("GITHUB_TOKEN has whitespace or control characters"))
				}
			}
			res := repoinit.NewCheck()
			if err := repoinit.CheckFiles(res, f.out, f.p, files); err != nil {
				return configErr(d, err)
			}
			if github {
				repoinit.CheckGitHub(ctx, res, gh, f.p)
			} else {
				res.Rows = append(res.Rows, repoinit.CheckRow{Scope: repoinit.ScopeGitHub, Item: repoinit.ItemGitHub, Status: repoinit.CheckSkip,
					Detail: "GitHub の environment と秘密の名前は見ていない (--github を付け、鍵を環境変数 GITHUB_TOKEN で渡すと、読むだけで確かめる)"})
			}
			if format == "json" {
				err = writeJSON(d, res)
			} else {
				err = repoinit.WriteCheck(d.Stdout, res)
			}
			if err != nil {
				return err
			}
			logCheckRows(d, res)
			if res.Problems() {
				// 問題の code は、行ごとに標準エラーへ出してある
				return &engine.ExitError{Exit: engine.ExitConfig, Err: errRepoCheckProblems}
			}
			return nil
		},
	}
	f.register(cmd, "検査するディレクトリ (必須。監査を回すリポジトリの作業ツリー)")
	cmd.BoolVar(&github, "github", false, "GitHub の environment と秘密の名前も確かめる (GitHub の API を読むだけ。鍵は環境変数 GITHUB_TOKEN か GH_TOKEN)")
	cmd.StringVar(&format, "format", "table", "出力形式 (table|json)。json は機械が読む形 (arata schema repo-check)")
	return cmd
}

// logCheckRows は、ng と warn の行を、標準エラーのログにも code 付きで出す (doctor と同じ。ADR 0054)。
func logCheckRows(d *Deps, res *repoinit.CheckOutput) {
	for _, r := range res.Rows {
		attrs := []any{"code", r.Code, "scope", r.Scope, "item", r.Item}
		if r.Target != "" {
			attrs = append(attrs, "target", r.Target)
		}
		switch r.Status {
		case repoinit.CheckNG:
			d.Engine.Logger.Error(r.Detail, attrs...)
		case repoinit.CheckWarn:
			d.Engine.Logger.Warn(r.Detail, attrs...)
		}
	}
}

// errRepoCheckProblems は repo check が ng を見つけたこと (終了コード 2。doctor と同じ)。
var errRepoCheckProblems = errors.New("repo check found problems")

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
func reportRepoInit(d *Deps, out string, p repoinit.Params, results []repoinit.Result, asked bool) error {
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
		fmt.Fprintf(&b, "次は %s/README.md の「置く順番」です (GitHub の設定を当てる → arata repo check --github で足りない秘密を見る → 出たコマンドで登録 → 最初の PR)。\n", out)
		if !p.Schedule {
			b.WriteString("定時はまだ入っていません。導入の流れ (arata help ai onboarding) が済んでから、同じ引数に --schedule --force を足します。\n")
		}
	}
	// 既にある aratam.yaml は書き直さない。違うチャンネル ID を渡されたら、黙って捨てずに、直す行を出す (ADR 0060)
	for _, r := range results {
		account, ok := strings.CutPrefix(r.Path, "aws/")
		account, isAratam := strings.CutSuffix(account, "/aratam.yaml")
		if !ok || !isAratam || r.Action != repoinit.Kept {
			continue
		}
		if lines := repoinit.ChannelLines(out, account, p); len(lines) > 0 {
			fmt.Fprintf(&b, "%s は既にあるので、書き直していません (渡されたチャンネル ID は書いていません)。変えるなら、slack の節の次の行を直して PR にします:\n", r.Path)
			for _, l := range lines {
				fmt.Fprintf(&b, "  %s\n", l)
			}
		}
	}
	if asked {
		// 聞いた答えを引数にした、同じコマンド (次からは対話なしで打てる。--channel と --urgent-channel は、aratam.yaml を新しく作るときだけ要る)
		fmt.Fprintf(&b, "同じ内容を引数で打つなら: %s%s\n", strings.TrimSuffix(p.Command(), " --out ."), channelArgs(p)+" --out "+out)
	}
	// 書き出した後に、ファイルの検査 (arata repo check と同じ) を流す。aratam.yaml が bot トークンの方式でない、などを、ここで知らせる
	check := repoinit.NewCheck()
	if files, err := repoinit.Files(p, checks.NewRegistry(), repoNow(d)); err == nil && len(differs) == 0 {
		if err := repoinit.CheckFiles(check, out, p, files); err == nil && check.Problems() {
			b.WriteString("\nこの一式には、直すところがあります (arata repo check と同じ検査):\n")
			var tbl strings.Builder
			if err := repoinit.WriteCheck(&tbl, check); err == nil {
				b.WriteString(tbl.String())
			}
		}
	}
	if _, err := d.Stdout.Write([]byte(b.String())); err != nil {
		return err
	}
	if check.Problems() {
		logCheckRows(d, check)
		return &engine.ExitError{Exit: engine.ExitConfig, Err: errRepoCheckProblems}
	}
	if len(differs) > 0 {
		return &engine.ExitError{Exit: exitRepoDiffers, Err: errors.New("some generated files differ from this version")}
	}
	return nil
}
