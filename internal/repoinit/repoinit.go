// Package repoinit は、監査を回すリポジトリ (GitHub Actions で arata と aratam を定時に動かすリポジトリ) の一式を作り (`arata repo init`。ADR 0059)、
// 今ある一式と GitHub の設定を、読むだけで確かめる (`arata repo check`。ADR 0060)。
//
// 一式は、バイナリに埋め込んだ雛形 (templates/) に、形を確かめた引数を決まった印の置換で差し込んで作る。
// 条件や繰り返しを持つテンプレートの言語は使わない (GitHub の式 ${{ }} と区切りがぶつかる)。
// 生成物は引数だけで決まり、時刻・ホスト名・環境変数を読まない (同じ版と同じ引数なら同じバイト列)。
// 例外は既知リストの approved_at だけで、config init と同じく書き出した日になる。
package repoinit

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/aratamscaffold"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/scaffold"
)

//go:embed templates
var templates embed.FS

const (
	// ProviderVersion は Terraform の GitHub の provider (integrations/github) の版。完全な版で固定する。
	// 上げるときは、公開から 7 日以上たった版にし (CI の tools/tfprovidergate が確かめる)、templates/github/terraform.lock.hcl を
	// 4 つの環境 (linux / darwin の amd64・arm64) のハッシュで作り直す (docs/supply-chain.md)。
	ProviderVersion = "6.13.0"

	// Environment は GitHub の environment の名前。ワークフロー・Terraform・runner.yaml の GitHubEnvironment で同じ文字列にする (ADR 0057)。
	Environment = "audit"

	// AuditProfile はワークフローが書く AWS のプロファイルの名前 (監査対象の読み取り専用ロール)。arata.yaml の aws.profile と同じ。
	AuditProfile = "arata-audit"

	maxAccounts = 100
)

// SecretNames は、この一式のワークフローが使う秘密の名前 (ADR 0060)。どの引数でも同じ 3 つ。
// ワークフローの secrets.* と同じであることをテストで固定する。arata repo check --github は、この名前が environment にあることを確かめる。
var SecretNames = []string{
	"ARATAM_SLACK_BOT_TOKEN",
	"ARATA_AUDIT_ROLE_ARNS",
	"ARATA_RUNNER_ROLE_ARN",
}

// FormerSecretNames は、これまでの一式 (手で写す見本、ADR 0059 の秘密の箱) が使っていて、この一式が使わない秘密の名前。
// リポジトリの (environment でない) 秘密に残っていれば、arata repo check --github は ng にする (SecretNames と同じ扱い)。
var FormerSecretNames = []string{
	"ARATAM_SLACK_URGENT_WEBHOOK",
	"ARATAM_SLACK_WEBHOOK",
	"ARATA_ALERT_WEBHOOK",
}

// 引数の「分けない」「知らせない」を表す語 (ADR 0060)。書かないことでは表さない (決めていないことと区別できない)。
const (
	SameChannel = "same" // --urgent-channel: 緊急用を分けない (通常用に、メンション付きで送る)
	NoAlert     = "none" // --alert-channel: 定時の通知が送れなかったことを知らせない
)

// Params は一式を決める引数。既定値は持たない (ADR 0014 と同じく、暗黙の値を一式に埋めない)。
type Params struct {
	Owner        string   // GitHub の組織 (か利用者) の名前
	Repo         string   // リポジトリの名前
	Accounts     []string // 監査対象の名前 (ディレクトリ・matrix・ストアの prefix)
	AuditAccount string   // 監査する側のアカウント (12 桁の ID か none)
	StoreBucket  string   // ストアのバケットの名前
	Region       string   // AWS のリージョン
	Schedule     bool     // 監査のワークフローに定時を入れる
	Version      string   // arata の版 (vX.Y.Z)

	// AlertChannel は、定時の通知が送れなかったことを知らせるチャンネル ID か、NoAlert (知らせない)。ワークフローに入る (生成物)。
	AlertChannel string
	// Channels と UrgentChannels は、アカウントの名前 → チャンネル ID (UrgentChannels は SameChannel も)。
	// 新しく作る aws/<アカウント>/aratam.yaml に書く。書き出した後は aratam.yaml だけが持つ (README のコマンドに載せない。ADR 0060)。
	// aratam.yaml が既にあるアカウントの分は、無くてよい。
	Channels       map[string]string
	UrgentChannels map[string]string
}

// 引数の形。値は YAML・HCL・シェル・Markdown の中にそのまま入るので、引用符・空白・改行・$ ・{ などは、形の時点で入らない。
var (
	ownerRE   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	accountRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	bucketRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRE  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]{1,16}){1,3}-[0-9]$`)
	// channelRE は Slack のチャンネル ID の形 (aratam の slack.channel と同じ。テストで固定する)
	channelRE = regexp.MustCompile(`^[CGD][A-Z0-9]{8,20}$`)
	versionRE = regexp.MustCompile(`^v(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$`)
)

// yamlWords は、引用符なしの YAML で文字列にならない語。アカウントの名前は引用符なしで matrix と name に入るので拒む。
var yamlWords = map[string]bool{"true": true, "false": true, "null": true, "yes": true, "no": true, "on": true, "off": true, "y": true, "n": true, "nan": true, "inf": true}

// Validate は引数の形を確かめる。通らなければ、一式は 1 つも作らない。
func (p Params) Validate() error {
	if err := p.ValidateBase(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range p.Accounts {
		seen[a] = true
	}
	// チャンネル ID はエラーに写さない (チャンネルの欄にトークンを貼った誤りのため。aratam と同じ)
	if p.AlertChannel != NoAlert && !channelRE.MatchString(p.AlertChannel) {
		return errors.New("--alert-channel is required: the Slack channel ID (such as C0123456789; not a channel name) that is told when a scheduled notification could not be sent, or none")
	}
	for _, m := range []struct {
		flag   string
		values map[string]string
		same   bool
	}{{"--channel", p.Channels, false}, {"--urgent-channel", p.UrgentChannels, true}} {
		for a, id := range m.values {
			if !seen[a] {
				return fmt.Errorf("%s: %q is not one of --accounts", m.flag, printableArg(a))
			}
			if !channelRE.MatchString(id) && (!m.same || id != SameChannel) {
				hint := ""
				if m.same {
					hint = ", or same"
				}
				return fmt.Errorf("%s %s=...: must be a Slack channel ID such as C0123456789 (not a channel name such as #general)%s", m.flag, a, hint)
			}
		}
	}
	return nil
}

// ValidateBase は、チャンネル ID のほかの引数の形を確かめる (対話でチャンネル ID を聞く前に、ほかの引数の誤りを先に出す)。
func (p Params) ValidateBase() error {
	if !ownerRE.MatchString(p.Owner) {
		return fmt.Errorf("--owner %q: must be a GitHub organization or user name (letters, digits and hyphens, at most 39 characters)", p.Owner)
	}
	if !repoRE.MatchString(p.Repo) || p.Repo == "." || p.Repo == ".." {
		return fmt.Errorf("--repo %q: must be a repository name (letters, digits, '.', '_' and '-')", p.Repo)
	}
	if len(p.Accounts) == 0 {
		return errors.New("--accounts is required: the names of the audited accounts, separated by commas (for example prod,staging)")
	}
	if len(p.Accounts) > maxAccounts {
		return fmt.Errorf("--accounts: at most %d accounts", maxAccounts)
	}
	seen := map[string]bool{}
	for _, a := range p.Accounts {
		if !accountRE.MatchString(a) || yamlWords[a] {
			return fmt.Errorf("--accounts %q: each name must start with a lowercase letter and use lowercase letters, digits and hyphens (at most 40 characters; not a YAML word such as true or null)", a)
		}
		if seen[a] {
			return fmt.Errorf("--accounts: %q appears twice", a)
		}
		seen[a] = true
	}
	if _, _, err := config.ParseAuditAccount(p.AuditAccount); err != nil {
		return fmt.Errorf("--audit-account %q: must be the 12-digit ID of the AWS account that runs the audit, or none", p.AuditAccount)
	}
	if !bucketRE.MatchString(p.StoreBucket) || strings.Contains(p.StoreBucket, "..") {
		return fmt.Errorf("--store-bucket %q: must be an S3 bucket name (not a URL)", p.StoreBucket)
	}
	if !regionRE.MatchString(p.Region) {
		return fmt.Errorf("--region %q: must be an AWS region name (for example ap-northeast-1)", p.Region)
	}
	if !versionRE.MatchString(p.Version) {
		return fmt.Errorf("arata version %q: must be a release version (vX.Y.Z)", p.Version)
	}
	return nil
}

// printableArg は、形を通らなかった引数をエラーに出すときに、長さを切り、制御文字を置き換える。
func printableArg(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return printable(s)
}

// ValidChannel は s がチャンネル ID の形か。
func ValidChannel(s string) bool { return channelRE.MatchString(s) }

// Kind はファイルの種類。
type Kind string

const (
	// Generated は生成物。手で直さない。--force で書き直し、--diff で比べる。
	Generated Kind = "generated"
	// Seed は利用者が育てるもの (aws/<アカウント>/)。無いときだけ作り、どの指定でも書き直さない。
	Seed Kind = "seed"
)

// File は一式の 1 つのファイル。Path はリポジトリの根からの相対パス (区切りは /)。
type File struct {
	Path string
	Body []byte
	Mode fs.FileMode
	Kind Kind
	// Missing は、このファイルを新しく作るのに足りない引数 (Seed の aratam.yaml のチャンネル ID)。
	// 空でなければ、Apply はこのファイルを作らずにエラーにする (既にあるなら、書き直さないので要らない)。
	Missing []string
}

// 生成物の一覧。雛形のパス → 書き出すパス。
var generated = []struct {
	template, path string
	mode           fs.FileMode
}{
	{"workflows/arata-audit.yml", ".github/workflows/arata-audit.yml", 0o644},
	{"workflows/arata-triage.yml", ".github/workflows/arata-triage.yml", 0o644},
	{"workflows/arata-notify-test.yml", ".github/workflows/arata-notify-test.yml", 0o644},
	{"workflows/arata-check.yml", ".github/workflows/arata-check.yml", 0o644},
	{"github/main.tf", "github/main.tf", 0o644},
	{"github/terraform.lock.hcl", "github/.terraform.lock.hcl", 0o644},
	{"README.md", "README.md", 0o644},
	{"gitignore", ".gitignore", 0o644},
}

// managedDirs は、一式に無いファイルを --diff が「この版の一式に無い」(extra) として出すディレクトリと、その対象の名前。
//   - .github/workflows と .github/scripts: 名前が arata- で始まるファイル (古い版の一式の残り。この版は .github/scripts を書き出さない)
//   - github と github/secrets: .tf のファイル (Terraform は同じ root の .tf を全部当てるので、手で作った宣言が残っていると、
//     書き出した宣言と二重になる・緩い設定が当たる。github/secrets は、これまでの版の「秘密の箱」で、この版は書き出さない。ADR 0060)
var managedDirs = []struct {
	dir   string
	match func(name string) bool
}{
	{".github/workflows", func(n string) bool { return strings.HasPrefix(n, "arata-") }},
	{".github/scripts", func(n string) bool { return strings.HasPrefix(n, "arata-") }},
	{"github", func(n string) bool { return strings.HasSuffix(n, ".tf") }},
	{"github/secrets", func(n string) bool { return strings.HasSuffix(n, ".tf") }},
}

// args は、一式 (生成物) を決める引数を、コマンドの引数の形で返す。チャンネル ID のうち aratam.yaml に入るもの (--channel・--urgent-channel) は入れない
// (書き出した後は aratam.yaml だけが持つ。ADR 0060)。
func (p Params) args() string {
	s := fmt.Sprintf("--owner %s --repo %s --accounts %s --audit-account %s --store-bucket %s --region %s --alert-channel %s",
		p.Owner, p.Repo, strings.Join(p.Accounts, ","), p.AuditAccount, p.StoreBucket, p.Region, p.AlertChannel)
	if p.Schedule {
		s += " --schedule"
	}
	return s + " --out ."
}

// Command は、この一式を書き出すコマンド (README に載せる。--out は . にする)。
func (p Params) Command() string { return "arata repo init " + p.args() }

// CheckCommand は、この一式を確かめるコマンド (README と、PR の検査のワークフローに載せる)。
func (p Params) CheckCommand() string { return "arata repo check " + p.args() }

// Files は一式を返す (パスの順)。引数の形が通らなければ、何も返さない。
// today は既知リストの approved_at にだけ使う (UTC の日付)。
func Files(p Params, reg *checks.Registry, today time.Time) ([]File, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	schedule := "workflows/schedule-off.txt"
	if p.Schedule {
		schedule = "workflows/schedule-on.txt"
	}
	sched, err := templates.ReadFile("templates/" + schedule)
	if err != nil {
		return nil, err
	}
	// 知らせ (定時の通知が送れなかったことを、bot で知らせる) の有無で、断片を選ぶ。断片の中の印は、先に埋める
	alert := p.AlertChannel != NoAlert
	fragment := func(name string) (string, error) {
		if !alert {
			return "", nil
		}
		b, err := templates.ReadFile("templates/workflows/" + name)
		if err != nil {
			return "", err
		}
		send, err := templates.ReadFile("templates/workflows/alert-send.txt")
		if err != nil {
			return "", err
		}
		return strings.NewReplacer("@@ALERT_SEND@@", string(send), "@@ALERT_CHANNEL@@", p.AlertChannel).Replace(string(b)), nil
	}
	alertStep, err := fragment("alert-on.txt")
	if err != nil {
		return nil, err
	}
	notifyTestAlert, err := fragment("notify-test-alert-on.txt")
	if err != nil {
		return nil, err
	}
	routes, routesCase, routesText, routeAlertText, routeAlertReadme, alertText := "normal, urgent", "normal | urgent", "normal / urgent", "", "", "この一式は、知らせを使わない設定です"
	if alert {
		routes, routesCase, routesText = "normal, urgent, alert", "normal | urgent | alert", "normal / urgent / alert"
		routeAlertText = " / alert = 知らせのチャンネルに 1 通 (定時の通知が送れなかったときの知らせの確認。アカウントによらない)"
		routeAlertReadme = "・知らせ (`alert`) "
		alertText = "`" + p.AlertChannel + "`。定時の通知が送れなかったときに、ここへ知らせます"
	}
	quoted := make([]string, len(p.Accounts))
	for i, a := range p.Accounts {
		quoted[i] = "`" + a + "`"
	}
	fill := strings.NewReplacer(
		"@@SCHEDULE@@", string(sched),
		"@@ARATA_VERSION@@", p.Version,
		"@@AWS_REGION@@", p.Region,
		"@@ACCOUNTS@@", strings.Join(p.Accounts, ", "),
		"@@ACCOUNTS_TEXT@@", strings.Join(quoted, "、"),
		"@@STORE_BUCKET@@", p.StoreBucket,
		"@@OWNER@@", p.Owner,
		"@@REPO@@", p.Repo,
		"@@PROVIDER_VERSION@@", ProviderVersion,
		"@@COMMAND@@", p.Command(),
		"@@CHECK_COMMAND@@", p.CheckCommand(),
		"@@ALERT_STEP@@", alertStep,
		"@@NOTIFY_TEST_ALERT@@", notifyTestAlert,
		"@@ROUTES@@", routes,
		"@@ROUTES_CASE@@", routesCase,
		"@@ROUTES_TEXT@@", routesText,
		"@@ROUTE_ALERT_TEXT@@", routeAlertText,
		"@@ROUTE_ALERT_README@@", routeAlertReadme,
		"@@ALERT_TEXT@@", alertText,
	)
	var files []File
	for _, g := range generated {
		b, err := templates.ReadFile("templates/" + g.template)
		if err != nil {
			return nil, err
		}
		body := fill.Replace(string(b))
		if strings.Contains(body, "@@") {
			return nil, fmt.Errorf("repoinit: template %s has an unknown marker", g.template)
		}
		files = append(files, File{Path: g.path, Body: []byte(body), Mode: g.mode, Kind: Generated})
	}
	id, none, err := config.ParseAuditAccount(p.AuditAccount)
	if err != nil {
		return nil, err
	}
	for _, a := range p.Accounts {
		dir := "aws/" + a + "/"
		files = append(files,
			File{Path: dir + "arata.yaml", Mode: 0o644, Kind: Seed, Body: scaffold.GenerateWith(reg, scaffold.Options{
				AuditAccount: p.AuditAccount, Name: a, Store: "s3://" + p.StoreBucket + "/" + a, Region: p.Region, Profile: AuditProfile,
			})},
			aratamSeed(p, a),
		)
		if !none {
			// 監査する側のアカウントを既知リストに書く (config init と同じ。ADR 0045)。none なら書かない
			al, _, err := scaffold.AuditAllowlist(nil, id, "", today)
			if err != nil {
				return nil, err
			}
			files = append(files, File{Path: dir + "allowlist.yaml", Mode: 0o644, Kind: Seed, Body: al})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// aratamSeed は、アカウントの aratam.yaml (bot トークンの方式。ADR 0060・0061)。チャンネル ID が足りなければ、Missing に足りない引数を入れる。
func aratamSeed(p Params, account string) File {
	f := File{Path: "aws/" + account + "/aratam.yaml", Mode: 0o644, Kind: Seed}
	channel, urgent := p.Channels[account], p.UrgentChannels[account]
	if channel == "" {
		f.Missing = append(f.Missing, "--channel "+account+"=<channel ID>")
	}
	if urgent == "" {
		f.Missing = append(f.Missing, "--urgent-channel "+account+"=<channel ID>|"+SameChannel)
	}
	if urgent == SameChannel {
		urgent = ""
	}
	f.Body = aratamscaffold.Bot(account, channel, urgent)
	return f
}

// ParseAssignments は、引数の「<アカウント>=<値>」のカンマ区切り (--channel・--urgent-channel) を読む。空なら nil。
// 形 (アカウントが --accounts にあるか、値がチャンネル ID か) は Validate が確かめる。ここでは、組の形と重複だけを見る。
// エラーに値は写さない (チャンネルの欄にトークンを貼った誤りのため)。
func ParseAssignments(flag, s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	return ParseAssignmentList(flag, strings.Split(s, ","))
}

// ParseAssignmentList は、「<アカウント>=<値>」の項目の並びを読む。引数を繰り返して渡したとき (--channel a=… --channel b=…) は、
// 全部の項目をつなげたものを渡す。空の項目・組の形でない項目・同じアカウントの 2 度目は、片方を選ばずにエラーにする (黙って捨てない)。
func ParseAssignmentList(flag string, parts []string) (map[string]string, error) {
	if len(parts) == 0 {
		return nil, nil
	}
	if len(parts) > maxAccounts {
		return nil, fmt.Errorf("%s: at most %d accounts", flag, maxAccounts)
	}
	out := make(map[string]string, len(parts))
	for _, part := range parts {
		account, value, ok := strings.Cut(part, "=")
		if !ok || account == "" || value == "" || strings.Contains(value, "=") {
			return nil, fmt.Errorf("%s: each item must be <account>=<value>, separated by commas (for example prod=C0123456789)", flag)
		}
		if !accountRE.MatchString(account) {
			return nil, fmt.Errorf("%s: %q is not an account name", flag, printableArg(account))
		}
		if _, dup := out[account]; dup {
			return nil, fmt.Errorf("%s: %q appears twice", flag, account)
		}
		out[account] = value
	}
	return out, nil
}
