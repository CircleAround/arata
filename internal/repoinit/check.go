package repoinit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/codes"
)

// repo check --format json のスキーマの名前と版 (ADR 0054・0060)。名前は `arata schema <名前>` の名前。
// 版は、項目を消す・名前や型や意味を変える・閉じた語彙 (rows[].scope・rows[].status) に値を足すときだけ上げる。
const (
	CheckSchema        = "repo-check"
	CheckSchemaVersion = 1
)

// 検査の結果の状態 (arata doctor と同じ語彙)。ng が 1 つでもあれば終了コード 2。warn だけなら 0。
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckNG   = "ng"
	CheckSkip = "skip"
)

// 検査の範囲。
const (
	ScopeFiles  = "files"  // 手元のファイルだけを読む検査 (いつも行う)
	ScopeGitHub = "github" // GitHub の設定を読む検査 (--github のときだけ)
)

// 検査の項目 (rows[].item)。開いた語彙 (版を上げずに足される)。
const (
	ItemFiles                = "files"
	ItemTerraform            = "terraform"
	ItemWorkflowSecrets      = "workflow_secrets"
	ItemNotify               = "notify"
	ItemAccounts             = "accounts"
	ItemGitHub               = "github"
	ItemEnvironment          = "environment"
	ItemDeploymentBranches   = "deployment_branches"
	ItemEnvironmentProtected = "environment_protection"
	ItemSecret               = "secret"
	ItemSecretUnused         = "secret_unused"
	ItemRepositorySecret     = "repository_secret"
)

// CheckOutput は repo check --format json の出力。
type CheckOutput struct {
	Schema        string     `json:"schema" jsonschema:"const=repo-check"`
	SchemaVersion int        `json:"schema_version" jsonschema:"const=1"`
	OK            bool       `json:"ok" desc:"ng の行が無い (終了コード 0)。warn だけなら true。ng が 1 つでもあれば false (終了コード 2)"`
	Rows          []CheckRow `json:"rows" desc:"検査の結果の行 (table の出力の行と同じ内容)"`
	// MissingSecrets は必ず出す (空でも)。--github を付けていなければ、GitHub を読んでいないので空
	MissingSecrets []MissingSecret `json:"missing_secrets" desc:"environment に足りない秘密 (--github を付けたときだけ調べる)。名前ごとに、登録のコマンドと、値の形・取得元。値そのものは扱わない"`
}

// CheckRow は検査 1 項目。
type CheckRow struct {
	Scope  string   `json:"scope" jsonschema:"enum=files|github" desc:"files = 手元のファイルの検査、github = GitHub の設定の検査 (--github)"`
	Item   string   `json:"item" desc:"検査した項目 (files / terraform / workflow_secrets / notify / accounts / github / environment / deployment_branches / environment_protection / secret / secret_unused / repository_secret)。開いた語彙"`
	Target string   `json:"target,omitempty" desc:"対象 (ファイルのパス、アカウントの名前、秘密の名前)。項目の全体についての行には無い"`
	Status string   `json:"status" jsonschema:"enum=ok|warn|ng|skip" desc:"ng が 1 つでもあれば終了コード 2。skip = 検査していない (--github を付けていない)"`
	Code   string   `json:"code,omitempty" desc:"ログと同じ固定語彙の code (warn・ng の行)"`
	Detail string   `json:"detail" desc:"人向けの文。文言は固定しない (機械で読まない)"`
	Fix    []string `json:"fix,omitempty" desc:"直し方。そのまま打てるコマンドか、ファイルに書く行 (人向け。秘密の値は含まない)"`
}

// MissingSecret は、environment に足りない秘密 1 つ。
type MissingSecret struct {
	Name        string `json:"name" desc:"秘密の名前"`
	Environment string `json:"environment" desc:"登録する先の environment の名前"`
	Command     string `json:"command" desc:"そのまま打てる登録のコマンド (値は gh が端末で聞く。コマンドには含まない)"`
	ValueFormat string `json:"value_format" desc:"値の形の例 (架空の値)"`
	Source      string `json:"source" desc:"値を取りに行く場所"`
}

// Problems は ng の行があるか。
func (o *CheckOutput) Problems() bool {
	for _, r := range o.Rows {
		if r.Status == CheckNG {
			return true
		}
	}
	return false
}

func (o *CheckOutput) add(scope, item, target, status, code, detail string, fix ...string) {
	o.Rows = append(o.Rows, CheckRow{Scope: scope, Item: item, Target: target, Status: status, Code: code, Detail: detail, Fix: fix})
	if status == CheckNG {
		o.OK = false
	}
}

// NewCheck は空の結果を返す。
func NewCheck() *CheckOutput {
	return &CheckOutput{Schema: CheckSchema, SchemaVersion: CheckSchemaVersion, OK: true, Rows: []CheckRow{}, MissingSecrets: []MissingSecret{}}
}

// CheckFiles は、dir にある一式を、この版・この引数の一式 (files) と比べ、ワークフローが使う秘密と、アカウントごとの aratam.yaml を確かめる
// (ADR 0060 のファイルの検査)。手元のファイルだけを読み、何も書かない。秘密も GitHub も要らない。
func CheckFiles(o *CheckOutput, dir string, p Params, files []File) error {
	diff, err := Diff(dir, files)
	if err != nil {
		return err
	}
	// files / terraform: この版の一式との差 (repo init --diff と同じ比べ方)。github/ の下は terraform の項目として出す
	force := "arata repo init " + p.args() + " --force"
	counts := map[string]int{}
	bad := map[string]bool{}
	for _, f := range diff.Files {
		if f.Kind != string(Generated) {
			continue
		}
		item := ItemFiles
		if strings.HasPrefix(f.Path, "github/") {
			item = ItemTerraform
		}
		switch f.Status {
		case StatusSame:
			counts[item]++
		case StatusDiffers:
			bad[item] = true
			o.add(ScopeFiles, item, printable(f.Path), CheckNG, codes.RepoSetDiffers, "この版の一式と中身が違う (生成物は手で直さない。違いは arata repo init … --diff で見られる)", force)
		case StatusMissing:
			bad[item] = true
			o.add(ScopeFiles, item, printable(f.Path), CheckNG, codes.RepoSetDiffers, "一式のファイルが無い", force)
		case StatusExtra:
			bad[item] = true
			detail := "この版の一式に無いファイル (古い版の残り。要らなければ消す)"
			switch {
			case strings.HasPrefix(f.Path, "github/secrets/"):
				detail = "この版の一式に無い Terraform の宣言 (これまでの版の「秘密の箱」。この版は秘密に触れない。github/secrets/ を、手元の state ごと消す。登録済みの秘密には何も起きない)"
			case item == ItemTerraform:
				detail = "この版の一式に無い Terraform の宣言 (同じディレクトリの .tf は全部当たる。手で作った宣言なら消す)"
			}
			o.add(ScopeFiles, item, printable(f.Path), CheckNG, codes.RepoSetDiffers, detail)
		}
	}
	for _, item := range []string{ItemFiles, ItemTerraform} {
		if !bad[item] {
			o.add(ScopeFiles, item, "", CheckOK, "", fmt.Sprintf("この版の一式と同じ (%d ファイル)", counts[item]))
		}
	}
	if err := checkWorkflowSecrets(o, dir); err != nil {
		return err
	}
	return checkAccounts(o, dir, p)
}

// checkWorkflowSecrets は、.github/workflows の arata- で始まるワークフローが参照する秘密の名前が、SecretNames と同じかを確かめる。
func checkWorkflowSecrets(o *CheckOutput, dir string) error {
	wfDir := filepath.Join(dir, ".github", "workflows")
	ents, err := os.ReadDir(wfDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	used := map[string]bool{}
	ok := true
	n := 0
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "arata-") || !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			continue
		}
		rel := ".github/workflows/" + name
		body, exists, err := readTarget(dir, rel)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		n++
		names, dynamic, err := WorkflowSecrets(body)
		if err != nil {
			ok = false
			o.add(ScopeFiles, ItemWorkflowSecrets, printable(rel), CheckNG, codes.RepoSetDiffers, "ワークフローを YAML として読めない (か、大きすぎる)")
			continue
		}
		if dynamic {
			ok = false
			o.add(ScopeFiles, ItemWorkflowSecrets, printable(rel), CheckNG, codes.RepoSetDiffers, "秘密の名前を式で作る参照 (secrets[…]) がある。ジョブに全部の秘密が渡るので、使わない")
		}
		for _, s := range names {
			used[s] = true
		}
	}
	if n == 0 {
		return nil // ワークフローが無いことは files の行が出している
	}
	want := map[string]bool{}
	for _, s := range SecretNames {
		want[s] = true
	}
	var extra, lacking []string
	for s := range used {
		if !want[s] {
			extra = append(extra, s)
		}
	}
	for s := range want {
		if !used[s] {
			lacking = append(lacking, s)
		}
	}
	sort.Strings(extra)
	sort.Strings(lacking)
	for _, s := range extra {
		ok = false
		o.add(ScopeFiles, ItemWorkflowSecrets, s, CheckNG, codes.RepoSetDiffers, "ワークフローが、この一式の使わない秘密を参照している (この一式が使うのは "+strings.Join(SecretNames, "・")+" だけ)")
	}
	for _, s := range lacking {
		ok = false
		o.add(ScopeFiles, ItemWorkflowSecrets, s, CheckNG, codes.RepoSetDiffers, "ワークフローが、この一式の使う秘密を参照していない")
	}
	if ok {
		o.add(ScopeFiles, ItemWorkflowSecrets, "", CheckOK, "", "ワークフローが参照する秘密は "+strings.Join(SecretNames, "・")+" だけ")
	}
	return nil
}

// checkAccounts は、アカウントごとに、設定のファイルがあるかと、aratam.yaml がワークフローの渡す秘密 (bot トークン) で送る設定かを確かめる。
func checkAccounts(o *CheckOutput, dir string, p Params) error {
	for _, a := range p.Accounts {
		present := true
		var aratam []byte
		for _, name := range []string{"arata.yaml", "aratam.yaml"} {
			rel := "aws/" + a + "/" + name
			body, exists, err := readTarget(dir, rel)
			if err != nil {
				return err
			}
			if !exists {
				present = false
				o.add(ScopeFiles, ItemAccounts, rel, CheckNG, codes.RepoSetDiffers, "アカウントの設定が無い (arata repo init が、無いものだけを作る。中身の形は config check が見る)")
				continue
			}
			if name == "aratam.yaml" {
				if body == nil {
					o.add(ScopeFiles, ItemNotify, a, CheckNG, codes.RepoNotifyMismatch, rel+" が大きすぎて読めない")
					present = false
					continue
				}
				aratam = body
			}
		}
		if present {
			o.add(ScopeFiles, ItemAccounts, a, CheckOK, "", "aws/"+a+"/ に arata.yaml と aratam.yaml がある")
		}
		if aratam == nil {
			continue
		}
		rel := "aws/" + a + "/aratam.yaml"
		slack, err := readAratamSlack(aratam)
		if err != nil {
			o.add(ScopeFiles, ItemNotify, a, CheckNG, codes.RepoNotifyMismatch, rel+" を YAML として読めない (aratam config check の出力を見る)")
			continue
		}
		if slack.method() == methodBot && slack.BotTokenEnv == botTokenSecret && slack.WebhookEnv == "" && slack.UrgentWebhookEnv == "" {
			o.add(ScopeFiles, ItemNotify, a, CheckOK, "", rel+" は bot トークンの方式 ("+botTokenSecret+")。チャンネル ID の形は aratam config check が見る")
			continue
		}
		// 直す行。チャンネル ID は、引数にあればその値、aratam.yaml に形の合うものがあればそのまま、無ければ書く場所だけを示す
		channel := p.Channels[a]
		if channel == "" && channelRE.MatchString(slack.Channel) {
			channel = slack.Channel
		}
		if channel == "" {
			channel = "<チャンネル ID (例 C0123456789)>"
		}
		o.add(ScopeFiles, ItemNotify, a, CheckNG, codes.RepoNotifyMismatch,
			rel+" が、bot トークンの方式 ("+botTokenSecret+") でない。この一式のワークフローは、bot トークンだけを渡す。slack の節を、次の行にする",
			`webhook_env: ""`, `urgent_webhook_env: ""`, "bot_token_env: "+botTokenSecret, `channel: "`+channel+`"`)
	}
	return nil
}

// botTokenSecret は、ワークフローが aratam に渡す秘密 (環境変数) の名前。
const botTokenSecret = "ARATAM_SLACK_BOT_TOKEN" // #nosec G101 -- 秘密の名前で、値ではない

const (
	methodBot     = "bot"
	methodWebhook = "webhook"
)

// aratamSlack は、aratam.yaml の slack の節のうち、送り方を決める項目 (ADR 0060)。
//
// 決定: arata は aratam の設定のパッケージ (internal/notify) につながない (ADR 0018・0059)。ここで読むのは項目の名前と値だけで、
// 形の検査 (環境変数の名前・チャンネル ID の形) は aratam config check の役目。
// 「aratam が判別する送り方と、ここで読んだ結果が同じ」ことは、テスト (cmd/aratam) が固定する。
type aratamSlack struct {
	WebhookEnv       string `yaml:"webhook_env"`
	UrgentWebhookEnv string `yaml:"urgent_webhook_env"`
	BotTokenEnv      string `yaml:"bot_token_env"`
	Channel          string `yaml:"channel"`
	UrgentChannel    string `yaml:"urgent_channel"`
}

// method は aratam と同じ判別: bot の項目が 1 つでも書いてあれば bot、無ければ webhook。
func (s aratamSlack) method() string {
	if s.BotTokenEnv != "" || s.Channel != "" || s.UrgentChannel != "" {
		return methodBot
	}
	return methodWebhook
}

// readAratamSlack は aratam.yaml の slack の節を読む。利用者のファイルなので、形が合わなければエラーにするだけで、値は外へ出さない。
func readAratamSlack(body []byte) (aratamSlack, error) {
	var doc struct {
		Slack aratamSlack `yaml:"slack"`
	}
	if len(body) > maxExisting {
		return aratamSlack{}, fmt.Errorf("too large")
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return aratamSlack{}, fmt.Errorf("not a YAML mapping with a slack section")
	}
	return doc.Slack, nil
}

// AratamSlackMethod は aratam.yaml の送り方 (bot / webhook) を返す (テスト用: aratam の判別と同じであることを固定する)。
func AratamSlackMethod(body []byte) (string, error) {
	s, err := readAratamSlack(body)
	if err != nil {
		return "", err
	}
	return s.method(), nil
}

var (
	// exprRE は GitHub の式 (${{ … }})。秘密は式の中でしか参照できない
	exprRE = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	// secretRefRE は、式の中の secrets.<名前>。GitHub の秘密の名前は、英数字と _ (大文字と小文字を区別しない)
	secretRefRE = regexp.MustCompile(`(?i)\bsecrets\s*\.\s*([A-Za-z_][A-Za-z0-9_]{0,254})`)
	// secretWordRE は、式の中の secrets という語。secrets.<名前> を除いた残りにあれば、名前を決められない参照
	// (secrets[…] や toJSON(secrets)。ジョブに全部の秘密が渡る)
	secretWordRE = regexp.MustCompile(`(?i)\bsecrets\b`)
)

// maxYAMLNodes は、ワークフローの YAML を歩く上限 (別名の展開で膨らむ入力を、途中でやめる)。
const maxYAMLNodes = 200_000

// WorkflowSecrets は、ワークフローの YAML が参照する秘密の名前 (大文字にそろえ、名前の順) を返す。
// dynamic は、名前を決められない参照があるか: 式の中の secrets[…]・toJSON(secrets) と、呼び出すワークフローに全部を渡す secrets: inherit。
// コメントは読まない (YAML として読み、値の文字列の中の式 ${{ … }} だけを見る)。利用者のファイルなので、読めなければエラーにする。
func WorkflowSecrets(body []byte) (names []string, dynamic bool, err error) {
	if len(body) > maxExisting {
		return nil, false, fmt.Errorf("too large")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(body, &root); err != nil {
		return nil, false, fmt.Errorf("not YAML")
	}
	seen := map[string]bool{}
	budget := maxYAMLNodes
	var walk func(n *yaml.Node, depth int) bool
	walk = func(n *yaml.Node, depth int) bool {
		budget--
		if n == nil {
			return true
		}
		if budget < 0 || depth > 200 {
			return false
		}
		switch n.Kind {
		case yaml.ScalarNode:
			for _, e := range exprRE.FindAllStringSubmatch(n.Value, -1) {
				for _, m := range secretRefRE.FindAllStringSubmatch(e[1], -1) {
					seen[strings.ToUpper(m[1])] = true
				}
				if secretWordRE.MatchString(secretRefRE.ReplaceAllString(e[1], " ")) {
					dynamic = true
				}
			}
		case yaml.AliasNode:
			return walk(n.Alias, depth+1)
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k, v := n.Content[i], n.Content[i+1]; k.Kind == yaml.ScalarNode && k.Value == "secrets" && v.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(v.Value), "inherit") {
					dynamic = true
				}
			}
		}
		for _, c := range n.Content {
			if !walk(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(&root, 0) {
		return nil, false, fmt.Errorf("too large")
	}
	for s := range seen {
		names = append(names, s)
	}
	sort.Strings(names)
	return names, dynamic, nil
}

// WriteCheck は人向けの表 (table)。文言と並びは固定しない (機械で読むのは --format json)。
func WriteCheck(w io.Writer, o *CheckOutput) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCOPE\tITEM\tTARGET\tSTATUS\tCODE\tDETAIL")
	for _, r := range o.Rows {
		code, target := r.Code, r.Target
		if code == "" {
			code = "-"
		}
		if target == "" {
			target = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Scope, r.Item, target, r.Status, code, r.Detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	var b strings.Builder
	// 直し方 (秘密の登録のほか)。同じものは 1 回
	seen := map[string]bool{}
	for _, r := range o.Rows {
		if len(r.Fix) == 0 || r.Item == ItemSecret {
			continue
		}
		key := r.Item + "\x00" + strings.Join(r.Fix, "\n")
		if r.Item == ItemNotify {
			key += "\x00" + r.Target
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		head := r.Item
		if r.Item == ItemNotify || r.Item == ItemSecretUnused || r.Item == ItemRepositorySecret {
			head += " " + r.Target
		}
		fmt.Fprintf(&b, "\n%s の直し方:\n", head)
		for _, l := range r.Fix {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}
	if len(o.MissingSecrets) > 0 {
		b.WriteString("\n足りない秘密 (コマンドをそのまま打つ。値は gh が端末で聞くので、貼り付ける。登録したら、もう一度 arata repo check … --github):\n")
		for _, m := range o.MissingSecrets {
			fmt.Fprintf(&b, "  %s\n      値の形: %s\n      取得元: %s\n", m.Command, m.ValueFormat, m.Source)
		}
	}
	switch {
	case o.Problems():
		b.WriteString("\nng があります (終了コード 2)。\n")
	default:
		b.WriteString("\nng はありません。\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// ChannelLines は、既にある aws/<account>/aratam.yaml のチャンネル ID が、引数 (--channel・--urgent-channel) と違うときに、直す行を返す (ADR 0060)。
// repo init は、既にある aratam.yaml を書き直さない。渡された値を黙って捨てずに、「書き直していない。変えるなら、この行を直す」と知らせるために使う。
// 引数に無いアカウント・同じ値・読めないファイルなら、何も返さない (読めないことは repo check の notify が出す)。
func ChannelLines(dir, account string, p Params) []string {
	body, exists, err := readTarget(dir, "aws/"+account+"/aratam.yaml")
	if err != nil || !exists || body == nil {
		return nil
	}
	slack, err := readAratamSlack(body)
	if err != nil {
		return nil
	}
	var lines []string
	if want := p.Channels[account]; want != "" && want != slack.Channel {
		lines = append(lines, `channel: "`+want+`"`)
	}
	if want := p.UrgentChannels[account]; want != "" {
		if want == SameChannel {
			want = ""
		}
		if want != slack.UrgentChannel {
			lines = append(lines, `urgent_channel: "`+want+`"`)
		}
	}
	return lines
}
