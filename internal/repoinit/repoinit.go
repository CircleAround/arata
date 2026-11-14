// Package repoinit は、監査を回すリポジトリ (GitHub Actions で arata と aratam を定時に動かすリポジトリ) の一式を作る
// (`arata repo init`。ADR 0059)。
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

	// Placeholder は秘密の箱に入れる仮の値。秘密ではない。ARN・JSON・URL・トークンのどの形でもなく、
	// ワークフローはこの値を見たら秘密の名前を出して止まる (.github/scripts/arata-secret-check.sh)。
	Placeholder = "arata-placeholder-not-set-yet"

	// Environment は GitHub の environment の名前。ワークフロー・Terraform・runner.yaml の GitHubEnvironment で同じ文字列にする (ADR 0057)。
	Environment = "audit"

	// AuditProfile はワークフローが書く AWS のプロファイルの名前 (監査対象の読み取り専用ロール)。arata.yaml の aws.profile と同じ。
	AuditProfile = "arata-audit"

	maxAccounts = 100
)

// SecretNames はワークフローが使う秘密の名前 (秘密の箱を作る名前)。ワークフローの secrets.* と同じであることをテストで固定する。
var SecretNames = []string{
	"ARATAM_SLACK_BOT_TOKEN",
	"ARATAM_SLACK_URGENT_WEBHOOK",
	"ARATAM_SLACK_WEBHOOK",
	"ARATA_ALERT_WEBHOOK",
	"ARATA_AUDIT_ROLE_ARNS",
	"ARATA_RUNNER_ROLE_ARN",
}

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
}

// 引数の形。値は YAML・HCL・シェル・Markdown の中にそのまま入るので、引用符・空白・改行・$ ・{ などは、形の時点で入らない。
var (
	ownerRE   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	accountRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	bucketRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRE  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]{1,16}){1,3}-[0-9]$`)
	versionRE = regexp.MustCompile(`^v(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$`)
)

// yamlWords は、引用符なしの YAML で文字列にならない語。アカウントの名前は引用符なしで matrix と name に入るので拒む。
var yamlWords = map[string]bool{"true": true, "false": true, "null": true, "yes": true, "no": true, "on": true, "off": true, "y": true, "n": true, "nan": true, "inf": true}

// Validate は引数の形を確かめる。通らなければ、一式は 1 つも作らない。
func (p Params) Validate() error {
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
	{"scripts/arata-slack-method.sh", ".github/scripts/arata-slack-method.sh", 0o755},
	{"scripts/arata-secret-check.sh", ".github/scripts/arata-secret-check.sh", 0o755},
	{"github/main.tf", "github/main.tf", 0o644},
	{"github/terraform.lock.hcl", "github/.terraform.lock.hcl", 0o644},
	{"github/secrets/main.tf", "github/secrets/main.tf", 0o644},
	{"github/terraform.lock.hcl", "github/secrets/.terraform.lock.hcl", 0o644},
	{"README.md", "README.md", 0o644},
	{"gitignore", ".gitignore", 0o644},
}

// managedDirs は、名前が arata- で始まるファイルをこのコマンドのものとみなすディレクトリ (--diff が「この版の一式に無い」を出す)。
var managedDirs = []string{".github/workflows", ".github/scripts"}

const managedPrefix = "arata-"

// Command は、この一式を書き出すコマンド (README に載せる。--out は . にする)。
func (p Params) Command() string {
	s := fmt.Sprintf("arata repo init --owner %s --repo %s --accounts %s --audit-account %s --store-bucket %s --region %s",
		p.Owner, p.Repo, strings.Join(p.Accounts, ","), p.AuditAccount, p.StoreBucket, p.Region)
	if p.Schedule {
		s += " --schedule"
	}
	return s + " --out ."
}

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
	names := make([]string, len(SecretNames))
	for i, n := range SecretNames {
		names[i] = `    "` + n + `",`
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
		"@@PLACEHOLDER@@", Placeholder,
		"@@SECRET_NAMES@@", strings.Join(names, "\n"),
		"@@COMMAND@@", p.Command(),
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
			File{Path: dir + "aratam.yaml", Mode: 0o644, Kind: Seed, Body: aratamscaffold.Named(a)},
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
