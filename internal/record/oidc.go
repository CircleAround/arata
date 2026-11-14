package record

import (
	"regexp"
	"strings"
)

// OIDC でのロールの引き受け (AssumeRoleWithWebIdentity) の値の形 (ADR 0055)。
// プロバイダの名前と sub はログ由来の値。collector (残すとき)・チェック (ストアから読み戻すとき)・既知リスト (人が書いた値) が同じ形で確かめる。

// GitHubOIDCProvider は GitHub Actions の OIDC プロバイダの名前 (プロバイダの ARN の oidc-provider/ より後ろ)。
// sub を読むのは、プロバイダがこの名前のときだけ (GitHub Enterprise Server など、発行元が別のホストのものは「GitHub 以外」)。
const GitHubOIDCProvider = "token.actions.githubusercontent.com"

// OIDCProviderUnparsed は、プロバイダの名前が決まった形でないときに代わりに使う値 (名前には `.` が要るので、実在の名前と重ならない)。
const OIDCProviderUnparsed = "unparsed"

// sub の形 (data.oidc_sub_form)。
const (
	OIDCSubGitHub   = "github"   // GitHub の決まった形として読めた
	OIDCSubUnparsed = "unparsed" // GitHub のプロバイダだが、決まった形でない (sub をカスタマイズしたリポジトリを含む)。値は残さない
	OIDCSubNotRead  = "not_read" // GitHub 以外のプロバイダ。sub は読まず、残さない
)

// sub の種類 (data.oidc_sub_kind)。
const (
	OIDCKindRef         = "ref"
	OIDCKindEnvironment = "environment"
	OIDCKindPullRequest = "pull_request"
)

// MaxOIDCSub は読む sub の長さの上限。
const MaxOIDCSub = 512

var (
	// プロバイダの名前はホスト名 (とパス)。`.` を 1 つ以上含む
	oidcProviderRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]{0,254}\z`)
	oidcProviderARNRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):oidc-provider/(.+)\z`)
	// GitHub が組織 (利用者) とリポジトリの名前に許す文字
	githubRepoRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\z`)
	githubSubRe  = regexp.MustCompile(`^repo:([A-Za-z0-9][A-Za-z0-9-]{0,38})(?:@([0-9]{1,20}))?/([A-Za-z0-9._-]{1,100})(?:@([0-9]{1,20}))?:(.+)\z`)
	// ref は refs/ で始まり、英数字と `._/@+=-` だけ (git が許す文字はもっと広いが、通知にそのまま出す値なので絞る。外れたら「読めない」)
	gitRefRe = regexp.MustCompile(`^refs/[A-Za-z0-9._/@+=-]{1,250}\z`)
	// environment の名前は英数字と `._-`、途中の空白
	githubEnvRe = regexp.MustCompile(`^[A-Za-z0-9._-](?:[A-Za-z0-9._ -]{0,253}[A-Za-z0-9._-])?\z`)
	runIDRe     = regexp.MustCompile(`(?:^|\s)md/run_id#([0-9]{1,20})(?:\s|\z)`)
)

// ValidOIDCProvider は s がプロバイダの名前の形か。
func ValidOIDCProvider(s string) bool {
	return oidcProviderRe.MatchString(s) && strings.Contains(s, ".")
}

// OIDCProvider は CloudTrail の userIdentity.identityProvider からプロバイダの名前と、ARN ならそのアカウントを返す。
// ARN (arn:aws:iam::NNN:oidc-provider/<名前>) なら oidc-provider/ より後ろ、そうでなければ値そのもの (cognito-identity.amazonaws.com など)。
// 名前が決まった形でなければ (OIDCProviderUnparsed, "")。
func OIDCProvider(identityProvider string) (name, account string) {
	name = identityProvider
	if m := oidcProviderARNRe.FindStringSubmatch(identityProvider); m != nil {
		account, name = m[1], m[2]
	}
	if !ValidOIDCProvider(name) {
		return OIDCProviderUnparsed, ""
	}
	return name, account
}

// ValidGitHubRepo は s が「組織/リポジトリ」の形か。
func ValidGitHubRepo(s string) bool { return githubRepoRe.MatchString(s) }

// ValidGitRef は s が sub に入る ref (refs/heads/main など) の形か。
func ValidGitRef(s string) bool { return gitRefRe.MatchString(s) }

// ValidGitHubEnvironment は s が environment の名前の形か。
func ValidGitHubEnvironment(s string) bool { return githubEnvRe.MatchString(s) }

// GitHubSub は GitHub の OIDC のトークンの sub を読んだもの。
type GitHubSub struct {
	Repo        string // 組織/リポジトリ (ID を外した形)
	OwnerID     string // ID 入りの形のときだけ
	RepoID      string
	Kind        string // OIDCKindRef / OIDCKindEnvironment / OIDCKindPullRequest
	Ref         string // Kind が ref のとき
	Environment string // Kind が environment のとき
}

// ParseGitHubSub は sub を読む。形は `repo:<組織>[@<数字>]/<リポジトリ>[@<数字>]:` の後に `ref:<ref>`・`environment:<名前>`・`pull_request`。
// 先頭から末尾までの一致で、決まった形でなければ ok が false (値は返さない)。
// 決定 (ADR 0055): ID 入りの形 (`example-org@1234567/example-repo@7654321`) は ID を外して同じ組にする。ID は OwnerID / RepoID に残す。
func ParseGitHubSub(sub string) (GitHubSub, bool) {
	if len(sub) > MaxOIDCSub {
		return GitHubSub{}, false
	}
	m := githubSubRe.FindStringSubmatch(sub)
	if m == nil {
		return GitHubSub{}, false
	}
	out := GitHubSub{Repo: m[1] + "/" + m[3], OwnerID: m[2], RepoID: m[4]}
	rest := m[5]
	switch {
	case rest == OIDCKindPullRequest:
		out.Kind = OIDCKindPullRequest
	case strings.HasPrefix(rest, "ref:") && ValidGitRef(rest[len("ref:"):]):
		out.Kind, out.Ref = OIDCKindRef, rest[len("ref:"):]
	case strings.HasPrefix(rest, "environment:") && ValidGitHubEnvironment(rest[len("environment:"):]):
		out.Kind, out.Environment = OIDCKindEnvironment, rest[len("environment:"):]
	default:
		return GitHubSub{}, false
	}
	return out, true
}

// Normalized は ID を外した sub (`repo:<組織>/<リポジトリ>:ref:<ref>` など)。Key と表示に使う。
func (s GitHubSub) Normalized() string {
	switch s.Kind {
	case OIDCKindRef:
		return "repo:" + s.Repo + ":ref:" + s.Ref
	case OIDCKindEnvironment:
		return "repo:" + s.Repo + ":environment:" + s.Environment
	case OIDCKindPullRequest:
		return "repo:" + s.Repo + ":pull_request"
	}
	return ""
}

// GitHubRunID は userAgent から GitHub Actions の実行の ID (`md/run_id#<数字>`) を取り出す。`exec-env/GitHubActions` を名乗る userAgent のときだけ。
// 決定 (ADR 0055): userAgent は呼ぶ側が自由に書ける値。判定には使わず、調べる手がかりとして残すだけにする。
func GitHubRunID(userAgent string) (string, bool) {
	if len(userAgent) > 2048 || !strings.Contains(userAgent, "exec-env/GitHubActions") {
		return "", false
	}
	m := runIDRe.FindStringSubmatch(userAgent)
	if m == nil {
		return "", false
	}
	return m[1], true
}
