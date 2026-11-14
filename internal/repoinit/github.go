package repoinit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/codes"
)

// GitHubAPIURL は GitHub の API の場所。設定や環境変数からは変えられない (鍵を別のホストへ送らせない。ADR 0060)。
// テストだけが、GitHub.BaseURL を偽の API に差し替える。GitHub Enterprise Server は対象にしない。
const GitHubAPIURL = "https://api.github.com"

// GitHub の応答の上限。応答は信用しない入力として読む (ADR 0041・0060)。
const (
	maxGitHubBody  = 1 << 20 // 1 回の応答の大きさ
	maxGitHubPages = 10      // 一覧のページ数 (1 ページ 100 件)
	gitHubPerPage  = 100
)

var (
	// githubSecretRE は、出力に運ぶ秘密の名前の形 (GitHub の秘密の名前: 英数字と _。GitHub は大文字で返す)。
	// 形の合わない名前は、数だけを数えて、出力には運ばない。
	githubSecretRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,254}$`)
	// githubBranchRE は、出力に運ぶブランチの名前の形。
	githubBranchRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
)

// GitHub は、GitHub の API を読むための設定。呼ぶのは GET だけ (テストが固定する)。
type GitHub struct {
	Client  *http.Client // nil なら、時間切れ 30 秒・リダイレクトを追わないクライアント
	BaseURL string       // 空なら GitHubAPIURL。テストだけが差し替える
	Token   string       // 環境変数 GITHUB_TOKEN (無ければ GH_TOKEN) の値。出力にもエラーにも写さない
}

// NewGitHubClient は、リダイレクトを追わないクライアントを返す (鍵の付いた要求を、別の場所へ送り直さない)。
func NewGitHubClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// apiError は API の失敗。応答の本文は持たない (出力に写さない)。
type apiError struct{ status int }

func (e *apiError) Error() string {
	switch e.status {
	case http.StatusUnauthorized:
		return "認証に失敗した (HTTP 401)。GITHUB_TOKEN の値を確かめる"
	case http.StatusForbidden:
		return "権限が足りないか、回数の制限に掛かった (HTTP 403)。リポジトリの admin を持つ鍵で読む"
	case http.StatusNotFound:
		return "見つからない (HTTP 404)。--owner と --repo の名前と、鍵がそのリポジトリを読めるかを確かめる"
	case 0:
		return "GitHub に繋がらないか、応答を読めない"
	}
	return "HTTP " + strconv.Itoa(e.status)
}

// get は path (/ で始まる。形を確かめた値だけで組み立てる) を GET で読み、JSON を into に入れる。
func (g GitHub) get(ctx context.Context, path string, into any) error {
	base := g.BaseURL
	if base == "" {
		base = GitHubAPIURL
	}
	client := g.Client
	if client == nil {
		client = NewGitHubClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return &apiError{}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "arata-repo-check")
	req.Header.Set("Authorization", "Bearer "+g.Token)
	resp, err := client.Do(req)
	if err != nil {
		// エラーの文は出さない (URL と、場合によっては応答の一部が入る)
		return &apiError{}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubBody+1))
	if err != nil || len(body) > maxGitHubBody {
		return &apiError{}
	}
	if resp.StatusCode != http.StatusOK {
		return &apiError{status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, into); err != nil {
		return &apiError{}
	}
	return nil
}

// GitHub の応答のうち、読む項目だけ。秘密の値は、API が返さない (名前と日時だけ)。日時も読まない。
type (
	ghRepository struct {
		DefaultBranch string `json:"default_branch"`
	}
	ghEnvironment struct {
		ProtectionRules []struct {
			Type string `json:"type"`
		} `json:"protection_rules"`
		DeploymentBranchPolicy *struct {
			ProtectedBranches    bool `json:"protected_branches"`
			CustomBranchPolicies bool `json:"custom_branch_policies"`
		} `json:"deployment_branch_policy"`
	}
	ghBranchPolicies struct {
		TotalCount     int `json:"total_count"`
		BranchPolicies []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"branch_policies"`
	}
	ghSecrets struct {
		TotalCount int `json:"total_count"`
		Secrets    []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
)

// secretNames は、秘密の名前の一覧 (path は一覧の API) を全部のページから読む。
// 形の合う名前だけを、大文字にそろえて返す。odd は、形の合わなかった名前の数。more は、ページの上限で読み切れなかったか。
func (g GitHub) secretNames(ctx context.Context, path string) (names []string, odd int, more bool, err error) {
	seen := map[string]bool{}
	for page := 1; ; page++ {
		if page > maxGitHubPages {
			more = true
			break
		}
		var res ghSecrets
		if err := g.get(ctx, fmt.Sprintf("%s?per_page=%d&page=%d", path, gitHubPerPage, page), &res); err != nil {
			return nil, 0, false, err
		}
		for _, s := range res.Secrets {
			if !githubSecretRE.MatchString(s.Name) {
				odd++
				continue
			}
			seen[strings.ToUpper(s.Name)] = true
		}
		if len(res.Secrets) < gitHubPerPage {
			break
		}
	}
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, odd, more, nil
}

// secretHelp は、足りない秘密の値の形 (架空の値) と、取りに行く場所。
func secretHelp(p Params, name string) (format, source string) {
	switch name {
	case "ARATA_RUNNER_ROLE_ARN":
		return "arn:aws:iam::123456789012:role/arata-runner", "実行の仕組み (deploy/github-actions/runner.yaml) のスタックの出力 RunnerRoleArn"
	case "ARATA_AUDIT_ROLE_ARNS":
		parts := make([]string, len(p.Accounts))
		for i, a := range p.Accounts {
			parts[i] = `"` + a + `": "arn:aws:iam::123456789012:role/arata-readonly"`
		}
		return "{" + strings.Join(parts, ", ") + "}", "読み取り専用ロール (deploy/iam/readonly-role.yaml) のスタックの出力。アカウントの名前から ARN を引く JSON にする"
	case botTokenSecret:
		return "xoxb-…", "Slack アプリ (deploy/slack/app-manifest.yaml から作る) の「OAuth & Permissions」の Bot User OAuth Token"
	}
	return "", ""
}

// CheckGitHub は、GitHub の environment と、秘密の名前を確かめる (ADR 0060 の GitHub の検査)。読むだけで、何も書かない。
// GitHub は秘密の名前と日時しか返さない。値は読めないし、読まない。
// API の失敗は、その項目の ng の行にする (エラーでは返さない)。p は Validate を通っていること (名前を URL とコマンドに入れる)。
func CheckGitHub(ctx context.Context, o *CheckOutput, g GitHub, p Params) {
	repo := "/repos/" + p.Owner + "/" + p.Repo
	slug := p.Owner + "/" + p.Repo
	env := repo + "/environments/" + Environment
	fail := func(item string, err error) {
		var ae *apiError
		msg := "GitHub の API を読めない"
		if errors.As(err, &ae) {
			msg += ": " + ae.Error()
		}
		o.add(ScopeGitHub, item, "", CheckNG, codes.GitHubAPIFailed, msg)
	}
	apply := "GITHUB_TOKEN=\"$(gh auth token)\" terraform -chdir=github apply"

	var r ghRepository
	if err := g.get(ctx, repo, &r); err != nil {
		fail(ItemGitHub, err)
		return // リポジトリを読めなければ、後も読めない
	}
	branch := r.DefaultBranch
	if !githubBranchRE.MatchString(branch) {
		branch = ""
	}

	var e ghEnvironment
	err := g.get(ctx, env, &e)
	var ae *apiError
	switch {
	case errors.As(err, &ae) && ae.status == http.StatusNotFound:
		o.add(ScopeGitHub, ItemEnvironment, Environment, CheckNG, codes.RepoEnvironmentMissing,
			"environment "+Environment+" が無い。ワークフローより先に作る (無い environment を参照するワークフローが動くと、制限なしで自動で作られる)", apply)
		// environment が無ければ、その秘密も無い。足りない秘密として出す
		checkSecrets(o, p, slug, nil)
	case err != nil:
		fail(ItemEnvironment, err)
	default:
		o.add(ScopeGitHub, ItemEnvironment, Environment, CheckOK, "", "environment "+Environment+" がある")
		checkBranches(ctx, o, g, env, e, branch, apply)
		var protected []string
		for _, rule := range e.ProtectionRules {
			switch rule.Type {
			case "required_reviewers":
				protected = append(protected, "レビュー担当")
			case "wait_timer":
				protected = append(protected, "待ち時間")
			}
		}
		if len(protected) > 0 {
			o.add(ScopeGitHub, ItemEnvironmentProtected, Environment, CheckWarn, codes.RepoEnvironmentProtected,
				"environment に "+strings.Join(protected, "と")+" が付いている。定時の実行が、承認か待ち時間で止まる", apply)
		} else {
			o.add(ScopeGitHub, ItemEnvironmentProtected, Environment, CheckOK, "", "レビュー担当も待ち時間も付いていない (定時の実行が止まらない)")
		}
		names, odd, more, err := g.secretNames(ctx, env+"/secrets")
		if err != nil {
			fail(ItemSecret, err)
		} else {
			checkSecrets(o, p, slug, names)
			noteOdd(o, ItemSecretUnused, odd, more)
		}
	}

	// リポジトリの (environment でない) 秘密。どのブランチのジョブにも渡るので、environment の守りを抜ける
	names, odd, more, err := g.secretNames(ctx, repo+"/actions/secrets")
	if err != nil {
		fail(ItemRepositorySecret, err)
		return
	}
	known := map[string]bool{}
	for _, n := range append(append([]string{}, SecretNames...), FormerSecretNames...) {
		known[n] = true
	}
	for _, n := range names {
		del := "gh secret delete " + n + " -R " + slug
		if known[n] {
			o.add(ScopeGitHub, ItemRepositorySecret, n, CheckNG, codes.RepoSecretOutsideEnvironment,
				"リポジトリの秘密 (environment の外) に、この一式の秘密の名前がある。どのブランチのジョブにも渡る。environment "+Environment+" に登録し、こちらは消す", del)
		} else {
			o.add(ScopeGitHub, ItemRepositorySecret, n, CheckWarn, codes.RepoSecretOutsideEnvironment,
				"リポジトリの秘密 (environment の外) がある。どのブランチのジョブにも渡る。この一式は使わない。要らなければ消す", del)
		}
	}
	if len(names) == 0 {
		o.add(ScopeGitHub, ItemRepositorySecret, "", CheckOK, "", "リポジトリの秘密 (environment の外) は無い")
	}
	noteOdd(o, ItemRepositorySecret, odd, more)
}

// noteOdd は、形の合わなかった名前・読み切れなかった一覧を warn の行にする (名前は出さない)。
func noteOdd(o *CheckOutput, item string, odd int, more bool) {
	if odd > 0 {
		o.add(ScopeGitHub, item, "", CheckWarn, codes.GitHubAPIFailed, fmt.Sprintf("秘密の名前の形でない名前が %d 個返った (出力には運ばない)", odd))
	}
	if more {
		o.add(ScopeGitHub, item, "", CheckWarn, codes.GitHubAPIFailed, fmt.Sprintf("秘密が多く、最初の %d 個までしか読んでいない", maxGitHubPages*gitHubPerPage))
	}
}

// checkBranches は、デプロイできるブランチが、既定のブランチ 1 つだけかを確かめる。
func checkBranches(ctx context.Context, o *CheckOutput, g GitHub, env string, e ghEnvironment, branch, apply string) {
	ng := func(detail string) {
		o.add(ScopeGitHub, ItemDeploymentBranches, Environment, CheckNG, codes.RepoEnvironmentOpen,
			detail+"。ほかのブランチのジョブにも、environment の秘密と OIDC の引き受けが渡る。既定のブランチだけにする", apply)
	}
	pol := e.DeploymentBranchPolicy
	switch {
	case pol == nil:
		ng("デプロイできるブランチが「すべてのブランチ」")
		return
	case pol.ProtectedBranches || !pol.CustomBranchPolicies:
		ng("デプロイできるブランチが「保護されたブランチ」(名前で絞っていない)")
		return
	case branch == "":
		ng("既定のブランチの名前を読めない")
		return
	}
	var res ghBranchPolicies
	if err := g.get(ctx, fmt.Sprintf("%s/deployment-branch-policies?per_page=%d", env, gitHubPerPage), &res); err != nil {
		var ae *apiError
		msg := "GitHub の API を読めない"
		if errors.As(err, &ae) {
			msg += ": " + ae.Error()
		}
		o.add(ScopeGitHub, ItemDeploymentBranches, Environment, CheckNG, codes.GitHubAPIFailed, msg)
		return
	}
	// type が無い応答 (古い形) は branch として扱う
	if len(res.BranchPolicies) == 1 && res.TotalCount <= 1 && res.BranchPolicies[0].Name == branch && (res.BranchPolicies[0].Type == "branch" || res.BranchPolicies[0].Type == "") {
		o.add(ScopeGitHub, ItemDeploymentBranches, Environment, CheckOK, "", "デプロイできるブランチは、既定のブランチ ("+branch+") だけ")
		return
	}
	if len(res.BranchPolicies) == 0 {
		ng("デプロイできるブランチが 1 つも無い (ワークフローが environment を使えない)")
		return
	}
	ng(fmt.Sprintf("デプロイできるブランチ・タグが、既定のブランチ (%s) だけでない (%d 個の指定がある)", branch, max(len(res.BranchPolicies), res.TotalCount)))
}

// checkSecrets は、environment の秘密の名前 (names。大文字) を、この一式の使う名前と比べる。
func checkSecrets(o *CheckOutput, p Params, slug string, names []string) {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	want := map[string]bool{}
	for _, n := range SecretNames {
		want[n] = true
		if have[n] {
			o.add(ScopeGitHub, ItemSecret, n, CheckOK, "", "environment "+Environment+" に登録されている (値は読んでいない。正しいかは、試しの通知と試しの実行で確かめる)")
			continue
		}
		cmd := "gh secret set " + n + " --env " + Environment + " -R " + slug
		format, source := secretHelp(p, n)
		o.add(ScopeGitHub, ItemSecret, n, CheckNG, codes.RepoSecretMissing, "environment "+Environment+" に登録されていない", cmd)
		o.MissingSecrets = append(o.MissingSecrets, MissingSecret{Name: n, Environment: Environment, Command: cmd, ValueFormat: format, Source: source})
	}
	for _, n := range names {
		if want[n] {
			continue
		}
		o.add(ScopeGitHub, ItemSecretUnused, n, CheckWarn, codes.RepoSecretUnused,
			"この一式が使わない秘密が、environment "+Environment+" に残っている。消すのは、その名前を使うワークフローが main に残っていないことを確かめてから",
			"gh secret delete "+n+" --env "+Environment+" -R "+slug)
	}
}
