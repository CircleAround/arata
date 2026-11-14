// actionsgate は GitHub Actions の参照を確かめる CI 用の小さなツール (ADR 0017・0035)。
//
//	go run ./tools/actionsgate -days 7 -lock .github/workflows/actions.lock .github/workflows examples/audit-repo/.github/workflows
//
// 確かめること:
//   - すべての uses が 40 桁の SHA で固定され、版がコメントに書かれている。コンテナイメージは @sha256: で固定されている
//   - コメントの版のタグが、その SHA を指している (読む人が見る版と動く版が同じ)
//   - その版が公開から -days 日以上経っている。-lock があれば、ロックファイルの推移的な依存も同じく確かめる
//
// -offline は固定の検査だけを行い、通信しない (go test から使う)。
// 公開時刻はリリースの published_at、リリースが無いタグはコミットの時刻。トークンは GITHUB_TOKEN から読む。
// 終了コード: 0 = 問題なし、1 = 固定の漏れ・版の不一致・新しすぎる版がある、2 = 入力・通信のエラー (判定できないものは通さない)。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Use は 1 つの参照。Raw は固定されているかを判定する前の値。
type Use struct {
	File string
	Raw  string
	Repo string // owner/repo (action の中のパスは除く)
	Ref  string // @ の後
	Tag  string // コメントの版
	// Locked はロックファイルの依存。ref は v1 や main のように動いてよく、実行されるのは Ref の commit。
	// ロックファイルとの整合は `gh actions-lock --verify` が見るので、ここでは公開時刻だけを確かめる。
	Locked bool
}

var (
	usesLine = regexp.MustCompile(`^\s*(?:- )?uses:\s*['"]?([^'"\s#]+)['"]?\s*(?:#\s*(\S+))?`)
	fullSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	version  = regexp.MustCompile(`^v?\d+(\.\d+)*([-+.][0-9A-Za-z.-]+)?$`)
	image    = regexp.MustCompile(`^docker://[^@\s]+@sha256:[0-9a-f]{64}$`)
)

func main() {
	client := &http.Client{Timeout: 30 * time.Second}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now(), client, os.Getenv("GITHUB_TOKEN")))
}

func run(args []string, stdout, stderr io.Writer, now time.Time, client *http.Client, token string) int {
	fs := flag.NewFlagSet("actionsgate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	days := fs.Int("days", 7, "公開から最低これだけの日数が経った版だけを通す")
	api := fs.String("api", "https://api.github.com", "GitHub の REST API")
	lock := fs.String("lock", "", "ロックファイル。無ければ読み飛ばす")
	offline := fs.Bool("offline", false, "固定の検査だけを行い、通信しない")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *days < 0 || fs.NArg() == 0 {
		fmt.Fprintln(stderr, "actionsgate: -days は 0 以上で、ワークフローのディレクトリを 1 つ以上渡す")
		return 2
	}
	uses, err := scan(fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "actionsgate: %v\n", err)
		return 2
	}
	if len(uses) == 0 {
		fmt.Fprintf(stderr, "actionsgate: uses が 1 つも見つからない: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}

	code := 0
	var pinned []Use
	for _, u := range uses {
		if msg := pinProblem(u); msg != "" {
			fmt.Fprintf(stderr, "actionsgate: %s: %s: %s\n", u.File, u.Raw, msg)
			code = 1
		} else if u.Repo != "" {
			pinned = append(pinned, u)
		}
	}
	if *offline {
		if code == 0 {
			fmt.Fprintf(stdout, "actionsgate: %d uses ok (固定のみ検査)\n", len(uses))
		}
		return code
	}

	if *lock != "" {
		data, err := os.ReadFile(*lock)
		switch {
		case errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(stdout, "actionsgate: %s は無いので、推移的な依存は確かめない\n", *lock)
		case err != nil:
			fmt.Fprintf(stderr, "actionsgate: %v\n", err)
			return 2
		default:
			locked, err := parseLock(data)
			if err != nil {
				fmt.Fprintf(stderr, "actionsgate: %s: %v\n", *lock, err)
				return 2
			}
			pinned = append(pinned, locked...)
		}
	}

	g := github{base: strings.TrimRight(*api, "/"), client: client, token: token}
	minAge := time.Duration(*days) * 24 * time.Hour
	seen := map[string]bool{}
	ctx := context.Background()
	for _, u := range pinned {
		key := u.Repo + "@" + u.Ref + "#" + u.Tag
		if seen[key] {
			continue
		}
		seen[key] = true
		name := u.Repo + "@" + u.Tag
		commit, err := g.tagCommit(ctx, u.Repo, u.Tag)
		if err != nil && !(u.Locked && errors.Is(err, errNotFound)) {
			fmt.Fprintf(stderr, "actionsgate: %s: タグを解決できない: %v\n", name, err)
			code = 2
			continue
		}
		if commit != u.Ref && !u.Locked {
			fmt.Fprintf(stderr, "actionsgate: %s: %s のタグは %s を指している (uses は %s)\n", u.File, name, commit, u.Ref)
			if code == 0 {
				code = 1
			}
			continue
		}
		var at time.Time
		if commit == u.Ref {
			at, err = g.published(ctx, u.Repo, u.Tag, u.Ref)
		} else {
			at, err = g.commitTime(ctx, u.Repo, u.Ref)
		}
		if err != nil {
			fmt.Fprintf(stderr, "actionsgate: %s: 公開時刻を取れない: %v\n", name, err)
			code = 2
			continue
		}
		if age := now.Sub(at); age < minAge {
			fmt.Fprintf(stderr, "actionsgate: %s は %s 公開 (%.1f 日前)。%d 日経つまで使わない\n",
				name, at.UTC().Format(time.RFC3339), age.Hours()/24, *days)
			if code == 0 {
				code = 1
			}
		}
	}
	if code == 0 {
		fmt.Fprintf(stdout, "actionsgate: %d actions ok (固定済み、公開から %d 日以上)\n", len(seen), *days)
	}
	return code
}

// scan はディレクトリ直下の *.yml / *.yaml から uses を集める。
func scan(dirs []string) ([]Use, error) {
	var uses []Use
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if ext := filepath.Ext(e.Name()); e.IsDir() || (ext != ".yml" && ext != ".yaml") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			text, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			uses = append(uses, parseUses(path, string(text))...)
		}
	}
	return uses, nil
}

// parseUses は uses の行を読む。コメントの版は YAML の解析で失われるので、行として読む。
// 同じリポジトリの中の action (./ と $/) はワークフローと同じコミットなので対象にしない。
func parseUses(file, text string) []Use {
	var uses []Use
	for _, line := range strings.Split(text, "\n") {
		m := usesLine.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(m[1], "./") || strings.HasPrefix(m[1], "$/") {
			continue
		}
		u := Use{File: file, Raw: m[1], Tag: m[2]}
		if path, ref, ok := strings.Cut(m[1], "@"); ok && !strings.HasPrefix(m[1], "docker://") {
			u.Ref = ref
			if parts := strings.Split(path, "/"); len(parts) >= 2 {
				u.Repo = parts[0] + "/" + parts[1]
			}
		}
		uses = append(uses, u)
	}
	return uses
}

// pinProblem は固定の問題を返す。問題が無ければ空。
func pinProblem(u Use) string {
	if strings.HasPrefix(u.Raw, "docker://") {
		if image.MatchString(u.Raw) {
			return ""
		}
		return "イメージは @sha256: で固定する"
	}
	if u.Repo == "" || !fullSHA.MatchString(u.Ref) {
		return "40 桁の SHA で固定する"
	}
	if !version.MatchString(u.Tag) {
		return "版をコメントに書く (# vX.Y.Z)"
	}
	return ""
}

// parseLock は .github/workflows/actions.lock の dependencies を読む。
func parseLock(data []byte) ([]Use, error) {
	var doc struct {
		Dependencies map[string]struct {
			Ref    string `yaml:"ref"`
			Commit string `yaml:"commit"`
		} `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(doc.Dependencies))
	for k := range doc.Dependencies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var uses []Use
	for _, k := range keys {
		d := doc.Dependencies[k]
		path, _, ok := strings.Cut(k, "@")
		parts := strings.Split(path, "/")
		commit, sha1 := strings.CutPrefix(d.Commit, "sha1-")
		if !ok || len(parts) < 2 || !sha1 || !fullSHA.MatchString(commit) || d.Ref == "" {
			return nil, fmt.Errorf("読めない依存: %s", k)
		}
		uses = append(uses, Use{File: "actions.lock", Raw: k, Repo: parts[0] + "/" + parts[1], Ref: commit, Tag: d.Ref, Locked: true})
	}
	return uses, nil
}

type github struct {
	base   string
	client *http.Client
	token  string
}

var errNotFound = errors.New("見つからない")

func (g github) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	res, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s: %w", path, errNotFound)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(v)
}

// tagCommit はタグが指すコミットを返す。annotated tag は辿る。
func (g github) tagCommit(ctx context.Context, repo, tag string) (string, error) {
	var ref struct {
		Object struct{ Type, SHA string } `json:"object"`
	}
	if err := g.get(ctx, "/repos/"+repo+"/git/ref/tags/"+url.PathEscape(tag), &ref); err != nil {
		return "", err
	}
	for range 5 {
		if ref.Object.Type == "commit" {
			return ref.Object.SHA, nil
		}
		sha := ref.Object.SHA
		if err := g.get(ctx, "/repos/"+repo+"/git/tags/"+sha, &ref); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("%s: タグが深すぎる", tag)
}

// published はリリースの公開時刻を返す。リリースの無いタグはコミットの時刻を使う。
func (g github) published(ctx context.Context, repo, tag, commit string) (time.Time, error) {
	var rel struct {
		PublishedAt time.Time `json:"published_at"`
	}
	err := g.get(ctx, "/repos/"+repo+"/releases/tags/"+url.PathEscape(tag), &rel)
	if err == nil && !rel.PublishedAt.IsZero() {
		return rel.PublishedAt, nil
	}
	if err != nil && !errors.Is(err, errNotFound) {
		return time.Time{}, err
	}
	return g.commitTime(ctx, repo, commit)
}

func (g github) commitTime(ctx context.Context, repo, commit string) (time.Time, error) {
	var c struct {
		Committer struct {
			Date time.Time `json:"date"`
		} `json:"committer"`
	}
	if err := g.get(ctx, "/repos/"+repo+"/git/commits/"+commit, &c); err != nil {
		return time.Time{}, err
	}
	if c.Committer.Date.IsZero() {
		return time.Time{}, errors.New("時刻が空")
	}
	return c.Committer.Date, nil
}
