package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/repoinit"
)

// 例の値はすべて架空。repo check の引数は、repo init と同じ (書き出した README のコマンドの init を check に替える)。
func (c *cli) repoCheck(extra ...string) int {
	args := append([]string{"repo", "check"}, repoArgs[2:]...)
	return c.run(append(args, extra...)...)
}

func dropFlag(args []string, flag string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// 端末から打って、チャンネル ID が足りないときだけ、対話で聞く (ADR 0060)。答えは引数と同じ形で確かめ、通らなければ聞き直す。
func TestRepoInitAsksForChannelsOnATerminal(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	c.terminal = true
	// 知らせ → prod の通常用 (1 回目は名前を打った) → prod の緊急用 → staging の通常用 → staging の緊急用
	c.stdin = "C0123456782\nmy-channel-name\nC0123456789\nC0123456780\n  C0123456781  \nsame\n"
	args := dropFlag(dropFlag(dropFlag(repoArgs, "--alert-channel"), "--channel"), "--urgent-channel")
	if code := c.run(append(args, "--out", out)...); code != 0 {
		t.Fatalf("exit %d: %s%s", code, c.stdout, c.stderr)
	}
	for _, want := range []string{"知らせるチャンネル ID", "prod の通常用のチャンネル ID: ", "prod の緊急用のチャンネル ID", "staging の通常用", "チャンネル ID の形"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Errorf("the prompts lack %q:\n%s", want, c.stdout)
		}
	}
	// 打った値 (形の合わないもの) は写さない。標準エラーは JSON のログだけ (問いを混ぜない)
	if strings.Contains(c.stdout.String(), "my-channel-name") || c.stderr.Len() != 0 {
		t.Errorf("the prompt echoes the input, or writes to stderr:\n%s%s", c.stdout, c.stderr)
	}
	prod, _ := os.ReadFile(filepath.Join(out, "aws/prod/aratam.yaml"))
	staging, _ := os.ReadFile(filepath.Join(out, "aws/staging/aratam.yaml"))
	wf, _ := os.ReadFile(filepath.Join(out, ".github/workflows/arata-audit.yml"))
	if !strings.Contains(string(prod), `channel: "C0123456789"`) || !strings.Contains(string(prod), `urgent_channel: "C0123456780"`) ||
		!strings.Contains(string(staging), `channel: "C0123456781"`) || !strings.Contains(string(staging), `urgent_channel: ""`) ||
		!strings.Contains(string(wf), "ALERT_CHANNEL: C0123456782 ") {
		t.Fatalf("the answers are not written:\n%s\n%s", prod, staging)
	}
	// 答えを引数にした、同じコマンドを出す (次からは対話なしで打てる)
	want := "--alert-channel C0123456782 --channel prod=C0123456789,staging=C0123456781 --urgent-channel prod=C0123456780,staging=same --out " + out
	if !strings.Contains(c.stdout.String(), want) {
		t.Errorf("the equivalent command is missing (%s):\n%s", want, c.stdout)
	}
	// 引数で全部渡した結果と、1 バイトも違わない
	c2 := newCLI(t)
	out2 := filepath.Join(c2.dir, "repo")
	if code := c2.repo("--out", out2); code != 0 {
		t.Fatal(code)
	}
	for _, p := range []string{"aws/prod/aratam.yaml", "aws/staging/aratam.yaml", ".github/workflows/arata-audit.yml", "README.md"} {
		a, _ := os.ReadFile(filepath.Join(out, p))
		b, _ := os.ReadFile(filepath.Join(out2, p))
		if string(a) != string(b) {
			t.Errorf("%s differs between the answers and the arguments", p)
		}
	}

	// 2 回目 (aratam.yaml は既にある): 引数が揃っていれば聞かない。チャンネルの引数が無くても、既にあるアカウントは聞かない
	c.stdin = ""
	if code := c.run(append(dropFlag(dropFlag(repoArgs, "--channel"), "--urgent-channel"), "--out", out, "--force")...); code != 0 || strings.Contains(c.stdout.String(), "チャンネル ID: ") {
		t.Fatalf("existing accounts must not be asked: exit %d\n%s", code, c.stdout)
	}
	// 知らせを使わない (none) も、答えられる
	c3 := newCLI(t)
	c3.terminal, c3.stdin = true, "none\n"
	out3 := filepath.Join(c3.dir, "repo")
	if code := c3.run(append(dropFlag(repoArgs, "--alert-channel"), "--out", out3)...); code != 0 {
		t.Fatalf("exit %d: %s", code, c3.stderr)
	}
	if wf, _ := os.ReadFile(filepath.Join(out3, ".github/workflows/arata-audit.yml")); strings.Contains(string(wf), "chat.postMessage") {
		t.Error("none must not write the alert step")
	}
}

// 対話でも、既定で進まない: 入力が終わる・形の合う答えが無ければ、何も書かずに止まる。ほかの引数の誤りは、聞く前に出す。
func TestRepoInitInteractiveNeverFallsBackToADefault(t *testing.T) {
	withVersion(t, "v0.15.0")
	noChannels := dropFlag(dropFlag(dropFlag(repoArgs, "--alert-channel"), "--channel"), "--urgent-channel")
	for name, stdin := range map[string]string{
		"empty input":   "",
		"empty lines":   "\n\n\n\n\n\n\n\n\n\n",
		"never valid":   "a\nb\nc\nd\n",
		"stops halfway": "C0123456782\nC0123456789\n",
		"binary":        strings.Repeat("\x00", 4096),
	} {
		c := newCLI(t)
		c.terminal, c.stdin = true, stdin
		out := filepath.Join(c.dir, "repo")
		if code := c.run(append(append([]string{}, noChannels...), "--out", out)...); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Errorf("%s: exit %d %v", name, code, c.codes())
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: nothing may be written", name)
		}
	}
	// ほかの引数の誤りは、聞く前に出す
	c := newCLI(t)
	c.terminal, c.stdin = true, "C0123456782\n"
	bad := append(dropFlag(noChannels, "--region"), "--out", filepath.Join(c.dir, "repo"))
	if code := c.run(bad...); code != 2 || strings.Contains(c.stdout.String(), "チャンネル ID") {
		t.Fatalf("must fail before asking: exit %d\n%s", code, c.stdout)
	}
	// --diff は聞かない (何も書かない。引数が足りなければ止まる)
	c = newCLI(t)
	c.terminal, c.stdin = true, "C0123456782\n"
	if code := c.run(append(dropFlag(repoArgs, "--alert-channel"), "--out", filepath.Join(c.dir, "repo"), "--diff")...); code != 2 || strings.Contains(c.stdout.String(), "知らせるチャンネル") {
		t.Fatalf("--diff must not ask: exit %d\n%s", code, c.stdout)
	}
}

// 端末の判定は、標準ライブラリだけで行う。/dev/null・パイプ・ふつうのファイルは、端末ではない (CI や cron で聞かない)。
func TestIsTerminal(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	file, err := os.Open(filepath.Join("testdata", "root_help.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	closed, _ := os.Open(os.DevNull)
	closed.Close()
	for name, f := range map[string]*os.File{"/dev/null": null, "pipe": r, "file": file, "closed": closed, "nil": nil} {
		if isTerminal(f) {
			t.Errorf("%s must not be a terminal", name)
		}
	}
}

// repo check: 書き出したままの一式は通る (終了コード 0)。--github を付けなければ GitHub は読まず、skip の行を出す。
func TestRepoCheckPassesOnTheFreshSet(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatal(code)
	}
	if code := c.repoCheck("--out", out); code != 0 || len(c.codes()) != 0 {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	for _, want := range []string{"SCOPE", "workflow_secrets", "notify", "skip", "ng はありません"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, c.stdout)
		}
	}
	// チャンネルの引数は要らない (PR の検査のワークフローは、チャンネルを知らない)
	args := append([]string{"repo", "check"}, dropFlag(dropFlag(repoArgs[2:], "--channel"), "--urgent-channel")...)
	if code := c.run(append(args, "--out", out, "--format", "json")...); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	var got repoinit.CheckOutput
	schematest.Conforms(t, repoinit.CheckSchema, c.stdout.Bytes(), &got)
	if !got.OK || got.Schema != "repo-check" || got.SchemaVersion != 1 || got.MissingSecrets == nil || len(got.MissingSecrets) != 0 {
		t.Fatalf("%+v", got)
	}
	last := got.Rows[len(got.Rows)-1]
	if last.Scope != "github" || last.Status != "skip" {
		t.Fatalf("the last row must say that GitHub was not read: %+v", last)
	}
	// 書き出したワークフローの PR の検査は、この同じコマンドを流す
	wf, _ := os.ReadFile(filepath.Join(out, ".github/workflows/arata-check.yml"))
	if !strings.Contains(string(wf), "run: arata repo check --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 --out . </dev/null") {
		t.Errorf("arata-check.yml does not run repo check:\n%s", wf)
	}
	// 何も書かない
	before := snapshot(t, out)
	c.repoCheck("--out", out)
	if after := snapshot(t, out); before != after {
		t.Fatal("repo check must not write")
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %d %s\n", p, info.Size(), info.ModTime())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// ng があれば終了コード 2 で、行と同じ code を標準エラーのログにも出す (doctor と同じ)。
func TestRepoCheckReportsProblems(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatal(code)
	}
	// 生成物を手で直した + Webhook の方式の aratam.yaml を持ち込んだ
	wf := filepath.Join(out, ".github/workflows/arata-triage.yml")
	b, _ := os.ReadFile(wf)
	if err := os.WriteFile(wf, append(b, []byte("# edited\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	am := filepath.Join(out, "aws/prod/aratam.yaml")
	b, _ = os.ReadFile(am)
	s := strings.Replace(string(b), "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`, 1)
	s = strings.Replace(s, `channel: "C0123456789"`, `channel: ""`, 1)
	s = strings.Replace(s, `urgent_channel: "C0123456780"`, `urgent_channel: ""`, 1)
	s = strings.Replace(s, `webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ", 1)
	if err := os.WriteFile(am, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := c.repoCheck("--out", out); code != 2 || strings.Join(c.codes(), ",") != "REPO_SET_DIFFERS,REPO_NOTIFY_MISMATCH" {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	for _, want := range []string{"notify prod の直し方:", "  bot_token_env: ARATAM_SLACK_BOT_TOKEN\n", `  channel: "C0123456789"`, "--out . --force", "ng があります"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, c.stdout)
		}
	}
	if code := c.repoCheck("--out", out, "--format", "json"); code != 2 {
		t.Fatal(code)
	}
	var got repoinit.CheckOutput
	schematest.Conforms(t, repoinit.CheckSchema, c.stdout.Bytes(), &got)
	if got.OK {
		t.Fatalf("%+v", got)
	}
	// repo init --force は生成物を書き直すが、aratam.yaml は書き直さない。合わないことを、その場で知らせる (終了コード 2)
	if code := c.repo("--out", out, "--force"); code != 2 || strings.Join(c.codes(), ",") != "REPO_NOTIFY_MISMATCH" || !strings.Contains(c.stdout.String(), "notify prod の直し方:") {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	if b, _ := os.ReadFile(am); string(b) != s {
		t.Fatal("aratam.yaml must never be rewritten")
	}
	for name, args := range map[string][]string{
		"bad format": {"--out", out, "--format", "yaml"},
		"no out":     {},
		"bad owner":  {"--out", out, "--owner", "a/b"},
	} {
		if code := c.repoCheck(args...); code != 2 || !strings.Contains(strings.Join(c.codes(), ","), "CONFIG_INVALID") {
			t.Errorf("%s: exit %d %v", name, code, c.codes())
		}
	}
}

// githubStub は、repo check --github が読む API の偽物 (実際の GitHub には接続しない)。
type githubStub struct {
	mu      sync.Mutex
	calls   []string
	auth    []string
	secrets []string
}

func (g *githubStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, r.Method+" "+r.URL.Path)
	g.auth = append(g.auth, r.Header.Get("Authorization"))
	const repo = "/repos/example-org/security-audit"
	switch r.URL.Path {
	case repo:
		fmt.Fprint(w, `{"default_branch":"main"}`)
	case repo + "/environments/audit":
		fmt.Fprint(w, `{"protection_rules":[{"type":"branch_policy"}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`)
	case repo + "/environments/audit/deployment-branch-policies":
		fmt.Fprint(w, `{"total_count":1,"branch_policies":[{"name":"main","type":"branch"}]}`)
	case repo + "/environments/audit/secrets":
		var items []string
		for _, n := range g.secrets {
			items = append(items, fmt.Sprintf(`{"name":%q,"updated_at":"2026-01-02T00:00:00Z"}`, n))
		}
		fmt.Fprintf(w, `{"total_count":%d,"secrets":[%s]}`, len(items), strings.Join(items, ","))
	case repo + "/actions/secrets":
		fmt.Fprint(w, `{"total_count":0,"secrets":[]}`)
	default:
		http.NotFound(w, r)
	}
}

// 最初は秘密は未登録 → 足りない名前と登録のコマンドが出る (終了コード 2) → 登録したら、もう一度の check が通る (ADR 0060 の流れ)。
func TestRepoCheckGitHubFlow(t *testing.T) {
	withVersion(t, "v0.15.0")
	const token = "dummy-token-for-the-fake-api"
	stub := &githubStub{}
	srv := httptest.NewServer(stub)
	defer srv.Close()
	c := newCLI(t)
	c.githubURL, c.githubClient = srv.URL, srv.Client()
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatal(code)
	}
	if len(stub.calls) != 0 {
		t.Fatalf("repo init must not reach GitHub: %v", stub.calls)
	}
	// --github が無ければ、鍵があっても GitHub を読まない
	c.env = map[string]string{"GITHUB_TOKEN": token}
	if code := c.repoCheck("--out", out); code != 0 || len(stub.calls) != 0 {
		t.Fatalf("without --github nothing may be read: exit %d %v", code, stub.calls)
	}
	// 鍵が無ければ止まる (API は呼ばない)。gh は起動しない
	c.env = map[string]string{}
	if code := c.repoCheck("--out", out, "--github"); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" || !strings.Contains(c.stderr.String(), "GITHUB_TOKEN") || len(stub.calls) != 0 {
		t.Fatalf("exit %d %v %v", code, c.codes(), stub.calls)
	}
	c.env = map[string]string{"GITHUB_TOKEN": "a b"}
	if code := c.repoCheck("--out", out, "--github"); code != 2 || len(stub.calls) != 0 || strings.Contains(c.stderr.String(), "a b") {
		t.Fatalf("a malformed token must be refused without echoing it: exit %d", code)
	}

	c.env = map[string]string{"GITHUB_TOKEN": token + "\n"}
	if code := c.repoCheck("--out", out, "--github"); code != 2 || strings.Join(c.codes(), ",") != "REPO_SECRET_MISSING,REPO_SECRET_MISSING,REPO_SECRET_MISSING" {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	for _, want := range []string{
		"足りない秘密",
		"  gh secret set ARATA_RUNNER_ROLE_ARN --env audit -R example-org/security-audit\n",
		"  gh secret set ARATA_AUDIT_ROLE_ARNS --env audit -R example-org/security-audit\n",
		"  gh secret set ARATAM_SLACK_BOT_TOKEN --env audit -R example-org/security-audit\n",
		"値の形: arn:aws:iam::123456789012:role/arata-runner", "RunnerRoleArn", "xoxb-…",
	} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, c.stdout)
		}
	}
	if strings.Contains(c.stdout.String()+c.stderr.String(), token) {
		t.Fatal("the token must not be printed")
	}
	// GH_TOKEN でも読める。JSON には missing_secrets
	c.env = map[string]string{"GH_TOKEN": token}
	if code := c.repoCheck("--out", out, "--github", "--format", "json"); code != 2 {
		t.Fatal(code)
	}
	var got repoinit.CheckOutput
	schematest.Conforms(t, repoinit.CheckSchema, c.stdout.Bytes(), &got)
	if got.OK || len(got.MissingSecrets) != 3 || got.MissingSecrets[0].Command == "" || got.MissingSecrets[0].Environment != "audit" {
		t.Fatalf("%+v", got.MissingSecrets)
	}
	raw := map[string]any{}
	if err := json.Unmarshal(c.stdout.Bytes(), &raw); err != nil || raw["missing_secrets"] == nil {
		t.Fatalf("%v %v", err, raw)
	}

	// 出たコマンドで 3 つを登録した (ことにする) → もう一度の check は通る
	stub.secrets = []string{"ARATA_RUNNER_ROLE_ARN", "ARATA_AUDIT_ROLE_ARNS", "ARATAM_SLACK_BOT_TOKEN"}
	if code := c.repoCheck("--out", out, "--github"); code != 0 || len(c.codes()) != 0 || !strings.Contains(c.stdout.String(), "ng はありません") {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	// 使わなくなった秘密が残っている → warn だけなので終了コード 0。消すコマンドを出す
	stub.secrets = append(stub.secrets, "ARATAM_SLACK_WEBHOOK")
	if code := c.repoCheck("--out", out, "--github"); code != 0 || strings.Join(c.codes(), ",") != "REPO_SECRET_UNUSED" ||
		!strings.Contains(c.stdout.String(), "gh secret delete ARATAM_SLACK_WEBHOOK --env audit -R example-org/security-audit") {
		t.Fatalf("exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	// 読むだけ。鍵は毎回付く
	for i, call := range stub.calls {
		if !strings.HasPrefix(call, "GET ") || stub.auth[i] != "Bearer "+token {
			t.Fatalf("call %s (auth ok: %v)", call, stub.auth[i] == "Bearer "+token)
		}
	}
}

// 既にある aratam.yaml に、違うチャンネル ID を渡しても、書き直さない。黙って捨てずに、直す行を出す (ADR 0060)。
func TestRepoInitDoesNotRewriteTheChannelOfAnExistingAccount(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatal(code)
	}
	before, _ := os.ReadFile(filepath.Join(out, "aws/prod/aratam.yaml"))
	args := append([]string{}, repoArgs...)
	for i, a := range args {
		switch a {
		case "--channel":
			args[i+1] = "prod=C0AAAAAAAAA,staging=C0123456781"
		case "--urgent-channel":
			args[i+1] = "prod=same,staging=same"
		}
	}
	if code := c.run(append(args, "--out", out, "--force")...); code != 0 {
		t.Fatalf("exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if after, _ := os.ReadFile(filepath.Join(out, "aws/prod/aratam.yaml")); string(after) != string(before) {
		t.Fatal("aratam.yaml must never be rewritten")
	}
	for _, want := range []string{"aws/prod/aratam.yaml は既にあるので、書き直していません", `  channel: "C0AAAAAAAAA"`, `  urgent_channel: ""`} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Errorf("the report lacks %q:\n%s", want, c.stdout)
		}
	}
	// 同じ値のアカウント (staging) には、何も出さない
	if strings.Contains(c.stdout.String(), "aws/staging/aratam.yaml は既にある") {
		t.Errorf("an unchanged account must not be mentioned:\n%s", c.stdout)
	}
}

// カンマ区切りの引数 (--accounts・--channel・--urgent-channel) は、繰り返して渡してもよい。繰り返しは、つなげて受け取る。
// 最後の 1 つだけを残して、ほかを黙って捨てない (捨てると、「--channel prod が足りない」のような、打ったものと合わないエラーになる)。
func TestRepoListFlagsMayBeRepeated(t *testing.T) {
	withVersion(t, "v0.15.0")
	base := []string{"--owner", "example-org", "--repo", "security-audit", "--audit-account", "111122223333",
		"--store-bucket", "example-arata-store", "--region", "ap-northeast-1", "--alert-channel", "C0123456782"}
	comma := []string{"--accounts", "prod,staging", "--channel", "prod=C0123456789,staging=C0123456781", "--urgent-channel", "prod=C0123456780,staging=same"}
	forms := map[string][]string{
		"repeated": {"--accounts", "prod", "--accounts", "staging", "--channel", "prod=C0123456789", "--channel", "staging=C0123456781",
			"--urgent-channel", "prod=C0123456780", "--urgent-channel", "staging=same"},
		"mixed": {"--accounts", "prod,staging", "--channel", "prod=C0123456789", "--urgent-channel", "prod=C0123456780,staging=same", "--channel", "staging=C0123456781"},
		"equal sign": {"--accounts=prod", "--accounts=staging", "--channel=prod=C0123456789", "--channel=staging=C0123456781",
			"--urgent-channel=prod=C0123456780", "--urgent-channel=staging=same"},
	}
	c := newCLI(t)
	want := filepath.Join(c.dir, "comma")
	if code := c.run(append(append([]string{"repo", "init"}, append(base, comma...)...), "--out", want)...); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	files := []string{"aws/prod/aratam.yaml", "aws/staging/aratam.yaml", ".github/workflows/arata-audit.yml", ".github/workflows/arata-check.yml", "README.md"}
	for name, args := range forms {
		out := filepath.Join(c.dir, strings.ReplaceAll(name, " ", "-"))
		if code := c.run(append(append([]string{"repo", "init"}, append(base, args...)...), "--out", out)...); code != 0 {
			t.Fatalf("%s: exit %d: %s", name, code, c.stderr)
		}
		for _, p := range files {
			a, _ := os.ReadFile(filepath.Join(want, p))
			b, err := os.ReadFile(filepath.Join(out, p))
			if err != nil || string(a) != string(b) {
				t.Errorf("%s: %s differs from the comma form (%v)", name, p, err)
			}
		}
		// repo check と --diff も、同じ引数の形で通る
		if code := c.run(append(append([]string{"repo", "check"}, append(base, args...)...), "--out", out)...); code != 0 {
			t.Errorf("%s: repo check exit %d\n%s", name, code, c.stdout)
		}
		if code := c.run(append(append([]string{"repo", "init"}, append(base, args...)...), "--out", out, "--diff")...); code != 0 {
			t.Errorf("%s: --diff exit %d\n%s", name, code, c.stdout)
		}
	}
	// 繰り返しで同じアカウントを 2 度書いたら、片方を選ばずに止める (どちらの値かを決めつけない)。空の項目も止める
	for name, args := range map[string][]string{
		"account twice":        {"--accounts", "prod", "--accounts", "prod", "--channel", "prod=C0123456789", "--urgent-channel", "prod=same"},
		"channel twice":        {"--accounts", "prod", "--channel", "prod=C0123456789", "--channel", "prod=C0AAAAAAAAA", "--urgent-channel", "prod=same"},
		"urgent twice":         {"--accounts", "prod", "--channel", "prod=C0123456789", "--urgent-channel", "prod=same", "--urgent-channel", "prod=C0123456780"},
		"empty repeated value": {"--accounts", "prod", "--accounts", "", "--channel", "prod=C0123456789", "--urgent-channel", "prod=same"},
		"empty channel item":   {"--accounts", "prod", "--channel", "prod=C0123456789", "--channel", "", "--urgent-channel", "prod=same"},
	} {
		out := filepath.Join(c.dir, "bad-"+strings.ReplaceAll(name, " ", "-"))
		if code := c.run(append(append([]string{"repo", "init"}, append(base, args...)...), "--out", out)...); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Errorf("%s: exit %d %v", name, code, c.codes())
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: nothing may be written", name)
		}
	}
}
