package repoinit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/aratamscaffold"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/notify"
)

// checkSet は見本の引数の一式を一時ディレクトリに書き、ファイルの検査を流す関数を返す。
func checkSet(t *testing.T) (dir string, p Params, run func() *CheckOutput) {
	t.Helper()
	dir = writeSet(t)
	p = exampleParams()
	return dir, p, func() *CheckOutput {
		t.Helper()
		o := NewCheck()
		if err := CheckFiles(o, dir, p, mustFiles(t, p)); err != nil {
			t.Fatal(err)
		}
		return o
	}
}

func rowsOf(o *CheckOutput, item, status string) []CheckRow {
	var out []CheckRow
	for _, r := range o.Rows {
		if r.Item == item && r.Status == status {
			out = append(out, r)
		}
	}
	return out
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func edit(t *testing.T, path, old, new string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(old)) {
		t.Fatalf("%s lacks %q", path, old)
	}
	mustWrite(t, path, strings.Replace(string(b), old, new, 1))
}

func TestCheckSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: CheckSchema, Version: CheckSchemaVersion, Type: CheckOutput{}, Versioned: true,
		Description: "arata repo check --format json の出力。監査を回すリポジトリの一式 (手元のファイル) と、--github を付けたときは GitHub の environment と秘密の名前を、読むだけで確かめた結果"}, *update)
}

// 書き出したままの一式は、ファイルの検査をすべて通る。行は JSON のスキーマに合う。
func TestCheckFilesPassesOnTheFreshSet(t *testing.T) {
	_, _, run := checkSet(t)
	o := run()
	if !o.OK || o.Problems() {
		t.Fatalf("the fresh set must pass: %+v", o.Rows)
	}
	for _, item := range []string{ItemFiles, ItemTerraform, ItemWorkflowSecrets} {
		if len(rowsOf(o, item, CheckOK)) != 1 {
			t.Errorf("want one ok row for %s: %+v", item, o.Rows)
		}
	}
	for _, item := range []string{ItemNotify, ItemAccounts} {
		if len(rowsOf(o, item, CheckOK)) != 2 {
			t.Errorf("want an ok row per account for %s: %+v", item, o.Rows)
		}
	}
	for _, r := range o.Rows {
		if r.Scope != ScopeFiles || r.Code != "" {
			t.Errorf("row %+v", r)
		}
	}
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	schematest.Matches(t, CheckSchema, b)
	if len(o.MissingSecrets) != 0 || !bytes.Contains(b, []byte(`"missing_secrets":[]`)) {
		t.Errorf("missing_secrets must be an empty list without --github: %s", b)
	}
}

// 生成物の違い・無いファイル・残りもの (古いスクリプト、秘密の箱、手で作った .tf) は ng。
func TestCheckFilesReportsDifferences(t *testing.T) {
	dir, _, run := checkSet(t)
	edit(t, filepath.Join(dir, workflowPaths[0]), "ARATA_VERSION: v0.15.0", "ARATA_VERSION: v0.14.0")
	if err := os.Remove(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, ".github/scripts/arata-secret-check.sh"), "#!/bin/sh\n")
	mustWrite(t, filepath.Join(dir, "github/secrets/main.tf"), "# box\n")
	mustWrite(t, filepath.Join(dir, "github/extra.tf"), "# mine\n")
	edit(t, filepath.Join(dir, "github/main.tf"), `allow_forking = false`, `allow_forking = true`)
	o := run()
	if o.OK {
		t.Fatal("must not be ok")
	}
	got := map[string]string{}
	for _, r := range o.Rows {
		if r.Status == CheckNG {
			if r.Code != "REPO_SET_DIFFERS" || r.Detail == "" {
				t.Errorf("row %+v", r)
			}
			got[r.Target] = r.Item
		}
	}
	want := map[string]string{
		workflowPaths[0]: ItemFiles, ".gitignore": ItemFiles, ".github/scripts/arata-secret-check.sh": ItemFiles,
		"github/secrets/main.tf": ItemTerraform, "github/extra.tf": ItemTerraform, "github/main.tf": ItemTerraform,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	// 直し方は、同じ引数の --force (チャンネルは入らない)
	for _, r := range rowsOf(o, ItemFiles, CheckNG) {
		if r.Target == workflowPaths[0] && (len(r.Fix) != 1 || !strings.HasPrefix(r.Fix[0], "arata repo init --owner example-org ") || !strings.HasSuffix(r.Fix[0], " --out . --force")) {
			t.Errorf("fix: %v", r.Fix)
		}
	}
	// 秘密の箱の残りには、消してよいことを書く
	for _, r := range rowsOf(o, ItemTerraform, CheckNG) {
		if r.Target == "github/secrets/main.tf" && !strings.Contains(r.Detail, "秘密の箱") {
			t.Errorf("detail: %s", r.Detail)
		}
	}
	// aws/ の中身を育てても、差にしない
	dir2, _, run2 := checkSet(t)
	edit(t, filepath.Join(dir2, "aws/prod/aratam.yaml"), `channel: "C0123456789"`, `channel: "C0999999999"`)
	mustWrite(t, filepath.Join(dir2, "aws/prod/arata.yaml"), "name: grown\n")
	if o := run2(); !o.OK {
		t.Fatalf("growing aws/ (and changing the channel) must pass: %+v", o.Rows)
	}
}

// ワークフローが参照する秘密は 3 つだけ。足す・減らす・名前を式で作る、は ng。
func TestCheckWorkflowSecrets(t *testing.T) {
	dir, _, run := checkSet(t)
	// この一式に無いワークフロー (arata- で始まる) が、Webhook の秘密と、式で作った名前を使っている
	mustWrite(t, filepath.Join(dir, ".github/workflows/arata-extra.yml"), `name: extra
on: workflow_dispatch
jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - run: echo
        env:
          A: ${{ secrets.ARATAM_SLACK_WEBHOOK }}
          B: ${{ secrets[format('X_{0}', matrix.account)] }}
          # C: ${{ secrets.COMMENTED_OUT }}
`)
	// arata- で始まらないワークフローは見ない
	mustWrite(t, filepath.Join(dir, ".github/workflows/ci.yml"), "name: ci\non: push\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo\n        env:\n          A: ${{ secrets.OTHER }}\n")
	o := run()
	var targets []string
	for _, r := range rowsOf(o, ItemWorkflowSecrets, CheckNG) {
		targets = append(targets, r.Target)
	}
	sort.Strings(targets)
	if strings.Join(targets, ",") != ".github/workflows/arata-extra.yml,ARATAM_SLACK_WEBHOOK" {
		t.Fatalf("workflow_secrets ng rows: %v", targets)
	}
	// 使う秘密を参照しなくなった
	dir, _, run = checkSet(t)
	edit(t, filepath.Join(dir, workflowPaths[0]), "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}", "''")
	edit(t, filepath.Join(dir, workflowPaths[0]), "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}", "''")
	edit(t, filepath.Join(dir, workflowPaths[2]), "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}", "''")
	edit(t, filepath.Join(dir, workflowPaths[2]), "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}", "''")
	rows := rowsOf(run(), ItemWorkflowSecrets, CheckNG)
	if len(rows) != 1 || rows[0].Target != "ARATAM_SLACK_BOT_TOKEN" {
		t.Fatalf("%+v", rows)
	}
	// YAML でないワークフロー
	dir, _, run = checkSet(t)
	mustWrite(t, filepath.Join(dir, ".github/workflows/arata-broken.yml"), "a: [\n")
	if rows := rowsOf(run(), ItemWorkflowSecrets, CheckNG); len(rows) != 1 || rows[0].Target != ".github/workflows/arata-broken.yml" {
		t.Fatalf("%+v", rows)
	}
}

func TestWorkflowSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		dynamic, bad     bool
	}{
		{"expression", "a: ${{ secrets.FOO }}\nb: x ${{ github.x && secrets.Bar_1 || '' }} y", "BAR_1,FOO", false, false},
		{"case and spaces", "a: ${{ SECRETS . foo }}", "FOO", false, false},
		{"comment", "a: 1 # ${{ secrets.FOO }}\n# b: ${{ secrets.BAR }}", "", false, false},
		{"outside an expression", "run: echo secrets.FOO and secrets[x]", "", false, false},
		{"index", "a: ${{ secrets[matrix.name] }}", "", true, false},
		{"toJSON", "a: ${{ toJSON(secrets) }}", "", true, false},
		{"both", "a: ${{ secrets.FOO }} ${{ secrets['BAR'] }}", "FOO", true, false},
		{"inherit", "jobs:\n  x:\n    uses: ./.github/workflows/y.yml\n    secrets: inherit", "", true, false},
		{"alias", "a: &v ${{ secrets.FOO }}\nb: *v", "FOO", false, false},
		{"not yaml", "a: [", "", false, true},
		{"empty", "", "", false, false},
	} {
		names, dynamic, err := WorkflowSecrets([]byte(tc.body))
		if (err != nil) != tc.bad || strings.Join(names, ",") != tc.want || dynamic != tc.dynamic {
			t.Errorf("%s: %v %v %v", tc.name, names, dynamic, err)
		}
	}
	if _, _, err := WorkflowSecrets(bytes.Repeat([]byte("a"), maxExisting+1)); err == nil {
		t.Error("a huge workflow must be refused")
	}
}

// aratam.yaml が bot トークンの方式でなければ ng で、slack の節に書く行をそのまま貼れる形で出す (ADR 0060)。
func TestCheckNotify(t *testing.T) {
	dir, p, run := checkSet(t)
	prod := filepath.Join(dir, "aws/prod/aratam.yaml")
	// Webhook の方式の aratam.yaml を持ち込んだ
	edit(t, prod, "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`)
	edit(t, prod, `channel: "C0123456789"`, `channel: ""`)
	edit(t, prod, `urgent_channel: "C0123456780"`, `urgent_channel: ""`)
	edit(t, prod, `webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ")
	o := run()
	rows := rowsOf(o, ItemNotify, CheckNG)
	if o.OK || len(rows) != 1 || rows[0].Target != "prod" || rows[0].Code != "REPO_NOTIFY_MISMATCH" {
		t.Fatalf("%+v", o.Rows)
	}
	// --channel を渡していれば、その ID を行に出す (見本の引数は prod=C0123456789)
	want := []string{`webhook_env: ""`, `urgent_webhook_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `channel: "C0123456789"`}
	if strings.Join(rows[0].Fix, "\n") != strings.Join(want, "\n") {
		t.Fatalf("fix:\n%s", strings.Join(rows[0].Fix, "\n"))
	}
	if len(rowsOf(o, ItemNotify, CheckOK)) != 1 {
		t.Error("staging must stay ok")
	}
	// 渡していなければ (PR の検査の arata repo check は、チャンネルを知らない)、書く場所だけを示す
	p.Channels, p.UrgentChannels = nil, nil
	o = NewCheck()
	if err := CheckFiles(o, dir, p, mustFiles(t, p)); err != nil {
		t.Fatal(err)
	}
	if rows := rowsOf(o, ItemNotify, CheckNG); len(rows) != 1 || rows[0].Fix[3] != `channel: "<チャンネル ID (例 C0123456789)>"` {
		t.Fatalf("%+v", rows)
	}
	p.Channels = map[string]string{"prod": "C0AAAAAAAAA"}
	o = NewCheck()
	if err := CheckFiles(o, dir, p, mustFiles(t, p)); err != nil {
		t.Fatal(err)
	}
	if rows := rowsOf(o, ItemNotify, CheckNG); len(rows) != 1 || rows[0].Fix[3] != `channel: "C0AAAAAAAAA"` {
		t.Fatalf("%+v", rows)
	}
	var text bytes.Buffer
	if err := WriteCheck(&text, o); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"notify prod の直し方:", "  bot_token_env: ARATAM_SLACK_BOT_TOKEN\n", "ng があります"} {
		if !strings.Contains(text.String(), s) {
			t.Errorf("table lacks %q:\n%s", s, text.String())
		}
	}

	// ほかの外れ方: 環境変数の名前を変えた / Webhook の項目が残っている (aratam も設定エラーにする) / YAML でない / 無い
	for name, change := range map[string]func(path string){
		"renamed env": func(path string) { edit(t, path, "bot_token_env: ARATAM_SLACK_BOT_TOKEN", "bot_token_env: MY_TOKEN") },
		"webhook left": func(path string) {
			edit(t, path, `urgent_webhook_env: "" `, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ")
		},
		"not yaml":      func(path string) { mustWrite(t, path, "slack: [\n") },
		"slack missing": func(path string) { mustWrite(t, path, "name: prod\n") },
	} {
		dir, _, run := checkSet(t)
		change(filepath.Join(dir, "aws/prod/aratam.yaml"))
		if o := run(); o.OK || len(rowsOf(o, ItemNotify, CheckNG)) != 1 {
			t.Errorf("%s: %+v", name, o.Rows)
		}
	}
	// 既にあるチャンネル ID は、直す行にそのまま使う (環境変数の名前だけが違うとき)
	dir, _, run = checkSet(t)
	edit(t, filepath.Join(dir, "aws/prod/aratam.yaml"), "bot_token_env: ARATAM_SLACK_BOT_TOKEN", "bot_token_env: MY_TOKEN")
	if rows := rowsOf(run(), ItemNotify, CheckNG); len(rows) != 1 || rows[0].Fix[3] != `channel: "C0123456789"` {
		t.Fatalf("%+v", rows)
	}
	// アカウントの設定が無い
	dir, _, run = checkSet(t)
	if err := os.Remove(filepath.Join(dir, "aws/staging/aratam.yaml")); err != nil {
		t.Fatal(err)
	}
	o = run()
	if rows := rowsOf(o, ItemAccounts, CheckNG); o.OK || len(rows) != 1 || rows[0].Target != "aws/staging/aratam.yaml" {
		t.Fatalf("%+v", o.Rows)
	}
}

// ---- GitHub の検査 (偽の API。実際の GitHub には接続しない) ----

// fakeGitHub は、arata repo check --github が読む GitHub の API だけを持つ偽のサーバー。呼ばれた要求をすべて記録する。
type fakeGitHub struct {
	mu          sync.Mutex
	calls       []string // "METHOD path?query"
	auth        []string
	status      map[string]int // path → 返す状態 (既定は 200)
	branch      string
	environment string // environments/audit の応答の本文。空なら 404
	policies    string
	envSecrets  []string
	repoSecrets []string
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{
		status:      map[string]int{},
		branch:      "main",
		environment: `{"name":"audit","protection_rules":[{"id":1,"type":"branch_policy"}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`,
		policies:    `{"total_count":1,"branch_policies":[{"id":1,"name":"main","type":"branch"}]}`,
		envSecrets:  append([]string{}, SecretNames...),
	}
}

func secretsBody(names []string, page int) string {
	lo := min((page-1)*gitHubPerPage, len(names))
	hi := min(lo+gitHubPerPage, len(names))
	var items []string
	for _, n := range names[lo:hi] {
		b, _ := json.Marshal(n)
		// GitHub は名前と日時だけを返す。値は返さない
		items = append(items, `{"name":`+string(b)+`,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}`)
	}
	return fmt.Sprintf(`{"total_count":%d,"secrets":[%s]}`, len(names), strings.Join(items, ","))
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if s, ok := f.status[r.URL.Path]; ok {
		http.Error(w, `{"message":"secret-looking response body that must not be printed"}`, s)
		return
	}
	page := 1
	fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
	const repo = "/repos/example-org/security-audit"
	switch r.URL.Path {
	case repo:
		b, _ := json.Marshal(f.branch)
		fmt.Fprintf(w, `{"name":"security-audit","default_branch":%s,"private":true}`, b)
	case repo + "/environments/audit":
		if f.environment == "" {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		fmt.Fprint(w, f.environment)
	case repo + "/environments/audit/deployment-branch-policies":
		fmt.Fprint(w, f.policies)
	case repo + "/environments/audit/secrets":
		fmt.Fprint(w, secretsBody(f.envSecrets, page))
	case repo + "/actions/secrets":
		fmt.Fprint(w, secretsBody(f.repoSecrets, page))
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

const fakeToken = "dummy-token-for-the-fake-api"

// checkGitHub は、偽の API に向けて GitHub の検査を流す。読むだけであること・鍵を出力に写さないことを、毎回確かめる。
func checkGitHub(t *testing.T, f *fakeGitHub) *CheckOutput {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	o := NewCheck()
	CheckGitHub(context.Background(), o, GitHub{Client: srv.Client(), BaseURL: srv.URL, Token: fakeToken}, exampleParams())
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("repo check must only read: %s", c)
		}
		if f.auth[i] != "Bearer "+fakeToken {
			t.Fatalf("call without the token: %s", c)
		}
		// 値を返す API・書き込みの準備の API (公開鍵) を呼ばない
		if strings.Contains(c, "public-key") || strings.Contains(c, "/secrets/") {
			t.Fatalf("repo check must only list names: %s", c)
		}
	}
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	schematest.Matches(t, CheckSchema, b)
	var text bytes.Buffer
	if err := WriteCheck(&text, o); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{string(b), text.String()} {
		if strings.Contains(out, fakeToken) || strings.Contains(out, "secret-looking response body") || strings.Contains(out, "2026-01-0") {
			t.Fatalf("the output carries the token, a response body or a timestamp:\n%s", out)
		}
	}
	for _, r := range o.Rows {
		if r.Scope != ScopeGitHub || (r.Status != CheckOK) == (r.Code == "") {
			t.Errorf("row %+v", r)
		}
	}
	return o
}

// 揃っているリポジトリは、すべて ok。呼ぶのは決まった 5 つの GET だけ。
func TestCheckGitHubPasses(t *testing.T) {
	f := newFakeGitHub()
	o := checkGitHub(t, f)
	if !o.OK || len(o.MissingSecrets) != 0 {
		t.Fatalf("%+v", o.Rows)
	}
	if len(rowsOf(o, ItemSecret, CheckOK)) != 3 || len(rowsOf(o, ItemEnvironment, CheckOK)) != 1 || len(rowsOf(o, ItemDeploymentBranches, CheckOK)) != 1 ||
		len(rowsOf(o, ItemEnvironmentProtected, CheckOK)) != 1 || len(rowsOf(o, ItemRepositorySecret, CheckOK)) != 1 {
		t.Fatalf("%+v", o.Rows)
	}
	want := []string{
		"GET /repos/example-org/security-audit",
		"GET /repos/example-org/security-audit/environments/audit",
		"GET /repos/example-org/security-audit/environments/audit/deployment-branch-policies?per_page=100",
		"GET /repos/example-org/security-audit/environments/audit/secrets?per_page=100&page=1",
		"GET /repos/example-org/security-audit/actions/secrets?per_page=100&page=1",
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(f.calls, "\n"))
	}
}

// 最初は、秘密は 1 つも登録されていない。足りない名前ごとに、そのまま打てるコマンドと、値の形・取得元を出す。
func TestCheckGitHubListsMissingSecretsWithCommands(t *testing.T) {
	f := newFakeGitHub()
	f.envSecrets = nil
	o := checkGitHub(t, f)
	if o.OK || len(rowsOf(o, ItemSecret, CheckNG)) != 3 || len(o.MissingSecrets) != 3 {
		t.Fatalf("%+v", o.Rows)
	}
	got := map[string]MissingSecret{}
	for _, m := range o.MissingSecrets {
		got[m.Name] = m
		if m.Environment != "audit" || m.Command != "gh secret set "+m.Name+" --env audit -R example-org/security-audit" || m.Source == "" {
			t.Errorf("%+v", m)
		}
	}
	if got["ARATA_RUNNER_ROLE_ARN"].ValueFormat != "arn:aws:iam::123456789012:role/arata-runner" || !strings.Contains(got["ARATA_RUNNER_ROLE_ARN"].Source, "RunnerRoleArn") ||
		got["ARATA_AUDIT_ROLE_ARNS"].ValueFormat != `{"prod": "arn:aws:iam::123456789012:role/arata-readonly", "staging": "arn:aws:iam::123456789012:role/arata-readonly"}` ||
		got["ARATAM_SLACK_BOT_TOKEN"].ValueFormat != "xoxb-…" {
		t.Fatalf("%+v", got)
	}
	for _, r := range rowsOf(o, ItemSecret, CheckNG) {
		if r.Code != "REPO_SECRET_MISSING" || len(r.Fix) != 1 || r.Fix[0] != got[r.Target].Command {
			t.Errorf("%+v", r)
		}
	}
	var text bytes.Buffer
	_ = WriteCheck(&text, o)
	for _, s := range []string{"  gh secret set ARATA_RUNNER_ROLE_ARN --env audit -R example-org/security-audit\n", "値の形: xoxb-…", "取得元: ", "ng があります"} {
		if !strings.Contains(text.String(), s) {
			t.Errorf("table lacks %q:\n%s", s, text.String())
		}
	}
	// 1 つ登録すると、残りの 2 つだけが出る
	f = newFakeGitHub()
	f.envSecrets = []string{"ARATA_RUNNER_ROLE_ARN"}
	if o := checkGitHub(t, f); len(o.MissingSecrets) != 2 || len(rowsOf(o, ItemSecret, CheckOK)) != 1 {
		t.Fatalf("%+v", o.MissingSecrets)
	}
}

// 要らない秘密 (Webhook など) は warn で、消すコマンドを出す。リポジトリの側の秘密は、この一式の名前なら ng。
func TestCheckGitHubUnusedAndRepositorySecrets(t *testing.T) {
	f := newFakeGitHub()
	f.envSecrets = append(f.envSecrets, "ARATAM_SLACK_WEBHOOK", "ARATA_ALERT_WEBHOOK")
	f.repoSecrets = []string{"ARATA_RUNNER_ROLE_ARN", "ARATAM_SLACK_URGENT_WEBHOOK", "SOMETHING_ELSE"}
	o := checkGitHub(t, f)
	unused := rowsOf(o, ItemSecretUnused, CheckWarn)
	if len(unused) != 2 || unused[0].Code != "REPO_SECRET_UNUSED" || unused[0].Fix[0] != "gh secret delete ARATAM_SLACK_WEBHOOK --env audit -R example-org/security-audit" || !strings.Contains(unused[0].Detail, "main") {
		t.Fatalf("%+v", unused)
	}
	ng, warn := rowsOf(o, ItemRepositorySecret, CheckNG), rowsOf(o, ItemRepositorySecret, CheckWarn)
	if o.OK || len(ng) != 2 || len(warn) != 1 || warn[0].Target != "SOMETHING_ELSE" || ng[0].Code != "REPO_SECRET_OUTSIDE_ENVIRONMENT" ||
		ng[1].Fix[0] != "gh secret delete ARATA_RUNNER_ROLE_ARN -R example-org/security-audit" {
		t.Fatalf("%+v\n%+v", ng, warn)
	}
	// warn だけなら ok (終了コード 0)
	f = newFakeGitHub()
	f.envSecrets = append(f.envSecrets, "ARATAM_SLACK_WEBHOOK")
	f.repoSecrets = []string{"SOMETHING_ELSE"}
	if o := checkGitHub(t, f); !o.OK || o.Problems() {
		t.Fatalf("warnings alone must not fail: %+v", o.Rows)
	}
}

// environment が無い・デプロイできるブランチが開いている・レビュー担当が付いている。
func TestCheckGitHubEnvironment(t *testing.T) {
	f := newFakeGitHub()
	f.environment = ""
	o := checkGitHub(t, f)
	if rows := rowsOf(o, ItemEnvironment, CheckNG); o.OK || len(rows) != 1 || rows[0].Code != "REPO_ENVIRONMENT_MISSING" || len(o.MissingSecrets) != 3 {
		t.Fatalf("%+v", o.Rows)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "/environments/audit/") {
			t.Errorf("must not read under a missing environment: %s", c)
		}
	}
	for name, tc := range map[string]struct{ env, policies, branch string }{
		"all branches":       {`{"deployment_branch_policy":null}`, "", "main"},
		"no policy key":      {`{}`, "", "main"},
		"protected branches": {`{"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}`, "", "main"},
		"two branches":       {"", `{"total_count":2,"branch_policies":[{"name":"main","type":"branch"},{"name":"release/*","type":"branch"}]}`, "main"},
		"another branch":     {"", `{"total_count":1,"branch_policies":[{"name":"develop","type":"branch"}]}`, "main"},
		"a tag":              {"", `{"total_count":1,"branch_policies":[{"name":"main","type":"tag"}]}`, "main"},
		"wildcard":           {"", `{"total_count":1,"branch_policies":[{"name":"*","type":"branch"}]}`, "main"},
		"no policies":        {"", `{"total_count":0,"branch_policies":[]}`, "main"},
		"hidden second page": {"", `{"total_count":150,"branch_policies":[{"name":"main","type":"branch"}]}`, "main"},
		"odd default branch": {"", "", "ma in\n"},
	} {
		f := newFakeGitHub()
		if tc.env != "" {
			f.environment = tc.env
		}
		if tc.policies != "" {
			f.policies = tc.policies
		}
		f.branch = tc.branch
		o := checkGitHub(t, f)
		if rows := rowsOf(o, ItemDeploymentBranches, CheckNG); o.OK || len(rows) != 1 || rows[0].Code != "REPO_ENVIRONMENT_OPEN" || !strings.Contains(rows[0].Fix[0], "terraform -chdir=github apply") {
			t.Errorf("%s: %+v", name, o.Rows)
		}
	}
	// 既定のブランチが main でなくても、そのブランチ 1 つなら ok
	f = newFakeGitHub()
	f.branch, f.policies = "trunk", `{"total_count":1,"branch_policies":[{"name":"trunk","type":"branch"}]}`
	if o := checkGitHub(t, f); !o.OK {
		t.Fatalf("%+v", o.Rows)
	}
	f = newFakeGitHub()
	f.environment = `{"protection_rules":[{"type":"required_reviewers"},{"type":"wait_timer","wait_timer":30},{"type":"branch_policy"}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`
	o = checkGitHub(t, f)
	if rows := rowsOf(o, ItemEnvironmentProtected, CheckWarn); !o.OK || len(rows) != 1 || rows[0].Code != "REPO_ENVIRONMENT_PROTECTED" {
		t.Fatalf("%+v", o.Rows)
	}
}

// API の失敗は、その項目の ng。応答の本文は出さない (checkGitHub が確かめる)。
func TestCheckGitHubAPIFailures(t *testing.T) {
	const repo = "/repos/example-org/security-audit"
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusFound} {
		f := newFakeGitHub()
		f.status[repo] = status
		o := checkGitHub(t, f)
		if rows := rowsOf(o, ItemGitHub, CheckNG); o.OK || len(rows) != 1 || rows[0].Code != "GITHUB_API_FAILED" || len(o.Rows) != 1 || len(f.calls) != 1 {
			t.Errorf("%d: %+v %v", status, o.Rows, f.calls)
		}
	}
	for path, item := range map[string]string{
		repo + "/environments/audit":                            ItemEnvironment,
		repo + "/environments/audit/deployment-branch-policies": ItemDeploymentBranches,
		repo + "/environments/audit/secrets":                    ItemSecret,
		repo + "/actions/secrets":                               ItemRepositorySecret,
	} {
		f := newFakeGitHub()
		f.status[path] = http.StatusForbidden
		o := checkGitHub(t, f)
		if rows := rowsOf(o, item, CheckNG); o.OK || len(rows) != 1 || rows[0].Code != "GITHUB_API_FAILED" {
			t.Errorf("%s: %+v", path, o.Rows)
		}
		// 秘密の一覧を読めなかったときに、「足りない」とは言わない
		if strings.HasSuffix(path, "/environments/audit/secrets") && len(o.MissingSecrets) != 0 {
			t.Errorf("an unreadable list must not be reported as missing secrets: %+v", o.MissingSecrets)
		}
	}
}

// 応答は信用しない: 名前は形の合うものだけを運び、ページは上限まで、リダイレクトは追わない。
func TestCheckGitHubDoesNotTrustTheResponse(t *testing.T) {
	f := newFakeGitHub()
	f.envSecrets = append(f.envSecrets, "ok_lower", "BAD NAME; rm -rf /", "$(id)", "A\nB", strings.Repeat("A", 300))
	o := checkGitHub(t, f)
	unused := rowsOf(o, ItemSecretUnused, CheckWarn)
	var targets []string
	for _, r := range unused {
		targets = append(targets, r.Target)
		for _, l := range r.Fix {
			if strings.ContainsAny(l, ";$\n()") {
				t.Errorf("a command carries an unsafe name: %q", l)
			}
		}
	}
	// 小文字の名前は大文字にそろえる。形の合わない 4 つは、数だけを出す
	if strings.Join(targets, ",") != "OK_LOWER," || !strings.Contains(unused[len(unused)-1].Detail, "4 個") {
		t.Fatalf("%v %+v", targets, unused)
	}
	// 1,000 個を超える一覧は、途中でやめる
	f = newFakeGitHub()
	for i := 0; i < maxGitHubPages*gitHubPerPage+50; i++ {
		f.repoSecrets = append(f.repoSecrets, fmt.Sprintf("S_%04d", i))
	}
	o = checkGitHub(t, f)
	pages := 0
	for _, c := range f.calls {
		if strings.Contains(c, "/actions/secrets?") {
			pages++
		}
	}
	if pages != maxGitHubPages || len(rowsOf(o, ItemRepositorySecret, CheckWarn)) != maxGitHubPages*gitHubPerPage+1 {
		t.Fatalf("pages %d rows %d", pages, len(rowsOf(o, ItemRepositorySecret, CheckWarn)))
	}
	// 大きすぎる応答・JSON でない応答
	for name, body := range map[string]string{"huge": `{"default_branch":"` + strings.Repeat("a", maxGitHubBody) + `"}`, "not json": "<html>"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
		o := NewCheck()
		CheckGitHub(context.Background(), o, GitHub{Client: srv.Client(), BaseURL: srv.URL, Token: fakeToken}, exampleParams())
		srv.Close()
		if o.OK || len(o.Rows) != 1 || o.Rows[0].Code != "GITHUB_API_FAILED" {
			t.Errorf("%s: %+v", name, o.Rows)
		}
	}
	// リダイレクトは追わない (鍵の付いた要求を、別の場所へ送り直さない)
	var elsewhere int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere++ }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer redirect.Close()
	o = NewCheck()
	CheckGitHub(context.Background(), o, GitHub{BaseURL: redirect.URL, Token: fakeToken}, exampleParams())
	if elsewhere != 0 || o.OK || o.Rows[0].Code != "GITHUB_API_FAILED" {
		t.Fatalf("the redirect was followed %d times: %+v", elsewhere, o.Rows)
	}
	if GitHubAPIURL != "https://api.github.com" {
		t.Fatal("the API location is fixed")
	}
}

// arata は aratam の設定のパッケージにつながずに、aratam.yaml の送り方を自分で読む (ADR 0060)。
// aratam が判別する送り方 (notify.SlackConfig.Method) と、ここで読んだ結果が同じであることを固定する。
// aratam が項目の名前や判別を変えたら、ここで気づく。チャンネル ID の形も、aratam と同じ。
func TestAratamSlackMethodAgreesWithAratam(t *testing.T) {
	scaffold := string(aratamscaffold.Scaffold())
	bodies := map[string]string{
		"scaffold":           scaffold,
		"bot":                string(aratamscaffold.Bot("prod", "C0123456789", "C0123456780")),
		"webhook":            strings.NewReplacer("bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`, `webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ").Replace(scaffold),
		"only a channel":     "slack:\n  channel: C0123456789\n",
		"only urgent":        "slack:\n  urgent_channel: C0123456789\n",
		"both":               "slack:\n  webhook_env: A\n  bot_token_env: B\n",
		"nothing":            "slack: {}\n",
		"no slack":           "name: x\n",
		"old keys only":      "slack:\n  webhook_env: ARATAM_SLACK_WEBHOOK\n  urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK\n",
		"custom env":         "slack:\n  bot_token_env: MY_TOKEN\n  channel: C0123456789\n",
		"quoted empty":       "slack:\n  bot_token_env: \"\"\n  channel: ''\n  webhook_env: X\n",
		"null values":        "slack:\n  bot_token_env: ~\n  webhook_env: X\n",
		"urgent webhook too": "slack:\n  urgent_webhook_env: Y\n",
	}
	for name, body := range bodies {
		var cfg notify.Config
		if err := yaml.Unmarshal([]byte(body), &cfg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := AratamSlackMethod([]byte(body))
		if err != nil || got != cfg.Slack.Method() {
			t.Errorf("%s: arata reads %q (%v), aratam reads %q", name, got, err, cfg.Slack.Method())
		}
		s, _ := readAratamSlack([]byte(body))
		if s.BotTokenEnv != cfg.Slack.BotTokenEnv || s.WebhookEnv != cfg.Slack.WebhookEnv || s.UrgentWebhookEnv != cfg.Slack.UrgentWebhookEnv ||
			s.Channel != cfg.Slack.Channel || s.UrgentChannel != cfg.Slack.UrgentChannel {
			t.Errorf("%s: the keys differ: %+v / %+v", name, s, cfg.Slack)
		}
	}
	if methodBot != notify.SlackBot || methodWebhook != notify.SlackWebhook {
		t.Fatal("the method names differ")
	}
	// 書き出した aratam.yaml は、aratam がそのまま読める (チャンネル ID の形も同じ)
	dir := t.TempDir()
	for name, body := range map[string][]byte{"split": aratamscaffold.Bot("prod", "C0123456789", "C0123456780"), "same": aratamscaffold.Bot("staging", "G0123456789ABCDEFGHIJ", "")} {
		p := filepath.Join(dir, name+".yaml")
		mustWrite(t, p, string(body))
		cfg, err := notify.LoadConfig(p)
		if err != nil || cfg.Slack.Method() != notify.SlackBot {
			t.Errorf("%s: aratam cannot load the written aratam.yaml: %v", name, err)
		}
	}
	// aratam が受け付けない形は、arata も引数で受け付けない
	for _, id := range []string{"C0123456789", "G0123456789ABCDEFGHIJ", "D01234567"} {
		p := filepath.Join(dir, "id.yaml")
		mustWrite(t, p, string(aratamscaffold.Bot("prod", id, "")))
		if _, err := notify.LoadConfig(p); (err == nil) != ValidChannel(id) {
			t.Errorf("%s: aratam %v, arata %v", id, err, ValidChannel(id))
		}
	}
	for _, id := range []string{"c0123456789", "#general", "C012", "X0123456789", "C0123456789ABCDEFGHIJK"} {
		if ValidChannel(id) {
			t.Errorf("%s must not be a channel ID", id)
		}
	}
}
