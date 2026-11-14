// Package githubactions_test は見本のワークフローを検査する (実行はしない。実 AWS・Slack には接続しない)。
// run のスクリプトは偽の実行ファイルで動かし、ログに機微な値を出さないことと終了コードを確かめる。
package githubactions_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 見本は、arata repo init が決まった架空の引数で書き出した一式 (examples/audit-repo。ADR 0059)。雛形と 1 バイトも違わないことは
// internal/repoinit のテストが固定する。ここでは、そのワークフローの中身を確かめる。
// 定時の監査 (アカウントの matrix)、finding を片付ける triage、PR で設定を検査する check (triage_check_test.go)、
// Slack への送信だけを確かめる notify-test (notifytest_test.go)。
const (
	workflowDir = "../audit-repo/.github/workflows"
	multiFile   = "arata-audit.yml"
	triageFile  = "arata-triage.yml"
	checkFile   = "arata-check.yml"
)

// workflowFiles は定時の監査の見本。allFiles は見本のすべて。
var (
	workflowFiles = []string{multiFile}
	allFiles      = []string{multiFile, triageFile, checkFile, notifyTestFile}
)

type step struct {
	ID             string            `yaml:"id"`
	Name           string            `yaml:"name"`
	If             string            `yaml:"if"`
	Uses           string            `yaml:"uses"`
	Run            string            `yaml:"run"`
	Env            map[string]string `yaml:"env"`
	With           map[string]any    `yaml:"with"`
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	ContinueOnErr  any               `yaml:"continue-on-error"`
}

type concurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress *bool  `yaml:"cancel-in-progress"`
}

type workflow struct {
	file string
	On   struct {
		Schedule []struct {
			Cron string `yaml:"cron"`
		} `yaml:"schedule"`
		WorkflowDispatch struct {
			Inputs map[string]struct {
				Type     string   `yaml:"type"`
				Options  []string `yaml:"options"`
				Required bool     `yaml:"required"`
			} `yaml:"inputs"`
		} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Concurrency concurrency       `yaml:"concurrency"`
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]string `yaml:"env"`
	Defaults    struct {
		Run struct {
			Shell string `yaml:"shell"`
		} `yaml:"run"`
	} `yaml:"defaults"`
	Jobs map[string]struct {
		RunsOn      string      `yaml:"runs-on"`
		Environment any         `yaml:"environment"`
		Concurrency concurrency `yaml:"concurrency"`
		Strategy    struct {
			FailFast *bool `yaml:"fail-fast"`
			Matrix   struct {
				Account []string `yaml:"account"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		TimeoutMinutes int               `yaml:"timeout-minutes"`
		Permissions    map[string]string `yaml:"permissions"`
		Env            map[string]string `yaml:"env"`
		Steps          []step            `yaml:"steps"`
	} `yaml:"jobs"`
}

func load(t *testing.T, file string) (*workflow, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(workflowDir, file))
	if err != nil {
		t.Fatal(err)
	}
	w := &workflow{file: file}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(false)
	if err := dec.Decode(w); err != nil {
		t.Fatal(err)
	}
	return w, string(b)
}

// forEachWorkflow は定時の監査の見本に検査をかける。
func forEachWorkflow(t *testing.T, fn func(t *testing.T, w *workflow, text string)) {
	t.Helper()
	for _, f := range workflowFiles {
		t.Run(f, func(t *testing.T) {
			w, text := load(t, f)
			fn(t, w, text)
		})
	}
}

func steps(t *testing.T, w *workflow) []step {
	t.Helper()
	if len(w.Jobs) != 1 {
		t.Fatalf("want one job, got %d", len(w.Jobs))
	}
	for _, j := range w.Jobs {
		return j.Steps
	}
	return nil
}

func stepByID(t *testing.T, w *workflow, id string) step {
	t.Helper()
	for _, s := range steps(t, w) {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no step with id %q", id)
	return step{}
}

func TestSchedule(t *testing.T) {
	forEachWorkflow(t, testSchedule)
}

func testSchedule(t *testing.T, w *workflow, text string) {
	if len(w.On.Schedule) != 2 {
		t.Fatalf("want daily and weekly crons: %+v", w.On.Schedule)
	}
	for _, c := range w.On.Schedule {
		f := strings.Fields(c.Cron)
		if len(f) != 5 {
			t.Fatalf("bad cron %q", c.Cron)
		}
		if f[0] == "0" || f[0] == "*" {
			t.Errorf("cron %q must avoid the top of the hour (runs are delayed or dropped there)", c.Cron)
		}
	}
	// 週次の判定は github.event.schedule を文字列で比べるので、cron とずれると weekly が動かなくなる
	for _, j := range w.Jobs {
		if !strings.Contains(j.Env["PROFILE"], "'"+w.On.Schedule[1].Cron+"'") {
			t.Errorf("PROFILE must compare with the weekly cron %q: %s", w.On.Schedule[1].Cron, j.Env["PROFILE"])
		}
	}
	in, ok := w.On.WorkflowDispatch.Inputs["profile"]
	if !ok || in.Type != "choice" || strings.Join(in.Options, ",") != "daily,weekly" {
		t.Errorf("workflow_dispatch must offer the profile as a choice: %+v", in)
	}
}

func TestConcurrencyAndPermissions(t *testing.T) {
	forEachWorkflow(t, testConcurrencyAndPermissions)
}

func testConcurrencyAndPermissions(t *testing.T, w *workflow, text string) {
	// 排他はストアごと。1 つのストアならワークフローに、アカウントごとのストアならジョブ (matrix) に置く
	c := w.Concurrency
	if w.file == multiFile {
		if c.Group != "" {
			t.Errorf("a workflow-level group would queue the whole matrix behind one run: %+v", c)
		}
		c = w.Jobs["audit"].Concurrency
		if !strings.Contains(c.Group, "${{ matrix.account }}") {
			t.Errorf("the group must be per store (per account): %q", c.Group)
		}
	}
	if c.Group == "" || c.CancelInProgress == nil || *c.CancelInProgress {
		t.Errorf("concurrency must queue, not cancel: %+v", c)
	}
	if len(w.Permissions) != 0 {
		t.Errorf("workflow-level permissions must be empty (grant them per job): %v", w.Permissions)
	}
	p := w.Jobs["audit"].Permissions
	if len(p) != 2 || p["id-token"] != "write" || p["contents"] != "read" {
		t.Errorf("permissions must be id-token: write and contents: read only: %v", p)
	}
	if w.Defaults.Run.Shell != "bash" {
		t.Errorf("shell: bash is needed for pipefail: %q", w.Defaults.Run.Shell)
	}
}

func TestActionsArePinnedToSHA(t *testing.T) {
	forEachWorkflow(t, testActionsArePinnedToSHA)
}

func testActionsArePinnedToSHA(t *testing.T, w *workflow, text string) {
	uses := regexp.MustCompile(`(?m)^\s*(?:- )?uses:\s*(.+)$`).FindAllStringSubmatch(text, -1)
	if len(uses) == 0 {
		t.Fatal("no uses found")
	}
	pinned := regexp.MustCompile(`^[\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$`)
	for _, u := range uses {
		if !pinned.MatchString(strings.TrimSpace(u[1])) {
			t.Errorf("must be pinned to a 40-char SHA with the version in a comment: %s", u[1])
		}
	}
}

func TestCredentials(t *testing.T) {
	forEachWorkflow(t, testCredentials)
}

func testCredentials(t *testing.T, w *workflow, text string) {
	s := stepByID(t, w, "aws")
	if !strings.HasPrefix(s.Uses, "aws-actions/configure-aws-credentials@") {
		t.Fatalf("uses: %s", s.Uses)
	}
	if got, _ := s.With["role-to-assume"].(string); !strings.Contains(got, "secrets.") {
		t.Errorf("the role ARN holds the account ID, so it must come from a secret: %v", s.With["role-to-assume"])
	}
	if s.With["mask-aws-account-id"] != true {
		t.Errorf("mask-aws-account-id must be true: %v", s.With["mask-aws-account-id"])
	}
	for _, c := range steps(t, w) {
		if strings.HasPrefix(c.Uses, "actions/checkout@") && c.With["persist-credentials"] != false {
			t.Errorf("checkout must set persist-credentials: false")
		}
	}
}

// Actions のログに機微な値を出さない。run には式を埋め込まない (ログの表示と注入を避け、env で渡す)。
func TestNoSensitiveOutput(t *testing.T) {
	forEachWorkflow(t, testNoSensitiveOutput)
}

func testNoSensitiveOutput(t *testing.T, w *workflow, text string) {
	for _, s := range steps(t, w) {
		if strings.Contains(s.Run, "${{") {
			t.Errorf("step %q: pass values through env, not ${{ }} in run", s.Name)
		}
		for _, bad := range []string{"set -x", "set -o xtrace", "bash -x"} {
			if strings.Contains(s.Run, bad) {
				t.Errorf("step %q must not use %s", s.Name, bad)
			}
		}
		if regexp.MustCompile(`\b(cat|echo|tee|head|tail)\b[^\n]*report\.(json|md)`).MatchString(s.Run) {
			t.Errorf("step %q must not print the report", s.Name)
		}
		if strings.Contains(s.Uses, "upload-artifact") {
			t.Errorf("artifacts are readable by anyone who can read the repository")
		}
	}
	if strings.Contains(text, "ACTIONS_STEP_DEBUG") {
		t.Errorf("must not turn on step debug")
	}
}

func TestSecretsReachOnlyTheStepsThatNeedThem(t *testing.T) {
	forEachWorkflow(t, testSecretsReachOnlyTheStepsThatNeedThem)
}

func testSecretsReachOnlyTheStepsThatNeedThem(t *testing.T, w *workflow, text string) {
	for k, v := range w.Env {
		if strings.Contains(v, "secrets.") {
			t.Errorf("workflow env %s must not hold a secret", k)
		}
	}
	for _, j := range w.Jobs {
		for k, v := range j.Env {
			if strings.Contains(v, "secrets.") {
				t.Errorf("job env %s must not hold a secret", k)
			}
		}
	}
	for _, s := range steps(t, w) {
		for k, v := range s.Env {
			if !strings.Contains(v, "secrets.") {
				continue
			}
			want := map[string]string{"GH_TOKEN": "install", "AUDIT_ROLE_ARNS": "aws-config",
				// 仮の値のままでないことを確かめる step (比べるだけで、値は出さない。secrets_test.go)
				"ARATA_RUNNER_ROLE_ARN": "secrets", "ARATA_AUDIT_ROLE_ARNS": "secrets", "ARATA_ALERT_WEBHOOK": "secrets", "ARATAM_SLACK_WEBHOOK": "notify", "ARATAM_SLACK_URGENT_WEBHOOK": "notify", "ARATAM_SLACK_BOT_TOKEN": "notify", "ALERT_WEBHOOK": "alert"}[k]
			if want != s.ID {
				t.Errorf("secret %s must not be given to step %q", k, s.ID)
			}
		}
	}
	// secrets[...] や toJSON(secrets) は、ジョブにすべての secrets を渡すことになるので使わない
	for _, expr := range regexp.MustCompile(`\$\{\{[^}]*\}\}`).FindAllString(text, -1) {
		for _, bad := range []string{"secrets[", "(secrets)", "secrets.*"} {
			if strings.Contains(expr, bad) {
				t.Errorf("must name each secret statically: %s", expr)
			}
		}
	}
	n := stepByID(t, w, "notify")
	if n.Env["ARATAM_SLACK_WEBHOOK"] == "" || n.Env["ARATAM_SLACK_URGENT_WEBHOOK"] == "" || n.Env["ARATAM_SLACK_BOT_TOKEN"] == "" {
		t.Errorf("notify needs both webhooks and the bot token (each only for its method): %v", n.Env)
	}
}

// arata が失敗しても (認証の失敗で走らなくても) aratam は「実行されていない」を送る。
func TestNotifyRunsWhenAuditFails(t *testing.T) {
	forEachWorkflow(t, testNotifyRunsWhenAuditFails)
}

func testNotifyRunsWhenAuditFails(t *testing.T, w *workflow, text string) {
	n := stepByID(t, w, "notify")
	if !strings.Contains(n.If, "always()") || !strings.Contains(n.If, "steps.install.outcome == 'success'") {
		t.Errorf("notify must run after any failure once the binaries are installed: %q", n.If)
	}
	a := stepByID(t, w, "audit")
	if a.ContinueOnErr != nil {
		t.Errorf("a failed audit must leave the job red")
	}
	if a.TimeoutMinutes == 0 || a.TimeoutMinutes >= 60 {
		t.Errorf("the audit step needs a timeout shorter than the 1 hour credentials: %d", a.TimeoutMinutes)
	}
	order := map[string]int{}
	for i, s := range steps(t, w) {
		order[s.ID] = i
	}
	// バイナリは認証より先に取る (OIDC が失敗しても aratam で知らせるため)
	if !(order["install"] < order["aws"] && order["aws"] < order["audit"] && order["audit"] < order["slack-method"] && order["slack-method"] < order["notify"] &&
		order["notify"] < order["save-proposals"] && order["save-proposals"] < order["alert"] && order["alert"] == len(order)-1) {
		t.Errorf("step order: %v", order)
	}
	p := stepByID(t, w, "save-proposals")
	if !strings.Contains(p.If, "always()") || !strings.Contains(p.If, "steps.aws.outcome == 'success'") {
		t.Errorf("save-proposals must run when credentials are available: %q", p.If)
	}
}

func TestRunScriptsParse(t *testing.T) {
	forEachWorkflow(t, testRunScriptsParse)
}

func testRunScriptsParse(t *testing.T, w *workflow, text string) {
	for _, s := range steps(t, w) {
		if s.Run == "" {
			continue
		}
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(s.Run)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("step %q: %v\n%s", s.Name, err, out)
		}
	}
}

// runStep は Actions と同じ bash の起動で step のスクリプトを動かす。PATH の先頭は偽の実行ファイルの置き場所。
func runStep(t *testing.T, script, bin string, env ...string) (string, int, string) {
	t.Helper()
	return runStepIn(t, repoWithMethodScript(t), script, bin, env...)
}

// runStepIn は dir をカレントディレクトリ (checkout したリポジトリのつもり) にして step を動かす。
func runStepIn(t *testing.T, dir, script, bin string, env ...string) (string, int, string) {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", path)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "RUNNER_TEMP=" + tmp,
		"GITHUB_PATH=" + filepath.Join(tmp, "github_path"), "GITHUB_ENV=" + filepath.Join(tmp, "github_env"),
		"GITHUB_STEP_SUMMARY=" + filepath.Join(tmp, "summary"), "GITHUB_OUTPUT=" + filepath.Join(tmp, "github_output"), "GITHUB_ACTOR=alice",
		"PROFILE=daily", "ARATA_VERSION=v0.0.0", "ARATA_CONFIG_DIR=arata", "ARATA_STORE_URL=s3://example-arata-store/example"}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return string(out), code, tmp
}

func fakeBin(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

const leakyLog = `echo 'report body 123456789012' 
echo '{"level":"INFO","msg":"collect ok","source":"trail"}' >&2
echo '{"level":"ERROR","msg":"store conflict at arn:aws:iam::123456789012:role/x","code":"STORE_CONFLICT","source":"trail","error":"alice@example.com"}' >&2
echo 'panic: not json 123456789012' >&2
`

func TestAuditAndNotifyLogOnlyCodesAndKeepExitCode(t *testing.T) {
	forEachWorkflow(t, testAuditAndNotifyLogOnlyCodesAndKeepExitCode)
}

func testAuditAndNotifyLogOnlyCodesAndKeepExitCode(t *testing.T, w *workflow, text string) {
	for id, tool := range map[string]string{"audit": "arata", "notify": "aratam"} {
		for _, exit := range []int{0, 2, 3} {
			t.Run(fmt.Sprintf("%s/exit=%d", id, exit), func(t *testing.T) {
				bin := fakeBin(t, tool, leakyLog+fmt.Sprintf("exit %d\n", exit))
				out, code, _ := runStep(t, stepByID(t, w, id).Run, bin)
				if code != exit {
					t.Errorf("exit code must be kept: got %d want %d\n%s", code, exit, out)
				}
				for _, secret := range []string{"123456789012", "alice@example.com", "collect ok", "report body"} {
					if strings.Contains(out, secret) {
						t.Errorf("leaked %q:\n%s", secret, out)
					}
				}
				if !strings.Contains(out, "STORE_CONFLICT") {
					t.Errorf("the error code must stay visible:\n%s", out)
				}
			})
		}
	}
}

func TestAuditRunsWithExpectedArguments(t *testing.T) {
	forEachWorkflow(t, testAuditRunsWithExpectedArguments)
}

func testAuditRunsWithExpectedArguments(t *testing.T, w *workflow, text string) {
	bin := fakeBin(t, "arata", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\n")
	_, code, tmp := runStep(t, stepByID(t, w, "audit").Run, bin)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "args"))
	if err != nil {
		t.Fatal(err)
	}
	want := "run\n-c\narata/arata.yaml\n--profile\ndaily\n--out\n" + tmp + "/arata-out\n"
	if string(b) != want {
		t.Errorf("args:\n%s\nwant:\n%s", b, want)
	}
}

func TestAWSConfigStepWritesAuditProfile(t *testing.T) {
	forEachWorkflow(t, testAWSConfigStepWritesAuditProfile)
}

func testAWSConfigStepWritesAuditProfile(t *testing.T, w *workflow, text string) {
	vars := []string{"AUDIT_ROLE_ARN=arn:aws:iam::123456789012:role/arata-readonly"}
	if w.file == multiFile {
		// アカウントごとのロールは 1 つの secret (JSON) から、matrix の名前で取り出す
		vars = []string{"ACCOUNT=prod", `AUDIT_ROLE_ARNS={"staging":"arn:aws:iam::111122223333:role/arata-readonly","prod":"arn:aws:iam::123456789012:role/arata-readonly"}`}
	}
	out, code, tmp := runStep(t, stepByID(t, w, "aws-config").Run, t.TempDir(), vars...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "111122223333") {
		t.Errorf("another account's role must stay out of the log:\n%s", out)
	}
	// 取り出した ARN は secret の一部で自動では隠れないので、::add-mask:: で隠す (それ以外には出さない)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, "123456789012") && !strings.HasPrefix(line, "::add-mask::") {
			t.Errorf("the role ARN must not be printed: %s", line)
		}
	}
	b, err := os.ReadFile(filepath.Join(tmp, "aws-config"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[profile arata-audit]", "role_arn = arn:aws:iam::123456789012:role/arata-readonly", "credential_source = Environment"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
	env, _ := os.ReadFile(filepath.Join(tmp, "github_env"))
	if string(env) != "AWS_CONFIG_FILE="+tmp+"/aws-config\n" {
		t.Errorf("GITHUB_ENV: %q", env)
	}
}

// fakeGH は gh release download の代わりに、指定のディレクトリへバイナリと SHA256SUMS を置く。
func fakeGH(t *testing.T, sums string) string {
	t.Helper()
	return fakeBin(t, "gh", fmt.Sprintf(`while [ $# -gt 0 ]; do [ "$1" = -D ] && dir="$2"; shift; done
echo fake-arata >"$dir/arata-linux-amd64"
echo fake-aratam >"$dir/aratam-linux-amd64"
cat >"$dir/SHA256SUMS" <<'SUMS'
%sSUMS
`, sums))
}

func sumLine(content, name string) string {
	return fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(content+"\n")), name)
}

func TestInstallVerifiesChecksums(t *testing.T) {
	forEachWorkflow(t, testInstallVerifiesChecksums)
}

func testInstallVerifiesChecksums(t *testing.T, w *workflow, text string) {
	script := stepByID(t, w, "install").Run
	good := sumLine("fake-arata", "arata-linux-amd64") + sumLine("fake-aratam", "aratam-linux-amd64") + sumLine("other", "arata-linux-arm64")

	t.Run("ok", func(t *testing.T) {
		out, code, tmp := runStep(t, script, fakeGH(t, good))
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		for _, name := range []string{"arata", "aratam"} {
			st, err := os.Stat(filepath.Join(tmp, "arata-bin", name))
			if err != nil || st.Mode()&0o100 == 0 {
				t.Errorf("%s must be installed and executable: %v", name, err)
			}
		}
		p, _ := os.ReadFile(filepath.Join(tmp, "github_path"))
		if string(p) != tmp+"/arata-bin\n" {
			t.Errorf("GITHUB_PATH: %q", p)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		bad := sumLine("evil", "arata-linux-amd64") + sumLine("fake-aratam", "aratam-linux-amd64")
		if out, code, _ := runStep(t, script, fakeGH(t, bad)); code == 0 {
			t.Errorf("a wrong checksum must fail\n%s", out)
		}
	})
	t.Run("missing line", func(t *testing.T) {
		if out, code, _ := runStep(t, script, fakeGH(t, sumLine("fake-arata", "arata-linux-amd64"))); code == 0 {
			t.Errorf("a binary without a checksum must fail\n%s", out)
		}
	})
}

func TestSaveProposalsOnlyWhenTheFileExists(t *testing.T) {
	forEachWorkflow(t, testSaveProposalsOnlyWhenTheFileExists)
}

func testSaveProposalsOnlyWhenTheFileExists(t *testing.T, w *workflow, text string) {
	script := stepByID(t, w, "save-proposals").Run
	bin := fakeBin(t, "aws", `printf '%s\n' "$@" >"$RUNNER_TEMP/aws-args"; echo 'upload: s3://bucket 123456789012'`+"\n")

	out, code, tmp := runStep(t, script, bin)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(tmp, "aws-args")); err == nil {
		t.Errorf("must not call aws without the file")
	}

	withFile := "mkdir -p \"$RUNNER_TEMP/arata-out\"; touch \"$RUNNER_TEMP/arata-out/waf-proposals.md\"\n" + script
	out, code, tmp = runStep(t, withFile, bin)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "123456789012") {
		t.Errorf("aws output must stay out of the log:\n%s", out)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "aws-args"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "s3://example-arata-store/example/reports/waf-proposals.md") {
		t.Errorf("aws args: %s", b)
	}
}

// 複数のアカウントの見本: 1 つの secret からそのアカウントのロールが取れなければ、何も書かずに失敗する。
func TestMultiAWSConfigFailsWithoutTheAccountRole(t *testing.T) {
	w, _ := load(t, multiFile)
	script := stepByID(t, w, "aws-config").Run
	for name, env := range map[string][]string{
		"missing account": {"ACCOUNT=prod", `AUDIT_ROLE_ARNS={"staging":"arn:aws:iam::111122223333:role/arata-readonly"}`},
		"not json":        {"ACCOUNT=prod", "AUDIT_ROLE_ARNS=arn:aws:iam::111122223333:role/arata-readonly"},
		"empty secret":    {"ACCOUNT=prod", "AUDIT_ROLE_ARNS="},
		"not a string":    {"ACCOUNT=prod", `AUDIT_ROLE_ARNS={"prod":{"arn":"arn:aws:iam::111122223333:role/arata-readonly"}}`},
		"not a role arn":  {"ACCOUNT=prod", `AUDIT_ROLE_ARNS={"prod":"111122223333"}`},
	} {
		t.Run(name, func(t *testing.T) {
			out, code, tmp := runStep(t, script, t.TempDir(), env...)
			if code == 0 {
				t.Errorf("must fail\n%s", out)
			}
			if strings.Contains(out, "111122223333") {
				t.Errorf("the secret must stay out of the log:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(tmp, "github_env")); err == nil {
				t.Errorf("must not set AWS_CONFIG_FILE")
			}
		})
	}
}

// 複数のアカウントの見本: アカウントごとにジョブを分け、設定の置き場所・ストアの prefix・排他をアカウントごとにする。
func TestMultiMatrix(t *testing.T) {
	w, _ := load(t, multiFile)
	j := w.Jobs["audit"]
	if j.Strategy.FailFast == nil || *j.Strategy.FailFast {
		t.Errorf("fail-fast must be false (one account's failure must not cancel the others)")
	}
	if len(j.Strategy.Matrix.Account) < 2 {
		t.Fatalf("the example needs two or more accounts: %v", j.Strategy.Matrix.Account)
	}
	name := regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`) // パスと prefix と排他の名前に使う
	for _, a := range j.Strategy.Matrix.Account {
		if !name.MatchString(a) {
			t.Errorf("account name %q", a)
		}
	}
	want := map[string]string{
		"ACCOUNT":          "${{ matrix.account }}",
		"ARATA_CONFIG_DIR": "aws/${{ matrix.account }}",
		"ARATA_STORE_URL":  "s3://example-arata-store/${{ matrix.account }}",
	}
	for k, v := range want {
		if j.Env[k] != v {
			t.Errorf("job env %s = %q, want %q", k, j.Env[k], v)
		}
		if _, ok := w.Env[k]; ok {
			t.Errorf("%s must be per job, not per workflow", k)
		}
	}
}
