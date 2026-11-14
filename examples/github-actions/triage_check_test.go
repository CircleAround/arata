package githubactions_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/engine"
)

// triggers はワークフローの on: のキー。
func triggers(t *testing.T, file string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(workflowDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		On map[string]any `yaml:"on"`
	}
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range w.On {
		out = append(out, k)
	}
	return out
}

// どの見本にも共通の規則: action は SHA で固定、run に式を埋め込まない、権限はジョブごと、checkout は資格情報を残さない。
func TestEveryWorkflowFollowsTheCommonRules(t *testing.T) {
	for _, f := range allFiles {
		t.Run(f, func(t *testing.T) {
			w, text := load(t, f)
			testActionsArePinnedToSHA(t, w, text)
			testNoSensitiveOutput(t, w, text)
			testRunScriptsParse(t, w, text)
			if len(w.Permissions) != 0 {
				t.Errorf("workflow-level permissions must be empty (grant them per job): %v", w.Permissions)
			}
			if w.Defaults.Run.Shell != "bash" {
				t.Errorf("shell: bash is needed for pipefail: %q", w.Defaults.Run.Shell)
			}
			for _, s := range steps(t, w) {
				if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != false {
					t.Errorf("checkout must set persist-credentials: false")
				}
			}
			for _, bad := range []string{"pull_request_target", "workflow_run"} {
				if strings.Contains(text, bad) {
					t.Errorf("must not use %s", bad)
				}
			}
		})
	}
}

// 利用者のリポジトリの前提 (README「実行するリポジトリと環境を堅くする」) を見本が満たすこと。
//   - secrets か OIDC を使う見本は、定時と手動でだけ動く (PR や push では動かさない)
//   - 使う action は、許可リストに書く 2 つ (GitHub 製の checkout と aws-actions/configure-aws-credentials) だけ
//   - secrets か OIDC を使う見本のジョブは、GitHub の environment (audit) で動く。秘密は environment に置き、デプロイできるブランチを
//     main だけにするので、ほかのブランチのジョブには秘密が渡らない。OIDC の sub は repo:…:environment:audit になり、
//     runner.yaml の GitHubEnvironment=audit と組になる (ADR 0057)
//   - secrets も OIDC も使わない見本 (PR の検査) には environment を付けない (PR のブランチでは動けなくなる。守る秘密も無い)
func TestEveryWorkflowFitsTheHardenedRepository(t *testing.T) {
	for _, f := range allFiles {
		t.Run(f, func(t *testing.T) {
			w, text := load(t, f)
			if strings.Contains(text, "secrets.") || strings.Contains(text, "id-token") {
				for _, tr := range triggers(t, f) {
					if tr != "schedule" && tr != "workflow_dispatch" {
						t.Errorf("a workflow with secrets or OIDC must run only on schedule / workflow_dispatch: %s", tr)
					}
				}
			}
			for _, s := range steps(t, w) {
				if s.Uses == "" {
					continue
				}
				if !strings.HasPrefix(s.Uses, "actions/checkout@") && !strings.HasPrefix(s.Uses, "aws-actions/configure-aws-credentials@") {
					t.Errorf("action outside the documented allowlist: %s", s.Uses)
				}
			}
			sensitive := strings.Contains(text, "secrets.") || strings.Contains(text, "id-token")
			for name, j := range w.Jobs {
				switch {
				case sensitive && j.Environment != "audit":
					// 名前は文字列でそのまま書く (式にしない。入力から environment を選べると、守りの弱い environment に逃がせる)
					t.Errorf("job %s uses secrets or OIDC and must run in the environment audit: %v", name, j.Environment)
				case !sensitive && j.Environment != nil:
					t.Errorf("job %s uses neither secrets nor OIDC and must not reference an environment: %v", name, j.Environment)
				}
			}
			if n := len(regexp.MustCompile(`(?m)^\s+environment:`).FindAllString(text, -1)); sensitive && n != 1 || !sensitive && n != 0 {
				t.Errorf("environment: must appear once, on the job (secrets or OIDC: %v): %d", sensitive, n)
			}
		})
	}
}

// 新しい見本は、監査の見本と同じ step (取得の照合、実行用ロール) と同じ action をそのまま使う。
func TestTriageAndCheckShareStepsWithAudit(t *testing.T) {
	audit, auditText := load(t, multiFile)
	pinned := map[string]bool{}
	for _, u := range regexp.MustCompile(`(?m)^\s*(?:- )?uses:\s*(\S+)`).FindAllStringSubmatch(auditText, -1) {
		pinned[u[1]] = true
	}
	same := func(file, id string) {
		t.Helper()
		w, text := load(t, file)
		x, _ := yaml.Marshal(stepByID(t, audit, id))
		y, _ := yaml.Marshal(stepByID(t, w, id))
		if string(x) != string(y) {
			t.Errorf("%s: step %q differs from %s:\n%s\n---\n%s", file, id, multiFile, y, x)
		}
		for _, u := range regexp.MustCompile(`(?m)^\s*(?:- )?uses:\s*(\S+)`).FindAllStringSubmatch(text, -1) {
			if !pinned[u[1]] {
				t.Errorf("%s: %s is not one of the actions (and SHAs) of %s", file, u[1], multiFile)
			}
		}
	}
	same(triageFile, "checkout")
	same(triageFile, "install")
	same(triageFile, "aws")
	same(checkFile, "checkout")
	same(checkFile, "install")
	same(notifyTestFile, "checkout")
	same(notifyTestFile, "install")
}

func TestTriageTriggerAndInputs(t *testing.T) {
	w, text := load(t, triageFile)
	if got := triggers(t, triageFile); len(got) != 1 || got[0] != "workflow_dispatch" {
		t.Fatalf("triage must run only by workflow_dispatch: %v", got)
	}
	in := w.On.WorkflowDispatch.Inputs
	multi, _ := load(t, multiFile)
	if a := in["account"]; a.Type != "choice" || !a.Required || strings.Join(a.Options, ",") != strings.Join(multi.Jobs["audit"].Strategy.Matrix.Account, ",") {
		t.Errorf("account must be a choice of the accounts of %s: %+v", multiFile, a)
	}
	// approve は入れない (ストアの finding が allowlist.yaml の PR のマージより先に解消されてしまう)
	if a := in["action"]; a.Type != "choice" || !a.Required || strings.Join(a.Options, ",") != "ack,snooze,resolve" {
		t.Errorf("action must be a choice of ack, snooze, resolve: %+v", a)
	}
	if regexp.MustCompile(`arata\s+approve\s+-|"approve"|\bapprove\)`).MatchString(text) {
		t.Errorf("the workflow must not run arata approve")
	}
	for _, name := range []string{"finding_id", "reason"} {
		if i := in[name]; i.Type != "string" || !i.Required {
			t.Errorf("%s must be a required string: %+v", name, i)
		}
	}
	if u, ok := in["until"]; !ok || u.Required {
		t.Errorf("until is only for snooze: %+v", u)
	}
	j := w.Jobs["triage"]
	// 定時の監査 (書き込む実行) と同じ group (アカウントごと) で、順番に動かす。試しの実行の group は別 (ストアに書かない。dryrun_test.go)
	want := strings.Replace(strings.Replace(multi.Jobs["audit"].Concurrency.Group, dryRunGroupSuffix, "", 1), "matrix.account", "inputs.account", 1)
	if c := j.Concurrency; c.Group != want || !strings.Contains(want, "inputs.account") || c.CancelInProgress == nil || *c.CancelInProgress {
		t.Errorf("concurrency must be the group of the audit (%q) and must queue: %+v", want, c)
	}
	if p := j.Permissions; len(p) != 2 || p["id-token"] != "write" || p["contents"] != "read" {
		t.Errorf("permissions must be id-token: write and contents: read only: %v", p)
	}
	for k, v := range map[string]string{"ACCOUNT": "${{ inputs.account }}", "ARATA_CONFIG_DIR": "aws/${{ inputs.account }}", "ACTION": "${{ inputs.action }}",
		"FINDING_ID": "${{ inputs.finding_id }}", "REASON": "${{ inputs.reason }}", "UNTIL": "${{ inputs.until }}"} {
		if j.Env[k] != v {
			t.Errorf("job env %s = %q, want %q", k, j.Env[k], v)
		}
	}
	// secrets は実行用ロールの ARN だけ (仮の値でないことを確かめる step と、引き受ける step の 2 か所)。Slack にも監査ロールにも用が無い
	if got := regexp.MustCompile(`secrets\.\w+`).FindAllString(text, -1); len(got) != 2 || got[0] != "secrets.ARATA_RUNNER_ROLE_ARN" || got[1] != got[0] {
		t.Errorf("secrets: %v", got)
	}
	order := map[string]int{}
	for i, s := range steps(t, w) {
		order[s.ID] = i
	}
	// 入力は認証より先に確かめる
	if !(order["validate"] < order["aws"] && order["install"] < order["aws"] && order["aws"] < order["triage"] && order["triage"] < order["summary"]) {
		t.Errorf("step order: %v", order)
	}
	if s := stepByID(t, w, "triage"); s.ContinueOnErr != nil || s.TimeoutMinutes == 0 {
		t.Errorf("a failed triage must leave the job red, with a timeout: %+v", s)
	}
	if s := stepByID(t, w, "summary"); !strings.Contains(s.If, "always()") || !strings.Contains(s.If, "steps.validate.outcome == 'success'") {
		t.Errorf("the summary must be written even when arata fails, but only for validated inputs: %q", s.If)
	}
}

func triageEnv(kv ...string) []string {
	env := map[string]string{"ACCOUNT": "prod", "ARATA_CONFIG_DIR": "aws/prod", "ACTION": "ack", "FINDING_ID": "0123456789ab", "REASON": "既知の作業", "UNTIL": ""}
	for i := 0; i+1 < len(kv); i += 2 {
		env[kv[i]] = kv[i+1]
	}
	var out []string
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func TestTriageValidatesInputs(t *testing.T) {
	w, _ := load(t, triageFile)
	script := stepByID(t, w, "validate").Run
	ok := [][]string{
		nil,
		{"ACTION", "resolve"},
		{"ACTION", "snooze", "UNTIL", "2027-03-31"},
		{"ACCOUNT", "staging-2"},
		// arata が実際に振る ID の形を受け付ける (形が変わったらここで気づく)
		{"FINDING_ID", engine.RandomID()},
		{"REASON", "$(touch pwned) `id` ; echo ${{ github.token }}"}, // ただの文字列として扱う
	}
	for _, kv := range ok {
		t.Run("ok/"+strings.Join(kv, " "), func(t *testing.T) {
			dir := t.TempDir()
			if out, code, _ := runStepIn(t, dir, script, t.TempDir(), triageEnv(kv...)...); code != 0 {
				t.Errorf("exit %d\n%s", code, out)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("the inputs must not be evaluated: %v", ents)
			}
		})
	}
	bad := map[string][]string{
		"empty id":             {"FINDING_ID", ""},
		"short id":             {"FINDING_ID", "0123456789a"},
		"long id":              {"FINDING_ID", "0123456789abc"},
		"upper id":             {"FINDING_ID", "0123456789AB"},
		"flag as id":           {"FINDING_ID", "--help"},
		"id with a command":    {"FINDING_ID", "0123456789ab; id"},
		"id with a newline":    {"FINDING_ID", "0123456789ab\n--until"},
		"approve":              {"ACTION", "approve"},
		"unknown action":       {"ACTION", "review"},
		"empty action":         {"ACTION", ""},
		"snooze without until": {"ACTION", "snooze"},
		"snooze bad until":     {"ACTION", "snooze", "UNTIL", "2027-3-31"},
		"snooze until + flag":  {"ACTION", "snooze", "UNTIL", "2027-03-31 --x"},
		"ack with until":       {"UNTIL", "2027-03-31"},
		"empty reason":         {"REASON", ""},
		"blank reason":         {"REASON", "  \t"},
		"multi-line reason":    {"REASON", "a\nb"},
		"long reason":          {"REASON", strings.Repeat("あ", 301)},
		"account path":         {"ACCOUNT", "../prod"},
		"account upper":        {"ACCOUNT", "Prod"},
		"empty account":        {"ACCOUNT", ""},
	}
	for name, kv := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			out, code, _ := runStep(t, script, t.TempDir(), triageEnv(kv...)...)
			if code != 1 || !strings.Contains(out, "::error::") {
				t.Errorf("must fail with an error annotation: exit %d\n%s", code, out)
			}
		})
	}
}

func TestTriageRunsArataWithExpectedArguments(t *testing.T) {
	w, _ := load(t, triageFile)
	script := stepByID(t, w, "triage").Run
	bin := fakeBin(t, "arata", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\n")
	for name, tc := range map[string]struct {
		kv   []string
		want string
	}{
		"ack":     {nil, "ack\n-c\naws/prod/arata.yaml\n0123456789ab\n"},
		"resolve": {[]string{"ACTION", "resolve", "ACCOUNT", "staging", "ARATA_CONFIG_DIR", "aws/staging"}, "resolve\n-c\naws/staging/arata.yaml\n0123456789ab\n"},
		"snooze":  {[]string{"ACTION", "snooze", "UNTIL", "2027-03-31"}, "snooze\n-c\naws/prod/arata.yaml\n--until\n2027-03-31\n0123456789ab\n"},
	} {
		t.Run(name, func(t *testing.T) {
			out, code, tmp := runStep(t, script, bin, triageEnv(tc.kv...)...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			b, err := os.ReadFile(filepath.Join(tmp, "args"))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.want {
				t.Errorf("args:\n%s\nwant:\n%s", b, tc.want)
			}
			// 理由と操作した人は arata に渡さない (ack / snooze / resolve にそのフラグは無い)。記録は Summary
			if strings.Contains(string(b), "既知の作業") || strings.Contains(string(b), "alice") {
				t.Errorf("reason and actor are not arata flags: %s", b)
			}
		})
	}
}

// ログの方針は監査と同じ (msg / error を出さず、終了コードは保つ)。
func TestTriageLogsOnlyCodesAndKeepsExitCode(t *testing.T) {
	w, _ := load(t, triageFile)
	for _, exit := range []int{0, 2} {
		t.Run(fmt.Sprintf("exit=%d", exit), func(t *testing.T) {
			bin := fakeBin(t, "arata", leakyLog+fmt.Sprintf("exit %d\n", exit))
			out, code, _ := runStep(t, stepByID(t, w, "triage").Run, bin, triageEnv()...)
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

// 誰が・何を・なぜ、は Summary に残す (ストアには残らない)。
func TestTriageSummaryRecordsActorAndReason(t *testing.T) {
	w, _ := load(t, triageFile)
	s := stepByID(t, w, "summary")
	if s.Env["RESULT"] != "${{ steps.triage.outcome }}" {
		t.Errorf("RESULT: %v", s.Env)
	}
	reason := "検証の作業 ``` </code> | **x** $(id) `id`"
	out, code, tmp := runStep(t, s.Run, t.TempDir(), append(triageEnv("ACTION", "snooze", "UNTIL", "2027-03-31", "REASON", reason), "RESULT=success")...)
	if code != 0 || strings.TrimSpace(out) != "" {
		t.Fatalf("exit %d; the record goes to the summary, not to the log:\n%s", code, out)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "summary"))
	if err != nil {
		t.Fatal(err)
	}
	sum := string(b)
	for _, want := range []string{"`prod`", "`snooze`", "`0123456789ab`", "`2027-03-31`", "`alice`", "`success`", "検証の作業"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	// reason はコードの囲みの中だけ。囲みを閉じる ``` を reason から作れない
	if strings.Count(sum, "```") != 2 || !strings.HasSuffix(sum, "```\n") {
		t.Errorf("the reason must stay inside one code fence:\n%s", sum)
	}
	// until は snooze のときだけ
	_, _, tmp = runStep(t, s.Run, t.TempDir(), append(triageEnv(), "RESULT=failure")...)
	if b, _ := os.ReadFile(filepath.Join(tmp, "summary")); strings.Contains(string(b), "until") || !strings.Contains(string(b), "`failure`") {
		t.Errorf("summary of ack:\n%s", b)
	}
}

func TestCheckTriggerAndPermissions(t *testing.T) {
	w, text := load(t, checkFile)
	if got := triggers(t, checkFile); len(got) != 1 || got[0] != "pull_request" {
		t.Fatalf("check must run only on pull_request: %v", got)
	}
	// AWS の認証も secrets も使わない (フォークからの PR でも同じに動き、漏らすものが無い)
	if p := w.Jobs["check"].Permissions; len(p) != 1 || p["contents"] != "read" {
		t.Errorf("permissions must be contents: read only: %v", p)
	}
	for _, bad := range []string{"secrets.", "id-token", "configure-aws-credentials", "role-to-assume"} {
		if strings.Contains(text, bad) {
			t.Errorf("check must not use %s", bad)
		}
	}
	if w.Jobs["check"].TimeoutMinutes == 0 {
		t.Errorf("the job needs a timeout")
	}
}

// check は、リポジトリの中の arata.yaml と aratam.yaml のすべてに config check をかける。
// 送り方の判別はしない (ADR 0060: aratam.yaml が bot トークンの方式であることは、次の repo-check が確かめる)。
func TestCheckRunsConfigCheckForEveryConfig(t *testing.T) {
	w, text := load(t, checkFile)
	script := stepByID(t, w, "check").Run
	for _, bad := range []string{"arata-slack-method", ".github/scripts", "--format json", "slack method"} {
		if strings.Contains(text, bad) {
			t.Errorf("the check must not detect the method by itself: %q", bad)
		}
	}
	// 偽の arata / aratam。引数を記録し、-c のファイルに bad と書いてあれば終了コード 2
	fake := `echo "$(basename "$0") $*" >>"$RUNNER_TEMP/calls"
echo '{"level":"ERROR","msg":"stderr log"}' >&2
cat >/dev/null # 標準入力 (ループのファイルの一覧) を読んでも、次のファイルが消えない
if grep -q bad "$4"; then exit 2; fi
echo "ok    $4: checked"
`
	bin := t.TempDir()
	for _, name := range []string{"arata", "aratam"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+fake), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tree := func(files map[string]string) string {
		dir := t.TempDir()
		for name, body := range files {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	calls := func(tmp string) string {
		b, _ := os.ReadFile(filepath.Join(tmp, "calls"))
		return string(b)
	}
	multi := map[string]string{
		"aws/prod/arata.yaml": "ok", "aws/prod/aratam.yaml": "ok", "aws/prod/allowlist.yaml": "ok",
		"aws/staging/arata.yaml": "ok", "aws/staging/aratam.yaml": "ok",
		".git/arata.yaml": "bad", "README.md": "ok",
	}
	wantMulti := "arata config check -c ./aws/prod/arata.yaml\naratam config check -c ./aws/prod/aratam.yaml\n" +
		"arata config check -c ./aws/staging/arata.yaml\naratam config check -c ./aws/staging/aratam.yaml\n"

	t.Run("multi", func(t *testing.T) {
		out, code, tmp := runStepIn(t, tree(multi), script, bin)
		if code != 0 || calls(tmp) != wantMulti {
			t.Errorf("exit %d, calls:\n%s\n%s", code, calls(tmp), out)
		}
		if !strings.Contains(out, "ok    ./aws/prod/arata.yaml: checked") || strings.Contains(out, "stderr log") {
			t.Errorf("the result lines must be shown, without the duplicate JSON log:\n%s", out)
		}
	})
	// 1 つが失敗しても残りを検査し、最後に失敗にする (1 回の PR で全部の誤りが分かる)
	for _, file := range []string{"aws/prod/arata.yaml", "aws/staging/aratam.yaml"} {
		t.Run("one fails: "+file, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range multi {
				files[k] = v
			}
			files[file] = "bad"
			_, code, tmp := runStepIn(t, tree(files), script, bin)
			if code != 1 || calls(tmp) != wantMulti {
				t.Errorf("exit %d, calls:\n%s", code, calls(tmp))
			}
		})
	}
	t.Run("nothing to check", func(t *testing.T) {
		out, code, _ := runStepIn(t, tree(map[string]string{"README.md": "ok"}), script, bin)
		if code != 1 || !strings.Contains(out, "::error::") {
			t.Errorf("no config must fail: exit %d\n%s", code, out)
		}
	})
}

// copyTree は src を一時ディレクトリに写す (見本を書き換えて確かめるため)。
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// PR の検査は、一式を書き出したときの引数で arata repo check を流す (ADR 0060)。--github は付けない (PR の検査は、秘密も GitHub を読む鍵も持たない)。
// 偽の出力ではなく、この版の本物の arata で、見本そのものに流して確かめる: 見本は通り、手で直した一式と、Webhook の aratam.yaml は止まる。
func TestCheckRunsRepoCheckOnTheSet(t *testing.T) {
	w, text := load(t, checkFile)
	s := stepByID(t, w, "repo-check")
	want := "arata repo check --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 --schedule --out . </dev/null 2>/dev/null"
	if s.Run != want {
		t.Fatalf("repo-check runs:\n%s\nwant:\n%s", s.Run, want)
	}
	// 設定の検査が落ちても流す (1 回の PR で、全部の誤りが分かる)。バイナリが取れなければ流せない
	if s.If != "always() && steps.install.outcome == 'success'" {
		t.Errorf("if: %q", s.If)
	}
	if strings.Contains(s.Run, "--github") || strings.Contains(text, "GITHUB_TOKEN") || strings.Contains(text, "GH_TOKEN: ${{ secrets") {
		t.Error("the PR check must not read GitHub settings")
	}
	// チャンネル ID (aratam.yaml が持つ) は、ワークフローに入れない
	for _, id := range []string{"C0123456789", "C0123456780", "C0123456781"} {
		if strings.Contains(text, id) {
			t.Errorf("the workflow must not carry the notification channel %s", id)
		}
	}
	bin := realBins(t)
	t.Run("the example passes", func(t *testing.T) {
		out, code, _ := runStepIn(t, copyTree(t, exampleRepo), s.Run, bin)
		if code != 0 || !strings.Contains(out, "ng はありません") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("an edited workflow stops", func(t *testing.T) {
		dir := copyTree(t, exampleRepo)
		p := filepath.Join(dir, ".github/workflows/arata-audit.yml")
		b, _ := os.ReadFile(p)
		if err := os.WriteFile(p, []byte(strings.Replace(string(b), "timeout-minutes: 60", "timeout-minutes: 90", 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		out, code, _ := runStepIn(t, dir, s.Run, bin)
		if code != 2 || !strings.Contains(out, "REPO_SET_DIFFERS") || !strings.Contains(out, ".github/workflows/arata-audit.yml") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("a webhook aratam.yaml stops", func(t *testing.T) {
		dir := copyTree(t, exampleRepo)
		p := filepath.Join(dir, "aws/staging/aratam.yaml")
		b, _ := os.ReadFile(p)
		body := strings.NewReplacer("bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`, `channel: "C0123456781"`, `channel: ""`, `webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ").Replace(string(b))
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		out, code, _ := runStepIn(t, dir, s.Run, bin)
		if code != 2 || !strings.Contains(out, "REPO_NOTIFY_MISMATCH") || !strings.Contains(out, "notify staging の直し方:") || !strings.Contains(out, "bot_token_env: ARATAM_SLACK_BOT_TOKEN") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	// 書き出した設定は、この版の config check もそのまま通る (最初の PR の検査が落ちない)
	t.Run("the example configs pass config check", func(t *testing.T) {
		out, code, _ := runStepIn(t, copyTree(t, exampleRepo), stepByID(t, w, "check").Run, bin)
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}
