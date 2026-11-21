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
	// high 以上の ack の守りを越える入力 (ADR 0068 の 2 節)。既定は false で、理由は今も必須
	if f, ok := in["force"]; !ok || f.Type != "boolean" || f.Required || f.Default != false {
		t.Errorf("force must be an optional boolean defaulting to false: %+v", f)
	}
	// 試し (ADR 0068 の 8 節): ストアを変えずに、何をどう変えるかと守りの結果だけを見る
	if f, ok := in["dry_run"]; !ok || f.Type != "boolean" || f.Required || f.Default != false {
		t.Errorf("dry_run must be an optional boolean defaulting to false: %+v", f)
	}
	j := w.Jobs["triage"]
	// 定時の監査 (書き込む実行) と同じ group (アカウントごと) で、順番に動かす。試しの実行の group は別 (ストアに書かない。dryrun_test.go)
	want := strings.Replace(strings.Replace(multi.Jobs["audit"].Concurrency.Group, dryRunGroupSuffix, "", 1), "matrix.account", "inputs.account", 1)
	if c := j.Concurrency; c.Group != want || !strings.Contains(want, "inputs.account") || c.CancelInProgress == nil || *c.CancelInProgress || c.Queue != "max" {
		t.Errorf("concurrency must be the group of the audit (%q) and must queue: %+v", want, c)
	}
	if p := j.Permissions; len(p) != 2 || p["id-token"] != "write" || p["contents"] != "read" {
		t.Errorf("permissions must be id-token: write and contents: read only: %v", p)
	}
	for k, v := range map[string]string{"ACCOUNT": "${{ inputs.account }}", "ARATA_CONFIG_DIR": "aws/${{ inputs.account }}", "ACTION": "${{ inputs.action }}",
		"FINDING_ID": "${{ inputs.finding_id }}", "REASON": "${{ inputs.reason }}", "UNTIL": "${{ inputs.until }}", "FORCE": "${{ inputs.force }}", "DRY_RUN": "${{ inputs.dry_run }}"} {
		if j.Env[k] != v {
			t.Errorf("job env %s = %q, want %q", k, j.Env[k], v)
		}
	}
	// secrets は実行用ロールの ARN だけ (仮の値でないことを確かめる step と、引き受ける step の 2 か所)。Slack にも監査ロールにも用が無い
	if got := regexp.MustCompile(`secrets\.\w+`).FindAllString(text, -1); len(got) != 2 || got[0] != "secrets.ARATA_RUNNER_ROLE_ARN" || got[1] != got[0] {
		t.Errorf("secrets: %v", got)
	}
	// 分けて確かめた ID の並びは、validate の出力 (12 桁の 16 進を空白で区切ったもの) から後の step に渡す (入力を分け直さない)
	for _, id := range []string{"finding", "triage", "summary"} {
		if s := stepByID(t, w, id); s.Env["FINDING_IDS"] != "${{ steps.validate.outputs.ids }}" {
			t.Errorf("step %s must take the ids from the validate step: %v", id, s.Env)
		}
	}
	order := map[string]int{}
	for i, s := range steps(t, w) {
		order[s.ID] = i
	}
	// 入力は認証より先に確かめる
	if !(order["validate"] < order["aws"] && order["install"] < order["aws"] && order["aws"] < order["finding"] && order["finding"] < order["triage"] && order["triage"] < order["summary"]) {
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
	env := map[string]string{"ACCOUNT": "prod", "ARATA_CONFIG_DIR": "aws/prod", "ACTION": "ack", "FINDING_ID": "0123456789ab", "FINDING_IDS": "0123456789ab", "REASON": "既知の作業", "UNTIL": "", "FORCE": "false", "DRY_RUN": "false"}
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
		{"FORCE", "true"},
		// 画面から実行しない (API) と、boolean の入力は空で届くことがある
		{"FORCE", ""},
		{"DRY_RUN", "true"},
		{"DRY_RUN", ""},
		{"DRY_RUN", "true", "ACTION", "snooze", "UNTIL", "2027-03-31"},
		// 複数の ID (ADR 0080)。空白かカンマで区切る。上限まで
		{"FINDING_ID", "0123456789ab ffffffffffff"},
		{"FINDING_ID", "0123456789ab,ffffffffffff, a1b2c3d4e5f6 ,"},
		{"FINDING_ID", "0123456789ab\tffffffffffff\na1b2c3d4e5f6"},
		{"FINDING_ID", manyIDs(100, ",")},
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
		"only separators":      {"FINDING_ID", " , ,"},
		"one bad among many":   {"FINDING_ID", "0123456789ab,ffffffffffff,0123456789AB"},
		"duplicate id":         {"FINDING_ID", "0123456789ab ffffffffffff 0123456789ab"},
		"ideographic space":    {"FINDING_ID", "0123456789ab\u3000ffffffffffff"},
		"too many ids":         {"FINDING_ID", manyIDs(101, " ")},
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
		// 操作した人は arata の --by の形 (ADR 0068)。bot からの実行は受け付けない
		"force on snooze":  {"ACTION", "snooze", "UNTIL", "2027-03-31", "FORCE", "true"},
		"force on resolve": {"ACTION", "resolve", "FORCE", "true"},
		"force not bool":   {"FORCE", "yes"},
		"dry_run not bool": {"DRY_RUN", "1"},
		"bot actor":        {"GITHUB_ACTOR", "github-actions[bot]"},
		"empty actor":      {"GITHUB_ACTOR", ""},
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

func manyIDs(n int, sep string) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%012x", i)
	}
	return strings.Join(ids, sep)
}

// ID の並びの分け方は arata (engine.ParseFindingIDs) と同じ: 受け付けるかどうかと、分けた並びが一致する。
// 分けた並びを validate の出力 ids に書き、後の step はそれを使う。止めたときは、通らない値の位置と重複した ID を全部出す (値そのものは写さない)。
func TestTriageSplitsIDsLikeArata(t *testing.T) {
	w, _ := load(t, triageFile)
	script := stepByID(t, w, "validate").Run
	for _, in := range []string{"0123456789ab", "0123456789ab ffffffffffff", " 0123456789ab,,ffffffffffff\t\n", "0123456789ab,ffffffffffff,0123456789ab",
		"0123456789ab\rffffffffffff", "0123456789ab\u3000ffffffffffff", "0123456789ab;ffffffffffff", ",", manyIDs(100, ","), manyIDs(101, ","), "-0123456789ab"} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			want, werr := engine.ParseFindingIDs([]string{in})
			out, code, tmp := runStep(t, script, t.TempDir(), triageEnv("FINDING_ID", in)...)
			if (werr == nil) != (code == 0) {
				t.Fatalf("arata %v, workflow exit %d\n%s", werr, code, out)
			}
			b, _ := os.ReadFile(filepath.Join(tmp, "github_output"))
			if werr != nil {
				if strings.Contains(string(b), "ids=") {
					t.Errorf("no ids on failure: %q", b)
				}
				return
			}
			if string(b) != "ids="+strings.Join(want, " ")+"\n" {
				t.Errorf("output %q, want the ids %v", b, want)
			}
		})
	}
	out, _, _ := runStep(t, script, t.TempDir(), triageEnv("FINDING_ID", "0123456789ab,--help,ffffffffffff,0123456789ab,x y")...)
	for _, w := range []string{"2 番目", "5 番目", "6 番目", "0123456789ab が 2 回"} {
		if !strings.Contains(out, w) {
			t.Errorf("the error lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "--help") {
		t.Errorf("a bad value must not be echoed:\n%s", out)
	}
}

func TestTriageRunsArataWithExpectedArguments(t *testing.T) {
	w, _ := load(t, triageFile)
	script := stepByID(t, w, "triage").Run
	bin := fakeBin(t, "arata", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\necho '{\"schema\":\"triage-result\"}'\n")
	for name, tc := range map[string]struct {
		kv   []string
		want string
	}{
		"ack":     {nil, "ack\n-c\naws/prod/arata.yaml\n--format\njson\n--reason\n既知の作業\n--by\nalice\n0123456789ab\n"},
		"resolve": {[]string{"ACTION", "resolve", "ACCOUNT", "staging", "ARATA_CONFIG_DIR", "aws/staging"}, "resolve\n-c\naws/staging/arata.yaml\n--format\njson\n--reason\n既知の作業\n--by\nalice\n0123456789ab\n"},
		"snooze":  {[]string{"ACTION", "snooze", "UNTIL", "2027-03-31"}, "snooze\n-c\naws/prod/arata.yaml\n--until\n2027-03-31\n--format\njson\n--reason\n既知の作業\n--by\nalice\n0123456789ab\n"},
		// 理由はそのまま 1 つの引数として渡す (シェルに解釈させない)。形の検査は arata が行う (ADR 0068)
		"ack dry run": {[]string{"DRY_RUN", "true"}, "ack\n-c\naws/prod/arata.yaml\n--dry-run\n--format\njson\n--reason\n既知の作業\n--by\nalice\n0123456789ab\n"},
		"ack force":   {[]string{"FORCE", "true"}, "ack\n-c\naws/prod/arata.yaml\n--force\n--format\njson\n--reason\n既知の作業\n--by\nalice\n0123456789ab\n"},
		// 複数の ID は 1 つずつの引数で、最後に渡す (ADR 0080)
		"many":           {[]string{"FINDING_IDS", "0123456789ab ffffffffffff a1b2c3d4e5f6"}, "ack\n-c\naws/prod/arata.yaml\n--format\njson\n--reason\n既知の作業\n--by\nalice\n0123456789ab\nffffffffffff\na1b2c3d4e5f6\n"},
		"hostile reason": {[]string{"REASON", "$(touch pwned) `id` --force"}, "ack\n-c\naws/prod/arata.yaml\n--format\njson\n--reason\n$(touch pwned) `id` --force\n--by\nalice\n0123456789ab\n"},
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
			// 結果 (--format json) は実行環境の一時ファイルに置き、Summary の step が読む。ログには出さない
			if r, _ := os.ReadFile(filepath.Join(tmp, "triage.json")); !strings.Contains(string(r), "triage-result") || strings.Contains(out, "triage-result") {
				t.Errorf("triage.json %q, log:\n%s", r, out)
			}
		})
	}
}

// high 以上の ack を arata が止めたら (ACK_REFUSED)、ログに案内を出し、Summary の step に知らせる。終了コードは保つ (ADR 0068)。
func TestTriageGuidesWhenAckIsRefused(t *testing.T) {
	w, _ := load(t, triageFile)
	refused := `echo '{"level":"ERROR","msg":"ack refused at arn:aws:iam::123456789012:root","code":"ACK_REFUSED","finding":"0123456789ab","check":"secret_access","severity":"high","error":"alice@example.com"}' >&2
echo 'finding 0123456789ab は重大度 high なので ack できません'
exit 2
`
	out, code, tmp := runStep(t, stepByID(t, w, "triage").Run, fakeBin(t, "arata", refused), triageEnv()...)
	if code != 2 {
		t.Fatalf("exit code must be kept: %d\n%s", code, out)
	}
	for _, want := range []string{"::error::", "ACK_REFUSED", "snooze", "resolve", "allowlist.yaml", "force", "arata help ai playbook"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"123456789012", "alice@example.com"} {
		if strings.Contains(out, secret) {
			t.Errorf("leaked %q:\n%s", secret, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(tmp, "github_output")); !strings.Contains(string(b), "refused=true") {
		t.Errorf("the summary step must learn the refusal: %q", b)
	}
	// 止められなかったときは知らせない
	_, _, tmp = runStep(t, stepByID(t, w, "triage").Run, fakeBin(t, "arata", "exit 0\n"), triageEnv()...)
	if b, _ := os.ReadFile(filepath.Join(tmp, "github_output")); strings.Contains(string(b), "refused=true") {
		t.Errorf("no refusal: %q", b)
	}

	s := stepByID(t, w, "summary")
	if s.Env["REFUSED"] != "${{ steps.triage.outputs.refused }}" {
		t.Errorf("REFUSED: %v", s.Env)
	}
	_, _, tmp = runStep(t, s.Run, t.TempDir(), append(triageEnv("FORCE", "true"), "RESULT=failure", "REFUSED=true")...)
	sum, _ := os.ReadFile(filepath.Join(tmp, "summary"))
	for _, want := range []string{"| force | `true` |", "high", "snooze", "resolve", "allowlist.yaml", "arata help ai playbook"} {
		if !strings.Contains(string(sum), want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
}

// 指摘の中身 (check・重大度・状態・初出・要約・Key) を、操作の前にストアから引いて Summary に出す (ID の取り違えに気づけるように。ADR 0068 の 8 節)。
// 引くのは機械が読む出力 (review --format json)。ログには出さない。引けなくても片付けは止めない。
func TestTriageShowsTheFinding(t *testing.T) {
	w, _ := load(t, triageFile)
	step := stepByID(t, w, "finding")
	review := `printf '%s\n' "$@" >"$RUNNER_TEMP/review-args"
echo '{"level":"INFO","msg":"opened","source":"store"}' >&2
cat <<'JSON'
[{"id":"0123456789ab","check":"secret_access","key":"arn:aws:iam::123456789012:role/app","severity":"high","status":"open","summary":"秘匿値の一括読み出し: arn:aws:iam::123456789012:role/app が 13 個","first_seen":"2026-10-20T01:00:00Z","last_seen":"2026-10-20T01:00:00Z","data":{"secrets":["prod/db"]},"triage":{"allowed":["snooze","resolve"]}},
 {"id":"ffffffffffff","check":"posture","key":"root_mfa","severity":"high","status":"open","summary":"x","first_seen":"2026-10-20T01:00:00Z","last_seen":"2026-10-20T01:00:00Z","data":{}}]
JSON
`
	out, code, tmp := runStep(t, step.Run, fakeBin(t, "arata", review), triageEnv("FINDING_IDS", "0123456789ab a1b2c3d4e5f6")...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, "123456789012") || strings.Contains(out, "秘匿値") {
		t.Errorf("the finding must not reach the log:\n%s", out)
	}
	args, _ := os.ReadFile(filepath.Join(tmp, "review-args"))
	if string(args) != "review\n-c\naws/prod/arata.yaml\n--format\njson\n--status\nopen,acked,snoozed,resolved\n" {
		t.Errorf("review args:\n%s", args)
	}
	// 渡した ID のものだけを、ID ごとに引く (ストアに無い ID は載らない)
	b, err := os.ReadFile(filepath.Join(tmp, "finding.json"))
	if err != nil || !strings.Contains(string(b), `{"0123456789ab":{"check":"secret_access"`) || strings.Contains(string(b), "posture") || strings.Contains(string(b), "prod/db") || strings.Contains(string(b), "a1b2c3d4e5f6") {
		t.Fatalf("finding.json: %v %s", err, b)
	}
	// review が失敗しても片付けは止めない (Summary に「引けなかった」と出る)
	out, code, tmp = runStep(t, step.Run, fakeBin(t, "arata", leakyLog+"exit 2\n"), triageEnv()...)
	if code != 0 || strings.Contains(out, "123456789012") {
		t.Errorf("a failed lookup must not stop the triage nor leak: exit %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(tmp, "finding.json")); len(strings.TrimSpace(string(b))) != 0 {
		t.Errorf("no finding on failure: %q", b)
	}

	// Summary: 12 桁の数字 (アカウント ID) は伏せ、値はコードの中に入れる
	s := stepByID(t, w, "summary")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "finding.json"), []byte(`{"0123456789ab":{"check":"secret_access","key":"arn:aws:iam::123456789012:role/app|x","severity":"high","status":"open","first_seen":"2026-10-20T01:00:00Z","summary":"a `+"`"+`b\nc 123456789012"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, tmp = runStep(t, s.Run, t.TempDir(), append(triageEnv("DRY_RUN", "true"), "RESULT=success", "RUNNER_TEMP="+dir)...)
	sum, _ := os.ReadFile(filepath.Join(tmp, "summary"))
	for _, want := range []string{"`secret_access`", "`high`", "`open`", "`2026-10-20T01:00:00Z`", "arn:aws:iam::************:role/app|x", "試し", "ストアは変えていない"} {
		if !strings.Contains(string(sum), want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	if regexp.MustCompile(`[0-9]{12}`).Match(sum) || strings.Contains(string(sum), "a `b") {
		t.Errorf("summary must mask 12 digits and keep values inside code:\n%s", sum)
	}
	// 引けなかったとき
	_, _, tmp = runStep(t, s.Run, t.TempDir(), append(triageEnv(), "RESULT=success", "RUNNER_TEMP="+t.TempDir())...)
	if sum, _ := os.ReadFile(filepath.Join(tmp, "summary")); !strings.Contains(string(sum), "引けなかった") || strings.Contains(string(sum), "試し") {
		t.Errorf("summary without the finding:\n%s", sum)
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

// 誰が・何を・なぜ、は Summary にも残す (ストアにも残る。ADR 0068)。
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
	if strings.Count(sum, "```") != 2 || !strings.Contains(sum[strings.Index(sum, "```"):strings.LastIndex(sum, "```")], "検証の作業") {
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
	want := "arata repo check --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 --schedule --collect-every 1h --flash --out . </dev/null 2>/dev/null"
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
	// --flash の一式で、hourly の重大度の下限が無い arata.yaml は止まり、足す行が出る (ADR 0082 の 5 節)
	t.Run("an hourly profile without min_severity stops", func(t *testing.T) {
		dir := copyTree(t, exampleRepo)
		p := filepath.Join(dir, "aws/prod/arata.yaml")
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), "\n    min_severity: high ") {
			t.Fatal("the example must write min_severity: high in the hourly profile")
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(b), "\n    min_severity: high ", "\n    # min_severity: high ", 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		out, code, _ := runStepIn(t, dir, s.Run, bin)
		if code != 2 || !strings.Contains(out, "REPO_FLASH_PROFILE") || !strings.Contains(out, "    min_severity: high") {
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

// 複数の ID では、Summary に ID ごとの中身 (操作の前) と結果 (arata の --format json) を出す (ADR 0080)。
// 値はログ由来・利用者の入力なので、コードの中に入れ、12 桁の数字を伏せ、長い値は切る。
func TestTriageSummaryPerID(t *testing.T) {
	w, _ := load(t, triageFile)
	s := stepByID(t, w, "summary")
	dir := t.TempDir()
	long := strings.Repeat("x", 500)
	files := map[string]string{
		"finding.json": `{"0123456789ab":{"check":"secret_access","key":"arn:aws:iam::123456789012:role/app","severity":"high","status":"open","first_seen":"2026-10-20T01:00:00Z","summary":"` + long + `"},
"ffffffffffff":{"check":"posture","key":"root_mfa","severity":"low","status":"acked","first_seen":"2026-10-19T01:00:00Z","summary":"s"}}`,
		"triage.json": `{"schema":"triage-result","schema_version":1,"action":"ack","dry_run":false,"written":false,"items":[
{"id":"0123456789ab","result":"refused","check":"secret_access","severity":"high","before":"open","forced":false,"code":"ACK_REFUSED","error":"x 123456789012"},
{"id":"ffffffffffff","result":"not_written","check":"posture","severity":"low","before":"acked","after":"acked","forced":false},
{"id":"a1b2c3d4e5f6","result":"refused","forced":false,"code":"CONFIG_INVALID"}]}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := append(triageEnv("FINDING_ID", "0123456789ab,ffffffffffff,a1b2c3d4e5f6", "FINDING_IDS", "0123456789ab ffffffffffff a1b2c3d4e5f6"), "RESULT=failure", "REFUSED=true", "RUNNER_TEMP="+dir)
	out, code, tmp := runStep(t, s.Run, t.TempDir(), env...)
	if code != 0 || strings.TrimSpace(out) != "" {
		t.Fatalf("exit %d\n%s", code, out)
	}
	b, _ := os.ReadFile(filepath.Join(tmp, "summary"))
	sum := string(b)
	for _, want := range []string{"| findings | 3 件 |",
		"`0123456789ab`", "`refused`", "`ACK_REFUSED`", "`secret_access`", "`high`",
		"`ffffffffffff`", "`not_written`", "`acked`", "`posture`",
		"`a1b2c3d4e5f6`", "`CONFIG_INVALID`", "引けなかった",
		"何も書いていない"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	// ID の順に並ぶ
	if i, j, k := strings.Index(sum, "`0123456789ab`"), strings.Index(sum, "`ffffffffffff`"), strings.Index(sum, "`a1b2c3d4e5f6`"); !(i < j && j < k) {
		t.Errorf("order of the ids:\n%s", sum)
	}
	if regexp.MustCompile(`[0-9]{12}`).MatchString(strings.NewReplacer("0123456789ab", "", "ffffffffffff", "").Replace(sum)) || strings.Contains(sum, long) {
		t.Errorf("summary must mask 12 digits and cut long values:\n%s", sum)
	}
	// 結果が読めない (arata が JSON を出す前に止まった) ときも、ID ごとの行は出る
	if err := os.WriteFile(filepath.Join(dir, "triage.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, code, tmp = runStep(t, s.Run, t.TempDir(), env...)
	b, _ = os.ReadFile(filepath.Join(tmp, "summary"))
	if code != 0 || !strings.Contains(string(b), "`a1b2c3d4e5f6`") || !strings.Contains(string(b), "結果は不明") {
		t.Errorf("exit %d, summary without the result:\n%s", code, b)
	}
}
