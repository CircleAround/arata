package githubactions_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/repoinit"
)

// 秘密の箱 (github/secrets の Terraform) は、秘密の名前を「仮の値」で作る (ADR 0059)。
// ワークフローは、秘密を使う前に仮の値と比べ、一致したら秘密の名前を出して止まる (形が合わずに偶然止まることに頼らない)。
const (
	secretScript     = "../audit-repo/.github/scripts/arata-secret-check.sh"
	secretScriptPath = ".github/scripts/arata-secret-check.sh" // 利用者のリポジトリでの置き場所
)

func runSecretCheck(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	abs, err := filepath.Abs(secretScript)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(abs, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestSecretCheckScript(t *testing.T) {
	if out, err := exec.Command("bash", "-n", secretScript).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
	if fi, err := os.Stat(secretScript); err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("the script must be executable: %v", err)
	}
	ph := repoinit.Placeholder
	real := "arn:aws:iam::123456789012:role/arata-runner"
	cases := []struct {
		name string
		env  []string
		args []string
		exit int
		want []string // 出力に出る名前
	}{
		{"real values", []string{"A_ONE=" + real, "B_TWO=https://hooks.slack.example/x"}, []string{"A_ONE", "B_TWO"}, 0, nil},
		{"placeholder", []string{"A_ONE=" + ph}, []string{"A_ONE"}, 1, []string{"A_ONE"}},
		{"names every placeholder", []string{"A_ONE=" + ph, "B_TWO=" + real, "C_THREE=" + ph}, []string{"A_ONE", "B_TWO", "C_THREE"}, 1, []string{"A_ONE", "C_THREE"}},
		// 空は通す: 使わない送り方の秘密は空で渡され、無い秘密は、使う step がそれぞれの理由で止まる
		{"empty passes", []string{"A_ONE="}, []string{"A_ONE"}, 0, nil},
		{"unset passes", nil, []string{"A_ONE"}, 0, nil},
		// 仮の値を含むだけの値は、仮の値ではない
		{"contains the placeholder", []string{"A_ONE=x" + ph}, []string{"A_ONE"}, 0, nil},
		{"no arguments", nil, nil, 2, nil},
		{"odd name", []string{"A_ONE=" + real}, []string{"A_ONE;id"}, 2, nil},
		{"lowercase name", nil, []string{"path"}, 2, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := runSecretCheck(t, c.env, c.args...)
			if code != c.exit {
				t.Fatalf("exit %d, want %d\n%s", code, c.exit, out)
			}
			for _, n := range c.want {
				if !strings.Contains(out, "::error::秘密 "+n+" が仮の値のまま") {
					t.Errorf("the output must name %s:\n%s", n, out)
				}
			}
			if c.exit == 0 && out != "" {
				t.Errorf("no output when nothing is wrong: %q", out)
			}
			// 値は出さない (本物の値も、仮の値も)
			for _, v := range []string{real, ph, "hooks.slack"} {
				if strings.Contains(out, v) {
					t.Errorf("the output must not show a value: %s", out)
				}
			}
		})
	}
}

// 監査と片付けは、実行用ロールを引き受ける前に、秘密が仮の値のままでないことを確かめる。
// ARATA_ALERT_WEBHOOK は、定時の通知が送れなかったときにしか使わないので、ここで見ないと仮の値のまま気づけない。
func TestWorkflowsStopOnPlaceholderSecretsBeforeAWS(t *testing.T) {
	for file, names := range map[string][]string{
		multiFile:  {"ARATA_RUNNER_ROLE_ARN", "ARATA_AUDIT_ROLE_ARNS", "ARATA_ALERT_WEBHOOK"},
		triageFile: {"ARATA_RUNNER_ROLE_ARN"},
	} {
		t.Run(file, func(t *testing.T) {
			w, _ := load(t, file)
			s := stepByID(t, w, "secrets")
			if s.If != "" {
				t.Errorf("the check must not be conditional: %q", s.If)
			}
			if len(s.Env) != len(names) {
				t.Errorf("env: %v", s.Env)
			}
			for _, n := range names {
				if s.Env[n] != "${{ secrets."+n+" }}" {
					t.Errorf("%s: %q", n, s.Env[n])
				}
			}
			if strings.TrimSpace(s.Run) != secretScriptPath+" "+strings.Join(names, " ") {
				t.Errorf("run: %q", s.Run)
			}
			// checkout (スクリプトがある) より後、実行用ロールの引き受けより前
			order := map[string]int{}
			for i, st := range steps(t, w) {
				order[st.ID] = i
			}
			if !(order["checkout"] < order["secrets"] && order["secrets"] < order["aws"]) {
				t.Errorf("order: %v", order)
			}
			env := []string{}
			for _, n := range names {
				env = append(env, n+"=real-value")
			}
			if out, code, _ := runStep(t, s.Run, t.TempDir(), env...); code != 0 {
				t.Errorf("real values: exit %d\n%s", code, out)
			}
			env[len(env)-1] = names[len(names)-1] + "=" + repoinit.Placeholder
			out, code, _ := runStep(t, s.Run, t.TempDir(), env...)
			if code != 1 || !strings.Contains(out, "秘密 "+names[len(names)-1]+" が仮の値のまま") {
				t.Errorf("placeholder: exit %d\n%s", code, out)
			}
		})
	}
}

// 通知する step (監査の notify、試しの通知) は、使う送り方の秘密が仮の値のままなら、aratam を呼ばずに止まる。
// 使わない送り方の秘密は空で渡されるので、箱が仮の値のままでも止まらない。
func TestNotifyStopsOnPlaceholderSlackSecrets(t *testing.T) {
	for file, id := range map[string]string{multiFile: "notify", notifyTestFile: "test-notify"} {
		t.Run(file, func(t *testing.T) {
			w, _ := load(t, file)
			s := stepByID(t, w, id)
			if !strings.Contains(s.Run, secretScriptPath+" ARATAM_SLACK_WEBHOOK ARATAM_SLACK_URGENT_WEBHOOK ARATAM_SLACK_BOT_TOKEN\n") {
				t.Fatalf("the step must check its Slack secrets first:\n%s", s.Run)
			}
			bin := fakeBin(t, "aratam", `touch "$RUNNER_TEMP/called"`+"\n")
			ph := repoinit.Placeholder
			// Webhook の方式: bot トークンは空で渡る
			out, code, tmp := runStep(t, s.Run, bin, "ROUTE=normal", "ARATAM_SLACK_WEBHOOK=https://hooks.slack.example/a", "ARATAM_SLACK_URGENT_WEBHOOK=https://hooks.slack.example/b", "ARATAM_SLACK_BOT_TOKEN=")
			if _, err := os.Stat(filepath.Join(tmp, "called")); code != 0 || err != nil {
				t.Errorf("real values must reach aratam: exit %d\n%s", code, out)
			}
			out, code, tmp = runStep(t, s.Run, bin, "ROUTE=normal", "ARATAM_SLACK_WEBHOOK=https://hooks.slack.example/a", "ARATAM_SLACK_URGENT_WEBHOOK="+ph, "ARATAM_SLACK_BOT_TOKEN=")
			if _, err := os.Stat(filepath.Join(tmp, "called")); code != 1 || err == nil || !strings.Contains(out, "秘密 ARATAM_SLACK_URGENT_WEBHOOK が仮の値のまま") {
				t.Errorf("a placeholder must stop the step before aratam: exit %d\n%s", code, out)
			}
			// 止まったときは、Slack に届いた印 (delivered) を付けない (定時なら、最後の alert が知らせる)
			if got := output(t, tmp); got != "" {
				t.Errorf("GITHUB_OUTPUT %q", got)
			}
		})
	}
}
