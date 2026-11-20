package githubactions_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// collectFile は、取得だけ (arata collect --incremental) を短い間隔で回す見本 (ADR 0078)。見本の引数は --collect-every 1h。
const collectFile = "arata-collect.yml"

// 取得のワークフローは監査と同じストアへ書くので、監査と同じ group で順番に待つ。別の group だと、取得と daily が同時に確定し、
// 後から確定した方 (daily なら、その日の判定と通知) が STORE_CONFLICT で失われる。待ちは取り消さない (queue: max。既定の single だと、
// 取得の待ちが、待っていた daily を取り消す)。
func TestCollectSharesTheGroupOfTheAudit(t *testing.T) {
	w, _ := load(t, collectFile)
	audit, _ := load(t, multiFile)
	if w.Concurrency.Group != "" {
		t.Errorf("a workflow-level group would queue the whole matrix behind one run: %+v", w.Concurrency)
	}
	j, ok := w.Jobs["collect"]
	if !ok || len(w.Jobs) != 1 {
		t.Fatalf("want one job named collect: %v", w.Jobs)
	}
	want := strings.Replace(audit.Jobs["audit"].Concurrency.Group, dryRunGroupSuffix, "", 1)
	if c := j.Concurrency; c.Group != want || !strings.Contains(want, "${{ matrix.account }}") || c.CancelInProgress == nil || *c.CancelInProgress || c.Queue != "max" {
		t.Errorf("concurrency must be the group of the audit (%q), must not cancel and must keep every pending run: %+v", want, c)
	}
	if strings.Join(j.Strategy.Matrix.Account, ",") != strings.Join(audit.Jobs["audit"].Strategy.Matrix.Account, ",") || j.Strategy.FailFast == nil || *j.Strategy.FailFast {
		t.Errorf("matrix must be the accounts of the audit, without fail-fast: %+v", j.Strategy)
	}
	if p := j.Permissions; len(p) != 2 || p["id-token"] != "write" || p["contents"] != "read" {
		t.Errorf("permissions must be id-token: write and contents: read only: %v", p)
	}
	for k, v := range map[string]string{"ACCOUNT": "${{ matrix.account }}", "ARATA_CONFIG_DIR": "aws/${{ matrix.account }}"} {
		if j.Env[k] != v {
			t.Errorf("job env %s = %q, want %q", k, j.Env[k], v)
		}
	}
	if w.Env["ARATA_VERSION"] != audit.Env["ARATA_VERSION"] || w.Env["AWS_REGION"] != audit.Env["AWS_REGION"] {
		t.Errorf("env must be the same as the audit: %v / %v", w.Env, audit.Env)
	}
	if j.TimeoutMinutes != audit.Jobs["audit"].TimeoutMinutes {
		t.Errorf("timeout-minutes: %d", j.TimeoutMinutes)
	}
}

// 準備の step (取得と照合、秘密の確かめ、OIDC、監査ロールのプロファイル) は、監査とそのまま同じにする (片方だけを直す誤りを止める)。
func TestCollectSharesStepsWithAudit(t *testing.T) {
	w, _ := load(t, collectFile)
	audit, _ := load(t, multiFile)
	for _, id := range []string{"checkout", "install", "secrets", "aws", "aws-config"} {
		x, _ := yaml.Marshal(stepByID(t, audit, id))
		y, _ := yaml.Marshal(stepByID(t, w, id))
		if string(x) != string(y) {
			t.Errorf("step %q differs from %s:\n%s\n---\n%s", id, multiFile, y, x)
		}
	}
	var ids []string
	for _, s := range steps(t, w) {
		ids = append(ids, s.ID)
	}
	if strings.Join(ids, ",") != "checkout,install,secrets,aws,aws-config,collect" {
		t.Errorf("steps: %v (the collection does not evaluate, report nor notify)", ids)
	}
}

// 取得は Slack に送らないので、秘密は認証の 2 つだけ (Slack のトークンを渡さない)。
func TestCollectUsesOnlyTheAWSSecrets(t *testing.T) {
	_, text := load(t, collectFile)
	got := map[string]bool{}
	for _, m := range regexp.MustCompile(`secrets\.(\w+)`).FindAllStringSubmatch(text, -1) {
		got[m[1]] = true
	}
	if len(got) != 2 || !got["ARATA_RUNNER_ROLE_ARN"] || !got["ARATA_AUDIT_ROLE_ARNS"] {
		t.Errorf("secrets: %v", got)
	}
	for _, bad := range []string{"aratam notify", "chat.postMessage", "SLACK", "--profile", "arata run"} {
		if strings.Contains(text, bad) {
			t.Errorf("the collect workflow must not mention %q", bad)
		}
	}
}

// cron は毎時ちょうどを避け、記録の遅れ (CloudTrail の ingest_delay の既定 15 分) より後の分にし、24 時間を割り切る間隔で 0 時を含む
// (daily の前に 1 回入る)。監査の cron と同じ分にしない。手動でも動かせる。
func TestCollectSchedule(t *testing.T) {
	w, _ := load(t, collectFile)
	audit, _ := load(t, multiFile)
	if len(w.On.Schedule) != 1 {
		t.Fatalf("want one cron: %+v", w.On.Schedule)
	}
	f := strings.Fields(w.On.Schedule[0].Cron)
	if len(f) != 5 || f[2] != "*" || f[3] != "*" || f[4] != "*" {
		t.Fatalf("bad cron %q", w.On.Schedule[0].Cron)
	}
	minute, err := strconv.Atoi(f[0])
	if err != nil || minute <= 15 || minute >= 60 {
		t.Errorf("minute %q must be a fixed minute after the ingest delay (15m)", f[0])
	}
	if f[1] != "*" {
		n, err := strconv.Atoi(strings.TrimPrefix(f[1], "*/"))
		if err != nil || !strings.HasPrefix(f[1], "*/") || n < 2 || 24%n != 0 {
			t.Errorf("hour %q must be * or */N with N dividing 24 (so that it runs at 0 o'clock)", f[1])
		}
	}
	dailyMinute, _ := strconv.Atoi(strings.Fields(audit.On.Schedule[0].Cron)[0])
	dailyHour, _ := strconv.Atoi(strings.Fields(audit.On.Schedule[0].Cron)[1])
	if dailyHour != 0 || minute >= dailyMinute {
		t.Errorf("the collection at 0:%02d must come before the daily (%s)", minute, audit.On.Schedule[0].Cron)
	}
	for _, c := range audit.On.Schedule {
		if strings.Fields(c.Cron)[0] == f[0] {
			t.Errorf("the collection must not share the minute of %q", c.Cron)
		}
	}
	if got := triggers(t, collectFile); len(got) != 2 {
		t.Errorf("triggers: %v (schedule and workflow_dispatch)", got)
	}
	if len(w.On.WorkflowDispatch.Inputs) != 0 {
		t.Errorf("workflow_dispatch takes no inputs: %v", w.On.WorkflowDispatch.Inputs)
	}
}

// 取得の step: 引数は collect --incremental と設定だけ。ログには INFO 以外の level / code / source だけを出す。
// 終了コード 3 (一部が取れなかった・max_collect に当たった) は警告にして成功にし、ほかの失敗はそのまま返す。
func TestCollectStepLogsOnlyCodesAndTreatsPartialAsWarning(t *testing.T) {
	w, _ := load(t, collectFile)
	s := stepByID(t, w, "collect")
	if s.TimeoutMinutes == 0 || s.TimeoutMinutes >= 60 || s.ContinueOnErr != nil || s.If != "" {
		t.Errorf("the collect step needs a timeout within the credentials (1h), and must fail the job: %+v", s)
	}
	for exit, want := range map[int]int{0: 0, 1: 1, 2: 2, 3: 0, 130: 130} {
		t.Run(fmt.Sprintf("exit=%d", exit), func(t *testing.T) {
			bin := fakeBin(t, "arata", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\n"+leakyLog+fmt.Sprintf("exit %d\n", exit))
			out, code, tmp := runStep(t, s.Run, bin, "ARATA_CONFIG_DIR=aws/prod")
			if code != want {
				t.Errorf("exit code: got %d want %d\n%s", code, want, out)
			}
			if warned := strings.Contains(out, "::warning::"); warned != (exit == 3) {
				t.Errorf("warning=%v for exit %d:\n%s", warned, exit, out)
			}
			for _, secret := range []string{"123456789012", "alice@example.com", "collect ok", "report body"} {
				if strings.Contains(out, secret) {
					t.Errorf("leaked %q:\n%s", secret, out)
				}
			}
			if !strings.Contains(out, "STORE_CONFLICT") {
				t.Errorf("the error code must stay visible:\n%s", out)
			}
			args, err := os.ReadFile(filepath.Join(tmp, "args"))
			if err != nil || string(args) != "collect\n--incremental\n-c\naws/prod/arata.yaml\n" {
				t.Errorf("args: %q %v", args, err)
			}
		})
	}
}
