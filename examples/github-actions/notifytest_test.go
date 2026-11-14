package githubactions_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/notify"
	"github.com/CircleAround/arata/internal/slack"
)

// 送信テストの見本 (arata-notify-test.yml): 監査を回さずに、Slack への通知の経路だけを確かめる。
const notifyTestFile = "arata-notify-test.yml"

func TestNotifyTestTriggerAndInputs(t *testing.T) {
	w, _ := load(t, notifyTestFile)
	if got := triggers(t, notifyTestFile); len(got) != 1 || got[0] != "workflow_dispatch" {
		t.Fatalf("notify-test must run only by workflow_dispatch: %v", got)
	}
	in := w.On.WorkflowDispatch.Inputs
	multi, _ := load(t, multiFile)
	if a := in["account"]; a.Type != "choice" || !a.Required || strings.Join(a.Options, ",") != strings.Join(multi.Jobs["audit"].Strategy.Matrix.Account, ",") {
		t.Errorf("account must be a choice of the accounts of %s: %+v", multiFile, a)
	}
	if r := in["route"]; r.Type != "choice" || !r.Required || strings.Join(r.Options, ",") != "normal,urgent,alert" {
		// 見本は知らせのチャンネルを使う (--alert-channel)。alert は、その知らせの送り方の確認 (ADR 0060)
		t.Errorf("route must be a choice of normal, urgent, alert: %+v", r)
	}
	if len(in) != 2 {
		t.Errorf("inputs must be account and route only: %v", in)
	}
	j, ok := w.Jobs["notify-test"]
	if !ok {
		t.Fatalf("no job notify-test")
	}
	if j.TimeoutMinutes == 0 || j.TimeoutMinutes > 10 {
		t.Errorf("the job needs a short timeout: %d", j.TimeoutMinutes)
	}
	for k, v := range map[string]string{"ACCOUNT": "${{ inputs.account }}", "ARATA_CONFIG_DIR": "aws/${{ inputs.account }}", "ROUTE": "${{ inputs.route }}"} {
		if j.Env[k] != v {
			t.Errorf("job env %s = %q, want %q", k, j.Env[k], v)
		}
	}
	// 版は監査と同じ (違う版の aratam で確かめても、定時の通知が届くことにならない)
	if w.Env["ARATA_VERSION"] == "" || w.Env["ARATA_VERSION"] != multi.Env["ARATA_VERSION"] {
		t.Errorf("ARATA_VERSION must be the version of %s (%q): %q", multiFile, multi.Env["ARATA_VERSION"], w.Env["ARATA_VERSION"])
	}
	order := map[string]int{}
	for i, s := range steps(t, w) {
		order[s.ID] = i
	}
	// 入力は、設定の checkout やバイナリの取得より先に確かめる
	if !(order["validate"] < order["checkout"] && order["checkout"] < order["install"] && order["install"] < order["test-notify"]) {
		t.Errorf("step order: %v", order)
	}
	if s := stepByID(t, w, "test-notify"); s.ContinueOnErr != nil || s.TimeoutMinutes == 0 || s.If != "inputs.route != 'alert'" {
		t.Errorf("a failed send must leave the job red, with a timeout: %+v", s)
	}
	// 監査はしない。ストアにも監査対象にも触れない
	for _, s := range steps(t, w) {
		if regexp.MustCompile(`\barata\s+(run|init|ack|snooze|resolve|approve)\b|\baratam\s+notify\b|\baws\s+s3\b`).MatchString(s.Run) {
			t.Errorf("step %q must not audit or touch the store", s.ID)
		}
	}
}

// test-notify は Slack に送るだけで、AWS にも LLM にも繋がない (cmd/aratam の newTestNotifyCmd)。
// OIDC も実行用ロールも要らないので、権限は contents: read だけにする。
func TestNotifyTestNeedsNoAWSCredentials(t *testing.T) {
	w, text := load(t, notifyTestFile)
	if p := w.Jobs["notify-test"].Permissions; len(p) != 1 || p["contents"] != "read" {
		t.Errorf("permissions must be contents: read only: %v", p)
	}
	for _, bad := range []string{"id-token", "configure-aws-credentials", "role-to-assume", "AWS_REGION", "AWS_CONFIG_FILE", "ARATA_RUNNER_ROLE_ARN", "ARATA_AUDIT_ROLE_ARN"} {
		if strings.Contains(text, bad) {
			t.Errorf("notify-test must not use %s", bad)
		}
	}
	if c := w.Jobs["notify-test"].Concurrency; c.Group != "" || w.Concurrency.Group != "" {
		t.Errorf("notify-test does not write the store, so it must not queue behind the audit: %+v", c)
	}
}

// Slack の秘密の渡し方は監査の notify と同じ (片方だけを直して食い違うのを防ぐ)。渡すのは bot トークンだけ (ADR 0060)。
func TestNotifyTestPassesSlackSecretsLikeTheAudit(t *testing.T) {
	w, text := load(t, notifyTestFile)
	for _, f := range workflowFiles {
		audit, _ := load(t, f)
		x, _ := yaml.Marshal(stepByID(t, audit, "notify").Env)
		y, _ := yaml.Marshal(stepByID(t, w, "test-notify").Env)
		if string(x) != string(y) {
			t.Errorf("env of test-notify differs from notify of %s:\n%s\n---\n%s", f, y, x)
		}
	}
	for _, s := range steps(t, w) {
		if s.ID == "slack-method" {
			t.Error("the workflow must not detect the method at run time")
		}
	}
	// secrets は bot トークンだけで、送る step (aratam の送信と、知らせの確認) にだけ渡す
	got := map[string]bool{}
	for _, s := range regexp.MustCompile(`secrets\.\w+`).FindAllString(text, -1) {
		got[s] = true
	}
	var names []string
	for s := range got {
		names = append(names, s)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "secrets.ARATAM_SLACK_BOT_TOKEN" {
		t.Errorf("secrets: %v", names)
	}
	for k, v := range w.Env {
		if strings.Contains(v, "secrets.") {
			t.Errorf("workflow env %s must not hold a secret", k)
		}
	}
	for k, v := range w.Jobs["notify-test"].Env {
		if strings.Contains(v, "secrets.") {
			t.Errorf("job env %s must not hold a secret", k)
		}
	}
	for _, s := range steps(t, w) {
		for k, v := range s.Env {
			if strings.Contains(v, "secrets.") && s.ID != "test-notify" && s.ID != "alert" {
				t.Errorf("secret %s must not be given to step %q", k, s.ID)
			}
		}
	}
	for _, expr := range regexp.MustCompile(`\$\{\{[^}]*\}\}`).FindAllString(text, -1) {
		for _, bad := range []string{"secrets[", "(secrets)", "secrets.*"} {
			if strings.Contains(expr, bad) {
				t.Errorf("must name each secret statically: %s", expr)
			}
		}
	}
}

// route: alert は、定時の通知が送れなかったことの知らせ (監査の最後の alert) と同じ送り方で、知らせのチャンネルに 1 通送る (ADR 0060)。
// 知らせは、ふだん使われない。bot を知らせのチャンネルに招待し忘れていることを、定時の前に確かめる。
func TestNotifyTestCanSendToTheAlertChannel(t *testing.T) {
	w, _ := load(t, notifyTestFile)
	a := stepByID(t, w, "alert")
	if a.If != "inputs.route == 'alert'" || stepByID(t, w, "test-notify").If != "inputs.route != 'alert'" {
		t.Errorf("alert runs only for the alert route: %q / %q", a.If, stepByID(t, w, "test-notify").If)
	}
	if len(a.Env) != 3 || a.Env["SLACK_BOT_TOKEN"] != "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}" || a.Env["ALERT_CHANNEL"] != alertChannel || a.TimeoutMinutes == 0 {
		t.Errorf("alert env: %v", a.Env)
	}
	// 送る部分は、監査の alert と 1 文字も違わない
	audit, _ := load(t, multiFile)
	const mark = "# ここから下は、"
	x, y := stepByID(t, audit, "alert").Run, a.Run
	if i, j := strings.Index(x, mark), strings.Index(y, mark); i < 0 || j < 0 || x[i:] != y[j:] {
		t.Error("the sending part must be the same as the alert of the audit")
	}
	env := []string{"SLACK_BOT_TOKEN=" + fakeToken, "ALERT_CHANNEL=" + alertChannel, "RUN_URL=https://github.example/acme/audit/actions/runs/42"}
	out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0, `{"ok":true}`), env...)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	checkAlertCall(t, tmp, "arata の知らせの試験メッセージです (定時の通知が送れなかったときに、ここへ知らせます)。 https://github.example/acme/audit/actions/runs/42")
	noLeak(t, out)
	// bot が知らせのチャンネルにいない → 失敗し、Slack の error コードだけを出す
	out, code, _ = runStep(t, a.Run, fakeCurl(t, 0, `{"ok":false,"error":"not_in_channel"}`), env...)
	if code != 1 || !strings.Contains(out, "slack error=not_in_channel") {
		t.Errorf("exit %d\n%s", code, out)
	}
	noLeak(t, out)
}

func notifyTestEnv(kv ...string) []string {
	env := map[string]string{"ACCOUNT": "prod", "ARATA_CONFIG_DIR": "aws/prod", "ROUTE": "normal"}
	for i := 0; i+1 < len(kv); i += 2 {
		env[kv[i]] = kv[i+1]
	}
	var out []string
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func TestNotifyTestValidatesInputs(t *testing.T) {
	w, _ := load(t, notifyTestFile)
	script := stepByID(t, w, "validate").Run
	for _, kv := range [][]string{nil, {"ROUTE", "urgent"}, {"ROUTE", "alert"}, {"ACCOUNT", "staging-2"}} {
		t.Run("ok/"+strings.Join(kv, " "), func(t *testing.T) {
			if out, code, _ := runStep(t, script, t.TempDir(), notifyTestEnv(kv...)...); code != 0 {
				t.Errorf("exit %d\n%s", code, out)
			}
		})
	}
	for name, kv := range map[string][]string{
		"empty route":   {"ROUTE", ""},
		"unknown route": {"ROUTE", "both"},
		"flag as route": {"ROUTE", "--urgent"},
		"route + flag":  {"ROUTE", "urgent --in x"},
		"account path":  {"ACCOUNT", "../prod"},
		"account upper": {"ACCOUNT", "Prod"},
		"empty account": {"ACCOUNT", ""},
		"account + cmd": {"ACCOUNT", "prod; id"},
	} {
		t.Run("bad/"+name, func(t *testing.T) {
			out, code, _ := runStep(t, script, t.TempDir(), notifyTestEnv(kv...)...)
			if code != 1 || !strings.Contains(out, "::error::") {
				t.Errorf("must fail with an error annotation: exit %d\n%s", code, out)
			}
		})
	}
}

func TestNotifyTestRunsAratamWithExpectedArguments(t *testing.T) {
	w, _ := load(t, notifyTestFile)
	script := stepByID(t, w, "test-notify").Run
	bin := fakeBin(t, "aratam", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\n")
	for name, tc := range map[string]struct {
		kv   []string
		want string
	}{
		"normal":  {nil, "test-notify\n-c\naws/prod/aratam.yaml\n"},
		"urgent":  {[]string{"ROUTE", "urgent"}, "test-notify\n-c\naws/prod/aratam.yaml\n--urgent\n"},
		"staging": {[]string{"ACCOUNT", "staging", "ARATA_CONFIG_DIR", "aws/staging"}, "test-notify\n-c\naws/staging/aratam.yaml\n"},
	} {
		t.Run(name, func(t *testing.T) {
			out, code, tmp := runStep(t, script, bin, notifyTestEnv(tc.kv...)...)
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
		})
	}
}

// ログの方針は監査と同じ (msg / error を出さず、終了コードは保つ)。5 は送信の失敗。
func TestNotifyTestLogsOnlyCodesAndKeepsExitCode(t *testing.T) {
	w, _ := load(t, notifyTestFile)
	for _, exit := range []int{0, 2, 5} {
		t.Run(fmt.Sprintf("exit=%d", exit), func(t *testing.T) {
			bin := fakeBin(t, "aratam", leakyLog+fmt.Sprintf("exit %d\n", exit))
			out, code, _ := runStep(t, stepByID(t, w, "test-notify").Run, bin, notifyTestEnv()...)
			if code != exit {
				t.Errorf("exit code must be kept: got %d want %d\n%s", code, exit, out)
			}
			for _, secret := range []string{"123456789012", "alice@example.com", "collect ok", "report body"} {
				if strings.Contains(out, secret) {
					t.Errorf("leaked %q:\n%s", secret, out)
				}
			}
			if !strings.Contains(out, "STORE_CONFLICT") || !strings.Contains(out, fmt.Sprintf("aratam exit=%d", exit)) {
				t.Errorf("the error code and the exit code must stay visible:\n%s", out)
			}
		})
	}
}

// sendFailedLine は aratam test-notify が送信に失敗したときの標準エラーの 1 行を書いたファイル。
// 項目は cmd/aratam の newTestNotifyCmd と同じ作り方 (notify.SendErrorAttrs) で作る。extra は、その後に足す・上書きする項目。
func sendFailedLine(t *testing.T, err error, extra map[string]any) string {
	t.Helper()
	line := map[string]any{"time": "2026-10-21T10:00:00Z", "level": "ERROR", "msg": "試験通知の送信に失敗しました", "code": "SEND_FAILED", "route": "normal"}
	attrs := notify.SendErrorAttrs(err)
	for i := 0; i+1 < len(attrs); i += 2 {
		line[attrs[i].(string)] = attrs[i+1]
	}
	for k, v := range extra {
		line[k] = v
	}
	b, merr := json.Marshal(line)
	if merr != nil {
		t.Fatal(merr)
	}
	path := filepath.Join(t.TempDir(), "line")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// bot トークンの方式の失敗は、Slack の error コード (not_in_channel など) だけを足して出す。
// 読むのはログの slack_error (機械が読む項目。log スキーマ)。人向けの error の文からは切り出さない (ADR 0054)。
// 行は internal/slack の APIError と notify.SendErrorAttrs から作る (aratam が出す形が変わったら、ここで気づく)。
func TestNotifyTestShowsTheSlackErrorCode(t *testing.T) {
	w, _ := load(t, notifyTestFile)
	script := stepByID(t, w, "test-notify").Run
	if strings.Contains(script, "capture(") || strings.Contains(script, ".error") {
		t.Errorf("the step must read slack_error, not the human text in error:\n%s", script)
	}
	const channel = "C0123456789"
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"not_in_channel":    {&slack.APIError{Method: "chat.postMessage", Code: "not_in_channel", Status: 200, Channel: channel}, "not_in_channel"},
		"channel_not_found": {&slack.APIError{Method: "chat.postMessage", Code: "channel_not_found", Status: 200, Channel: channel}, "channel_not_found"},
		"invalid_auth":      {&slack.APIError{Method: "chat.postMessage", Code: "invalid_auth", Status: 200, Channel: channel}, "invalid_auth"},
		"no hint":           {&slack.APIError{Method: "chat.postMessage", Code: "team_access_not_granted", Status: 200, Channel: channel}, "team_access_not_granted"},
		"no channel":        {&slack.APIError{Method: "chat.postMessage", Code: "invalid_auth", Status: 200}, "invalid_auth"},
		"http status":       {&slack.APIError{Method: "chat.postMessage", Code: "internal_error", Status: 500, Channel: channel}, "internal_error"},
		"ratelimited":       {&slack.APIError{Method: "chat.postMessage", Code: "ratelimited", Status: 429, Channel: channel, RetryAfter: 60 * time.Second}, "ratelimited"},
		"wrapped":           {fmt.Errorf("urgent: %w", &slack.APIError{Method: "chat.postMessage", Code: "is_archived", Status: 200, Channel: channel}), "is_archived"},
	} {
		t.Run(name, func(t *testing.T) {
			bin := fakeBin(t, "aratam", fmt.Sprintf("cat %q >&2\nexit 5\n", sendFailedLine(t, tc.err, nil)))
			out, code, _ := runStep(t, script, bin, notifyTestEnv()...)
			if code != 5 {
				t.Errorf("exit %d\n%s", code, out)
			}
			if !strings.Contains(out, "slack error="+tc.want+"\n") || !strings.Contains(out, "SEND_FAILED") {
				t.Errorf("the Slack error code must be shown:\n%s", out)
			}
			// 出すのはコードだけ。エラーの文 (チャンネル ID・案内) と msg は出さない
			for _, bad := range []string{channel, "招待", "トークン", "試験通知", "Retry-After"} {
				if strings.Contains(out, bad) {
					t.Errorf("only the code may be shown, got %q:\n%s", bad, out)
				}
			}
		})
	}
	// コードの無い失敗 (Webhook、接続の失敗、HTTP の状態だけ) は、何も足さない。error の文にコードらしい語があっても読まない
	for name, err := range map[string]error{
		"webhook body":  errors.New("slack: webhook returned 404: no_service 123456789012"),
		"webhook dial":  errors.New("slack: post webhook: dial tcp: lookup hooks.example.com: no such host"),
		"text only":     errors.New("slack: chat.postMessage failed: not_in_channel"),
		"status only":   &slack.APIError{Method: "chat.postMessage", Status: 502, Channel: channel},
		"odd code":      &slack.APIError{Method: "chat.postMessage", Code: "Not_In_Channel 123456789012", Status: 200},
		"long code":     &slack.APIError{Method: "chat.postMessage", Code: strings.Repeat("a", 65), Status: 200},
		"code and tail": &slack.APIError{Method: "chat.postMessage", Code: "abc/secret", Status: 200},
	} {
		t.Run("hidden/"+name, func(t *testing.T) {
			bin := fakeBin(t, "aratam", fmt.Sprintf("cat %q >&2\nexit 5\n", sendFailedLine(t, err, nil)))
			out, code, _ := runStep(t, script, bin, notifyTestEnv()...)
			if code != 5 || !strings.Contains(out, "SEND_FAILED") {
				t.Errorf("exit %d\n%s", code, out)
			}
			if strings.Contains(out, "slack error=") {
				t.Errorf("must not print an unverified error:\n%s", out)
			}
		})
	}
	// ワークフローの側でも形を確かめる: 形に合わない slack_error、文字列でない slack_error、別の code の行の slack_error は出さない
	for name, extra := range map[string]map[string]any{
		"upper":        {"slack_error": "Not_In_Channel"},
		"with newline": {"slack_error": "a\n::add-mask::x"},
		"with space":   {"slack_error": "not in channel 123456789012"},
		"too long":     {"slack_error": strings.Repeat("a", 65)},
		"not a string": {"slack_error": []string{"not_in_channel"}},
		"other code":   {"slack_error": "not_in_channel", "code": "CONFIG_INVALID"},
	} {
		t.Run("rejected/"+name, func(t *testing.T) {
			bin := fakeBin(t, "aratam", fmt.Sprintf("cat %q >&2\nexit 5\n", sendFailedLine(t, errors.New("x"), extra)))
			out, _, _ := runStep(t, script, bin, notifyTestEnv()...)
			if strings.Contains(out, "slack error=") || strings.Contains(out, "add-mask") || strings.Contains(out, "123456789012") {
				t.Errorf("must not print it:\n%s", out)
			}
		})
	}
}
