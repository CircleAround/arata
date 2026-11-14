package githubactions_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoWithMethodScript は、一式のスクリプト (.github/scripts) を置いた、利用者のリポジトリのつもりのディレクトリ。
func repoWithMethodScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(methodScriptPath)), 0o750); err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{methodScript: methodScriptPath, secretScript: secretScriptPath} {
		body, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, dst), body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func output(t *testing.T, tmp string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(tmp, "github_output"))
	return string(b)
}

// 定時の監査は、送り方を 1 つのスクリプトで判別し、その結果を notify に渡す。判別できなければ、その段階で止まる。
func TestAuditDetectsTheSlackMethod(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		s := stepByID(t, w, "slack-method")
		// arata が失敗しても判別する (notify は「実行されていない」を送る)。試しの実行では通知しないので、判別もしない
		if s.If != "always() && steps.install.outcome == 'success' && !inputs.dry_run" || s.If != stepByID(t, w, "notify").If {
			t.Errorf("slack-method must run whenever notify runs: %q", s.If)
		}
		if !strings.Contains(s.Run, methodScriptPath+` "$ARATA_CONFIG_DIR/aratam.yaml"`) {
			t.Errorf("slack-method must call the shared script:\n%s", s.Run)
		}
		// 人向けの出力を読む書き方を、見本に残さない
		for _, bad := range []string{"config check |", "grep 'slack", `grep "slack`, "slack bot$", "slack webhook$"} {
			if strings.Contains(text, bad) {
				t.Errorf("the workflow must not read the human output of config check: %q", bad)
			}
		}
		for method, exit := range map[string]int{"bot": 0, "webhook": 0, "email": 1} {
			t.Run(method, func(t *testing.T) {
				bin := fakeBin(t, "aratam", fmt.Sprintf(`echo '{"ok":true,"slack":{"method":%q},"rows":[]}'`+"\n", method))
				out, code, tmp := runStepIn(t, repoWithMethodScript(t), s.Run, bin)
				if code != exit {
					t.Fatalf("exit %d, want %d\n%s", code, exit, out)
				}
				want := ""
				if exit == 0 {
					want = "method=" + method + "\n"
				}
				if got := output(t, tmp); got != want {
					t.Errorf("GITHUB_OUTPUT %q, want %q", got, want)
				}
			})
		}
	})
}

// notify には、判別した送り方の secret だけを渡す (bot なら Webhook の URL を、webhook なら bot トークンを、ジョブに出さない)。
func TestNotifyGetsOnlyTheSecretsOfTheMethod(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		env := stepByID(t, w, "notify").Env
		for k, method := range map[string]string{"ARATAM_SLACK_WEBHOOK": "webhook", "ARATAM_SLACK_URGENT_WEBHOOK": "webhook", "ARATAM_SLACK_BOT_TOKEN": "bot"} {
			want := fmt.Sprintf("${{ steps.slack-method.outputs.method == '%s' && secrets.%s || '' }}", method, k)
			if env[k] != want {
				t.Errorf("%s: %q, want %q", k, env[k], want)
			}
		}
	})
}

// notify は、Slack に何かが届いた終了コード (0・3・4) のときだけ delivered の印を出す。終了コードはそのまま。
func TestNotifyMarksWhatWasDelivered(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		for exit, delivered := range map[int]bool{0: true, 3: true, 4: true, 2: false, 5: false, 1: false, 137: false} {
			bin := fakeBin(t, "aratam", fmt.Sprintf("exit %d\n", exit))
			out, code, tmp := runStep(t, stepByID(t, w, "notify").Run, bin)
			if code != exit {
				t.Errorf("exit %d, want %d\n%s", code, exit, out)
			}
			if got := output(t, tmp) == "delivered=true\n"; got != delivered || (!delivered && output(t, tmp) != "") {
				t.Errorf("exit %d: GITHUB_OUTPUT %q", exit, output(t, tmp))
			}
		}
	})
}

// fakeCurl は引数と標準入力を記録する。
func fakeCurl(t *testing.T, exit int) string {
	t.Helper()
	return fakeBin(t, "curl", fmt.Sprintf(`printf '%%s\n' "$@" >"$RUNNER_TEMP/curl-args"
cat >"$RUNNER_TEMP/curl-body"
echo 'curl: (22) error for https://alerts.example/hook/SECRET' >&2
echo 'response body SECRET'
exit %d
`, exit))
}

const alertURL = "https://alerts.example/hook/SECRET"

// steps の JSON (toJSON(steps))。outputs には、送らない値が入っている。
const stepsJSON = `{
  "checkout": {"outcome": "success", "conclusion": "success", "outputs": {}},
  "install": {"outcome": "success", "conclusion": "success", "outputs": {}},
  "aws": {"outcome": "success", "conclusion": "success", "outputs": {"aws-account-id": "123456789012"}},
  "audit": {"outcome": "failure", "conclusion": "failure", "outputs": {"detail": "arn:aws:iam::123456789012:role/x alice@example.com"}},
  "slack-method": {"outcome": "success", "conclusion": "success", "outputs": {"method": "bot"}},
  "notify": {"outcome": "failure", "conclusion": "failure", "outputs": {}},
  "save-proposals": {"outcome": "skipped", "conclusion": "skipped", "outputs": {}},
  "Bad Id <!channel>": {"outcome": "failure", "conclusion": "failure", "outputs": {}}
}`

func alertEnv(kv ...string) []string {
	return append([]string{"ALERT_WEBHOOK=" + alertURL, "STEPS=" + stepsJSON, "ARATA_TARGET=prod", "PROFILE=weekly",
		"RUN_URL=https://github.example/acme/audit/actions/runs/42"}, kv...)
}

// 定時の実行で Slack に何も届かなかったら、最後の段階が別の経路で知らせる。送るのは対象・プロファイル・失敗した段階の id・実行の URL だけ。
func TestAlertTellsWhichTargetWasNotNotified(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		a := stepByID(t, w, "alert")
		// 定時の実行だけ。aratam が Slack に何かを送れたとき (delivered) は送らない。always() にしない (成功した実行で送らない)
		if a.If != "failure() && github.event_name == 'schedule' && steps.notify.outputs.delivered != 'true'" {
			t.Errorf("if: %q", a.If)
		}
		if a.Env["ALERT_WEBHOOK"] != "${{ secrets.ARATA_ALERT_WEBHOOK }}" || a.Env["STEPS"] != "${{ toJSON(steps) }}" ||
			a.Env["RUN_URL"] != "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}" {
			t.Errorf("env: %v", a.Env)
		}
		// 通知用の secret は渡さない (別の経路)。報告のファイルも読まない
		for k := range a.Env {
			if strings.HasPrefix(k, "ARATAM_") {
				t.Errorf("alert must not get %s", k)
			}
		}
		for _, bad := range []string{"arata-out", "report.json", "report.md", ".log", "$RUNNER_TEMP"} {
			if strings.Contains(a.Run, bad) {
				t.Errorf("alert must not read the audit output: %q", bad)
			}
		}
		if a.TimeoutMinutes == 0 || a.ContinueOnErr != nil {
			t.Errorf("alert needs a timeout and must fail loudly")
		}

		t.Run("sends", func(t *testing.T) {
			out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0), alertEnv()...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			body, _ := os.ReadFile(filepath.Join(tmp, "curl-body"))
			var payload map[string]string
			if err := json.Unmarshal(body, &payload); err != nil || len(payload) != 1 {
				t.Fatalf("payload must be {\"text\": ...}: %v\n%s", err, body)
			}
			want := "arata の定時の通知を送れていません。対象: prod / プロファイル: weekly / 失敗した段階: audit, notify / https://github.example/acme/audit/actions/runs/42"
			if payload["text"] != want {
				t.Errorf("text:\n%s\nwant:\n%s", payload["text"], want)
			}
			args, _ := os.ReadFile(filepath.Join(tmp, "curl-args"))
			if !strings.HasSuffix(strings.TrimSpace(string(args)), alertURL) || !strings.Contains(string(args), "--fail") || !strings.Contains(string(args), "--max-time") {
				t.Errorf("curl args:\n%s", args)
			}
			// ログには、段階の id だけ。URL・outputs の値・curl の出力は出さない
			if !strings.Contains(out, "failed steps: audit, notify") {
				t.Errorf("log:\n%s", out)
			}
			for _, secret := range []string{"SECRET", "alerts.example", "123456789012", "alice@example.com", "response body", "channel"} {
				if strings.Contains(out, secret) {
					t.Errorf("the log leaked %q:\n%s", secret, out)
				}
			}
			for _, value := range []string{"123456789012", "alice@example.com", "channel", "method", "outputs"} {
				if strings.Contains(string(body), value) {
					t.Errorf("the message carries %q:\n%s", value, body)
				}
			}
		})
		t.Run("send fails", func(t *testing.T) {
			out, code, _ := runStep(t, a.Run, fakeCurl(t, 22), alertEnv()...)
			if code != 1 || !strings.Contains(out, "::error::") || strings.Contains(out, "SECRET") || strings.Contains(out, "alerts.example") {
				t.Errorf("exit %d\n%s", code, out)
			}
		})
		t.Run("no webhook", func(t *testing.T) {
			out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0), alertEnv("ALERT_WEBHOOK=")...)
			if code != 1 || !strings.Contains(out, "::error::ARATA_ALERT_WEBHOOK") {
				t.Errorf("exit %d\n%s", code, out)
			}
			if _, err := os.Stat(filepath.Join(tmp, "curl-args")); err == nil {
				t.Errorf("curl must not run without a URL")
			}
		})
		// steps が読めなくても、対象と URL は知らせる
		t.Run("unreadable steps", func(t *testing.T) {
			out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0), alertEnv("STEPS={not json")...)
			body, _ := os.ReadFile(filepath.Join(tmp, "curl-body"))
			if code != 0 || !strings.Contains(string(body), "失敗した段階: 不明 / https://") || !strings.Contains(string(body), "対象: prod") {
				t.Errorf("exit %d\n%s\n%s", code, out, body)
			}
		})
	})
	// 対象の名前は matrix のアカウント
	multi, _ := load(t, multiFile)
	if multi.Jobs["audit"].Env["ARATA_TARGET"] != "${{ matrix.account }}" {
		t.Errorf("ARATA_TARGET: %q", multi.Jobs["audit"].Env["ARATA_TARGET"])
	}
}

// fakeYQ は `yq -r '.env.ARATA_VERSION' <file>` だけを受け付け、ファイルの「ARATA_VERSION: 値」の行の値を返す。
// 行が無ければ、本物の yq (mikefarah/yq v4) と同じく null と出す。broken と書いたファイルは、YAML として読めないことにする。
// 式は、利用者の側で GitHub の実行環境の yq で動かして確かめた形 (.env.ARATA_VERSION) にそろえてある。
const fakeYQ = `if [ "$#" -ne 3 ] || [ "$1" != -r ] || [ "$2" != '.env.ARATA_VERSION' ]; then echo "unexpected yq $*" >&2; exit 64; fi
if grep -q broken "$3"; then echo "yaml: line 1: did not find expected key" >&2; exit 1; fi
v="$(sed -n 's/^  ARATA_VERSION: *\([^ ]*\).*/\1/p' "$3")"
echo "${v:-null}"
`

// PR の検査は、arata を使うワークフローの版が揃っていることを確かめる (片方だけ上げて、検査と定時の実行の版がずれるのを防ぐ)。
func TestCheckRequiresTheSameVersionEverywhere(t *testing.T) {
	w, _ := load(t, checkFile)
	script := stepByID(t, w, "versions").Run
	if !strings.Contains(script, `yq -r '.env.ARATA_VERSION' "$file"`) || strings.Contains(script, "grep") {
		t.Errorf("versions must read the workflows as YAML:\n%s", script)
	}
	order := map[string]int{}
	for i, s := range steps(t, w) {
		order[s.ID] = i
	}
	if !(order["checkout"] < order["versions"] && order["versions"] < order["check"]) {
		t.Errorf("step order: %v", order)
	}
	bin := fakeBin(t, "yq", fakeYQ)
	tree := func(files map[string]string) string {
		dir := t.TempDir()
		for name, body := range files {
			p := filepath.Join(dir, ".github/workflows", name)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	at := func(v string) string { return "env:\n  ARATA_VERSION: " + v + "   # comment v9.9.9\n" }
	same := map[string]string{"arata-audit.yml": at("v0.14.0"), "arata-notify-test.yml": at("v0.14.0"), "arata-check.yml": at("v0.14.0"), "ci.yml": "name: ci\n"}
	with := func(name, body string) map[string]string {
		m := map[string]string{}
		for k, v := range same {
			m[k] = v
		}
		m[name] = body
		return m
	}
	cases := []struct {
		name    string
		files   map[string]string
		version string
		exit    int
		want    string
	}{
		{"same", same, "v0.14.0", 0, "ARATA_VERSION=v0.14.0 のワークフロー: 3"},
		{"yaml extension too", with("arata-triage.yaml", at("v0.14.0")), "v0.14.0", 0, "ワークフロー: 4"},
		{"one differs", with("arata-audit.yml", at("v0.13.0")), "v0.14.0", 1, "::error file=.github/workflows/arata-audit.yml::"},
		{"yaml extension differs", with("arata-triage.yaml", at("v0.13.0")), "v0.14.0", 1, "::error file=.github/workflows/arata-triage.yaml::"},
		{"unreadable workflow", with("arata-audit.yml", "broken"), "v0.14.0", 1, "::error file=.github/workflows/arata-audit.yml::YAML として読めない"},
		{"not pinned", same, "main", 1, "v1.2.3 の形"},
		{"latest", same, "latest", 1, "v1.2.3 の形"},
		{"no workflow uses arata", map[string]string{"ci.yml": "name: ci\n"}, "v0.14.0", 1, "見つからない"},
		{"odd file name", with("a b.yml", at("v0.14.0")), "v0.14.0", 1, "名前に使えない文字"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, _ := runStepIn(t, tree(tc.files), script, bin, "ARATA_VERSION="+tc.version)
			if code != tc.exit || !strings.Contains(out, tc.want) {
				t.Errorf("exit %d, want %d and %q:\n%s", code, tc.exit, tc.want, out)
			}
			// 食い違った版 (PR のファイルの値) はログに出さない
			if strings.Contains(out, "v0.13.0") || strings.Contains(out, "v9.9.9") || strings.Contains(out, "did not find") {
				t.Errorf("values read from the files must not be printed:\n%s", out)
			}
		})
	}
}

// 見本のワークフローは、どれも同じ版に固定してある (写したままで PR の検査が通る)。
func TestEveryExampleUsesTheSameVersion(t *testing.T) {
	check, _ := load(t, checkFile)
	want := check.Env["ARATA_VERSION"]
	if want == "" {
		t.Fatal("arata-check.yml has no ARATA_VERSION")
	}
	for _, f := range allFiles {
		if w, _ := load(t, f); w.Env["ARATA_VERSION"] != want {
			t.Errorf("%s: ARATA_VERSION %q, want %q", f, w.Env["ARATA_VERSION"], want)
		}
	}
}
