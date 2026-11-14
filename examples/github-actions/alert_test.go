package githubactions_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exampleVersion は、見本の一式を書き出した版 (ワークフローの ARATA_VERSION)。
const exampleVersion = "v0.15.0"

// exampleRepo は見本の一式 (arata repo init の出力そのもの)。
const exampleRepo = "../audit-repo"

func output(t *testing.T, tmp string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(tmp, "github_output"))
	return string(b)
}

// 送り方を、実行のときに判別しない (ADR 0060)。notify には bot トークンだけを渡す。Webhook の秘密も、判別のスクリプトも、仮の値の検査も無い。
// aratam.yaml が bot トークンの方式であることは、PR の検査の arata repo check が確かめる。
func TestNotifyGetsOnlyTheBotToken(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		n := stepByID(t, w, "notify")
		if len(n.Env) != 1 || n.Env["ARATAM_SLACK_BOT_TOKEN"] != "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}" {
			t.Errorf("notify env: %v", n.Env)
		}
		// arata が失敗しても通知する (「実行されていない」を送る)。試しの実行では通知しない
		if n.If != "always() && steps.install.outcome == 'success' && !inputs.dry_run" {
			t.Errorf("notify if: %q", n.If)
		}
		for _, s := range steps(t, w) {
			if s.ID == "slack-method" {
				t.Error("the workflow must not detect the method at run time")
			}
		}
		for _, bad := range []string{"arata-slack-method", "arata-secret-check", ".github/scripts", "WEBHOOK", "config check |", "grep 'slack"} {
			if strings.Contains(text, bad) {
				t.Errorf("the workflow must not mention %q", bad)
			}
		}
	})
}

// 認証に使う秘密が未登録 (空) なら、AWS に行く前に、秘密の名前と「arata repo check --github」を出して止まる (ADR 0060)。
// 秘密は、最初は 1 つも登録されていない。値は出さない。
func TestWorkflowsStopOnUnregisteredSecretsBeforeAWS(t *testing.T) {
	for file, names := range map[string][]string{multiFile: {"ARATA_RUNNER_ROLE_ARN", "ARATA_AUDIT_ROLE_ARNS"}, triageFile: {"ARATA_RUNNER_ROLE_ARN"}} {
		w, _ := load(t, file)
		all := steps(t, w)
		pos := map[string]int{}
		for i, s := range all {
			pos[s.ID] = i
		}
		s := stepByID(t, w, "secrets")
		if pos["secrets"] > pos["aws"] || pos["secrets"] < pos["checkout"] {
			t.Errorf("%s: the check must run after checkout and before the AWS credentials", file)
		}
		if len(s.Env) != len(names) {
			t.Errorf("%s: secrets env: %v", file, s.Env)
		}
		var set []string
		for _, n := range names {
			if s.Env[n] != "${{ secrets."+n+" }}" {
				t.Errorf("%s: %s = %q", file, n, s.Env[n])
			}
			set = append(set, n+"=arn:aws:iam::123456789012:role/example-secret-value")
		}
		out, code, _ := runStep(t, s.Run, t.TempDir(), set...)
		if code != 0 || strings.Contains(out, "example-secret-value") {
			t.Errorf("%s: registered secrets must pass without printing them: exit %d\n%s", file, code, out)
		}
		// 1 つでも空なら止まり、その名前を全部出す
		for i, missing := range names {
			env := append([]string{}, set...)
			env[i] = missing + "="
			out, code, _ := runStep(t, s.Run, t.TempDir(), env...)
			if code != 1 || !strings.Contains(out, "::error::秘密 "+missing+" が未登録") || !strings.Contains(out, "arata repo check --github") || strings.Contains(out, "example-secret-value") {
				t.Errorf("%s: %s unset: exit %d\n%s", file, missing, code, out)
			}
		}
		out, code, _ = runStep(t, s.Run, t.TempDir())
		for _, n := range names {
			if code != 1 || !strings.Contains(out, "秘密 "+n+" が未登録") {
				t.Errorf("%s: nothing registered: exit %d\n%s", file, code, out)
			}
		}
	}
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

// fakeToken は偽の bot トークン (実際の Slack には接続しない)。
const fakeToken = "xoxb-0000-FAKE-TOKEN"

// fakeCurl は、引数・標準入力 (ヘッダー)・--data-binary @<file> の中身を記録し、response を標準出力に出す。
// 標準エラーと応答には、ログに出てはいけない文字列を入れてある。
func fakeCurl(t *testing.T, exit int, response string) string {
	t.Helper()
	return fakeBin(t, "curl", fmt.Sprintf(`printf '%%s\n' "$@" >"$RUNNER_TEMP/curl-args"
cat >"$RUNNER_TEMP/curl-stdin"
for a in "$@"; do
  case "$a" in
    @-) ;;
    @*) cat "${a#@}" >"$RUNNER_TEMP/curl-body" ;;
  esac
done
echo 'curl: (22) error LEAK-IN-STDERR' >&2
printf '%%s' %q
exit %d
`, response, exit))
}

const alertChannel = "C0123456782" // 見本の --alert-channel

// steps の JSON (toJSON(steps))。outputs には、送らない値が入っている。
const stepsJSON = `{
  "checkout": {"outcome": "success", "conclusion": "success", "outputs": {}},
  "install": {"outcome": "success", "conclusion": "success", "outputs": {}},
  "aws": {"outcome": "success", "conclusion": "success", "outputs": {"aws-account-id": "123456789012"}},
  "audit": {"outcome": "failure", "conclusion": "failure", "outputs": {"detail": "arn:aws:iam::123456789012:role/x alice@example.com"}},
  "notify": {"outcome": "failure", "conclusion": "failure", "outputs": {}},
  "save-proposals": {"outcome": "skipped", "conclusion": "skipped", "outputs": {}},
  "Bad Id <!channel>": {"outcome": "failure", "conclusion": "failure", "outputs": {}}
}`

func alertEnv(kv ...string) []string {
	return append([]string{"SLACK_BOT_TOKEN=" + fakeToken, "ALERT_CHANNEL=" + alertChannel, "STEPS=" + stepsJSON, "ARATA_TARGET=prod", "PROFILE=weekly",
		"RUN_URL=https://github.example/acme/audit/actions/runs/42"}, kv...)
}

// checkAlertCall は、偽の curl が受け取ったものを確かめる: chat.postMessage へ、トークンは標準入力のヘッダーで (引数に書かない)、本文は JSON。
func checkAlertCall(t *testing.T, tmp, wantText string) {
	t.Helper()
	args, _ := os.ReadFile(filepath.Join(tmp, "curl-args"))
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	if lines[len(lines)-1] != "https://slack.com/api/chat.postMessage" || !strings.Contains(string(args), "--fail") || !strings.Contains(string(args), "--max-time") {
		t.Errorf("curl args:\n%s", args)
	}
	if strings.Contains(string(args), fakeToken) || strings.Contains(string(args), "hooks.slack.com") {
		t.Errorf("the token must not be in the arguments (and no webhook):\n%s", args)
	}
	if header, _ := os.ReadFile(filepath.Join(tmp, "curl-stdin")); string(header) != "Authorization: Bearer "+fakeToken+"\n" {
		t.Errorf("the header on stdin: %q", header)
	}
	body, _ := os.ReadFile(filepath.Join(tmp, "curl-body"))
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil || len(payload) != 4 || payload["channel"] != alertChannel ||
		payload["unfurl_links"] != false || payload["unfurl_media"] != false {
		t.Fatalf("payload: %v\n%s", err, body)
	}
	if payload["text"] != wantText {
		t.Errorf("text:\n%s\nwant:\n%s", payload["text"], wantText)
	}
	for _, value := range []string{"123456789012", "alice@example.com", "<!channel>", "outputs", fakeToken} {
		if strings.Contains(string(body), value) {
			t.Errorf("the message carries %q:\n%s", value, body)
		}
	}
}

// noLeak は、ログにトークン・curl の出力・応答の本文・outputs の値が出ていないことを確かめる。
func noLeak(t *testing.T, out string) {
	t.Helper()
	for _, secret := range []string{fakeToken, "LEAK-IN", "123456789012", "alice@example.com", "Bearer", `"ok"`} {
		if strings.Contains(out, secret) {
			t.Errorf("the log leaked %q:\n%s", secret, out)
		}
	}
}

// 定時の実行で Slack に何も届かなかったら、最後の段階が、同じ bot トークンで知らせのチャンネルへ送る (ADR 0060)。
// 送るのは対象・プロファイル・失敗した段階の id・実行の URL だけ。Slack は失敗でも HTTP 200 を返すので、応答の ok を見る。
func TestAlertTellsWhichTargetWasNotNotified(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		a := stepByID(t, w, "alert")
		// 定時の実行だけ。aratam が Slack に何かを送れたとき (delivered) は送らない。always() にしない (成功した実行で送らない)
		if a.If != "failure() && github.event_name == 'schedule' && steps.notify.outputs.delivered != 'true'" {
			t.Errorf("if: %q", a.If)
		}
		if len(a.Env) != 4 || a.Env["SLACK_BOT_TOKEN"] != "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}" || a.Env["ALERT_CHANNEL"] != alertChannel || a.Env["STEPS"] != "${{ toJSON(steps) }}" ||
			a.Env["RUN_URL"] != "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}" {
			t.Errorf("env: %v", a.Env)
		}
		// aratam を通さない (バイナリが取れない・設定が壊れているときにも送る)。報告のファイルも読まない
		for _, bad := range []string{"aratam ", "arata-out", "report.json", "report.md", ".log", "hooks.slack.com", "WEBHOOK"} {
			if strings.Contains(a.Run, bad) {
				t.Errorf("alert must not use %q", bad)
			}
		}
		if a.TimeoutMinutes == 0 || a.ContinueOnErr != nil {
			t.Errorf("alert needs a timeout and must fail loudly")
		}
		want := "arata の定時の通知を送れていません。対象: prod / プロファイル: weekly / 失敗した段階: audit, notify / https://github.example/acme/audit/actions/runs/42"

		t.Run("sends", func(t *testing.T) {
			out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0, `{"ok":true,"channel":"C0123456782","ts":"1.2","message":{"text":"LEAK-IN-RESPONSE"}}`), alertEnv()...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			checkAlertCall(t, tmp, want)
			// ログには、段階の id だけ
			if !strings.Contains(out, "failed steps: audit, notify") {
				t.Errorf("log:\n%s", out)
			}
			noLeak(t, out)
		})
		// secret の末尾の改行や空白は除く (ヘッダーを壊さない)
		t.Run("token with a trailing newline", func(t *testing.T) {
			out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0, `{"ok":true}`), alertEnv("SLACK_BOT_TOKEN="+fakeToken+" \n")...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			checkAlertCall(t, tmp, want)
		})
		// Slack は失敗でも HTTP 200 を返す。ok が true でなければ失敗にし、error のコードだけを出す
		for name, tc := range map[string]struct {
			exit      int
			response  string
			wantError string
		}{
			"not in channel":     {0, `{"ok":false,"error":"not_in_channel","LEAK-IN-RESPONSE":1}`, "slack error=not_in_channel"},
			"invalid auth":       {0, `{"ok":false,"error":"invalid_auth"}`, "slack error=invalid_auth"},
			"odd error":          {0, `{"ok":false,"error":"LEAK-IN-RESPONSE <!channel>"}`, "slack error=unknown"},
			"ok is a string":     {0, `{"ok":"true"}`, "slack error=unknown"},
			"no ok":              {0, `{}`, "slack error=unknown"},
			"not json":           {0, `<html>LEAK-IN-RESPONSE</html>`, "slack error=unknown"},
			"empty":              {0, ``, "slack error=unknown"},
			"curl fails":         {22, ``, "slack error=unknown"},
			"curl fails with ok": {22, `{"ok":true}`, "slack error=unknown"},
		} {
			t.Run(name, func(t *testing.T) {
				out, code, _ := runStep(t, a.Run, fakeCurl(t, tc.exit, tc.response), alertEnv()...)
				if code != 1 || !strings.Contains(out, "::error::知らせを送れなかった ("+tc.wantError+")") {
					t.Errorf("exit %d\n%s", code, out)
				}
				noLeak(t, out)
			})
		}
		// トークンが未登録 (空) なら、送らずに、名前を出して失敗する (知らせは、トークンが使えないときには届かない。ADR 0060)
		for name, token := range map[string]string{"no token": "", "blank token": " \n"} {
			t.Run(name, func(t *testing.T) {
				out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0, `{"ok":true}`), alertEnv("SLACK_BOT_TOKEN="+token)...)
				if code != 1 || !strings.Contains(out, "::error::ARATAM_SLACK_BOT_TOKEN が未登録") {
					t.Errorf("exit %d\n%s", code, out)
				}
				if _, err := os.Stat(filepath.Join(tmp, "curl-args")); err == nil {
					t.Errorf("curl must not run without a token")
				}
			})
		}
		// steps が読めなくても、対象と URL は知らせる
		t.Run("unreadable steps", func(t *testing.T) {
			out, code, tmp := runStep(t, a.Run, fakeCurl(t, 0, `{"ok":true}`), alertEnv("STEPS={not json")...)
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
