package githubactions_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 送り方を判別するスクリプト。定時の監査・試しの送信・PR の検査の見本が、同じこれを呼ぶ。
const (
	methodScript     = "../audit-repo/.github/scripts/arata-slack-method.sh"
	methodScriptPath = ".github/scripts/arata-slack-method.sh" // 利用者のリポジトリでの置き場所
)

// runMethodScript は偽の aratam (body) を PATH に置いてスクリプトを動かす。
func runMethodScript(t *testing.T, bin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	abs, err := filepath.Abs(methodScript)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{abs}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH")}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

// bot / webhook だけを通し、それ以外 (読めない設定・古い aratam・知らない値・JSON でない出力) は止める。
// 人向けの出力を読んでいた頃は、行末に項目が足されて判別が外れ、定時の通知が送れなかった (ADR 0054)。
func TestSlackMethodScript(t *testing.T) {
	cases := []struct {
		name, fake, want string
		exit             int
	}{
		{"bot", `echo '{"schema":"aratam-config-check","schema_version":1,"ok":true,"slack":{"method":"bot","format":"blocks"},"timezone":"Asia/Tokyo","rows":[]}'`, "bot\n", 0},
		{"webhook", `echo '{"ok":true,"slack":{"method":"webhook","format":"text"},"rows":[]}'`, "webhook\n", 0},
		// 項目が足されても読める (足すのは互換)
		{"added fields", `echo '{"ok":true,"added":{"x":1},"slack":{"added":true,"method":"bot"},"rows":[]}'`, "bot\n", 0},
		// warn があっても送り方は決まっている
		{"warning rows", `echo '{"ok":true,"slack":{"method":"webhook"},"rows":[{"status":"warn","item":"context","message":"slack bot"}]}'`, "webhook\n", 0},
		{"config does not load", `echo '{"ok":false,"rows":[{"status":"ng","item":"config","message":"slack bot"}]}'; exit 2`, "", 1},
		{"unknown method", `echo '{"ok":true,"slack":{"method":"email"},"rows":[]}'`, "", 1},
		{"method is not a string", `echo '{"ok":true,"slack":{"method":["bot"]},"rows":[]}'`, "", 1},
		{"null", `echo '{"ok":true,"slack":{"method":null}}'`, "", 1},
		{"empty", `echo '{"ok":true,"slack":{"method":""}}'`, "", 1},
		// 古い aratam は --format を知らず、終了コード 2。人向けの行を出しても読まない
		{"old aratam", `echo '{"level":"ERROR","msg":"flag provided but not defined: -format","code":"CONFIG_INVALID"}' >&2; exit 2`, "", 1},
		{"human output", `echo 'ok    aratam.yaml: name example, provider none, format blocks, slack bot, timezone UTC'`, "", 1},
		{"human output ending with the method", `echo 'ok    aratam.yaml: slack bot'`, "", 1},
		{"not json", `echo 'bot'`, "", 1},
		// 終了コードが 0 でなければ、出力が何であっても通さない
		{"failed but printed a method", `echo '{"slack":{"method":"bot"}}'; exit 2`, "", 1},
		// 値に改行やワークフローのコマンドが入っていても、出力に運ばない
		{"injection", `echo '{"slack":{"method":"bot\n::add-mask::x"}}'`, "", 1},
		{"two documents", `echo '{"slack":{"method":"bot"}}'; echo '{"slack":{"method":"webhook"}}'`, "", 1},
		{"no aratam output", `exit 0`, "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := fakeBin(t, "aratam", `echo "$*" >"$(dirname "$0")/args"`+"\n"+tc.fake+"\n")
			out, errOut, code := runMethodScript(t, bin, "aws/prod/aratam.yaml")
			if out != tc.want || code != tc.exit {
				t.Fatalf("stdout %q exit %d, want %q exit %d\nstderr: %s", out, code, tc.want, tc.exit, errOut)
			}
			if args, _ := os.ReadFile(filepath.Join(bin, "args")); string(args) != "config check -c aws/prod/aratam.yaml --format json\n" {
				t.Errorf("aratam was called with %q", args)
			}
			if tc.exit != 0 {
				if !strings.Contains(errOut, "::error::") {
					t.Errorf("a failure must say why:\n%s", errOut)
				}
				// aratam の出力 (設定の中身・ログ) は、失敗の説明に写さない
				for _, leak := range []string{"slack bot", "email", "add-mask", "flag provided", "CONFIG_INVALID"} {
					if strings.Contains(out+errOut, leak) {
						t.Errorf("leaked %q:\n%s%s", leak, out, errOut)
					}
				}
			}
		})
	}
	t.Run("usage", func(t *testing.T) {
		bin := fakeBin(t, "aratam", "echo called >&2\n")
		for _, args := range [][]string{nil, {"a.yaml", "b.yaml"}} {
			if out, errOut, code := runMethodScript(t, bin, args...); code != 1 || out != "" || strings.Contains(errOut, "called") {
				t.Errorf("%v: stdout %q exit %d\n%s", args, out, code, errOut)
			}
		}
	})
	if out, err := exec.Command("bash", "-n", methodScript).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if fi, err := os.Stat(methodScript); err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("the script must be executable: %v", err)
	}
}

var (
	aratamOnce sync.Once
	aratamDir  string
	aratamErr  error
)

// realAratam はこのリポジトリの aratam をビルドした置き場所 (PATH に足す)。config check は Slack にも LLM にも繋がない。
func realAratam(t *testing.T) string {
	t.Helper()
	aratamOnce.Do(func() {
		aratamDir, aratamErr = os.MkdirTemp("", "aratam-bin-*")
		if aratamErr != nil {
			return
		}
		cmd := exec.Command("go", "build", "-o", filepath.Join(aratamDir, "aratam"), "../../cmd/aratam")
		if out, err := cmd.CombinedOutput(); err != nil {
			aratamErr = &buildError{string(out), err}
		}
	})
	if aratamErr != nil {
		t.Fatalf("building aratam: %v", aratamErr)
	}
	return aratamDir
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

func TestMain(m *testing.M) {
	code := m.Run()
	if aratamDir != "" {
		os.RemoveAll(aratamDir)
	}
	os.Exit(code)
}

// スクリプトと、本物の aratam の出力 (この版の config check --format json) が噛み合うこと。偽の出力だけで確かめない。
func TestSlackMethodScriptWithTheRealAratam(t *testing.T) {
	bin := realAratam(t)
	scaffold, err := exec.Command(filepath.Join(bin, "aratam"), "config", "init", "--out", "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "aratam.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	replace := func(s string, pairs ...string) string {
		for i := 0; i < len(pairs); i += 2 {
			if !strings.Contains(s, pairs[i]) {
				t.Fatalf("the scaffold lacks %q", pairs[i])
			}
			s = strings.Replace(s, pairs[i], pairs[i+1], 1)
		}
		return s
	}
	// 雛形は bot トークンの方式 (ADR 0061)。Webhook の方式 (非推奨。動き続ける) の設定は、雛形を書き換えて作る
	webhook := replace(string(scaffold), "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`,
		`webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ", `urgent_webhook_env: "" `, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ")
	bot := replace(webhook, "webhook_env: ARATAM_SLACK_WEBHOOK ", `webhook_env: "" `, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ", `urgent_webhook_env: "" `,
		`bot_token_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `  channel: ""`, "  channel: C0123456789")
	// timezone を書いた設定でも変わらない (人向けの行の末尾に timezone が足されて、判別が外れたことがある)
	botTokyo := replace(bot, "timezone: UTC", "timezone: Asia/Tokyo")
	both := replace(webhook, `bot_token_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `  channel: ""`, "  channel: C0123456789")
	for _, tc := range []struct {
		name, body, want string
		exit             int
	}{
		{"webhook", webhook, "webhook\n", 0},
		{"bot", bot, "bot\n", 0},
		{"bot with a timezone", botTokyo, "bot\n", 0},
		{"both methods", both, "", 1},
		{"broken", "name: [", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runMethodScript(t, bin, write(tc.body))
			if out != tc.want || code != tc.exit {
				t.Fatalf("stdout %q exit %d, want %q exit %d\n%s", out, code, tc.want, tc.exit, errOut)
			}
		})
	}
	if out, _, code := runMethodScript(t, bin, filepath.Join(t.TempDir(), "none.yaml")); out != "" || code != 1 {
		t.Fatalf("missing file: %q exit %d", out, code)
	}
}

// --urgent-webhook は、緊急用の Webhook を別に持つか (.slack.urgent_webhook) を true / false で出す。
// ワークフローは、true のときだけ緊急用の Webhook の秘密を notify に渡す (使わない秘密の箱が、仮の値のままでも止まらないように。ADR 0059)。
// 真偽値でなければ止める (項目を知らない古い aratam・読めない設定・JSON でない出力)。決めつけて先へ進まない。
func TestSlackMethodScriptUrgentWebhook(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		exit             int
	}{
		{"true", `echo '{"ok":true,"slack":{"method":"webhook","format":"text","urgent_webhook":true},"rows":[]}'`, "true\n", 0},
		{"false", `echo '{"ok":true,"slack":{"method":"webhook","urgent_webhook":false},"rows":[]}'`, "false\n", 0},
		{"bot", `echo '{"ok":true,"slack":{"method":"bot","urgent_webhook":false},"rows":[]}'`, "false\n", 0},
		{"old aratam without the field", `echo '{"ok":true,"slack":{"method":"webhook","format":"text"},"rows":[]}'`, "", 1},
		{"string instead of a boolean", `echo '{"ok":true,"slack":{"method":"webhook","urgent_webhook":"true"},"rows":[]}'`, "", 1},
		{"null", `echo '{"ok":true,"slack":{"urgent_webhook":null}}'`, "", 1},
		{"no slack", `echo '{"ok":false,"rows":[]}'; exit 2`, "", 1},
		{"failed but printed a value", `echo '{"slack":{"urgent_webhook":true}}'; exit 2`, "", 1},
		{"not json", `echo 'ok    aratam.yaml: urgent_webhook true'`, "", 1},
		{"two documents", `echo '{"slack":{"urgent_webhook":true}}'; echo '{"slack":{"urgent_webhook":false}}'`, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runMethodScript(t, fakeBin(t, "aratam", tc.body+"\n"), "--urgent-webhook", "aws/prod/aratam.yaml")
			if out != tc.want || code != tc.exit {
				t.Fatalf("stdout %q exit %d, want %q exit %d\n%s", out, code, tc.want, tc.exit, errOut)
			}
			if tc.exit != 0 && !strings.Contains(errOut, "::error::") {
				t.Errorf("a failure must say why:\n%s", errOut)
			}
		})
	}
	// 引数の数が違えば止まる
	if _, _, code := runMethodScript(t, fakeBin(t, "aratam", "exit 0\n"), "--urgent-webhook"); code != 1 {
		t.Errorf("missing file argument: exit %d", code)
	}
}

// 本物の aratam (この版) の出力と噛み合うこと: 雛形 (緊急用の Webhook あり) は true、urgent_webhook_env を空にすると false、bot は false。
func TestSlackMethodScriptUrgentWebhookWithTheRealAratam(t *testing.T) {
	bin := realAratam(t)
	scaffold, err := exec.Command(filepath.Join(bin, "aratam"), "config", "init", "--out", "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	replace := func(s string, pairs ...string) string {
		for i := 0; i < len(pairs); i += 2 {
			if !strings.Contains(s, pairs[i]) {
				t.Fatalf("the scaffold lacks %q", pairs[i])
			}
			s = strings.Replace(s, pairs[i], pairs[i+1], 1)
		}
		return s
	}
	// 雛形は bot トークンの方式 (ADR 0061)。Webhook の方式 (非推奨。動き続ける) の設定は、雛形を書き換えて作る
	webhook := replace(string(scaffold), "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `bot_token_env: ""`,
		`webhook_env: "" `, "webhook_env: ARATAM_SLACK_WEBHOOK ", `urgent_webhook_env: "" `, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ")
	noUrgent := replace(webhook, "urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK ", `urgent_webhook_env: "" `)
	bot := replace(noUrgent, "webhook_env: ARATAM_SLACK_WEBHOOK ", `webhook_env: "" `, `bot_token_env: ""`, "bot_token_env: ARATAM_SLACK_BOT_TOKEN", `  channel: ""`, "  channel: C0123456789")
	for _, tc := range []struct{ name, body, want string }{
		{"webhook with the urgent webhook", webhook, "true\n"},
		{"webhook without the urgent webhook", noUrgent, "false\n"},
		{"bot", bot, "false\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "aratam.yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, errOut, code := runMethodScript(t, bin, "--urgent-webhook", p); out != tc.want || code != 0 {
				t.Fatalf("stdout %q exit %d, want %q\n%s", out, code, tc.want, errOut)
			}
		})
	}
}
