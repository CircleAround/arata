package githubactions_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 取得の回の hourly の判定 (arata repo init --flash。ADR 0082)。偽の arata で run: を動かす (実の AWS・Slack には繋がない)。
//   - 引数は run --profile hourly と設定と出力のディレクトリだけ。ログには INFO 以外の level / code / source だけ
//   - 0 と 3 (一部が取れなかった) は report.json があるので aratam へ進む印 (reported=true) を付ける。3 は警告にして成功にする
//   - ほかの失敗はそのまま返し、印を付けない (確定していないので aratam を呼ばない)
func TestFlashHourlyStep(t *testing.T) {
	w, _ := load(t, collectFile)
	s := stepByID(t, w, "hourly")
	if s.TimeoutMinutes != 15 || s.ContinueOnErr != nil || s.If != "" || len(s.Env) != 0 {
		t.Errorf("hourly: %+v", s)
	}
	for exit, tc := range map[int]struct {
		code     int
		reported bool
	}{0: {0, true}, 3: {0, true}, 1: {1, false}, 2: {2, false}, 130: {130, false}} {
		t.Run(fmt.Sprintf("exit=%d", exit), func(t *testing.T) {
			bin := fakeBin(t, "arata", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\n"+leakyLog+fmt.Sprintf("exit %d\n", exit))
			out, code, tmp := runStep(t, s.Run, bin, "ARATA_CONFIG_DIR=aws/prod")
			if code != tc.code {
				t.Errorf("exit code: got %d want %d\n%s", code, tc.code, out)
			}
			if got := output(t, tmp) == "reported=true\n"; got != tc.reported || (!tc.reported && output(t, tmp) != "") {
				t.Errorf("GITHUB_OUTPUT %q", output(t, tmp))
			}
			if warned := strings.Contains(out, "::warning::"); warned != (exit == 3) {
				t.Errorf("warning=%v for exit %d:\n%s", warned, exit, out)
			}
			for _, secret := range []string{"123456789012", "alice@example.com", "collect ok", "report body"} {
				if strings.Contains(out, secret) {
					t.Errorf("leaked %q:\n%s", secret, out)
				}
			}
			args, err := os.ReadFile(filepath.Join(tmp, "args"))
			if want := "run\n-c\naws/prod/arata.yaml\n--profile\nhourly\n--out\n" + filepath.Join(tmp, "arata-out") + "\n"; err != nil || string(args) != want {
				t.Errorf("args: %q %v", args, err)
			}
		})
	}
	// aratam は判定が報告を書いた回だけ動く (判定が失敗した回に「実行されていない」を毎時に送らない)
	if n := stepByID(t, w, "notify"); n.If != "always() && steps.hourly.outputs.reported == 'true'" || n.TimeoutMinutes != 5 {
		t.Errorf("notify: %+v", n)
	}
}

// 1 時間ごとの通知が届かなかったときの知らせ (ADR 0082 の 6 節)。知らせるべき指摘 (new・changed・recurred) があった回だけ送る。
// 数は report.json を数として読む。指摘の中身・件数は送らない。
func TestFlashAlertOnlyWhenSomethingWasNotDelivered(t *testing.T) {
	w, _ := load(t, collectFile)
	a := stepByID(t, w, "alert")
	if a.If != "failure() && github.event_name == 'schedule' && steps.notify.outcome == 'failure' && steps.notify.outputs.delivered != 'true'" {
		t.Errorf("if: %q", a.If)
	}
	if len(a.Env) != 3 || a.Env["SLACK_BOT_TOKEN"] != "${{ secrets.ARATAM_SLACK_BOT_TOKEN }}" || a.Env["ALERT_CHANNEL"] != alertChannel {
		t.Errorf("env: %v", a.Env)
	}
	if a.TimeoutMinutes == 0 || a.ContinueOnErr != nil {
		t.Errorf("alert needs a timeout and must fail loudly")
	}
	// 知らせを送る部分は、監査と同じ (同じ送り方で確かめて、初めて確認になる)
	audit, _ := load(t, multiFile)
	_, send, _ := strings.Cut(stepByID(t, audit, "alert").Run, "# ここから下は")
	_, mine, _ := strings.Cut(a.Run, "# ここから下は")
	if send == "" || send != mine {
		t.Errorf("the sending part differs from the audit's alert:\n%s\n---\n%s", mine, send)
	}
	want := "arata の 1 時間ごとの通知を送れていません (知らせるべき指摘があります)。対象: prod / プロファイル: hourly / https://github.example/acme/audit/actions/runs/42"
	env := []string{"SLACK_BOT_TOKEN=" + fakeToken, "ALERT_CHANNEL=" + alertChannel, "ACCOUNT=prod", "RUN_URL=https://github.example/acme/audit/actions/runs/42"}
	report := func(t *testing.T, tmp, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(tmp, "arata-out"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "arata-out", "report.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		body string
		send bool
	}{
		"new high":         {`{"summary":{"new":1,"changed":0,"recurred":0,"max_severity":"high"},"findings":{"new":[{"summary":"alice@example.com 123456789012"}]}}`, true},
		"changed":          {`{"summary":{"new":0,"changed":2,"recurred":0}}`, true},
		"quiet":            {`{"summary":{"new":0,"changed":0,"recurred":0,"still_open":3}}`, false},
		"not numbers":      {`{"summary":{"new":"1; echo LEAK-IN","changed":null}}`, false},
		"not json":         {`<html>LEAK-IN</html>`, false},
		"no report.json":   {"", false},
		"negative numbers": {`{"summary":{"new":-1,"changed":0,"recurred":0}}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			// runStep は RUNNER_TEMP を自分で作るので、report.json は RUNNER_TEMP を上書きして置く
			tmp := t.TempDir()
			if tc.body != "" {
				report(t, tmp, tc.body)
			}
			out, code, _ := runStep(t, a.Run, fakeCurl(t, 0, `{"ok":true}`), append(env, "RUNNER_TEMP="+tmp)...)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			_, err := os.Stat(filepath.Join(tmp, "curl-args"))
			if sent := err == nil; sent != tc.send {
				t.Fatalf("sent=%v want %v\n%s", sent, tc.send, out)
			}
			if tc.send {
				checkAlertCall(t, tmp, want)
			}
			noLeak(t, out)
		})
	}
}
