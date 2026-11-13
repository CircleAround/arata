package githubactions_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 試しの実行 (arata run --dry-run。ADR 0049) の入力。定時の監査の 2 つの見本に同じ検査をかける。

// dryRunGroupSuffix は試しの実行の排他の group に付く接尾辞 (定時の実行では空になる式)。
const dryRunGroupSuffix = "${{ inputs.dry_run && '-dry-run' || '' }}"

func TestDryRunInputs(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		in := w.On.WorkflowDispatch.Inputs
		if d, ok := in["dry_run"]; !ok || d.Type != "boolean" || d.Required {
			t.Errorf("workflow_dispatch needs an optional boolean dry_run: %+v", d)
		}
		if d, ok := in["window"]; !ok || d.Type != "string" || d.Required {
			t.Errorf("workflow_dispatch needs an optional string window: %+v", d)
		}
		a := stepByID(t, w, "audit")
		if a.Env["DRY_RUN"] != "${{ inputs.dry_run }}" || a.Env["DRY_RUN_WINDOW"] != "${{ inputs.window }}" {
			t.Errorf("the inputs must reach the audit step through env: %v", a.Env)
		}
	})
}

// 試しの実行のときだけ --dry-run (と --window) を付ける。定時の実行 (入力が空) と dry_run が false の手動実行は今までどおり。
func TestDryRunArguments(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		for _, c := range []struct {
			env  []string
			want string
		}{
			{[]string{"DRY_RUN=true", "DRY_RUN_WINDOW=1h"}, "--dry-run\n--window\n1h\n"},
			{[]string{"DRY_RUN=true", "DRY_RUN_WINDOW="}, "--dry-run\n"},
			{[]string{"DRY_RUN=false", "DRY_RUN_WINDOW=1h"}, ""},
			{[]string{"DRY_RUN=", "DRY_RUN_WINDOW="}, ""},
			// 値はそのまま 1 つの引数として渡る (シェルに解釈させない)。妥当かは arata が確かめる
			{[]string{"DRY_RUN=true", "DRY_RUN_WINDOW=1h; touch pwned $(touch pwned)"}, "--dry-run\n--window\n1h; touch pwned $(touch pwned)\n"},
		} {
			bin := fakeBin(t, "arata", `printf '%s\n' "$@" >"$RUNNER_TEMP/args"`+"\n")
			dir := t.TempDir()
			_, code, tmp := runStepIn(t, dir, stepByID(t, w, "audit").Run, bin, c.env...)
			if code != 0 {
				t.Fatalf("%v: exit %d", c.env, code)
			}
			b, err := os.ReadFile(filepath.Join(tmp, "args"))
			if err != nil {
				t.Fatal(err)
			}
			want := "run\n-c\narata/arata.yaml\n--profile\ndaily\n--out\n" + tmp + "/arata-out\n" + c.want
			if string(b) != want {
				t.Errorf("%v: args:\n%s\nwant:\n%s", c.env, b, want)
			}
			if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
				t.Errorf("%v: the window was interpreted by the shell", c.env)
			}
		}
	})
}

// 試しの実行では通知せず、ストアのバケットにも何も置かない。排他の group も定時の実行と分ける
// (同じ group だと、待っている定時の実行を試しの実行が取り消し得る。試しの実行はストアに書かないので排他は要らない)。
func TestDryRunDoesNotNotifyOrWrite(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		for _, id := range []string{"notify", "save-proposals"} {
			if s := stepByID(t, w, id); !strings.Contains(s.If, "!inputs.dry_run") {
				t.Errorf("step %q must be skipped in a dry run: %q", id, s.If)
			}
		}
		c := w.Concurrency
		if w.file == multiFile {
			c = w.Jobs["audit"].Concurrency
		}
		if !strings.HasSuffix(c.Group, dryRunGroupSuffix) {
			t.Errorf("a dry run must use its own concurrency group: %q", c.Group)
		}
		order := map[string]int{}
		for i, s := range steps(t, w) {
			order[s.ID] = i
		}
		if !(order["audit"] < order["dry-run-summary"] && order["dry-run-summary"] < order["notify"]) {
			t.Errorf("step order: %v", order)
		}
	})
}

const dryRunReportJSON = `{"profile":"daily","dry_run":true,"name":"acme 123456789012","run_id":"r1",
"window":{"from":"2026-10-22T04:00:00Z","to":"2026-10-22T05:00:00Z"},
"summary":{"new":2,"changed":1,"recurred":0,"resolved":0,"still_open":3,"max_severity":"critical","collect_errors":[{"source":"trail","code":"ACCESS_DENIED","message":"arn:aws:iam::123456789012:role/x"}]},
"findings":{"new":[{"id":"f1","check":"root_usage","key":"arn:aws:iam::123456789012:root|198.51.100.8","severity":"critical","summary":"ルートアカウント 123456789012","data":{"ip":"198.51.100.8"}},
{"id":"f2","check":"iam_changes","key":"k","severity":"high\n::warning::injected 123456789012","summary":"s","data":{}}],
"changed":[{"id":"f3","check":"iam_changes","key":"k3","severity":"high","summary":"alice@example.com","data":{}}],"recurred":[],"resolved":[],"still_open":[]},
"coverage":{"sources_ok":[],"sources_failed":[{"source":"trail","code":"ACCESS_DENIED"}],"checks_run":[],"checks_skipped":[{"check":"x","reason":"source trail failed 123456789012"}],"formats":[],
"notes":["見た範囲は 123456789012"]}}`

// 試しの実行の結果は、件数と重大度だけを Actions のログに出す。指摘の中身 (主体・IP・要約) と注記の文は出さない。
func TestDryRunSummaryLogsOnlyCounts(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		s := stepByID(t, w, "dry-run-summary")
		if !strings.Contains(s.If, "always()") || !strings.Contains(s.If, "inputs.dry_run") || strings.Contains(s.If, "!inputs.dry_run") {
			t.Errorf("dry-run-summary must run only in a dry run, even when arata exits 3: %q", s.If)
		}
		if len(s.Env) != 0 {
			t.Errorf("dry-run-summary needs no secrets: %v", s.Env)
		}
		bin := t.TempDir()
		tmp := t.TempDir()
		// runStepIn は RUNNER_TEMP を自分で作るので、後ろに足した値で上書きして報告を先に置く
		if err := os.MkdirAll(filepath.Join(tmp, "arata-out"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "arata-out", "report.json"), []byte(dryRunReportJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		out, code, _ := runStep(t, s.Run, bin, "RUNNER_TEMP="+tmp)
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		for _, want := range []string{`"new":2`, `"changed":1`, `"still_open":3`, `"max_severity":"critical"`, `"critical":1`, `"high":1`, `"sources_failed":1`, `"checks_skipped":1`, `"notes":1`, "2026-10-22T04:00:00Z"} {
			if !strings.Contains(out, want) {
				t.Errorf("summary must show %s:\n%s", want, out)
			}
		}
		for _, secret := range []string{"123456789012", "198.51.100.8", "alice@example.com", "root_usage", "ルートアカウント", "injected", "::warning::", "見た範囲", "acme"} {
			if strings.Contains(out, secret) {
				t.Errorf("leaked %q:\n%s", secret, out)
			}
		}

		// 報告が無い (arata が失敗した) ときは、無いことだけを伝えて成功で終わる (失敗は audit の step が示している)
		out, code, _ = runStep(t, s.Run, bin)
		if code != 0 || strings.TrimSpace(out) == "" {
			t.Errorf("without a report: exit %d\n%s", code, out)
		}
		// 壊れた報告でも中身を出さない
		if err := os.WriteFile(filepath.Join(tmp, "arata-out", "report.json"), []byte(`{"summary": "123456789012", "findings": [`), 0o600); err != nil {
			t.Fatal(err)
		}
		out, _, _ = runStep(t, s.Run, bin, "RUNNER_TEMP="+tmp)
		if strings.Contains(out, "123456789012") {
			t.Errorf("leaked from a broken report:\n%s", out)
		}
	})
}
