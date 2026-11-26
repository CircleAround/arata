package githubactions_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 利用者のログの集計の数 (user-coverage)。数と、決まった形の名前だけを Actions のログに出す。

// 値は架空。数でない値・形に合わない名前には leak- か 123456789012 を入れ、出力に現れないことを見る。
const userCoverageReportJSON = `{"name":"leak-name 123456789012","findings":{"new":[{"key":"leak-key"}]},
"coverage":{"notes":["leak-note"],"formats":[
{"source":"prod-nginx-access","log_group":"/leak/group","requests":{"total":9}},
{"source":"Prod.app log","log_group":"/leak/group","requests":{"total":50,
"users":{"from":"leak-from","with_user":41,"user_rate":0.82,"with_by":2,"user_id_invalid":3,"extra":"leak-extra",
"kinds":{"member":30,"admin_user":11,"198.51.100.8":1,"alice@example.com":2,"Leak-Kind":3,"staff":"leak-count"}},
"auth":{"success":7,"failure":4,"impersonate":1,"invalid":"leak-invalid",
"via":{"":5,"password":2,"/leak/path":9},
"reasons":{"bad_password":4,"leak reason 123456789012":1}}}},
{"source":"leak/123456789012","requests":{"users":{"with_user":"123456789012","user_rate":null,"kinds":"leak-kinds"}}}
]}}`

func TestUserCoverageLogsOnlyCounts(t *testing.T) {
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		s := stepByID(t, w, "user-coverage")
		// daily の実行で出すので、条件は always() だけ
		if s.If != "always()" {
			t.Errorf("user-coverage must run in every run, even when arata fails: %q", s.If)
		}
		if len(s.Env) != 0 {
			t.Errorf("user-coverage needs no secrets: %v", s.Env)
		}
		if s.TimeoutMinutes == 0 {
			t.Errorf("user-coverage needs a timeout")
		}
		order := map[string]int{}
		for i, s := range steps(t, w) {
			order[s.ID] = i
		}
		if !(order["audit"] < order["user-coverage"] && order["user-coverage"] < order["dry-run-summary"]) {
			t.Errorf("step order: %v", order)
		}

		run := func(report string) string {
			t.Helper()
			tmp := t.TempDir()
			if report != "" {
				if err := os.MkdirAll(filepath.Join(tmp, "arata-out"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(tmp, "arata-out", "report.json"), []byte(report), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out, code, _ := runStep(t, s.Run, t.TempDir(), "RUNNER_TEMP="+tmp)
			if code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			return strings.TrimSpace(out)
		}

		want := `[{"source":"Prod.app log","users":{"with_user":41,"user_rate":0.82,"with_by":2,"user_id_invalid":3,"kinds":{"member":30,"admin_user":11,"staff":null}},` +
			`"auth":{"success":7,"failure":4,"impersonate":1,"invalid":null,"via":{"":5,"password":2},"reasons":{"bad_password":4}}},` +
			`{"source":null,"users":{"with_user":null,"user_rate":null,"with_by":null,"user_id_invalid":null,"kinds":null},"auth":null}]`
		if out := run(userCoverageReportJSON); out != want {
			t.Errorf("output:\n%s\nwant:\n%s", out, want)
		}
		// 利用者のソースの無い設定では、空の配列だけ
		if out := run(`{"coverage":{"formats":[{"source":"prod-nginx-access"}]}}`); out != "[]" {
			t.Errorf("without user sources: %s", out)
		}
		if out := run(""); out != "報告がありません" {
			t.Errorf("without a report: %s", out)
		}
		if out := run(`{"coverage": "123456789012", "formats": [`); out != "報告を読めませんでした" {
			t.Errorf("broken report: %s", out)
		}
	})
}

// 項目名は report の型に合わせる (型の名前が変わると、上の固定の JSON では気づけないので、型から作った報告でも確かめる)。
func TestUserCoverageReadsReportTypes(t *testing.T) {
	rate := 0.5
	report := schema.Report{Coverage: schema.Coverage{Formats: []schema.FormatCoverage{{
		Source: "prod-app-log",
		Requests: &schema.RequestCoverage{
			Users: &schema.UserCoverage{From: "app_line", WithUser: 11, UserRate: &rate, Kinds: map[string]int64{"member": 12}, WithBy: 13, Invalid: 14},
			Auth: &schema.AuthCoverage{Success: 15, Via: map[string]int64{"password": 16}, Failure: 17,
				Reasons: map[string]int64{"bad_password": 18}, Impersonate: 19, Invalid: 20},
		},
	}}}}
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	forEachWorkflow(t, func(t *testing.T, w *workflow, text string) {
		tmp := t.TempDir()
		if err := os.MkdirAll(filepath.Join(tmp, "arata-out"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, "arata-out", "report.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		out, code, _ := runStep(t, stepByID(t, w, "user-coverage").Run, t.TempDir(), "RUNNER_TEMP="+tmp)
		want := `[{"source":"prod-app-log","users":{"with_user":11,"user_rate":0.5,"with_by":13,"user_id_invalid":14,"kinds":{"member":12}},` +
			`"auth":{"success":15,"failure":17,"impersonate":19,"invalid":20,"via":{"password":16},"reasons":{"bad_password":18}}}]`
		if code != 0 || strings.TrimSpace(out) != want {
			t.Errorf("exit %d\n%s\nwant:\n%s", code, out, want)
		}
	})
}
