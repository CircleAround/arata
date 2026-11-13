package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
)

// appConfig は trail + nginx (http_access) + waf (waf_action) の設定。
func (c *cli) appConfig(extra string) {
	c.writeConfig(fmt.Sprintf(`
name: acme
store: dir://%s/store
aws:
  region: ap-northeast-1
sources:
  - id: trail
    kind: cloudtrail-lookup
  - id: web
    kind: cloudwatch-logs
    log_group: /app/nginx
    format: nginx_access
  - id: rails
    kind: cloudwatch-logs
    log_group: /app/rails
    format: json
    fields: { ip: remote_ip, path: path, status: status }
    expected_match_rate: 0.6
%sprofiles:
  daily:
    window: 24h
    checks: [default-daily]
`, c.dir, extra))
}

func doctorRows(matched, unmatched int) cwlogstest.Response {
	var rows []map[string]string
	for i := 0; i < matched; i++ {
		rows = append(rows, cwlogstest.Rows("@timestamp", "2026-10-21 08:00:00.000", "@message", "ok", "arata_matched", "1"))
	}
	for i := 0; i < unmatched; i++ {
		rows = append(rows, cwlogstest.Rows("@timestamp", "2026-10-21 08:00:00.000", "@message", fmt.Sprintf(`Started GET "/users/%d" for 198.51.100.%d user=carol@example.com`, i, i), "arata_matched", "0"))
	}
	return cwlogstest.Response{Rows: rows}
}

func TestDoctor(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		c := newCLI(t)
		c.appConfig("")
		c.logs.LogGroups = []string{"/app/nginx", "/app/nginx-old", "/app/rails"}
		c.logs.On("sort @timestamp desc", doctorRows(97, 3))
		if code := c.run("doctor", "--config", c.cfg); code != 0 {
			t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
		}
		compareGolden(t, "doctor.txt", c.stdout.Bytes())
		// appConfig は daily だけなので hourly のチェックが入っていない。warn は終了コードを変えず、標準エラーに CHECK_UNUSED を出す
		if strings.Join(c.codes(), ",") != "CHECK_UNUSED" {
			t.Fatalf("codes: %v", c.codes())
		}
		if strings.Contains(c.stdout.String(), "carol") {
			t.Fatal("samples must be masked")
		}
		// テンプレートの構文検査は Start してすぐ Stop する (doctor のサンプル取得 2 本以外は全部 Stop)
		if len(c.logs.Stopped) == 0 || len(c.logs.Stopped) != len(c.logs.Started)-2 {
			t.Fatalf("started %d stopped %d", len(c.logs.Started), len(c.logs.Stopped))
		}
		c.assertCodesInVocabulary()
	})
	t.Run("problems", func(t *testing.T) {
		c := newCLI(t)
		c.appConfig("")
		c.fake.Err = cloudtrailtest.APIError{Code: "AccessDeniedException"}
		c.logs.LogGroups = []string{"/app/nginx"} // /app/rails が無い
		c.logs.On("sort @timestamp desc", doctorRows(10, 90))
		c.logs.On("as http_hits", cwlogstest.Response{StartErr: cwlogstest.APIError{Code: "MalformedQueryException"}})
		if code := c.run("doctor", "--config", c.cfg, "--format", "json"); code != 2 {
			t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
		}
		var res struct {
			Rows []struct {
				Source, Item, Status, Code, Detail string
				Samples                            []string
			}
			RequiredActions []string `json:"required_actions"`
		}
		if err := json.Unmarshal(c.stdout.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, r := range res.Rows {
			if r.Status == "ng" {
				got[r.Source+"/"+r.Item] += r.Code + " "
			}
			if r.Code == "FORMAT_MISMATCH" && (len(r.Samples) != 3 || strings.Contains(strings.Join(r.Samples, ""), "carol")) {
				t.Fatalf("samples: %v", r.Samples)
			}
			if r.Code == "ACCESS_DENIED" && !strings.Contains(r.Detail, "cloudtrail:LookupEvents") {
				t.Fatalf("denied action must be named: %s", r.Detail)
			}
		}
		want := map[string]string{
			"trail/permission": "ACCESS_DENIED ACCESS_DENIED ", // 2 リージョン
			"web/match_rate":   "FORMAT_MISMATCH ",
			"web/queries":      "QUERY_INVALID ",
			"rails/log_group":  "LOG_GROUP_MISSING ",
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("ng rows:\n got %v\nwant %v", got, want)
		}
		if strings.Join(res.RequiredActions, ",") != "cloudtrail:LookupEvents,logs:DescribeLogGroups,logs:GetQueryResults,logs:StartQuery,logs:StopQuery" {
			t.Fatalf("required actions: %v", res.RequiredActions)
		}
		codes := strings.Join(c.codes(), ",")
		for _, want := range []string{"ACCESS_DENIED", "FORMAT_MISMATCH", "QUERY_INVALID", "LOG_GROUP_MISSING"} {
			if !strings.Contains(codes, want) {
				t.Fatalf("stderr codes %s lack %s", codes, want)
			}
		}
		c.assertCodesInVocabulary()
	})
	t.Run("doctor query rejected", func(t *testing.T) {
		c := newCLI(t)
		c.appConfig("")
		c.logs.LogGroups = []string{"/app/nginx", "/app/rails"}
		// 本番で見つかった方言の問題 (parse で定義したフィールドの再宣言) のように、doctor 自身のクエリが拒否された場合も queries 行に出る
		c.logs.On("sort @timestamp desc", cwlogstest.Response{StartErr: cwlogstest.APIError{Code: "MalformedQueryException"}})
		if code := c.run("doctor", "--config", c.cfg, "--format", "json"); code != 2 {
			t.Fatalf("exit %d", code)
		}
		var res struct {
			Rows []struct{ Source, Item, Status, Code, Detail string }
		}
		_ = json.Unmarshal(c.stdout.Bytes(), &res)
		var got []string
		for _, r := range res.Rows {
			if r.Source == "web" && r.Status == "ng" {
				got = append(got, r.Item+":"+r.Code+":"+strings.SplitN(r.Detail, ":", 2)[0])
			}
		}
		if strings.Join(got, ",") != "queries:QUERY_INVALID:doctor,match_rate:QUERY_INVALID:MalformedQueryException" {
			t.Fatalf("ng rows: %v", got)
		}
	})
	t.Run("does not take the store lock", func(t *testing.T) {
		c := newCLI(t)
		c.appConfig("")
		c.logs.LogGroups = []string{"/app/nginx", "/app/rails"}
		if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
			t.Fatalf("init exit %d: %s", code, c.stderr)
		}
		if code := c.run("doctor", "--config", c.cfg); code != 0 {
			t.Fatalf("exit %d: %s", code, c.stderr)
		}
	})
}

// TestNewLogGroup は作ったばかりのロググループをソースにしたとき、init・doctor・run が止まらないことを確かめる。
// Insights は問い合わせの終わりが作成時刻より前の範囲を MalformedQueryException で拒否する (フェイクも同じ)。
func TestNewLogGroup(t *testing.T) {
	c := newCLI(t)
	c.appConfig("")
	c.logs.Now = func() time.Time { return c.now }
	c.logs.Groups = map[string]cwlogstest.Group{
		"/app/nginx": {Created: c.now.Add(-time.Hour), RetentionDays: 7},
		"/app/rails": {Created: c.now.AddDate(0, -1, 0), RetentionDays: 7},
	}
	c.logs.On("sort @timestamp desc", doctorRows(10, 0))
	if code := c.run("init", "--config", c.cfg, "--window", "3d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	if code := c.run("doctor", "--config", c.cfg); code != 0 {
		t.Fatalf("doctor exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	// appConfig は daily だけなので doctor の CHECK_UNUSED (warn) だけが出る
	if codes := strings.Join(c.codes(), ","); codes != "CHECK_UNUSED" {
		t.Fatalf("codes: %v", codes)
	}
}

// TestAppLayerRun は Logs Insights の集計から login_bruteforce が新規として報告され、翌日は鳴らないことを確かめる。
func TestAppLayerRun(t *testing.T) {
	c := newCLI(t)
	c.appConfig("")
	lines := func(day string) cwlogstest.Response {
		return cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", day+" 00:00:00.000", "lines_total", "1000", "lines_matched", "990")}}
	}
	c.logs.On("as lines_total", lines("2026-10-21"))
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.logs.On("as lines_total", lines("2026-10-22"))
	c.logs.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", "2026-10-22 00:00:00.000", "ip", "198.51.100.7", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "120"),
	}})
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	var rep struct {
		Summary  struct{ New int }
		Findings struct {
			New []struct{ Check, Key, Severity string }
		}
		Coverage struct {
			SourcesOK []string `json:"sources_ok"`
			Formats   []struct {
				Source    string
				MatchRate float64 `json:"match_rate"`
			}
			ChecksRun []string `json:"checks_run"`
		}
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.New != 1 || rep.Findings.New[0].Check != "login_bruteforce" || rep.Findings.New[0].Key != "198.51.100.7" || rep.Findings.New[0].Severity != "medium" {
		t.Fatalf("findings: %+v", rep.Findings)
	}
	if len(rep.Coverage.Formats) != 2 || rep.Coverage.Formats[0].MatchRate != 0.99 || strings.Join(rep.Coverage.SourcesOK, ",") != "trail,web,rails" {
		t.Fatalf("coverage: %+v", rep.Coverage)
	}
	if !strings.Contains(strings.Join(rep.Coverage.ChecksRun, ","), "login_bruteforce,new_principal,principal_new_source,probe_paths") {
		t.Fatalf("checks_run: %v", rep.Coverage.ChecksRun)
	}
	// 翌日: 同じ IP が続けて失敗しても event 型なので still_open で沈黙する
	c.now = c.now.Add(24 * time.Hour)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	_ = json.Unmarshal(c.stdout.Bytes(), &rep)
	if rep.Summary.New != 0 {
		t.Fatalf("next day must be quiet: %+v", rep.Summary)
	}
	c.assertCodesInVocabulary()
}

// TestProfileOverridesAndUnusedChecks はプロファイルの overrides が判定に効くこと、どのプロファイルにも入っていないチェックが CHECK_UNUSED で警告されることを確かめる。
func TestProfileOverridesAndUnusedChecks(t *testing.T) {
	c := newCLI(t)
	c.appConfig("")
	body, err := os.ReadFile(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// 全体の既定 (min_count 20) なら web と rails の合算 180 件で鳴るが、daily だけ 200 に上げる
	c.writeConfig(string(body) + "    overrides:\n      login_bruteforce: { min_count: 200 }\n")
	c.logs.On("as lines_total", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "lines_total", "1000", "lines_matched", "990")}})
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.logs.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", "2026-10-22 00:00:00.000", "ip", "198.51.100.7", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "90"),
	}})
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	var rep struct{ Summary struct{ New int } }
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil || rep.Summary.New != 0 {
		t.Fatalf("overrides must raise the threshold: %v %s", err, c.stdout)
	}
	var warned map[string]any
	for _, m := range c.logLines() {
		if m["code"] == "CHECK_UNUSED" {
			warned = m
		}
	}
	if warned == nil || warned["level"] != "WARN" || fmt.Sprint(warned["checks"]) != "[root_usage unknown_assume_role credential_hygiene guardduty_findings posture access_analyzer waf_review log_hygiene]" {
		t.Fatalf("CHECK_UNUSED: %v", warned)
	}
	if code := c.run("evaluate", "--config", c.cfg, "--profile", "daily"); code != 0 || !strings.Contains(strings.Join(c.codes(), ","), "CHECK_UNUSED") {
		t.Fatalf("evaluate must warn: exit %d %v", code, c.codes())
	}
	c.assertCodesInVocabulary()
}

// wafv2 のソースの doctor (ADR 0028): resources を WebACL の資源と突き合わせ、Insights の費用を見積もる。max_scan_gb が無ければ warn。
func TestDoctorWAF(t *testing.T) {
	setup := func(t *testing.T, extra string) *cli {
		c := newCLI(t)
		c.appConfig(`  - id: waf
    kind: cloudwatch-logs
    log_group: aws-waf-logs-prod
    format: wafv2
    resources: ["123456789012:abcde12345:prod", "app/app-alb/*", "app/missing-alb/*"]
` + extra)
		c.logs.LogGroups = []string{"/app/nginx", "/app/rails", "aws-waf-logs-prod"}
		resp := doctorRows(100, 0)
		resp.BytesScanned = 5e9 // 直近 24h のスキャン量 = 1 日のログ 5 GB
		c.logs.On("sort @timestamp desc", resp)
		c.logs.On("as lines_total", cwlogstest.Response{BytesScanned: 4e9})
		acl := accounttest.WebACL(waftypes.ScopeRegional, "ap-northeast-1", "prod-waf")
		c.acct.WAF = &accounttest.WAF{
			WebACLs: map[string][]waftypes.WebACL{"REGIONAL|ap-northeast-1": {acl}},
			Logging: map[string][]string{*acl.ARN: {"arn:aws:logs:ap-northeast-1:123456789012:log-group:aws-waf-logs-prod"}},
			Resources: map[string]map[waftypes.ResourceType][]string{*acl.ARN: {
				waftypes.ResourceTypeApplicationLoadBalancer: {"arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/app-alb/50dc6c495c0c9188"},
				waftypes.ResourceTypeApiGateway:              {"arn:aws:apigateway:ap-northeast-1::/restapis/abcde12345/stages/prod"},
			}},
		}
		return c
	}
	rows := func(t *testing.T, c *cli, args ...string) map[string][2]string {
		t.Helper()
		if code := c.run(append([]string{"doctor", "--config", c.cfg, "--format", "json"}, args...)...); code != 0 {
			t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
		}
		var res struct {
			Rows []struct{ Source, Item, Status, Detail string }
		}
		if err := json.Unmarshal(c.stdout.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		out := map[string][2]string{}
		for _, r := range res.Rows {
			if r.Source == "waf" {
				out[r.Item] = [2]string{r.Status, r.Detail}
			}
		}
		return out
	}

	c := setup(t, "")
	got := rows(t, c)
	res := got["resources"]
	if res[0] != "warn" || !strings.Contains(res[1], "app/missing-alb/*") || strings.Contains(res[1], "app/app-alb/*") || !strings.Contains(res[1], "prod-waf") {
		t.Fatalf("resources: %v", res)
	}
	cost := got["cost"]
	// 既定は直近 24h に解釈率の集計 (stats) を流して実測する (sandbox で sort+limit のスキャン量は約 75% に少なく出た。ADR 0028)。
	// 実測した範囲・読み取り量・その費用も出す
	// クエリは 4 本 (ADR 0031)。範囲は実行時刻で決まるので、最小になる時刻 (UTC 0 時 + ingest_delay + 余裕 15 分) と、その時の量も出す。
	// 直近の run が無ければ今の実行時刻の範囲は出さない
	for _, want := range []string{"4.00 GB", "実測", "直近 24h", "読み取り 4.00 GB", "約 0.03 USD", "daily", "32.06 GB", "4 本", "0.24 USD", "7.31 USD", "0.0076 USD/GB", "max_scan_gb", "推奨 49",
		"UTC 00:20 (JST 09:20) に回すと約 24.3 時間 (1 回 16.22 GB、約 3.70 USD/30 日)"} {
		if !strings.Contains(cost[1], want) {
			t.Fatalf("cost lacks %q: %v", want, cost)
		}
	}
	if cost[0] != "warn" || strings.Contains(cost[1], "直近の run") {
		t.Fatalf("cost: %v", cost)
	}

	// 直近の daily の run (保存したレポートの窓の終わり) が UTC 22:00 (JST 07:00) なら、範囲は前日の 0 時からの約 46 時間
	c = setup(t, "")
	if err := os.MkdirAll(filepath.Join(c.dir, "store", "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, "store", "reports", "daily.json"), []byte(`{"window":{"from":"2026-10-19T22:00:00Z","to":"2026-10-20T22:00:00Z"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if cost := rows(t, c)["cost"]; !strings.Contains(cost[1], "直近の run (UTC 22:00、JST 07:00) では範囲 約 46.0 時間 (1 回 30.67 GB)") {
		t.Fatalf("cost: %v", cost)
	}

	// max_scan_gb があり、resources がすべて見つかれば ok。--no-measure-scan は解釈率のサンプルのスキャン量からの推定 (追加の読み取りなし)
	c = setup(t, "    max_scan_gb: 200\n")
	c.acct.WAF.Resources[*c.acct.WAF.WebACLs["REGIONAL|ap-northeast-1"][0].ARN][waftypes.ResourceTypeApplicationLoadBalancer] = append(
		c.acct.WAF.Resources[*c.acct.WAF.WebACLs["REGIONAL|ap-northeast-1"][0].ARN][waftypes.ResourceTypeApplicationLoadBalancer],
		"arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/missing-alb/0123456789abcdef")
	got = rows(t, c, "--no-measure-scan")
	if got["resources"][0] != "ok" {
		t.Fatalf("resources: %v", got["resources"])
	}
	if got["cost"][0] != "ok" || !strings.Contains(got["cost"][1], "5.00 GB") || !strings.Contains(got["cost"][1], "推定") || strings.Contains(got["cost"][1], "実測") {
		t.Fatalf("cost: %v", got["cost"])
	}
}
