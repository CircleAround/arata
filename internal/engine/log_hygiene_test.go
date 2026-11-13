package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
)

const hygieneSources = `  - id: app_prod
    kind: cloudwatch-logs
    log_group: prod-app
    format: text
    max_scan_gb: 5
`

const hygieneChecks = `checks:
  log_hygiene:
    sources: [app_prod]
    kinds: [secret_aws_access_key, secret_slack_token, secret_private_key, presigned_url_long_term_key, presigned_url, unfiltered_param, debug_sql]
    param_fields: [name, address, tel]
`

// hygieneQueryMark は log_hygiene のクエリだけが含む文字列 (偽の API の応答の振り分けに使う)。
const hygieneQueryMark = "as f_secret_aws_access_key"

// hygieneResult は log_hygiene のクエリへの応答 (書いていない列は 0)。
func hygieneResult(kv ...string) cwlogstest.Response {
	row := map[string]string{"n_lines": "5000"}
	for _, n := range []string{"n_secret_aws_access_key", "n_secret_slack_token", "n_secret_private_key", "n_presigned_url_long_term_key", "n_presigned_url",
		"n_unfiltered_param", "n_param_0", "n_param_1", "n_param_2", "n_debug_sql"} {
		row[n] = "0"
	}
	for i := 0; i+1 < len(kv); i += 2 {
		row[kv[i]] = kv[i+1]
	}
	return cwlogstest.Response{Rows: []map[string]string{row}, BytesScanned: 1e9}
}

func hygieneClasses(rep *report.Report) map[string]string {
	out := map[string]string{}
	for k, v := range classes(rep) {
		if key, ok := strings.CutPrefix(k, "log_hygiene/"); ok {
			out[key] = v
		}
	}
	return out
}

func hygieneQueries(h *harness) int {
	n := 0
	for _, q := range h.logs.Queries() {
		if strings.Contains(q, hygieneQueryMark) {
			n++
		}
	}
	return n
}

func TestLogHygieneWeekly(t *testing.T) {
	h := newHarnessWith(t, hygieneSources, hygieneChecks)
	h.logs.Groups = map[string]cwlogstest.Group{"prod-app": {Created: h.now.AddDate(0, -6, 0)}}
	h.logs.Now = func() time.Time { return h.now }
	h.logs.On(hygieneQueryMark, hygieneResult("n_unfiltered_param", "12", "n_param_0", "9", "n_param_2", "5", "n_secret_private_key", "1"))
	e := h.open(t)
	ctx := context.Background()

	// daily は log_hygiene を必要としない: text のソースを引かない
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.logs.Started) != 0 || strings.Contains(strings.Join(r.Report.Coverage.SourcesOK, ","), "app_prod") {
		t.Fatalf("daily must not read the text source: %v %+v", h.logs.Queries(), r.Report.Coverage)
	}

	// weekly: 1 本だけ流し、ロググループ × 種類で finding
	h.now = h.now.Add(time.Hour)
	r, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.logs.Started) != 1 || hygieneQueries(h) != 1 {
		t.Fatalf("weekly must run exactly one query: %v", h.logs.Queries())
	}
	if got := hygieneClasses(r.Report); len(got) != 2 || got["app_prod|unfiltered_param"] != "new" || got["app_prod|secret_private_key"] != "new" {
		t.Fatalf("classes: %v (skipped %+v, failed %v)", got, r.Report.Coverage.ChecksSkipped, r.Report.Coverage.SourcesFailed)
	}
	if !contains(r.Report.Coverage.SourcesOK, "app_prod") || !contains(r.Report.Coverage.ChecksRun, "log_hygiene") || len(r.Report.Coverage.Formats) != 0 {
		t.Fatalf("coverage: %+v", r.Report.Coverage)
	}
	var up report.Finding
	for _, f := range r.Report.Findings.New {
		if f.Key == "app_prod|unfiltered_param" {
			up = f
		}
	}
	if up.Severity != "medium" || up.Summary != "ロググループ prod-app のログに、隠されていない送信項目 (name, tel) が 12 行 (直近 7 日。保持期間は無期限)" ||
		up.Data["retention"] != "never" || up.Data["log_group"] != "prod-app" {
		t.Fatalf("finding: %+v", up)
	}
	if r.Report.Summary.MaxSeverity != "high" {
		t.Fatalf("max severity: %s", r.Report.Summary.MaxSeverity)
	}

	// 次の週: クエリが失敗 (max_scan_gb の超過)。スナップショットを置き換えず、finding を維持して sources_failed に出す
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.logs.On(hygieneQueryMark, cwlogstest.Response{Rows: hygieneResult().Rows, BytesScanned: 6e9})
	r, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitPartial || !sourceFailed(r.Report, "app_prod") {
		t.Fatalf("failed week: exit %d coverage %+v", r.Exit, r.Report.Coverage)
	}
	if got := hygieneClasses(r.Report); got["app_prod|unfiltered_param"] == "resolved" || got["app_prod|secret_private_key"] == "resolved" {
		t.Fatalf("a failed read must not resolve findings: %v", got)
	}
	items, _ := e.Store().Snapshot(ctx, record.KindLogHygiene)
	if len(items) != 7 {
		t.Fatalf("snapshot must be kept: %d items", len(items))
	}
	open, _ := e.Store().Findings(ctx, "log_hygiene", []string{"open"})
	if len(open) != 2 {
		t.Fatalf("findings must stay open: %+v", open)
	}

	// 読めない結果 (数でない値) も失敗。0 件として解消しない
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.logs.On(hygieneQueryMark, hygieneResult("n_unfiltered_param", "none"))
	r, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if open, _ := e.Store().Findings(ctx, "log_hygiene", []string{"open"}); len(open) != 2 || !sourceFailed(r.Report, "app_prod") {
		t.Fatalf("unreadable result must not resolve: %+v %+v", open, r.Report.Coverage)
	}
	// 失敗した週の分を追いついて読まない: 範囲は run の窓 (7 日) のまま (読み取りが倍になって max_scan_gb を超え続けない)
	if codes := strings.Join(h.logCodes(t), ","); strings.Contains(codes, CodeSourceCatchup) || r.Report.Window.From != h.now.Add(-7*24*time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("a hygiene-only source must not be caught up: codes %s, window %+v", codes, r.Report.Window)
	}
	if last := h.logs.Started[len(h.logs.Started)-1]; *last.StartTime != h.now.Add(-7*24*time.Hour).Unix() || *last.EndTime != h.now.Unix()-1 {
		t.Fatalf("range after a failed week: %s - %s", time.Unix(*last.StartTime, 0).UTC(), time.Unix(*last.EndTime, 0).UTC())
	}

	// 別の項目が当たり始めたら changed。行数だけが変わった種類は changed にしない
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.logs.On(hygieneQueryMark, hygieneResult("n_unfiltered_param", "20", "n_param_0", "9", "n_param_1", "3", "n_param_2", "8", "n_secret_private_key", "4"))
	r, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if got := hygieneClasses(r.Report); got["app_prod|unfiltered_param"] != "changed" || got["app_prod|secret_private_key"] != "still_open" {
		t.Fatalf("classes: %v", got)
	}

	// 直った週: 0 行 → 解消
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.logs.On(hygieneQueryMark, hygieneResult())
	r, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if got := hygieneClasses(r.Report); got["app_prod|unfiltered_param"] != "resolved" || got["app_prod|secret_private_key"] != "resolved" {
		t.Fatalf("classes: %v", got)
	}

	// 値を引くクエリを 1 本も流していない
	for _, q := range h.logs.Queries() {
		for _, bad := range []string{"display", "limit", "sort", "parse", "fields @message"} {
			if strings.Contains(q, bad) {
				t.Fatalf("query must not return values (%s):\n%s", bad, q)
			}
		}
	}
}

// 既存の形式のソースを log_hygiene でも読む: daily は今までどおりの集計だけ、weekly は衛生のクエリだけ。daily は衛生のスナップショットを消さない。
func TestLogHygieneOnAccessLogSource(t *testing.T) {
	h := newHarnessWith(t, nginxSource, strings.Replace(hygieneChecks, "[app_prod]", "[web]", 1))
	h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 950))
	h.logs.On(hygieneQueryMark, hygieneResult("n_presigned_url", "7"))
	e := h.open(t)
	ctx := context.Background()

	r, err := e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if got := hygieneClasses(r.Report); len(got) != 1 || got["web|presigned_url"] != "new" {
		t.Fatalf("weekly: %v %+v", got, r.Report.Coverage)
	}
	if len(h.logs.Started) != 1 || len(r.Report.Coverage.Formats) != 0 {
		t.Fatalf("weekly must run only the hygiene query: %v", h.logs.Queries())
	}
	ms, _ := e.Store().Snapshot(ctx, record.KindLogHygiene)
	if len(ms) != 7 {
		t.Fatalf("snapshot: %d", len(ms))
	}

	h.now = h.now.Add(time.Hour)
	before := len(h.logs.Started)
	r, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if hygieneQueries(h) != 1 || len(h.logs.Started) == before || len(r.Report.Coverage.Formats) != 1 {
		t.Fatalf("daily must run the access-log aggregates only: %v", h.logs.Queries()[before:])
	}
	if ms, _ := e.Store().Snapshot(ctx, record.KindLogHygiene); len(ms) != 7 {
		t.Fatalf("daily must not replace the hygiene snapshot: %d items", len(ms))
	}

	// collect (種類を絞らない収集) も衛生のクエリを流さない
	if _, err := e.CollectOnly(ctx, 24*time.Hour, []string{"web"}); err != nil {
		t.Fatal(err)
	}
	if hygieneQueries(h) != 1 {
		t.Fatalf("collect must not run the hygiene query: %v", h.logs.Queries())
	}
	if ms, _ := e.Store().Snapshot(ctx, record.KindLogHygiene); len(ms) != 7 {
		t.Fatalf("collect must not replace the hygiene snapshot: %d items", len(ms))
	}

	h.now = h.now.Add(7 * 24 * time.Hour)
	r, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	if got := hygieneClasses(r.Report); got["web|presigned_url"] != "still_open" {
		t.Fatalf("second weekly: %v", got)
	}
}

// 設定が空 (既定) なら読み取りは起きず、チェックは理由を付けて skip になる。
func TestLogHygieneDisabledByDefault(t *testing.T) {
	for name, tc := range map[string]struct{ checks, reason string }{
		"no config":       {"", "checks.log_hygiene.sources is empty"},
		"sources only":    {"checks:\n  log_hygiene:\n    sources: [app_prod]\n", "checks.log_hygiene.kinds is empty"},
		"kinds only":      {"checks:\n  log_hygiene:\n    kinds: [debug_sql]\n", "checks.log_hygiene.sources is empty"},
		"no text sources": {"", "checks.log_hygiene.sources is empty"},
	} {
		sources := hygieneSources
		if name == "no text sources" {
			sources = ""
		}
		h := newHarnessWith(t, sources, tc.checks)
		e := h.open(t)
		r, err := e.Run(context.Background(), "weekly")
		if err != nil {
			t.Fatal(err)
		}
		reason := ""
		for _, s := range r.Report.Coverage.ChecksSkipped {
			if s.Check == "log_hygiene" {
				reason = s.Reason
			}
		}
		if !strings.Contains(reason, tc.reason) || len(h.logs.Started) != 0 || contains(r.Report.Coverage.SourcesOK, "app_prod") {
			t.Errorf("%s: reason %q, %d queries, coverage %+v", name, reason, len(h.logs.Started), r.Report.Coverage)
		}
	}
}

func TestDoctorLogHygiene(t *testing.T) {
	h := newHarnessWith(t, hygieneSources+nginxSource+`  - id: staged
    kind: cloudwatch-logs
    log_group: prod-worker
    format: text
`, strings.Replace(hygieneChecks, "[app_prod]", "[app_prod, web]", 1))
	h.logs.LogGroups = []string{"prod-app", "/app/nginx", "prod-worker"}
	h.logs.On("ispresent", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("@message", "x", "arata_matched", "1")}})
	res := Doctor(context.Background(), h.cfg, h.deps, time.Hour)
	rows := map[string]DoctorRow{}
	for _, r := range res.Rows {
		rows[r.Source+"/"+r.Item] = r
	}
	// text のソース: ロググループと、log_hygiene のクエリの構文だけを確かめる (解釈率は無い)
	if r := rows["app_prod/queries"]; r.Status != DoctorOK || !strings.Contains(r.Detail, "1 本のクエリ") || !strings.Contains(r.Detail, "log_hygiene") {
		t.Fatalf("app_prod queries: %+v", r)
	}
	if _, ok := rows["app_prod/match_rate"]; ok || rows["app_prod/log_group"].Status != DoctorOK {
		t.Fatalf("app_prod: %+v", res.Rows)
	}
	if r := rows["app_prod/cost"]; r.Status != DoctorOK || !strings.Contains(r.Detail, "log_hygiene") || !strings.Contains(r.Detail, "weekly") || !strings.Contains(r.Detail, "max_scan_gb 5") {
		t.Fatalf("app_prod cost: %+v", r)
	}
	// 既存の形式のソース: 今までのクエリに log_hygiene が足される。max_scan_gb が無ければ cost は warn
	if r := rows["web/queries"]; r.Status != DoctorOK || !strings.Contains(r.Detail, "6 本のクエリ") || !strings.Contains(r.Detail, "log_hygiene") {
		t.Fatalf("web queries: %+v", r)
	}
	if r := rows["web/cost"]; r.Status != DoctorWarn || !strings.Contains(r.Detail, "max_scan_gb が未設定") {
		t.Fatalf("web cost: %+v", r)
	}
	// log_hygiene.sources に無い text のソースは、どのチェックにも読まれない
	if r := rows["staged/queries"]; r.Status != DoctorWarn || !strings.Contains(r.Detail, "checks.log_hygiene.sources") {
		t.Fatalf("staged: %+v", r)
	}
	if _, ok := rows["staged/cost"]; ok {
		t.Fatalf("staged must have no cost row: %+v", res.Rows)
	}
	// 値を引くクエリ (サンプル・解釈率) を text のソースには流さない
	for _, in := range h.logs.Started {
		if *in.LogGroupName != "/app/nginx" && !strings.Contains(*in.QueryString, hygieneQueryMark) {
			t.Fatalf("unexpected query on %s:\n%s", *in.LogGroupName, *in.QueryString)
		}
	}
	// 権限は増えない
	if got := strings.Join(res.RequiredActions, ","); got != "cloudtrail:LookupEvents,logs:DescribeLogGroups,logs:GetQueryResults,logs:StartQuery,logs:StopQuery" {
		t.Fatalf("required actions: %s", got)
	}

	// Insights がクエリを拒否したら QUERY_INVALID
	h2 := newHarnessWith(t, hygieneSources, hygieneChecks)
	h2.logs.LogGroups = []string{"prod-app"}
	h2.logs.On(hygieneQueryMark, cwlogstest.Response{StartErr: cwlogstest.APIError{Code: "MalformedQueryException", Message: "unexpected symbol"}})
	res = Doctor(context.Background(), h2.cfg, h2.deps, time.Hour)
	found := false
	for _, r := range res.Rows {
		if r.Source == "app_prod" && r.Item == "queries" && r.Status == DoctorNG && r.Code == "QUERY_INVALID" {
			found = true
		}
	}
	if !found || !res.Problems() {
		t.Fatalf("malformed query must be ng: %+v", res.Rows)
	}

	// 設定が空なら、doctor の「skip される」の行に、何を書けば動くかが出る
	h3 := newHarnessWith(t, "", "")
	res = Doctor(context.Background(), h3.cfg, h3.deps, time.Hour)
	found = false
	for _, r := range res.Rows {
		if r.Item == "check" && strings.Contains(r.Detail, "log_hygiene は skip される: checks.log_hygiene.sources is empty") {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor must explain why log_hygiene is skipped: %+v", res.Rows)
	}
}

func sourceFailed(rep *report.Report, id string) bool {
	for _, f := range rep.Coverage.SourcesFailed {
		if f.Source == id {
			return true
		}
	}
	return false
}
