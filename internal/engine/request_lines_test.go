package engine

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/store"
)

// request_lines (ADR 0051) のソース。Rails の既定のログの見本 (docs/ai/logs.md と同じ)。
const requestLinesSource = `  - id: web
    kind: cloudwatch-logs
    log_group: prod-app
    format: request_lines
    request:
      id: '(?:^| -- : )\[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] '
      lines:
        - name: started
          regex: 'Started (?P<method>[A-Z]+) "(?P<path>[^"?]*)[^"]*" for (?P<ip>\S+) at '
        - name: completed
          regex: 'Completed (?P<status>\d{3}) '
        - name: no_route
          regex: 'ActionController::RoutingError'
          set: { status: 404 }
`

// requestRows は解釈率のクエリ (2 段の stats) の結果。kv は行ごとの (rl_requests, rl_starts, lines_total, lines_matched, status)。
func requestRows(day string, rows ...[5]string) cwlogstest.Response {
	var out []map[string]string
	for _, r := range rows {
		m := cwlogstest.Rows("day", day+" 00:00:00.000", "rl_requests", r[0], "rl_starts", r[1], "lines_total", r[2], "lines_matched", r[3],
			"rl_kind_0", r[0], "rl_kind_1", r[0], "rl_kind_2", "0")
		if r[4] != "" {
			m["status"] = r[4]
		}
		out = append(out, m)
	}
	// 解釈率のクエリは 1 日ずつ流れる。前の日の分 (終わりが 0 時 + 余白) には何も返さない
	return cwlogstest.Response{BytesScanned: 3e6, RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
		if end := time.Unix(aws.ToInt64(in.EndTime), 0).UTC(); end.Hour() == 0 && end.Minute() < 2 {
			return nil
		}
		return out
	}}
}

func TestRequestLinesRun(t *testing.T) {
	h := newHarnessWith(t, requestLinesSource, "")
	ctx := context.Background()
	// 980 件は揃っている、20 件は最初の行が無い (途中から)、1 つの ID は最初の行が 3 つ。タグの無い行が 50 行 (うち最初の行 2 つ)
	h.logs.On("as lines_total", requestRows("2026-10-21",
		[5]string{"980", "1", "3920", "3920", "200"}, [5]string{"20", "0", "40", "40", ""}, [5]string{"1", "3", "12", "12", "422"}, [5]string{"1", "2", "50", "0", ""}))
	h.logs.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "method", "POST", "status", "422", "sign_in", "/users/sign_in", "http_hits", "30")}})
	e := h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK {
		t.Fatalf("exit %d: %+v", r.Exit, r.Report.Coverage)
	}
	fc := r.Report.Coverage.Formats
	if len(fc) != 1 || fc[0].Format != "request_lines" || fc[0].Requests == nil {
		t.Fatalf("formats: %+v", fc)
	}
	rq := fc[0].Requests
	if rq.Total != 1001 || rq.Complete != 981 || *rq.CompleteRate != 0.98 || rq.Expected != 0.8 || rq.WithStatus != 981 || rq.Starts != 983 || rq.Reused != 1 || rq.StartsUntagged != 2 {
		t.Fatalf("requests: %+v", rq)
	}
	if fc[0].Total != 4022 || fc[0].Matched != 3972 {
		t.Fatalf("lines: %+v", fc[0])
	}
	// 既存のチェックの集計はそのまま (http_access の metric)。リクエスト単位の集計も日次で残る
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: "sign_in_failures"})
	if len(ms) != 1 || ms[0].Key != "198.51.100.7" || ms[0].Value != 30 || ms[0].From != "http_access" {
		t.Fatalf("metrics: %+v", ms)
	}
	for name, want := range map[string]float64{"requests_total": 1001, "requests_complete": 981, "request_id_reused": 1} {
		ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: name})
		if len(ms) != 1 || ms[0].Value != want {
			t.Fatalf("%s: %+v", name, ms)
		}
	}
	last, _ := e.Store().RecentRuns(ctx, 1)
	rs, _ := last[0].Stats["request_stats"].(map[string]any)
	web, _ := rs["web"].(map[string]any)
	if web["total"] != 1001.0 || web["complete_rate"] != 0.98 || web["request_id_reused"] != 1.0 || web["starts_untagged"] != 2.0 {
		t.Fatalf("runs.stats: %+v", last[0].Stats)
	}
	md := string(r.Report.Markdown())
	if !strings.Contains(md, "リクエスト単位: まとめられた割合 0.98 (981/1001)、閾値 0.80、ステータスあり 981、request_id の使い回し 1、タグの無い最初の行 2") {
		t.Fatalf("report.md:\n%s", md)
	}
	// 1 行 = 1 リクエストの形式には出さない
	j, _ := r.Report.JSON()
	if !strings.Contains(string(j), `"requests": {`) {
		t.Fatalf("report.json に requests が無い:\n%s", j)
	}
}

// 鍵の取り違え (request_id の異なりの数が最初の行の数より極端に少ない) は FORMAT_MISMATCH。集計は保存しない。
func TestRequestLinesMismatch(t *testing.T) {
	h := newHarnessWith(t, requestLinesSource, "")
	h.logs.On("as lines_total", requestRows("2026-10-21", [5]string{"1", "500", "2000", "2000", "200"}, [5]string{"1", "480", "1900", "1900", "200"}))
	e := h.open(t)
	r, err := e.Run(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitPartial {
		t.Fatalf("exit %d", r.Exit)
	}
	if sf := r.Report.Coverage.SourcesFailed; len(sf) != 1 || sf[0].Source != "web" || sf[0].Code != "FORMAT_MISMATCH" {
		t.Fatalf("sources_failed: %+v", sf)
	}
	fc := r.Report.Coverage.Formats
	if len(fc) != 1 || fc[0].Code != "FORMAT_MISMATCH" || fc[0].Requests == nil || fc[0].Requests.Total != 2 || fc[0].Requests.Starts != 980 {
		t.Fatalf("formats: %+v", fc)
	}
	line := h.logLine(t, "FORMAT_MISMATCH")
	if line["reason"] != "request_id" || line["requests_total"] != 2.0 || line["request_starts"] != 980.0 || line["source"] != "web" {
		t.Fatalf("log line: %v", line)
	}
	for _, name := range []string{"lines_total", "requests_total"} {
		if ms, _ := e.Store().Metrics(context.Background(), store.MetricFilter{Metric: name}); len(ms) != 0 {
			t.Fatalf("FORMAT_MISMATCH なのに %s を保存した: %+v", name, ms)
		}
	}
	if !strings.Contains(string(r.Report.Markdown()), "`FORMAT_MISMATCH`") {
		t.Fatalf("report.md:\n%s", r.Report.Markdown())
	}
}

func requestDoctor(t *testing.T, resp cwlogstest.Response) (*DoctorResult, *harness) {
	t.Helper()
	h := newHarnessWith(t, requestLinesSource, "")
	h.logs.LogGroups = []string{"prod-app"}
	h.logs.On("sort @timestamp desc", doctorSample(95, 5))
	h.logs.On("as lines_total", resp)
	return Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour), h
}

// doctor は request_lines のソースに、まとめの結果 (2 つ目の解釈率・取り違えの検査・使い回し・行の種類ごとの数) を出す。
func TestDoctorRequestLines(t *testing.T) {
	res, h := requestDoctor(t, requestRows("2026-10-21", [5]string{"980", "1", "3920", "3920", "200"}, [5]string{"20", "0", "40", "40", ""}))
	var row *DoctorRow
	for i, r := range res.Rows {
		if r.Source == "web" && r.Item == "requests" {
			row = &res.Rows[i]
		}
		if r.Source == "web" && r.Status == DoctorNG {
			t.Fatalf("ng: %+v", r)
		}
	}
	if row == nil {
		t.Fatalf("requests の行が無い: %+v", res.Rows)
	}
	for _, want := range []string{"まとめられた割合 0.98 (980/1000 リクエスト、閾値 0.80)", "最初の行 980", "ステータスあり 980", "request_id の使い回し 0",
		"行の種類: started=1000, completed=1000, no_route=0", "取れている項目: ip, method, path, status", "スキャン"} {
		if !strings.Contains(row.Detail, want) {
			t.Errorf("detail に %q が無い: %s", want, row.Detail)
		}
	}
	// 当たらない行の種類があるので warn (設定を直す手がかり)
	if row.Status != DoctorWarn || !strings.Contains(row.Detail, "当たらない行の種類: no_route") {
		t.Fatalf("row: %+v", row)
	}
	// 集計のクエリ (2 段の stats) も構文検査に入る
	var out bytes.Buffer
	_ = res.WriteTable(&out)
	if !strings.Contains(out.String(), "http_hits") || !strings.Contains(out.String(), "http_lines") {
		t.Fatalf("queries:\n%s", out.String())
	}
	n := 0
	for _, q := range h.logs.Queries() {
		if strings.Contains(q, "by rl_request_id") {
			n++
		}
	}
	if n < 3 {
		t.Fatalf("2 段のクエリを流していない: %d", n)
	}

	// 鍵の取り違え → ng (FORMAT_MISMATCH)
	res, _ = requestDoctor(t, requestRows("2026-10-21", [5]string{"3", "400", "4800", "4800", "200"}))
	row = nil
	for i, r := range res.Rows {
		if r.Source == "web" && r.Item == "requests" {
			row = &res.Rows[i]
		}
	}
	if row == nil || row.Status != DoctorNG || row.Code != "FORMAT_MISMATCH" || !strings.Contains(row.Detail, "request_id の異なりの数 3 が最初の行の数 1200 の半分未満") ||
		row.Hint != "arata help ai logs (「"+LogsGuidePitfalls+"」)" {
		t.Fatalf("取り違え: %+v", row)
	}
	// まとめられた割合が閾値未満 → ng
	res, _ = requestDoctor(t, requestRows("2026-10-21", [5]string{"100", "1", "400", "400", "200"}, [5]string{"300", "0", "300", "300", "200"}))
	for _, r := range res.Rows {
		if r.Source == "web" && r.Item == "requests" && (r.Status != DoctorNG || r.Code != "FORMAT_MISMATCH" || !strings.Contains(r.Detail, "まとめられた割合 0.25")) {
			t.Fatalf("complete rate: %+v", r)
		}
	}
	// リクエストが無い → warn
	res, _ = requestDoctor(t, cwlogstest.Response{})
	found := false
	for _, r := range res.Rows {
		if r.Source == "web" && r.Item == "requests" {
			found = r.Status == DoctorWarn
		}
	}
	if !found {
		t.Fatalf("リクエストが無いときの行: %+v", res.Rows)
	}
}
