package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ユーザー ID と auth の行 (ADR 0052) を読む設定。アプリが足す行の見本 (docs/ai/request_lines.md と同じ)。
func requestUserSource(from string) string {
	return requestLinesSource + `      user_id:
        from: ` + from + `
        regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})(?: by=(?P<by_kind>[a-z_]{1,32}):(?P<by_id>[A-Za-z0-9_-]{1,64}))?$'
      auth:
        regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] auth result=(?P<auth_result>success|failure|impersonate) kind=(?P<auth_kind>[a-z_]{1,32}) id=(?P<auth_id>[A-Za-z0-9_-]{1,64})(?: via=(?P<auth_via>password|remember))?(?: reason=(?P<auth_reason>[a-z_]{1,64}))?$'
`
}

// userRow は解釈率のクエリの結果の 1 行 (n 件のリクエスト。1 件 4 行)。kv はユーザー ID と auth の列。
func userRow(n string, kv ...string) map[string]string {
	lines := n + "0"
	m := cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "rl_requests", n, "rl_starts", "1", "lines_total", lines, "lines_matched", lines, "status", "200",
		"rl_kind_0", n, "rl_kind_1", n, "rl_kind_2", "0", "rl_users", "0", "rl_user_lines", "0", "rl_bys", "0", "rl_auth_lines", "0", "rl_kind_user", "0", "rl_kind_auth", "0")
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func userRows(rows ...map[string]string) cwlogstest.Response {
	return cwlogstest.Response{BytesScanned: 3e6, Rows: rows}
}

// userCheck はユーザー ID の要るチェックの代わり (段 1 のチェックは次の PR)。skip の判定だけに使う。
type userCheck struct{}

func (userCheck) Name() string            { return "needs_http_user" }
func (userCheck) Cadence() checks.Cadence { return checks.Daily }
func (userCheck) Mode() checks.Mode       { return checks.ModeEvent }
func (userCheck) Needs() []record.Kind    { return []record.Kind{record.KindHTTPUser} }
func (userCheck) Evaluate(context.Context, store.Query, collect.Window, *allowlist.List) ([]checks.Observation, error) {
	return nil, nil
}

var userRunRows = []map[string]string{
	userRow("500"), // ログイン前
	userRow("400", "user_kind", "user", "rl_users", "1", "rl_user_lines", "1", "rl_kind_user", "400"),
	userRow("60", "user_kind", "staff", "rl_users", "1", "rl_user_lines", "1", "rl_kind_user", "60"),
	userRow("20", "user_kind", "user", "rl_users", "1", "rl_user_lines", "1", "rl_bys", "1", "rl_kind_user", "20"),
	userRow("5", "rl_user_lines", "1", "rl_kind_user", "5"), // 値が形に合わず、クエリの中で捨てた
	userRow("9", "auth_result", "success", "auth_via", "password", "rl_auth_lines", "1", "rl_kind_auth", "9", "user_kind", "user", "rl_users", "1", "rl_user_lines", "1"),
	userRow("4", "auth_result", "failure", "auth_reason", "invalid", "rl_auth_lines", "1", "rl_kind_auth", "4"),
	userRow("2", "auth_result", "failure", "auth_reason", "not_found_in_database", "rl_auth_lines", "1", "rl_kind_auth", "2"),
}

func TestRequestUserRun(t *testing.T) {
	h := newHarnessWith(t, requestUserSource("app_line"), "")
	ctx := context.Background()
	h.logs.On("as lines_total", userRows(userRunRows...))
	e := h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK {
		t.Fatalf("exit %d: %+v", r.Exit, r.Report.Coverage)
	}
	rq := r.Report.Coverage.Formats[0].Requests
	if rq == nil || rq.Starts != 1000 || rq.Users == nil || rq.Auth == nil {
		t.Fatalf("requests: %+v", rq)
	}
	u, a := rq.Users, rq.Auth
	if u.From != "app_line" || u.WithUser != 489 || u.UserRate == nil || *u.UserRate != 0.489 || u.WithBy != 20 || u.Invalid != 5 || u.Kinds["user"] != 429 || u.Kinds["staff"] != 60 {
		t.Fatalf("users: %+v", u)
	}
	if a.Success != 9 || a.Via["password"] != 9 || a.Failure != 6 || a.Reasons["invalid"] != 4 || a.Reasons["not_found_in_database"] != 2 || a.Impersonate != 0 || a.Invalid != 0 {
		t.Fatalf("auth: %+v", a)
	}
	// 日次の metric (From は http_user)。段 0 の metric は今のまま
	for name, want := range map[string]float64{"user_requests_by": 20, "user_id_invalid": 5, "auth_impersonate": 0, "requests_total": 1000} {
		ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: name})
		if len(ms) != 1 || ms[0].Value != want || (name != "requests_total") != (ms[0].From == "http_user") {
			t.Fatalf("%s: %+v", name, ms)
		}
	}
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{Metric: "user_requests"})
	if len(ms) != 2 || ms[0].Key+ms[1].Key != "staffuser" || ms[0].Value != 60 || ms[1].Value != 429 {
		t.Fatalf("user_requests: %+v", ms)
	}
	ms, _ = e.Store().Metrics(ctx, store.MetricFilter{Metric: "auth_failures"})
	if len(ms) != 2 || ms[0].Key != "invalid" || ms[0].Value != 4 {
		t.Fatalf("auth_failures: %+v", ms)
	}
	// run の stats に割合を残す (後から「直近の平均から落ちた」を判定できる)
	last, _ := e.Store().RecentRuns(ctx, 1)
	web, _ := last[0].Stats["request_stats"].(map[string]any)["web"].(map[string]any)
	if web["with_user"] != 489.0 || web["user_rate"] != 0.489 || web["user_id_from"] != "app_line" {
		t.Fatalf("runs.stats: %+v", web)
	}
	md := string(r.Report.Markdown())
	for _, want := range []string{
		"ユーザー ID (app_line): 付いたリクエスト 489/1000 (割合 0.49)、種類 staff=60 user=429、代わりのログインの操作 20、形に合わず捨てた 5",
		"ログインの結果 (auth): 成功 9 (password=9)、失敗 6 (invalid=4 not_found_in_database=2)、代わりのログインの開始 0、形に合わず捨てた 0",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report.md に %q が無い:\n%s", want, md)
		}
	}
	j, _ := r.Report.JSON()
	for _, want := range []string{`"users": {`, `"user_rate": 0.489`, `"user_id_invalid": 5`, `"auth": {`} {
		if !strings.Contains(string(j), want) {
			t.Errorf("report.json に %q が無い", want)
		}
	}

	// ユーザー ID の要るチェックは、ID が取れているので skip しない
	cr := e.Collect(ctx, collect.Window{From: h.now.Add(-24 * time.Hour), To: h.now}, CollectOptions{})
	available, failed := e.availableKinds(&cr)
	if reason := skipReason(userCheck{}, available, failed, unavailableOf(&cr)); reason != "" || !available[record.KindHTTPUser] {
		t.Fatalf("skip された: %q (%v)", reason, available)
	}
	// プロファイルのチェックが http_user だけを必要としていても、このソースを引く
	cr = e.Collect(ctx, collect.Window{From: h.now.Add(-24 * time.Hour), To: h.now}, CollectOptions{Needs: map[record.Kind]bool{record.KindHTTPUser: true}})
	if len(cr.SourcesOK) != 1 || cr.SourcesOK[0] != "web" || len(cr.Formats) != 1 || cr.Formats[0].Requests.Users.WithUser != 489 {
		t.Fatalf("http_user だけを必要とする収集: %+v", cr)
	}
}

// 設定に書いていても、その run で ID の付いたリクエストが 0 件なら、http_user を出さなかったものとして扱い、
// ユーザー ID の要るチェックを skip して理由を出す。段 0 は同じに動く (ADR 0051 の 2 節・4 節)。
func TestRequestUserNoneSkips(t *testing.T) {
	h := newHarnessWith(t, requestUserSource("debug_sql"), "")
	ctx := context.Background()
	h.logs.On("as lines_total", userRows(userRow("1000")))
	e := h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK || len(r.Report.Coverage.SourcesFailed) != 0 {
		t.Fatalf("0 件でもソースは失敗にしない: exit %d %+v", r.Exit, r.Report.Coverage)
	}
	u := r.Report.Coverage.Formats[0].Requests.Users
	if u == nil || u.From != "debug_sql" || u.WithUser != 0 || u.UserRate == nil || *u.UserRate != 0 {
		t.Fatalf("users: %+v", u)
	}
	if !strings.Contains(string(r.Report.Markdown()), "ユーザー ID (debug_sql): 付いたリクエスト 0/1000 (割合 0.00)") {
		t.Fatalf("report.md:\n%s", r.Report.Markdown())
	}
	if !strings.Contains(h.stderr.String(), "no requests with a user id") {
		t.Fatalf("WARN が無い:\n%s", h.stderr.String())
	}
	cr := e.Collect(ctx, collect.Window{From: h.now.Add(-24 * time.Hour), To: h.now}, CollectOptions{})
	available, failed := e.availableKinds(&cr)
	reason := skipReason(userCheck{}, available, failed, unavailableOf(&cr))
	if !strings.Contains(reason, "web: ユーザー ID の付いたリクエストがこの run に 0 件 (request.user_id.from: debug_sql)") {
		t.Fatalf("skip の理由: %q", reason)
	}
	// 段 0 のチェックは skip しない
	for _, s := range r.Report.Coverage.ChecksSkipped {
		if s.Check == "login_bruteforce" || s.Check == "probe_paths" {
			t.Fatalf("段 0 のチェックを skip した: %+v", s)
		}
	}

	// ユーザー ID を取り出す設定の無いソースしか無ければ「no http_user source」(設定不足)
	h2 := newHarnessWith(t, requestLinesSource, "")
	h2.logs.On("as lines_total", userRows(userRow("1000")))
	e2 := h2.open(t)
	cr = e2.Collect(ctx, collect.Window{From: h2.now.Add(-24 * time.Hour), To: h2.now}, CollectOptions{})
	available, failed = e2.availableKinds(&cr)
	if reason := skipReason(userCheck{}, available, failed, unavailableOf(&cr)); reason != "no http_user source" {
		t.Fatalf("設定の無いとき: %q", reason)
	}
	if rq := cr.Formats[0].Requests; rq.Users != nil || rq.Auth != nil {
		t.Fatalf("設定が無いのに users / auth を出した: %+v", rq)
	}
}

func userDoctorRow(t *testing.T, from string, rows ...map[string]string) DoctorRow {
	t.Helper()
	h := newHarnessWith(t, requestUserSource(from), "")
	h.logs.LogGroups = []string{"prod-app"}
	h.logs.On("sort @timestamp desc", doctorSample(95, 5))
	h.logs.On("as lines_total", userRows(rows...))
	res := Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour)
	for _, r := range res.Rows {
		if r.Source == "web" && r.Item == "requests" {
			return r
		}
	}
	t.Fatalf("requests の行が無い: %+v", res.Rows)
	return DoctorRow{}
}

// doctor は ID の付いたリクエストの割合・種類・捨てた数・auth の数を出し、debug_sql の間と 0 件のときは warn にする。
func TestDoctorRequestUser(t *testing.T) {
	rows := append([]map[string]string{}, userRunRows...)
	rows = append(rows, userRow("1", "rl_kind_2", "1")) // no_route の行も当たっている (ほかの warn を出さない)
	row := userDoctorRow(t, "app_line", rows...)
	for _, want := range []string{
		"行の種類: started=1001, completed=1001, no_route=1, user_id=485, auth=15",
		"ユーザー ID (app_line): 付いたリクエスト 489/1001 (割合 0.49)、種類 staff=60 user=429、代わりのログインの操作 20、形に合わず捨てた 5",
		"ログインの結果 (auth): 成功 9 (password=9)、失敗 6 (invalid=4 not_found_in_database=2)",
	} {
		if !strings.Contains(row.Detail, want) {
			t.Errorf("detail に %q が無い: %s", want, row.Detail)
		}
	}
	// 形に合わず捨てた値があるので warn (ID の形・設定の正規表現を見直す手がかり)
	if row.Status != DoctorWarn || !strings.Contains(row.Detail, "形に合わない値を捨てた") || strings.Contains(row.Detail, "debug_sql") {
		t.Fatalf("row: %+v", row)
	}

	// debug_sql を使っている間は、取れていても warn を出し続ける
	row = userDoctorRow(t, "debug_sql", userRow("400", "user_kind", "users", "rl_users", "1", "rl_user_lines", "1", "rl_kind_user", "400", "rl_kind_2", "1", "rl_kind_auth", "1"))
	if row.Status != DoctorWarn || !strings.Contains(row.Detail, "from: debug_sql は消えうる取り方") || !strings.Contains(row.Detail, "app_line") {
		t.Fatalf("debug_sql: %+v", row)
	}
	// 0 件: warn。ユーザー ID の要るチェックが skip されることを書く
	row = userDoctorRow(t, "app_line", userRow("400", "rl_kind_2", "1", "rl_kind_auth", "1"))
	if row.Status != DoctorWarn || !strings.Contains(row.Detail, "ユーザー ID の付いたリクエストが 0 件") || !strings.Contains(row.Detail, "skip") ||
		!strings.Contains(row.Detail, "当たらない行の種類: user_id") {
		t.Fatalf("0 件: %+v", row)
	}
}

// ユーザー ID を取り出す設定のあるソースは、設定の上でも http_user を出すソースとして扱う (doctor の「no http_user source」の判定)。
func TestKindsOfHTTPUser(t *testing.T) {
	h := newHarnessWith(t, requestUserSource("app_line"), "")
	src := h.cfg.Sources[len(h.cfg.Sources)-1]
	if got := kindsOf(h.cfg, src); len(got) != 2 || got[0] != record.KindHTTPAccess || got[1] != record.KindHTTPUser {
		t.Fatalf("kindsOf: %v", got)
	}
	h = newHarnessWith(t, requestLinesSource, "")
	if got := kindsOf(h.cfg, h.cfg.Sources[len(h.cfg.Sources)-1]); len(got) != 1 {
		t.Fatalf("kindsOf (設定なし): %v", got)
	}
}
