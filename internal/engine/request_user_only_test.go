package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

// yields: http_user のソースと、プロファイルの records (ADR 0075)。入口のアクセスログを別のソースで読む構成で、アプリのログからは
// ユーザー ID と auth の行だけを読む。http_access のチェックはこのソースを引かず、records に http_user を書いたプロファイルだけが引く。

func userOnlySourceYAML() string {
	return strings.Replace(requestUserSource("app_line"), "    format: request_lines\n", "    format: request_lines\n    yields: http_user\n", 1)
}

// records を書いたプロファイル (daily と同じチェックに records を足したもの)。
const userRecordsProfile = `  daily_user:
    window: 24h
    checks: [default-daily]
    records: [http_user]
`

func formatOf(t *testing.T, fs []report.FormatCoverage, src string) report.FormatCoverage {
	t.Helper()
	for _, f := range fs {
		if f.Source == src {
			return f
		}
	}
	t.Fatalf("coverage.formats に %s が無い: %+v", src, fs)
	return report.FormatCoverage{}
}

func TestRequestUserOnlyRun(t *testing.T) {
	h := newHarnessWith(t, userOnlySourceYAML(), userRecordsProfile)
	ctx := context.Background()
	h.logs.On("as lines_total", userRows(userRunRows...))
	e := h.open(t)

	src := h.cfg.Sources[len(h.cfg.Sources)-1]
	if got := kindsOf(h.cfg, src); len(got) != 1 || got[0] != record.KindHTTPUser {
		t.Fatalf("kindsOf: %v", got)
	}

	// records の無い daily は、このソースを引かない (http_access のチェックは http_user だけのソースを引かない)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK || len(r.Report.Coverage.Formats) != 0 || len(h.logs.Queries()) != 0 {
		t.Fatalf("records の無い run が引いた: exit %d formats %+v queries %d", r.Exit, r.Report.Coverage.Formats, len(h.logs.Queries()))
	}
	skipped := map[string]string{}
	for _, s := range r.Report.Coverage.ChecksSkipped {
		skipped[s.Check] = s.Reason
	}
	for _, c := range []string{"login_bruteforce", "probe_paths"} {
		if skipped[c] != "no http_access source" {
			t.Fatalf("%s: skip の理由 %q (http_user だけのソースは http_access を出さない)", c, skipped[c])
		}
	}

	// records: [http_user] のプロファイルは、要るチェックが無くても引き、日次の集計と coverage を残す
	r, err = e.Run(ctx, "daily_user")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK {
		t.Fatalf("exit %d: %+v", r.Exit, r.Report.Coverage)
	}
	fc := formatOf(t, r.Report.Coverage.Formats, "web")
	if strings.Join(fc.Yields, ",") != "http_user" || fc.Requests == nil || fc.Requests.Users == nil || fc.Requests.Users.WithUser != 489 || fc.Requests.Auth.Failure != 6 {
		t.Fatalf("coverage: %+v %+v", fc, fc.Requests)
	}
	for _, q := range h.logs.Queries() {
		if strings.Contains(q, "as http_hits") {
			t.Fatalf("http_access の集計のクエリを流した:\n%s", q)
		}
	}
	ms, _ := e.Store().Metrics(ctx, store.MetricFilter{})
	got := map[string]bool{}
	for _, m := range ms {
		if m.Source != "web" {
			continue
		}
		if m.From != record.KindHTTPUser {
			t.Fatalf("%s の From が %s", m.Metric, m.From)
		}
		got[m.Metric] = true
	}
	for _, want := range []string{"user_requests", "auth_failures", "requests_total"} {
		if !got[want] {
			t.Errorf("%s が無い: %v", want, got)
		}
	}
	j, _ := r.Report.JSON()
	if !strings.Contains(string(j), `"yields": [`) {
		t.Fatalf("report.json に yields が無い:\n%s", j)
	}
	if md := string(r.Report.Markdown()); !strings.Contains(md, "記録: http_user") {
		t.Fatalf("report.md に引いた記録の種類が無い:\n%s", md)
	}
}

// ID の付いたリクエストが 0 件の日も、毎日の run は落ちない (ソースは成功、終了コード 0)。http_user は coverage の yields から外れ、WARN を出す。
func TestRequestUserOnlyNoneDoesNotFail(t *testing.T) {
	h := newHarnessWith(t, userOnlySourceYAML(), userRecordsProfile)
	h.logs.On("as lines_total", userRows(userRow("1000")))
	e := h.open(t)
	r, err := e.Run(context.Background(), "daily_user")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK || len(r.Report.Coverage.SourcesFailed) != 0 {
		t.Fatalf("0 件の日に run が落ちた: exit %d %+v", r.Exit, r.Report.Coverage)
	}
	fc := formatOf(t, r.Report.Coverage.Formats, "web")
	if len(fc.Yields) != 0 || fc.Requests.Users == nil || fc.Requests.Users.WithUser != 0 {
		t.Fatalf("coverage: yields %v users %+v", fc.Yields, fc.Requests.Users)
	}
	if !strings.Contains(h.stderr.String(), "no requests with a user id") {
		t.Fatalf("WARN が無い:\n%s", h.stderr.String())
	}
}

func doctorRowOf(t *testing.T, rows []DoctorRow, src, item string) (DoctorRow, bool) {
	t.Helper()
	for _, r := range rows {
		if r.Source == src && r.Item == item {
			return r, true
		}
	}
	return DoctorRow{}, false
}

// doctor は、http_user だけを出すソースをどのプロファイルが引くかを出す。どれも引かなければ warn (書いても何も集まらない)。
func TestDoctorRequestUserOnlyRecords(t *testing.T) {
	for _, c := range []struct {
		name, profiles, status, want string
	}{
		{"records あり", userRecordsProfile, DoctorOK, "daily_user (records: http_user)"},
		{"どのプロファイルも引かない", "", DoctorWarn, "records: [http_user]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarnessWith(t, userOnlySourceYAML(), c.profiles)
			h.logs.LogGroups = []string{"prod-app"}
			h.logs.On("sort @timestamp desc", doctorSample(95, 5))
			h.logs.On("as lines_total", userRows(userRunRows...))
			res := Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour)
			row, ok := doctorRowOf(t, res.Rows, "web", "records")
			if !ok || row.Status != c.status || !strings.Contains(row.Detail, c.want) {
				t.Fatalf("records の行: %+v (%v)", row, ok)
			}
			// ユーザー ID の数は今までどおり requests の行に出る
			if r, ok := doctorRowOf(t, res.Rows, "web", "requests"); !ok || !strings.Contains(r.Detail, "付いたリクエスト 489/") {
				t.Fatalf("requests の行: %+v", r)
			}
		})
	}
	// 既定 (http_access も出す) のソースには records の行を出さない (daily の http_access のチェックが引く)
	h := newHarnessWith(t, requestUserSource("app_line"), "")
	h.logs.LogGroups = []string{"prod-app"}
	h.logs.On("sort @timestamp desc", doctorSample(95, 5))
	h.logs.On("as lines_total", userRows(userRunRows...))
	if r, ok := doctorRowOf(t, Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour).Rows, "web", "records"); ok {
		t.Fatalf("既定のソースに records の行: %+v", r)
	}
}
