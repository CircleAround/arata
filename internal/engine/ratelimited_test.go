package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/record"
)

// rate_limited_ip (ADR 0094 の 2 節) の run と doctor。値はすべて架空。実 AWS には接続しない (cwlogstest.Fake)。

const rateLimitedSources = `  - { id: alb, kind: cloudwatch-logs, log_group: prod-alb-access, format: alb_access }
` + requestLinesSource + userProbeUserID

const rateLimitedChecks = `checks:
  rate_limited_ip:
    user_sources: [web]
`

// user_sources を書けば http_user も引かせる (U3)。書かなければ引かせない。ユーザー ID が取れない run でも skip しない。
func TestRateLimitedIPNeededKinds(t *testing.T) {
	open := func(h *harness) *Engine {
		e, err := Open(h.cfg, h.deps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e.Close() })
		return e
	}
	h := newHarnessWith(t, rateLimitedSources, "")
	if open(h).neededKinds(h.cfg.Profiles["daily"])["http_user"] {
		t.Fatal("http_user is needed without user_sources")
	}
	h = newHarnessWith(t, rateLimitedSources, rateLimitedChecks)
	if !open(h).neededKinds(h.cfg.Profiles["daily"])["http_user"] {
		t.Fatal("http_user is not needed with user_sources")
	}
	c := checks.RateLimitedIP{Config: h.cfg.Checks.RateLimitedIP}
	if r := skipReason(c, map[record.Kind]bool{record.KindHTTPAccess: true}, nil, map[record.Kind]string{record.KindHTTPUser: "web: no user ids"}); r != "" {
		t.Fatalf("skipped: %s", r)
	}
}

func ipUsersDoctor(t *testing.T, sources string, users, present cwlogstest.Response) DoctorRow {
	t.Helper()
	h := newHarnessWith(t, sources, rateLimitedChecks)
	h.logs.LogGroups = []string{"prod-app", "prod-alb-access"}
	h.logs.On("sort @timestamp desc", doctorSample(95, 5))
	h.logs.On("as lines_total", requestRows("2026-10-21", [5]string{"1000", "1", "4000", "4000", "200"}))
	h.logs.On("as ip_users", users)
	h.logs.On("as arata_ip_hits", present)
	res := Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour)
	for _, r := range res.Rows {
		if r.Item == "ip_users" {
			if r.Source != "web" {
				t.Fatalf("row: %+v", r)
			}
			return r
		}
	}
	t.Fatalf("ip_users の行が無い: %+v", res.Rows)
	return DoctorRow{}
}

// ADR 0094 の「確かめが要る点」の 1: アプリのログの ip が、ALB のログの client の IP と同じ値か。
func TestDoctorIPUsers(t *testing.T) {
	users := cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "203.0.113.50", "ip_users", "40"),
		cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.31", "ip_users", "3"),
	}}
	both := cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("ip", "203.0.113.50", "arata_ip_hits", "900"), cwlogstest.Rows("ip", "198.51.100.31", "arata_ip_hits", "20"),
	}}
	r := ipUsersDoctor(t, rateLimitedSources, users, both)
	if r.Status != DoctorOK || !strings.Contains(r.Detail, "2 個のうち 2 個 (1.00) が alb の IP に現れる") {
		t.Fatalf("row: %+v", r)
	}
	// アプリのログの ip が ALB の内側の IP なら、ALB のログに現れない → warn
	r = ipUsersDoctor(t, rateLimitedSources, users, cwlogstest.Response{})
	if r.Status != DoctorWarn || !strings.Contains(r.Detail, "remote_ip") {
		t.Fatalf("row: %+v", r)
	}
	// 比べる http_access のソースが無い → warn
	r = ipUsersDoctor(t, requestLinesSource+userProbeUserID, users, both)
	if r.Status != DoctorWarn || !strings.Contains(r.Detail, "ほかのソース") {
		t.Fatalf("row: %+v", r)
	}
	// ログインした利用者の IP が無い → warn
	r = ipUsersDoctor(t, rateLimitedSources, cwlogstest.Response{}, both)
	if r.Status != DoctorWarn || !strings.Contains(r.Detail, "利用者の IP が無い") {
		t.Fatalf("row: %+v", r)
	}
}
