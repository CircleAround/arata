package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

func sampleInput() Input {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	from := now.Add(-24 * time.Hour)
	f := func(id, check, key, sev, status string, first time.Time, reported time.Time, data map[string]any) store.Finding {
		return store.Finding{ID: id, Check: check, Key: key, Severity: sev, Summary: "summary of " + key, Status: status, FirstSeen: first, LastSeen: now, LastChanged: first, ReportedAt: reported, Data: data}
	}
	return Input{
		Profile: "daily", Name: "acme", RunID: "run-1", Window: collect.Window{From: from, To: now}, Now: now,
		Results: []checks.Result{
			{Class: checks.ClassNew, Finding: f("f-001", "new_principal", "arn:aws:iam::1:user/x", "medium", "open", now, time.Time{}, map[string]any{"count": 3, "ips": []string{"203.0.113.1"}})},
			{Class: checks.ClassNew, Finding: f("f-002", "root_usage", "arn:aws:iam::1:root|203.0.113.1", "critical", "open", now, time.Time{}, map[string]any{"count": 1})},
			{Class: checks.ClassChanged, Finding: f("f-003", "unknown_assume_role", "a->b", "high", "open", from.Add(-time.Hour), from.Add(-time.Hour), map[string]any{"count": 2})},
			{Class: checks.ClassResolved, Finding: f("f-004", "iam_changes", "CreateUser|p|t", "medium", "resolved", from.Add(-48*time.Hour), from.Add(-48*time.Hour), nil)},
			{Class: checks.ClassStillOpen, Finding: f("f-005", "new_principal", "arn:aws:iam::1:user/old", "medium", "open", from.Add(-72*time.Hour), from.Add(-72*time.Hour), map[string]any{"count": 1})},
			{Class: checks.ClassStillOpen, Finding: f("f-006", "root_usage", "arn:aws:iam::1:root|198.51.100.1", "critical", "open", now.Add(-2*time.Hour), now.Add(-time.Hour), map[string]any{"count": 1})},
			{Class: checks.ClassNew, Finding: f("f-007", "iam_changes", "PutRolePolicy|deploy|r", "info", "open", now, time.Time{}, map[string]any{"known_deploy_principal": true})},
			{Class: checks.ClassRecurred, Finding: f("f-009", "root_usage", "arn:aws:iam::1:root|192.0.2.1", "critical", "open", from.Add(-10*24*time.Hour), from.Add(-10*24*time.Hour), map[string]any{"count": 2})},
			{Class: checks.ClassNew, Finding: f("f-010", "login_bruteforce", "198.51.100.7", "medium", "open", now, time.Time{}, map[string]any{"count": 52.0, "date": "2026-10-20", "reason": "above_baseline"})},
			{Class: checks.ClassSuppressed, Finding: f("f-008", "new_principal", "arn:aws:iam::1:user/acked", "medium", "acked", from, from, nil)},
		},
		CollectErrors: []CollectError{{Source: "trail-us", Code: "QUERY_LIMIT", Message: "cloudtrail:LookupEvents: throttled", CoveredFrom: "2026-10-20T20:00:00Z", CoveredUntil: "2026-10-21T09:00:00Z"}},
		SourcesOK:     []string{"trail"},
		ChecksRun:     []string{"iam_changes", "new_principal", "root_usage", "unknown_assume_role"},
		ChecksSkipped: []SkippedCheck{{Check: "login_bruteforce", Reason: "no http_access source"}},
		Formats: []FormatCoverage{
			{Source: "nginx", Format: "nginx_access", LogGroup: "/app/nginx", Total: 1000, Matched: 990, MatchRate: ptr(0.99), Expected: 0.8, RecentAverage: ptr(0.98), BytesScanned: 1.5e9},
			{Source: "app", Format: "json", LogGroup: "/app/rails", Total: 1000, Matched: 500, MatchRate: ptr(0.5), Expected: 0.4, RecentAverage: ptr(0.9), Code: "FORMAT_DRIFT"},
			{Source: "waf", Format: "wafv2", LogGroup: "aws-waf-logs-prod", Expected: 0.8},
		},
	}
}

func ptr(f float64) *float64 { return &f }

func TestBuild(t *testing.T) {
	r := Build(sampleInput())
	if r.Summary.New != 3 || r.Summary.Changed != 1 || r.Summary.Recurred != 1 || r.Summary.Resolved != 1 || r.Summary.StillOpen != 1 || r.Summary.MaxSeverity != "critical" {
		t.Fatalf("summary: %+v", r.Summary)
	}
	if len(r.Info) != 1 || r.Info[0].ID != "f-007" {
		t.Fatalf("info: %+v", r.Info)
	}
	if len(r.AlreadyReported) != 1 || r.AlreadyReported[0].ID != "f-006" {
		t.Fatalf("already_reported: %+v", r.AlreadyReported)
	}
	if r.Findings.New[0].ID != "f-002" {
		t.Fatalf("new should be sorted by severity desc: %+v", r.Findings.New)
	}
	if len(r.Findings.Recurred) != 1 || r.Findings.Recurred[0].ID != "f-009" {
		t.Fatalf("recurred: %+v", r.Findings.Recurred)
	}
	for _, l := range [][]Finding{r.Findings.New, r.Findings.Changed, r.Findings.Recurred, r.Findings.Resolved, r.Findings.StillOpen, r.AlreadyReported, r.Info} {
		for _, f := range l {
			if f.ID == "f-008" {
				t.Fatal("suppressed finding must not appear")
			}
		}
	}
	if sf := r.Coverage.SourcesFailed; len(sf) != 1 || sf[0].Source != "trail-us" || sf[0].Code != "QUERY_LIMIT" || sf[0].CoveredFrom != "2026-10-20T20:00:00Z" {
		t.Fatalf("sources_failed: %+v", sf)
	}
	empty := Build(Input{Profile: "daily", Now: time.Now()})
	b, _ := empty.JSON()
	// 空の報告も、配列を null にせず、スキーマに合う (ADR 0054)
	schematest.Conforms(t, schema.ReportSchema, b, &schema.Report{})
	for _, want := range []string{`"collect_errors": []`, `"sources_ok": []`, `"checks_skipped": []`, `"formats": []`, `"new": []`, `"recurred": []`, `"max_severity": ""`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("empty report must still have %s:\n%s", want, b)
		}
	}
}

func TestGolden(t *testing.T) {
	r := Build(sampleInput())
	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "report.json", j)
	schematest.Conforms(t, schema.ReportSchema, j, &schema.Report{})
	compareGolden(t, "report.md", []byte(r.Markdown()))
}

// TestGoldenLogHygiene は log_hygiene の finding の report.md を固定する。入れ子の data (fields: 項目名 → 行数) は
// Go の map の書式 (`map[address:137 …]`) ではなく、「名前 数」を名前順に並べて書く。
// 決定: 共有のゴールデン (report.json。aratam のテストも読む) には足さず、別のファイルにする (通知側のゴールデンと件数の期待値を巻き込まない)。
func TestGoldenLogHygiene(t *testing.T) {
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	finding := func(id, key, sev, summary string, data map[string]any) checks.Result {
		return checks.Result{Class: checks.ClassNew, Finding: store.Finding{ID: id, Check: "log_hygiene", Key: key, Severity: sev, Summary: summary, Status: "open",
			FirstSeen: now, LastSeen: now, LastChanged: now, Data: data}}
	}
	r := Build(Input{Profile: "weekly", Name: "acme", RunID: "run-1", Window: collect.Window{From: now.Add(-7 * 24 * time.Hour), To: now}, Now: now,
		SourcesOK: []string{"app_prod"}, ChecksRun: []string{"log_hygiene"},
		Results: []checks.Result{
			// ストアから戻した形 (数は float64、fields は map[string]any)
			finding("f-001", "app_prod|unfiltered_param", "medium", "ロググループ prod-app のログに、隠されていない送信項目 (address, name, zipcode) が 446 行 (直近 7 日。保持期間は無期限)",
				map[string]any{"kind": "unfiltered_param", "count": 446.0, "log_group": "prod-app", "retention": "never", "window_hours": 168.0,
					"fields": map[string]any{"zipcode": 134.0, "address": 137.0, "name": 175.0}}),
			// チェックが出したままの形 (数は int64)
			finding("f-002", "app_prod|debug_sql", "low", "ロググループ prod-app のログに、debug の SQL の出力が 403,003 行 (直近 7 日。保持期間は 30 日)",
				map[string]any{"kind": "debug_sql", "count": int64(403003), "log_group": "prod-app", "retention": "set", "retention_days": 30, "window_hours": int64(168)}),
			finding("f-003", "web|unfiltered_param", "medium", "summary", map[string]any{"kind": "unfiltered_param", "count": int64(1), "fields": map[string]any{"tel": int64(1)}}),
		}})
	md := r.Markdown()
	if strings.Contains(md, "map[") {
		t.Fatalf("report.md must not print a Go map:\n%s", md)
	}
	compareGolden(t, "log_hygiene.md", []byte(md))
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs from golden (run `go test ./internal/report -update` after reviewing):\n--- got ---\n%s", name, got)
	}
}

// アカウントしか分からない主体の表記と data の値は、チェック (record) と report.md・通知 (schema。標準ライブラリだけ) で同じ。
func TestAccountOnlyLabelMatchesRecord(t *testing.T) {
	if a, b := schema.AccountOnlyLabel("111122223333"), record.AccountOnlyLabel("111122223333"); a != b {
		t.Fatalf("schema %q != record %q", a, b)
	}
	if schema.IdentityAccountOnly != record.IdentityAccountOnly {
		t.Fatal("IdentityAccountOnly")
	}
}
