package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/report/schema"
)

// TestPeriodReport は run を重ねたストアから、収集せずに月次レポートを作る。
func TestPeriodReport(t *testing.T) {
	c := newCLI(t)
	if code := c.run("init", "-c", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour) // 10-22
	c.fake.Add(
		cloudtrailtest.Event("n1", c.now.Add(-2*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}),
		cloudtrailtest.Event("n2", c.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
	)
	if code := c.run("run", "-c", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	var rep struct {
		Findings struct{ New []struct{ ID, Check string } }
	}
	_ = json.Unmarshal(c.stdout.Bytes(), &rep)
	var rootID string
	for _, f := range rep.Findings.New {
		if f.Check == "root_usage" {
			rootID = f.ID
		}
	}
	c.now = c.now.Add(time.Hour)
	if code := c.run("resolve", rootID, "-c", c.cfg); code != 0 {
		t.Fatalf("resolve exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(3 * 24 * time.Hour) // daily が 3 日空く
	if code := c.run("run", "-c", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	calls := len(c.fake.Calls)
	c.now = time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	if code := c.run("report", "-c", c.cfg, "--month", "2026-10", "--format", "md"); code != 0 {
		t.Fatalf("report exit %d: %s", code, c.stderr)
	}
	if len(c.fake.Calls) != calls {
		t.Fatal("period report must not collect")
	}
	compareGolden(t, "period.md", c.stdout.Bytes())

	out := filepath.Join(c.dir, "monthly")
	if code := c.run("report", "-c", c.cfg, "--from", "2026-10-22", "--to", "2026-10-22", "--out", out); code != 0 {
		t.Fatalf("report exit %d: %s", code, c.stderr)
	}
	b, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	schematest.Conforms(t, schema.PeriodReportSchema, b, &schema.PeriodReport{})
	var period struct {
		Kind    string
		Summary struct{ New, Resolved int }
		Notes   []string
	}
	if err := json.Unmarshal(b, &period); err != nil || period.Kind != "period" || period.Summary.New != 3 || period.Summary.Resolved != 1 || len(period.Notes) != 0 {
		t.Fatalf("%v %+v", err, period)
	}
	if _, err := os.Stat(filepath.Join(out, "report.md")); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"--month", "2026-13"},
		{"--from", "2026-10-01"},
		{"--from", "2026-10-31", "--to", "2026-10-01"},
		{"--month", "2026-10", "--from", "2026-10-01", "--to", "2026-10-02"},
	} {
		if code := c.run(append([]string{"report", "-c", c.cfg}, args...)...); code != 2 || !strings.Contains(strings.Join(c.codes(), ","), "CONFIG_INVALID") {
			t.Fatalf("%v: exit %d %v", args, code, c.codes())
		}
	}
	c.assertCodesInVocabulary()
}
