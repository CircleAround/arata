package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store/storetest"
)

func readReport(t *testing.T, dir string) *report.Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := report.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// arata run --dry-run は dir:// のストアを 1 バイトも変えず、レポートに試しの実行であることを書く。
// 次の定時の実行は、試しの実行が無かったときと同じ指摘を新規として出す (ADR 0049)。
func TestRunDryRunDirStore(t *testing.T) {
	c := newCLI(t)
	storeDir := filepath.Join(c.dir, "store")
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--out", filepath.Join(c.dir, "out")); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, c.stderr)
	}
	c.now = c.now.Add(20 * time.Hour)
	c.rootLogin("r1")
	before := storetest.TreeState(t, storeDir)
	allow, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))

	out := filepath.Join(c.dir, "try")
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--dry-run", "--window", "2h", "--out", out); code != 0 {
		t.Fatalf("dry run: exit %d\n%s", code, c.stderr)
	}
	c.assertCodesInVocabulary()
	if after := storetest.TreeState(t, storeDir); !reflect.DeepEqual(before, after) {
		t.Fatalf("store changed:\nbefore %v\nafter  %v", before, after)
	}
	if b, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml")); string(b) != string(allow) {
		t.Fatal("allowlist changed")
	}
	rep := readReport(t, out)
	if !rep.DryRun || rep.Summary.New != 1 || rep.Window.From != "2026-10-22T03:00:00Z" {
		t.Fatalf("dry_run=%v %+v %+v", rep.DryRun, rep.Summary, rep.Window)
	}
	var raw map[string]any
	b, _ := os.ReadFile(filepath.Join(out, "report.json"))
	if err := json.Unmarshal(b, &raw); err != nil || raw["dry_run"] != true {
		t.Fatalf("report.json must carry dry_run: true: %v", raw["dry_run"])
	}
	md, _ := os.ReadFile(filepath.Join(out, "report.md"))
	if !strings.Contains(string(md), "試しの実行") {
		t.Fatalf("report.md must say it is a dry run:\n%s", md)
	}

	// 標準出力にも出せる
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--dry-run", "--format", "md"); code != 0 || !strings.Contains(c.stdout.String(), "試しの実行") {
		t.Fatalf("dry run to stdout: exit %d\n%s", code, c.stdout)
	}
	if after := storetest.TreeState(t, storeDir); !reflect.DeepEqual(before, after) {
		t.Fatal("store changed by the second dry run")
	}

	c.now = c.now.Add(4 * time.Hour)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--out", filepath.Join(c.dir, "out")); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, c.stderr)
	}
	next := readReport(t, filepath.Join(c.dir, "out"))
	if next.DryRun || next.Summary.New != 1 || next.Window.From != "2026-10-21T09:00:00Z" {
		t.Fatalf("the scheduled run must report the finding as new from the previous window end: %+v %+v", next.Summary, next.Window)
	}
}

// s3:// のストアでは、試しの実行は S3 へ何も送らない。
func TestRunDryRunS3Store(t *testing.T) {
	c, f := newS3CLI(t)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, c.stderr)
	}
	c.now = c.now.Add(20 * time.Hour)
	c.rootLogin("r1")
	before := f.Snapshot()
	f.ResetRequests()
	out := filepath.Join(c.dir, "try")
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--dry-run", "--window", "2h", "--out", out); code != 0 {
		t.Fatalf("dry run: exit %d\n%s", code, c.stderr)
	}
	if n := len(f.Requests("PUT")); n != 0 {
		t.Fatalf("dry run sent %d PUT requests", n)
	}
	if after := f.Snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("S3 changed:\nbefore %v\nafter  %v", before, after)
	}
	if rep := readReport(t, out); !rep.DryRun || rep.Summary.New != 1 {
		t.Fatalf("%+v", rep.Summary)
	}
}

// --window は --dry-run のときだけ。誤った指定はストアを開く前に止める (ストアを作らない)。
func TestRunDryRunFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--window", "1h"},
		{"--dry-run", "--window", "soon"},
		{"--dry-run", "--window", "0"},
		{"--dry-run", "--window", "-1h"},
	} {
		c := newCLI(t)
		code := c.run(append([]string{"run", "--config", c.cfg, "--profile", "daily"}, args...)...)
		if code != 2 || !strings.Contains(strings.Join(c.codes(), ","), "CONFIG_INVALID") {
			t.Fatalf("%v: exit %d codes %v\n%s", args, code, c.codes(), c.stderr)
		}
		if _, err := os.Stat(filepath.Join(c.dir, "store")); !os.IsNotExist(err) {
			t.Fatalf("%v: the store must not be created: %v", args, err)
		}
	}
}

// ストアがまだ無くても試せる (全部が新規として出る)。ストアは作らない。
func TestRunDryRunWithoutStore(t *testing.T) {
	c := newCLI(t)
	c.rootLogin("r1")
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--dry-run"); code != 0 {
		t.Fatalf("dry run: exit %d\n%s", code, c.stderr)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "store")); !os.IsNotExist(err) {
		t.Fatalf("the store must not be created: %v", err)
	}
}
