package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
)

func TestRebuildCommand(t *testing.T) {
	c := newCLI(t)
	c.fake.Add(cloudtrailtest.Event("r1", c.now.Add(-time.Hour), cloudtrailtest.Root("123456789012"), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, c.stderr)
	}
	store := filepath.Join(c.dir, "store")

	if code := c.run("rebuild", "--config", c.cfg); code != 0 {
		t.Fatalf("rebuild: exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	out := c.stdout.String()
	for _, want := range []string{"rebuilt " + filepath.Join(store, "audit.sqlite"), "carried over from the existing database: runs, findings, finding_events, meta, principal status",
		"trail_event", "backup: " + filepath.Join(store, "audit.sqlite.bak")} {
		if !strings.Contains(out, want) {
			t.Fatalf("output must contain %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(store, "audit.sqlite.bak")); err != nil {
		t.Fatal(err)
	}

	if code := c.run("rebuild", "--config", c.cfg, "--from-scratch", "--format", "json"); code != 0 {
		t.Fatalf("rebuild --from-scratch: exit %d\n%s", code, c.stderr)
	}
	var res map[string]any
	if err := json.Unmarshal(c.stdout.Bytes(), &res); err != nil {
		t.Fatalf("json: %v\n%s", err, c.stdout)
	}
	if res["from_scratch"] != true || res["records"].(map[string]any)["trail_event"] != float64(1) || res["principal_status"] != "unknown" {
		t.Fatalf("json: %s", c.stdout)
	}
	// findings を空から作ったので、次の run で全部が new になることを標準エラーで知らせる
	if !strings.Contains(c.stderr.String(), "reported again as new") {
		t.Fatalf("stderr must warn: %s", c.stderr)
	}

	if code := c.run("rebuild", "--config", c.cfg, "--baseline"); code != 2 {
		t.Fatalf("--baseline without --from-scratch must be rejected: exit %d", code)
	}
	c.assertCodesInVocabulary()
}

func TestRebuildCommandWithoutStore(t *testing.T) {
	c := newCLI(t)
	if code := c.run("rebuild", "--config", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "STORE_CORRUPT" || !strings.Contains(c.stderr.String(), "--from-scratch") {
		t.Fatalf("exit %d codes %v\n%s", code, c.codes(), c.stderr)
	}
	if code := c.run("rebuild", "--config", c.cfg, "--from-scratch", "--baseline"); code != 0 {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "principals: baseline") {
		t.Fatalf("%s", c.stdout)
	}
}
