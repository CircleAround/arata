package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/scaffold"
)

// 設定ファイルの解決順: -c > 環境変数 ARATA_CONFIG > カレントディレクトリの ./arata.yaml。
func TestConfigPathResolution(t *testing.T) {
	c := newCLI(t)
	base, _ := os.ReadFile(c.cfg)
	write := func(p, name string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(base), "name: acme", "name: "+name, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cwd := filepath.Join(c.dir, "cwd")
	write(filepath.Join(cwd, "arata.yaml"), "from-cwd")
	envCfg := filepath.Join(c.dir, "env", "env.yaml")
	write(envCfg, "from-env")
	flagCfg := filepath.Join(c.dir, "flag", "flag.yaml")
	write(flagCfg, "from-flag")
	t.Chdir(cwd)

	name := func(args ...string) string {
		t.Helper()
		if code := c.run(append([]string{"run", "--format", "md"}, args...)...); code != 0 {
			t.Fatalf("%v: exit %d %s", args, code, c.stderr)
		}
		first, _, _ := strings.Cut(c.stdout.String(), "\n")
		return first
	}
	if got := name(); !strings.Contains(got, "(from-cwd)") {
		t.Fatalf("./arata.yaml must be used without -c and ARATA_CONFIG: %s", got)
	}
	c.env["ARATA_CONFIG"] = envCfg
	if got := name(); !strings.Contains(got, "(from-env)") {
		t.Fatalf("ARATA_CONFIG must win over ./arata.yaml: %s", got)
	}
	if got := name("-c", flagCfg); !strings.Contains(got, "(from-flag)") {
		t.Fatalf("-c must win over ARATA_CONFIG: %s", got)
	}
	// 環境変数で指したファイルが無ければ ./arata.yaml に落ちずに設定エラー
	c.env["ARATA_CONFIG"] = filepath.Join(c.dir, "nope.yaml")
	if code := c.run("run"); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" || !strings.Contains(c.stderr.String(), "nope.yaml") {
		t.Fatalf("missing ARATA_CONFIG file: exit %d %s", code, c.stderr)
	}
	// config init --diff も同じ順で探す
	delete(c.env, "ARATA_CONFIG")
	if code := c.run("config", "init", "--diff"); code != 0 {
		t.Fatalf("diff must use ./arata.yaml: exit %d %s", code, c.stderr)
	}
}

func TestConfigPathNotFound(t *testing.T) {
	c := newCLI(t)
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{"run"}, {"profiles"}, {"config", "init", "--diff"}} {
		code := c.run(args...)
		var msg map[string]any
		for _, m := range c.logLines() {
			if m["code"] == "CONFIG_INVALID" {
				msg = m
			}
		}
		if code != 2 || msg == nil {
			t.Fatalf("%v: exit %d %s", args, code, c.stderr)
		}
		// 探した場所を列挙する
		for _, want := range []string{"-c/--config", "ARATA_CONFIG", "./arata.yaml"} {
			if !strings.Contains(msg["msg"].(string), want) {
				t.Fatalf("%v: message must list %q: %v", args, want, msg["msg"])
			}
		}
	}
}

// config init の --out の既定は ./arata.yaml。標準出力へは --out -。
func TestConfigInitDefaultOut(t *testing.T) {
	c := newCLI(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if code := c.run("config", "init", "--audit-account", "none"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	b, err := os.ReadFile(filepath.Join(dir, "arata.yaml"))
	if err != nil || string(b) != string(scaffold.Generate(checks.NewRegistry(), config.AuditAccountNone)) {
		t.Fatalf("./arata.yaml must be the template: %v", err)
	}
	// 既定の場所なら -c なしで次の手順を案内する
	if !strings.Contains(c.stdout.String(), "arata doctor を実行") {
		t.Fatalf("stdout: %s", c.stdout)
	}
	if err := os.WriteFile(filepath.Join(dir, "arata.yaml"), []byte("name: kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := c.run("config", "init", "--audit-account", "none"); code != 2 || !strings.Contains(c.stderr.String(), "or --diff to compare") {
		t.Fatalf("must refuse to overwrite ./arata.yaml: exit %d %s", code, c.stderr)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "arata.yaml")); string(b) != "name: kept\n" {
		t.Fatalf("overwritten: %s", b)
	}
	if code := c.run("config", "init", "--audit-account", "none", "--out", "-"); code != 0 || c.stdout.String() != string(scaffold.Generate(checks.NewRegistry(), config.AuditAccountNone)) {
		t.Fatalf("--out - must print the template: exit %d", code)
	}
}
