package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/repoinit"
)

// 例の値はすべて架空。
var repoArgs = []string{"repo", "init", "--owner", "example-org", "--repo", "security-audit", "--accounts", "prod,staging",
	"--audit-account", "111122223333", "--store-bucket", "example-arata-store", "--region", "ap-northeast-1",
	"--alert-channel", "C0123456782", "--channel", "prod=C0123456789,staging=C0123456781", "--urgent-channel", "prod=C0123456780,staging=same"}

// withVersion は、このテストの間だけバイナリの版を差し替える (ビルド時に -ldflags で埋まる値)。
func withVersion(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

func (c *cli) repo(extra ...string) int {
	return c.run(append(append([]string{}, repoArgs...), extra...)...)
}

// TestRepoInitWritesTheSetOfThisVersion は、一式を書き出し、ワークフローの版がバイナリの版になることを確かめる (ADR 0059)。
func TestRepoInitWritesTheSetOfThisVersion(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatalf("exit %d: %s%s", code, c.stdout, c.stderr)
	}
	for _, p := range []string{".github/workflows/arata-audit.yml", ".github/workflows/arata-check.yml", "github/main.tf",
		"github/.terraform.lock.hcl", "aws/prod/arata.yaml", "aws/prod/allowlist.yaml", "aws/staging/aratam.yaml", "README.md", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Error(err)
		}
	}
	wf, _ := os.ReadFile(filepath.Join(out, ".github/workflows/arata-audit.yml"))
	if !strings.Contains(string(wf), "ARATA_VERSION: v0.15.0 ") || strings.Contains(string(wf), "cron:") {
		t.Errorf("the workflow must pin this version and have no schedule without --schedule")
	}
	// 既知リストの approved_at は、書き出した日 (テストの時計)
	al, _ := os.ReadFile(filepath.Join(out, "aws/prod/allowlist.yaml"))
	if !strings.Contains(string(al), "approved_at: 2026-10-21") {
		t.Errorf("allowlist: %s", al)
	}
	// 書き出した設定は、そのまま config check を通る (PR の検査と同じ)
	if code := c.run("config", "check", "-c", filepath.Join(out, "aws/prod/arata.yaml")); code != 0 {
		t.Errorf("config check exit %d: %s", code, c.stdout)
	}
	// もう一度流しても何も変えず、終了コード 0
	if code := c.repo("--out", out); code != 0 {
		t.Fatalf("second run exit %d: %s", code, c.stdout)
	}
	// --diff は差なし
	if code := c.repo("--out", out, "--diff"); code != 0 || !strings.Contains(c.stdout.String(), "揃っています") {
		t.Fatalf("diff exit %d: %s", code, c.stdout)
	}
}

// TestRepoInitDoesNotOverwrite は、既にあるファイルを上書きしないことと、--force が生成物だけを書き直すことを確かめる。
func TestRepoInitDoesNotOverwrite(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	wf, seed := filepath.Join(out, ".github/workflows/arata-check.yml"), filepath.Join(out, "aws/prod/allowlist.yaml")
	for _, p := range []string{wf, seed} {
		if err := os.WriteFile(p, []byte("edited\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 違いがあれば、書かずに終了コード 1 (エラーのログは出さない: 設定の誤りではない)
	if code := c.repo("--out", out); code != 1 || len(c.codes()) != 0 || !strings.Contains(c.stdout.String(), ".github/workflows/arata-check.yml") {
		t.Fatalf("exit %d codes %v: %s", code, c.codes(), c.stdout)
	}
	if b, _ := os.ReadFile(wf); string(b) != "edited\n" {
		t.Fatal("overwritten without --force")
	}
	// 定時を有効にする: --schedule --force。生成物は書き直し、aws/ は書き直さない
	if code := c.repo("--out", out, "--schedule", "--force"); code != 0 {
		t.Fatalf("--force exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if b, _ := os.ReadFile(wf); string(b) == "edited\n" {
		t.Error("--force must rewrite the generated file")
	}
	if b, _ := os.ReadFile(seed); string(b) != "edited\n" {
		t.Error("--force must not rewrite aws/")
	}
	if b, _ := os.ReadFile(filepath.Join(out, ".github/workflows/arata-audit.yml")); !strings.Contains(string(b), "cron:") {
		t.Error("--schedule must add the schedule")
	}
}

// TestRepoInitDiffJSON は、--diff --format json の形と終了コードを固定する (機械が読む出力。ADR 0054)。
func TestRepoInitDiffJSON(t *testing.T) {
	withVersion(t, "v0.15.0")
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	if code := c.repo("--out", out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	// 新しい版のバイナリで比べると、版の行が違う
	withVersion(t, "v0.16.0")
	if code := c.repo("--out", out, "--diff", "--format", "json"); code != 1 || len(c.codes()) != 0 {
		t.Fatalf("exit %d codes %v", code, c.codes())
	}
	var got repoinit.DiffOutput
	schematest.Conforms(t, repoinit.DiffSchema, c.stdout.Bytes(), &got)
	status := map[string]string{}
	for _, f := range got.Files {
		status[f.Path] = f.Status
	}
	if got.OK || got.Schema != "repo-diff" || got.SchemaVersion != 1 ||
		status[".github/workflows/arata-audit.yml"] != "differs" || status["github/main.tf"] != "same" || status["aws/prod/arata.yaml"] != "present" {
		t.Fatalf("%+v", got)
	}
	// --diff は何も書かない
	if b, _ := os.ReadFile(filepath.Join(out, ".github/workflows/arata-audit.yml")); !strings.Contains(string(b), "v0.15.0") {
		t.Error("--diff must not write")
	}
	// 人向けの出力は行の差分を添える
	if code := c.repo("--out", out, "--diff"); code != 1 || !strings.Contains(c.stdout.String(), "+  ARATA_VERSION: v0.16.0") {
		t.Fatalf("exit %d: %s", code, c.stdout)
	}
}

// TestRepoInitRejectsBadArguments は、形に合わない引数・足りない引数では何も書かないことを確かめる (既定値は持たない)。
func TestRepoInitRejectsBadArguments(t *testing.T) {
	withVersion(t, "v0.15.0")
	replace := func(flag, value string) []string {
		args := append([]string{}, repoArgs...)
		for i, a := range args {
			if a == flag {
				args[i+1] = value
			}
		}
		return args
	}
	drop := func(flag string) []string {
		var args []string
		for i := 0; i < len(repoArgs); i++ {
			if repoArgs[i] == flag {
				i++
				continue
			}
			args = append(args, repoArgs[i])
		}
		return args
	}
	cases := map[string][]string{
		"no owner":         drop("--owner"),
		"no repo":          drop("--repo"),
		"no accounts":      drop("--accounts"),
		"no audit account": drop("--audit-account"),
		"no bucket":        drop("--store-bucket"),
		"no region":        drop("--region"),
		"bad owner":        replace("--owner", "example-org/security-audit"),
		"bad account":      replace("--accounts", "prod,,staging"),
		"injection":        replace("--repo", "x\"\n${{ secrets.X }}"),
		// チャンネル ID に既定は無い (ADR 0060)。端末でなければ聞かずに止まる (newCLI は端末でない)
		"no alert channel":      drop("--alert-channel"),
		"no channel":            drop("--channel"),
		"no urgent channel":     drop("--urgent-channel"),
		"one channel missing":   replace("--channel", "prod=C0123456789"),
		"channel name":          replace("--channel", "prod=#general,staging=C0123456781"),
		"channel token":         replace("--channel", "prod=xoxb-0000-not-a-channel,staging=C0123456781"),
		"channel other account": replace("--channel", "prod=C0123456789,staging=C0123456781,dev=C0123456783"),
		"channel twice":         replace("--channel", "prod=C0123456789,prod=C0123456781"),
		"channel without =":     replace("--channel", "C0123456789"),
		"urgent keyword":        replace("--urgent-channel", "prod=none,staging=same"),
		"alert same":            replace("--alert-channel", "same"),
		"alert name":            replace("--alert-channel", "#alerts"),
		"bad format":            append(append([]string{}, repoArgs...), "--diff", "--format", "yaml"),
		"force with diff":       append(append([]string{}, repoArgs...), "--diff", "--force"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			c := newCLI(t)
			out := filepath.Join(c.dir, "repo")
			if code := c.run(append(args, "--out", out)...); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
				t.Fatalf("exit %d %v", code, c.codes())
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("nothing may be written")
			}
			// 貼り間違えたトークンを、エラーに写さない
			if strings.Contains(c.stderr.String(), "xoxb-0000") {
				t.Fatalf("the error carries the value: %s", c.stderr)
			}
		})
	}
	t.Run("no out", func(t *testing.T) {
		c := newCLI(t)
		if code := c.repo(); code != 2 {
			t.Fatalf("--out has no default: exit %d", code)
		}
	})
}

// TestRepoInitNeedsAReleaseVersion は、版の付かないビルドでは止まり、--arata-version を書いたときだけ進むことと、
// リリース版ではほかの版を指定できないことを確かめる。
func TestRepoInitNeedsAReleaseVersion(t *testing.T) {
	c := newCLI(t)
	out := filepath.Join(c.dir, "repo")
	withVersion(t, "dev")
	if code := c.repo("--out", out); code != 2 || !strings.Contains(c.stderr.String(), "--arata-version") {
		t.Fatalf("a dev build must stop: exit %d %s", code, c.stderr)
	}
	if code := c.repo("--out", out, "--arata-version", "v0.15.0"); code != 0 {
		t.Fatalf("exit %d: %s", code, c.stderr)
	}
	withVersion(t, "v0.15.0")
	if code := c.repo("--out", out, "--arata-version", "v0.14.0"); code != 2 {
		t.Fatalf("a release build must refuse another version: exit %d", code)
	}
	if code := c.repo("--out", out, "--arata-version", "v0.15.0", "--diff"); code != 0 {
		t.Fatalf("the same version is accepted: exit %d", code)
	}
}

// TestArataDoesNotLinkTheNotifier は、arata が通知と LLM のパッケージにつながっていないことを固定する (ADR 0001・0018)。
// repo init は aratam の設定の雛形も書くが、本文は internal/aratamscaffold (標準ライブラリだけ) から取る (ADR 0059)。
func TestArataDoesNotLinkTheNotifier(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Skipf("go list is not available: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, bad := range []string{"/internal/notify", "/internal/llm", "/internal/slack", "bedrockruntime"} {
			if strings.HasSuffix(p, bad) || strings.Contains(p, bad+"/") {
				t.Errorf("arata must not depend on %s", p)
			}
		}
	}
}
