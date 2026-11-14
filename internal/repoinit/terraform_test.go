package repoinit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Terraform を実際に動かすテスト。provider の取得にネットワーク (Terraform のレジストリ) が要るので、ふだんの go test ./... では動かさない。
// 環境変数 ARATA_TEST_TERRAFORM=1 で有効にする (CI の terraform のジョブと make test-terraform)。
// GitHub には接続しない: 流すのは fmt と validate だけで、plan も apply もしない (この一式の Terraform は、秘密に触れない。ADR 0060)。
func terraformBin(t *testing.T) string {
	t.Helper()
	if os.Getenv("ARATA_TEST_TERRAFORM") != "1" {
		t.Skip("set ARATA_TEST_TERRAFORM=1 to run the Terraform tests (needs terraform on PATH and network access to the Terraform registry)")
	}
	bin, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("ARATA_TEST_TERRAFORM=1 but terraform is not on PATH: %v", err)
	}
	return bin
}

type tfRoot struct {
	t   *testing.T
	bin string
	dir string
	env []string
}

func (r tfRoot) run(args ...string) (string, error) {
	r.t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), r.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r tfRoot) must(args ...string) string {
	r.t.Helper()
	out, err := r.run(args...)
	if err != nil {
		r.t.Fatalf("terraform %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// writeSet は見本の引数の一式を一時ディレクトリに書く。
func writeSet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := Apply(dir, mustFiles(t, exampleParams()), false); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestTerraformFormatAndValidate は、書き出した Terraform が terraform fmt の形で、固定した provider の版で validate を通ることを確かめる。
// init は lock を書き換えさせない (-lockfile=readonly): 書き出した lock のハッシュで、取得した provider が確かめられる。
func TestTerraformFormatAndValidate(t *testing.T) {
	bin := terraformBin(t)
	dir := writeSet(t)
	cache := t.TempDir()
	if out, err := (tfRoot{t, bin, dir, nil}).run("fmt", "-check", "-recursive", "-diff", "."); err != nil {
		t.Fatalf("terraform fmt: %v\n%s", err, out)
	}
	for _, root := range []string{"github"} {
		r := tfRoot{t, bin, filepath.Join(dir, root), []string{"TF_IN_AUTOMATION=1", "TF_PLUGIN_CACHE_DIR=" + cache, "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE=0"}}
		before, _ := os.ReadFile(filepath.Join(r.dir, ".terraform.lock.hcl"))
		r.must("init", "-input=false", "-no-color", "-lockfile=readonly")
		if out := r.must("validate", "-no-color"); !strings.Contains(out, "Success") {
			t.Errorf("%s: %s", root, out)
		}
		if after, _ := os.ReadFile(filepath.Join(r.dir, ".terraform.lock.hcl")); string(before) != string(after) {
			t.Errorf("%s: init changed the lock file", root)
		}
	}
}
