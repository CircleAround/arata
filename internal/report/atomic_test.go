package report

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// 読み手 (aratam) が書きかけの report.json を読まないよう、一時ファイルから置き換える。
func TestWriteFileAtomicReplacesWholeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("同じファイルに上書きしている (rename で置き換えていない)")
	}
	if p := after.Mode().Perm(); p != 0o640 {
		t.Fatalf("mode %o", p)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("%q", b)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 {
		t.Fatalf("一時ファイルが残った: %v", es)
	}
}

// 置いてあったシンボリックリンクの先を書き換えない。
func TestWriteFileAtomicDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("リンク先が書き換わった: %q", b)
	}
}

func TestWriteFileAtomicFailureLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "report.json"), []byte("x")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%v", err)
	}
}
