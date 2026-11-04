package store

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeGz(t *testing.T, path string, size int) {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// 圧縮率の高いオブジェクト (gzip の爆弾) でディスクを埋めない。上限を超えたら止め、途中のファイルも残さない。
func TestGunzipStopsAtLimit(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "a.gz"), filepath.Join(dir, "a")
	writeGz(t, src, 1<<20)
	if err := gunzipFile(src, dst, 1024); !errors.Is(err, ErrDatabaseTooLarge) {
		t.Fatalf("err = %v, want ErrDatabaseTooLarge", err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("途中のファイルが残っている: %v", err)
	}
}

func TestGunzipAtLimit(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "a.gz"), filepath.Join(dir, "a")
	writeGz(t, src, 1024)
	if err := gunzipFile(src, dst, 1024); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() != 1024 {
		t.Fatalf("size = %v, err = %v", fi, err)
	}
}
