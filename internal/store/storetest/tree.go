package storetest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TreeState は dir の下の全ファイルの「相対パス → 権限・更新時刻・内容のハッシュ」(ディレクトリは権限だけ)。
// 実行の前後で比べて、ファイルが増えも減りもせず 1 バイトも変わっていないことを確かめる。dir が無ければ空。
func TreeState(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			out[rel+"/"] = fi.Mode().String()
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[rel] = fi.Mode().String() + " " + fi.ModTime().UTC().Format(time.RFC3339Nano) + " " + hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return out
}
