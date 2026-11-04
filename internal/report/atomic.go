package report

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic は path を 0640 のファイルで置き換える (同じディレクトリの一時ファイルから rename)。
// 決定 (ADR 0037 の続き): aratam が書きかけの report.json を読まないように。置いてあったシンボリックリンクの先も書き換えない。
func WriteFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // rename の後は無いので失敗してよい
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
