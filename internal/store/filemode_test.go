package store

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
)

func checkDBModes(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{dbFile, dbFile + "-wal", dbFile + "-shm"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if p := fi.Mode().Perm(); p&0o027 != 0 {
			t.Errorf("%s: mode %o (0640 より緩い)", name, p)
		}
	}
}

// 監査の結果を持つ SQLite は、umask に関わらず他のユーザーに読ませない (store の dir を利用者が 0755 で作っていても)。
func TestDatabaseIsNotWorldReadable(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0))
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(context.Background(), record.TrailEvent{EventID: "e", Time: time.Now(), Name: "x", Source: "s", CollectedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	checkDBModes(t, dir)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{}); err != nil {
		t.Fatal(err)
	}
	checkDBModes(t, dir)
}

// 以前の版が 0644 で作ったファイルも、開いたときに狭める。
func TestDatabaseModeIsTightenedOnOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dbFile)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- 古い版の状態の再現
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkDBModes(t, dir)
}
