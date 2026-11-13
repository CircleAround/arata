package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
	"github.com/CircleAround/arata/internal/store/storetest"
)

func seedStore(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	if err := s.UpsertFinding(ctx, store.Finding{ID: "f1", Check: "root_usage", Key: "k1", Severity: "critical", Summary: "s", FirstSeen: at, LastSeen: at, LastChanged: at, Status: store.FindingOpen}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendRaw(ctx, "trail", record.Metric{Date: "2026-10-20", Source: "trail", Metric: "m", Value: 1}); err != nil {
		t.Fatal(err)
	}
}

func scratchWrites(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if err := s.UpsertFinding(ctx, store.Finding{ID: "f2", Check: "root_usage", Key: "k2", Severity: "critical", Summary: "s", FirstSeen: at, LastSeen: at, LastChanged: at, Status: store.FindingOpen}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkReported(ctx, []string{"f1", "f2"}, at); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendRaw(ctx, "trail", record.Metric{Date: "2026-10-20", Source: "trail", Metric: "m", Value: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginRun(ctx, store.Run{ID: "r", Profile: "daily", WindowFrom: at, WindowTo: at, StartedAt: at, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// 複製はストアの今の状態を読め、複製への書き込み・Commit・Close の後も元のディレクトリは 1 バイトも変わらない (ADR 0049)。
func TestOpenScratchLeavesTheStoreUntouched(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	orig, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedStore(t, orig)
	if err := orig.Close(); err != nil {
		t.Fatal(err)
	}
	before := storetest.TreeState(t, dir)

	s, err := store.OpenScratch(dir)
	if err != nil {
		t.Fatal(err)
	}
	work := s.Path()
	if work == dir {
		t.Fatal("scratch must not work in the store directory")
	}
	fs, err := s.Findings(context.Background(), "root_usage", nil)
	if err != nil || len(fs) != 1 || fs[0].ID != "f1" {
		t.Fatalf("scratch must see the store's findings: %v %+v", err, fs)
	}
	scratchWrites(t, s)
	if fs, _ := s.Findings(context.Background(), "root_usage", nil); len(fs) != 2 {
		t.Fatalf("scratch must hold its own writes: %+v", fs)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if after := storetest.TreeState(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("store changed:\nbefore %v\nafter  %v", before, after)
	}
	if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scratch directory must be removed on Close: %v", err)
	}
	// 複製を開いている間も、閉じた後も、元のストアはふつうに開ける (複製の間だけロックを持つ)
	again, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}

// 書き込み中の実行がロックを持っている間は複製しない (途中の状態を読まない)。
func TestOpenScratchFailsWhileLocked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	orig, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	if _, err := store.OpenScratch(dir); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

// 複製を開いている間は元のストアのロックを持たない (試しの収集の間に定時の実行を止めない)。
func TestOpenScratchReleasesTheLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	orig, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	orig.Close()
	s, err := store.OpenScratch(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	again, err := store.Open(dir)
	if err != nil {
		t.Fatalf("the store must be free while a scratch copy is open: %v", err)
	}
	again.Close()
}

// ストアがまだ無ければ空の複製で始め、ストアのディレクトリを作らない。
func TestOpenScratchWithoutStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s, err := store.OpenScratch(dir)
	if err != nil {
		t.Fatal(err)
	}
	scratchWrites(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("store directory must not be created: %v", err)
	}
}

// 前の実行が異常終了して -wal が残っていても、その内容を含めて読み、元のファイルは変えない。
func TestOpenScratchReadsLeftoverWAL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	orig, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	seedStore(t, orig)
	// 開いたまま (チェックポイント前) のファイルを別のディレクトリへ写し、異常終了の後の姿を作る
	crashed := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(crashed, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"audit.sqlite", "audit.sqlite-wal", "audit.lock"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(crashed, name), b, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	orig.Close()
	before := storetest.TreeState(t, crashed)
	s, err := store.OpenScratch(crashed)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := s.Findings(context.Background(), "root_usage", nil)
	if err != nil || len(fs) != 1 {
		t.Fatalf("the finding in the WAL must be visible: %v %+v", err, fs)
	}
	s.Close()
	if after := storetest.TreeState(t, crashed); !reflect.DeepEqual(before, after) {
		t.Fatalf("store changed:\nbefore %v\nafter  %v", before, after)
	}
}

// S3 の複製は書き込んでも Commit しても S3 へ何も送らず、raw も取得しない。
func TestOpenS3ScratchNeverWrites(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, "example-arata-store")
	loc := store.S3Location{Bucket: "example-arata-store", Prefix: "acme"}
	orig, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	seedStore(t, orig)
	if err := orig.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	orig.Close()
	before := f.Snapshot()
	f.ResetRequests()

	s, err := store.OpenS3Scratch(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	if fs, err := s.Findings(ctx, "root_usage", nil); err != nil || len(fs) != 1 {
		t.Fatalf("scratch must see the store's findings: %v %+v", err, fs)
	}
	scratchWrites(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(f.Requests("PUT")); n != 0 {
		t.Fatalf("scratch sent %d PUT requests", n)
	}
	if after := f.Snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("S3 changed:\nbefore %v\nafter  %v", before, after)
	}
	for _, r := range f.Requests("GET") {
		if r.Key != "acme/audit.sqlite.gz" {
			t.Fatalf("scratch must fetch only the database, got %s", r.Key)
		}
	}
}
