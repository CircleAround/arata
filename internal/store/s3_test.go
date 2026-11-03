package store_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
	"github.com/CircleAround/arata/internal/store/storetest"
)

const (
	bucket = "example-arata-store"
	dbKey  = "acme/audit.sqlite.gz"
)

var (
	day1 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	day2 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	loc  = store.S3Location{Bucket: bucket, Prefix: "acme"}
)

func trail(id string, at time.Time) record.TrailEvent {
	return record.TrailEvent{EventID: id, Time: at, Name: "ConsoleLogin", Source: "trail", CollectedAt: at}
}

func rawKey(at time.Time) string {
	return "acme/raw/trail/" + at.Format("2006-01-02") + ".jsonl"
}

// write は 1 件の事象を、run と同じように raw と SQLite へ入れる。
func write(t *testing.T, s store.Store, e record.TrailEvent) {
	t.Helper()
	ctx := context.Background()
	if err := s.AppendRaw(ctx, "trail", e); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
}

func eventIDs(t *testing.T, s store.Query) []string {
	t.Helper()
	evs, err := s.Events(context.Background(), time.Time{}, day2.Add(24*time.Hour), store.EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range evs {
		out = append(out, e.EventID)
	}
	return out
}

func lines(b []byte) int { return bytes.Count(b, []byte("\n")) }

// 初回は If-None-Match: * で作り、2 回目は開始時の ETag の If-Match で置き換える。中身は次の Open に引き継がれる。
func TestS3FirstWriteThenConditionalUpdate(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	write(t, s, trail("e1", day1))
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()
	puts := f.Requests("PUT")
	if last := puts[len(puts)-1]; last.Key != dbKey || last.IfNoneMatch != "*" || last.IfMatch != "" {
		t.Fatalf("the database goes last with If-None-Match: *: %+v", puts)
	}
	first := f.Snapshot()[dbKey]

	f.ResetRequests()
	s, err = store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := eventIDs(t, s); !reflect.DeepEqual(got, []string{"e1"}) {
		t.Fatalf("the database must be restored from S3: %v", got)
	}
	write(t, s, trail("e2", day1))
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	puts = f.Requests("PUT")
	if last := puts[len(puts)-1]; last.Key != dbKey || last.IfMatch != first {
		t.Fatalf("the database must be written with If-Match %s: %+v", first, puts)
	}
	// SQLite は gzip で置く
	zr, err := gzip.NewReader(bytes.NewReader(f.Get(dbKey)))
	if err != nil {
		t.Fatal(err)
	}
	head, _ := io.ReadAll(zr)
	if !bytes.HasPrefix(head, []byte("SQLite format 3")) {
		t.Fatalf("not a gzipped SQLite file")
	}
	if n := lines(f.Get(rawKey(day1))); n != 2 {
		t.Fatalf("raw lines: %d", n)
	}
}

// 同時に 2 つ走ると、後から終わったほうが STORE_CONFLICT で失敗し、先の結果 (原本を含む) を変えない。
func TestS3ConcurrentRunsConflict(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e0", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()

	a, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	write(t, a, trail("a1", day1))
	write(t, b, trail("b1", day1))
	if err := a.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after := f.Snapshot()
	if err := b.Commit(ctx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if !reflect.DeepEqual(f.Snapshot(), after) {
		t.Fatalf("the loser must not change S3")
	}
}

// SQLite の事前の確かめを通った後に別の実行が同じ日の JSONL を書いても、条件付きなので原本の行を消さない。
func TestS3RawIsConditional(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e0", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()

	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	write(t, s, trail("e1", day1))
	other := append(f.Get(rawKey(day1)), []byte("{\"other\":true}\n")...)
	f.BeforePut = func(key string) int {
		if key == rawKey(day1) {
			f.BeforePut = nil
			f.Put(key, other)
		}
		return 0
	}
	if err := s.Commit(ctx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if !bytes.Equal(f.Get(rawKey(day1)), other) {
		t.Fatalf("the other run's raw lines must survive")
	}
}

// Commit しなければ (途中の失敗・中断・読むだけのコマンド) S3 は変わらず、一時ディレクトリは消える。
func TestS3WithoutCommitChangesNothing(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e0", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()
	before := f.Snapshot()
	f.ResetRequests()

	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	work := s.Path()
	write(t, s, trail("e1", day2))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.Snapshot(), before) || len(f.Requests("PUT")) != 0 {
		t.Fatalf("S3 must not change without Commit: %+v", f.Requests("PUT"))
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("the temporary directory must be removed: %v", err)
	}
}

// 中断された ctx の Commit は何も送らない。
func TestS3CommitInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f, api := storetest.NewFakeS3(t, bucket)
	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	write(t, s, trail("e1", day1))
	cancel()
	if err := s.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if len(f.Snapshot()) != 0 {
		t.Fatalf("nothing must be uploaded: %v", f.Snapshot())
	}
}

// JSONL は追記した日のファイルだけを取得して送る。追記先が窓の予測から外れた過去の日でも、S3 の既存の行を保つ。
func TestS3RawTransfersOnlyTouchedDays(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e1", day1))
	write(t, seed, trail("e2", day2))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()
	f.ResetRequests()
	day1Tag := f.Snapshot()[rawKey(day1)]

	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, r := range f.Requests("GET") {
		if strings.Contains(r.Key, "/raw/") {
			t.Fatalf("raw must not be fetched before it is touched: %+v", r)
		}
	}
	write(t, s, trail("e3", day2))
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if f.Snapshot()[rawKey(day1)] != day1Tag {
		t.Fatalf("an untouched day must not change")
	}
	if n := lines(f.Get(rawKey(day2))); n != 2 {
		t.Fatalf("appending must keep the existing lines: %d", n)
	}
	for _, r := range append(f.Requests("GET"), f.Requests("PUT")...) {
		if r.Key == rawKey(day1) {
			t.Fatalf("an untouched day must not be transferred: %+v", r)
		}
	}
}

// reports/ (arata report が読む) は Open で戻り、変わったものだけ送る。
func TestS3Reports(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	s, _ := store.OpenS3(ctx, api, loc)
	defer s.Close()
	dir := filepath.Join(s.Path(), "reports")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "daily.json"), []byte(`{"a":1}`), 0o640)
	_ = os.WriteFile(filepath.Join(dir, "weekly.json"), []byte(`{"w":1}`), 0o640)
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()
	f.ResetRequests()

	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dir = filepath.Join(s.Path(), "reports")
	b, err := os.ReadFile(filepath.Join(dir, "daily.json"))
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("report must be restored: %q %v", b, err)
	}
	// 同じ長さで内容だけ変わっても送る
	_ = os.WriteFile(filepath.Join(dir, "daily.json"), []byte(`{"a":2}`), 0o640)
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := string(f.Get("acme/reports/daily.json")); got != `{"a":2}` {
		t.Fatalf("report: %q", got)
	}
	for _, r := range f.Requests("PUT") {
		if strings.HasSuffix(r.Key, "weekly.json") {
			t.Fatalf("an unchanged report must not be uploaded")
		}
	}
}

// 権限の失敗を「まだ無い」と取り違えない (空のストアで始めて全部 new にしない)。
func TestS3AccessDeniedIsNotEmptyStore(t *testing.T) {
	f, api := storetest.NewFakeS3(t, bucket)
	f.Denied["GET"] = true
	_, err := store.OpenS3(context.Background(), api, loc)
	if !errors.Is(err, store.ErrS3Unavailable) {
		t.Fatalf("want ErrS3Unavailable, got %v", err)
	}
}

func TestS3CorruptDatabase(t *testing.T) {
	f, api := storetest.NewFakeS3(t, bucket)
	f.Put(dbKey, []byte("not gzip"))
	_, err := store.OpenS3(context.Background(), api, loc)
	if err == nil || errors.Is(err, store.ErrS3Unavailable) {
		t.Fatalf("a broken object is corruption, not unavailability: %v", err)
	}
}

// JSONL だけが先に進んだ (SQLite の書き込みが失敗した) 次の run は、古い SQLite から同じ窓を引き直す。
// SQLite では二重に数えず、原本には行が重なるが rebuild の events は event_id で 1 件になる (ADR 0034)。
func TestS3RawAheadOfDatabase(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e0", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()

	s, _ := store.OpenS3(ctx, api, loc)
	defer s.Close()
	write(t, s, trail("e1", day1))
	f.BeforePut = func(key string) int {
		if key == dbKey {
			return 500
		}
		return 0
	}
	if err := s.Commit(ctx); !errors.Is(err, store.ErrS3Unavailable) {
		t.Fatalf("want ErrS3Unavailable, got %v", err)
	}
	s.Close()
	f.BeforePut = nil
	if n := lines(f.Get(rawKey(day1))); n != 2 {
		t.Fatalf("raw went ahead: %d", n)
	}

	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := eventIDs(t, s); !reflect.DeepEqual(got, []string{"e0"}) {
		t.Fatalf("the database must be the last committed one: %v", got)
	}
	write(t, s, trail("e1", day1))
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{}); err != nil {
		t.Fatal(err)
	}
	s, err = store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := eventIDs(t, s); !reflect.DeepEqual(got, []string{"e0", "e1"}) {
		t.Fatalf("rebuild must not double the event: %v", got)
	}
}

// rebuild は raw を全部取得して作り直し、SQLite だけを条件付きで置き換える。ページをまたぐ一覧も読む。
func TestS3Rebuild(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	f.PageSize = 1
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e1", day1))
	write(t, seed, trail("e2", day2))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()
	raw := f.Snapshot()[rawKey(day1)]
	oldDB := f.Snapshot()[dbKey]
	f.ResetRequests()

	res, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || res.Database != "s3://"+bucket+"/"+dbKey || res.Backup != "" {
		t.Fatalf("result: %+v", res)
	}
	puts := f.Requests("PUT")
	if len(puts) != 1 || puts[0].Key != dbKey || puts[0].IfMatch != oldDB {
		t.Fatalf("only the database, conditionally: %+v", puts)
	}
	if f.Snapshot()[rawKey(day1)] != raw {
		t.Fatalf("raw must not change")
	}
}

func TestS3RebuildConflict(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e1", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()
	f.BeforePut = func(key string) int {
		f.BeforePut = nil
		f.Put(key, []byte("written by another run"))
		return 0
	}
	if _, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if string(f.Get(dbKey)) != "written by another run" {
		t.Fatalf("the other run's database must survive")
	}
}

// SQLite が壊れた・失われたときの戻し方。--from-scratch は壊れたオブジェクトを読まず、それでも条件付きで置き換える。
func TestS3RebuildFromScratch(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e1", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()

	f.Put(dbKey, []byte("broken"))
	broken := f.Snapshot()[dbKey]
	if _, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{}); err == nil || errors.Is(err, store.ErrS3Unavailable) {
		t.Fatalf("carrying over from a broken database must fail as corruption: %v", err)
	}
	f.ResetRequests()
	if _, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{FromScratch: true}); err != nil {
		t.Fatal(err)
	}
	if puts := f.Requests("PUT"); len(puts) != 1 || puts[0].IfMatch != broken {
		t.Fatalf("conditional on the broken object: %+v", puts)
	}

	f.Delete(dbKey)
	if _, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{}); !errors.Is(err, store.ErrNoDatabase) {
		t.Fatalf("want ErrNoDatabase, got %v", err)
	}
	f.ResetRequests()
	if _, err := store.RebuildS3(ctx, api, loc, store.RebuildOptions{FromScratch: true}); err != nil {
		t.Fatal(err)
	}
	if puts := f.Requests("PUT"); len(puts) != 1 || puts[0].IfNoneMatch != "*" {
		t.Fatalf("a lost database is created with If-None-Match: %+v", puts)
	}
	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := eventIDs(t, s); !reflect.DeepEqual(got, []string{"e1"}) {
		t.Fatalf("rebuilt events: %v", got)
	}
}

// 負けが確かな実行は raw も進めない (別の日のファイルで raw の条件には掛からなくても、先に SQLite の版で気づく)。
func TestS3ConflictIsDetectedBeforeRaw(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	seed, _ := store.OpenS3(ctx, api, loc)
	write(t, seed, trail("e0", day1))
	if err := seed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	seed.Close()

	a, _ := store.OpenS3(ctx, api, loc)
	defer a.Close()
	b, _ := store.OpenS3(ctx, api, loc)
	defer b.Close()
	write(t, a, trail("a1", day1))
	write(t, b, trail("b1", day2))
	if err := a.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(ctx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if f.Get(rawKey(day2)) != nil {
		t.Fatalf("the loser must not upload raw")
	}
}

// raw があるのに SQLite が無いのは消えた可能性が高い。初回 (raw も無い) と区別する。
func TestS3RawWithoutDatabase(t *testing.T) {
	ctx := context.Background()
	f, api := storetest.NewFakeS3(t, bucket)
	s, err := store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.RawWithoutDatabase() {
		t.Fatalf("a new store has neither")
	}
	write(t, s, trail("e1", day1))
	if err := s.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.RawWithoutDatabase() {
		t.Fatalf("both exist")
	}
	s.Close()

	f.Delete(dbKey)
	s, err = store.OpenS3(ctx, api, loc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.RawWithoutDatabase() {
		t.Fatalf("the database was lost")
	}
}
