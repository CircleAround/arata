package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/store"
	"github.com/CircleAround/arata/internal/store/storetest"
)

const testBucket = "example-arata-store"

// useS3 は harness のストアを偽の S3 に向ける (実 AWS には接続しない)。
func useS3(t *testing.T, h *harness) *storetest.FakeS3 {
	t.Helper()
	f, api := storetest.NewFakeS3(t, testBucket)
	h.cfg.Store = config.Store{Scheme: "s3", Bucket: testBucket, Prefix: "acme"}
	h.deps.S3Store = func(context.Context, *config.Config) (store.S3API, error) { return api, nil }
	return f
}

func addRootLogin(h *harness, id string) {
	h.fake.Add(cloudtrailtest.Event(id, h.now.Add(-time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
}

// 同じ入力で dir:// と s3:// の run の結果 (レポートと表の中身) が同じ。run を重ねると 2 回目は S3 の複製から続く。
func TestS3StoreMatchesDirStore(t *testing.T) {
	ctx := context.Background()
	runTwice := func(h *harness) [][]byte {
		var out [][]byte
		for i := range 2 {
			addRootLogin(h, fmt.Sprintf("r%d", i))
			e, err := Open(h.cfg, h.deps)
			if err != nil {
				t.Fatal(err)
			}
			res, err := e.Run(ctx, "daily")
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			j, err := res.Report.JSON()
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, j)
			h.now = h.now.Add(24 * time.Hour)
		}
		return out
	}
	dir := newHarness(t)
	s3h := newHarness(t)
	f := useS3(t, s3h)
	want, got := runTwice(dir), runTwice(s3h)
	for i := range want {
		if !bytes.Equal(want[i], got[i]) {
			t.Fatalf("run %d: reports differ:\n%s\n---\n%s", i, want[i], got[i])
		}
	}
	dump := func(s store.Store) map[string][]string {
		m, err := storetest.Dump(s.Path())
		if err != nil {
			t.Fatal(err)
		}
		delete(m, "runs") // finished_at は実時間
		return m
	}
	de, _ := Open(dir.cfg, dir.deps)
	defer de.Close()
	se, err := Open(s3h.cfg, s3h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer se.Close()
	if a, b := dump(de.Store()), dump(se.Store()); !reflect.DeepEqual(a, b) {
		t.Fatalf("tables differ:\n%v\n---\n%v", a, b)
	}
	// report (再評価しない再表示) も S3 から読める
	if b, err := se.LastReport("daily"); err != nil || !bytes.Equal(b, got[1]) {
		t.Fatalf("last report: %v\n%s", err, b)
	}
	if f.Get("acme/reports/daily.md") == nil || f.Get("acme/audit.sqlite.gz") == nil {
		t.Fatalf("objects: %v", f.Snapshot())
	}
}

// 同時に 2 つ走らせると後のほうが STORE_CONFLICT (exit 2) で失敗し、先の結果は残る。
func TestS3ConflictExit(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	f := useS3(t, h)
	addRootLogin(h, "r1")
	a, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, e := range []*Engine{a, b} {
		if _, err := e.Run(ctx, "daily"); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	after := f.Snapshot()
	err = b.Commit(ctx)
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Code != CodeStoreConflict || xe.Exit != ExitConfig {
		t.Fatalf("want STORE_CONFLICT, got %v", err)
	}
	if !reflect.DeepEqual(f.Snapshot(), after) {
		t.Fatalf("the loser must not change S3")
	}
	if codes := strings.Join(h.logCodes(t), ","); !strings.Contains(codes, CodeStoreConflict) {
		t.Fatalf("log codes: %s", codes)
	}
}

// 権限が無いときは STORE_UNAVAILABLE で、STORE_CORRUPT (rebuild を促す) にしない。
func TestS3UnavailableIsNotCorrupt(t *testing.T) {
	h := newHarness(t)
	f := useS3(t, h)
	f.Denied["GET"] = true
	_, err := Open(h.cfg, h.deps)
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Code != CodeStoreUnavailable || xe.Exit != ExitConfig {
		t.Fatalf("want STORE_UNAVAILABLE, got %v", err)
	}
	if _, err := Rebuild(context.Background(), h.cfg, h.deps, store.RebuildOptions{}); !errors.As(err, &xe) || xe.Code != CodeStoreUnavailable {
		t.Fatalf("rebuild: want STORE_UNAVAILABLE, got %v", err)
	}
}

func TestS3Rebuild(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	f := useS3(t, h)
	addRootLogin(h, "r1")
	e, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.Delete("acme/audit.sqlite.gz")
	var xe *ExitError
	if _, err := Rebuild(ctx, h.cfg, h.deps, store.RebuildOptions{}); !errors.As(err, &xe) || xe.Code != CodeStoreCorrupt {
		t.Fatalf("want STORE_CORRUPT, got %v", err)
	}
	res, err := Rebuild(ctx, h.cfg, h.deps, store.RebuildOptions{FromScratch: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Database != "s3://"+testBucket+"/acme/audit.sqlite.gz" || f.Get("acme/audit.sqlite.gz") == nil {
		t.Fatalf("result: %+v", res)
	}
}

func doctorRow(r *DoctorResult, item string) *DoctorRow {
	for i := range r.Rows {
		if r.Rows[i].Item == item {
			return &r.Rows[i]
		}
	}
	return nil
}

// doctor はストアのバケットを読めるかを確かめ、書き込みは試さない。読み取り専用の約束との区別を表示する。
func TestDoctorS3Store(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	f := useS3(t, h)
	f.Versioning, f.Encrypted, f.PublicBlocked = "Enabled", true, true
	res := Doctor(ctx, h.cfg, h.deps, 24*time.Hour)
	if len(f.Requests("PUT")) != 0 {
		t.Fatalf("doctor must not write: %+v", f.Requests("PUT"))
	}
	for _, item := range []string{"store_read", "store_versioning", "store_encryption", "store_public_access"} {
		if row := doctorRow(res, item); row == nil || row.Status != DoctorOK {
			t.Fatalf("%s: %+v\n%+v", item, row, res.Rows)
		}
	}
	scope := doctorRow(res, "store_scope")
	if scope == nil || !strings.Contains(scope.Detail, "読み取り専用") || !strings.Contains(scope.Detail, "書き込みは試さない") {
		t.Fatalf("scope: %+v", scope)
	}
	if strings.Join(res.StoreActions, ",") != "s3:GetObject,s3:ListBucket,s3:PutObject" {
		t.Fatalf("store actions: %v", res.StoreActions)
	}
	for _, a := range res.RequiredActions {
		if strings.HasPrefix(a, "s3:PutObject") {
			t.Fatalf("store actions must stay out of the audit role's actions: %v", res.RequiredActions)
		}
	}
	var table bytes.Buffer
	if err := res.WriteTable(&table); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table.String(), "s3:PutObject") {
		t.Fatalf("table: %s", table.String())
	}
}

func TestDoctorS3StoreRecommendations(t *testing.T) {
	h := newHarness(t)
	useS3(t, h)
	res := Doctor(context.Background(), h.cfg, h.deps, 24*time.Hour)
	for _, item := range []string{"store_versioning", "store_encryption", "store_public_access"} {
		if row := doctorRow(res, item); row == nil || row.Status != DoctorWarn {
			t.Fatalf("%s: %+v", item, row)
		}
	}
}

// 推奨の確かめは読める範囲で。権限が無ければ warn にせず飛ばす。読めないのは ng。
func TestDoctorS3StoreDenied(t *testing.T) {
	h := newHarness(t)
	f := useS3(t, h)
	for _, op := range []string{"VERSIONING", "ENCRYPTION", "PUBLIC_ACCESS_BLOCK", "LIST"} {
		f.Denied[op] = true
	}
	res := Doctor(context.Background(), h.cfg, h.deps, 24*time.Hour)
	if row := doctorRow(res, "store_read"); row == nil || row.Status != DoctorNG || row.Code != "ACCESS_DENIED" {
		t.Fatalf("read: %+v", row)
	}
	if row := doctorRow(res, "store_versioning"); row == nil || row.Status != DoctorOK || !strings.Contains(row.Detail, "skip") {
		t.Fatalf("versioning: %+v", row)
	}
}

// doctor の費用の見積もりは S3 のストアの保存済みレポートも読む。dir:// は今までどおり。
func TestDoctorLastRunToReadsS3(t *testing.T) {
	h := newHarness(t)
	f := useS3(t, h)
	f.Put("acme/reports/daily.json", []byte(`{"window":{"to":"2026-10-21T09:00:00Z"}}`))
	d := &doctor{cfg: h.cfg, deps: h.deps, res: &DoctorResult{}}
	d.deps.fill(h.cfg)
	if to, ok := d.lastRunTo(context.Background(), "daily"); !ok || !to.Equal(h.now) {
		t.Fatalf("last run: %v %v", to, ok)
	}
}

// SQLite が消えて raw だけ残っているときは書き込み系を止める。続けると空の SQLite が findings・承認・ack の状態を上書きし、次からは気づけない。
func TestS3StopsWhenDatabaseIsLost(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	f := useS3(t, h)
	addRootLogin(h, "r1")
	e, err := Open(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	e.Close()
	if strings.Contains(h.stderr.String(), "rebuild --from-scratch") {
		t.Fatalf("the first run of a new store must not stop: %s", h.stderr)
	}

	f.Delete("acme/audit.sqlite.gz")
	_, err = Open(h.cfg, h.deps)
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Code != CodeStoreCorrupt || xe.Exit != ExitConfig {
		t.Fatalf("want STORE_CORRUPT, got %v", err)
	}
	if !strings.Contains(h.stderr.String(), "arata rebuild --from-scratch") {
		t.Fatalf("must point to rebuild: %s", h.stderr)
	}

	// 読むだけなら止めず、警告する
	h.stderr.Reset()
	r, err := OpenForRead(ctx, h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !strings.Contains(h.stderr.String(), "arata rebuild --from-scratch") {
		t.Fatalf("a reader must be warned: %s", h.stderr)
	}
}

// doctor はこの状態を ng で示す。
func TestDoctorS3DatabaseLost(t *testing.T) {
	h := newHarness(t)
	f := useS3(t, h)
	f.Put("acme/raw/trail/2026-10-21.jsonl", []byte("{}\n"))
	res := Doctor(context.Background(), h.cfg, h.deps, 24*time.Hour)
	row := doctorRow(res, "store_read")
	if row == nil || row.Status != DoctorNG || row.Code != CodeStoreCorrupt || !strings.Contains(row.Detail, "rebuild --from-scratch") {
		t.Fatalf("row: %+v", row)
	}
}

// S3 への問い合わせの途中の中断は、権限・通信の失敗 (STORE_UNAVAILABLE) でも破損 (STORE_CORRUPT) でもない。
func TestS3OpenInterrupted(t *testing.T) {
	h := newHarness(t)
	useS3(t, h)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := OpenContext(ctx, h.cfg, h.deps)
	var xe *ExitError
	if !errors.Is(err, context.Canceled) || errors.As(err, &xe) {
		t.Fatalf("want a plain context.Canceled, got %v", err)
	}
	if codes := h.logCodes(t); len(codes) != 0 {
		t.Fatalf("no error code here: %v", codes)
	}
}
