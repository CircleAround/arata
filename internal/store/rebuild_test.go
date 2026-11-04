package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store/storetest"
)

const (
	rbAlice = "arn:aws:iam::123456789012:user/alice"
	rbBob   = "arn:aws:iam::123456789012:user/bob"
)

var rbOrder = []string{"trail", "trail2", "gd", "nginx"}

// ingest は engine.ingest と同じ手順 (raw に追記してから SQLite へ反映)。
func ingest(t *testing.T, st *Dir, source string, rec record.Record, status string) {
	t.Helper()
	ctx := context.Background()
	if err := st.AppendRaw(ctx, source, rec); err != nil {
		t.Fatal(err)
	}
	var err error
	switch v := rec.(type) {
	case record.TrailEvent:
		err = st.InsertEvent(ctx, v)
	case record.PrincipalSeen:
		err = st.UpsertPrincipalSeen(ctx, v, status)
	case record.Metric:
		err = st.UpsertMetric(ctx, v)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// snapshot は engine の収集と同じく、項目を raw に追記してから (kind, source) を置き換える。
func snapshot(t *testing.T, st *Dir, source string, kind record.Kind, at time.Time, keys ...string) {
	t.Helper()
	var items []record.SnapshotItem
	for _, k := range keys {
		it := record.SnapshotItem{Kind: kind, Time: at, Source: source, Key: k, Data: map[string]any{"severity": 5, "type": "Recon:" + k}}
		ingest(t, st, source, it, "")
		items = append(items, it)
	}
	if err := st.ReplaceSnapshot(context.Background(), kind, source, items, at); err != nil {
		t.Fatal(err)
	}
}

func ev(id string, at, collected time.Time, source string) record.TrailEvent {
	return record.TrailEvent{EventID: id, Time: at, Source: source, Name: "ConsoleLogin", EventSource: "signin.amazonaws.com", PrincipalARN: rbAlice,
		PrincipalKind: record.PrincipalUser, IP: "203.0.113.1", Region: "us-east-1", Data: map[string]any{"mfa": true, "n": 2}, CollectedAt: collected}
}

func seen(source, arn, ip string, first, last, collected time.Time, count, rescan int) record.PrincipalSeen {
	return record.PrincipalSeen{Time: last, FirstTime: first, Source: source, ARN: arn, Kind: record.PrincipalUser, IP: ip, Count: count, RescanCount: rescan, CollectedAt: collected}
}

// buildHistory は 3 回の run に相当する記録を積む。rebuild が行順の規則を正しく再現しないと値が変わる組み合わせを入れてある。
func buildHistory(t *testing.T, st *Dir) {
	t.Helper()
	ctx := context.Background()
	c1, c2, c3 := ts, ts.Add(time.Hour), ts.Add(2*time.Hour)

	// run 1 (init 相当。主体は baseline)
	if err := st.BeginRun(ctx, Run{ID: "r1", Profile: "init", WindowFrom: c1.Add(-24 * time.Hour), WindowTo: c1, StartedAt: c1, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	ingest(t, st, "trail", ev("e1", c1.Add(-30*time.Minute), c1, "trail"), "")
	ingest(t, st, "trail", ev("e2", c1.Add(-5*time.Minute), c1, "trail"), "")
	// 同じイベントが別ソースにも見えた (同じ run): 設定で先のソース (trail) の行が残る
	ingest(t, st, "trail2", ev("e1", c1.Add(-30*time.Minute), c1, "trail2"), "")
	ingest(t, st, "trail", seen("trail", rbAlice, "203.0.113.1", c1.Add(-50*time.Minute+500*time.Millisecond), c1.Add(-5*time.Minute), c1, 2, 0), PrincipalBaseline)
	ingest(t, st, "trail2", seen("trail2", rbAlice, "203.0.113.1", c1.Add(-50*time.Minute), c1.Add(-6*time.Minute), c1, 1, 0), PrincipalBaseline)
	ingest(t, st, "nginx", record.Metric{Date: "2026-10-21", Source: "nginx", From: record.KindHTTPAccess, Metric: "admin_404", Key: "198.51.100.1", Value: 3}, "")
	snapshot(t, st, "gd", record.KindGuardDuty, c1, "g1", "g2")
	if err := st.FinishRun(ctx, "r1", "ok", map[string]any{"records": 7}); err != nil {
		t.Fatal(err)
	}

	// run 2 (再走査あり。主体は unknown)
	if err := st.BeginRun(ctx, Run{ID: "r2", Profile: "daily", WindowFrom: c1, WindowTo: c2, StartedAt: c2, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	ingest(t, st, "trail", ev("e2", c1.Add(-5*time.Minute), c2, "trail"), "") // 再走査で同じイベント: 最初の行 (collected_at = c1) が残る
	ingest(t, st, "trail", ev("e3", c2.Add(-10*time.Minute), c2, "trail"), "")
	ingest(t, st, "trail", seen("trail", rbAlice, "203.0.113.1", c1.Add(-5*time.Minute), c2.Add(-10*time.Minute), c2, 1, 2), PrincipalUnknown)
	// bob × IP は trail が先に行を作る (再走査分 1 を足す)。trail2 は後なので再走査分 5 は足さない → 1 + 2 = 3
	ingest(t, st, "trail", seen("trail", rbBob, "198.51.100.7", c1.Add(-2*time.Minute), c1.Add(-2*time.Minute), c2, 0, 1), PrincipalUnknown)
	ingest(t, st, "trail2", seen("trail2", rbBob, "198.51.100.7", c1.Add(-3*time.Minute), c2.Add(-1*time.Minute), c2, 2, 5), PrincipalUnknown)
	// 同じ日を引き直した集計は後の値で置き換える
	ingest(t, st, "nginx", record.Metric{Date: "2026-10-21", Source: "nginx", From: record.KindHTTPAccess, Metric: "admin_404", Key: "198.51.100.1", Value: 5}, "")
	ingest(t, st, "nginx", record.Metric{Date: "2026-10-21", Source: "nginx", From: record.KindHTTPAccess, Metric: "admin_404", Key: "198.51.100.2", Value: 1}, "")
	// GuardDuty の収集が途中で失敗した: 項目は raw に残るが、表は置き換えない (印も無い)
	ingest(t, st, "gd", record.SnapshotItem{Kind: record.KindGuardDuty, Time: c2, Source: "gd", Key: "g3", Data: map[string]any{"severity": 8}}, "")
	if err := st.FinishRun(ctx, "r2", "partial", nil); err != nil {
		t.Fatal(err)
	}

	// run 3: GuardDuty の finding が全部なくなった (0 件で置き換え)。設定に無いソース (iam) も raw にある
	if err := st.BeginRun(ctx, Run{ID: "r3", Profile: "weekly", WindowFrom: c2, WindowTo: c3, StartedAt: c3, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	snapshot(t, st, "gd", record.KindGuardDuty, c3)
	snapshot(t, st, "iam", record.KindCredentialReport, c3, "alice")
	if err := st.FinishRun(ctx, "r3", "ok", nil); err != nil {
		t.Fatal(err)
	}

	// raw に無いもの: 人の判断と差分判定の状態
	if err := st.SetPrincipalStatus(ctx, rbAlice, PrincipalApproved); err != nil {
		t.Fatal(err)
	}
	f := Finding{ID: "f1", Check: "new_principal", Key: rbBob, Severity: "medium", FirstSeen: c2, LastSeen: c3, LastChanged: c2, Status: FindingOpen, Data: map[string]any{"count": 3}}
	if err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := st.AddFindingEvents(ctx, []FindingEvent{{FindingID: "f1", Check: f.Check, Key: f.Key, Class: "new", Severity: "medium", At: c2, RunID: "r2", Profile: "daily"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFindingStatus(ctx, "f1", FindingSnoozed, c3.Add(24*time.Hour), c3); err != nil {
		t.Fatal(err)
	}
}

func dump(t *testing.T, dir string) map[string][]string {
	t.Helper()
	d, err := storetest.Dump(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func diffTables(t *testing.T, want, got map[string][]string, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		for k := range want {
			tables = append(tables, k)
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				tables = append(tables, k)
			}
		}
	}
	for _, tb := range tables {
		if !reflect.DeepEqual(want[tb], got[tb]) {
			t.Errorf("table %s differs:\nwant:\n  %s\ngot:\n  %s", tb, strings.Join(want[tb], "\n  "), strings.Join(got[tb], "\n  "))
		}
	}
}

func TestRebuildMatchesIncrementalStore(t *testing.T) {
	st, dir := open(t)
	buildHistory(t, st)
	before := dump(t, dir)
	// 前提: 行の順序の規則が効く値になっている
	if !strings.Contains(strings.Join(before["principal_ips"], "\n"), "arn="+rbBob+"|ip=198.51.100.7|country=|first_seen=2026-10-21T00:57:00Z|last_seen=2026-10-21T01:59:00Z|count=3") {
		t.Fatalf("scenario: %v", before["principal_ips"])
	}
	for _, l := range before["snapshot_items"] {
		if strings.HasPrefix(l, "kind=guardduty") {
			t.Fatalf("scenario: guardduty snapshot must be empty: %v", before["snapshot_items"])
		}
	}
	st.Close()

	res, err := Rebuild(context.Background(), dir, RebuildOptions{SourceOrder: rbOrder})
	if err != nil {
		t.Fatal(err)
	}
	diffTables(t, before, dump(t, dir))
	if res.Backup != filepath.Join(dir, "audit.sqlite.bak") || res.FromScratch {
		t.Fatalf("result: %+v", res)
	}
	if _, err := os.Stat(res.Backup); err != nil {
		t.Fatal(err)
	}
	want := map[record.Kind]int{record.KindTrailEvent: 5, record.KindPrincipalSeen: 5, record.KindMetric: 3, record.KindGuardDuty: 3, record.KindCredentialReport: 1, record.KindSnapshotReplaced: 3}
	if !reflect.DeepEqual(res.Records, want) || res.Malformed != 0 || len(res.UnknownKinds) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("result: %+v", res)
	}
	for _, p := range []string{"audit.sqlite.rebuild-tmp", "audit.sqlite.rebuild-tmp-journal"} {
		if _, err := os.Stat(filepath.Join(dir, p)); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed: %v", p, err)
		}
	}

	// 作り直したストアはそのまま開けて使え、もう一度 rebuild しても同じ (.bak は 1 世代で上書き)
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.BeginRun(context.Background(), Run{ID: "r4", Profile: "daily", WindowFrom: ts, WindowTo: ts, StartedAt: ts.Add(3 * time.Hour), Status: "running"}); err != nil {
		t.Fatal(err)
	}
	after := dump(t, dir)
	st2.Close()
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{SourceOrder: rbOrder}); err != nil {
		t.Fatal(err)
	}
	diffTables(t, after, dump(t, dir))
}

func TestRebuildFromScratch(t *testing.T) {
	st, dir := open(t)
	buildHistory(t, st)
	before := dump(t, dir)
	st.Close()
	// SQLite が壊れた: 既定 (引き継ぎ) は開けずに失敗し、元のファイルに触らない
	garbage := []byte("this is not a sqlite database")
	if err := os.WriteFile(filepath.Join(dir, "audit.sqlite"), garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"audit.sqlite-wal", "audit.sqlite-shm"} {
		_ = os.Remove(filepath.Join(dir, p))
	}
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{SourceOrder: rbOrder}); err == nil {
		t.Fatal("rebuild must fail when the existing database cannot be read")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "audit.sqlite")); string(b) != string(garbage) {
		t.Fatal("the existing file must be untouched")
	}

	res, err := Rebuild(context.Background(), dir, RebuildOptions{SourceOrder: rbOrder, FromScratch: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.FromScratch {
		t.Fatalf("%+v", res)
	}
	if b, _ := os.ReadFile(res.Backup); string(b) != string(garbage) {
		t.Fatal("the broken file must be kept as the backup")
	}
	got := dump(t, dir)
	diffTables(t, before, got, "events", "principal_ips", "metrics", "snapshot_items")
	// raw に無いものは空から。主体は既定で unknown (一度全部報告される)
	for _, tb := range []string{"runs", "findings", "finding_events", "meta"} {
		if len(got[tb]) != 0 {
			t.Errorf("%s must be empty: %v", tb, got[tb])
		}
	}
	if want := strings.ReplaceAll(strings.ReplaceAll(strings.Join(before["principals"], "\n"), "status=approved", "status=unknown"), "status=baseline", "status=unknown"); strings.Join(got["principals"], "\n") != want {
		t.Fatalf("principals:\n%s\nwant\n%s", strings.Join(got["principals"], "\n"), want)
	}

	// --baseline: 全主体を baseline にする (init と同じ扱い)
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{SourceOrder: rbOrder, FromScratch: true, Baseline: true}); err != nil {
		t.Fatal(err)
	}
	for _, l := range dump(t, dir)["principals"] {
		if !strings.HasSuffix(l, "status=baseline") {
			t.Fatalf("baseline: %s", l)
		}
	}
}

func TestRebuildBaselineNeedsFromScratch(t *testing.T) {
	_, dir := open(t)
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{Baseline: true}); err == nil {
		t.Fatal("--baseline without --from-scratch must be rejected")
	}
}

// 以前の版で書いた raw (principal_seen に collected_at が無い・置き換えの印が無い)、知らない種類の行、壊れた行。
func TestRebuildOldAndBrokenLines(t *testing.T) {
	dir := t.TempDir()
	write := func(source, day string, lines ...string) {
		t.Helper()
		p := filepath.Join(dir, "raw", source)
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, day+".jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ps := func(source, last string, count, rescan int) string {
		return `{"kind":"principal_seen","time":"` + last + `","data":{"time":"` + last + `","first_time":"` + last + `","source":"` + source + `","arn":"` + rbBob + `","kind":"user","ip":"198.51.100.7","count":` +
			strconv.Itoa(count) + `,"rescan_count":` + strconv.Itoa(rescan) + `}}`
	}
	gd := func(at, key string) string {
		return `{"kind":"guardduty","time":"` + at + `","data":{"kind":"guardduty","time":"` + at + `","source":"gd","key":"` + key + `","data":{"severity":5}}}`
	}
	// 時刻の順で近似: trail2 の行 (01:00) が先なので再走査分 4 を足し、trail の行 (02:00) は Count だけ → 3 + 4 + 1 = 8
	write("trail", "2026-10-21", ps("trail", "2026-10-21T02:00:00Z", 1, 9), `{"kind":"future_kind","time":"2026-10-21T02:00:00Z","data":{}}`, "", `{"kind":"principal_seen","time":"2026-10-21T0`)
	write("trail2", "2026-10-21", ps("trail2", "2026-10-21T01:00:00Z", 3, 4))
	// 印が無い: 時刻が最大の組を使う
	write("gd", "2026-10-20", gd("2026-10-20T09:00:00Z", "old"))
	write("gd", "2026-10-21", gd("2026-10-21T09:00:00Z", "new1"), gd("2026-10-21T09:00:00Z", "new2"))
	// raw/<source> の下の .jsonl 以外は読まない
	if err := os.WriteFile(filepath.Join(dir, "raw", "gd", "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Rebuild(context.Background(), dir, RebuildOptions{SourceOrder: []string{"trail", "trail2", "gd"}, FromScratch: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Malformed != 1 || res.UnknownKinds["future_kind"] != 1 || res.Backup != "" {
		t.Fatalf("result: %+v", res)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "collected_at") || !strings.Contains(joined, "snapshot_replaced") || !strings.Contains(joined, "trail/2026-10-21.jsonl:4") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	got := dump(t, dir)
	if len(got["principal_ips"]) != 1 || !strings.HasSuffix(got["principal_ips"][0], "count=8") {
		t.Fatalf("principal_ips: %v", got["principal_ips"])
	}
	if len(got["snapshot_items"]) != 2 || !strings.Contains(got["snapshot_items"][0], "key=new1") || !strings.Contains(got["snapshot_items"][1], "key=new2") {
		t.Fatalf("snapshot_items: %v", got["snapshot_items"])
	}
}

func TestRebuildLockAndMissing(t *testing.T) {
	st, dir := open(t)
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked: %v", err)
	}
	if _, err := Rebuild(context.Background(), dir, RebuildOptions{FromScratch: true}); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked (from scratch): %v", err)
	}
	st.Close()
	empty := t.TempDir()
	if _, err := Rebuild(context.Background(), empty, RebuildOptions{}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("expected ErrNoDatabase: %v", err)
	}
	if _, err := os.Stat(filepath.Join(empty, "audit.sqlite")); !os.IsNotExist(err) {
		t.Fatal("must not create a database when refusing")
	}
	if _, err := Rebuild(context.Background(), filepath.Join(empty, "nope"), RebuildOptions{FromScratch: true}); err == nil {
		t.Fatal("a missing store directory must be an error")
	}
}

// 途中で止まっても元の SQLite は変わらず、一時ファイルも残らない。
func TestRebuildCanceledKeepsOriginal(t *testing.T) {
	st, dir := open(t)
	buildHistory(t, st)
	before := dump(t, dir)
	st.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Rebuild(ctx, dir, RebuildOptions{SourceOrder: rbOrder}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled: %v", err)
	}
	diffTables(t, before, dump(t, dir))
	for _, p := range []string{"audit.sqlite.rebuild-tmp", "audit.sqlite.bak"} {
		if _, err := os.Stat(filepath.Join(dir, p)); !os.IsNotExist(err) {
			t.Fatalf("%s must not exist: %v", p, err)
		}
	}
}
