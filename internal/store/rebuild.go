package store

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/record"
)

// ErrNoDatabase は rebuild (引き継ぎ) で audit.sqlite が無いとき。--from-scratch で raw だけから作る。
var ErrNoDatabase = errors.New("store: audit.sqlite does not exist; use --from-scratch to build it from raw only")

// RebuildOptions は Rebuild の指定。
type RebuildOptions struct {
	// FromScratch は既存の SQLite を読まずに作る (壊れていても可)。raw に無いもの (runs・findings・finding_events・meta・主体の状態) は空から。
	FromScratch bool
	// Baseline は FromScratch のとき全主体を baseline (init と同じ扱い。new_principal の対象外) にする。既定は unknown。
	Baseline bool
	// SourceOrder は設定のソースの順。同じ run の中で複数のソースが同じ行に触れたとき、run と同じ順で適用する。
	// ここに無いソース (設定から外したもの) は後ろに名前順で続ける。
	SourceOrder []string
}

// RebuildResult は Rebuild の結果。
type RebuildResult struct {
	Dir         string
	FromScratch bool
	Files       int
	// Records は適用した行の数 (種類ごと)。スナップショットの項目は、表に入らなかった (後の収集で置き換えられた) ものも数える。
	Records map[record.Kind]int
	// Malformed は読めなかった行 (書き込み途中で止まった最後の行など)。UnknownKinds はこの版が知らない種類の行。どちらも飛ばす。
	Malformed    int
	UnknownKinds map[string]int
	// Warnings は近似した箇所や飛ばした行の説明。
	Warnings []string
	// Backup は作り直す前の audit.sqlite を残した場所 (1 世代。次の rebuild で上書き)。元が無ければ空。
	Backup string
}

// raw に無いので既存の SQLite から引き継ぐテーブル (列を明示する。移行で足した列の位置に依らない)。
var carriedTables = []struct{ name, cols string }{
	{"runs", `id, profile, window_from, window_to, started_at, finished_at, status, stats`},
	{"findings", `id, "check", key, severity, summary, first_seen, last_seen, last_changed, status, reported_at, snooze_until, fingerprint, data, suppressed_severity`},
	{"finding_events", `seq, finding_id, "check", key, class, severity, summary, at, run_id, profile, data`},
	{"meta", `key, value`},
}

const maxLineWarnings = 20

// Rebuild は <dir>/raw の JSONL から audit.sqlite を作り直す (ADR 0033)。
//
// 決定: raw 由来のテーブル (events・principals・principal_ips・metrics・snapshot_items) は、記録したときと同じ規則で入れ直す。
// raw に無いもの (runs・findings・finding_events・meta・principals.status) は、既定では既存の SQLite から引き継ぐ (移行を通してから読む)。
// 一時ファイルに作ってから入れ替えるので、途中で失敗しても元は変わらない。元のファイルは audit.sqlite.bak に 1 世代残す。
func Rebuild(ctx context.Context, dir string, o RebuildOptions) (*RebuildResult, error) {
	if o.Baseline && !o.FromScratch {
		return nil, errors.New("store: --baseline is only for --from-scratch (rebuild keeps the principals' status otherwise)")
	}
	if fi, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) && !o.FromScratch {
			return nil, ErrNoDatabase
		}
		return nil, fmt.Errorf("store: %w", err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("store: %s is not a directory", dir)
	}
	lock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock(lock)

	dbPath := filepath.Join(dir, dbFile)
	_, statErr := os.Stat(dbPath)
	hasDB := statErr == nil
	var old *Dir
	if !o.FromScratch {
		if !hasDB {
			return nil, ErrNoDatabase
		}
		// 古い schema なら Open と同じ移行を通す (引き継ぐ列をそろえる)
		if old, err = openDir(dir, nil); err != nil {
			return nil, err
		}
		defer func() {
			if old != nil && old.db != nil {
				old.db.Close()
			}
		}()
	}

	tmpPath := dbPath + ".rebuild-tmp"
	removeDB(tmpPath)
	ok := false
	defer func() {
		if !ok {
			removeDB(tmpPath)
		}
	}()
	// 一時ファイルは WAL にしない (閉じたら 1 ファイルにまとまり、入れ替えで -wal が取り残されない)
	db, err := openDB(tmpPath, "DELETE")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	nd := &Dir{dir: dir, db: db}
	if err := nd.migrate(); err != nil {
		return nil, err
	}
	res := &RebuildResult{Dir: dir, FromScratch: o.FromScratch, Records: map[record.Kind]int{}, UnknownKinds: map[string]int{}}
	status := PrincipalUnknown
	if o.Baseline {
		status = PrincipalBaseline
	}
	if err := replay(ctx, db, dir, o.SourceOrder, status, res); err != nil {
		return nil, err
	}
	if old != nil {
		if err := carry(ctx, db, dbPath); err != nil {
			return nil, err
		}
		if err := old.db.Close(); err != nil {
			return nil, wrap(err)
		}
		old.db = nil
	}
	if err := db.Close(); err != nil {
		return nil, wrap(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 入れ替え。元のファイルは .bak にハードリンク (無理ならコピー) してから、一時ファイルを rename で上書きする (どの時点で止まっても audit.sqlite がある)
	if hasDB {
		bak := dbPath + ".bak"
		removeDB(bak)
		if err := linkOrCopy(dbPath, bak); err != nil {
			return nil, err
		}
		// 引き継ぎでは閉じた時点で -wal は書き戻されて消えている。--from-scratch で開かなかったときは、元の -wal を .bak の側へ移す
		for _, suf := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(dbPath + suf); err == nil {
				if err := os.Rename(dbPath+suf, bak+suf); err != nil {
					return nil, fmt.Errorf("store: %w", err)
				}
			}
		}
		res.Backup = bak
	}
	if err := os.Rename(tmpPath, dbPath); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	ok = true
	syncDir(dir)
	return res, nil
}

func removeDB(path string) {
	for _, suf := range []string{"", "-journal", "-wal", "-shm"} {
		_ = os.Remove(path + suf)
	}
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("store: %w", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return fmt.Errorf("store: %w", err)
	}
	return wrap(out.Close())
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// carry は既存の SQLite から raw に無いものを引き継ぐ。主体の状態は ARN ごとに引き継ぎ、既存に無い主体は unknown のまま (次の run が allowlist と同期する)。
func carry(ctx context.Context, db *sql.DB, oldPath string) error {
	if _, err := db.ExecContext(ctx, `ATTACH DATABASE ? AS old`, oldPath); err != nil {
		return wrap(err)
	}
	defer db.ExecContext(context.Background(), `DETACH DATABASE old`)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	defer tx.Rollback()
	for _, t := range carriedTables {
		if _, err := tx.ExecContext(ctx, `INSERT INTO main.`+t.name+`(`+t.cols+`) SELECT `+t.cols+` FROM old.`+t.name); err != nil {
			return fmt.Errorf("store: carry %s: %w", t.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE main.principals SET status = (SELECT o.status FROM old.principals o WHERE o.arn = principals.arn)
		WHERE arn IN (SELECT arn FROM old.principals)`); err != nil {
		return fmt.Errorf("store: carry principals: %w", err)
	}
	return wrap(tx.Commit())
}

// replayer は raw の行を順に適用する。
//
//   - events: event_id が同じなら最初に収集した行 (collected_at が最小。同じなら設定で先のソース) を残す (InsertEvent の INSERT OR IGNORE と同じ結果)
//   - metrics: 行順に置き換える (同じソースの中でだけ衝突するので、ソースの中の日付順・行順で同じ結果)
//   - principals / principal_ips: 初出・最終観測は MIN / MAX (保存と同じ文字列の比較)。件数は Count の和に、(arn, ip) の行を最初に作った
//     記録の再走査分 (RescanCount) を足す (ADR 0013)。「最初」は (collected_at, ソースの順, 行順)。collected_at の無い以前の行は時刻順で近似する
//   - snapshot_items: (kind, source) ごとに、置き換えの印 (snapshot_replaced) が最後に付いた収集の項目。印が無い以前の raw は時刻が最大の収集で近似する
type replayer struct {
	ctx      context.Context
	tx       *sql.Tx
	res      *RebuildResult
	status   string
	srcIdx   int
	seq      int
	pairs    map[[2]string]*pairAgg
	arns     map[string]*arnAgg
	snaps    map[[2]string]*snapAgg
	noCollAt int
	lineWarn int
}

type orderKey struct {
	rank   int // 0 = collected_at の無い以前の行 (先に収集されたもの)、1 = collected_at あり
	at     string
	srcIdx int
	seq    int
}

func (a orderKey) less(b orderKey) bool {
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	if a.at != b.at {
		return a.at < b.at
	}
	if a.srcIdx != b.srcIdx {
		return a.srcIdx < b.srcIdx
	}
	return a.seq < b.seq
}

type pairAgg struct {
	first             orderKey
	firstCount        int // 最初の記録の Count + RescanCount
	firstPlain        int // 最初の記録の Count (後で別の記録が最初になったら、こちらは Count だけが残る)
	rest              int
	minFirst, maxLast string
}

type arnAgg struct {
	first             orderKey
	kind              string
	minFirst, maxLast string
}

type snapAgg struct {
	groups  map[string]map[string]record.SnapshotItem // 収集の時刻 → key → 項目
	markers map[string]int                            // 収集の時刻 → 印の件数
}

func replay(ctx context.Context, db *sql.DB, dir string, order []string, status string, res *RebuildResult) error {
	sources, err := rawSources(filepath.Join(dir, "raw"), order)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	defer tx.Rollback()
	r := &replayer{ctx: ctx, tx: tx, res: res, status: status, pairs: map[[2]string]*pairAgg{}, arns: map[string]*arnAgg{}, snaps: map[[2]string]*snapAgg{}}
	for i, src := range sources {
		r.srcIdx = i
		files, err := filepath.Glob(filepath.Join(dir, "raw", src, "*.jsonl"))
		if err != nil {
			return wrap(err)
		}
		sort.Strings(files)
		for _, f := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := r.file(src, f, filepath.Join(src, filepath.Base(f))); err != nil {
				return err
			}
			res.Files++
		}
	}
	if err := r.flush(); err != nil {
		return err
	}
	if r.noCollAt > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d principal_seen lines have no collected_at (written by an older version): principal_ips.count of a principal × IP seen by several sources is approximated by time order", r.noCollAt))
	}
	if r.lineWarn > maxLineWarnings {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d more skipped lines are not listed", r.lineWarn-maxLineWarnings))
	}
	return wrap(tx.Commit())
}

// rawSources は raw の下のソースのディレクトリを、設定の順、続けて設定に無いものを名前順で返す。raw が無ければ空。
func rawSources(rawDir string, order []string) ([]string, error) {
	ents, err := os.ReadDir(rawDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: %w", err)
	}
	present := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() {
			present[e.Name()] = true
		}
	}
	var out []string
	for _, s := range order {
		if present[s] {
			out = append(out, s)
			delete(present, s)
		}
	}
	var rest []string
	for s := range present {
		rest = append(rest, s)
	}
	sort.Strings(rest)
	return append(out, rest...), nil
}

func (r *replayer) skip(where string, lineNo int, msg string) {
	r.lineWarn++
	if r.lineWarn <= maxLineWarnings {
		r.res.Warnings = append(r.res.Warnings, fmt.Sprintf("raw/%s:%d: %s (skipped)", where, lineNo, msg))
	}
}

func (r *replayer) file(src, path, where string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for lineNo := 1; ; lineNo++ {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if aerr := r.line(src, where, lineNo, line); aerr != nil {
				return aerr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if lineNo%1000 == 0 {
			if err := r.ctx.Err(); err != nil {
				return err
			}
		}
	}
}

func (r *replayer) line(src, where string, lineNo int, line []byte) error {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil
	}
	rec, err := record.Unmarshal(line)
	if err != nil {
		if errors.Is(err, record.ErrUnknownKind) {
			var env record.Envelope
			_ = json.Unmarshal(line, &env)
			r.res.UnknownKinds[string(env.Kind)]++
			r.skip(where, lineNo, fmt.Sprintf("unknown kind %q", env.Kind))
			return nil
		}
		r.res.Malformed++
		r.skip(where, lineNo, "malformed line: "+err.Error())
		return nil
	}
	r.seq++
	r.res.Records[rec.RecordKind()]++
	switch v := rec.(type) {
	case record.TrailEvent:
		return r.event(v)
	case record.PrincipalSeen:
		r.principal(v)
	case record.Metric:
		_, err := r.tx.ExecContext(r.ctx, `INSERT INTO metrics(date, source, "from", metric, key, value) VALUES (?,?,?,?,?,?)
			ON CONFLICT(date, source, metric, key) DO UPDATE SET value=excluded.value, "from"=excluded."from"`,
			v.Date, v.Source, string(v.From), v.Metric, v.Key, v.Value)
		return wrap(err)
	case record.SnapshotItem:
		g := r.snap(v.Kind, src)
		t := fmtTime(v.Time)
		if g.groups[t] == nil {
			g.groups[t] = map[string]record.SnapshotItem{}
		}
		g.groups[t][v.Key] = v
	case record.SnapshotReplaced:
		r.snap(v.SnapshotKind, src).markers[fmtTime(v.Time)] = v.Count
	}
	return nil
}

func (r *replayer) event(e record.TrailEvent) error {
	ro := 0
	if e.ReadOnly {
		ro = 1
	}
	// 最初に収集した行を残す。'' (schema 3 より前の収集) は最も古い
	_, err := r.tx.ExecContext(r.ctx, `INSERT INTO events(event_id, time, source, name, event_source, principal_arn, principal_kind, ip, region, resource, read_only, error_code, data, collected_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(event_id) DO UPDATE SET time=excluded.time, source=excluded.source, name=excluded.name, event_source=excluded.event_source,
		  principal_arn=excluded.principal_arn, principal_kind=excluded.principal_kind, ip=excluded.ip, region=excluded.region, resource=excluded.resource,
		  read_only=excluded.read_only, error_code=excluded.error_code, data=excluded.data, collected_at=excluded.collected_at
		WHERE excluded.collected_at < events.collected_at`,
		e.EventID, fmtTime(e.Time), e.Source, e.Name, e.EventSource, e.PrincipalARN, string(e.PrincipalKind), e.IP, e.Region, e.Resource, ro, e.ErrorCode, toJSON(e.Data), fmtFixedTime(e.CollectedAt))
	return wrap(err)
}

func (r *replayer) principal(p record.PrincipalSeen) {
	k := orderKey{rank: 1, at: fmtFixedTime(p.CollectedAt), srcIdx: r.srcIdx, seq: r.seq}
	if p.CollectedAt.IsZero() {
		k.rank, k.at = 0, fmtFixedTime(p.Time)
		r.noCollAt++
	}
	first, last := fmtTime(p.FirstTime), fmtTime(p.Time)
	if p.FirstTime.IsZero() {
		first = last
	}
	a := r.arns[p.ARN]
	if a == nil {
		a = &arnAgg{first: k, kind: string(p.Kind), minFirst: first, maxLast: last}
		r.arns[p.ARN] = a
	} else {
		if k.less(a.first) {
			a.first, a.kind = k, string(p.Kind)
		}
		a.minFirst, a.maxLast = min(a.minFirst, first), max(a.maxLast, last)
	}
	if p.IP == "" {
		return
	}
	pk := [2]string{p.ARN, p.IP}
	g := r.pairs[pk]
	switch {
	case g == nil:
		r.pairs[pk] = &pairAgg{first: k, firstCount: p.Count + p.RescanCount, firstPlain: p.Count, minFirst: first, maxLast: last}
		return
	case k.less(g.first):
		// それまで最初だった記録は、後から来たものとして Count だけを数える
		g.rest += g.firstPlain
		g.first, g.firstCount, g.firstPlain = k, p.Count+p.RescanCount, p.Count
	default:
		g.rest += p.Count
	}
	g.minFirst, g.maxLast = min(g.minFirst, first), max(g.maxLast, last)
}

func (r *replayer) snap(kind record.Kind, src string) *snapAgg {
	k := [2]string{string(kind), src}
	g := r.snaps[k]
	if g == nil {
		g = &snapAgg{groups: map[string]map[string]record.SnapshotItem{}, markers: map[string]int{}}
		r.snaps[k] = g
	}
	return g
}

func (r *replayer) flush() error {
	arns := make([]string, 0, len(r.arns))
	for a := range r.arns {
		arns = append(arns, a)
	}
	sort.Strings(arns)
	for _, arn := range arns {
		a := r.arns[arn]
		if _, err := r.tx.ExecContext(r.ctx, `INSERT INTO principals(arn, kind, first_seen, last_seen, status) VALUES (?,?,?,?,?)`, arn, a.kind, a.minFirst, a.maxLast, r.status); err != nil {
			return wrap(err)
		}
	}
	for pk, g := range r.pairs {
		if _, err := r.tx.ExecContext(r.ctx, `INSERT INTO principal_ips(arn, ip, first_seen, last_seen, count) VALUES (?,?,?,?,?)`, pk[0], pk[1], g.minFirst, g.maxLast, g.firstCount+g.rest); err != nil {
			return wrap(err)
		}
	}
	keys := make([][2]string, 0, len(r.snaps))
	for k := range r.snaps {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	for _, k := range keys {
		g := r.snaps[k]
		at := ""
		if len(g.markers) > 0 {
			for t := range g.markers {
				at = max(at, t)
			}
			if n := len(g.groups[at]); n != g.markers[at] {
				r.res.Warnings = append(r.res.Warnings, fmt.Sprintf("snapshot %s of source %s at %s: the marker says %d items but raw has %d", k[0], k[1], at, g.markers[at], n))
			}
		} else {
			for t := range g.groups {
				at = max(at, t)
			}
			r.res.Warnings = append(r.res.Warnings, fmt.Sprintf("snapshot %s of source %s has no snapshot_replaced marker (written by an older version): used the latest collection at %s, which may have been a failed one; a collection that found 0 items cannot be reproduced", k[0], k[1], at))
		}
		for key, it := range g.groups[at] {
			if _, err := r.tx.ExecContext(r.ctx, `INSERT INTO snapshot_items(kind, source, key, data, collected_at) VALUES (?,?,?,?,?)`, k[0], k[1], key, toJSON(it.Data), at); err != nil {
				return wrap(err)
			}
		}
	}
	return nil
}
