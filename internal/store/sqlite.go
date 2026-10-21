package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/CircleAround/arata/internal/record"
)

//go:embed schema.sql
var schemaSQL string

const schemaVersion = 4

// Dir は dir:// バックエンド。<dir>/audit.sqlite と <dir>/raw/ を持つ。
type Dir struct {
	dir  string
	db   *sql.DB
	lock *os.File
}

var _ Store = (*Dir)(nil)

// Open はディレクトリを作り、排他ロックを取り、SQLite を開いてマイグレーションを適用する。
func Open(dir string) (*Dir, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "audit.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	dsn := "file:" + filepath.Join(dir, "audit.sqlite") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		lock.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Dir{dir: dir, db: db, lock: lock}
	if err := s.migrate(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Dir) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	var n int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&n)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	switch {
	case n == 0:
		_, err = s.db.Exec(`INSERT INTO schema_version(version) VALUES (?)`, schemaVersion)
	case n < schemaVersion:
		// 追加したテーブルは schema.sql の CREATE IF NOT EXISTS で作られている。追加した列はここで足す
		if err := s.addColumn("events", "collected_at", `TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
		_, err = s.db.Exec(`UPDATE schema_version SET version=?`, schemaVersion)
	}
	return err
}

// addColumn は列が無ければ足す。
func (s *Dir) addColumn(table, column, def string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + def)
	return err
}

// Close は DB とロックを解放する。
func (s *Dir) Close() error {
	var first error
	if s.db != nil {
		first = s.db.Close()
		s.db = nil
	}
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		if err := s.lock.Close(); err != nil && first == nil {
			first = err
		}
		s.lock = nil
	}
	return first
}

// Path はストアのディレクトリ。
func (s *Dir) Path() string { return s.dir }

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// fixedTimeLayout は文字列の大小で比べる列 (events.collected_at) の書式。RFC3339Nano は末尾の 0 を落とすので大小が崩れる。
const fixedTimeLayout = "2006-01-02T15:04:05.000000000Z"

func fmtFixedTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(fixedTimeLayout)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return fmtTime(t)
}

func toJSON(m map[string]any) string {
	if m == nil {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func fromJSON(s string) map[string]any {
	m := map[string]any{}
	if s == "" {
		return m
	}
	_ = json.Unmarshal([]byte(s), &m)
	return m
}

// --- runs ---

func (s *Dir) BeginRun(ctx context.Context, r Run) error {
	// 状態遷移の履歴 (finding_events) は schema 4 以降の最初の run から記録される
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO meta(key, value) VALUES ('history_since', ?)`, fmtTime(r.StartedAt)); err != nil {
		return wrap(err)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO runs(id, profile, window_from, window_to, started_at, status, stats) VALUES (?,?,?,?,?,?,?)`,
		r.ID, r.Profile, fmtTime(r.WindowFrom), fmtTime(r.WindowTo), fmtTime(r.StartedAt), r.Status, toJSON(r.Stats))
	return wrap(err)
}

func (s *Dir) FinishRun(ctx context.Context, id, status string, stats map[string]any) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET finished_at=?, status=?, stats=? WHERE id=?`, fmtTime(time.Now()), status, toJSON(stats), id)
	return wrap(err)
}

func (s *Dir) UpdateRun(ctx context.Context, id string, windowTo time.Time, stats map[string]any) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET window_to=?, stats=?, status='running', finished_at=NULL WHERE id=?`, fmtTime(windowTo), toJSON(stats), id)
	return wrap(err)
}

func (s *Dir) LastRun(ctx context.Context, profile string, statuses []string) (*Run, error) {
	q := `SELECT id, profile, window_from, window_to, started_at, COALESCE(finished_at,''), status, stats FROM runs WHERE profile=?`
	args := []any{profile}
	if len(statuses) > 0 {
		q += ` AND status IN (` + placeholders(len(statuses)) + `)`
		for _, st := range statuses {
			args = append(args, st)
		}
	}
	q += ` ORDER BY started_at DESC LIMIT 1`
	row := s.db.QueryRowContext(ctx, q, args...)
	var r Run
	var from, to, started, finished, stats string
	if err := row.Scan(&r.ID, &r.Profile, &from, &to, &started, &finished, &r.Status, &stats); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, wrap(err)
	}
	r.WindowFrom, r.WindowTo, r.StartedAt, r.FinishedAt = parseTime(from), parseTime(to), parseTime(started), parseTime(finished)
	r.Stats = fromJSON(stats)
	return &r, nil
}

// RecentRuns は finished_at のある run を started_at の新しい順に返す。
func (s *Dir) RecentRuns(ctx context.Context, limit int) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, profile, window_from, window_to, started_at, COALESCE(finished_at,''), status, stats FROM runs
		WHERE finished_at IS NOT NULL ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		var from, to, started, finished, stats string
		if err := rows.Scan(&r.ID, &r.Profile, &from, &to, &started, &finished, &r.Status, &stats); err != nil {
			return nil, wrap(err)
		}
		r.WindowFrom, r.WindowTo, r.StartedAt, r.FinishedAt = parseTime(from), parseTime(to), parseTime(started), parseTime(finished)
		r.Stats = fromJSON(stats)
		out = append(out, r)
	}
	return out, wrap(rows.Err())
}

// --- raw ---

func (s *Dir) AppendRaw(ctx context.Context, source string, rec record.Record) error {
	line, err := record.Marshal(rec)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.dir, "raw", source)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	name := filepath.Join(dir, rec.RecordTime().UTC().Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// --- principals ---

func (s *Dir) UpsertPrincipalSeen(ctx context.Context, p record.PrincipalSeen, initialStatus string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	defer tx.Rollback()
	first, last := fmtTime(p.FirstTime), fmtTime(p.Time)
	if p.FirstTime.IsZero() {
		first = last
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO principals(arn, kind, first_seen, last_seen, status) VALUES (?,?,?,?,?)
		ON CONFLICT(arn) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen), first_seen=MIN(first_seen, excluded.first_seen)`,
		p.ARN, string(p.Kind), first, last, initialStatus)
	if err != nil {
		return wrap(err)
	}
	if p.IP != "" {
		// 再走査の区間の件数は、行を初めて作るとき (前回までに一度も数えていない) だけ足す (ADR 0013)
		_, err = tx.ExecContext(ctx, `INSERT INTO principal_ips(arn, ip, first_seen, last_seen, count) VALUES (?,?,?,?,?)
			ON CONFLICT(arn, ip) DO UPDATE SET last_seen=MAX(last_seen, excluded.last_seen), first_seen=MIN(first_seen, excluded.first_seen), count=count+?`,
			p.ARN, p.IP, first, last, p.Count+p.RescanCount, p.Count)
		if err != nil {
			return wrap(err)
		}
	}
	return wrap(tx.Commit())
}

func (s *Dir) SetPrincipalStatus(ctx context.Context, arn, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE principals SET status=? WHERE arn=?`, status, arn)
	return wrap(err)
}

func (s *Dir) Principals(ctx context.Context, f PrincipalFilter) ([]Principal, error) {
	q := `SELECT arn, kind, first_seen, last_seen, status FROM principals`
	var args []any
	if len(f.Statuses) > 0 {
		q += ` WHERE status IN (` + placeholders(len(f.Statuses)) + `)`
		for _, st := range f.Statuses {
			args = append(args, st)
		}
	}
	q += ` ORDER BY first_seen, arn`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []Principal
	for rows.Next() {
		var p Principal
		var kind, first, last string
		if err := rows.Scan(&p.ARN, &kind, &first, &last, &p.Status); err != nil {
			return nil, wrap(err)
		}
		p.Kind, p.FirstSeen, p.LastSeen = record.PrincipalKind(kind), parseTime(first), parseTime(last)
		out = append(out, p)
	}
	return out, wrap(rows.Err())
}

func (s *Dir) PrincipalIPs(ctx context.Context, arn string) ([]PrincipalIP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT arn, ip, country, first_seen, last_seen, count FROM principal_ips WHERE arn=? ORDER BY first_seen, ip`, arn)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []PrincipalIP
	for rows.Next() {
		var p PrincipalIP
		var first, last string
		if err := rows.Scan(&p.ARN, &p.IP, &p.Country, &first, &last, &p.Count); err != nil {
			return nil, wrap(err)
		}
		p.FirstSeen, p.LastSeen = parseTime(first), parseTime(last)
		out = append(out, p)
	}
	return out, wrap(rows.Err())
}

// --- events ---

func (s *Dir) InsertEvent(ctx context.Context, e record.TrailEvent) error {
	ro := 0
	if e.ReadOnly {
		ro = 1
	}
	// 再走査で同じイベントが来ても最初の行 (collected_at を含む) を残す
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO events(event_id, time, source, name, event_source, principal_arn, principal_kind, ip, region, resource, read_only, error_code, data, collected_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.EventID, fmtTime(e.Time), e.Source, e.Name, e.EventSource, e.PrincipalARN, string(e.PrincipalKind), e.IP, e.Region, e.Resource, ro, e.ErrorCode, toJSON(e.Data), fmtFixedTime(e.CollectedAt))
	return wrap(err)
}

func (s *Dir) Events(ctx context.Context, from, to time.Time, f EventFilter) ([]record.TrailEvent, error) {
	q := `SELECT event_id, time, source, name, event_source, principal_arn, principal_kind, ip, region, resource, read_only, error_code, data, collected_at FROM events WHERE `
	args := []any{fmtTime(from), fmtTime(to)}
	if !f.LateFrom.IsZero() && !f.CollectedSince.IsZero() && f.LateFrom.Before(from) {
		q += `((time >= ? AND time < ?) OR (time >= ? AND time < ? AND collected_at >= ?))`
		args = append(args, fmtTime(f.LateFrom), fmtTime(from), fmtFixedTime(f.CollectedSince))
	} else {
		q += `time >= ? AND time < ?`
	}
	if len(f.Names) > 0 || len(f.NamePrefixes) > 0 {
		var parts []string
		if len(f.Names) > 0 {
			parts = append(parts, `name IN (`+placeholders(len(f.Names))+`)`)
			for _, n := range f.Names {
				args = append(args, n)
			}
		}
		for _, p := range f.NamePrefixes {
			parts = append(parts, `name LIKE ?`)
			args = append(args, strings.ReplaceAll(strings.ReplaceAll(p, "%", `\%`), "_", `\_`)+"%")
		}
		q += ` AND (` + strings.Join(parts, " OR ") + `)`
	}
	if len(f.EventSources) > 0 {
		q += ` AND event_source IN (` + placeholders(len(f.EventSources)) + `)`
		for _, e := range f.EventSources {
			args = append(args, e)
		}
	}
	if len(f.PrincipalKinds) > 0 {
		q += ` AND principal_kind IN (` + placeholders(len(f.PrincipalKinds)) + `)`
		for _, k := range f.PrincipalKinds {
			args = append(args, string(k))
		}
	}
	if f.WriteOnly {
		q += ` AND read_only = 0`
	}
	q += ` ORDER BY time, event_id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []record.TrailEvent
	for rows.Next() {
		var e record.TrailEvent
		var ts, kind, data, collected string
		var ro int
		if err := rows.Scan(&e.EventID, &ts, &e.Source, &e.Name, &e.EventSource, &e.PrincipalARN, &kind, &e.IP, &e.Region, &e.Resource, &ro, &e.ErrorCode, &data, &collected); err != nil {
			return nil, wrap(err)
		}
		e.Time, e.PrincipalKind, e.ReadOnly, e.Data, e.CollectedAt = parseTime(ts), record.PrincipalKind(kind), ro == 1, fromJSON(data), parseTime(collected)
		out = append(out, e)
	}
	return out, wrap(rows.Err())
}

// --- metrics ---

func (s *Dir) UpsertMetric(ctx context.Context, m record.Metric) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO metrics(date, source, "from", metric, key, value) VALUES (?,?,?,?,?,?)
		ON CONFLICT(date, source, metric, key) DO UPDATE SET value=excluded.value, "from"=excluded."from"`,
		m.Date, m.Source, string(m.From), m.Metric, m.Key, m.Value)
	return wrap(err)
}

func (s *Dir) Metrics(ctx context.Context, f MetricFilter) ([]record.Metric, error) {
	q := `SELECT date, source, "from", metric, key, value FROM metrics WHERE 1=1`
	var args []any
	if f.Metric != "" {
		q += ` AND metric = ?`
		args = append(args, f.Metric)
	}
	if f.From != "" {
		q += ` AND date >= ?`
		args = append(args, f.From)
	}
	if f.To != "" {
		q += ` AND date <= ?`
		args = append(args, f.To)
	}
	if len(f.Sources) > 0 {
		q += ` AND source IN (` + placeholders(len(f.Sources)) + `)`
		for _, src := range f.Sources {
			args = append(args, src)
		}
	}
	q += ` ORDER BY date, source, key`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []record.Metric
	for rows.Next() {
		var m record.Metric
		var from string
		if err := rows.Scan(&m.Date, &m.Source, &from, &m.Metric, &m.Key, &m.Value); err != nil {
			return nil, wrap(err)
		}
		m.From = record.Kind(from)
		out = append(out, m)
	}
	return out, wrap(rows.Err())
}

// --- findings ---

func (s *Dir) UpsertFinding(ctx context.Context, f Finding) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO findings(id, "check", key, severity, summary, first_seen, last_seen, last_changed, status, reported_at, snooze_until, fingerprint, data)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT("check", key) DO UPDATE SET severity=excluded.severity, summary=excluded.summary, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
		  last_changed=excluded.last_changed, status=excluded.status, reported_at=excluded.reported_at, snooze_until=excluded.snooze_until, fingerprint=excluded.fingerprint, data=excluded.data`,
		f.ID, f.Check, f.Key, f.Severity, f.Summary, fmtTime(f.FirstSeen), fmtTime(f.LastSeen), fmtTime(f.LastChanged), f.Status, nullableTime(f.ReportedAt), nullableTime(f.SnoozeUntil), f.Fingerprint, toJSON(f.Data))
	return wrap(err)
}

func (s *Dir) MarkReported(ctx context.Context, ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	args := []any{fmtTime(at)}
	for _, id := range ids {
		args = append(args, id)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE findings SET reported_at=? WHERE id IN (`+placeholders(len(ids))+`)`, args...)
	return wrap(err)
}

func (s *Dir) Finding(ctx context.Context, id string) (*Finding, error) {
	fs, err := s.queryFindings(ctx, ` AND id = ?`, []any{id})
	if err != nil || len(fs) == 0 {
		return nil, err
	}
	return &fs[0], nil
}

func (s *Dir) SetFindingStatus(ctx context.Context, id, status string, snoozeUntil, at time.Time) error {
	if status != FindingSnoozed {
		snoozeUntil = time.Time{}
	}
	f, err := s.Finding(ctx, id)
	if err != nil {
		return err
	}
	if f == nil {
		return fmt.Errorf("store: finding %q not found", id)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET status=?, snooze_until=?, last_changed=? WHERE id=?`, status, nullableTime(snoozeUntil), fmtTime(at), id); err != nil {
		return wrap(err)
	}
	if status == FindingResolved && f.Status != FindingResolved {
		if err := addFindingEvent(ctx, tx, FindingEvent{FindingID: f.ID, Check: f.Check, Key: f.Key, Class: FindingResolved, Severity: f.Severity, Summary: f.Summary, At: at, Data: f.Data}); err != nil {
			return err
		}
	}
	return wrap(tx.Commit())
}

// --- snapshot ---

func (s *Dir) ReplaceSnapshot(ctx context.Context, kind record.Kind, source string, items []record.SnapshotItem, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM snapshot_items WHERE kind=? AND source=?`, string(kind), source); err != nil {
		return wrap(err)
	}
	for _, it := range items {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO snapshot_items(kind, source, key, data, collected_at) VALUES (?,?,?,?,?)`,
			string(kind), source, it.Key, toJSON(it.Data), fmtTime(at)); err != nil {
			return wrap(err)
		}
	}
	return wrap(tx.Commit())
}

func (s *Dir) Snapshot(ctx context.Context, kind record.Kind) ([]record.SnapshotItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, key, data, collected_at FROM snapshot_items WHERE kind=? ORDER BY source, key`, string(kind))
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []record.SnapshotItem
	for rows.Next() {
		it := record.SnapshotItem{Kind: kind}
		var data, at string
		if err := rows.Scan(&it.Source, &it.Key, &data, &at); err != nil {
			return nil, wrap(err)
		}
		it.Data, it.Time = fromJSON(data), parseTime(at)
		out = append(out, it)
	}
	return out, wrap(rows.Err())
}

// --- finding_events / 期間集計 ---

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func addFindingEvent(ctx context.Context, db execer, e FindingEvent) error {
	_, err := db.ExecContext(ctx, `INSERT INTO finding_events(finding_id, "check", key, class, severity, summary, at, run_id, profile, data) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.FindingID, e.Check, e.Key, e.Class, e.Severity, e.Summary, fmtTime(e.At), e.RunID, e.Profile, toJSON(e.Data))
	return wrap(err)
}

func (s *Dir) AddFindingEvents(ctx context.Context, evs []FindingEvent) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap(err)
	}
	defer tx.Rollback()
	for _, e := range evs {
		if err := addFindingEvent(ctx, tx, e); err != nil {
			return err
		}
	}
	return wrap(tx.Commit())
}

func (s *Dir) FindingEvents(ctx context.Context, from, to time.Time) ([]FindingEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT finding_id, "check", key, class, severity, summary, at, run_id, profile, data FROM finding_events
		WHERE at >= ? AND at < ? ORDER BY at, seq`, fmtTime(from), fmtTime(to))
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []FindingEvent
	for rows.Next() {
		var e FindingEvent
		var at, data string
		if err := rows.Scan(&e.FindingID, &e.Check, &e.Key, &e.Class, &e.Severity, &e.Summary, &at, &e.RunID, &e.Profile, &data); err != nil {
			return nil, wrap(err)
		}
		e.At, e.Data = parseTime(at), fromJSON(data)
		out = append(out, e)
	}
	return out, wrap(rows.Err())
}

func (s *Dir) Runs(ctx context.Context, from, to time.Time) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, profile, window_from, window_to, started_at, COALESCE(finished_at,''), status, stats FROM runs
		WHERE started_at >= ? AND started_at < ? ORDER BY started_at, id`, fmtTime(from), fmtTime(to))
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		var wf, wt, started, finished, stats string
		if err := rows.Scan(&r.ID, &r.Profile, &wf, &wt, &started, &finished, &r.Status, &stats); err != nil {
			return nil, wrap(err)
		}
		r.WindowFrom, r.WindowTo, r.StartedAt, r.FinishedAt = parseTime(wf), parseTime(wt), parseTime(started), parseTime(finished)
		r.Stats = fromJSON(stats)
		out = append(out, r)
	}
	return out, wrap(rows.Err())
}

func (s *Dir) HistorySince(ctx context.Context) (time.Time, error) {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='history_since'`).Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, wrap(err)
	}
	return parseTime(v), nil
}

func (s *Dir) Findings(ctx context.Context, check string, statuses []string) ([]Finding, error) {
	var where string
	var args []any
	if check != "" {
		where += ` AND "check" = ?`
		args = append(args, check)
	}
	if len(statuses) > 0 {
		where += ` AND status IN (` + placeholders(len(statuses)) + `)`
		for _, st := range statuses {
			args = append(args, st)
		}
	}
	return s.queryFindings(ctx, where, args)
}

func (s *Dir) queryFindings(ctx context.Context, where string, args []any) ([]Finding, error) {
	q := `SELECT id, "check", key, severity, summary, first_seen, last_seen, last_changed, status, COALESCE(reported_at,''), COALESCE(snooze_until,''), fingerprint, data FROM findings WHERE 1=1` + where + ` ORDER BY "check", key`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var first, last, changed, reported, snooze, data string
		if err := rows.Scan(&f.ID, &f.Check, &f.Key, &f.Severity, &f.Summary, &first, &last, &changed, &f.Status, &reported, &snooze, &f.Fingerprint, &data); err != nil {
			return nil, wrap(err)
		}
		f.FirstSeen, f.LastSeen, f.LastChanged, f.ReportedAt, f.SnoozeUntil = parseTime(first), parseTime(last), parseTime(changed), parseTime(reported), parseTime(snooze)
		f.Data = fromJSON(data)
		out = append(out, f)
	}
	return out, wrap(rows.Err())
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("store: %w", err)
}
