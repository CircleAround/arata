// Package store は JSONL 原本 + SQLite 派生の二層ストア (設計書 5 章)。
// Query は読み取り (チェックに渡す)、Store は読み書き全体。
package store

import (
	"context"
	"errors"
	"time"

	"github.com/CircleAround/arata/internal/record"
)

// ErrLocked は別プロセスがストアを掴んでいるときに Open が返す (code: STORE_LOCKED)。
var ErrLocked = errors.New("store: locked by another process")

// Run は runs テーブルの 1 行。
type Run struct {
	ID         string
	Profile    string
	WindowFrom time.Time
	WindowTo   time.Time
	StartedAt  time.Time
	FinishedAt time.Time // ゼロ値 = 未完了
	Status     string    // running / ok / partial / failed
	Stats      map[string]any
}

// 主体の状態 (principals.status)。
const (
	PrincipalUnknown  = "unknown"  // 未承認
	PrincipalApproved = "approved" // allowlist にある
	PrincipalExpired  = "expired"  // allowlist の expires を過ぎた
	PrincipalBaseline = "baseline" // init のベースライン収集で初出 (new_principal の対象外)
)

// Principal は principals テーブルの 1 行。
type Principal struct {
	ARN       string
	Kind      record.PrincipalKind
	FirstSeen time.Time
	LastSeen  time.Time
	Status    string
}

// PrincipalIP は principal_ips テーブルの 1 行。
type PrincipalIP struct {
	ARN       string
	IP        string
	Country   string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int
}

// finding の状態 (findings.status)。
const (
	FindingOpen     = "open"
	FindingResolved = "resolved"
	FindingAcked    = "acked"
	FindingSnoozed  = "snoozed"
)

// Finding は findings テーブルの 1 行。
type Finding struct {
	ID          string
	Check       string
	Key         string
	Severity    string
	Summary     string
	FirstSeen   time.Time
	LastSeen    time.Time
	LastChanged time.Time
	Status      string
	ReportedAt  time.Time // ゼロ値 = 未報告
	SnoozeUntil time.Time // snoozed のときの期日
	Fingerprint string
	Data        map[string]any
}

// FindingEvent は finding の状態遷移 1 件 (finding_events)。Severity / Summary / Data はその時点の値。
type FindingEvent struct {
	FindingID string
	Check     string
	Key       string
	Class     string // new / changed / recurred / resolved
	Severity  string
	Summary   string
	At        time.Time
	RunID     string // 人の操作 (resolve / approve) なら空
	Profile   string
	Data      map[string]any
}

// EventFilter は Events の絞り込み。空のフィールドは条件に含めない。
type EventFilter struct {
	Names          []string
	NamePrefixes   []string
	EventSources   []string
	PrincipalKinds []record.PrincipalKind
	WriteOnly      bool // read_only=false のみ
	// ErrorCodes は error_code がこの集合に入るもの (完全一致)。拒否された呼び出し (access_denied) に使う。
	ErrorCodes []string
	// LateFrom と CollectedSince が両方あれば、[LateFrom, from) のうち collected_at >= CollectedSince のもの
	// (再走査で遅れて届いたイベント。ADR 0013) も返す。
	LateFrom       time.Time
	CollectedSince time.Time
}

// PrincipalFilter は Principals の絞り込み。
type PrincipalFilter struct {
	Statuses []string
}

// MetricFilter は Metrics の絞り込み。日付は YYYY-MM-DD (UTC) で、From / To とも含む。空なら条件に含めない。
type MetricFilter struct {
	Metric  string
	From    string
	To      string
	Sources []string
}

// Query は読み取り側。チェックの Evaluate にはこれだけを渡す。
type Query interface {
	Events(ctx context.Context, from, to time.Time, f EventFilter) ([]record.TrailEvent, error)
	Principals(ctx context.Context, f PrincipalFilter) ([]Principal, error)
	PrincipalIPs(ctx context.Context, arn string) ([]PrincipalIP, error)
	// LastRun は profile の直近の run。statuses が空でなければその状態のものに絞る。
	LastRun(ctx context.Context, profile string, statuses []string) (*Run, error)
	Findings(ctx context.Context, check string, statuses []string) ([]Finding, error)
	// Metrics は日次集計を (date, source, key) の順で返す。
	Metrics(ctx context.Context, f MetricFilter) ([]record.Metric, error)
	// Snapshot は kind の最新のスナップショット (全 source、source → key の順)。一度も取れていなければ空。
	Snapshot(ctx context.Context, kind record.Kind) ([]record.SnapshotItem, error)
	// FindingEvents は [from, to) の状態遷移を時刻順に返す。
	FindingEvents(ctx context.Context, from, to time.Time) ([]FindingEvent, error)
	// Runs は started_at が [from, to) の run を時刻順に返す (init を含む)。
	Runs(ctx context.Context, from, to time.Time) ([]Run, error)
	// HistorySince は状態遷移の履歴を記録し始めた時刻 (schema 4 以降の最初の run の開始時刻)。まだ run が無ければゼロ。
	HistorySince(ctx context.Context) (time.Time, error)
}

// Store は読み書き全体。dir バックエンド (SQLite + JSONL) が実装する。S3 バックエンドは後続 Step。
type Store interface {
	Query
	BeginRun(ctx context.Context, r Run) error
	FinishRun(ctx context.Context, id, status string, stats map[string]any) error
	// UpdateRun は実行中の run の窓の終わりと stats を更新する (init の進捗)。status は running に戻す。
	UpdateRun(ctx context.Context, id string, windowTo time.Time, stats map[string]any) error
	// AppendRaw は raw/<source>/<YYYY-MM-DD>.jsonl に追記する。
	AppendRaw(ctx context.Context, source string, rec record.Record) error
	// UpsertPrincipalSeen は principals / principal_ips を更新する。initialStatus は新規挿入時のみ使う。
	UpsertPrincipalSeen(ctx context.Context, p record.PrincipalSeen, initialStatus string) error
	SetPrincipalStatus(ctx context.Context, arn, status string) error
	// InsertEvent は event_id が既にあれば何もしない (再収集で重複しない)。
	InsertEvent(ctx context.Context, e record.TrailEvent) error
	// UpsertMetric は (date, source, metric, key) が同じ行を置き換える。
	UpsertMetric(ctx context.Context, m record.Metric) error
	// RecentRuns は完了した run を新しい順に最大 limit 件返す (FORMAT_DRIFT の判定に使う)。
	RecentRuns(ctx context.Context, limit int) ([]Run, error)
	UpsertFinding(ctx context.Context, f Finding) error
	// Finding は ID で 1 件引く。無ければ nil。
	Finding(ctx context.Context, id string) (*Finding, error)
	// SetFindingStatus は人の判断 (approve / ack / snooze / resolve) で状態を変える。snoozeUntil は snoozed のときだけ使う。
	// resolved にしたときは finding_events にも resolved を記録する (run_id 空)。
	SetFindingStatus(ctx context.Context, id, status string, snoozeUntil, at time.Time) error
	MarkReported(ctx context.Context, ids []string, at time.Time) error
	// ReplaceSnapshot は (kind, source) のスナップショットを items で丸ごと置き換える (空なら空にする)。
	ReplaceSnapshot(ctx context.Context, kind record.Kind, source string, items []record.SnapshotItem, at time.Time) error
	// AddFindingEvents は状態遷移を追記する。
	AddFindingEvents(ctx context.Context, evs []FindingEvent) error
	Close() error
}
