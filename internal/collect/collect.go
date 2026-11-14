// Package collect は Collector インターフェースと収集エラーの分類を定義する (設計書 4-2)。
package collect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/smithy-go"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/record"
)

// Window は収集・評価の対象期間 [From, To)。
//
// 決定 (ADR 0013): イベントは記録・取り込みまで遅れるので、収集は前回の窓の末尾を遅延分だけ再走査する。
// From / To は run の窓 (次回の From は今回の To) のまま、ScanFrom (= From - ingest_delay) から引く。
type Window struct {
	From time.Time
	To   time.Time
	// ScanFrom は再走査の始まり。ゼロなら From (再走査しない)。
	// collector は [ScanFrom, To) を引く。イベント型チェックは [ScanFrom, From) のうち今回の収集で初めて保存したもの (遅れて届いたもの) も評価する。
	ScanFrom time.Time
	// CollectedAt は今回の収集の時刻 (events.collected_at)。遅れて届いたイベントの判定に使う。ゼロなら判定しない。
	CollectedAt time.Time
}

// Start は実際に引き始める時刻 (ScanFrom があればそれ、無ければ From)。
func (w Window) Start() time.Time {
	if !w.ScanFrom.IsZero() && w.ScanFrom.Before(w.From) {
		return w.ScanFrom
	}
	return w.From
}

// RecordSink は正規化レコードの受け口。store への反映は engine 側が行う。
type RecordSink interface {
	Emit(ctx context.Context, rec record.Record) error
}

// SinkFunc は関数を RecordSink にする。
type SinkFunc func(ctx context.Context, rec record.Record) error

func (f SinkFunc) Emit(ctx context.Context, rec record.Record) error { return f(ctx, rec) }

// Collector はソース 1 つ分の収集。
type Collector interface {
	ID() string
	// Yields はこの collector が出すレコード種類 (coverage と checks_skipped の判定に使う)。
	Yields() []record.Kind
	Collect(ctx context.Context, w Window, sink RecordSink) error
}

// 収集エラーの code (設計書 2-2 の固定語彙)。
const (
	CodeFormatMismatch  = codes.FormatMismatch
	CodeFormatDrift     = codes.FormatDrift
	CodeAccessDenied    = codes.AccessDenied
	CodeLogGroupMissing = codes.LogGroupMissing
	CodeQueryLimit      = codes.QueryLimit
	// 決定: クエリ / 設定の不備 (Insights の構文エラーなど) は上限とは別に QUERY_INVALID とする。
	CodeQueryInvalid = codes.QueryInvalid
	// 決定: 上記に分類できない収集エラーの code。
	CodeCollectFailed = codes.CollectFailed
)

// Error は分類済みの収集エラー。
type Error struct {
	Code   string
	Source string
	Action string // 不足した IAM action など
	Err    error
	// CoveredFrom / CoveredUntil は失敗するまでに取得できた期間 (取得済みの分はストアに残っている)。
	// LookupEvents は新しい順に返すので、取りこぼすのは CoveredFrom より古い側。ゼロ値なら何も取れていない。
	CoveredFrom  time.Time
	CoveredUntil time.Time
	// Details は標準エラーの JSON ログに添える属性 (FORMAT_MISMATCH の match_rate / expected / samples など)。
	// レポートには出さない (サンプル行はマスク済みでも個人情報を含み得るため)。
	Details map[string]any
}

func (e *Error) Error() string {
	if e.Action != "" {
		return fmt.Sprintf("%s: %s (%s): %v", e.Source, e.Code, e.Action, e.Err)
	}
	return fmt.Sprintf("%s: %s: %v", e.Source, e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Classify は SDK のエラーを固定語彙の Error に包む。既に Error ならそのまま返す。
func Classify(source, action string, err error) *Error {
	var ce *Error
	if errors.As(err, &ce) {
		return ce
	}
	code := CodeCollectFailed
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDeniedException", "AccessDenied", "UnauthorizedOperation", "UnauthorizedException", "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredToken":
			code = CodeAccessDenied
		case "ResourceNotFoundException":
			code = CodeLogGroupMissing
		case "ThrottlingException", "LimitExceededException", "ServiceQuotaExceededException":
			code = CodeQueryLimit
		case "MalformedQueryException", "InvalidParameterException", "InvalidLookupAttributesException", "InvalidTimeRangeException":
			code = CodeQueryInvalid
		}
	}
	out := &Error{Code: code, Source: source, Err: err}
	if code == CodeAccessDenied {
		out.Action = action
	}
	return out
}

// FormatStats は形式プロファイルの解釈率 (設計書 2-2)。cloudwatch-logs の collector が毎回計測する。
type FormatStats struct {
	Source   string
	Format   string
	LogGroup string
	Total    int64
	Matched  int64
	Expected float64
	// BytesScanned はこの収集で Insights がスキャンした量 (課金の目安)。
	BytesScanned float64
	// OutOfRange は問い合わせ範囲がロググループの作成前 / 保持期間外で、問い合わせずに「データなし」とした理由 (空なら問い合わせた)。
	OutOfRange string
	// Truncated は結果が行の上限 (10000) に当たった集計の名前 (件数は少なめ。run の stats に残す)。
	Truncated []string
	// Requests は request_lines 形式のリクエスト単位の集計 (ADR 0051)。それ以外の形式では nil。
	Requests *RequestStats
}

// RequestStats は request_lines 形式のソースが、行を request_id でまとめた結果 (設計書 2-2)。
type RequestStats struct {
	// Total は request_id の異なりの数。
	Total int64
	// Complete は最初の行 (ip と path を取り出す行) のある request_id の数。Complete / Total が「まとめられた割合」。
	Complete int64
	// WithStatus はステータスの取れた request_id の数。
	WithStatus int64
	// Starts は最初の行の数 (集計が数えるリクエストの数。同じ request_id の使い回しで減らない)。
	Starts int64
	// Reused は最初の行が 2 つ以上ある request_id の数 (項目が混ざる)。
	Reused int64
	// StartsUntagged は request_id の付かない最初の行の数 (リクエストにまとめられず、どの集計にも入らない)。
	StartsUntagged int64
	// Expected は expected_complete_rate。
	Expected float64
	// Users はユーザー ID の付いたリクエストの集計 (request.user_id を書いたソースだけ。ADR 0052)。
	Users *UserStats
	// Auth はログインの結果の行 (auth) の集計 (request.auth を書いたソースだけ)。
	Auth *AuthStats
}

// UserStats はユーザー ID (アプリの足した actor の行など) の付いたリクエストの集計。数はどれも「数えたリクエスト」(最初の行の数) の単位。
type UserStats struct {
	// From は request.user_id.from (app_line / debug_sql)。
	From string
	// Requests は形に合った種類と ID の付いたリクエストの数。Kinds はその種類ごとの数。
	Requests int64
	Kinds    map[string]int64
	// By はそのうち by (代わりにログインした操作) の付いた数。
	By int64
	// Invalid は行はあるが、値が形に合わず捨てたリクエストの数。
	Invalid int64
}

// AuthStats はログインの結果の行の集計。
type AuthStats struct {
	// Success は成功の数。Via は手段ごと (無ければ空の key)。
	Success int64
	Via     map[string]int64
	// Failure は失敗の数。Reasons は理由ごと (無ければ空の key)。
	Failure int64
	Reasons map[string]int64
	// Impersonate は代わりのログインを始めた数。
	Impersonate int64
	// Invalid は行はあるが、結果の値が形に合わず捨てたリクエストの数。
	Invalid int64
}

// UserRate は Users.Requests / Starts (ID の付いたリクエストの割合)。ユーザー ID を取らないソース・数えたリクエストが 0 なら ok=false。
func (s RequestStats) UserRate() (rate float64, ok bool) {
	if s.Users == nil || s.Starts <= 0 {
		return 0, false
	}
	return float64(s.Users.Requests) / float64(s.Starts), true
}

// CompleteRate は Complete / Total。Total が 0 なら ok=false。
func (s RequestStats) CompleteRate() (rate float64, ok bool) {
	if s.Total <= 0 {
		return 0, false
	}
	return float64(s.Complete) / float64(s.Total), true
}

// AddTruncated は行の上限に当たった集計の名前を足す (同じ名前は 1 回)。
func (s *FormatStats) AddTruncated(name string) {
	for _, n := range s.Truncated {
		if n == name {
			return
		}
	}
	s.Truncated = append(s.Truncated, name)
}

// Rate は matched / total。total が 0 なら ok=false (行が無く判定できない)。
func (s FormatStats) Rate() (rate float64, ok bool) {
	if s.Total <= 0 {
		return 0, false
	}
	return float64(s.Matched) / float64(s.Total), true
}

// FormatReporter は解釈率を計測する collector が満たす。Collect の後に呼ぶ (失敗時も計測できた分を返す)。
type FormatReporter interface {
	FormatStats() *FormatStats
}

// AvailabilityReporter は、収集は成功したがレコード種類が取れない状態 (GuardDuty が無効、アナライザーが無い) を返す collector が満たす。
// Collect の後に呼ぶ。engine はその種類を必要とするチェックを skip し、coverage.checks_skipped に理由を出す (スナップショットは置き換えない)。
type AvailabilityReporter interface {
	Unavailable() map[record.Kind]string
}

// PartialReporter は、一部の項目だけ取れなかった (権限不足など) collector が満たす。Collect の後に呼ぶ。
// 決定 (ADR 0015): ソースは失敗扱いにせず取れた項目で評価する。問題は coverage.sources_failed (partial) と標準エラーに出し、終了コード 3。
type PartialReporter interface {
	Problems() []*Error
}

// ProbeResult は doctor の権限検査 1 件 (action ごと)。Err が nil なら許可されている。
// Warn は「許可されているが、この項目は取れない」(収集はその項目だけ不明として続ける) ことの理由。doctor は warn の行にする。
type ProbeResult struct {
	Action string
	Detail string
	Err    error
	Warn   string
}

// Prober は doctor の権限検査を、副作用の無い読み取り API だけで行う collector が満たす。
type Prober interface {
	Probe(ctx context.Context) []ProbeResult
}

// APICode は SDK のエラーコード (smithy.APIError でなければ "")。
func APICode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}
