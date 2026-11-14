// Package engine は collect → evaluate → report の流れを束ねる (設計書 4 章)。
// CLI (cmd/arata) と後続の Lambda ハンドラの両方がこれを呼ぶ。
//
// 決定: 設計書 4-1 のパッケージ一覧に無いが、cmd と cmd/arata-lambda で同じ流れを共有するため internal/engine に置く。
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	acc "github.com/aws/aws-sdk-go-v2/service/account"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

// エンジン自身のログの code (設計書 2-2)。収集側の語彙は collect パッケージにある。
const (
	CodeStoreLocked  = codes.StoreLocked
	CodeStoreCorrupt = codes.StoreCorrupt
	// CodeStoreConflict は s3:// のストアを別の実行が先に書いた (何も上書きしていない。もう一度実行する)。
	CodeStoreConflict = codes.StoreConflict
	// CodeStoreUnavailable は s3:// のストアに問い合わせられない (権限・通信)。破損ではないので rebuild はしない。
	CodeStoreUnavailable = codes.StoreUnavailable
	// CodeInterrupted は SIGINT / SIGTERM で止まった (設定の誤りではない。もう一度実行する)。
	CodeInterrupted   = codes.Interrupted
	CodeRunMissed     = codes.RunMissed
	CodeConfigInvalid = codes.ConfigInvalid
	// CodeCheckUnused はどのプロファイルにも入っていないチェックがある (警告。設定の雛形と照らして入れ忘れを疑う)。
	CodeCheckUnused = codes.CheckUnused
	// CodeReportNotFound は report で再表示するレポートが無い (そのプロファイルの run がまだ無い)。
	CodeReportNotFound = codes.ReportNotFound
)

// Codes は arata の標準エラーの JSON 行ログに現れ得る code (一覧は internal/codes。ADR 0054)。
var Codes = codes.Names(codes.Arata)

// 終了コード (設計書 8 章)。
const (
	ExitOK      = 0
	ExitConfig  = 2 // 設定 / 権限エラー
	ExitPartial = 3 // 収集の一部失敗 (レポートは出す)
)

// ExitError は終了コードと code を持つエラー。
type ExitError struct {
	Code string
	Exit int
	Err  error
}

func (e *ExitError) Error() string { return fmt.Sprintf("%s: %v", e.Code, e.Err) }
func (e *ExitError) Unwrap() error { return e.Err }

// Deps は差し替え可能な依存。テストではフェイクと固定時計を注入する。
type Deps struct {
	Now   func() time.Time
	NewID func() string
	// CloudTrail はソースとリージョンごとのクライアントを作る。
	CloudTrail func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cloudtrail.API, error)
	// CloudWatchLogs は cloudwatch-logs ソースのクライアントを作る。
	CloudWatchLogs func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cwlogs.API, error)
	// Account はアカウント単位のソース (iam-credential-report / guardduty / access-analyzer / posture) のクライアントの束を作る。
	Account func(ctx context.Context, cfg *config.Config, src config.Source, region string) (account.Clients, error)
	// S3Store は s3:// のストアのクライアントを作る。監査対象の認証 (aws:) とは別に store_profile / store_region を使う。
	S3Store func(ctx context.Context, cfg *config.Config) (store.S3API, error)
	// Sleep は Insights のポーリングと、スロットル時の再試行の待ち。nil なら実時間で待つ。テストでは即時に返す関数を渡す。
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
	// Registry はチェック名と周期の一覧 (default-* の展開と CHECK_UNUSED)。評価はプロファイルの overrides を重ねて組み直す (Engine.registry)。
	Registry *checks.Registry
	// User は approve の approved_by の既定。Git は approve --commit の git 実行。
	User func() string
	Git  func(ctx context.Context, dir string, args ...string) ([]byte, error)
	// Limiter は LookupEvents のレート制限。nil なら既定 (2 req/s)。同じアカウントの上限なので全ソースで 1 つ共有する。
	Limiter cloudtrail.Limiter
}

// DefaultDeps は実 AWS SDK を使う依存。
func DefaultDeps(logger *slog.Logger) Deps {
	return Deps{
		Now:            time.Now,
		NewID:          RandomID,
		CloudTrail:     NewCloudTrailClient,
		CloudWatchLogs: NewCloudWatchLogsClient,
		Account:        NewAccountClients,
		S3Store:        NewS3StoreClient,
		Logger:         logger,
	}
}

// RandomID は 12 桁の 16 進 ID を返す。
func RandomID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CloudTrailMaxAttempts は LookupEvents の最大試行回数 (SDK 既定の 3 ではスロットルに足りない)。
const CloudTrailMaxAttempts = 10

// NewCloudTrailRetryer は adaptive モード (スロットルに応じて送信側で間引く) で最大 10 回まで試行するリトライを返す。
// ThrottlingException は SDK 既定のスロットル判定 (retry.DefaultThrottleErrorCodes) に含まれる。
func NewCloudTrailRetryer() aws.Retryer {
	return retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
		o.StandardOptions = append(o.StandardOptions, func(so *retry.StandardOptions) {
			so.MaxAttempts = CloudTrailMaxAttempts
		})
	})
}

// NewCloudTrailClient は SDK の標準認証チェーンで CloudTrail クライアントを作る。
func NewCloudTrailClient(ctx context.Context, cfg *config.Config, _ config.Source, region string) (cloudtrail.API, error) {
	ac, err := loadAWSConfig(ctx, cfg, region, awsconfig.WithRetryer(NewCloudTrailRetryer))
	if err != nil {
		return nil, err
	}
	return ct.NewFromConfig(ac), nil
}

// NewCloudWatchLogsClient は SDK の標準認証チェーンで CloudWatch Logs クライアントを作る。
func NewCloudWatchLogsClient(ctx context.Context, cfg *config.Config, _ config.Source, region string) (cwlogs.API, error) {
	ac, err := loadAWSConfig(ctx, cfg, region)
	if err != nil {
		return nil, err
	}
	return cwl.NewFromConfig(ac), nil
}

// NewAccountClients は SDK の標準認証チェーンでアカウント単位のソースのクライアントを作る。
func NewAccountClients(ctx context.Context, cfg *config.Config, _ config.Source, region string) (account.Clients, error) {
	ac, err := loadAWSConfig(ctx, cfg, region)
	if err != nil {
		return account.Clients{}, err
	}
	return account.Clients{Region: region, IAM: iam.NewFromConfig(ac), GuardDuty: guardduty.NewFromConfig(ac), AccessAnalyzer: accessanalyzer.NewFromConfig(ac),
		CloudTrail: ct.NewFromConfig(ac), S3Control: s3control.NewFromConfig(ac), STS: sts.NewFromConfig(ac), WAFV2: wafv2.NewFromConfig(ac),
		ELBV2: elbv2.NewFromConfig(ac), Account: acc.NewFromConfig(ac), CostExplorer: costexplorer.NewFromConfig(ac)}, nil
}

// NewS3StoreClient はストアのバケットのクライアントを作る。store_profile を省略すると SDK の標準の連鎖 (aws.profile は使わない)。
func NewS3StoreClient(ctx context.Context, cfg *config.Config) (store.S3API, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(cfg.StoreRegion)}
	if cfg.StoreProfile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.StoreProfile))
	}
	ac, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(ac, func(o *s3.Options) { o.DisableLogOutputChecksumValidationSkipped = true }), nil
}

func loadAWSConfig(ctx context.Context, cfg *config.Config, region string, extra ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
	opts := append([]func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}, extra...)
	if cfg.AWS.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.AWS.Profile))
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

// Engine は 1 つの設定 + ストアに対する処理。
type Engine struct {
	cfg  *config.Config
	deps Deps
	st   store.Store
	al   *allowlist.List
	log  *slog.Logger
	// runID / runProfile は実行中の run (finding_events に残す)。
	runID, runProfile string
	// scratch はストアの複製を開いている (試しの実行。ADR 0049)。書き込みは複製に対してだけで、Close で捨てる。
	scratch bool
	// diffFrom は差分判定 (再発と「報告済み」) の境界。ゼロなら窓の始まり。試しの実行が定時の実行の境界に合わせるのに使う。
	diffFrom time.Time
}

func (d *Deps) fill(cfg *config.Config) {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.NewID == nil {
		d.NewID = RandomID
	}
	if d.CloudTrail == nil {
		d.CloudTrail = NewCloudTrailClient
	}
	if d.CloudWatchLogs == nil {
		d.CloudWatchLogs = NewCloudWatchLogsClient
	}
	if d.Account == nil {
		d.Account = NewAccountClients
	}
	if d.S3Store == nil {
		d.S3Store = NewS3StoreClient
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if d.Registry == nil {
		d.Registry = checks.NewRegistryFor(cfg.Checks)
		d.Registry.SetAuditLogGroups(cfg.AuditLogGroups())
		d.Registry.SetUnusedRegionSources(cfg.UnusedRegionSources())
	}
	if d.Limiter == nil {
		d.Limiter = cloudtrail.NewLimiter()
	}
	if d.User == nil {
		d.User = OSUser
	}
	if d.Git == nil {
		d.Git = RunGit
	}
}

// Open は OpenContext の中断しない版。
func Open(cfg *config.Config, deps Deps) (*Engine, error) {
	return OpenContext(context.Background(), cfg, deps)
}

// OpenContext はストアを開き allowlist を読む。ロック失敗は STORE_LOCKED、S3 に問い合わせられないときは STORE_UNAVAILABLE (exit 2)。
//
// 決定: S3 に raw があるのに SQLite が無ければ STORE_CORRUPT で止める (ADR 0034)。続けると空の SQLite を Commit して findings・承認・ack の状態を
// 空で上書きし、次からは気づけない。止まれば aratam が「実行されていない」と知らせる。読むだけなら OpenForRead。
func OpenContext(ctx context.Context, cfg *config.Config, deps Deps) (*Engine, error) {
	return open(ctx, cfg, deps, openWrite)
}

// OpenForRead は Commit しないコマンド (report / review) 用。S3 に SQLite が無く raw があっても止めず、警告する。
func OpenForRead(ctx context.Context, cfg *config.Config, deps Deps) (*Engine, error) {
	return open(ctx, cfg, deps, openRead)
}

// OpenDryRun は試しの実行 (`arata run --dry-run`) 用。ストアを一時ディレクトリへ複製して開き、元のストアには何も書かない (ADR 0049)。
// 返したエンジンは RunWithOptions の DryRun だけを受ける。Commit は何もしない。
//
// 決定: dir:// は複製する間だけロックを取る (書き込み中の実行がいれば STORE_LOCKED。途中の状態を読まない)。複製の後は放すので、
// 試しの収集の間も定時の実行は動ける。s3:// はロックが無く、SQLite を 1 回取得するだけで整合した状態を読める。
// S3 に SQLite が無く raw があるときは OpenForRead と同じく警告して空の状態で進む (何も書かないので上書きの心配が無い)。
func OpenDryRun(ctx context.Context, cfg *config.Config, deps Deps) (*Engine, error) {
	return open(ctx, cfg, deps, openScratch)
}

// openMode はストアの開き方。
type openMode int

const (
	openWrite   openMode = iota // 書き込み系のコマンド
	openRead                    // Commit しないコマンド (report / review)
	openScratch                 // 試しの実行 (複製)
)

func open(ctx context.Context, cfg *config.Config, deps Deps, mode openMode) (*Engine, error) {
	deps.fill(cfg)
	readOnly := mode != openWrite
	st, err := openStore(ctx, cfg, deps, mode == openScratch)
	if err != nil {
		// 中断はここでは分類しない (CLI が INTERRUPTED にする)
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		if errors.Is(err, store.ErrLocked) {
			deps.Logger.Error("store is locked by another process", "code", CodeStoreLocked, "dir", cfg.Store.String())
			return nil, &ExitError{Code: CodeStoreLocked, Exit: ExitConfig, Err: err}
		}
		if isStoreUnavailable(err) {
			return nil, storeUnavailable(deps, cfg, err)
		}
		deps.Logger.Error("failed to open store", "code", CodeStoreCorrupt, "dir", cfg.Store.String(), "error", err.Error())
		return nil, &ExitError{Code: CodeStoreCorrupt, Exit: ExitConfig, Err: err}
	}
	if s, ok := st.(*store.S3); ok && s.RawWithoutDatabase() {
		attrs := []any{"code", CodeStoreCorrupt, "store", cfg.Store.String(), "action", lostDatabaseAction}
		if !readOnly {
			st.Close()
			deps.Logger.Error("the S3 store has raw files but no database; stopped so that the findings and approvals are not overwritten with an empty database", attrs...)
			return nil, &ExitError{Code: CodeStoreCorrupt, Exit: ExitConfig, Err: errLostDatabase}
		}
		deps.Logger.Warn("the S3 store has raw files but no database; showing an empty database", attrs...)
	}
	al, err := allowlist.Load(cfg.Allowlist)
	if err != nil {
		st.Close()
		deps.Logger.Error("invalid allowlist", "code", CodeConfigInvalid, "path", cfg.Allowlist, "error", err.Error())
		return nil, &ExitError{Code: CodeConfigInvalid, Exit: ExitConfig, Err: err}
	}
	return &Engine{cfg: cfg, deps: deps, st: st, al: al, log: deps.Logger, scratch: mode == openScratch}, nil
}

const lostDatabaseAction = "arata rebuild --from-scratch builds it from raw, or restore the previous version if the bucket has versioning"

var errLostDatabase = errors.New("the S3 store has raw files but no database")

func openStore(ctx context.Context, cfg *config.Config, deps Deps, scratch bool) (store.Store, error) {
	if cfg.Store.Scheme != "s3" {
		if scratch {
			return store.OpenScratch(cfg.Store.Dir)
		}
		return store.Open(cfg.Store.Dir)
	}
	api, err := deps.S3Store(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", store.ErrS3Unavailable, err)
	}
	if scratch {
		return store.OpenS3Scratch(ctx, api, s3Location(cfg))
	}
	return store.OpenS3(ctx, api, s3Location(cfg))
}

func s3Location(cfg *config.Config) store.S3Location {
	return store.S3Location{Bucket: cfg.Store.Bucket, Prefix: cfg.Store.Prefix}
}

// isStoreUnavailable は S3 に問い合わせられなかった (期限切れを含む) か。破損と区別する。中断 (context.Canceled) は含めない。
func isStoreUnavailable(err error) bool {
	return errors.Is(err, store.ErrS3Unavailable) || errors.Is(err, context.DeadlineExceeded)
}

func storeUnavailable(deps Deps, cfg *config.Config, err error) error {
	deps.Logger.Error("cannot reach the S3 store", "code", CodeStoreUnavailable, "store", cfg.Store.String(), "error", err.Error())
	return &ExitError{Code: CodeStoreUnavailable, Exit: ExitConfig, Err: err}
}

// Rebuild は raw JSONL から audit.sqlite を作り直す (ADR 0033)。ソースの順は設定に従う。
// ロック失敗は STORE_LOCKED、既存の SQLite が無い・読めないときは STORE_CORRUPT (exit 2。--from-scratch を案内する)。
// s3:// では別の実行が先に書いたら STORE_CONFLICT、問い合わせられなければ STORE_UNAVAILABLE。
func Rebuild(ctx context.Context, cfg *config.Config, deps Deps, o store.RebuildOptions) (*store.RebuildResult, error) {
	deps.fill(cfg)
	o.SourceOrder = nil
	for _, src := range cfg.Sources {
		o.SourceOrder = append(o.SourceOrder, src.ID)
	}
	res, err := rebuildStore(ctx, cfg, deps, o)
	if err == nil {
		return res, nil
	}
	dir := cfg.Store.String()
	switch {
	case errors.Is(err, store.ErrLocked):
		deps.Logger.Error("store is locked by another process", "code", CodeStoreLocked, "dir", dir)
		return nil, &ExitError{Code: CodeStoreLocked, Exit: ExitConfig, Err: err}
	case errors.Is(err, store.ErrConflict):
		return nil, storeConflict(deps, cfg, err)
	case errors.Is(err, store.ErrS3Unavailable):
		return nil, storeUnavailable(deps, cfg, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		deps.Logger.Error("rebuild interrupted; the store is unchanged", "code", CodeInterrupted, "dir", dir, "error", err.Error())
		return nil, err
	case errors.Is(err, store.ErrNoDatabase) || !o.FromScratch:
		deps.Logger.Error("cannot read the existing database to carry over runs, findings and principal status", "code", CodeStoreCorrupt, "dir", dir, "error", err.Error(),
			"action", "arata rebuild --from-scratch builds it from raw only (findings start empty; every open finding is reported again as new on the next run)")
		return nil, &ExitError{Code: CodeStoreCorrupt, Exit: ExitConfig, Err: err}
	}
	deps.Logger.Error("rebuild failed; the store is unchanged", "code", CodeStoreCorrupt, "dir", dir, "error", err.Error())
	return nil, &ExitError{Code: CodeStoreCorrupt, Exit: ExitConfig, Err: err}
}

func rebuildStore(ctx context.Context, cfg *config.Config, deps Deps, o store.RebuildOptions) (*store.RebuildResult, error) {
	if cfg.Store.Scheme == "s3" {
		api, err := deps.S3Store(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", store.ErrS3Unavailable, err)
		}
		return store.RebuildS3(ctx, api, s3Location(cfg), o)
	}
	if o.FromScratch {
		if err := os.MkdirAll(cfg.Store.Dir, 0o750); err != nil {
			return nil, err
		}
	}
	return store.Rebuild(ctx, cfg.Store.Dir, o)
}

func storeConflict(deps Deps, cfg *config.Config, err error) error {
	deps.Logger.Error("another run updated the store first; this run's results were not saved and nothing was overwritten", "code", CodeStoreConflict, "store", cfg.Store.String(),
		"error", err.Error(), "action", "run the same command again")
	return &ExitError{Code: CodeStoreConflict, Exit: ExitConfig, Err: err}
}

// Commit は書き込みを確定する (ADR 0034)。書き込み系のコマンドが成功したときだけ呼ぶ。dir:// では何もしない。
// s3:// では以後ストアを読み書きできないので、最後に呼ぶ (Close は別に要る)。別の実行が先に書いていたら STORE_CONFLICT。
func (e *Engine) Commit(ctx context.Context) error {
	err := e.st.Commit(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrConflict):
		return storeConflict(e.deps, e.cfg, err)
	case isStoreUnavailable(err):
		return storeUnavailable(e.deps, e.cfg, err)
	}
	return err
}

// Close はストアを閉じる。Commit していない s3:// の書き込みは捨てる。
func (e *Engine) Close() error { return e.st.Close() }

// Store は下層のストア (review など後続コマンド用)。
func (e *Engine) Store() store.Store { return e.st }

// CollectResult は収集の結果。
type CollectResult struct {
	SourcesOK     []string
	SourcesFailed []string
	Errors        []report.CollectError
	Records       int
	// DeniedEvents は拒否された呼び出し (access_denied の error_codes) として出した trail_event の数 (run の stats の目安。重複排除の前)。
	DeniedEvents int
	// SecretReadEvents は秘匿値の読み取り (secret_access が見る操作。成否・復号の有無を問わない) として出した trail_event の数
	// (保存量の目安。GetParameter はアプリの起動ごとに呼ばれて多い。重複排除の前。ADR 0027)。
	SecretReadEvents int
	// UnusedRegionEvents はふだん使わないリージョン (cloudtrail-unused-regions) の書き込みとして出した trail_event の数、
	// UnusedRegionsScanned はそのソースが引いたリージョン (ADR 0032。run の stats に残す)。
	UnusedRegionEvents   int
	UnusedRegionsScanned []string
	// Formats は cloudwatch-logs ソースの解釈率 (失敗したソースも計測できた分は入る)。
	Formats []report.FormatCoverage
	// yielded はソースごとに出せるレコード種類 (チェックの skip 判定に使う)
	yielded map[string][]record.Kind
	// attempted は収集を試みたソース (プロファイルが必要としないソースは試みない)
	attempted map[string]bool
	// unavailable は収集は成功したが取れないレコード種類と理由 (GuardDuty 無効など)。
	unavailable map[record.Kind]string
	// partialItems は一部の項目が取れなかったソースがある (posture の権限不足など。終了コード 3)。
	partialItems bool
	// outOfRange は範囲がロググループの作成前 / 保持期間外で問い合わせなかったソースと理由 (データなしとして成功扱い)。
	outOfRange map[string]string
}

func (r CollectResult) partial() bool { return len(r.SourcesFailed) > 0 || r.partialItems }

// CollectOptions は Collect の対象の絞り込み。
type CollectOptions struct {
	// SourceIDs が空でなければそのソースだけ。
	SourceIDs []string
	// Needs が空でなければ、そのレコード種類を出すソースだけ (プロファイルのチェックが必要とするもの)。
	Needs map[record.Kind]bool
	// PrincipalStatus は新規主体の初期状態 (unknown / baseline)。
	PrincipalStatus string
	// RunID はログに添える。
	RunID string
	// Rescan は各ソースの ingest_delay だけ窓の前を再走査する (run。ADR 0013)。init のチャンクは取り込み済みの過去の日を
	// 続けて引くので再走査しない (最後の日の終わり側は次の run の再走査が拾う)。
	Rescan bool
	// BaseFrom は再走査の基準 (ゼロなら窓の From)。SourceFrom はそこより前から引くソース (失敗した期間の追いつき。ADR 0038)。
	BaseFrom   time.Time
	SourceFrom map[string]time.Time
}

// Collect は設定の sources から窓内を収集し、ストアへ反映する。失敗したソースは記録して続行する。
//
// 決定: run はプロファイルのチェックが必要とするレコードを出すソースだけを引く (hourly で Logs Insights を回さないため。設計書 3 章)。
// 決定 (ADR 0013): o.Rescan なら各ソースは [From - ingest_delay, To) を引く (前回の窓の末尾に起きて遅れて記録されたイベントを拾う)。
// trail_event には収集の時刻 (w.CollectedAt、ゼロなら今) を付け、イベント型チェックが遅れて届いたものを見分けられるようにする。
func (e *Engine) Collect(ctx context.Context, w collect.Window, o CollectOptions) CollectResult {
	if w.CollectedAt.IsZero() {
		w.CollectedAt = e.deps.Now()
	}
	res := CollectResult{SourcesOK: []string{}, SourcesFailed: []string{}, Errors: []report.CollectError{}, Formats: []report.FormatCoverage{},
		yielded: map[string][]record.Kind{}, attempted: map[string]bool{}, unavailable: map[record.Kind]string{}, outOfRange: map[string]string{}}
	denied := map[string]bool{}
	for _, c := range e.cfg.Checks.AccessDenied.ErrorCodes {
		denied[c] = true
	}
	want := map[string]bool{}
	for _, id := range o.SourceIDs {
		want[id] = true
	}
	for _, src := range e.cfg.Sources {
		if len(want) > 0 && !want[src.ID] {
			continue
		}
		if len(o.Needs) > 0 && !anyNeeded(kindsOf(e.cfg, src), o.Needs) {
			continue
		}
		if len(o.Needs) == 0 && len(formatKinds(src)) == 0 && src.Kind == config.KindCloudWatchLogs {
			// 決定 (ADR 0050): 種類を絞らない収集 (collect・init) は log_hygiene を流さない。format: text のソースには他に引くものが無い
			e.log.Debug("source is read only by log_hygiene in a run of a profile that has it; skipping", "source", src.ID)
			continue
		}
		res.attempted[src.ID] = true
		c, err := e.collector(ctx, src)
		if err == nil {
			if lc, ok := c.(*cwlogs.Collector); ok {
				if len(o.Needs) > 0 {
					lc.Select(o.Needs)
				}
				// log_hygiene の範囲は run の窓。失敗したソースの追いつき (ADR 0038) の分は足さない (cwlogs.Collector.HygieneFrom)
				lc.HygieneFrom = w.From
				if !o.BaseFrom.IsZero() {
					lc.HygieneFrom = o.BaseFrom
				}
			}
			res.yielded[src.ID] = c.Yields()
			n := 0
			snapshots := map[record.Kind][]record.SnapshotItem{}
			sink := collect.SinkFunc(func(ctx context.Context, rec record.Record) error {
				n++
				switch v := rec.(type) {
				case record.TrailEvent:
					v.CollectedAt = w.CollectedAt
					if src.Kind == config.KindCloudTrailUnusedRegions {
						// 既存の stats (denied_events / secret_read_events) を変えない
						res.UnusedRegionEvents++
						rec = v
						break
					}
					if denied[v.ErrorCode] {
						res.DeniedEvents++
					}
					if checks.IsSecretRead(v) {
						res.SecretReadEvents++
					}
					rec = v
				case record.PrincipalSeen:
					// rebuild が (arn, ip) の行を最初に作った記録を決めるのに使う (ADR 0033)
					v.CollectedAt = w.CollectedAt
					rec = v
				case record.SnapshotItem:
					snapshots[v.Kind] = append(snapshots[v.Kind], v)
				}
				return e.ingest(ctx, src.ID, rec, o.PrincipalStatus)
			})
			sw := w
			sw.ScanFrom = time.Time{}
			if o.Rescan {
				if !o.BaseFrom.IsZero() {
					sw.From = o.BaseFrom
				}
				if t, ok := o.SourceFrom[src.ID]; ok && t.Before(sw.From) {
					sw.From = t
				}
				sw.ScanFrom = sw.From.Add(-src.IngestDelay)
			}
			err = c.Collect(ctx, sw, sink)
			res.Records += n
			if ur, ok := c.(*cloudtrail.UnusedRegions); ok {
				res.UnusedRegionsScanned = append(res.UnusedRegionsScanned, ur.ScannedRegions()...)
			}
			if fr, ok := c.(collect.FormatReporter); ok && fr.FormatStats() != nil {
				if r := fr.FormatStats().OutOfRange; r != "" {
					res.outOfRange[src.ID] = r
				}
				res.Formats = append(res.Formats, e.formatCoverage(ctx, *fr.FormatStats(), err, o.RunID))
			}
			if err == nil {
				err = e.replaceSnapshots(ctx, c, src.ID, snapshots, w.CollectedAt, &res)
			}
			if err == nil {
				e.partialProblems(c, src, o.RunID, &res)
			}
		}
		if err != nil {
			ce := collect.Classify(src.ID, "", err)
			attrs := []any{"code", ce.Code, "source", src.ID, "kind", src.Kind, "error", ce.Err.Error()}
			if ce.Action != "" {
				attrs = append(attrs, "action", ce.Action)
			}
			for _, k := range sortedKeys(ce.Details) {
				attrs = append(attrs, k, ce.Details[k])
			}
			if o.RunID != "" {
				attrs = append(attrs, "run_id", o.RunID)
			}
			e.log.Error("collect failed", attrs...)
			res.SourcesFailed = append(res.SourcesFailed, src.ID)
			// 決定 (ADR 0037): AWS のエラー文は主体の ARN (セッション名) を含むので、そのままレポートに写さない
			msg := record.MaskIdentity(ce.Err.Error())
			if ce.Action != "" {
				msg = ce.Action + ": " + msg
			}
			re := report.CollectError{Source: src.ID, Code: ce.Code, Action: ce.Action, Message: msg}
			if !ce.CoveredFrom.IsZero() {
				re.CoveredFrom, re.CoveredUntil = ce.CoveredFrom.UTC().Format(time.RFC3339), ce.CoveredUntil.UTC().Format(time.RFC3339)
				e.log.Info("partial data kept for failed source", "source", src.ID, "covered_from", re.CoveredFrom, "covered_until", re.CoveredUntil)
			}
			res.Errors = append(res.Errors, re)
			continue
		}
		res.SourcesOK = append(res.SourcesOK, src.ID)
		attrs := []any{"source", src.ID, "from", w.From.UTC().Format(time.RFC3339), "to", w.To.UTC().Format(time.RFC3339)}
		if o.Rescan {
			attrs = append(attrs, "scan_from", w.From.Add(-src.IngestDelay).UTC().Format(time.RFC3339))
		}
		e.log.Info("collect ok", attrs...)
	}
	return res
}

// replaceSnapshots は成功した収集のスナップショットで (kind, source) を丸ごと置き換える (取れた項目が 0 件なら空にする)。
// 決定 (ADR 0015): 失敗した収集では置き換えない (前回のまま。チェックは skip されるので、権限を失ったことを解消と誤認しない)。
// 取れない種類 (GuardDuty 無効など) も置き換えず、理由を記録してチェックを skip させる。
func (e *Engine) replaceSnapshots(ctx context.Context, c collect.Collector, sourceID string, items map[record.Kind][]record.SnapshotItem, at time.Time, res *CollectResult) error {
	var unavailable map[record.Kind]string
	if ar, ok := c.(collect.AvailabilityReporter); ok {
		unavailable = ar.Unavailable()
	}
	for _, k := range c.Yields() {
		if reason, ok := unavailable[k]; ok {
			res.unavailable[k] = sourceID + ": " + reason
			e.log.Info("record kind is unavailable", "source", sourceID, "kind", string(k), "reason", reason)
			continue
		}
		if !record.SnapshotKinds[k] {
			continue
		}
		if err := e.st.ReplaceSnapshot(ctx, k, sourceID, items[k], at); err != nil {
			return err
		}
	}
	return nil
}

// partialProblems は一部の項目だけ取れなかった collector の問題を、標準エラーと coverage (partial) に出す (ソースは成功扱いで評価する)。
func (e *Engine) partialProblems(c collect.Collector, src config.Source, runID string, res *CollectResult) {
	pr, ok := c.(collect.PartialReporter)
	if !ok {
		return
	}
	for _, p := range pr.Problems() {
		attrs := []any{"code", p.Code, "source", src.ID, "kind", src.Kind, "action", p.Action, "error", p.Err.Error()}
		if runID != "" {
			attrs = append(attrs, "run_id", runID)
		}
		e.log.Error("collect partially failed; evaluating with the items that were fetched", attrs...)
		res.Errors = append(res.Errors, report.CollectError{Source: src.ID, Code: p.Code, Action: p.Action, Partial: true, Message: p.Action + ": " + p.Err.Error()})
		res.partialItems = true
	}
}

func (e *Engine) collector(ctx context.Context, src config.Source) (collect.Collector, error) {
	switch src.Kind {
	case config.KindCloudTrailUnusedRegions:
		// 有効なリージョンの一覧 (Account Management) はグローバルなので us-east-1 のクライアントで引く
		cl, err := e.deps.Account(ctx, e.cfg, src, config.GlobalRegion)
		if err != nil {
			return nil, err
		}
		c := cloudtrail.NewUnusedRegions(src.ID, cl.Account, e.cfg.ActiveRegions(), func(ctx context.Context, region string) (cloudtrail.API, error) {
			return e.deps.CloudTrail(ctx, e.cfg, src, region)
		})
		c.Limiter = e.deps.Limiter
		c.Logger = e.log
		if e.deps.Sleep != nil {
			c.Sleep = e.deps.Sleep
		}
		return c, nil
	case config.KindCredentialReport, config.KindGuardDuty, config.KindAccessAnalyzer, config.KindPosture, config.KindWAFConfig, config.KindCostAnomaly:
		clients := make([]account.Clients, 0, len(src.Regions))
		for _, region := range src.Regions {
			cl, err := e.deps.Account(ctx, e.cfg, src, region)
			if err != nil {
				return nil, err
			}
			clients = append(clients, cl)
		}
		var c interface {
			collect.Collector
			SetSleep(func(ctx context.Context, d time.Duration) error)
			SetLogger(*slog.Logger)
		}
		switch src.Kind {
		case config.KindCredentialReport:
			c = account.NewCredentialReport(src.ID, clients...)
		case config.KindGuardDuty:
			c = account.NewGuardDuty(src.ID, clients...)
		case config.KindAccessAnalyzer:
			c = account.NewAccessAnalyzer(src.ID, clients...)
		case config.KindCostAnomaly:
			// regions は us-east-1 に固定 (Cost Explorer の API。config で検証済み)
			c = account.NewCostAnomaly(src.ID, e.cfg.Checks.CostAnomaly.LookbackDays, e.cfg.Checks.CostAnomaly.MinImpactUSD, clients...)
		case config.KindWAFConfig:
			// CLOUDFRONT の WebACL は us-east-1 にしか無いので、regions に関係なく us-east-1 のクライアントを足す
			cf, err := e.deps.Account(ctx, e.cfg, src, config.GlobalRegion)
			if err != nil {
				return nil, err
			}
			c = account.NewWAFConfig(src.ID, cf, clients...)
		default:
			c = account.NewPosture(src.ID, clients...)
		}
		c.SetLogger(e.log)
		if e.deps.Sleep != nil {
			c.SetSleep(e.deps.Sleep)
		}
		return c, nil
	case config.KindCloudWatchLogs:
		api, err := e.deps.CloudWatchLogs(ctx, e.cfg, src, src.Regions[0])
		if err != nil {
			return nil, err
		}
		c, err := cwlogs.New(src, e.cfg.Checks, api)
		if err != nil {
			return nil, err
		}
		if e.deps.Sleep != nil {
			c.Sleep = e.deps.Sleep
		}
		c.Now = e.deps.Now
		c.Logger = e.log
		return c, nil
	case config.KindCloudTrailLookup:
		clients := make([]cloudtrail.RegionClient, 0, len(src.Regions))
		for _, region := range src.Regions {
			api, err := e.deps.CloudTrail(ctx, e.cfg, src, region)
			if err != nil {
				return nil, err
			}
			clients = append(clients, cloudtrail.RegionClient{Region: region, API: api})
		}
		c := cloudtrail.New(src.ID, clients...)
		// 拒否された呼び出しを events に残すコードは設定に従う (access_denied。ADR 0021)
		c.Notable = cloudtrail.NotableWith(e.cfg.Checks.AccessDenied.ErrorCodes)
		c.Limiter = e.deps.Limiter
		c.Logger = e.log
		if e.deps.Sleep != nil {
			c.Sleep = e.deps.Sleep
		}
		return c, nil
	}
	return nil, fmt.Errorf("unsupported source kind %q", src.Kind)
}

func (e *Engine) ingest(ctx context.Context, source string, rec record.Record, principalStatus string) error {
	if err := e.st.AppendRaw(ctx, source, rec); err != nil {
		return err
	}
	switch v := rec.(type) {
	case record.TrailEvent:
		return e.st.InsertEvent(ctx, v)
	case record.PrincipalSeen:
		return e.st.UpsertPrincipalSeen(ctx, v, principalStatus)
	case record.Metric:
		return e.st.UpsertMetric(ctx, v)
	}
	return nil
}

// EvalResult は評価の結果。
type EvalResult struct {
	Results []checks.Result
	// Proposals は WAF の修正提案の候補 (waf_review。ADR 0023)。
	Proposals []schema.Proposal
	// CoverageNotes はチェックが返した注記 (判定しなかった記録など。checks.Noter)。report.json の coverage.notes に出す。
	CoverageNotes []string
	ChecksRun     []string
	ChecksSkipped []report.SkippedCheck
}

// Evaluate はプロファイルのチェックを走らせ、差分判定の結果を返す。
// cr が nil なら「全ソースが取れた」とみなす (collect を伴わない evaluate コマンド用)。
func (e *Engine) Evaluate(ctx context.Context, profileName string, w collect.Window, cr *CollectResult) (EvalResult, error) {
	prof, ok := e.cfg.Profiles[profileName]
	if !ok {
		return EvalResult{}, e.configErr(fmt.Errorf("profile %q is not defined", profileName))
	}
	if err := e.syncPrincipalStatus(ctx, w.To); err != nil {
		return EvalResult{}, err
	}
	res := EvalResult{ChecksRun: []string{}, ChecksSkipped: []report.SkippedCheck{}}
	// 人が allowlist.yaml を直接編集して承認した主体の finding を解消する (approve を経由しない経路)
	resolved, err := e.resolveAllowlisted(ctx, e.al, w.To, e.deps.Now(), "")
	if err != nil {
		return EvalResult{}, err
	}
	for _, f := range resolved {
		res.Results = append(res.Results, checks.Result{Class: checks.ClassResolved, Finding: f})
	}
	available, failedKinds := e.availableKinds(cr)
	reg := e.registry(profileName)
	for _, name := range prof.ExpandChecks(reg.Defaults()) {
		c, ok := reg.Get(name)
		if !ok {
			return EvalResult{}, e.configErr(fmt.Errorf("profile %q: unknown check %q", profileName, name))
		}
		// 設定が空で何も見ないチェック (log_hygiene。ADR 0050) は、何を書けば動くかを理由にして skip する
		if d, ok := c.(checks.Disabler); ok && d.Disabled() != "" {
			res.ChecksSkipped = append(res.ChecksSkipped, report.SkippedCheck{Check: name, Reason: d.Disabled()})
			continue
		}
		if reason := skipReason(c, available, failedKinds, unavailableOf(cr)); reason != "" {
			res.ChecksSkipped = append(res.ChecksSkipped, report.SkippedCheck{Check: name, Reason: reason})
			continue
		}
		if reason := e.storedSkipReason(c); reason != "" {
			res.ChecksSkipped = append(res.ChecksSkipped, report.SkippedCheck{Check: name, Reason: reason})
			continue
		}
		var obs []checks.Observation
		q := e.queryFor(name)
		if p, ok := c.(checks.Proposer); ok {
			var props []schema.Proposal
			props, obs, err = p.Propose(ctx, q, w)
			res.Proposals = append(res.Proposals, props...)
		} else if n, ok := c.(checks.Noter); ok {
			var notes []string
			obs, notes, err = n.EvaluateWithNotes(ctx, q, w, e.al)
			res.CoverageNotes = append(res.CoverageNotes, notes...)
		} else {
			obs, err = c.Evaluate(ctx, q, w, e.al)
		}
		if err != nil {
			return EvalResult{}, fmt.Errorf("check %s: %w", name, err)
		}
		dw := w
		if !e.diffFrom.IsZero() {
			dw.From = e.diffFrom
		}
		diff, err := checks.Diff(ctx, e.st, checks.DiffParams{Check: name, Mode: c.Mode(), Window: dw, Now: e.deps.Now(), NewID: e.deps.NewID}, obs)
		if err != nil {
			return EvalResult{}, err
		}
		res.Results = append(res.Results, diff...)
		res.ChecksRun = append(res.ChecksRun, name)
		var evs []store.FindingEvent
		for _, r := range diff {
			switch r.Class {
			case checks.ClassNew, checks.ClassChanged, checks.ClassRecurred, checks.ClassResolved:
				evs = append(evs, findingEvent(r.Finding, string(r.Class), e.deps.Now(), e.runID, profileName))
			}
		}
		if err := e.st.AddFindingEvents(ctx, evs); err != nil {
			return EvalResult{}, err
		}
	}
	return res, nil
}

// queryFor はチェックに渡す Query。決定 (ADR 0032): ふだん使わないリージョンのイベント (cloudtrail-unused-regions のソース) は
// unused_region_activity だけが見る。他のチェックには除いた Query を渡す (二重の報告と、既存のチェックの結果・平常帯の変化を防ぐ)。
func (e *Engine) queryFor(check string) store.Query {
	ids := e.cfg.UnusedRegionSources()
	if len(ids) == 0 || check == "unused_region_activity" {
		return e.st
	}
	return excludeSources{Query: e.st, ids: ids}
}

// excludeSources は Events から ids のソースのイベントを除く Query。
type excludeSources struct {
	store.Query
	ids []string
}

func (q excludeSources) Events(ctx context.Context, from, to time.Time, f store.EventFilter) ([]record.TrailEvent, error) {
	f.ExcludeSources = append(append([]string(nil), f.ExcludeSources...), q.ids...)
	return q.Query.Events(ctx, from, to, f)
}

// registry はプロファイルで効くパラメータ (checks: に overrides を重ねたもの) でチェックを組んだ Registry。
func (e *Engine) registry(profileName string) *checks.Registry {
	r := checks.NewRegistryFor(e.cfg.ChecksFor(profileName))
	r.SetAuditLogGroups(e.cfg.AuditLogGroups())
	r.SetUnusedRegionSources(e.cfg.UnusedRegionSources())
	return r
}

// trailCollected は ok のソースに cloudtrail-lookup があるか。run の stats に checks.TrailCollectedStat を付ける条件
// (principal_new_source / secret_access が「収集し終えた日」に数える。ADR 0027)。
func (e *Engine) trailCollected(ok []string) bool {
	for _, src := range e.cfg.Sources {
		if src.Kind == config.KindCloudTrailLookup && contains(ok, src.ID) {
			return true
		}
	}
	return false
}

// UnusedChecks は登録済みのチェックのうち、どのプロファイルにも入っていないもの (登録順)。
func UnusedChecks(cfg *config.Config, reg *checks.Registry) []string {
	used := map[string]bool{}
	for _, p := range cfg.Profiles {
		for _, n := range p.ExpandChecks(reg.Defaults()) {
			used[n] = true
		}
	}
	var out []string
	for _, n := range reg.Names() {
		if !used[n] {
			out = append(out, n)
		}
	}
	return out
}

// warnUnusedChecks はどのプロファイルにも入っていないチェックを CHECK_UNUSED で警告する (run / evaluate)。
func (e *Engine) warnUnusedChecks() {
	if unused := UnusedChecks(e.cfg, e.deps.Registry); len(unused) > 0 {
		e.log.Warn("checks are not in any profile; they never run", "code", CodeCheckUnused, "checks", unused,
			"hint", "add them to a profile, or compare with `arata config init --diff`")
	}
}

// findingEvent は状態遷移の履歴 1 件 (ADR 0016)。
func findingEvent(f store.Finding, class string, at time.Time, runID, profile string) store.FindingEvent {
	return store.FindingEvent{FindingID: f.ID, Check: f.Check, Key: f.Key, Class: class, Severity: f.Severity, Summary: f.Summary, At: at, RunID: runID, Profile: profile, Data: f.Data}
}

// availableKinds は取得できたソースが出すレコード種類と、失敗したソースが出すはずだった種類を返す。
func (e *Engine) availableKinds(cr *CollectResult) (map[record.Kind]bool, map[record.Kind]string) {
	available := map[record.Kind]bool{}
	failed := map[record.Kind]string{}
	for _, src := range e.cfg.Sources {
		if cr != nil && cr.attempted != nil && !cr.attempted[src.ID] {
			continue
		}
		var kinds []record.Kind
		if cr != nil {
			kinds = cr.yielded[src.ID]
		}
		if kinds == nil {
			kinds = kindsOf(e.cfg, src)
		}
		ok := cr == nil || contains(cr.SourcesOK, src.ID)
		for _, k := range kinds {
			if ok {
				available[k] = true
			} else if _, seen := failed[k]; !seen {
				failed[k] = src.ID
			}
		}
	}
	return available, failed
}

// kindsOf はソースが出し得るレコード種類。cloudwatch-logs は形式の種類に加えて、checks.log_hygiene.sources にあれば log_hygiene も出す (ADR 0050)。
func kindsOf(cfg *config.Config, src config.Source) []record.Kind {
	if src.Kind == config.KindCloudWatchLogs && cfg.Checks.LogHygiene.Covers(src.ID) {
		return append(formatKinds(src), record.KindLogHygiene)
	}
	return formatKinds(src)
}

// formatKinds は log_hygiene を除いた、ソースの種類と形式で決まるレコード種類 (format: text の cloudwatch-logs は何も出さない)。
func formatKinds(src config.Source) []record.Kind {
	switch src.Kind {
	case config.KindCloudTrailLookup:
		return []record.Kind{record.KindTrailEvent, record.KindPrincipalSeen}
	case config.KindCloudWatchLogs:
		if src.Yields == "" {
			return nil
		}
		// ユーザー ID を取り出す設定のあるソースは http_user も出す (ADR 0051 の 2 節。0 件の run では collector が Unavailable で外す)
		if src.UserIDFrom() != config.UserIDFromNone {
			return []record.Kind{record.Kind(src.Yields), record.KindHTTPUser}
		}
		return []record.Kind{record.Kind(src.Yields)}
	case config.KindCredentialReport:
		return []record.Kind{record.KindCredentialReport}
	case config.KindGuardDuty:
		return []record.Kind{record.KindGuardDuty}
	case config.KindAccessAnalyzer:
		return []record.Kind{record.KindAccessAnalyzer}
	case config.KindPosture:
		return []record.Kind{record.KindPostureItem}
	case config.KindWAFConfig:
		return []record.Kind{record.KindWAFConfig}
	case config.KindCloudTrailUnusedRegions:
		return []record.Kind{record.KindUnusedRegionEvent}
	case config.KindCostAnomaly:
		return []record.Kind{record.KindCostAnomaly}
	}
	return nil
}

func anyNeeded(kinds []record.Kind, needs map[record.Kind]bool) bool {
	for _, k := range kinds {
		if needs[k] {
			return true
		}
	}
	return false
}

// neededKinds はプロファイルのチェックが必要とするレコード種類。未知のチェックは Evaluate で CONFIG_INVALID にするのでここでは無視する。
func (e *Engine) neededKinds(prof config.Profile) map[record.Kind]bool {
	out := map[record.Kind]bool{}
	for _, name := range prof.ExpandChecks(e.deps.Registry.Defaults()) {
		if c, ok := e.deps.Registry.Get(name); ok {
			for _, k := range c.Needs() {
				out[k] = true
			}
		}
	}
	return out
}

func unavailableOf(cr *CollectResult) map[record.Kind]string {
	if cr == nil {
		return nil
	}
	return cr.unavailable
}

func skipReason(c checks.Check, available map[record.Kind]bool, failed map[record.Kind]string, unavailable map[record.Kind]string) string {
	for _, k := range c.Needs() {
		if reason, ok := unavailable[k]; ok {
			return reason
		}
		if available[k] {
			continue
		}
		if src, ok := failed[k]; ok {
			return fmt.Sprintf("source %s failed", src)
		}
		return fmt.Sprintf("no %s source", k)
	}
	return ""
}

// storedSkipReason は保存済みのデータだけを読むチェック (checks.StoredNeeder) について、その種類を出すソースが設定に無ければ理由を返す。
// 決定 (ADR 0023): waf_review は daily が貯めた wafv2 の日次集計を読むだけで、weekly の run は wafv2 のソースを引かない (Insights の費用)。
func (e *Engine) storedSkipReason(c checks.Check) string {
	sn, ok := c.(checks.StoredNeeder)
	if !ok {
		return ""
	}
	configured := map[record.Kind]bool{}
	for _, src := range e.cfg.Sources {
		for _, k := range kindsOf(e.cfg, src) {
			configured[k] = true
		}
	}
	for _, k := range sn.StoredNeeds() {
		if !configured[k] {
			return fmt.Sprintf("no %s source (reads the daily metrics)", k)
		}
	}
	return ""
}

// syncPrincipalStatus は allowlist の内容を principals.status に反映する (ADR 0007)。
func (e *Engine) syncPrincipalStatus(ctx context.Context, at time.Time) error {
	ps, err := e.st.Principals(ctx, store.PrincipalFilter{})
	if err != nil {
		return err
	}
	for _, p := range ps {
		_, st := e.al.Principal(p.ARN, at)
		want := p.Status
		switch st {
		case allowlist.StatusApproved:
			want = store.PrincipalApproved
		case allowlist.StatusExpired:
			want = store.PrincipalExpired
		default:
			if p.Status == store.PrincipalApproved || p.Status == store.PrincipalExpired {
				want = store.PrincipalUnknown
			}
		}
		if want != p.Status {
			if err := e.st.SetPrincipalStatus(ctx, p.ARN, want); err != nil {
				return err
			}
		}
	}
	return nil
}

// RunResult は Run の結果。
type RunResult struct {
	Report *report.Report
	Exit   int
}

// Run は collect → evaluate → report → 保存 を行う (prune は後続 Step)。
func (e *Engine) Run(ctx context.Context, profileName string) (*RunResult, error) {
	return e.RunWith(ctx, profileName, nil)
}

// RunWith は Run に、報告済みの印を付ける前の準備 (prepare) を足す。prepare はレポートの出力の準備で、失敗したら run を failed にして印を付けない。
//
// 決定 (ADR 0038): 順序は 準備 → saveReport → markReported → FinishRun で、呼び出し側が Commit → 公開 と続ける。
// S3 の Commit は 1 回だけで、未確定の結果を通知しない (ADR 0034) ので、「公開してから印を付ける」はできない。
// 準備で失敗の多くを先に出し、残る失敗の窓は公開の rename と標準出力だけにする。
func (e *Engine) RunWith(ctx context.Context, profileName string, prepare func(*report.Report) error) (*RunResult, error) {
	return e.RunWithOptions(ctx, profileName, RunOptions{Prepare: prepare})
}

// RunOptions は RunWithOptions の指定。
type RunOptions struct {
	// Prepare は RunWith の prepare。
	Prepare func(*report.Report) error
	// DryRun は試しの実行 (ADR 0049)。OpenDryRun で開いたエンジンでだけ使える。
	DryRun bool
	// Window は試しの実行の窓の長さ (ゼロならプロファイルの window)。DryRun のときだけ使える。
	Window time.Duration
}

// RunWithOptions は run の本体。
//
// 決定 (試しの実行。ADR 0049): DryRun では窓を [now - Window, now) にし、前回の window_to からの追いつきと、失敗したソースの追いつき
// (ADR 0038) をしない (短く試すのが目的で、追いつきは定時の実行が行う)。ingest_delay の再走査は同じ。収集と評価はストアの複製の上で
// ふだんと同じ手順で行い、複製は捨てる。差分判定の境界は定時の実行の窓の始まりに合わせる (dryRunWindow)。
// 決定: 取り違えを両側で止める。複製でないエンジンは DryRun を断り (本番のストアに書かせない)、複製のエンジンは DryRun 以外を断る
// (結果が捨てられるのに成功に見える)。
func (e *Engine) RunWithOptions(ctx context.Context, profileName string, o RunOptions) (*RunResult, error) {
	prof, ok := e.cfg.Profiles[profileName]
	if !ok {
		return nil, e.configErr(fmt.Errorf("profile %q is not defined", profileName))
	}
	switch {
	case o.DryRun != e.scratch:
		return nil, e.configErr(errors.New("a dry run needs an engine opened with OpenDryRun, and such an engine runs nothing else"))
	case o.Window != 0 && !o.DryRun:
		return nil, e.configErr(errors.New("--window can be used only with --dry-run (a scheduled run continues from the previous window end)"))
	case o.Window < 0:
		return nil, e.configErr(errors.New("--window must be positive"))
	}
	e.warnUnusedChecks()
	now := e.deps.Now()
	var w collect.Window
	var dry *dryRunInfo
	cu := &catchup{covered: map[string]time.Time{}, from: map[string]time.Time{}}
	var err error
	if o.DryRun {
		if w, dry, err = e.dryRunWindow(ctx, profileName, prof, o.Window, now); err != nil {
			return nil, err
		}
		e.diffFrom = dry.diffFrom
		defer func() { e.diffFrom = time.Time{} }()
	} else if w, err = e.window(ctx, profileName, prof, now, true); err != nil {
		return nil, err
	}
	base := w.From
	if !o.DryRun {
		if cu, err = e.planCatchup(ctx, profileName, prof, base, now); err != nil {
			return nil, err
		}
	}
	// 集計のソースが遅れていれば、チェックの窓も広げる (日次集計は窓の中の日だけを見るため)
	if cu.metricsFrom.Before(w.From) && !cu.metricsFrom.IsZero() {
		w.From = cu.metricsFrom
	}
	// 再走査 (ADR 0013)。収集はソースごとの ingest_delay、評価は最大の ingest_delay まで遡って遅れて届いたイベントを見る
	w.ScanFrom, w.CollectedAt = w.From.Add(-e.cfg.MaxIngestDelay()), now
	// 追いついたイベントは「遅れて届いたもの」と同じ扱いで評価する
	if t := cu.eventsFrom.Add(-e.cfg.MaxIngestDelay()); !cu.eventsFrom.IsZero() && t.Before(w.ScanFrom) {
		w.ScanFrom = t
	}
	runID := e.deps.NewID()
	e.runID, e.runProfile = runID, profileName
	defer func() { e.runID, e.runProfile = "", "" }()
	if err := e.st.BeginRun(ctx, store.Run{ID: runID, Profile: profileName, WindowFrom: w.From, WindowTo: w.To, StartedAt: now, Status: "running"}); err != nil {
		return nil, err
	}
	cr := e.Collect(ctx, w, CollectOptions{Needs: e.neededKinds(prof), PrincipalStatus: store.PrincipalUnknown, RunID: runID, Rescan: true, BaseFrom: base, SourceFrom: cu.from})
	ev, err := e.Evaluate(ctx, profileName, w, &cr)
	if err != nil {
		_ = e.st.FinishRun(ctx, runID, "failed", map[string]any{"error": err.Error()})
		return nil, err
	}
	rep := e.buildReport(profileName, runID, w, now, cr, ev)
	if dry != nil {
		rep.DryRun = true
		rep.Coverage.Notes = append(e.dryRunNotes(prof, w, dry, ev), rep.Coverage.Notes...)
	}
	if o.Prepare != nil {
		if err := o.Prepare(rep); err != nil {
			_ = e.st.FinishRun(ctx, runID, "failed", map[string]any{"error": err.Error()})
			return nil, err
		}
	}
	if err := e.saveReport(profileName, rep); err != nil {
		return nil, err
	}
	if err := e.markReported(ctx, rep, now); err != nil {
		return nil, err
	}
	status, exit := "ok", ExitOK
	if cr.partial() {
		status, exit = "partial", ExitPartial
	}
	stats := map[string]any{
		"records": cr.Records, "denied_events": cr.DeniedEvents, "secret_read_events": cr.SecretReadEvents, "sources_ok": len(cr.SourcesOK), "sources_failed": len(cr.SourcesFailed),
		"new": rep.Summary.New, "changed": rep.Summary.Changed, "recurred": rep.Summary.Recurred, "resolved": rep.Summary.Resolved, "still_open": rep.Summary.StillOpen,
	}
	stats[collectResultStat] = collectSummary{OK: cr.SourcesOK, Failed: cr.SourcesFailed, Errors: cr.Errors}
	stats[sourceCoveredStat] = cu.advance(cr, base, w.To)
	if len(cu.from) > 0 {
		stats[catchupStat] = timesText(cu.from)
	}
	addFormatStats(stats, cr.Formats)
	if e.cfg.HasSourceKind(config.KindCloudTrailUnusedRegions) {
		stats["unused_region_events"] = cr.UnusedRegionEvents
		stats["unused_regions_scanned"] = strings.Join(cr.UnusedRegionsScanned, ",")
	}
	if e.trailCollected(cr.SourcesOK) {
		stats[checks.TrailCollectedStat] = true
	}
	if err := e.st.FinishRun(ctx, runID, status, stats); err != nil {
		return nil, err
	}
	if dry != nil {
		e.log.Info("dry run finished; nothing was written to the store", "profile", profileName, "run_id", runID, "status", status, "new", rep.Summary.New, "max_severity", rep.Summary.MaxSeverity,
			"from", w.From.UTC().Format(time.RFC3339), "to", w.To.UTC().Format(time.RFC3339))
		return &RunResult{Report: rep, Exit: exit}, nil
	}
	e.log.Info("run finished", "profile", profileName, "run_id", runID, "status", status, "new", rep.Summary.New, "max_severity", rep.Summary.MaxSeverity)
	return &RunResult{Report: rep, Exit: exit}, nil
}

// EvaluateOnly は収集せずに評価とレポート生成だけを行う (evaluate コマンド)。
func (e *Engine) EvaluateOnly(ctx context.Context, profileName string) (*RunResult, error) {
	return e.EvaluateWith(ctx, profileName, nil)
}

// EvaluateWith は EvaluateOnly に出力の準備を足す (RunWith と同じ)。
func (e *Engine) EvaluateWith(ctx context.Context, profileName string, prepare func(*report.Report) error) (*RunResult, error) {
	prof, ok := e.cfg.Profiles[profileName]
	if !ok {
		return nil, e.configErr(fmt.Errorf("profile %q is not defined", profileName))
	}
	e.warnUnusedChecks()
	now := e.deps.Now()
	w := collect.Window{From: now.Add(-prof.Window), To: now}
	runID := e.deps.NewID()
	e.runID, e.runProfile = runID, profileName
	defer func() { e.runID, e.runProfile = "", "" }()
	ev, err := e.Evaluate(ctx, profileName, w, nil)
	if err != nil {
		return nil, err
	}
	// 決定 (ADR 0037): evaluate は収集しないので、直近の collect の結果をそのまま報告する (全部取れたことにしない)
	cr, err := e.lastCollect(ctx)
	if err != nil {
		return nil, err
	}
	rep := e.buildReport(profileName, runID, w, now, cr, ev)
	if prepare != nil {
		if err := prepare(rep); err != nil {
			return nil, err
		}
	}
	if err := e.saveReport(profileName, rep); err != nil {
		return nil, err
	}
	if err := e.markReported(ctx, rep, now); err != nil {
		return nil, err
	}
	exit := ExitOK
	if cr.partial() {
		exit = ExitPartial
	}
	return &RunResult{Report: rep, Exit: exit}, nil
}

// CollectOnly は collect コマンド用。窓の長さを直接指定する。
func (e *Engine) CollectOnly(ctx context.Context, window time.Duration, sourceIDs []string) (*CollectResult, error) {
	for _, id := range sourceIDs {
		found := false
		for _, s := range e.cfg.Sources {
			found = found || s.ID == id
		}
		if !found {
			return nil, e.configErr(fmt.Errorf("source %q is not defined", id))
		}
	}
	now := e.deps.Now()
	w := collect.Window{From: now.Add(-window), To: now}
	runID := e.deps.NewID()
	if err := e.st.BeginRun(ctx, store.Run{ID: runID, Profile: collectRunProfile, WindowFrom: w.From, WindowTo: w.To, StartedAt: now, Status: "running"}); err != nil {
		return nil, err
	}
	cr := e.Collect(ctx, w, CollectOptions{SourceIDs: sourceIDs, PrincipalStatus: store.PrincipalUnknown, RunID: runID})
	status := "ok"
	if cr.partial() {
		status = "partial"
	}
	stats := map[string]any{collectResultStat: collectSummary{OK: cr.SourcesOK, Failed: cr.SourcesFailed, Errors: cr.Errors}}
	if err := e.st.FinishRun(ctx, runID, status, stats); err != nil {
		return nil, err
	}
	return &cr, nil
}

// collect コマンドの結果を evaluate に渡す run の記録 (ADR 0037)。
const (
	collectRunProfile = "collect-only"
	collectResultStat = "collect_result"
	// recentCollectRuns は収集の記録を探す run の数 (evaluate は記録の無い run を残さないので、ふつうは最新の 1 件で見つかる)。
	recentCollectRuns = 20
)

type collectSummary struct {
	OK     []string              `json:"ok"`
	Failed []string              `json:"failed"`
	Errors []report.CollectError `json:"errors"`
}

// lastCollect は直近の収集 (run または collect) の結果を返す。記録が無ければ「取れたソースは無い」とする (取れたと報告しない)。
func (e *Engine) lastCollect(ctx context.Context) (CollectResult, error) {
	cr := CollectResult{SourcesOK: []string{}, SourcesFailed: []string{}, Errors: []report.CollectError{}}
	recent, err := e.st.RecentRuns(ctx, recentCollectRuns)
	if err != nil {
		return cr, err
	}
	var result any
	for _, r := range recent {
		if v, ok := r.Stats[collectResultStat]; ok {
			result = v
			break
		}
	}
	if result == nil {
		return cr, nil
	}
	b, err := json.Marshal(result)
	if err != nil {
		return cr, err
	}
	var s collectSummary
	if err := json.Unmarshal(b, &s); err != nil {
		return cr, err
	}
	if s.OK != nil {
		cr.SourcesOK = s.OK
	}
	if s.Failed != nil {
		cr.SourcesFailed = s.Failed
	}
	if s.Errors != nil {
		cr.Errors = s.Errors
	}
	return cr, nil
}

// window は今回の run の窓を決める (設計書 3 章の決定)。
//
//   - 通常は [now - window, now)。
//   - 同じ profile の直近の ok / partial な run があれば From = min(now - window, 前回の WindowTo) とし、
//     cron の遅延・欠落で空いた期間を取りこぼさない。
//   - ただし追いつきは max_catchup (既定 7d) まで。超えた分は諦めて From = now - max_catchup とし、RUN_MISSED に gap と covered_from を添える。
//   - 前回の実行から周期の 2 倍以上空いていれば (追いつけた場合も) RUN_MISSED を警告する。
//   - 窓の終わりは now のまま。記録の遅れは収集側の再走査 [From - ingest_delay, To) で拾う (ADR 0013)。
//
// warn が false なら RUN_MISSED を出さない (試しの実行が定時の実行の窓を知るためだけに呼ぶ)。
func (e *Engine) window(ctx context.Context, profileName string, prof config.Profile, now time.Time, warn bool) (collect.Window, error) {
	w := collect.Window{From: now.Add(-prof.Window), To: now}
	last, err := e.st.LastRun(ctx, profileName, []string{"ok", "partial"})
	if err != nil {
		return w, err
	}
	if last == nil {
		return w, nil
	}
	truncated := false
	if last.WindowTo.Before(w.From) {
		w.From = last.WindowTo
		if floor := now.Add(-prof.MaxCatchup); w.From.Before(floor) {
			w.From = floor
			truncated = true
		}
	}
	if gap := now.Sub(last.StartedAt); warn && (gap >= 2*prof.Window || truncated) {
		attrs := []any{"code", CodeRunMissed, "profile", profileName,
			"last_started_at", last.StartedAt.UTC().Format(time.RFC3339), "last_window_to", last.WindowTo.UTC().Format(time.RFC3339),
			"gap", gap.String(), "covered_from", w.From.UTC().Format(time.RFC3339), "truncated", truncated}
		msg := "previous run is too old; catching up from its window end"
		if truncated {
			msg = "previous run is too old; gap exceeds max_catchup, events before covered_from are lost"
		}
		e.log.Warn(msg, attrs...)
	}
	return w, nil
}

func (e *Engine) buildReport(profileName, runID string, w collect.Window, now time.Time, cr CollectResult, ev EvalResult) *report.Report {
	rep := report.Build(report.Input{
		Profile: profileName, Name: e.cfg.Name, RunID: runID, Window: w, Now: now, DiffFrom: e.diffFrom,
		Results: ev.Results, CollectErrors: cr.Errors, SourcesOK: cr.SourcesOK, Formats: cr.Formats,
		ChecksRun: ev.ChecksRun, ChecksSkipped: ev.ChecksSkipped, Proposals: ev.Proposals,
	})
	// 決定 (ADR 0055): チェックが判定しなかった記録 (以前の版で集めた記録など) は、黙って捨てずに coverage.notes に出す
	rep.Coverage.Notes = append(rep.Coverage.Notes, ev.CoverageNotes...)
	return rep
}

func (e *Engine) markReported(ctx context.Context, rep *report.Report, now time.Time) error {
	var ids []string
	for _, l := range [][]report.Finding{rep.Findings.New, rep.Findings.Changed, rep.Findings.Recurred, rep.Info} {
		for _, f := range l {
			ids = append(ids, f.ID)
		}
	}
	sort.Strings(ids)
	return e.st.MarkReported(ctx, ids, now)
}

// saveReport は最新レポートを <store>/reports/<profile>.json と .md に保存する (report コマンドが読む)。
// 決定: report コマンド (期間指定なし) は再評価せず、保存済みの最新レポートを出す。
func (e *Engine) saveReport(profileName string, rep *report.Report) error {
	dir := filepath.Join(e.st.Path(), "reports")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return WriteReport(dir, profileName, rep)
}

// WriteReport は dir に <name>.json と <name>.md を書く。
func WriteReport(dir, name string, rep *report.Report) error {
	j, err := rep.JSON()
	if err != nil {
		return err
	}
	// 決定: md を先に置く。aratam は json を入口にするので、json が見えたときに md も新しい
	if err := report.WriteFileAtomic(filepath.Join(dir, name+".md"), []byte(rep.Markdown())); err != nil {
		return err
	}
	return report.WriteFileAtomic(filepath.Join(dir, name+".json"), j)
}

// LastReport は保存済みの最新レポート (JSON) を返す。無ければ nil。
// 決定 (ADR 0037): 設定に無い profile は読まない (--profile の値をストアの外のパスにさせない)。
func (e *Engine) LastReport(profileName string) ([]byte, error) {
	if _, ok := e.cfg.Profiles[profileName]; !ok {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(e.st.Path(), "reports", profileName+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (e *Engine) configErr(err error) error {
	e.log.Error("invalid configuration", "code", CodeConfigInvalid, "error", err.Error())
	return &ExitError{Code: CodeConfigInvalid, Exit: ExitConfig, Err: err}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
