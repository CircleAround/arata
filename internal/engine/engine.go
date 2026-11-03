// Package engine は collect → evaluate → report の流れを束ねる (設計書 4 章)。
// CLI (cmd/arata) と後続の Lambda ハンドラの両方がこれを呼ぶ。
//
// 決定: 設計書 4-1 のパッケージ一覧に無いが、cmd と cmd/arata-lambda で同じ流れを共有するため internal/engine に置く。
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

// エンジン自身のログの code (設計書 2-2)。収集側の語彙は collect パッケージにある。
const (
	CodeStoreLocked   = "STORE_LOCKED"
	CodeStoreCorrupt  = "STORE_CORRUPT"
	CodeRunMissed     = "RUN_MISSED"
	CodeConfigInvalid = "CONFIG_INVALID"
	// CodeCheckUnused はどのプロファイルにも入っていないチェックがある (警告。設定の雛形と照らして入れ忘れを疑う)。
	CodeCheckUnused = "CHECK_UNUSED"
	// CodeReportNotFound は report で再表示するレポートが無い (そのプロファイルの run がまだ無い)。
	CodeReportNotFound = "REPORT_NOT_FOUND"
)

// Codes は標準エラーの JSON 行ログに現れ得る code の固定語彙。テストで保証する。
var Codes = []string{
	collect.CodeFormatMismatch, collect.CodeFormatDrift, collect.CodeLogGroupMissing, collect.CodeAccessDenied, collect.CodeQueryLimit, collect.CodeQueryInvalid,
	CodeStoreLocked, CodeStoreCorrupt, CodeRunMissed, collect.CodeCollectFailed, CodeConfigInvalid, CodeCheckUnused, CodeReportNotFound,
}

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
		CloudTrail: ct.NewFromConfig(ac), S3Control: s3control.NewFromConfig(ac), STS: sts.NewFromConfig(ac)}, nil
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
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if d.Registry == nil {
		d.Registry = checks.NewRegistryFor(cfg.Checks)
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

// Open はストアを開き allowlist を読む。ロック失敗は STORE_LOCKED (exit 2)。
func Open(cfg *config.Config, deps Deps) (*Engine, error) {
	deps.fill(cfg)
	st, err := store.Open(cfg.Store.Dir)
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			deps.Logger.Error("store is locked by another process", "code", CodeStoreLocked, "dir", cfg.Store.Dir)
			return nil, &ExitError{Code: CodeStoreLocked, Exit: ExitConfig, Err: err}
		}
		deps.Logger.Error("failed to open store", "code", CodeStoreCorrupt, "dir", cfg.Store.Dir, "error", err.Error())
		return nil, &ExitError{Code: CodeStoreCorrupt, Exit: ExitConfig, Err: err}
	}
	al, err := allowlist.Load(cfg.Allowlist)
	if err != nil {
		st.Close()
		deps.Logger.Error("invalid allowlist", "code", CodeConfigInvalid, "path", cfg.Allowlist, "error", err.Error())
		return nil, &ExitError{Code: CodeConfigInvalid, Exit: ExitConfig, Err: err}
	}
	return &Engine{cfg: cfg, deps: deps, st: st, al: al, log: deps.Logger}, nil
}

// Close はストアを閉じる。
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
		if len(o.Needs) > 0 && !anyNeeded(kindsOf(src), o.Needs) {
			continue
		}
		res.attempted[src.ID] = true
		c, err := e.collector(ctx, src)
		if err == nil {
			res.yielded[src.ID] = c.Yields()
			n := 0
			snapshots := map[record.Kind][]record.SnapshotItem{}
			sink := collect.SinkFunc(func(ctx context.Context, rec record.Record) error {
				n++
				switch v := rec.(type) {
				case record.TrailEvent:
					v.CollectedAt = w.CollectedAt
					if denied[v.ErrorCode] {
						res.DeniedEvents++
					}
					rec = v
				case record.SnapshotItem:
					snapshots[v.Kind] = append(snapshots[v.Kind], v)
				}
				return e.ingest(ctx, src.ID, rec, o.PrincipalStatus)
			})
			sw := w
			sw.ScanFrom = time.Time{}
			if o.Rescan {
				sw.ScanFrom = w.From.Add(-src.IngestDelay)
			}
			err = c.Collect(ctx, sw, sink)
			res.Records += n
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
			msg := ce.Err.Error()
			if ce.Action != "" {
				msg = ce.Action + ": " + msg
			}
			re := report.CollectError{Source: src.ID, Code: ce.Code, Action: ce.Action, Message: msg}
			if !ce.CoveredFrom.IsZero() {
				re.CoveredFrom, re.CoveredUntil = ce.CoveredFrom.UTC().Format(time.RFC3339), ce.CoveredUntil.UTC().Format(time.RFC3339)
				e.log.Warn("partial data kept for failed source", "source", src.ID, "covered_from", re.CoveredFrom, "covered_until", re.CoveredUntil)
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
	case config.KindCredentialReport, config.KindGuardDuty, config.KindAccessAnalyzer, config.KindPosture:
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
	Results       []checks.Result
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
		if reason := skipReason(c, available, failedKinds, unavailableOf(cr)); reason != "" {
			res.ChecksSkipped = append(res.ChecksSkipped, report.SkippedCheck{Check: name, Reason: reason})
			continue
		}
		obs, err := c.Evaluate(ctx, e.st, w, e.al)
		if err != nil {
			return EvalResult{}, fmt.Errorf("check %s: %w", name, err)
		}
		diff, err := checks.Diff(ctx, e.st, checks.DiffParams{Check: name, Mode: c.Mode(), Window: w, Now: e.deps.Now(), NewID: e.deps.NewID}, obs)
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

// registry はプロファイルで効くパラメータ (checks: に overrides を重ねたもの) でチェックを組んだ Registry。
func (e *Engine) registry(profileName string) *checks.Registry {
	return checks.NewRegistryFor(e.cfg.ChecksFor(profileName))
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
			kinds = kindsOf(src)
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

func kindsOf(src config.Source) []record.Kind {
	switch src.Kind {
	case config.KindCloudTrailLookup:
		return []record.Kind{record.KindTrailEvent, record.KindPrincipalSeen}
	case config.KindCloudWatchLogs:
		return []record.Kind{record.Kind(src.Yields)}
	case config.KindCredentialReport:
		return []record.Kind{record.KindCredentialReport}
	case config.KindGuardDuty:
		return []record.Kind{record.KindGuardDuty}
	case config.KindAccessAnalyzer:
		return []record.Kind{record.KindAccessAnalyzer}
	case config.KindPosture:
		return []record.Kind{record.KindPostureItem}
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
	prof, ok := e.cfg.Profiles[profileName]
	if !ok {
		return nil, e.configErr(fmt.Errorf("profile %q is not defined", profileName))
	}
	e.warnUnusedChecks()
	now := e.deps.Now()
	w, err := e.window(ctx, profileName, prof, now)
	if err != nil {
		return nil, err
	}
	// 再走査 (ADR 0013)。収集はソースごとの ingest_delay、評価は最大の ingest_delay まで遡って遅れて届いたイベントを見る
	w.ScanFrom, w.CollectedAt = w.From.Add(-e.cfg.MaxIngestDelay()), now
	runID := e.deps.NewID()
	e.runID, e.runProfile = runID, profileName
	defer func() { e.runID, e.runProfile = "", "" }()
	if err := e.st.BeginRun(ctx, store.Run{ID: runID, Profile: profileName, WindowFrom: w.From, WindowTo: w.To, StartedAt: now, Status: "running"}); err != nil {
		return nil, err
	}
	cr := e.Collect(ctx, w, CollectOptions{Needs: e.neededKinds(prof), PrincipalStatus: store.PrincipalUnknown, RunID: runID, Rescan: true})
	ev, err := e.Evaluate(ctx, profileName, w, &cr)
	if err != nil {
		_ = e.st.FinishRun(ctx, runID, "failed", map[string]any{"error": err.Error()})
		return nil, err
	}
	rep := e.buildReport(profileName, runID, w, now, cr, ev)
	if err := e.markReported(ctx, rep, now); err != nil {
		return nil, err
	}
	if err := e.saveReport(profileName, rep); err != nil {
		return nil, err
	}
	status, exit := "ok", ExitOK
	if cr.partial() {
		status, exit = "partial", ExitPartial
	}
	stats := map[string]any{
		"records": cr.Records, "denied_events": cr.DeniedEvents, "sources_ok": len(cr.SourcesOK), "sources_failed": len(cr.SourcesFailed),
		"new": rep.Summary.New, "changed": rep.Summary.Changed, "recurred": rep.Summary.Recurred, "resolved": rep.Summary.Resolved, "still_open": rep.Summary.StillOpen,
	}
	addFormatStats(stats, cr.Formats)
	if err := e.st.FinishRun(ctx, runID, status, stats); err != nil {
		return nil, err
	}
	e.log.Info("run finished", "profile", profileName, "run_id", runID, "status", status, "new", rep.Summary.New, "max_severity", rep.Summary.MaxSeverity)
	return &RunResult{Report: rep, Exit: exit}, nil
}

// EvaluateOnly は収集せずに評価とレポート生成だけを行う (evaluate コマンド)。
func (e *Engine) EvaluateOnly(ctx context.Context, profileName string) (*RunResult, error) {
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
	ids := []string{}
	for _, s := range e.cfg.Sources {
		ids = append(ids, s.ID)
	}
	cr := CollectResult{SourcesOK: ids, SourcesFailed: []string{}, Errors: []report.CollectError{}}
	rep := e.buildReport(profileName, runID, w, now, cr, ev)
	if err := e.markReported(ctx, rep, now); err != nil {
		return nil, err
	}
	if err := e.saveReport(profileName, rep); err != nil {
		return nil, err
	}
	return &RunResult{Report: rep, Exit: ExitOK}, nil
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
	cr := e.Collect(ctx, w, CollectOptions{SourceIDs: sourceIDs, PrincipalStatus: store.PrincipalUnknown})
	return &cr, nil
}

// window は今回の run の窓を決める (設計書 3 章の決定)。
//
//   - 通常は [now - window, now)。
//   - 同じ profile の直近の ok / partial な run があれば From = min(now - window, 前回の WindowTo) とし、
//     cron の遅延・欠落で空いた期間を取りこぼさない。
//   - ただし追いつきは max_catchup (既定 7d) まで。超えた分は諦めて From = now - max_catchup とし、RUN_MISSED に gap と covered_from を添える。
//   - 前回の実行から周期の 2 倍以上空いていれば (追いつけた場合も) RUN_MISSED を警告する。
//   - 窓の終わりは now のまま。記録の遅れは収集側の再走査 [From - ingest_delay, To) で拾う (ADR 0013)。
func (e *Engine) window(ctx context.Context, profileName string, prof config.Profile, now time.Time) (collect.Window, error) {
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
	if gap := now.Sub(last.StartedAt); gap >= 2*prof.Window || truncated {
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
	return report.Build(report.Input{
		Profile: profileName, Name: e.cfg.Name, RunID: runID, Window: w, Now: now,
		Results: ev.Results, CollectErrors: cr.Errors, SourcesOK: cr.SourcesOK, Formats: cr.Formats,
		ChecksRun: ev.ChecksRun, ChecksSkipped: ev.ChecksSkipped,
	})
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
	dir := filepath.Join(e.cfg.Store.Dir, "reports")
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
	if err := os.WriteFile(filepath.Join(dir, name+".json"), j, 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".md"), []byte(rep.Markdown()), 0o640)
}

// LastReport は保存済みの最新レポート (JSON) を返す。無ければ nil。
func (e *Engine) LastReport(profileName string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(e.cfg.Store.Dir, "reports", profileName+".json"))
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
