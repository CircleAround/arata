// Package account はアカウント単位の状態 (スナップショット) を取る collector を持つ: IAM 認証情報レポート、GuardDuty の findings、
// IAM Access Analyzer の findings、姿勢 (CloudTrail 証跡・GuardDuty 有効・ルート MFA・S3 Public Access Block・パスワードポリシー)。
//
// 決定 (ADR 0015): 窓に依らない「今の状態」なので Window は使わず、record.SnapshotItem を出す。engine は収集が成功したときだけ
// (kind, source) 単位でスナップショットを丸ごと置き換える。設計書 4-1 の guardduty/ iam/ accessanalyzer/ posture/ を
// 1 パッケージにまとめた (どれも同じ形の小さな collector で、SDK クライアントの束を共有するため)。
package account

import (
	"context"
	"io"
	"log/slog"
	"time"

	aa "github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// IAM の action。
const (
	ActionGenerateCredentialReport = "iam:GenerateCredentialReport" // 書き込み系 (レポートの生成のみ。他に副作用は無い)
	ActionGetCredentialReport      = "iam:GetCredentialReport"
	ActionGetAccountSummary        = "iam:GetAccountSummary"
	ActionGetPasswordPolicy        = "iam:GetAccountPasswordPolicy"
	ActionListDetectors            = "guardduty:ListDetectors"
	ActionGetDetector              = "guardduty:GetDetector"
	ActionListGDFindings           = "guardduty:ListFindings"
	ActionGetGDFindings            = "guardduty:GetFindings"
	ActionListAnalyzers            = "access-analyzer:ListAnalyzers"
	ActionListAAFindings           = "access-analyzer:ListFindings"
	ActionDescribeTrails           = "cloudtrail:DescribeTrails"
	ActionGetTrailStatus           = "cloudtrail:GetTrailStatus"
	ActionGetPublicAccessBlock     = "s3:GetAccountPublicAccessBlock"
)

// RequiredActions は source.kind ごとに読み取りロールへ付ける action (doctor の表の最後に出す)。
var RequiredActions = map[string][]string{
	KindCredentialReport: {ActionGenerateCredentialReport, ActionGetCredentialReport},
	KindGuardDuty:        {ActionListDetectors, ActionListGDFindings, ActionGetGDFindings},
	KindAccessAnalyzer:   {ActionListAnalyzers, ActionListAAFindings},
	KindPosture:          {ActionDescribeTrails, ActionGetTrailStatus, ActionListDetectors, ActionGetDetector, ActionGetAccountSummary, ActionGetPasswordPolicy, ActionGetPublicAccessBlock},
}

// source.kind (config と同じ文字列)。
const (
	KindCredentialReport = "iam-credential-report"
	KindGuardDuty        = "guardduty"
	KindAccessAnalyzer   = "access-analyzer"
	KindPosture          = "posture"
)

// IAMAPI は IAM クライアントのうち使う部分。
type IAMAPI interface {
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
}

// GuardDutyAPI は GuardDuty クライアントのうち使う部分。
type GuardDutyAPI interface {
	ListDetectors(ctx context.Context, in *gd.ListDetectorsInput, optFns ...func(*gd.Options)) (*gd.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, in *gd.GetDetectorInput, optFns ...func(*gd.Options)) (*gd.GetDetectorOutput, error)
	ListFindings(ctx context.Context, in *gd.ListFindingsInput, optFns ...func(*gd.Options)) (*gd.ListFindingsOutput, error)
	GetFindings(ctx context.Context, in *gd.GetFindingsInput, optFns ...func(*gd.Options)) (*gd.GetFindingsOutput, error)
}

// AccessAnalyzerAPI は IAM Access Analyzer クライアントのうち使う部分。
type AccessAnalyzerAPI interface {
	ListAnalyzers(ctx context.Context, in *aa.ListAnalyzersInput, optFns ...func(*aa.Options)) (*aa.ListAnalyzersOutput, error)
	ListFindings(ctx context.Context, in *aa.ListFindingsInput, optFns ...func(*aa.Options)) (*aa.ListFindingsOutput, error)
}

// CloudTrailAPI は証跡の状態を見るのに使う部分。
type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, in *ct.DescribeTrailsInput, optFns ...func(*ct.Options)) (*ct.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *ct.GetTrailStatusInput, optFns ...func(*ct.Options)) (*ct.GetTrailStatusOutput, error)
}

// S3ControlAPI はアカウント単位の Public Access Block を見るのに使う部分。
type S3ControlAPI interface {
	GetPublicAccessBlock(ctx context.Context, in *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

// STSAPI はアカウント ID を知るのに使う (権限不要)。
type STSAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Clients はリージョン 1 つ分の SDK クライアントの束。テストではフェイクを入れる。
type Clients struct {
	Region         string
	IAM            IAMAPI
	GuardDuty      GuardDutyAPI
	AccessAnalyzer AccessAnalyzerAPI
	CloudTrail     CloudTrailAPI
	S3Control      S3ControlAPI
	STS            STSAPI
}

// base は collector の共通部。
type base struct {
	id      string
	clients []Clients
	// Sleep は認証情報レポートの生成待ち。テストでは即時に返す関数に差し替える。
	Sleep  func(ctx context.Context, d time.Duration) error
	Logger *slog.Logger
}

func newBase(id string, clients []Clients) base {
	return base{id: id, clients: clients, Sleep: sleepFor, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (b *base) ID() string { return b.id }

// SetSleep と SetLogger は engine が依存を入れる。
func (b *base) SetSleep(f func(ctx context.Context, d time.Duration) error) { b.Sleep = f }
func (b *base) SetLogger(l *slog.Logger)                                    { b.Logger = l }

// fail は action を添えた分類済みエラー。
func (b *base) fail(action string, err error) *collect.Error {
	return collect.Classify(b.id, action, err)
}

func snapshotTime(w collect.Window) time.Time {
	if w.CollectedAt.IsZero() {
		return time.Now()
	}
	return w.CollectedAt
}

func item(kind record.Kind, at time.Time, source, key string, data map[string]any) record.SnapshotItem {
	return record.SnapshotItem{Kind: kind, Time: at, Source: source, Key: key, Data: data}
}

func sleepFor(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func probe(action string, err error) collect.ProbeResult {
	return collect.ProbeResult{Action: action, Err: err}
}
