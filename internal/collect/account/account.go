// Package account はアカウント単位の状態 (スナップショット) を取る collector を持つ: IAM 認証情報レポート、GuardDuty の findings、
// IAM Access Analyzer の findings、姿勢 (CloudTrail 証跡・GuardDuty 有効・ルート MFA・S3 Public Access Block・パスワードポリシー・
// インターネット向けの ALB の WebACL)、
// WAFv2 の WebACL の設定。
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
	acc "github.com/aws/aws-sdk-go-v2/service/account"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	ce "github.com/aws/aws-sdk-go-v2/service/costexplorer"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// IAM の action。
const (
	ActionGenerateCredentialReport = "iam:GenerateCredentialReport" // 書き込み系 (レポートの生成のみ。他に副作用は無い)
	ActionGetCredentialReport      = "iam:GetCredentialReport"      // #nosec G101 -- 名前に credential を含むだけの種類の識別子で、秘密の値ではない
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
	ActionListWebACLs              = "wafv2:ListWebACLs"
	ActionGetWebACL                = "wafv2:GetWebACL"
	ActionGetLoggingConfiguration  = "wafv2:GetLoggingConfiguration"
	ActionListResourcesForWebACL   = "wafv2:ListResourcesForWebACL"
	ActionDescribeLoadBalancers    = "elasticloadbalancing:DescribeLoadBalancers"
	ActionGetWebACLForResource     = "wafv2:GetWebACLForResource"
	ActionListRegions              = "account:ListRegions"
	ActionLookupEvents             = "cloudtrail:LookupEvents"
	ActionGetAnomalyMonitors       = "ce:GetAnomalyMonitors"
	ActionGetAnomalies             = "ce:GetAnomalies"
)

// RequiredActions は source.kind ごとに読み取りロールへ付ける action (doctor の表の最後に出す)。
var RequiredActions = map[string][]string{
	KindCredentialReport: {ActionGenerateCredentialReport, ActionGetCredentialReport},
	KindGuardDuty:        {ActionListDetectors, ActionListGDFindings, ActionGetGDFindings},
	KindAccessAnalyzer:   {ActionListAnalyzers, ActionListAAFindings},
	KindPosture: {ActionDescribeTrails, ActionGetTrailStatus, ActionListDetectors, ActionGetDetector, ActionGetAccountSummary, ActionGetPasswordPolicy, ActionGetPublicAccessBlock,
		ActionDescribeLoadBalancers, ActionGetWebACLForResource},
	KindWAFConfig: {ActionListWebACLs, ActionGetWebACL, ActionGetLoggingConfiguration, ActionListResourcesForWebACL},
	// cloudtrail-unused-regions の collector は internal/collect/cloudtrail にあるが、action はここにまとめる (doctor と読み取りロールの突き合わせ)
	KindUnusedRegions: {ActionListRegions, ActionLookupEvents},
	KindCostAnomaly:   {ActionGetAnomalyMonitors, ActionGetAnomalies},
}

// source.kind (config と同じ文字列)。
const (
	KindCredentialReport = "iam-credential-report" // #nosec G101 -- 名前に credential を含むだけの種類の識別子で、秘密の値ではない
	KindGuardDuty        = "guardduty"
	KindAccessAnalyzer   = "access-analyzer"
	KindPosture          = "posture"
	KindWAFConfig        = "waf-config"
	KindUnusedRegions    = "cloudtrail-unused-regions"
	KindCostAnomaly      = "cost-anomaly"
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

// WAFV2API は WAFv2 クライアントのうち使う部分 (読み取りのみ)。
type WAFV2API interface {
	ListWebACLs(ctx context.Context, in *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	GetWebACL(ctx context.Context, in *wafv2.GetWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error)
	GetLoggingConfiguration(ctx context.Context, in *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error)
	ListResourcesForWebACL(ctx context.Context, in *wafv2.ListResourcesForWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error)
	GetWebACLForResource(ctx context.Context, in *wafv2.GetWebACLForResourceInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLForResourceOutput, error)
}

// ELBV2API は Elastic Load Balancing v2 のうち使う部分 (ALB の一覧だけ。posture の alb_waf。ADR 0048)。
type ELBV2API interface {
	DescribeLoadBalancers(ctx context.Context, in *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
}

// AccountAPI は Account Management のうち使う部分 (有効なリージョンの一覧。cloudtrail-unused-regions)。
type AccountAPI interface {
	ListRegions(ctx context.Context, in *acc.ListRegionsInput, optFns ...func(*acc.Options)) (*acc.ListRegionsOutput, error)
}

// CostExplorerAPI は Cost Explorer のうち使う部分 (Cost Anomaly Detection の読み取りだけ)。
type CostExplorerAPI interface {
	GetAnomalyMonitors(ctx context.Context, in *ce.GetAnomalyMonitorsInput, optFns ...func(*ce.Options)) (*ce.GetAnomalyMonitorsOutput, error)
	GetAnomalies(ctx context.Context, in *ce.GetAnomaliesInput, optFns ...func(*ce.Options)) (*ce.GetAnomaliesOutput, error)
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
	WAFV2          WAFV2API
	ELBV2          ELBV2API
	Account        AccountAPI
	CostExplorer   CostExplorerAPI
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
