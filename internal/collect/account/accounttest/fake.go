// Package accounttest はアカウント単位の collector (認証情報レポート・GuardDuty・Access Analyzer・姿勢・WAF の設定) が使う SDK のフェイク。
package accounttest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	aa "github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go"

	"github.com/CircleAround/arata/internal/collect/account"
)

// APIError は smithy.APIError のフェイク。
type APIError struct{ Code string }

func (e APIError) Error() string                 { return e.Code }
func (e APIError) ErrorCode() string             { return e.Code }
func (e APIError) ErrorMessage() string          { return e.Code }
func (e APIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// Denied は AccessDenied のエラー。
var Denied = APIError{Code: "AccessDeniedException"}

// Fake は 1 アカウント分の状態。Errs に action (例: "guardduty:ListDetectors") → エラーを入れるとその API が失敗する。
type Fake struct {
	mu    sync.Mutex
	Errs  map[string]error
	Calls []string

	// IAM
	CredentialCSV []byte
	ReportTime    time.Time
	// ReportMissing なら GetCredentialReport は ReportNotPresent (Generate が通れば次から返す)。
	ReportMissing bool
	// InProgress 回だけ GetCredentialReport が ReportInProgress を返す。
	InProgress     int
	AccountSummary map[string]int32
	PasswordPolicy *iamtypes.PasswordPolicy // nil なら NoSuchEntity

	// GuardDuty: detector ID → 有効か (リージョン共通)
	Detectors  map[string]bool
	GDFindings []gdtypes.Finding

	// Access Analyzer
	Analyzers  []aatypes.AnalyzerSummary
	AAFindings []aatypes.FindingSummary

	// CloudTrail: 証跡と、ARN → ログ記録中か
	Trails  []cttypes.Trail
	Logging map[string]bool

	// S3 のアカウント単位の Public Access Block (nil なら未設定)
	PublicAccessBlock *s3types.PublicAccessBlockConfiguration

	// WAF は WAFv2 の WebACL (nil なら WebACL が無い)。
	WAF *WAF
}

// Clients は region のクライアントの束を返す (全部このフェイク)。
func (f *Fake) Clients(region string) account.Clients {
	return account.Clients{Region: region, IAM: f, GuardDuty: gdFake{f}, AccessAnalyzer: aaFake{f}, CloudTrail: f, S3Control: f, STS: f, WAFV2: wafFake{f, region}}
}

func (f *Fake) call(action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, action)
	return f.Errs[action]
}

// Called は action が呼ばれた回数。
func (f *Fake) Called(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c == action {
			n++
		}
	}
	return n
}

// CredentialRow は認証情報レポートの 1 行。日時は空なら N/A。
type CredentialRow struct {
	User, ARN                 string
	Password, MFA             bool
	PasswordLastUsed          time.Time
	Key1Active, Key2Active    bool
	Key1LastUsed, Key1Rotated time.Time
	Key2LastUsed, Key2Rotated time.Time
	PasswordNotSupported      bool // ルートの行
}

// CredentialReport は行から CSV を作る。
func CredentialReport(rows ...CredentialRow) []byte {
	var b strings.Builder
	b.WriteString("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n")
	tm := func(t time.Time) string {
		if t.IsZero() {
			return "N/A"
		}
		return t.UTC().Format("2006-01-02T15:04:05+00:00")
	}
	for _, r := range rows {
		pw := fmt.Sprint(r.Password)
		if r.PasswordNotSupported {
			pw = "not_supported"
		}
		fmt.Fprintf(&b, "%s,%s,2025-01-01T00:00:00+00:00,%s,%s,N/A,N/A,%t,%t,%s,%s,N/A,N/A,%t,%s,%s,N/A,N/A,false,N/A,false,N/A\n",
			r.User, r.ARN, pw, tm(r.PasswordLastUsed), r.MFA, r.Key1Active, tm(r.Key1Rotated), tm(r.Key1LastUsed), r.Key2Active, tm(r.Key2Rotated), tm(r.Key2LastUsed))
	}
	return []byte(b.String())
}

// --- IAM ---

func (f *Fake) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	if err := f.call(account.ActionGenerateCredentialReport); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.ReportMissing = false
	f.mu.Unlock()
	return &iam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeStarted}, nil
}

func (f *Fake) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	if err := f.call(account.ActionGetCredentialReport); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ReportMissing {
		return nil, APIError{Code: "ReportNotPresent"}
	}
	if f.InProgress > 0 {
		f.InProgress--
		return nil, APIError{Code: "ReportInProgress"}
	}
	return &iam.GetCredentialReportOutput{Content: f.CredentialCSV, GeneratedTime: aws.Time(f.ReportTime), ReportFormat: iamtypes.ReportFormatTypeTextCsv}, nil
}

func (f *Fake) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	if err := f.call(account.ActionGetAccountSummary); err != nil {
		return nil, err
	}
	return &iam.GetAccountSummaryOutput{SummaryMap: f.AccountSummary}, nil
}

func (f *Fake) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if err := f.call(account.ActionGetPasswordPolicy); err != nil {
		return nil, err
	}
	if f.PasswordPolicy == nil {
		return nil, APIError{Code: "NoSuchEntity"}
	}
	return &iam.GetAccountPasswordPolicyOutput{PasswordPolicy: f.PasswordPolicy}, nil
}

// --- GuardDuty ---

type gdFake struct{ *Fake }

func (f gdFake) ListDetectors(context.Context, *gd.ListDetectorsInput, ...func(*gd.Options)) (*gd.ListDetectorsOutput, error) {
	if err := f.call(account.ActionListDetectors); err != nil {
		return nil, err
	}
	out := &gd.ListDetectorsOutput{}
	for id := range f.Detectors {
		out.DetectorIds = append(out.DetectorIds, id)
	}
	return out, nil
}

func (f gdFake) GetDetector(_ context.Context, in *gd.GetDetectorInput, _ ...func(*gd.Options)) (*gd.GetDetectorOutput, error) {
	if err := f.call(account.ActionGetDetector); err != nil {
		return nil, err
	}
	st := gdtypes.DetectorStatusDisabled
	if f.Detectors[aws.ToString(in.DetectorId)] {
		st = gdtypes.DetectorStatusEnabled
	}
	return &gd.GetDetectorOutput{Status: st}, nil
}

// ListFindings は 2 件ずつページ分けして返す (ページングの確認用)。
func (f gdFake) ListFindings(_ context.Context, in *gd.ListFindingsInput, _ ...func(*gd.Options)) (*gd.ListFindingsOutput, error) {
	if err := f.call(account.ActionListGDFindings); err != nil {
		return nil, err
	}
	start := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	var ids []string
	for _, x := range f.GDFindings {
		if x.Service != nil && aws.ToBool(x.Service.Archived) {
			continue
		}
		ids = append(ids, aws.ToString(x.Id))
	}
	end := min(start+2, len(ids))
	out := &gd.ListFindingsOutput{FindingIds: ids[start:end]}
	if end < len(ids) {
		out.NextToken = aws.String(fmt.Sprint(end))
	}
	return out, nil
}

func (f gdFake) GetFindings(_ context.Context, in *gd.GetFindingsInput, _ ...func(*gd.Options)) (*gd.GetFindingsOutput, error) {
	if err := f.call(account.ActionGetGDFindings); err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, id := range in.FindingIds {
		want[id] = true
	}
	out := &gd.GetFindingsOutput{}
	for _, x := range f.GDFindings {
		if want[aws.ToString(x.Id)] {
			out.Findings = append(out.Findings, x)
		}
	}
	return out, nil
}

// GDFinding は GuardDuty の finding を組み立てる。
func GDFinding(id, typ string, severity float64, count int32) gdtypes.Finding {
	return gdtypes.Finding{Id: aws.String(id), Type: aws.String(typ), Title: aws.String(typ), Severity: aws.Float64(severity), Region: aws.String("ap-northeast-1"),
		UpdatedAt: aws.String("2026-10-20T00:00:00.000Z"), Resource: &gdtypes.Resource{ResourceType: aws.String("Instance")}, Service: &gdtypes.Service{Count: aws.Int32(count), Archived: aws.Bool(false)}}
}

// --- Access Analyzer ---

type aaFake struct{ *Fake }

func (f aaFake) ListAnalyzers(context.Context, *aa.ListAnalyzersInput, ...func(*aa.Options)) (*aa.ListAnalyzersOutput, error) {
	if err := f.call(account.ActionListAnalyzers); err != nil {
		return nil, err
	}
	return &aa.ListAnalyzersOutput{Analyzers: f.Analyzers}, nil
}

func (f aaFake) ListFindings(_ context.Context, in *aa.ListFindingsInput, _ ...func(*aa.Options)) (*aa.ListFindingsOutput, error) {
	if err := f.call(account.ActionListAAFindings); err != nil {
		return nil, err
	}
	out := &aa.ListFindingsOutput{}
	for _, x := range f.AAFindings {
		if x.Status == aatypes.FindingStatusActive {
			out.Findings = append(out.Findings, x)
		}
	}
	return out, nil
}

// Analyzer は ACTIVE なアカウントのアナライザー。
func Analyzer(name string) aatypes.AnalyzerSummary {
	return aatypes.AnalyzerSummary{Arn: aws.String("arn:aws:access-analyzer:ap-northeast-1:123456789012:analyzer/" + name), Name: aws.String(name),
		Status: aatypes.AnalyzerStatusActive, Type: aatypes.TypeAccount}
}

// AAFinding は Access Analyzer の finding を組み立てる。
func AAFinding(id, resource string, public bool, actions ...string) aatypes.FindingSummary {
	return aatypes.FindingSummary{Id: aws.String(id), Resource: aws.String(resource), ResourceType: aatypes.ResourceTypeAwsS3Bucket, IsPublic: aws.Bool(public),
		Status: aatypes.FindingStatusActive, Action: actions, Principal: map[string]string{"AWS": "*"}}
}

// --- CloudTrail ---

func (f *Fake) DescribeTrails(context.Context, *ct.DescribeTrailsInput, ...func(*ct.Options)) (*ct.DescribeTrailsOutput, error) {
	if err := f.call(account.ActionDescribeTrails); err != nil {
		return nil, err
	}
	return &ct.DescribeTrailsOutput{TrailList: f.Trails}, nil
}

func (f *Fake) GetTrailStatus(_ context.Context, in *ct.GetTrailStatusInput, _ ...func(*ct.Options)) (*ct.GetTrailStatusOutput, error) {
	if err := f.call(account.ActionGetTrailStatus); err != nil {
		return nil, err
	}
	return &ct.GetTrailStatusOutput{IsLogging: aws.Bool(f.Logging[aws.ToString(in.Name)])}, nil
}

// Trail は証跡を組み立てる。
func Trail(name string, multiRegion, validation bool) cttypes.Trail {
	return cttypes.Trail{Name: aws.String(name), TrailARN: aws.String("arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/" + name),
		IsMultiRegionTrail: aws.Bool(multiRegion), LogFileValidationEnabled: aws.Bool(validation)}
}

// --- S3 / STS ---

func (f *Fake) GetPublicAccessBlock(context.Context, *s3control.GetPublicAccessBlockInput, ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if err := f.call(account.ActionGetPublicAccessBlock); err != nil {
		return nil, err
	}
	if f.PublicAccessBlock == nil {
		return nil, APIError{Code: "NoSuchPublicAccessBlockConfiguration"}
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.PublicAccessBlock}, nil
}

func (f *Fake) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

// WAF は WAFv2 のフェイクの状態。WebACLs の key は "<scope>|<region>" (CLOUDFRONT は us-east-1 のクライアントだけが引ける)。
type WAF struct {
	WebACLs map[string][]waftypes.WebACL
	// Logging は WebACL の ARN → ログの送り先 (無ければ WAFNonexistentItemException)。
	Logging map[string][]string
	// Resources は WebACL の ARN → 資源の種類 → 関連付けた資源の ARN。
	Resources map[string]map[waftypes.ResourceType][]string
}

type wafFake struct {
	*Fake
	region string
}

func (f wafFake) ListWebACLs(_ context.Context, in *wafv2.ListWebACLsInput, _ ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
	if err := f.call(account.ActionListWebACLs); err != nil {
		return nil, err
	}
	out := &wafv2.ListWebACLsOutput{}
	if f.WAF == nil {
		return out, nil
	}
	acls := f.WAF.WebACLs[string(in.Scope)+"|"+f.region]
	// 1 ページ 1 件にしてページ送りを確かめる
	start := 0
	if in.NextMarker != nil {
		fmt.Sscan(*in.NextMarker, &start)
	}
	if start < len(acls) {
		a := acls[start]
		out.WebACLs = []waftypes.WebACLSummary{{ARN: a.ARN, Id: a.Id, Name: a.Name}}
		if start+1 < len(acls) {
			out.NextMarker = aws.String(fmt.Sprint(start + 1))
		}
	}
	return out, nil
}

func (f wafFake) GetWebACL(_ context.Context, in *wafv2.GetWebACLInput, _ ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error) {
	if err := f.call(account.ActionGetWebACL); err != nil {
		return nil, err
	}
	for _, a := range f.WAF.WebACLs[string(in.Scope)+"|"+f.region] {
		if aws.ToString(a.Id) == aws.ToString(in.Id) && aws.ToString(a.Name) == aws.ToString(in.Name) {
			a := a
			return &wafv2.GetWebACLOutput{WebACL: &a}, nil
		}
	}
	return nil, APIError{Code: "WAFNonexistentItemException"}
}

func (f wafFake) GetLoggingConfiguration(_ context.Context, in *wafv2.GetLoggingConfigurationInput, _ ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
	if err := f.call(account.ActionGetLoggingConfiguration); err != nil {
		return nil, err
	}
	dst, ok := f.WAF.Logging[aws.ToString(in.ResourceArn)]
	if !ok {
		return nil, APIError{Code: "WAFNonexistentItemException"}
	}
	return &wafv2.GetLoggingConfigurationOutput{LoggingConfiguration: &waftypes.LoggingConfiguration{ResourceArn: in.ResourceArn, LogDestinationConfigs: dst}}, nil
}

func (f wafFake) ListResourcesForWebACL(_ context.Context, in *wafv2.ListResourcesForWebACLInput, _ ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error) {
	if err := f.call(account.ActionListResourcesForWebACL); err != nil {
		return nil, err
	}
	return &wafv2.ListResourcesForWebACLOutput{ResourceArns: f.WAF.Resources[aws.ToString(in.WebACLArn)][in.ResourceType]}, nil
}

// WebACL は WebACL のフェイク。ARN は region と scope から作る。
func WebACL(scope waftypes.Scope, region, name string, rules ...waftypes.Rule) waftypes.WebACL {
	s := "regional"
	if scope == waftypes.ScopeCloudfront {
		s = "global"
	}
	return waftypes.WebACL{Name: aws.String(name), Id: aws.String(name + "-id"),
		ARN:           aws.String(fmt.Sprintf("arn:aws:wafv2:%s:123456789012:%s/webacl/%s/%s-id", region, s, name, name)),
		DefaultAction: &waftypes.DefaultAction{Allow: &waftypes.AllowAction{}}, Rules: rules}
}
