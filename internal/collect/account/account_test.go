package account_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/record"
)

var now = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

type sink struct{ items []record.SnapshotItem }

func (s *sink) Emit(_ context.Context, r record.Record) error {
	s.items = append(s.items, r.(record.SnapshotItem))
	return nil
}

func (s *sink) byKey() map[string]record.SnapshotItem {
	m := map[string]record.SnapshotItem{}
	for _, it := range s.items {
		m[it.Key] = it
	}
	return m
}

func noSleep(context.Context, time.Duration) error { return nil }

func collectWith(t *testing.T, c collect.Collector) (*sink, error) {
	t.Helper()
	s := &sink{}
	if x, ok := c.(interface {
		SetSleep(func(context.Context, time.Duration) error)
	}); ok {
		x.SetSleep(noSleep)
	}
	err := c.Collect(context.Background(), collect.Window{CollectedAt: now}, s)
	return s, err
}

func TestCredentialReport(t *testing.T) {
	f := &accounttest.Fake{ReportMissing: true, InProgress: 2, ReportTime: now.Add(-time.Minute), CredentialCSV: accounttest.CredentialReport(
		accounttest.CredentialRow{User: account.RootUser, ARN: "arn:aws:iam::123456789012:root", PasswordNotSupported: true, MFA: true, Key1Active: true, Key1Rotated: now.AddDate(-1, 0, 0)},
		accounttest.CredentialRow{User: "alice", ARN: "arn:aws:iam::123456789012:user/alice", Password: true, PasswordLastUsed: now.AddDate(0, 0, -1), Key2Active: true, Key2LastUsed: now.AddDate(0, 0, -100)},
	)}
	s, err := collectWith(t, account.NewCredentialReport("iam", f.Clients("ap-northeast-1")))
	if err != nil {
		t.Fatal(err)
	}
	if f.Called(account.ActionGetCredentialReport) != 3 { // 生成を頼んだ後 InProgress × 2 → 取得
		t.Fatalf("polls: %v", f.Calls)
	}
	items := s.byKey()
	alice := items["alice"]
	keys := alice.Data["access_keys"].([]any)
	k2 := keys[1].(map[string]any)
	if len(s.items) != 2 || alice.Kind != record.KindCredentialReport || !alice.Bool("password_enabled") || alice.Bool("mfa_active") ||
		k2["active"] != true || k2["last_used"] != "2026-07-13T09:00:00Z" || alice.String("report_generated_at") != "2026-10-21T08:59:00Z" || !alice.Time.Equal(now) {
		t.Fatalf("alice: %+v", alice)
	}
	if root := items[account.RootUser]; root.Bool("password_enabled") || root.Data["access_keys"].([]any)[0].(map[string]any)["active"] != true {
		t.Fatalf("root: %+v", root)
	}
}

func TestCredentialReportGenerateDenied(t *testing.T) {
	// 生成は拒否されたが 4 時間以内のレポートがある → それを使う
	f := &accounttest.Fake{Errs: map[string]error{account.ActionGenerateCredentialReport: accounttest.Denied}, ReportTime: now.Add(-3 * time.Hour),
		CredentialCSV: accounttest.CredentialReport(accounttest.CredentialRow{User: "bob", ARN: "arn:aws:iam::1:user/bob"})}
	s, err := collectWith(t, account.NewCredentialReport("iam", f.Clients("ap-northeast-1")))
	if err != nil || len(s.items) != 1 || s.items[0].String("report_generated_at") != "2026-10-21T06:00:00Z" {
		t.Fatalf("%v %+v", err, s.items)
	}
	// レポートも無い → ACCESS_DENIED (action は Generate)
	f.ReportMissing = true
	_, err = collectWith(t, account.NewCredentialReport("iam", f.Clients("ap-northeast-1")))
	ce := collect.Classify("iam", "", err)
	if ce.Code != collect.CodeAccessDenied || ce.Action != account.ActionGenerateCredentialReport {
		t.Fatalf("%+v", ce)
	}
	// 取得が拒否された
	f = &accounttest.Fake{Errs: map[string]error{account.ActionGetCredentialReport: accounttest.Denied}}
	_, err = collectWith(t, account.NewCredentialReport("iam", f.Clients("ap-northeast-1")))
	if ce := collect.Classify("iam", "", err); ce.Code != collect.CodeAccessDenied || ce.Action != account.ActionGetCredentialReport {
		t.Fatalf("%+v", ce)
	}
}

func TestGuardDuty(t *testing.T) {
	f := &accounttest.Fake{Detectors: map[string]bool{"d1": true}}
	archived := accounttest.GDFinding("f9", "Old", 8, 1)
	archived.Service.Archived = aws.Bool(true)
	f.GDFindings = append(f.GDFindings, accounttest.GDFinding("f1", "Recon:EC2/PortProbeUnprotectedPort", 2, 5), accounttest.GDFinding("f2", "UnauthorizedAccess:IAMUser/MaliciousIPCaller", 8.0, 1),
		accounttest.GDFinding("f3", "CryptoCurrency:EC2/BitcoinTool.B", 5, 3), archived)
	c := account.NewGuardDuty("gd", f.Clients("ap-northeast-1"))
	s, err := collectWith(t, c)
	if err != nil || len(s.items) != 3 || c.Unavailable() != nil {
		t.Fatalf("%v %+v", err, s.items)
	}
	if f2 := s.byKey()["f2"]; f2.Number("severity") != 8 || f2.Number("count") != 1 || f2.String("type") != "UnauthorizedAccess:IAMUser/MaliciousIPCaller" || f2.String("resource_type") != "Instance" {
		t.Fatalf("f2: %+v", f2)
	}
	// 無効 (detector 停止中 / 無し) なら取れない理由を返す
	for _, dets := range []map[string]bool{{"d1": false}, {}} {
		f.Detectors = dets
		s, err = collectWith(t, c)
		if err != nil || len(s.items) != 0 || c.Unavailable()[record.KindGuardDuty] != account.UnavailableGuardDuty {
			t.Fatalf("%v %+v %v", err, s.items, c.Unavailable())
		}
	}
	f.Errs = map[string]error{account.ActionListDetectors: accounttest.Denied}
	_, err = collectWith(t, c)
	if ce := collect.Classify("gd", "", err); ce.Code != collect.CodeAccessDenied || ce.Action != account.ActionListDetectors {
		t.Fatalf("%+v", ce)
	}
}

func TestAccessAnalyzer(t *testing.T) {
	f := &accounttest.Fake{}
	c := account.NewAccessAnalyzer("aa", f.Clients("ap-northeast-1"))
	s, err := collectWith(t, c)
	if err != nil || len(s.items) != 0 || c.Unavailable()[record.KindAccessAnalyzer] != account.UnavailableAnalyzer {
		t.Fatalf("%v %v", err, c.Unavailable())
	}
	f.Analyzers = append(f.Analyzers, accounttest.Analyzer("default"))
	f.AAFindings = append(f.AAFindings, accounttest.AAFinding("a1", "arn:aws:s3:::public-bucket", true, "s3:GetObject", "s3:ListBucket"))
	s, err = collectWith(t, c)
	if err != nil || len(s.items) != 1 || c.Unavailable() != nil {
		t.Fatalf("%v %+v", err, s.items)
	}
	if a := s.items[0]; a.Key != "a1" || !a.Bool("is_public") || a.String("actions") != "s3:GetObject,s3:ListBucket" || a.String("principal") != "AWS=*" || a.String("analyzer") != "default" {
		t.Fatalf("%+v", a)
	}
}

func TestPosture(t *testing.T) {
	f := &accounttest.Fake{
		Trails:         []cttypes.Trail{accounttest.Trail("main", true, true), accounttest.Trail("old", false, false)},
		Logging:        map[string]bool{"arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/main": true, "arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/old": true},
		Detectors:      map[string]bool{"d1": true},
		AccountSummary: map[string]int32{"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0},
		PasswordPolicy: &iamtypes.PasswordPolicy{MinimumPasswordLength: aws.Int32(8)},
	}
	c := account.NewPosture("posture", f.Clients("ap-northeast-1"), f.Clients("us-east-1"))
	s, err := collectWith(t, c)
	if err != nil || len(c.Problems()) != 0 {
		t.Fatalf("%v %v", err, c.Problems())
	}
	m := s.byKey()
	if len(m) != 6 {
		t.Fatalf("items: %v", m)
	}
	if ct := m[account.PostureCloudTrail]; !ct.Bool("multi_region_logging") || len(ct.Data["without_validation"].([]string)) != 1 {
		t.Fatalf("cloudtrail: %+v", ct)
	}
	if !m["guardduty|us-east-1"].Bool("enabled") || !m[account.PostureRootMFA].Bool("mfa_enabled") || m[account.PostureS3PublicAccess].Bool("configured") ||
		m[account.PosturePasswordPolicy].Number("minimum_length") != 8 {
		t.Fatalf("items: %+v", m)
	}
	// 一部が拒否されても他は取る。取れなかった項目は unknown で出し、Problems に action
	f.Errs = map[string]error{account.ActionGetPublicAccessBlock: accounttest.Denied, account.ActionGetDetector: accounttest.Denied}
	f.PublicAccessBlock = &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true)}
	s, err = collectWith(t, c)
	if err != nil {
		t.Fatal(err)
	}
	m = s.byKey()
	if !account.IsUnknown(m[account.PostureS3PublicAccess]) || m[account.PostureS3PublicAccess].String("action") != account.ActionGetPublicAccessBlock ||
		!account.IsUnknown(m["guardduty|ap-northeast-1"]) || account.IsUnknown(m[account.PostureRootMFA]) {
		t.Fatalf("items: %+v", m)
	}
	var actions []string
	for _, p := range c.Problems() {
		actions = append(actions, p.Code+":"+p.Action)
	}
	if strings.Join(actions, ",") != "ACCESS_DENIED:guardduty:GetDetector,ACCESS_DENIED:guardduty:GetDetector,ACCESS_DENIED:s3:GetAccountPublicAccessBlock" {
		t.Fatalf("problems: %v", actions)
	}
}

func TestProbe(t *testing.T) {
	f := &accounttest.Fake{Errs: map[string]error{account.ActionDescribeTrails: accounttest.Denied}, AccountSummary: map[string]int32{}}
	res := account.NewPosture("posture", f.Clients("ap-northeast-1")).Probe(context.Background())
	got := map[string]string{}
	for _, r := range res {
		v := "ok"
		if r.Err != nil {
			v = collect.Classify("", "", r.Err).Code
		}
		got[r.Action] = v + " " + r.Detail
	}
	if got[account.ActionDescribeTrails] != "ACCESS_DENIED " || got[account.ActionGetTrailStatus] != "ok cloudtrail:DescribeTrails が拒否されたため未確認" || got[account.ActionGetAccountSummary] != "ok " {
		t.Fatalf("%v", got)
	}
	// 認証情報レポートの Probe は Generate を呼ばない
	f = &accounttest.Fake{ReportMissing: true}
	res = account.NewCredentialReport("iam", f.Clients("ap-northeast-1")).Probe(context.Background())
	if f.Called(account.ActionGenerateCredentialReport) != 0 || res[0].Err != nil || !strings.Contains(res[1].Detail, "書き込み系") {
		t.Fatalf("%+v %v", res, f.Calls)
	}
}
