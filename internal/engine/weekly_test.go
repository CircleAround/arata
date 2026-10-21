package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

const weeklySources = `  - id: iam
    kind: iam-credential-report
  - id: gd
    kind: guardduty
  - id: aa
    kind: access-analyzer
  - id: posture
    kind: posture
`

// weeklyProfiles は harness の daily / weekly (default-weekly) に hourly を足す。
const weeklyProfiles = `  hourly:
    window: 1h
    checks: [root_usage]
`

// healthyAccount は問題の無いアカウント。
func healthyAccount(f *accounttest.Fake, now time.Time) {
	f.ReportTime = now
	f.CredentialCSV = accounttest.CredentialReport(accounttest.CredentialRow{User: account.RootUser, ARN: "arn:aws:iam::" + acct + ":root", PasswordNotSupported: true, MFA: true})
	f.Detectors = map[string]bool{"d1": true}
	f.Analyzers = append(f.Analyzers[:0], accounttest.Analyzer("default"))
	f.Trails = []cttypes.Trail{accounttest.Trail("main", true, true)}
	f.Logging = map[string]bool{"arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/main": true}
	f.AccountSummary = map[string]int32{"AccountMFAEnabled": 1}
	f.PasswordPolicy = &iamtypes.PasswordPolicy{MinimumPasswordLength: aws.Int32(14)}
	f.PublicAccessBlock = &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}
}

func classes(rep *report.Report) map[string]string {
	out := map[string]string{}
	add := func(class string, fs []report.Finding) {
		for _, f := range fs {
			out[f.Check+"/"+f.Key] = class
		}
	}
	add("new", rep.Findings.New)
	add("changed", rep.Findings.Changed)
	add("resolved", rep.Findings.Resolved)
	add("still_open", rep.Findings.StillOpen)
	return out
}

func TestWeeklyRun(t *testing.T) {
	h := newHarnessWith(t, weeklySources, weeklyProfiles)
	healthyAccount(h.acct, h.now)
	h.acct.CredentialCSV = accounttest.CredentialReport(
		accounttest.CredentialRow{User: "alice", ARN: "arn:aws:iam::" + acct + ":user/alice", Password: true, Key1Active: true, Key1LastUsed: h.now.AddDate(0, 0, -120)})
	h.acct.GDFindings = append(h.acct.GDFindings, accounttest.GDFinding("g1", "UnauthorizedAccess:IAMUser/MaliciousIPCaller", 8, 1))
	h.acct.AAFindings = append(h.acct.AAFindings, accounttest.AAFinding("a1", "arn:aws:s3:::public", true, "s3:GetObject"))
	h.acct.AccountSummary = map[string]int32{"AccountMFAEnabled": 0}
	e := h.open(t)
	ctx := context.Background()

	// hourly はアカウント単位のソースを引かない (プロファイルが必要とするレコードだけを収集する)
	if _, err := e.Run(ctx, "hourly"); err != nil {
		t.Fatal(err)
	}
	if len(h.acct.Calls) != 0 {
		t.Fatalf("hourly must not call account APIs: %v", h.acct.Calls)
	}

	res, err := e.Run(ctx, "weekly")
	if err != nil || res.Exit != ExitOK {
		t.Fatalf("%v %+v", err, res)
	}
	got := classes(res.Report)
	for _, k := range []string{"credential_hygiene/no_mfa|alice", "credential_hygiene/unused_key|alice|1", "guardduty_findings/g1", "posture/root_mfa", "access_analyzer/a1"} {
		if got[k] != "new" {
			t.Errorf("%s: %q (%v)", k, got[k], got)
		}
	}
	if len(got) != 5 || res.Report.Summary.MaxSeverity != "high" {
		t.Fatalf("%v %s", got, res.Report.Summary.MaxSeverity)
	}
	if strings.Join(res.Report.Coverage.ChecksRun, ",") != "access_analyzer,credential_hygiene,guardduty_findings,posture" {
		t.Fatalf("checks_run: %v", res.Report.Coverage.ChecksRun)
	}

	// 翌週: ルート MFA を有効にし、GuardDuty の件数が増え、Access Analyzer の finding がアーカイブされた
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.acct.AccountSummary = map[string]int32{"AccountMFAEnabled": 1}
	h.acct.GDFindings[0].Service.Count = aws.Int32(4)
	h.acct.AAFindings = nil
	res, err = e.Run(ctx, "weekly")
	if err != nil {
		t.Fatal(err)
	}
	got = classes(res.Report)
	want := map[string]string{"posture/root_mfa": "resolved", "access_analyzer/a1": "resolved", "guardduty_findings/g1": "changed",
		"credential_hygiene/no_mfa|alice": "still_open", "credential_hygiene/unused_key|alice|1": "still_open"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	// 状態遷移の履歴 (new 5 + changed 1 + resolved 2)
	evs, err := e.Store().FindingEvents(ctx, h.now.Add(-30*24*time.Hour), h.now.Add(time.Hour))
	if err != nil || len(evs) != 8 || evs[0].Profile != "weekly" || evs[0].RunID == "" {
		t.Fatalf("finding events: %d %+v %v", len(evs), evs, err)
	}
}

func TestWeeklyUnavailableAndDenied(t *testing.T) {
	h := newHarnessWith(t, weeklySources, weeklyProfiles)
	healthyAccount(h.acct, h.now)
	h.acct.GDFindings = append(h.acct.GDFindings, accounttest.GDFinding("g1", "Recon:EC2/Portscan", 5, 1))
	e := h.open(t)
	ctx := context.Background()
	if _, err := e.Run(ctx, "weekly"); err != nil {
		t.Fatal(err)
	}

	// GuardDuty が無効になった / アナライザーが消えた → そのチェックは skip (理由付き)。無効であることは posture が報告。前回の finding は resolved にしない
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.acct.Detectors = map[string]bool{"d1": false}
	h.acct.Analyzers = nil
	res, err := e.Run(ctx, "weekly")
	if err != nil || res.Exit != ExitOK {
		t.Fatalf("%v %+v", err, res)
	}
	skipped := map[string]string{}
	for _, s := range res.Report.Coverage.ChecksSkipped {
		skipped[s.Check] = s.Reason
	}
	if skipped["guardduty_findings"] != "gd: "+account.UnavailableGuardDuty || skipped["access_analyzer"] != "aa: "+account.UnavailableAnalyzer {
		t.Fatalf("skipped: %v", skipped)
	}
	got := classes(res.Report)
	if got["posture/guardduty_enabled|ap-northeast-1"] != "new" || got["guardduty_findings/g1"] != "" {
		t.Fatalf("%v", got)
	}

	// 権限不足: GuardDuty のソースは ListFindings が拒否 → guardduty_findings だけ skip (他は続行)。
	// posture は S3 だけ拒否 → 取れた項目で評価し、S3 の前回の finding は維持。coverage に partial と action、終了コード 3
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.acct.Detectors = map[string]bool{"d1": true}
	h.acct.PublicAccessBlock = nil // 未設定 (ng) を一度報告させる
	if _, err := e.Run(ctx, "weekly"); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(7 * 24 * time.Hour)
	h.acct.Errs = map[string]error{account.ActionListGDFindings: accounttest.Denied, account.ActionGetPublicAccessBlock: accounttest.Denied}
	h.stderr.Reset()
	res, err = e.Run(ctx, "weekly")
	if err != nil || res.Exit != ExitPartial {
		t.Fatalf("%v %+v", err, res)
	}
	var failed []string
	for _, f := range res.Report.Coverage.SourcesFailed {
		failed = append(failed, f.Source+":"+f.Code+":"+f.Action+":"+map[bool]string{true: "partial", false: "failed"}[f.Partial])
	}
	if strings.Join(failed, ",") != "gd:ACCESS_DENIED:guardduty:ListFindings:failed,posture:ACCESS_DENIED:s3:GetAccountPublicAccessBlock:partial" {
		t.Fatalf("sources_failed: %v", failed)
	}
	if !strings.Contains(strings.Join(res.Report.Coverage.ChecksRun, ","), "posture") || strings.Contains(strings.Join(res.Report.Coverage.ChecksRun, ","), "guardduty_findings") {
		t.Fatalf("checks_run: %v", res.Report.Coverage.ChecksRun)
	}
	got = classes(res.Report)
	if got["posture/s3_public_access_block"] != "still_open" || got["guardduty_findings/g1"] != "" {
		t.Fatalf("%v", got)
	}
	open, _ := e.Store().Findings(ctx, "guardduty_findings", []string{store.FindingOpen})
	if len(open) != 1 {
		t.Fatalf("guardduty finding must stay open while the source fails: %+v", open)
	}
	if codes := strings.Join(h.logCodes(t), ","); !strings.Contains(codes, "ACCESS_DENIED") {
		t.Fatalf("codes: %s", codes)
	}
	// 失敗したソースのスナップショットは前回のまま
	if items, _ := e.Store().Snapshot(ctx, record.KindGuardDuty); len(items) != 1 {
		t.Fatalf("snapshot must be kept: %+v", items)
	}
}
