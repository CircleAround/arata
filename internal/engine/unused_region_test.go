package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	acctypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

const unusedSources = `  - id: unused
    kind: cloudtrail-unused-regions
  - id: cost
    kind: cost-anomaly
`

// regionFakes は harness の CloudTrail をリージョンごとのフェイクにする (ふだん使うリージョンは h.fake)。
func regionFakes(h *harness, unused map[string]*cloudtrailtest.Fake) {
	h.acct.Regions = map[string]acctypes.RegionOptStatus{"ap-northeast-1": acctypes.RegionOptStatusEnabledByDefault, "us-east-1": acctypes.RegionOptStatusEnabledByDefault,
		"af-south-1": acctypes.RegionOptStatusDisabled}
	for r := range unused {
		h.acct.Regions[r] = acctypes.RegionOptStatusEnabledByDefault
	}
	h.deps.CloudTrail = func(ctx context.Context, cfg *config.Config, src config.Source, region string) (cloudtrail.API, error) {
		h.regions = append(h.regions, src.ID+":"+region)
		if f, ok := unused[region]; ok {
			return f, nil
		}
		return h.fake, nil
	}
}

func checkFindings(rep *report.Report, check string) []report.Finding {
	var out []report.Finding
	for _, fs := range [][]report.Finding{rep.Findings.New, rep.Findings.Changed, rep.Findings.Recurred, rep.Findings.StillOpen} {
		for _, f := range fs {
			if f.Check == check {
				out = append(out, f)
			}
		}
	}
	return out
}

// ふだん使わないリージョンの書き込みは unused_region_activity だけが報告し、既存のチェック (defense_evasion・public_exposure・access_denied・
// new_principal・principal_new_source) の結果を変えない。
func TestUnusedRegionRun(t *testing.T) {
	h := newHarnessWith(t, unusedSources, "")
	eu := &cloudtrailtest.Fake{}
	regionFakes(h, map[string]*cloudtrailtest.Fake{"eu-west-1": eu})
	h.acct.Monitors = []cetypes.AnomalyMonitor{{MonitorArn: aws.String("arn:aws:ce::" + acct + ":anomalymonitor/m1")}}
	in := h.now.Add(-2 * time.Hour)
	mallory := cloudtrailtest.User(acct, "mallory")
	eu.Add(
		cloudtrailtest.Event("u1", in, mallory, "ec2.amazonaws.com", "RunInstances", "eu-west-1", "203.0.113.9", false, map[string]any{"instanceType": "p3.16xlarge"}),
		cloudtrailtest.Event("u2", in.Add(time.Minute), mallory, "ec2.amazonaws.com", "DeleteFlowLogs", "eu-west-1", "203.0.113.9", false, map[string]any{"DeleteFlowLogsRequest": map[string]any{"FlowLogId": map[string]any{"content": "fl-1"}}}),
		cloudtrailtest.Event("u3", in.Add(2*time.Minute), mallory, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", "eu-west-1", "203.0.113.9", false,
			map[string]any{"groupId": "sg-1", "ipPermissions": map[string]any{"items": []any{map[string]any{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": map[string]any{"items": []any{map[string]any{"cidrIp": "0.0.0.0/0"}}}}}}}),
	)
	for i := 0; i < 30; i++ {
		eu.Add(cloudtrailtest.WithError(cloudtrailtest.Event("d"+string(rune('a'+i)), in.Add(time.Duration(i)*time.Second), mallory, "ec2.amazonaws.com", "CreateKeyPair", "eu-west-1", "203.0.113.9", false, nil), "Client.UnauthorizedOperation"))
	}
	e := h.open(t)
	ctx := context.Background()
	res, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	rep := res.Report
	got := checkFindings(rep, "unused_region_activity")
	if len(got) != 1 || got[0].Severity != "critical" || got[0].Key != "eu-west-1|arn:aws:iam::"+acct+":user/mallory" {
		t.Fatalf("unused_region_activity: %+v", got)
	}
	for _, c := range []string{"defense_evasion", "public_exposure", "access_denied", "new_principal", "principal_new_source", "iam_changes"} {
		if fs := checkFindings(rep, c); len(fs) != 0 {
			t.Fatalf("%s must not see unused-region events: %+v", c, fs)
		}
	}
	// 未使用リージョンの主体は principals に入れない (new_principal の対象を変えない)
	ps, err := e.Store().Principals(ctx, store.PrincipalFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if strings.Contains(p.ARN, "mallory") {
			t.Fatalf("principal from unused region: %+v", p)
		}
	}
	// 未使用リージョンの LookupEvents は 1 回、ふだん使うリージョンは cloudtrail-lookup だけが引く
	if len(eu.Calls) != 1 || strings.Join(h.regions, ",") != "trail:ap-northeast-1,trail:us-east-1,unused:eu-west-1" {
		t.Fatalf("calls: %d regions %v", len(eu.Calls), h.regions)
	}
	run, _ := e.Store().LastRun(ctx, "daily", nil)
	if run.Stats["unused_region_events"] != 33.0 || run.Stats["unused_regions_scanned"] != "eu-west-1" || run.Stats["denied_events"] != 0.0 {
		t.Fatalf("stats: %+v", run.Stats)
	}
}

// ListRegions が拒否されたら unused_region_activity だけを skip し (0 件と誤らない)、他は続ける。
func TestUnusedRegionDenied(t *testing.T) {
	h := newHarnessWith(t, unusedSources, "")
	regionFakes(h, map[string]*cloudtrailtest.Fake{})
	h.acct.Errs = map[string]error{account.ActionListRegions: accounttest.Denied}
	e := h.open(t)
	res, err := e.Run(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	skipped := map[string]string{}
	for _, s := range res.Report.Coverage.ChecksSkipped {
		skipped[s.Check] = s.Reason
	}
	if _, ok := skipped["unused_region_activity"]; !ok {
		t.Fatalf("skipped: %v", skipped)
	}
	if _, ok := skipped["defense_evasion"]; ok {
		t.Fatal("other checks keep running")
	}
	// モニターが無いので cost_anomaly も skip (理由に作り方)
	if !strings.Contains(skipped["cost_anomaly"], "モニター") {
		t.Fatalf("cost_anomaly skip reason: %q", skipped["cost_anomaly"])
	}
	if res.Exit != ExitPartial {
		t.Fatalf("exit: %d", res.Exit)
	}
}

// cost_anomaly は Cost Anomaly Detection の異常を予想に対する割合で報告する。Cost Explorer は us-east-1 で引く。
func TestCostAnomalyRun(t *testing.T) {
	h := newHarnessWith(t, unusedSources, "")
	regionFakes(h, map[string]*cloudtrailtest.Fake{})
	h.acct.Monitors = []cetypes.AnomalyMonitor{{MonitorArn: aws.String("arn:aws:ce::" + acct + ":anomalymonitor/m1")}}
	h.acct.Anomalies = []cetypes.Anomaly{{AnomalyId: aws.String("an-1"), DimensionValue: aws.String("Amazon Elastic Compute Cloud - Compute"),
		AnomalyStartDate: aws.String("2026-10-20"), AnomalyEndDate: aws.String("2026-10-21"),
		Impact: &cetypes.Impact{TotalImpact: 90, TotalExpectedSpend: aws.Float64(30), TotalActualSpend: aws.Float64(120), TotalImpactPercentage: aws.Float64(300)}}}
	var regions []string
	acctFn := h.deps.Account
	h.deps.Account = func(ctx context.Context, cfg *config.Config, src config.Source, region string) (account.Clients, error) {
		regions = append(regions, src.ID+":"+region)
		return acctFn(ctx, cfg, src, region)
	}
	e := h.open(t)
	res, err := e.Run(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	got := checkFindings(res.Report, "cost_anomaly")
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Summary, "+300%") {
		t.Fatalf("cost_anomaly: %+v", got)
	}
	if !strings.Contains(strings.Join(regions, ","), "cost:us-east-1") {
		t.Fatalf("cost explorer region: %v", regions)
	}
	// weekly は daily のソースを引かない
	n := h.acct.Called(account.ActionGetAnomalies)
	if _, err := e.Run(context.Background(), "weekly"); err != nil {
		t.Fatal(err)
	}
	if h.acct.Called(account.ActionGetAnomalies) != n {
		t.Fatal("weekly must not call GetAnomalies")
	}
}

func doctorRows(r *DoctorResult, src string) []DoctorRow {
	var out []DoctorRow
	for _, row := range r.Rows {
		if row.Source == src {
			out = append(out, row)
		}
	}
	return out
}

// doctor は未使用リージョンの一覧 (ListRegions) と各リージョンの LookupEvents を試し、費用の行 (無料) を出す。
// cost-anomaly はモニターが無ければ warn (作り方の案内) にし、Cost Explorer の API の費用の見込みを出す。
func TestDoctorUnusedRegionsAndCostAnomaly(t *testing.T) {
	h := newHarnessWith(t, unusedSources, "")
	eu, sa := &cloudtrailtest.Fake{}, &cloudtrailtest.Fake{Err: cloudtrailtest.APIError{Code: "AccessDeniedException"}}
	regionFakes(h, map[string]*cloudtrailtest.Fake{"eu-west-1": eu, "sa-east-1": sa})
	res := Doctor(context.Background(), h.cfg, h.deps, time.Hour)
	var lines []string
	for _, row := range doctorRows(res, "unused") {
		lines = append(lines, row.Item+" "+row.Status+" "+row.Detail)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"permission ok account:ListRegions (有効なリージョン 4、ふだん使うリージョン ap-northeast-1, us-east-1 を除く 2: eu-west-1, sa-east-1)",
		"permission ok cloudtrail:LookupEvents (eu-west-1)",
		"permission ng cloudtrail:LookupEvents が拒否された: cloudtrail:LookupEvents (sa-east-1)",
		"cost ok LookupEvents は無料",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor rows lack %q:\n%s", want, got)
		}
	}
	if len(eu.Calls) != 1 || aws.ToInt32(eu.Calls[0].MaxResults) != 1 {
		t.Fatalf("probe calls: %+v", eu.Calls)
	}

	// モニターが無い → warn。費用は daily 1 回 × 2 リクエスト × 0.01 USD
	lines = nil
	for _, row := range doctorRows(res, "cost") {
		lines = append(lines, row.Item+" "+row.Status+" "+row.Detail)
	}
	got = strings.Join(lines, "\n")
	for _, want := range []string{"permission warn ce:GetAnomalyMonitors (us-east-1): AWS Cost Anomaly Detection のモニターが無い", "permission ok ce:GetAnomalies (us-east-1)",
		"cost ok Cost Explorer の API 1 リクエスト 0.01 USD。daily: 1 日 1 回 × 2 リクエスト → 約 0.02 USD/日・0.60 USD/30 日"} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor rows lack %q:\n%s", want, got)
		}
	}
	for _, a := range []string{"account:ListRegions", "ce:GetAnomalies", "ce:GetAnomalyMonitors"} {
		if !strings.Contains(strings.Join(res.RequiredActions, ","), a) {
			t.Fatalf("required actions lack %s: %v", a, res.RequiredActions)
		}
	}
}
