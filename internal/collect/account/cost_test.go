package account_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/record"
)

func anomaly(id string, total float64, feedback cetypes.AnomalyFeedbackType) cetypes.Anomaly {
	return cetypes.Anomaly{
		AnomalyId: aws.String(id), MonitorArn: aws.String("arn:aws:ce::123456789012:anomalymonitor/m1"),
		AnomalyStartDate: aws.String("2026-10-19"), AnomalyEndDate: aws.String("2026-10-20"), DimensionValue: aws.String("Amazon Elastic Compute Cloud - Compute"),
		Feedback: feedback, AnomalyScore: &cetypes.AnomalyScore{MaxScore: 0.9, CurrentScore: 0.8},
		Impact: &cetypes.Impact{TotalImpact: total, MaxImpact: total / 2, TotalActualSpend: aws.Float64(total + 10), TotalExpectedSpend: aws.Float64(10), TotalImpactPercentage: aws.Float64(1000)},
		RootCauses: []cetypes.RootCause{{Service: aws.String("Amazon Elastic Compute Cloud - Compute"), Region: aws.String("eu-west-1"), UsageType: aws.String("EU-BoxUsage:p3.16xlarge"),
			LinkedAccount: aws.String("123456789012"), LinkedAccountName: aws.String("example-account-name"), Impact: &cetypes.RootCauseImpact{Contribution: total}}},
	}
}

// 直近 lookback_days 日に終わった異常のうち総影響額が下限以上のものを、異常ごとに 1 項目で出す。
// 問い合わせは us-east-1 の 1 つのクライアントで、下限はサーバー側で絞る (ページ数 = 費用を減らす)。
func TestCostAnomalyCollect(t *testing.T) {
	f := &accounttest.Fake{Monitors: []cetypes.AnomalyMonitor{{MonitorArn: aws.String("arn:aws:ce::123456789012:anomalymonitor/m1"), MonitorName: aws.String("services")}},
		Anomalies: []cetypes.Anomaly{anomaly("a1", 1500, ""), anomaly("a2", 50, ""), anomaly("a3", 300, cetypes.AnomalyFeedbackTypeNo)}}
	c := account.NewCostAnomaly("cost", 7, 100, f.Clients("us-east-1"))
	s, err := collectWith(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Unavailable()) != 0 {
		t.Fatalf("unavailable: %v", c.Unavailable())
	}
	in := f.AnomalyCalls[0]
	if aws.ToString(in.DateInterval.StartDate) != "2026-10-14" || aws.ToString(in.DateInterval.EndDate) != "2026-10-21" {
		t.Fatalf("date interval: %+v", in.DateInterval)
	}
	if in.TotalImpact == nil || in.TotalImpact.NumericOperator != cetypes.NumericOperatorGreaterThanOrEqual || in.TotalImpact.StartValue != 100 {
		t.Fatalf("total impact filter: %+v", in.TotalImpact)
	}
	got := s.byKey()
	if len(got) != 2 || got["a2"].Key != "" {
		t.Fatalf("items: %v", got)
	}
	a1 := got["a1"]
	if a1.Kind != record.KindCostAnomaly || a1.Source != "cost" || a1.Data["total_impact"] != 1500.0 || a1.Data["start_date"] != "2026-10-19" ||
		a1.Data["dimension_value"] != "Amazon Elastic Compute Cloud - Compute" || a1.Data["feedback"] != "" {
		t.Fatalf("a1: %+v", a1)
	}
	rcs := a1.Data["root_causes"].([]map[string]any)
	if len(rcs) != 1 || rcs[0]["region"] != "eu-west-1" || rcs[0]["usage_type"] != "EU-BoxUsage:p3.16xlarge" || rcs[0]["linked_account"] != "123456789012" || rcs[0]["contribution"] != 1500.0 {
		t.Fatalf("root causes: %+v", rcs)
	}
	// 連結アカウントの名前 (利用者が付けた名前) は残さない
	if _, ok := rcs[0]["linked_account_name"]; ok {
		t.Fatal("linked account name must not be kept")
	}
	if got["a3"].Data["feedback"] != "NO" {
		t.Fatalf("feedback is kept for the check: %+v", got["a3"])
	}
}

// モニターが無ければ取れない (チェックは skip、理由に作り方の案内)。異常は問い合わせない (費用をかけない)。
func TestCostAnomalyNoMonitor(t *testing.T) {
	f := &accounttest.Fake{}
	c := account.NewCostAnomaly("cost", 7, 100, f.Clients("us-east-1"))
	if _, err := collectWith(t, c); err != nil {
		t.Fatal(err)
	}
	if c.Unavailable()[record.KindCostAnomaly] != account.UnavailableCostAnomaly || f.Called(account.ActionGetAnomalies) != 0 {
		t.Fatalf("unavailable: %v calls %v", c.Unavailable(), f.Calls)
	}
	res := c.Probe(context.Background())
	if len(res) != 2 || res[0].Action != account.ActionGetAnomalyMonitors || res[0].Warn == "" || res[0].Err != nil {
		t.Fatalf("probe: %+v", res)
	}

	f = &accounttest.Fake{Errs: map[string]error{account.ActionGetAnomalyMonitors: accounttest.Denied}}
	c = account.NewCostAnomaly("cost", 7, 100, f.Clients("us-east-1"))
	_, err := collectWith(t, c)
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeAccessDenied || ce.Action != account.ActionGetAnomalyMonitors {
		t.Fatalf("denied: %v", err)
	}
}
