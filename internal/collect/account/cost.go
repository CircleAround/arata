package account

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ce "github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// UnavailableCostAnomaly はモニターが無いときの skip の理由 (作り方の案内)。
const UnavailableCostAnomaly = "AWS Cost Anomaly Detection のモニターが無い (Billing and Cost Management の Cost Anomaly Detection で " +
	"AWS のサービスを見るモニター (AWS::CE::AnomalyMonitor、無料) を作ると検査できる)"

// CostExplorerUSDPerRequest は Cost Explorer の API の 1 リクエスト (ページ) の料金 (USD)。doctor の費用の見込みに使う。
// 決定 (ADR 0032): 公式の料金表は Cost Explorer の API を 1 リクエスト 0.01 USD とし、GetAnomalies / GetAnomalyMonitors が対象かを明記していないので、対象とみなす。
const CostExplorerUSDPerRequest = 0.01

// CostAnomaly は AWS Cost Anomaly Detection の異常を取り、異常ごとに 1 項目を出す collector (cost-anomaly → cost_anomaly。ADR 0032)。
//
// 決定:
//   - Cost Explorer の API は us-east-1 だけなので、クライアントは 1 つ (最初のもの) だけを使う
//   - 先に GetAnomalyMonitors でモニターの有無を見る。無ければ Unavailable (チェックは skip) にし、GetAnomalies は呼ばない
//   - GetAnomalies は直近 lookbackDays 日に終わった (続いている) 異常を、総影響額 >= minImpactUSD でサーバー側で絞って引く
//     (ページ数 = 費用。多くは 1 ページ)。1 回の収集で 0.01 USD × (1 + ページ数)
//   - 連結アカウントの名前 (LinkedAccountName) は利用者が付けた名前なので残さない。ID だけ
type CostAnomaly struct {
	base
	lookbackDays int
	minImpactUSD float64
	unavailable  map[record.Kind]string
}

var (
	_ collect.Collector            = (*CostAnomaly)(nil)
	_ collect.AvailabilityReporter = (*CostAnomaly)(nil)
	_ collect.Prober               = (*CostAnomaly)(nil)
)

// NewCostAnomaly は collector を作る。clients は us-east-1 のもの。
func NewCostAnomaly(id string, lookbackDays int, minImpactUSD float64, clients ...Clients) *CostAnomaly {
	return &CostAnomaly{base: newBase(id, clients), lookbackDays: lookbackDays, minImpactUSD: minImpactUSD}
}

func (c *CostAnomaly) Yields() []record.Kind { return []record.Kind{record.KindCostAnomaly} }

func (c *CostAnomaly) Unavailable() map[record.Kind]string { return c.unavailable }

// monitors はモニターの数。
func monitors(ctx context.Context, api CostExplorerAPI) (int, error) {
	n := 0
	in := &ce.GetAnomalyMonitorsInput{}
	for {
		out, err := api.GetAnomalyMonitors(ctx, in)
		if err != nil {
			return 0, err
		}
		n += len(out.AnomalyMonitors)
		if out.NextPageToken == nil || *out.NextPageToken == "" || n > 0 {
			// 有無だけが要るので、1 件でもあれば次のページは引かない (費用)
			return n, nil
		}
		in.NextPageToken = out.NextPageToken
	}
}

func (c *CostAnomaly) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.unavailable = nil
	if len(c.clients) == 0 {
		return nil
	}
	api := c.clients[0].CostExplorer
	n, err := monitors(ctx, api)
	if err != nil {
		return c.fail(ActionGetAnomalyMonitors, err)
	}
	if n == 0 {
		c.unavailable = map[record.Kind]string{record.KindCostAnomaly: UnavailableCostAnomaly}
		return nil
	}
	at := snapshotTime(w)
	in := &ce.GetAnomaliesInput{
		DateInterval: &cetypes.AnomalyDateInterval{
			StartDate: aws.String(at.UTC().AddDate(0, 0, -c.lookbackDays).Format(record.DateLayout)),
			EndDate:   aws.String(at.UTC().Format(record.DateLayout)),
		},
		TotalImpact: &cetypes.TotalImpactFilter{NumericOperator: cetypes.NumericOperatorGreaterThanOrEqual, StartValue: c.minImpactUSD},
	}
	for {
		out, err := api.GetAnomalies(ctx, in)
		if err != nil {
			return c.fail(ActionGetAnomalies, err)
		}
		for _, a := range out.Anomalies {
			id := aws.ToString(a.AnomalyId)
			if id == "" {
				continue
			}
			if err := sink.Emit(ctx, item(record.KindCostAnomaly, at, c.id, id, anomalyData(a))); err != nil {
				return err
			}
		}
		if out.NextPageToken == nil || *out.NextPageToken == "" {
			return nil
		}
		in.NextPageToken = out.NextPageToken
	}
}

func anomalyData(a cetypes.Anomaly) map[string]any {
	d := map[string]any{
		"monitor_arn":     aws.ToString(a.MonitorArn),
		"dimension_value": aws.ToString(a.DimensionValue),
		"start_date":      aws.ToString(a.AnomalyStartDate),
		"end_date":        aws.ToString(a.AnomalyEndDate),
		"feedback":        string(a.Feedback),
	}
	if im := a.Impact; im != nil {
		d["total_impact"] = im.TotalImpact
		d["max_impact"] = im.MaxImpact
		if im.TotalActualSpend != nil {
			d["total_actual_spend"] = *im.TotalActualSpend
		}
		if im.TotalExpectedSpend != nil {
			d["total_expected_spend"] = *im.TotalExpectedSpend
		}
		if im.TotalImpactPercentage != nil {
			d["total_impact_percentage"] = *im.TotalImpactPercentage
		}
	}
	if sc := a.AnomalyScore; sc != nil {
		d["max_score"] = sc.MaxScore
	}
	rcs := []map[string]any{}
	for i, rc := range a.RootCauses {
		if i >= 10 {
			break
		}
		m := map[string]any{}
		for k, v := range map[string]*string{"service": rc.Service, "region": rc.Region, "usage_type": rc.UsageType, "linked_account": rc.LinkedAccount} {
			if s := aws.ToString(v); s != "" {
				m[k] = s
			}
		}
		if rc.Impact != nil {
			m["contribution"] = rc.Impact.Contribution
		}
		rcs = append(rcs, m)
	}
	d["root_causes"] = rcs
	return d
}

// Probe は GetAnomalyMonitors (モニターの有無) と GetAnomalies (1 件) を試す (合わせて約 0.02 USD)。
func (c *CostAnomaly) Probe(ctx context.Context) []collect.ProbeResult {
	if len(c.clients) == 0 {
		return nil
	}
	cl := c.clients[0]
	n, err := monitors(ctx, cl.CostExplorer)
	r := collect.ProbeResult{Action: ActionGetAnomalyMonitors, Detail: cl.Region, Err: err}
	if err == nil {
		if n == 0 {
			r.Warn = UnavailableCostAnomaly
		} else {
			r.Detail += fmt.Sprintf(": モニター %d 個以上", n)
		}
	}
	_, aerr := cl.CostExplorer.GetAnomalies(ctx, &ce.GetAnomaliesInput{MaxResults: aws.Int32(1),
		DateInterval: &cetypes.AnomalyDateInterval{StartDate: aws.String(snapshotTime(collect.Window{}).UTC().AddDate(0, 0, -1).Format(record.DateLayout))}})
	return []collect.ProbeResult{r, {Action: ActionGetAnomalies, Detail: cl.Region, Err: aerr}}
}
