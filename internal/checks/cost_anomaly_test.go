package checks

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// costItem は予想額 expected に対して total だけ増えた異常 (割合は TotalImpactPercentage。expected <= 0 なら割合を持たない)。
func costItem(id string, expected, total float64, feedback string) record.SnapshotItem {
	kv := []any{"total_impact", total, "max_impact", total / 2, "total_actual_spend", expected + total}
	if expected > 0 {
		kv = append(kv, "total_expected_spend", expected, "total_impact_percentage", total/expected*100)
	}
	return snap(record.KindCostAnomaly, id, append(kv, "feedback", feedback, "dimension_value", "Amazon Elastic Compute Cloud - Compute",
		"start_date", "2026-10-19", "end_date", "2026-10-20", "monitor_arn", "arn:aws:ce::123456789012:anomalymonitor/m1",
		"root_causes", []map[string]any{{"service": "Amazon Elastic Compute Cloud - Compute", "region": "eu-west-1", "usage_type": "EU-BoxUsage:p3.16xlarge", "linked_account": "123456789012", "contribution": total}})...)
}

// 重大度は予想に対する増加の割合で決める (固定の金額はサービスの規模で意味が変わる): 予想の 1.5 倍以上 (+50%) で medium、2 倍以上 (+100%) で high。
// 影響額が min_impact_usd 未満のものは割合が大きくても報告しない (1 USD → 5 USD のような誤報を防ぐ)。
// 予想額が無ければ割合を出せないので、影響額が下限以上なら medium。コンソールで「異常でない」「計画した活動」とした異常は報告しない。
func TestCostAnomaly(t *testing.T) {
	st := newStore(t)
	snapshot(t, st, record.KindCostAnomaly,
		costItem("double", 12.3, 49.2, ""), // +400% → high
		costItem("half", 100, 60, "YES"),   // +60% → medium
		costItem("slight", 1000, 300, ""),  // +30% → 報告しない
		costItem("tiny", 1, 4, ""),         // +400% だが影響 4 USD → 報告しない
		costItem("noexp", 0, 20, ""),       // 予想額なし → medium
		costItem("no", 10, 2000, "NO"), costItem("planned", 10, 2000, "PLANNED_ACTIVITY"))
	c := CostAnomaly{Config: config.DefaultChecks().CostAnomaly}
	if c.Mode() != ModeEvent || c.Cadence() != Daily || c.Needs()[0] != record.KindCostAnomaly {
		t.Fatal("cost_anomaly is a daily event check on cost_anomaly")
	}
	obs, err := c.Evaluate(context.Background(), st, collect.Window{To: now}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := byKeyObs(obs)
	if len(got) != 3 || got["double"].Severity != High || got["half"].Severity != Medium || got["noexp"].Severity != Medium {
		t.Fatalf("%v", bySev(obs))
	}
	d := got["double"]
	for _, want := range []string{"予想 12.30 USD", "61.50 USD", "+400%", "影響 49.20 USD", "eu-west-1", "Amazon Elastic Compute Cloud - Compute"} {
		if !strings.Contains(d.Summary, want) {
			t.Fatalf("summary %q lacks %q", d.Summary, want)
		}
	}
	if d.Data["total_impact"] != 49.2 || d.Data["total_expected_spend"] != 12.3 || math.Abs(d.Data["total_actual_spend"].(float64)-61.5) > 1e-9 || d.Data["impact_ratio"] != 4.0 {
		t.Fatalf("data: %+v", d.Data)
	}
	rcs := d.Data["root_causes"].([]map[string]any)
	if len(rcs) != 1 || rcs[0]["usage_type"] != "EU-BoxUsage:p3.16xlarge" {
		t.Fatalf("root causes: %+v", rcs)
	}
	if n := got["noexp"]; !strings.Contains(n.Summary, "予想額が無いので割合を出せない") || n.Data["impact_ratio"] != nil {
		t.Fatalf("no expected: %+v", n)
	}
	// 影響額が日々増えても重大度が同じなら changed にしない (still_open)
	snapshot(t, st, record.KindCostAnomaly, costItem("double", 12.3, 80, ""))
	obs2, _ := c.Evaluate(context.Background(), st, collect.Window{To: now}, nil)
	if obs2[0].Fingerprint != d.Fingerprint {
		t.Fatalf("fingerprint changed with impact: %q %q", obs2[0].Fingerprint, d.Fingerprint)
	}
}
