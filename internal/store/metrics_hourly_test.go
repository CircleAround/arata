package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/CircleAround/arata/internal/record"
)

// 時ごとの集計 (ADR 0064): 同じ (時, source, metric, key) は置き換え、日の値は時の和として Metrics に出る。
// 時ごとの行がある (日, source, metric) では、前の版が書いた日の行を使わない (移行の日に二重に足さない)。
func TestHourlyMetrics(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	const m = record.MetricPrincipalSource
	key := record.ActivityKey("arn:aws:iam::123456789012:role/app", "198.51.100.0/24")
	for _, x := range []record.Metric{
		// 前の版の日の行 (10-20 は時ごとの行が無いので残る。10-21 は時ごとの行があるので使わない)
		{Date: "2026-10-20", Source: "trail", From: record.KindTrailEvent, Metric: m, Key: key, Value: 7},
		{Date: "2026-10-21", Source: "trail", From: record.KindTrailEvent, Metric: m, Key: key, Value: 2},
		{Date: "2026-10-21", Hour: "2026-10-21T01", Source: "trail", From: record.KindTrailEvent, Metric: m, Key: key, Value: 1},
		{Date: "2026-10-21", Hour: "2026-10-21T01", Source: "trail", From: record.KindTrailEvent, Metric: m, Key: key, Value: 4}, // 置き換え
		{Date: "2026-10-21", Hour: "2026-10-21T09", Source: "trail", From: record.KindTrailEvent, Metric: m, Key: key, Value: 3},
		// 別のソースの日の行は、そのソースに時ごとの行が無いので残る
		{Date: "2026-10-21", Source: "trail2", From: record.KindTrailEvent, Metric: m, Key: key, Value: 5},
	} {
		if err := st.UpsertMetric(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Metrics(ctx, MetricFilter{Metric: m})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		date, source string
		value        float64
	}
	var rows []row
	for _, x := range got {
		if x.Hour != "" || x.Key != key || x.From != record.KindTrailEvent {
			t.Errorf("daily rows should not carry the hour: %+v", x)
		}
		rows = append(rows, row{x.Date, x.Source, x.Value})
	}
	want := []row{{"2026-10-20", "trail", 7}, {"2026-10-21", "trail", 7}, {"2026-10-21", "trail2", 5}}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("metrics = %+v, want %+v", rows, want)
	}
	got, _ = st.Metrics(ctx, MetricFilter{Metric: m, From: "2026-10-21", To: "2026-10-21", Sources: []string{"trail"}})
	if len(got) != 1 || got[0].Value != 7 {
		t.Errorf("filtered = %+v", got)
	}
}
