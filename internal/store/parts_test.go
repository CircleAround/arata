package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// 部分の行 (ADR 0065): Logs Insights のクエリの行を (ソース, クエリ, 時) ごとに丸ごと置き換えて残し、時の範囲で読む。
// 確定した日から retention の日数を過ぎた行は、書くときに消す。
func TestMetricParts(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	h := func(d, hh int) time.Time { return time.Date(2026, 10, d, hh, 0, 0, 0, time.UTC) }
	row := func(v string) map[string]string { return map[string]string{"day": v, "n": "1"} }
	for _, p := range []struct {
		hour time.Time
		rows []map[string]string
	}{
		{h(20, 23), []map[string]string{row("a")}},
		{h(21, 0), []map[string]string{row("b"), row("c")}},
		{h(21, 1), nil}, // 行の無い時も、置き換えとして書く
		{h(21, 0), []map[string]string{row("d")}}, // 置き換え
	} {
		if err := st.PutParts(ctx, "waf", "waf_actions", p.hour, p.rows, 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutParts(ctx, "waf", "lines_total", h(21, 0), []map[string]string{row("x")}, 3); err != nil {
		t.Fatal(err)
	}
	got, hours, err := st.Parts(ctx, "waf", "waf_actions", h(21, 0), h(22, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []map[string]string{row("d")}) || hours != 2 {
		t.Fatalf("parts = %v (hours %d)", got, hours)
	}
	got, hours, _ = st.Parts(ctx, "waf", "waf_actions", h(20, 0), h(22, 0))
	if len(got) != 2 || got[0]["day"] != "a" || hours != 3 {
		t.Fatalf("parts over two days = %v (hours %d)", got, hours)
	}
	// 25 日に書くと、retention (3 日) より前の日 (21 日まで) の行は消える
	if err := st.PutParts(ctx, "waf", "waf_actions", h(25, 5), nil, 3); err != nil {
		t.Fatal(err)
	}
	if got, hours, _ := st.Parts(ctx, "waf", "waf_actions", h(20, 0), h(22, 0)); len(got) != 0 || hours != 0 {
		t.Fatalf("old parts should be pruned: %v (hours %d)", got, hours)
	}
}
