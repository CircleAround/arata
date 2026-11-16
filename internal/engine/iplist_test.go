package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/store"
)

const ipListConfig = `ip_list:
  reasons:
    probe: {}
    sign_in_failure: {}
`

// 怪しい IP の一覧 (ADR 0069): 収集が成功した cloudwatch-logs のソースについて、読んだ日の一覧を日の値から作り直す。
// ip_list: が無ければ作らない。作り直しは置き換え (同じ日を 2 回読んでも行が同じ)。
func TestRunBuildsIPList(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprint(on), func(t *testing.T) {
			extra := ""
			if on {
				extra = ipListConfig
			}
			h := newHarnessWith(t, nginxSource, extra)
			ctx := context.Background()
			h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 950))
			h.logs.On("as http_hits", cwlogstest.Response{Rows: []map[string]string{
				cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "30"),
				cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.8", "method", "POST", "status", "401", "sign_in", "/users/sign_in", "http_hits", "3"),
			}})
			e := h.open(t)
			for i := 0; i < 2; i++ {
				if _, err := e.Run(ctx, "daily"); err != nil {
					t.Fatal(err)
				}
				h.now = h.now.Add(1)
			}
			rows, err := e.Store().IPListDays(ctx, "", "")
			if err != nil {
				t.Fatal(err)
			}
			want := []store.IPListRow{{Date: "2026-10-21", Source: "web", Reason: "sign_in_failure", IP: "198.51.100.7", Count: 30}}
			if !on {
				want = nil
			}
			if fmt.Sprint(rows) != fmt.Sprint(want) {
				t.Fatalf("rows = %+v, want %+v", rows, want)
			}
			last, _ := e.Store().RecentRuns(ctx, 1)
			st, ok := last[0].Stats["ip_list"].(map[string]any)
			if ok != on {
				t.Fatalf("stats: %+v", last[0].Stats)
			}
			if on && (st["sign_in_failure"] != float64(1) || st["sign_in_by_day"] != float64(1)) {
				t.Errorf("ip_list stats: %+v", st)
			}
		})
	}
}
