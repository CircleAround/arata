package iplist

import (
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/store"
)

// 渡す IP の並べ方 (ADR 0069 の 4 節): (1) 理由の数の多い順 (2) 直近 N 日の waf_block の件数 (3) 全部の理由の件数 (4) last_seen の新しい順 (5) IP の文字列の順。
// 使うのは日の終わりの時点でアクティブな IP (last_seen が直近 N 日の中) で、選んだ理由だけ。既知の送信元は使わない。
func TestSelect(t *testing.T) {
	r := func(d int, src, reason, ip string, n float64) store.IPListRow {
		return store.IPListRow{Date: day(d), Source: src, Reason: reason, IP: ip, Count: n}
	}
	rows := []store.IPListRow{
		r(-7, "waf", ReasonWAFBlock, "198.51.100.1", 500), // N (7 日) の外
		r(-6, "waf", ReasonWAFBlock, "198.51.100.2", 10),
		r(0, "web", ReasonProbe, "198.51.100.2", 3), // 理由 2 つ
		r(0, "waf", ReasonWAFBlock, "198.51.100.3", 40),
		r(-1, "waf", ReasonWAFBlock, "198.51.100.4", 40), // 3 と同じ件数、last_seen が古い
		r(0, "waf", ReasonWAFBlock, "198.51.100.5", 40),  // 3 と同じ件数・同じ日 → 文字列の順
		r(0, "web", ReasonProbe, "198.51.100.6", 90),     // BLOCK 0、全部の件数は多い
		r(0, "web", ReasonSignInFailure, "198.51.100.7", 50),
		r(0, "web", ReasonSignInFailure, "192.0.2.10", 50), // 既知
		r(1, "waf", ReasonWAFBlock, "198.51.100.8", 99),    // 日の後
	}
	sel := Select(rows, day(0), 7, []string{ReasonWAFBlock, ReasonProbe}, func(ip string) bool { return ip == "192.0.2.10" })
	if got := strings.Join(sel.IPs, ","); got != "198.51.100.2,198.51.100.3,198.51.100.5,198.51.100.4,198.51.100.6" {
		t.Fatalf("IPs = %s", got)
	}
	if sel.BlockTotal != 130 || sel.ProbeTotal != 93 {
		t.Errorf("totals %v %v", sel.BlockTotal, sel.ProbeTotal)
	}
	b, p := sel.Share(2)
	if b != 50.0/130 || p != 3.0/93 {
		t.Errorf("share(2) = %v %v", b, p)
	}
	if b, p := sel.Share(5); b != 1 || p != 1 {
		t.Errorf("share(all) = %v %v", b, p)
	}
	if b, p := (Selection{}).Share(0); b != -1 || p != -1 {
		t.Errorf("share of nothing = %v %v (want -1: no denominator)", b, p)
	}
}
