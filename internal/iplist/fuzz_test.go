package iplist

import (
	"testing"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
)

// FuzzBuild: 日の値の key はログ由来の値 (信用できない入力。ADR 0041)。一覧の行は後で Logs Insights の問い合わせの文に入るので、
// 守る規則: 行の IP はすべて正規の形 (Canonical(ip) == ip) で、既知の送信元を含まず、理由は 3 つのどれか、件数は正、日とソースは渡したもの。
func FuzzBuild(f *testing.F) {
	for _, s := range []string{"198.51.100.7", "2001:DB8::1", "::ffff:203.0.113.5", "fe80::1%eth0", "\"] | filter 1=1 | [\"", "192.0.2.4\n", "", "0.0.0.0", "::"} {
		f.Add(s, 25.0)
	}
	f.Fuzz(func(t *testing.T, key string, v float64) {
		s := Series{}
		for _, m := range Metrics {
			s.set(day(0), m, key, v)
			s.set(day(-1), m, key, v)
		}
		s.set(day(0), cwlogs.MetricSignInFailures, "192.0.2.10", 100)
		known := func(ip string) bool { return ip == "192.0.2.10" }
		res := Build(list(), "src", day(0), s, known)
		for _, r := range res.Rows {
			if c, ok := Canonical(r.IP); !ok || c != r.IP {
				t.Fatalf("row IP %q is not canonical (key %q)", r.IP, key)
			}
			if r.IP == "192.0.2.10" {
				t.Fatalf("known IP listed: %+v", r)
			}
			if r.Reason != ReasonWAFBlock && r.Reason != ReasonProbe && r.Reason != ReasonSignInFailure {
				t.Fatalf("reason %q", r.Reason)
			}
			if !(r.Count > 0) || r.Date != day(0) || r.Source != "src" {
				t.Fatalf("row %+v", r)
			}
		}
	})
}
