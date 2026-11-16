package iplist

import (
	"sort"

	"github.com/CircleAround/arata/internal/store"
)

// Selection は一覧の問い合わせ (ADR 0069 の 4 節) に渡す IP を、並べた順に持つ。
type Selection struct {
	IPs []string
	// BlockTotal / ProbeTotal はアクティブな全部の IP の、直近 N 日の waf_block / probe の件数の和 (割合の分母)。
	BlockTotal, ProbeTotal float64
	block, probe           []float64 // IPs と同じ順の件数
}

// Select は date の終わりの時点でアクティブな (last_seen が date を含む直近 n 日の中の) IP を、reasons の行だけから選び、並べる。
// 並べ方: (1) 理由の数の多い順 (2) 直近 n 日の waf_block の件数 (3) 全部の理由の件数 (4) last_seen の新しい順 (5) IP の文字列の順。
// known が true を返す IP (allowlist の source_ips。一覧に載った後に足されたもの) は使わない。
func Select(rows []store.IPListRow, date string, n int, reasons []string, known func(string) bool) Selection {
	use := map[string]bool{}
	for _, r := range reasons {
		use[r] = true
	}
	from := addDays(date, -(n - 1))
	type agg struct {
		reasons             map[string]bool
		block, probe, total float64
		last                string
	}
	m := map[string]*agg{}
	for _, r := range rows {
		if r.Date < from || r.Date > date || !use[r.Reason] || (known != nil && known(r.IP)) {
			continue
		}
		a := m[r.IP]
		if a == nil {
			a = &agg{reasons: map[string]bool{}}
			m[r.IP] = a
		}
		a.reasons[r.Reason] = true
		a.total += r.Count
		switch r.Reason {
		case ReasonWAFBlock:
			a.block += r.Count
		case ReasonProbe:
			a.probe += r.Count
		}
		if r.Date > a.last {
			a.last = r.Date
		}
	}
	var sel Selection
	for ip, a := range m {
		sel.IPs = append(sel.IPs, ip)
		sel.BlockTotal += a.block
		sel.ProbeTotal += a.probe
	}
	sort.Slice(sel.IPs, func(i, j int) bool {
		a, b := m[sel.IPs[i]], m[sel.IPs[j]]
		switch {
		case len(a.reasons) != len(b.reasons):
			return len(a.reasons) > len(b.reasons)
		case a.block != b.block:
			return a.block > b.block
		case a.total != b.total:
			return a.total > b.total
		case a.last != b.last:
			return a.last > b.last
		}
		return sel.IPs[i] < sel.IPs[j]
	})
	for _, ip := range sel.IPs {
		sel.block = append(sel.block, m[ip].block)
		sel.probe = append(sel.probe, m[ip].probe)
	}
	return sel
}

// Share は先頭の used 個の IP が占める、waf_block / probe の件数の割合。分母が 0 なら -1 (割合が無い)。
func (s Selection) Share(used int) (block, probe float64) {
	if used > len(s.IPs) {
		used = len(s.IPs)
	}
	var b, p float64
	for i := 0; i < used; i++ {
		b += s.block[i]
		p += s.probe[i]
	}
	block, probe = -1, -1
	if s.BlockTotal > 0 {
		block = b / s.BlockTotal
	}
	if s.ProbeTotal > 0 {
		probe = p / s.ProbeTotal
	}
	return block, probe
}
