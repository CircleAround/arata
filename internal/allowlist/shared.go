package allowlist

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SharedSourceEntry は shared_sources の 1 件。NAT の内側に多くの利用者がいる送信元 (学校・会場・社内の回線)。
// 外すのではなく、別のしきい値で見る (ADR 0094 の 1 節)。
//
// 決定 (ADR 0094 の 1 節の実装):
//   - cidr と note は必須。note は「なぜ人が多いのか」で、後から外す判断の材料になる (assume_destinations と同じ)
//   - expires は任意。期限日の終わりまで有効で、過ぎたら普通の送信元に戻る (principals などと同じ)
//   - source_ips とも当たる IP は source_ips を優先する (丸ごと外す)。SharedSource は source_ips の IP に何も返さない
//   - 効くのは login_bruteforce (平常帯の下限と new_top_ip) と rate_limited_ip (下限と理由) だけ。endpoint_abuse・probe_paths には効かせない
//   - 広すぎる範囲 (IPv4 は /24、IPv6 は /48 より広い) は、run は受け付けるが config check が warn にし、approve は書かない (SharedCIDRTooBroad)
type SharedSourceEntry struct {
	CIDR       string `yaml:"cidr"`
	Note       string `yaml:"note"`
	ApprovedBy string `yaml:"approved_by"`
	ApprovedAt string `yaml:"approved_at"`
	Expires    string `yaml:"expires"`

	expires time.Time
	net     *net.IPNet
}

// 人の多い送信元として書ける範囲の広さの上限 (プレフィックスの長さの下限)。これより広い範囲は、総当たりのしきい値を広く上げる穴になる。
const (
	SharedMinPrefixV4 = 24
	SharedMinPrefixV6 = 48
)

// Subject は項目の対象の表示 (shared_source:<cidr>)。
func (e *SharedSourceEntry) Subject() string { return "shared_source:" + e.CIDR }

func (e *SharedSourceEntry) active(at time.Time) bool {
	return e.expires.IsZero() || at.Before(e.expires)
}

func (e *SharedSourceEntry) validate() error {
	_, n, err := net.ParseCIDR(e.CIDR)
	if err != nil {
		return fmt.Errorf("cidr: %w", err)
	}
	if strings.TrimSpace(e.Note) == "" {
		return fmt.Errorf("note is required (why many users share this source: a school, a venue, an office network)")
	}
	if e.Expires != "" {
		t, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			return fmt.Errorf("expires %q: want YYYY-MM-DD", e.Expires)
		}
		e.expires = t.Add(24 * time.Hour) // 期限日の終わりまで有効
	}
	e.net = n
	return nil
}

// SharedCIDRTooBroad は cidr が人の多い送信元として広すぎるか (IPv4 は /24、IPv6 は /48 より広い)。読めない値は false (Parse が拒む)。
func SharedCIDRTooBroad(cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := n.Mask.Size()
	switch {
	case bits == 32:
		return ones < SharedMinPrefixV4
	case n.IP.To4() != nil:
		// IPv4 射影アドレス (::ffff:198.51.100.0/120) は IPv4 の範囲として照合される (::ffff:0.0.0.0/96 は IPv4 の全部)。前の 96 ビットを除いて比べる
		return ones-96 < SharedMinPrefixV4
	}
	return ones < SharedMinPrefixV6
}

// SharedSource は ip が at の時点で期限内の shared_sources の項目に含まれるかを返す。含まれれば、最も狭い (プレフィックスの長い) 項目を返す
// (同じ長さなら先に書いたもの)。source_ips に含まれる IP は丸ごと外す側なので、何も返さない (ADR 0094 の 1 節)。
func (l *List) SharedSource(ip string, at time.Time) (*SharedSourceEntry, bool) {
	addr := net.ParseIP(ip)
	if addr == nil || l.SourceIPAllowed(ip) {
		return nil, false
	}
	var best *SharedSourceEntry
	bestOnes := -1
	for i := range l.SharedSources {
		e := &l.SharedSources[i]
		if e.net == nil || !e.active(at) || !e.net.Contains(addr) {
			continue
		}
		if ones, _ := e.net.Mask.Size(); ones > bestOnes {
			best, bestOnes = e, ones
		}
	}
	return best, best != nil
}

// HasSharedSources は shared_sources の項目が 1 つでもあるか。
func (l *List) HasSharedSources() bool { return len(l.SharedSources) > 0 }

// netsOverlap は 2 つの範囲が重なるか (片方がもう片方を含む)。
func netsOverlap(a, b *net.IPNet) bool {
	return a != nil && b != nil && (a.Contains(b.IP) || b.Contains(a.IP))
}

// NewSharedSource は approve が shared_sources に追記する 1 件。
type NewSharedSource struct {
	CIDR       string
	Note       string
	ApprovedBy string
	ApprovedAt string // YYYY-MM-DD
	Expires    string // YYYY-MM-DD、空なら無期限
}

// Subject は追記する項目の表示 (SharedSourceEntry.Subject と同じ形)。
func (s NewSharedSource) Subject() string { return "shared_source:" + s.CIDR }

// AppendShared は path の allowlist.yaml の shared_sources の末尾に s を追記し、追記したテキストを返す (Append と同じ書き方)。
func AppendShared(path string, s NewSharedSource) (string, error) {
	return appendFile(path, func(src []byte) ([]byte, string, error) { return AppendSharedBytes(src, s) })
}

// AppendSharedBytes は allowlist.yaml のテキストに s を追記した結果と、追記した部分を返す。
//
// 決定 (ADR 0094 の 1 節の実装): 差し込み方は principals と同じ (ADR 0010。ほかの行は変えない)。節が無ければファイルの末尾に足す。
// cidr はネットワークの形 (198.51.100.0/24。ホストの部分が 0) だけを受け付ける。広すぎる範囲 (SharedCIDRTooBroad) は書かない。
// 同じ範囲の項目が既にあれば ErrAlreadyListed (期限を延ばすのは人が項目を直す)。source_ips と重なる範囲は書かない
// (重なる IP は source_ips が優先して丸ごと外れるので、書いても効かない)。
func AppendSharedBytes(src []byte, s NewSharedSource) ([]byte, string, error) {
	e := SharedSourceEntry{CIDR: s.CIDR, Note: s.Note, Expires: s.Expires}
	if err := e.validate(); err != nil {
		return nil, "", fmt.Errorf("allowlist: shared_sources: %w", err)
	}
	if e.net.String() != s.CIDR {
		return nil, "", fmt.Errorf("allowlist: shared_sources: cidr %q: write the network address (%s)", s.CIDR, e.net.String())
	}
	if SharedCIDRTooBroad(s.CIDR) {
		return nil, "", fmt.Errorf("allowlist: shared_sources: cidr %s is broader than /%d (IPv4) or /%d (IPv6)", s.CIDR, SharedMinPrefixV4, SharedMinPrefixV6)
	}
	before, err := Parse(src)
	if err != nil {
		return nil, "", fmt.Errorf("allowlist: current file is invalid: %w", err)
	}
	for i := range before.SharedSources {
		if x := &before.SharedSources[i]; x.net.String() == e.net.String() {
			return nil, "", fmt.Errorf("%w: %s (edit the entry directly to change note / expires)", ErrAlreadyListed, x.Subject())
		}
	}
	for i := range before.SourceIPs {
		if x := &before.SourceIPs[i]; netsOverlap(e.net, x.net) {
			return nil, "", fmt.Errorf("allowlist: shared_sources: %s overlaps source_ips[%d] (%s), which excludes those IPs entirely", s.CIDR, i, x.CIDR)
		}
	}
	result, added, err := appendToSection(src, "shared_sources", s.render)
	if err != nil {
		return nil, "", err
	}
	after, err := Parse(result)
	if err != nil {
		return nil, "", fmt.Errorf("allowlist: refusing to write an invalid file: %w", err)
	}
	n := len(after.SharedSources)
	if n != len(before.SharedSources)+1 || after.SharedSources[n-1].CIDR != s.CIDR || len(after.Principals) != len(before.Principals) || len(after.SourceIPs) != len(before.SourceIPs) {
		return nil, "", fmt.Errorf("allowlist: refusing to write: the new entry did not land at the end of shared_sources")
	}
	return result, added, nil
}

// render は列の 1 要素を indent 付きで書く (末尾改行あり)。
func (s NewSharedSource) render(indent string) string {
	lines := []string{"cidr: " + s.CIDR, "note: " + scalar(s.Note)}
	if s.ApprovedBy != "" {
		lines = append(lines, "approved_by: "+scalar(s.ApprovedBy))
	}
	if s.ApprovedAt != "" {
		lines = append(lines, "approved_at: "+s.ApprovedAt)
	}
	if s.Expires != "" {
		lines = append(lines, "expires: "+s.Expires)
	}
	var b strings.Builder
	for i, l := range lines {
		if i == 0 {
			b.WriteString(indent + "- ")
		} else {
			b.WriteString(indent + "  ")
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}
