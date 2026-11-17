package config

import (
	"fmt"
	"time"
)

// IPList は怪しい IP の一覧 (ADR 0069) の設定。`ip_list:` が無ければ一覧を作らない (nil)。
//
// 決定 (ADR 0069 の 3 節): 判定に使う期間 N (active) と保持の期間 M (retention.ip_list) を分ける。N ≦ M。
// 最後に見てから N を過ぎた IP は使わない (休止)。M より前の日の行は消す。
// 書いていない項目はこの版の既定値 (DefaultIPList。雛形が書き出す値と同じ) で埋め、config init --diff で既定値との違いが見える。
// 理由は書いたものだけが効く (書いていない理由では一覧に載せない)。
type IPList struct {
	ActiveRaw string        `yaml:"active"`
	Active    time.Duration `yaml:"-"`
	Reasons   IPListReasons `yaml:"reasons"`
	// CountSuspect は count_rule_status の suspect に、一覧の IP からの一致を足す問い合わせ (ADR 0069 の 4 節)。nil なら問い合わせない。
	CountSuspect *IPListCountSuspect `yaml:"count_suspect"`
}

// IPListCountSuspect は一覧の IP に絞った問い合わせの設定。確定した UTC の日ごとに 1 回、上位 K 個 (K = min(max_ips, max_queries 本に収まる数)) の IP で流す。
// 絞っても Insights は 1 日分を全部読むので、1 本ごとに 1 日分の読み取りが増える。
type IPListCountSuspect struct {
	// Reasons は使う理由 (ip_list.reasons に書いたものだけ。書かなければ書いた理由の全部)。
	Reasons []string `yaml:"reasons"`
	// MaxIPs は渡す IP の数の上限、MaxQueries は 1 日に流す本数の上限 (1〜10)。
	MaxIPs     int `yaml:"max_ips"`
	MaxQueries int `yaml:"max_queries"`
	// MinBlockShare は、渡した IP が占める BLOCK の件数の割合がこれより低い日に、listed_coverage: low を付ける下限 (0〜1)。
	MinBlockShare float64 `yaml:"min_block_share"`
}

// MaxListedQueries は max_queries の上限 (1 本ごとに 1 日分を読むので、費用を桁で増やさない)。
const MaxListedQueries = 10

// IPListReasons は一覧に載る理由ごとの条件。nil の理由では載せない。
type IPListReasons struct {
	// WAFBlock は wafv2 の BLOCK (レートベース・既定の action・sign-in のパス・trusted_cidrs を除く) が日に min_count 件以上。
	WAFBlock *IPListCount `yaml:"waf_block"`
	// Probe は探索 (http_access の probe_hits と、wafv2 の許可された探索) が日に min_count 件以上。
	Probe *IPListCount `yaml:"probe"`
	// SignInFailure は sign-in の失敗。日の件数と直近 N 日の窓の 2 つの載り方がある (IPListSignIn)。
	SignInFailure *IPListSignIn `yaml:"sign_in_failure"`
}

// IPListCount は日の件数の下限だけを持つ理由の条件。
type IPListCount struct {
	MinCount float64 `yaml:"min_count"`
}

// IPListSignIn は sign_in_failure の条件 (ADR 0069 の 1 節)。
//   - 日: その IP の 1 日の失敗が min_count 以上、かつその IP 自身の平常帯 (直近 baseline_days 日の中央値 × factor) を超えた
//   - 窓 (ゆっくりした総当たり): その日に失敗があり、直近 N 日の合計が min_count_window 以上、失敗のあった日が min_days 以上、
//     かつ窓の前の baseline_days 日の中央値 × N × factor を超えた
//
// どちらも、平常帯の過去の日 (データのある日) が min_baseline_days に足りなければ件数 (と日数) だけで判定する。
type IPListSignIn struct {
	MinCount        float64 `yaml:"min_count"`
	BaselineDays    int     `yaml:"baseline_days"`
	Factor          float64 `yaml:"factor"`
	MinBaselineDays int     `yaml:"min_baseline_days"`
	MinCountWindow  float64 `yaml:"min_count_window"`
	MinDays         int     `yaml:"min_days"`
}

// 既定値 (雛形が書き出す値)。sign_in_failure の日の値は login_bruteforce の既定と同じ (値は別に持つ)。窓の値は仮 (実データで見直す)。
var (
	DefaultIPListActive   = "7d"
	DefaultIPListWAFBlock = IPListCount{MinCount: 1}
	DefaultIPListProbe    = IPListCount{MinCount: 3}
	DefaultIPListSignIn   = IPListSignIn{MinCount: 20, BaselineDays: 14, Factor: 3, MinBaselineDays: 7, MinCountWindow: 50, MinDays: 3}
	// 渡す IP の上限は、実データの 1 日 (BLOCK 約 9.6 万件・約 1 万 IP) で、上位 1,000 IP が BLOCK の 87% を占めた (ADR 0069 の「確かめ方」)
	DefaultIPListCountSuspect = IPListCountSuspect{Reasons: []string{"waf_block", "probe", "sign_in_failure"}, MaxIPs: 1000, MaxQueries: 2, MinBlockShare: 0.5}
)

// written は ip_list.reasons に書いた理由 (雛形の順)。
func (l *IPList) written() []string {
	var out []string
	if l.Reasons.WAFBlock != nil {
		out = append(out, "waf_block")
	}
	if l.Reasons.Probe != nil {
		out = append(out, "probe")
	}
	if l.Reasons.SignInFailure != nil {
		out = append(out, "sign_in_failure")
	}
	return out
}

// ActiveDays は N を日の数で返す。
func (l *IPList) ActiveDays() int { return int(l.Active / (24 * time.Hour)) }

func (l *IPList) applyDefaults() {
	if l.ActiveRaw == "" {
		l.ActiveRaw = DefaultIPListActive
	}
	if r := l.Reasons.WAFBlock; r != nil && r.MinCount == 0 {
		r.MinCount = DefaultIPListWAFBlock.MinCount
	}
	if r := l.Reasons.Probe; r != nil && r.MinCount == 0 {
		r.MinCount = DefaultIPListProbe.MinCount
	}
	if r := l.Reasons.SignInFailure; r != nil {
		d := DefaultIPListSignIn
		setFloat(&r.MinCount, d.MinCount)
		setInt(&r.BaselineDays, d.BaselineDays)
		setFloat(&r.Factor, d.Factor)
		setInt(&r.MinBaselineDays, d.MinBaselineDays)
		setFloat(&r.MinCountWindow, d.MinCountWindow)
		setInt(&r.MinDays, d.MinDays)
	}
	if cs := l.CountSuspect; cs != nil {
		d := DefaultIPListCountSuspect
		if len(cs.Reasons) == 0 {
			cs.Reasons = l.written()
		}
		setInt(&cs.MaxIPs, d.MaxIPs)
		setInt(&cs.MaxQueries, d.MaxQueries)
		setFloat(&cs.MinBlockShare, d.MinBlockShare)
	}
}

func (l *IPList) validate(retention time.Duration, retentionRaw string) error {
	d, err := ParseDuration(l.ActiveRaw)
	if err != nil {
		return fmt.Errorf("config: ip_list.active %q: %w", l.ActiveRaw, err)
	}
	if d%(24*time.Hour) != 0 {
		return fmt.Errorf("config: ip_list.active must be whole days (got %q)", l.ActiveRaw)
	}
	l.Active = d
	if d > retention {
		return fmt.Errorf("config: ip_list.active (%s) must not be longer than retention.ip_list (%s) (an IP is used only while its records are kept; ADR 0069)", l.ActiveRaw, retentionRaw)
	}
	r := l.Reasons
	if r.WAFBlock == nil && r.Probe == nil && r.SignInFailure == nil {
		return fmt.Errorf("config: ip_list: at least one reason (waf_block, probe, sign_in_failure) is required under ip_list.reasons (remove ip_list: to build no list)")
	}
	for name, c := range map[string]*IPListCount{"waf_block": r.WAFBlock, "probe": r.Probe} {
		if c != nil && c.MinCount < 1 {
			return fmt.Errorf("config: ip_list.reasons.%s: min_count >= 1", name)
		}
	}
	if s := r.SignInFailure; s != nil {
		if s.MinCount < 1 || s.BaselineDays < 1 || s.Factor <= 0 || s.MinBaselineDays < 0 || s.MinBaselineDays > s.BaselineDays || s.MinCountWindow < 1 || s.MinDays < 1 {
			return fmt.Errorf("config: ip_list.reasons.sign_in_failure: min_count >= 1, baseline_days >= 1, factor > 0, 0 <= min_baseline_days <= baseline_days, min_count_window >= 1, min_days >= 1")
		}
		if s.MinDays > l.ActiveDays() {
			return fmt.Errorf("config: ip_list.reasons.sign_in_failure: min_days <= active days (%d)", l.ActiveDays())
		}
	}
	if cs := l.CountSuspect; cs != nil {
		written := map[string]bool{}
		for _, r := range l.written() {
			written[r] = true
		}
		for _, r := range cs.Reasons {
			if !written[r] {
				return fmt.Errorf("config: ip_list.count_suspect.reasons: %s is not in ip_list.reasons (an IP is listed only for the reasons written there)", r)
			}
		}
		if cs.MaxIPs < 1 || cs.MaxQueries < 1 || cs.MaxQueries > MaxListedQueries || cs.MinBlockShare < 0 || cs.MinBlockShare > 1 {
			return fmt.Errorf("config: ip_list.count_suspect: max_ips >= 1, 1 <= max_queries <= %d (each query reads the whole day), 0 <= min_block_share <= 1", MaxListedQueries)
		}
	}
	return nil
}

// IPListParam は ip_list: の項目 1 つと、この版の既定値 (雛形が書き出す値。config init --diff が比べる)。Path は ip_list の下のパス。
type IPListParam struct {
	Path  string
	Value any
}

// DefaultIPListParams は ip_list: の全項目の既定値 (雛形の順)。
func DefaultIPListParams() []IPListParam {
	w, p, s := DefaultIPListWAFBlock, DefaultIPListProbe, DefaultIPListSignIn
	return []IPListParam{
		{"active", DefaultIPListActive},
		{"reasons.waf_block.min_count", w.MinCount},
		{"reasons.probe.min_count", p.MinCount},
		{"reasons.sign_in_failure.min_count", s.MinCount},
		{"reasons.sign_in_failure.baseline_days", s.BaselineDays},
		{"reasons.sign_in_failure.factor", s.Factor},
		{"reasons.sign_in_failure.min_baseline_days", s.MinBaselineDays},
		{"reasons.sign_in_failure.min_count_window", s.MinCountWindow},
		{"reasons.sign_in_failure.min_days", s.MinDays},
		{"count_suspect.reasons", DefaultIPListCountSuspect.Reasons},
		{"count_suspect.max_ips", DefaultIPListCountSuspect.MaxIPs},
		{"count_suspect.max_queries", DefaultIPListCountSuspect.MaxQueries},
		{"count_suspect.min_block_share", DefaultIPListCountSuspect.MinBlockShare},
	}
}
