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
}

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
)

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
	}
}
