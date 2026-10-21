// Package checks は Check インターフェース、差分判定の共通部、各チェックを持つ (設計書 4-2, 7 章)。
package checks

import (
	"context"
	"sort"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// Cadence はチェックの周期。
type Cadence string

const (
	Hourly Cadence = "hourly"
	Daily  Cadence = "daily"
	Weekly Cadence = "weekly"
)

// Mode はチェックの性質。差分判定の扱いが変わる (設計書 4-2 の決定)。
//   - ModeEvent: 窓内の事象を報告する。未観測でも resolved にしない。再観測は recurred。
//   - ModeState: 現在の状態を報告する。未観測なら resolved。
type Mode string

const (
	ModeEvent Mode = "event"
	ModeState Mode = "state"
)

// Severity は重大度。
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

var severityRank = map[Severity]int{Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1}

// Rank は比較用の順位 (大きいほど重い)。未知は 0。
func (s Severity) Rank() int { return severityRank[s] }

// MaxSeverity は最大の重大度を返す。空なら "" 。
func MaxSeverity(ss []Severity) Severity {
	var max Severity
	for _, s := range ss {
		if s.Rank() > max.Rank() {
			max = s
		}
	}
	return max
}

// Observation はチェックが返す「今の観測」。履歴は意識しない。
type Observation struct {
	Check    string
	Key      string
	Severity Severity
	Summary  string
	// Fingerprint は changed 判定に使う安定した要素 (重大度・IP 集合など)。空なら Data 全体を比較する。
	// count / first_time / last_time のように毎回変わる値は Data に残し Fingerprint には入れない。
	Fingerprint string
	Data        map[string]any // 根拠。個人特定値は入れない
}

// Check は 1 チェック。
type Check interface {
	Name() string
	Cadence() Cadence
	Mode() Mode
	Needs() []record.Kind
	Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error)
}

// Registry は利用可能なチェックの一覧。
type Registry struct {
	byName map[string]Check
	order  []string
}

// NewRegistry は初期セットのチェックを既定の設定で登録した Registry を返す。
func NewRegistry() *Registry {
	return NewRegistryFor(config.DefaultChecks())
}

// NewRegistryFor はアプリ層チェックを設定 (パス・閾値) 付きで登録した Registry を返す。
func NewRegistryFor(c config.Checks) *Registry {
	r := &Registry{byName: map[string]Check{}}
	for _, ch := range []Check{RootUsage{}, UnknownAssumeRole{}, NewPrincipal{}, IAMChanges{},
		LoginBruteforce{Config: c.LoginBruteforce}, ProbePaths{Config: c.ProbePaths}, WAFBlockTrend{Config: c.WAFBlockTrend}, AIPathUsage{},
		CredentialHygiene{Config: c.CredentialHygiene}, GuardDutyFindings{}, Posture{Config: c.Posture}, AccessAnalyzer{}} {
		r.Register(ch)
	}
	return r
}

// Register はチェックを追加する。
func (r *Registry) Register(c Check) {
	if _, ok := r.byName[c.Name()]; !ok {
		r.order = append(r.order, c.Name())
	}
	r.byName[c.Name()] = c
}

// Get は名前で引く。
func (r *Registry) Get(name string) (Check, bool) {
	c, ok := r.byName[name]
	return c, ok
}

// Names は登録順の名前一覧。
func (r *Registry) Names() []string { return append([]string(nil), r.order...) }

// Defaults は cadence 名 → その周期のチェック名 (ソート済み)。profile の `default-daily` 展開に使う。
func (r *Registry) Defaults() map[string][]string {
	out := map[string][]string{}
	for _, n := range r.order {
		c := r.byName[n]
		out[string(c.Cadence())] = append(out[string(c.Cadence())], n)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}
