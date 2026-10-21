package config

import "fmt"

// Checks はアプリ層チェックの設定 (設計書 7 章)。パス・閾値・除外パスを顧客ごとに変える。
// collector (cwlogs) はこの設定から集計クエリを組み、チェックは同じ設定で判定する。
type Checks struct {
	LoginBruteforce LoginBruteforce `yaml:"login_bruteforce"`
	ProbePaths      ProbePaths      `yaml:"probe_paths"`
	WAFBlockTrend   WAFBlockTrend   `yaml:"waf_block_trend"`
	// 以下は週次チェック (Step 3)。
	CredentialHygiene CredentialHygiene `yaml:"credential_hygiene"`
	Posture           Posture           `yaml:"posture"`
}

// CredentialHygiene は credential_hygiene の設定。
type CredentialHygiene struct {
	// UnusedDays はアクセスキーを「未使用」とみなす日数 (最終使用、使われていなければ作成・ローテーションからの日数)。
	UnusedDays int `yaml:"unused_days"`
}

// Posture は posture の設定。
type Posture struct {
	// MinPasswordLength は IAM パスワードポリシーの最小文字数の下限。
	MinPasswordLength int `yaml:"min_password_length"`
}

// Baseline は平常帯 (直近 baseline_days 日の日次値の中央値 × factor、ただし min_count 以上) の指定。
type Baseline struct {
	BaselineDays int     `yaml:"baseline_days"` // 既定 14
	Factor       float64 `yaml:"factor"`        // 既定 3
	MinCount     float64 `yaml:"min_count"`     // 平常帯の下限 (中央値 0 の IP でもこの件数までは鳴らさない)
	// MinBaselineDays は「初出」判定に必要な、データのある過去日数 (導入直後に全部が初出になるのを防ぐ)。既定 7。
	MinBaselineDays int `yaml:"min_baseline_days"`
}

// LoginBruteforce は login_bruteforce の設定。
type LoginBruteforce struct {
	// Paths は sign-in の送信先パス (完全一致。クエリ文字列は除いて比較する)。
	Paths []string `yaml:"paths"`
	// Methods は sign-in 試行とみなす HTTP メソッド。
	Methods []string `yaml:"methods"`
	// FailureStatuses は失敗とみなすステータス (Devise の再表示は 401 / 422、成功は 302 / 303)。
	FailureStatuses []int    `yaml:"failure_statuses"`
	Baseline        Baseline `yaml:",inline"`
	// TopIPMinCount は「その日の Top IP が過去に無い」を報告する件数の下限。
	TopIPMinCount float64 `yaml:"top_ip_min_count"`
}

// ProbePaths は probe_paths の設定。
type ProbePaths struct {
	// Paths は機密パスの接頭辞 (/.env, /.git/ など)。
	Paths []string `yaml:"paths"`
	// ExcludePaths は対象から外す接頭辞 (正規の管理画面など)。
	ExcludePaths  []string `yaml:"exclude_paths"`
	Statuses      []int    `yaml:"statuses"`
	Baseline      Baseline `yaml:",inline"`
	TopIPMinCount float64  `yaml:"top_ip_min_count"`
}

// WAFBlockTrend は waf_block_trend の設定。
type WAFBlockTrend struct {
	// TopN は Top IP の入れ替わりを見る件数。
	TopN int `yaml:"top_n"`
	// MinCount は Top IP の新顔として報告する BLOCK 件数の下限。
	MinCount float64 `yaml:"min_count"`
	// NewRuleMinCount は「新規に鳴り始めたルール」として報告する BLOCK 件数の下限。
	NewRuleMinCount float64 `yaml:"new_rule_min_count"`
	BaselineDays    int     `yaml:"baseline_days"`
	MinBaselineDays int     `yaml:"min_baseline_days"`
}

// 既定値。
var (
	DefaultSignInPaths     = []string{"/users/sign_in", "/login", "/signin"}
	DefaultSignInMethods   = []string{"POST"}
	DefaultSignInFailures  = []int{401, 403, 422}
	DefaultProbePathPrefix = []string{"/.env", "/.git/", "/.aws/", "/.ssh/", "/wp-login.php", "/wp-admin", "/xmlrpc.php", "/phpmyadmin", "/pma", "/server-status", "/actuator", "/config.json", "/backup", "/.DS_Store"}
	DefaultProbeStatuses   = []int{403, 404}
)

// DefaultChecks は既定値だけのアプリ層チェック設定。
func DefaultChecks() Checks {
	var c Checks
	c.applyDefaults()
	return c
}

func (b *Baseline) applyDefaults(minCount float64) {
	if b.BaselineDays == 0 {
		b.BaselineDays = 14
	}
	if b.Factor == 0 {
		b.Factor = 3
	}
	if b.MinCount == 0 {
		b.MinCount = minCount
	}
	if b.MinBaselineDays == 0 {
		b.MinBaselineDays = 7
	}
}

func (b Baseline) validate() error {
	if b.BaselineDays < 1 || b.Factor <= 0 || b.MinCount < 0 || b.MinBaselineDays < 0 || b.MinBaselineDays > b.BaselineDays {
		return fmt.Errorf("baseline_days >= 1, factor > 0, min_count >= 0, 0 <= min_baseline_days <= baseline_days")
	}
	return nil
}

func (c *Checks) applyDefaults() {
	lb := &c.LoginBruteforce
	if len(lb.Paths) == 0 {
		lb.Paths = DefaultSignInPaths
	}
	if len(lb.Methods) == 0 {
		lb.Methods = DefaultSignInMethods
	}
	if len(lb.FailureStatuses) == 0 {
		lb.FailureStatuses = DefaultSignInFailures
	}
	lb.Baseline.applyDefaults(20)
	if lb.TopIPMinCount == 0 {
		lb.TopIPMinCount = 5
	}
	pp := &c.ProbePaths
	if len(pp.Paths) == 0 {
		pp.Paths = DefaultProbePathPrefix
	}
	if len(pp.Statuses) == 0 {
		pp.Statuses = DefaultProbeStatuses
	}
	pp.Baseline.applyDefaults(10)
	if pp.TopIPMinCount == 0 {
		pp.TopIPMinCount = 5
	}
	if c.CredentialHygiene.UnusedDays == 0 {
		c.CredentialHygiene.UnusedDays = 90
	}
	if c.Posture.MinPasswordLength == 0 {
		c.Posture.MinPasswordLength = 14
	}
	wb := &c.WAFBlockTrend
	if wb.TopN == 0 {
		wb.TopN = 5
	}
	if wb.MinCount == 0 {
		wb.MinCount = 10
	}
	if wb.NewRuleMinCount == 0 {
		wb.NewRuleMinCount = 1
	}
	if wb.BaselineDays == 0 {
		wb.BaselineDays = 14
	}
	if wb.MinBaselineDays == 0 {
		wb.MinBaselineDays = 7
	}
}

func (c *Checks) validate() error {
	if err := c.LoginBruteforce.Baseline.validate(); err != nil {
		return fmt.Errorf("login_bruteforce: %w", err)
	}
	if err := c.ProbePaths.Baseline.validate(); err != nil {
		return fmt.Errorf("probe_paths: %w", err)
	}
	wb := c.WAFBlockTrend
	if wb.TopN < 1 || wb.BaselineDays < 1 || wb.MinBaselineDays > wb.BaselineDays {
		return fmt.Errorf("waf_block_trend: top_n >= 1, baseline_days >= 1, min_baseline_days <= baseline_days")
	}
	if c.CredentialHygiene.UnusedDays < 1 {
		return fmt.Errorf("credential_hygiene: unused_days >= 1")
	}
	if c.Posture.MinPasswordLength < 1 || c.Posture.MinPasswordLength > 128 {
		return fmt.Errorf("posture: 1 <= min_password_length <= 128")
	}
	for _, p := range append(append([]string{}, c.LoginBruteforce.Paths...), append(c.ProbePaths.Paths, c.ProbePaths.ExcludePaths...)...) {
		if len(p) == 0 || p[0] != '/' {
			return fmt.Errorf("path %q must start with /", p)
		}
	}
	return nil
}
