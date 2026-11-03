package config

import (
	"fmt"
	"net/netip"
)

// Checks はアプリ層チェックの設定 (設計書 7 章)。パス・閾値・除外パスを顧客ごとに変える。
// collector (cwlogs) はこの設定から集計クエリを組み、チェックは同じ設定で判定する。
type Checks struct {
	LoginBruteforce LoginBruteforce `yaml:"login_bruteforce"`
	ProbePaths      ProbePaths      `yaml:"probe_paths"`
	WAFBlockTrend   WAFBlockTrend   `yaml:"waf_block_trend"`
	// WAFReview は wafv2 の日次集計の条件と、週次の waf_review (WAF の修正提案の候補) の閾値 (ADR 0023)。
	WAFReview    WAFReview    `yaml:"waf_review"`
	AccessDenied AccessDenied `yaml:"access_denied"`
	// DefenseEvasion と PublicExposure は CloudTrail の注目イベントを見る daily のチェック (ADR 0026)。
	DefenseEvasion DefenseEvasion `yaml:"defense_evasion"`
	PublicExposure PublicExposure `yaml:"public_exposure"`
	// PrincipalNewSource と SecretAccess は CloudTrail の主体の活動・秘匿値の読み取りを見る daily のチェック (ADR 0027)。
	PrincipalNewSource PrincipalNewSource `yaml:"principal_new_source"`
	SecretAccess       SecretAccess       `yaml:"secret_access"`
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

// WAFReview は waf_review の設定 (ADR 0023)。前半は wafv2 の日次集計の条件 (集計条件なので overrides では変えられない)、後半は判定の閾値。
//
// 決定: 候補は「人が本番の WAF を変える」判断材料になるので、閾値は「迷ったら提案しない」側に置く。
type WAFReview struct {
	// TopPaths は waf_block_path / waf_allow_probe を日ごとに残す正規化パスの数 (件数の多い順)。集計条件。
	TopPaths int `yaml:"top_paths"`
	// RatePathGroups は 1 IP あたりの件数 (waf_ip_rate) を分けて測るパスの接頭辞。どれにも当たらなければ「その他」(*)。集計条件。
	RatePathGroups []string `yaml:"rate_path_groups"`
	// TrustedCIDRs は監視・開発会社などの正規の送信元。wafv2 の新しい集計 (パス・カウント・レート) と候補から外す。集計条件。
	TrustedCIDRs []string `yaml:"trusted_cidrs"`
	// ExpectedHighRatePaths はリクエストが多いのが仕様のパスの接頭辞 (決済など)。レート制限の候補から外す。
	ExpectedHighRatePaths []string `yaml:"expected_high_rate_paths"`
	// Days は候補を作るのに見る直近の日数 (保存済みの metrics を読む)。
	Days int `yaml:"days"`
	// MinDistinctIPs は「誤検知の疑い」に要る異なり IP 数 (日ごとの値の最大。下限の見積もり)。
	MinDistinctIPs float64 `yaml:"min_distinct_ips"`
	// FindingDistinctIPs は「誤検知の疑い」を low の finding にもする異なり IP 数。
	FindingDistinctIPs float64 `yaml:"finding_distinct_ips"`
	// MinCount は「すり抜けている探索」に要る、許可された探索の件数 (Days の合計)。
	MinCount float64 `yaml:"min_count"`
	// RateFactor は「レート制限が無い」とみなす条件: 5 分あたりの最大が p99 のこの倍を超える。
	RateFactor float64 `yaml:"rate_factor"`
	// RateMargin と RateFloor は提案する上限 limit = max(p99 × rate_margin, rate_floor) (5 分あたり)。
	RateMargin float64 `yaml:"rate_margin"`
	RateFloor  float64 `yaml:"rate_floor"`
	// RateLooseFactor は既存のレート制限が観測の最大のこの倍より高ければ「緩すぎる」とする。観測の p99 より低ければ「厳しすぎる」。
	RateLooseFactor float64 `yaml:"rate_loose_factor"`
	// UnusedDays は「使われていないルール」とみなす一致 0 の日数 (データのある日で数える)。
	UnusedDays int `yaml:"unused_days"`
	// MaxProposals は候補の種類ごとに出す上限 (根拠の強い順)。
	MaxProposals int `yaml:"max_proposals"`
}

// DefaultRatePathGroups は rate_path_groups の既定。
var DefaultRatePathGroups = []string{"/login", "/api/"}

// AccessDenied は access_denied の設定 (ADR 0021)。
// 平常帯は Baseline と同じ形 (主体自身の直近 baseline_days 日の日次値の中央値 × factor)。min_count は量の条件の下限。
// min_baseline_days は平常帯を使うのに要る、データのある過去日数 (それ未満なら平常帯を 0 とみなし絶対の閾値だけで判定する)。
type AccessDenied struct {
	// ErrorCodes は拒否とみなす CloudTrail の errorCode (完全一致)。events に残す条件なので overrides では変えられない。
	ErrorCodes []string `yaml:"error_codes"`
	// MinDistinctAPIs は拒否された API (eventSource:eventName) の種類がこれ以上で報告する (medium)。
	MinDistinctAPIs int `yaml:"min_distinct_apis"`
	// HighDistinctAPIs は種類がこれ以上で high。
	HighDistinctAPIs int      `yaml:"high_distinct_apis"`
	Baseline         Baseline `yaml:",inline"`
}

// DefenseEvasion は defense_evasion (監査・検知の仕組みを止める・弱める操作) の設定 (ADR 0026)。
// 監査対象のロググループ (cloudwatch-logs のソースの log_group) は設定から自動で作るのでここには書かない (Config.AuditLogGroups)。
type DefenseEvasion struct {
	// MinLogRetentionDays はロググループの保持期間の下限。PutRetentionPolicy でこれより短くしたものを報告する
	// (CloudTrail には新しい値しか残らないので「短くした」かは分からず、下限との比較で判定する)。
	MinLogRetentionDays int `yaml:"min_log_retention_days"`
	// TrailBuckets は CloudTrail の証跡の宛先の S3 バケット名。バケットポリシーの削除・ライフサイクルの設定を報告する。
	// 保存済みの CreateTrail / UpdateTrail の宛先 (s3BucketName) も自動で加える。
	TrailBuckets []string `yaml:"trail_buckets"`
}

// PublicExposure は public_exposure (外部に開く設定変更) の設定 (ADR 0026)。
type PublicExposure struct {
	// SensitivePorts はセキュリティグループを 0.0.0.0/0・::/0 に開けたときに high とするポート (範囲が重なれば該当)。全ポート (protocol -1) は常に high。
	SensitivePorts []int `yaml:"sensitive_ports"`
}

// PrincipalNewSource は principal_new_source (既知の主体の初めての送信元・リージョン) の設定 (ADR 0027)。
type PrincipalNewSource struct {
	// BaselineDays は「初めて」とみなすために比べる過去の日数 (窓の始まりの日の前日から)。
	BaselineDays int `yaml:"baseline_days"`
	// MinBaselineDays は判定に要る、CloudTrail を収集し終えた過去日数 (活動の有無ではない) (導入直後に全部が初めてになるのを防ぐ)。既定は baseline_days の半分。
	MinBaselineDays int `yaml:"min_baseline_days"`
	// MinWrites は新しい送信元からの書き込みがこれ以上なら medium (それ未満は low)。
	MinWrites int `yaml:"min_writes"`
}

// SecretAccess は secret_access (秘匿値の読み取りの異常) の設定 (ADR 0027)。
type SecretAccess struct {
	// BaselineDays は「主体 × 秘匿値」の初出と、一括読み出しの平常帯に使う過去の日数。
	BaselineDays int `yaml:"baseline_days"`
	// MinBaselineDays は初出の判定に要る、CloudTrail を収集し終えた過去日数 (活動の有無ではない) (導入直後は初出を報告しない)。
	MinBaselineDays int `yaml:"min_baseline_days"`
	// Factor は一括読み出しの平常帯の倍率 (その主体の日ごとの異なる秘匿値の数の中央値 × factor)。
	Factor float64 `yaml:"factor"`
	// MinDistinct は一括読み出しとみなす異なる秘匿値の数の下限 (これを超えたら)。
	MinDistinct int `yaml:"min_distinct"`
}

// DefaultSensitivePorts は sensitive_ports の既定 (SSH・RDP・DB・キャッシュ・検索・Docker の API)。
var DefaultSensitivePorts = []int{22, 3389, 3306, 5432, 1433, 1521, 6379, 11211, 27017, 9200, 5601, 2375}

// DefaultDeniedErrorCodes は拒否とみなす errorCode の既定 (IAM・S3 などは AccessDenied / AccessDeniedException、EC2 は UnauthorizedOperation)。
var DefaultDeniedErrorCodes = []string{"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Client.UnauthorizedOperation"}

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
	ad := &c.AccessDenied
	if len(ad.ErrorCodes) == 0 {
		ad.ErrorCodes = DefaultDeniedErrorCodes
	}
	if ad.MinDistinctAPIs == 0 {
		ad.MinDistinctAPIs = 5
	}
	if ad.HighDistinctAPIs == 0 {
		ad.HighDistinctAPIs = 20
	}
	ad.Baseline.applyDefaults(50)
	setInt(&c.DefenseEvasion.MinLogRetentionDays, 90)
	if len(c.PublicExposure.SensitivePorts) == 0 {
		c.PublicExposure.SensitivePorts = DefaultSensitivePorts
	}
	ns := &c.PrincipalNewSource
	setInt(&ns.BaselineDays, 30)
	setInt(&ns.MinBaselineDays, (ns.BaselineDays+1)/2)
	setInt(&ns.MinWrites, 5)
	sa := &c.SecretAccess
	setInt(&sa.BaselineDays, 14)
	setInt(&sa.MinBaselineDays, (sa.BaselineDays+1)/2)
	setFloat(&sa.Factor, 3)
	setInt(&sa.MinDistinct, 10)
	if c.CredentialHygiene.UnusedDays == 0 {
		c.CredentialHygiene.UnusedDays = 90
	}
	if c.Posture.MinPasswordLength == 0 {
		c.Posture.MinPasswordLength = 14
	}
	wr := &c.WAFReview
	if wr.TopPaths == 0 {
		wr.TopPaths = 50
	}
	if len(wr.RatePathGroups) == 0 {
		wr.RatePathGroups = DefaultRatePathGroups
	}
	setInt(&wr.Days, 7)
	setFloat(&wr.MinDistinctIPs, 10)
	setFloat(&wr.FindingDistinctIPs, 50)
	setFloat(&wr.MinCount, 10)
	setFloat(&wr.RateFactor, 10)
	setFloat(&wr.RateMargin, 3)
	setFloat(&wr.RateFloor, 100)
	setFloat(&wr.RateLooseFactor, 10)
	setInt(&wr.UnusedDays, 30)
	setInt(&wr.MaxProposals, 20)
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
	if err := c.WAFReview.validate(); err != nil {
		return fmt.Errorf("waf_review: %w", err)
	}
	ad := c.AccessDenied
	if err := ad.Baseline.validate(); err != nil {
		return fmt.Errorf("access_denied: %w", err)
	}
	if ad.MinDistinctAPIs < 1 || ad.HighDistinctAPIs < ad.MinDistinctAPIs {
		return fmt.Errorf("access_denied: 1 <= min_distinct_apis <= high_distinct_apis")
	}
	for _, code := range ad.ErrorCodes {
		if code == "" {
			return fmt.Errorf("access_denied: error_codes must not contain an empty string")
		}
	}
	if c.DefenseEvasion.MinLogRetentionDays < 1 {
		return fmt.Errorf("defense_evasion: min_log_retention_days >= 1")
	}
	for _, b := range c.DefenseEvasion.TrailBuckets {
		if b == "" {
			return fmt.Errorf("defense_evasion: trail_buckets must not contain an empty string")
		}
	}
	for _, p := range c.PublicExposure.SensitivePorts {
		if p < 0 || p > 65535 {
			return fmt.Errorf("public_exposure: sensitive_ports must be 0-65535 (got %d)", p)
		}
	}
	if ns := c.PrincipalNewSource; ns.BaselineDays < 1 || ns.MinBaselineDays < 1 || ns.MinBaselineDays > ns.BaselineDays || ns.MinWrites < 1 {
		return fmt.Errorf("principal_new_source: baseline_days >= 1, 1 <= min_baseline_days <= baseline_days, min_writes >= 1")
	}
	if sa := c.SecretAccess; sa.BaselineDays < 1 || sa.MinBaselineDays < 1 || sa.MinBaselineDays > sa.BaselineDays || sa.Factor <= 0 || sa.MinDistinct < 1 {
		return fmt.Errorf("secret_access: baseline_days >= 1, 1 <= min_baseline_days <= baseline_days, factor > 0, min_distinct >= 1")
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

func setInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setFloat(p *float64, v float64) {
	if *p == 0 {
		*p = v
	}
}

func (w WAFReview) validate() error {
	if w.TopPaths < 1 || w.Days < 1 || w.UnusedDays < 1 || w.MaxProposals < 1 {
		return fmt.Errorf("top_paths, days, unused_days, max_proposals >= 1")
	}
	if w.MinDistinctIPs < 1 || w.FindingDistinctIPs < w.MinDistinctIPs || w.MinCount < 1 {
		return fmt.Errorf("min_distinct_ips >= 1, finding_distinct_ips >= min_distinct_ips, min_count >= 1")
	}
	if w.RateFactor <= 1 || w.RateMargin <= 0 || w.RateFloor < 1 || w.RateLooseFactor <= 1 {
		return fmt.Errorf("rate_factor > 1, rate_margin > 0, rate_floor >= 1, rate_loose_factor > 1")
	}
	for _, p := range append(append([]string{}, w.RatePathGroups...), w.ExpectedHighRatePaths...) {
		if len(p) == 0 || p[0] != '/' {
			return fmt.Errorf("path %q must start with /", p)
		}
	}
	for _, c := range w.TrustedCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			return fmt.Errorf("trusted_cidrs: %q is not a CIDR (e.g. 203.0.113.0/24)", c)
		}
	}
	return nil
}
