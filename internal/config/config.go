// Package config は YAML 設定の読み込み・検証・既定値を担う (設計書 4-1)。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config は arata の設定全体。
type Config struct {
	Name     string `yaml:"name"`
	Store    Store  `yaml:"-"`
	StoreURL string `yaml:"store"`
	// StoreProfile / StoreRegion は s3:// のストアのバケットに使う認証とリージョン (監査対象の aws: とは別。ADR 0034)。
	// StoreProfile の省略時は SDK の標準の連鎖、StoreRegion の省略時は aws.region。dir:// では書けない。
	StoreProfile string             `yaml:"store_profile"`
	StoreRegion  string             `yaml:"store_region"`
	Allowlist    string             `yaml:"allowlist"`
	AWS          AWS                `yaml:"aws"`
	Sources      []Source           `yaml:"sources"`
	Profiles     map[string]Profile `yaml:"profiles"`
	Retention    Retention          `yaml:"retention"`
	// Checks はアプリ層チェックのパス・閾値 (省略時は既定値)。
	Checks Checks `yaml:"checks"`
	// checksRaw は既定値を埋める前の checks: (パラメータの由来の判定に使う)。
	checksRaw Checks

	// Path は読み込んだ設定ファイルの絶対パス。
	Path string `yaml:"-"`
}

// Store はストアのバックエンド指定。dir:// は Dir、s3:// は Bucket と Prefix を使う。
type Store struct {
	Scheme string // "dir" / "s3"
	Dir    string
	Bucket string
	Prefix string // 末尾の / は持たない。空ならバケットの直下
}

// String はログと出力に使う表記 (dir:// はディレクトリ、s3:// は URL)。
func (s Store) String() string {
	if s.Scheme != "s3" {
		return s.Dir
	}
	if s.Prefix == "" {
		return "s3://" + s.Bucket
	}
	return "s3://" + s.Bucket + "/" + s.Prefix
}

// AWS は SDK の標準認証チェーンに渡す最小限の指定。
type AWS struct {
	Region  string `yaml:"region"`
	Profile string `yaml:"profile"`
}

// Source は収集元 1 つ。
type Source struct {
	ID   string `yaml:"id"`
	Kind string `yaml:"kind"`
	// Regions は引くリージョン。決定: 既定は [aws.region, us-east-1] (IAM / ConsoleLogin / STS の一部は us-east-1 に記録されるため)。
	// `region:` (単数) も後方互換で受け付け、1 要素にする。
	Regions   []string `yaml:"regions"`
	RegionRaw string   `yaml:"region"`
	// 以下は cloudwatch-logs 用 (設計書 2 章、cwlogs.go)。
	LogGroup     string            `yaml:"log_group"`
	StreamPrefix string            `yaml:"stream_prefix"`
	Format       string            `yaml:"format"`
	Regex        string            `yaml:"regex"`
	Yields       string            `yaml:"yields"`
	Fields       map[string]string `yaml:"fields"`
	// ExpectedMatchRate は解釈率の閾値 (既定 0.8)。下回ると FORMAT_MISMATCH。
	ExpectedMatchRate    float64  `yaml:"-"`
	ExpectedMatchRateRaw *float64 `yaml:"expected_match_rate"`
	// SampleLines は FORMAT_MISMATCH のエラーに解釈できなかった行の例 (マスク済み) を添えるか (既定 true)。
	SampleLines    bool  `yaml:"-"`
	SampleLinesRaw *bool `yaml:"sample_lines"`
	// StripPathPrefix は wafv2 のログの httpRequest.uri の前に付く接頭辞 (API Gateway の REST API のステージ名 `/prod` など)。
	// 探索パス・パスの群の判定とパスの正規化の前に外す (ADR 0023)。集計条件。wafv2 のときだけ。
	StripPathPrefix string `yaml:"strip_path_prefix"`
	// Resources は wafv2 のログのうち集計する資源 (httpSourceId の完全一致か、`*` / `?` の glob)。空なら全部。
	// 1 つの WebACL を本番と staging の資源が共有するときに本番だけを監査する (ADR 0028)。集計条件。スキャン量 (費用) は減らない。
	Resources []string `yaml:"resources"`
	// MaxScanGB は 1 回の収集でこのソースが Insights でスキャンしてよい量 (GB)。0 なら無制限。超えたら QUERY_LIMIT。
	MaxScanGB float64 `yaml:"max_scan_gb"`
	// IngestDelay はイベントが起きてから取得できるようになるまでの遅延の見込み。収集は [From - IngestDelay, To) を引き、
	// 前回の窓の末尾に起きて遅れて記録されたイベントを拾う (設計書 3 章、ADR 0013)。既定は kind ごと (DefaultIngestDelay)。0 で再走査しない。
	IngestDelay    time.Duration `yaml:"-"`
	IngestDelayRaw string        `yaml:"ingest_delay"`
}

// DefaultIngestDelay は kind ごとの ingest_delay の既定。
// 決定: CloudTrail は記録まで通常 5〜15 分かかるので上限の 15m、CloudWatch Logs は取り込みの数分の遅延を見て 5m。
var DefaultIngestDelay = map[string]time.Duration{KindCloudTrailLookup: 15 * time.Minute, KindCloudTrailUnusedRegions: 15 * time.Minute, KindCloudWatchLogs: 5 * time.Minute}

// Profile は周期ごとの窓とチェック集合。
type Profile struct {
	Window    time.Duration `yaml:"-"`
	WindowRaw string        `yaml:"window"`
	// MaxCatchup は前回 run からの追いつきの上限 (既定 7d)。決定: 設計書 3 章。
	MaxCatchup    time.Duration `yaml:"-"`
	MaxCatchupRaw string        `yaml:"max_catchup"`
	Checks        []string      `yaml:"checks"`
	// Overrides はこのプロファイルでだけ変える判定パラメータ (書かなければ全体の checks: の値)。
	// 決定: 集計条件 (CollectionParams) は書けない (params.go)。
	Overrides Checks `yaml:"overrides"`
}

// DefaultMaxCatchup は max_catchup の既定値。
const DefaultMaxCatchup = 7 * 24 * time.Hour

// GlobalRegion はグローバルサービス (IAM, STS, signin) のイベントが記録されるリージョン。
const GlobalRegion = "us-east-1"

// Retention は保持期間 (設計書 5-3)。
type Retention struct {
	RawJSONL time.Duration `yaml:"-"`
	Events   time.Duration `yaml:"-"`
	Metrics  time.Duration `yaml:"-"`
	Findings time.Duration `yaml:"-"`
	Runs     time.Duration `yaml:"-"`

	RawJSONLRaw string `yaml:"raw_jsonl"`
	EventsRaw   string `yaml:"events"`
	MetricsRaw  string `yaml:"metrics"`
	FindingsRaw string `yaml:"findings"`
	RunsRaw     string `yaml:"runs"`
}

// DefaultRetention は保持期間の既定値 (設計書 5-3)。
var DefaultRetention = Retention{RawJSONLRaw: "365d", EventsRaw: "90d", MetricsRaw: "400d", FindingsRaw: "180d", RunsRaw: "400d"}

// DefaultRegion は aws.region の既定値。
const DefaultRegion = "ap-northeast-1"

// source.kind。
const (
	KindCloudTrailLookup = "cloudtrail-lookup"
	KindCloudWatchLogs   = "cloudwatch-logs"
	// 以下はアカウント単位の状態 (スナップショット) を取る。窓に依らず、取るたびに丸ごと置き換える (ADR 0015)。
	KindCredentialReport = "iam-credential-report" // #nosec G101 -- 名前に credential を含むだけの種類の識別子で、秘密の値ではない
	KindGuardDuty        = "guardduty"
	KindAccessAnalyzer   = "access-analyzer"
	KindPosture          = "posture"
	// KindWAFConfig は WAFv2 の WebACL の設定。REGIONAL は regions、CLOUDFRONT は us-east-1 を引く (ADR 0023)。
	KindWAFConfig = "waf-config"
	// KindCloudTrailUnusedRegions は、アカウントで有効なリージョン (account:ListRegions) のうち cloudtrail-lookup の regions に無い
	// リージョン (ふだん使わないリージョン) の書き込みを LookupEvents で引く (unused_region_activity。ADR 0032)。regions は書かない (実行時に決める)。
	KindCloudTrailUnusedRegions = "cloudtrail-unused-regions"
	// KindCostAnomaly は AWS Cost Anomaly Detection の異常 (ce:GetAnomalies) のスナップショット。Cost Explorer の API は us-east-1 だけ (ADR 0032)。
	KindCostAnomaly = "cost-anomaly"
)

// SupportedKinds は受け付ける source.kind。
var SupportedKinds = map[string]bool{KindCloudTrailLookup: true, KindCloudWatchLogs: true,
	KindCredentialReport: true, KindGuardDuty: true, KindAccessAnalyzer: true, KindPosture: true, KindWAFConfig: true,
	KindCloudTrailUnusedRegions: true, KindCostAnomaly: true}

// SnapshotSourceKinds はスナップショットを取る source.kind (regions の既定は aws.region だけ、ingest_delay は使わない)。
var SnapshotSourceKinds = map[string]bool{KindCredentialReport: true, KindGuardDuty: true, KindAccessAnalyzer: true, KindPosture: true, KindWAFConfig: true, KindCostAnomaly: true}

// Load は設定を読み、既定値を埋め、検証する。
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", abs, err)
	}
	cfg.Path = abs
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() error {
	if c.AWS.Region == "" {
		c.AWS.Region = DefaultRegion
	}
	if c.Allowlist == "" {
		c.Allowlist = "allowlist.yaml"
	}
	if !filepath.IsAbs(c.Allowlist) {
		c.Allowlist = filepath.Join(filepath.Dir(c.Path), c.Allowlist)
	}
	for i := range c.Sources {
		s := &c.Sources[i]
		if s.RegionRaw != "" && len(s.Regions) > 0 {
			return fmt.Errorf("config: source %s: use either region or regions, not both", s.ID)
		}
		if s.RegionRaw != "" {
			s.Regions = []string{s.RegionRaw}
		}
		switch s.Kind {
		case KindCloudTrailUnusedRegions:
			// 決定 (ADR 0032): 対象のリージョンは実行時に「有効なリージョン − cloudtrail-lookup の regions」で決める。書かせない
			if len(s.Regions) > 0 {
				return fmt.Errorf("config: source %s: %s does not take regions (it scans the enabled regions that are not in the cloudtrail-lookup regions)", s.ID, s.Kind)
			}
		case KindCostAnomaly:
			if len(s.Regions) > 0 && (len(s.Regions) != 1 || s.Regions[0] != GlobalRegion) {
				return fmt.Errorf("config: source %s: %s: the Cost Explorer API is only in %s (omit regions)", s.ID, s.Kind, GlobalRegion)
			}
			s.Regions = []string{GlobalRegion}
		}
		if len(s.Regions) == 0 && s.Kind != KindCloudTrailUnusedRegions {
			if s.Kind == KindCloudWatchLogs || SnapshotSourceKinds[s.Kind] {
				// ロググループ・GuardDuty・アナライザーはリージョンに属するので既定は aws.region だけ (IAM と S3 のアカウント設定はグローバル)
				s.Regions = []string{c.AWS.Region}
			} else {
				s.Regions = []string{c.AWS.Region, GlobalRegion}
			}
		}
		s.Regions = dedup(s.Regions)
		if s.Kind == KindCloudWatchLogs {
			s.applyLogsDefaults()
		}
		s.IngestDelay = DefaultIngestDelay[s.Kind]
		if s.IngestDelayRaw != "" {
			d, err := parseDelay(s.IngestDelayRaw)
			if err != nil {
				return fmt.Errorf("config: source %s: ingest_delay %q: %w", s.ID, s.IngestDelayRaw, err)
			}
			s.IngestDelay = d
		}
	}
	c.checksRaw = c.Checks
	c.Checks.applyDefaults()
	defaults := []struct {
		raw *string
		dst *time.Duration
		def string
	}{
		{&c.Retention.RawJSONLRaw, &c.Retention.RawJSONL, DefaultRetention.RawJSONLRaw},
		{&c.Retention.EventsRaw, &c.Retention.Events, DefaultRetention.EventsRaw},
		{&c.Retention.MetricsRaw, &c.Retention.Metrics, DefaultRetention.MetricsRaw},
		{&c.Retention.FindingsRaw, &c.Retention.Findings, DefaultRetention.FindingsRaw},
		{&c.Retention.RunsRaw, &c.Retention.Runs, DefaultRetention.RunsRaw},
	}
	for _, d := range defaults {
		if *d.raw == "" {
			*d.raw = d.def
		}
		v, err := ParseDuration(*d.raw)
		if err != nil {
			return fmt.Errorf("config: retention %q: %w", *d.raw, err)
		}
		*d.dst = v
	}
	for name, p := range c.Profiles {
		if p.WindowRaw == "" {
			return fmt.Errorf("config: profile %s: window is required", name)
		}
		w, err := ParseDuration(p.WindowRaw)
		if err != nil {
			return fmt.Errorf("config: profile %s: window %q: %w", name, p.WindowRaw, err)
		}
		p.Window = w
		if p.MaxCatchupRaw == "" {
			p.MaxCatchup = DefaultMaxCatchup
		} else {
			mc, err := ParseDuration(p.MaxCatchupRaw)
			if err != nil {
				return fmt.Errorf("config: profile %s: max_catchup %q: %w", name, p.MaxCatchupRaw, err)
			}
			p.MaxCatchup = mc
		}
		c.Profiles[name] = p
	}
	return nil
}

// parseDelay は ParseDuration に加えて 0 (再走査しない) を受け付ける。
func parseDelay(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil && d == 0 || s == "0d" {
		return 0, nil
	}
	return ParseDuration(s)
}

// MaxIngestDelay はソースの ingest_delay の最大 (イベント型チェックが遅れて届いたイベントを探す幅)。
func (c *Config) MaxIngestDelay() time.Duration {
	var max time.Duration
	for _, s := range c.Sources {
		if s.IngestDelay > max {
			max = s.IngestDelay
		}
	}
	return max
}

// Validate は設定の整合性を検証する。
func (c *Config) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("config: name is required")
	}
	st, err := parseStore(c.StoreURL)
	if err != nil {
		return err
	}
	c.Store = st
	if st.Scheme != "s3" {
		// 効かない設定を黙って無視しない
		if c.StoreProfile != "" {
			return fmt.Errorf("config: store_profile is only for an s3:// store")
		}
		if c.StoreRegion != "" {
			return fmt.Errorf("config: store_region is only for an s3:// store")
		}
	} else if c.StoreRegion == "" {
		c.StoreRegion = c.AWS.Region
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("config: at least one source is required")
	}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if s.ID == "" {
			return fmt.Errorf("config: source id is required")
		}
		if !safeName(s.ID) {
			return fmt.Errorf("config: source id %q must not contain a path separator or be . or .. (it becomes a directory of the store)", s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("config: duplicate source id %q", s.ID)
		}
		seen[s.ID] = true
		if !SupportedKinds[s.Kind] {
			return fmt.Errorf("config: source %s: unsupported kind %q", s.ID, s.Kind)
		}
		if s.Kind == KindCloudWatchLogs {
			if err := s.validateLogs(); err != nil {
				return fmt.Errorf("config: source %s: %w", s.ID, err)
			}
		}
	}
	if err := c.validateUnusedRegions(); err != nil {
		return err
	}
	if err := c.Checks.validate(); err != nil {
		return fmt.Errorf("config: checks: %w", err)
	}
	if err := c.validateEndpointSources(); err != nil {
		return fmt.Errorf("config: checks: endpoint_abuse: %w", err)
	}
	if len(c.Profiles) == 0 {
		return fmt.Errorf("config: at least one profile is required (profiles:)")
	}
	for name, p := range c.Profiles {
		if !safeName(name) {
			return fmt.Errorf("config: profile %q must not contain a path separator or be . or .. (it becomes a file name of the store)", name)
		}
		if len(p.Checks) == 0 {
			return fmt.Errorf("config: profile %s: checks is required", name)
		}
		if err := validateOverrides(p.Overrides); err != nil {
			return fmt.Errorf("config: profile %s: %w", name, err)
		}
		eff := c.ChecksFor(name)
		if err := eff.validate(); err != nil {
			return fmt.Errorf("config: profile %s: overrides: %w", name, err)
		}
	}
	return nil
}

// safeName は source の id や profile 名をファイルのパスと S3 のキーに使えるか (ストアの外を指さないか)。ADR 0037
func safeName(s string) bool {
	return s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// validateUnusedRegions は cloudtrail-unused-regions のソースに cloudtrail-lookup のソースがあるかを確かめる。
func (c *Config) validateUnusedRegions() error {
	for _, s := range c.Sources {
		if s.Kind == KindCloudTrailUnusedRegions && len(c.ActiveRegions()) == 0 {
			return fmt.Errorf("config: source %s: %s は cloudtrail-lookup の regions を「ふだん使うリージョン」として使う (それ以外の有効なリージョンを引く)。cloudtrail-lookup のソースを足す", s.ID, s.Kind)
		}
	}
	return nil
}

// UnusedRegionSources は cloudtrail-unused-regions のソースの ID (設定順)。そのイベントは unused_region_activity だけが見る (ADR 0032)。
func (c *Config) UnusedRegionSources() []string {
	var out []string
	for _, s := range c.Sources {
		if s.Kind == KindCloudTrailUnusedRegions {
			out = append(out, s.ID)
		}
	}
	return out
}

// HasSourceKind は kind のソースがあるか。
func (c *Config) HasSourceKind(kind string) bool {
	for _, s := range c.Sources {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// ActiveRegions はふだん使うリージョン (cloudtrail-lookup のソースの regions の和。重複除去、設定順)。
// cloudtrail-unused-regions はアカウントで有効なリージョンからこれを除いたリージョンを引く (ADR 0032)。
func (c *Config) ActiveRegions() []string {
	var out []string
	for _, s := range c.Sources {
		if s.Kind == KindCloudTrailLookup {
			out = append(out, s.Regions...)
		}
	}
	return dedup(out)
}

// validateEndpointSources は endpoint_abuse の endpoints[].sources が http_access を出す cloudwatch-logs のソースかを確かめる。
func (c *Config) validateEndpointSources() error {
	byID := map[string]Source{}
	for _, s := range c.Sources {
		byID[s.ID] = s
	}
	for _, ep := range c.Checks.EndpointAbuse.Endpoints {
		for _, id := range ep.Sources {
			s, ok := byID[id]
			if ok && s.Kind == KindCloudWatchLogs && s.Yields == YieldsWAFAction {
				return fmt.Errorf("endpoints: %s: source %q is a wafv2 source, which endpoint_abuse does not support yet (planned; use an http_access source)", ep.Name, id)
			}
			if !ok || s.Kind != KindCloudWatchLogs || s.Yields != YieldsHTTPAccess {
				return fmt.Errorf("endpoints: %s: source %q must be a cloudwatch-logs source that yields http_access", ep.Name, id)
			}
		}
	}
	return nil
}

func parseStore(u string) (Store, error) {
	if u == "" {
		return Store{}, fmt.Errorf("config: store is required (e.g. dir:///var/lib/arata/<name> or s3://<bucket>/<prefix>)")
	}
	if rest, ok := strings.CutPrefix(u, "s3://"); ok {
		return parseS3Store(u, rest)
	}
	const prefix = "dir://"
	if !strings.HasPrefix(u, prefix) {
		return Store{}, fmt.Errorf("config: store %q: only dir:// and s3:// are supported", u)
	}
	dir := strings.TrimPrefix(u, prefix)
	if dir == "" {
		return Store{}, fmt.Errorf("config: store %q: path is empty", u)
	}
	return Store{Scheme: "dir", Dir: dir}, nil
}

func parseS3Store(u, rest string) (Store, error) {
	bucket, prefix, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return Store{}, fmt.Errorf("config: store %q: bucket is empty (want s3://<bucket>/<prefix>)", u)
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if strings.Contains(prefix, "//") || strings.HasPrefix(prefix, "/") {
		return Store{}, fmt.Errorf("config: store %q: prefix has an empty path segment", u)
	}
	return Store{Scheme: "s3", Bucket: bucket, Prefix: prefix}, nil
}

// ExpandChecks は `default-<cadence>` を展開した有効チェック名の一覧を返す (重複除去、ソート)。
// defaults は cadence 名 → その周期の全チェック名。
func (p Profile) ExpandChecks(defaults map[string][]string) []string {
	set := map[string]bool{}
	for _, name := range p.Checks {
		if cad, ok := strings.CutPrefix(name, "default-"); ok {
			for _, n := range defaults[cad] {
				set[n] = true
			}
			continue
		}
		set[name] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func dedup(l []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(l))
	for _, s := range l {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ParseDuration は time.ParseDuration に `d` (日) を加えた形式を解釈する。負値は拒否する。
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var d time.Duration
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive: %q", s)
	}
	return d, nil
}

// AuditLogGroups は arata が監査に使うロググループ (cloudwatch-logs のソースの log_group。重複除去、設定順)。
// defense_evasion がこれらのロググループへの削除・保持期間の短縮を critical にする (ADR 0026)。
func (c *Config) AuditLogGroups() []string {
	var out []string
	for _, s := range c.Sources {
		if s.Kind == KindCloudWatchLogs && s.LogGroup != "" {
			out = append(out, s.LogGroup)
		}
	}
	return dedup(out)
}
