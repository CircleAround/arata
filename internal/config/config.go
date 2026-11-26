// Package config は YAML 設定の読み込み・検証・既定値を担う (設計書 4-1)。
package config

import (
	"fmt"
	"math"
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
	StoreProfile string `yaml:"store_profile"`
	StoreRegion  string `yaml:"store_region"`
	Allowlist    string `yaml:"allowlist"`
	// AuditAccount は監査する側のアカウント: 12 桁の ID (別のアカウントのロールが監査対象の読み取り専用ロールを引き受ける) か
	// none (外から監査しない)。`arata config init --audit-account` が書く。空は「選んでいない」(この項目より前の版の設定)。
	// 決定 (ADR 0045): 判定には使わない (承認は allowlist だけが持つ)。config check / doctor が allowlist との食い違いを確かめる材料。
	AuditAccount string             `yaml:"audit_account"`
	AWS          AWS                `yaml:"aws"`
	Sources      []Source           `yaml:"sources"`
	Profiles     map[string]Profile `yaml:"profiles"`
	Retention    Retention          `yaml:"retention"`
	// IPList は怪しい IP の一覧 (ADR 0069)。nil なら一覧を作らない。
	IPList *IPList `yaml:"ip_list"`
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
	// Request は request_lines 形式のまとめ方 (request.go、ADR 0051)。request_lines のときだけ。
	Request *Request `yaml:"request"`
	// PathIDs はパスの中の ID の位置 (pathids.go、ADR 0071・0087)。http_access か http_user を出すソースだけ。
	PathIDs *PathIDs `yaml:"path_ids"`
	// ExpectedCompleteRate は request_lines の「まとめられた割合」(最初の行のあるリクエスト / request_id の数) の閾値 (既定 0.8)。下回ると FORMAT_MISMATCH。
	ExpectedCompleteRate    float64  `yaml:"-"`
	ExpectedCompleteRateRaw *float64 `yaml:"expected_complete_rate"`
	// 以下は cloudtrail-s3 用 (trail の S3 への配信。ADR 0063、trail_s3.go)。
	Bucket         string `yaml:"bucket"`
	Prefix         string `yaml:"prefix"`
	OrganizationID string `yaml:"organization_id"`
	// AccountID は記録を読むアカウント (監査されるアカウント。キーに入る)。
	AccountID string `yaml:"account_id"`
	// BucketRegion はバケットのリージョン (既定は aws.region)。
	BucketRegion string `yaml:"bucket_region"`
	// Collect は cloudwatch-logs の読み方。"hourly" なら時の単位で続きだけを読み、部分の行から日の値を作る (ADR 0065)。空なら日の頭から読み直す (今まで)。
	Collect string `yaml:"collect"`
	// MaxCollect は 1 回の収集でこのソースが集める範囲の上限 (0 なら上限なし)。超えたら上限まで集めて位置を進め、run は partial。
	// 決定 (ADR 0064): 資格情報が 1 時間で切れる環境 (GitHub Actions の役割の連鎖) で、止まった後の追いつきが毎回途中で失敗し続けないため。
	// CloudTrail の種類 (cloudtrail-lookup・cloudtrail-s3・cloudtrail-unused-regions) だけ。1h 以上
	MaxCollect    time.Duration `yaml:"-"`
	MaxCollectRaw string        `yaml:"max_collect"`
	// IngestDelay はイベントが起きてから取得できるようになるまでの遅延の見込み。収集は [From - IngestDelay, To) を引き、
	// 前回の窓の末尾に起きて遅れて記録されたイベントを拾う (設計書 3 章、ADR 0013)。既定は kind ごと (DefaultIngestDelay)。0 で再走査しない。
	IngestDelay    time.Duration `yaml:"-"`
	IngestDelayRaw string        `yaml:"ingest_delay"`
}

// DefaultIngestDelay は kind ごとの ingest_delay の既定。
// 決定: CloudTrail は記録まで通常 5〜15 分かかるので上限の 15m、CloudWatch Logs は取り込みの数分の遅延を見て 5m。
var DefaultIngestDelay = map[string]time.Duration{KindCloudTrailLookup: 15 * time.Minute, KindCloudTrailS3: 15 * time.Minute, KindCloudTrailUnusedRegions: 15 * time.Minute, KindCloudWatchLogs: 5 * time.Minute}

// Profile は周期ごとの窓とチェック集合。
type Profile struct {
	Window    time.Duration `yaml:"-"`
	WindowRaw string        `yaml:"window"`
	// MaxCatchup は前回 run からの追いつきの上限 (既定 7d)。決定: 設計書 3 章。
	MaxCatchup    time.Duration `yaml:"-"`
	MaxCatchupRaw string        `yaml:"max_catchup"`
	Checks        []string      `yaml:"checks"`
	// Records は、プロファイルのチェックが必要としなくても、この run で引く記録の種類 (ADR 0075)。今は http_user だけ書ける。
	// 決定: http_user を要るチェックがまだ無い間も、http_user だけを出すソースの日次の集計と coverage を毎日貯めるため。暗黙の既定は持たない (ADR 0014)。
	Records []string `yaml:"records"`
	// Silenced は報告に「黙らせているもの」の節 (ack・snooze 中の finding、期日の近い snooze、期限の近い allowlist の項目) を出す (ADR 0068)。
	// 暗黙の既定は持たない (ADR 0014)。雛形では weekly に書く。
	Silenced bool `yaml:"silenced"`
	// MinSeverity は重大度の下限 (ADR 0082)。この重大度より下の観測は、この run では差分判定に渡さず、記録も報告もしない
	// (次の下限なしのプロファイル、ふつうは daily が新規として報告する)。書かなければ下限なし。暗黙の既定は持たない (ADR 0014)。雛形では hourly に書く。
	// 決定: 入れられるのは event 型のチェックだけ (state 型は観測を捨てると既存の finding を解消してしまう)。チェックの型はこのパッケージから見えないので、
	// engine (run・config check・doctor) が確かめる。
	// 決定: 書いたかどうかを区別するため、YAML の節のまま受け取る (MinSeverityRaw)。空文字・null も誤り (書いたのに下限なし、を受け取らない。
	// repo check --flash と config init --diff が同じに見えるように)。
	MinSeverity    string    `yaml:"-"`
	MinSeverityRaw yaml.Node `yaml:"min_severity"`
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
	// IPList は怪しい IP の一覧 (ip_list_days) の保持の期間 M (ADR 0069)。M より前の日の行は書くときに消す。
	IPList time.Duration `yaml:"-"`

	RawJSONLRaw string `yaml:"raw_jsonl"`
	EventsRaw   string `yaml:"events"`
	MetricsRaw  string `yaml:"metrics"`
	FindingsRaw string `yaml:"findings"`
	RunsRaw     string `yaml:"runs"`
	IPListRaw   string `yaml:"ip_list"`
}

// DefaultRetention は保持期間の既定値 (設計書 5-3)。
var DefaultRetention = Retention{RawJSONLRaw: "365d", EventsRaw: "90d", MetricsRaw: "400d", FindingsRaw: "180d", RunsRaw: "400d", IPListRaw: "30d"}

// DefaultRegion は aws.region の既定値。
const DefaultRegion = "ap-northeast-1"

// source.kind。
const (
	KindCloudTrailLookup = "cloudtrail-lookup"
	// KindCloudTrailS3 は trail の S3 への配信 (gzip の JSON) を読む。cloudtrail-lookup と同じレコードを出す (ADR 0063)。
	KindCloudTrailS3   = "cloudtrail-s3"
	KindCloudWatchLogs = "cloudwatch-logs"
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
var SupportedKinds = map[string]bool{KindCloudTrailLookup: true, KindCloudTrailS3: true, KindCloudWatchLogs: true,
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
		case KindCloudTrailS3:
			// 決定 (ADR 0063): 読むリージョンは明示する (trail の記録の範囲は trail の設定に依るので、暗黙の既定を持たない。ADR 0014)
			if len(s.Regions) == 0 {
				return fmt.Errorf("config: source %s: regions is required for kind %s (e.g. [%s, %s])", s.ID, s.Kind, c.AWS.Region, GlobalRegion)
			}
			if s.BucketRegion == "" {
				s.BucketRegion = c.AWS.Region
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
			if err := s.applyRequestDefaults(); err != nil {
				return fmt.Errorf("config: source %s: %w", s.ID, err)
			}
		}
		if s.MaxCollectRaw != "" {
			switch {
			case s.Kind == KindCloudTrailLookup, s.Kind == KindCloudTrailS3, s.Kind == KindCloudTrailUnusedRegions:
			case s.Kind == KindCloudWatchLogs && s.Collect == CollectHourlyMode:
			default:
				return fmt.Errorf("config: source %s: max_collect is only for %s, %s, %s and %s with collect: %s (Logs Insights reads from the start of the day otherwise; see ADR 0065)",
					s.ID, KindCloudTrailLookup, KindCloudTrailS3, KindCloudTrailUnusedRegions, KindCloudWatchLogs, CollectHourlyMode)
			}
			d, err := ParseDuration(s.MaxCollectRaw)
			if err != nil {
				return fmt.Errorf("config: source %s: max_collect %q: %w", s.ID, s.MaxCollectRaw, err)
			}
			if d < time.Hour {
				return fmt.Errorf("config: source %s: max_collect %q must be at least 1h", s.ID, s.MaxCollectRaw)
			}
			s.MaxCollect = d
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
		{&c.Retention.IPListRaw, &c.Retention.IPList, DefaultRetention.IPListRaw},
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
	if c.IPList != nil {
		c.IPList.applyDefaults()
		if err := c.IPList.validate(c.Retention.IPList, c.Retention.IPListRaw); err != nil {
			return err
		}
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
		if p.MinSeverityRaw.Kind != 0 {
			v := p.MinSeverityRaw.Value
			if p.MinSeverityRaw.Kind != yaml.ScalarNode || p.MinSeverityRaw.Tag != "!!str" || !contains(MinSeverities, v) {
				if len(v) > 40 {
					v = v[:40]
				}
				return fmt.Errorf("config: profile %s: min_severity: %q: want %s (an empty value is an error; remove the line for no floor)", name, v, strings.Join(MinSeverities, ", "))
			}
			p.MinSeverity = v
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
	if c.AuditAccount != "" {
		if _, _, err := ParseAuditAccount(c.AuditAccount); err != nil {
			return fmt.Errorf("config: audit_account: %w", err)
		}
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
		if err := s.validateCollect(); err != nil {
			return fmt.Errorf("config: source %s: %w", s.ID, err)
		}
		if s.Kind == KindCloudWatchLogs {
			if err := s.validateLogs(); err != nil {
				return fmt.Errorf("config: source %s: %w", s.ID, err)
			}
		}
		if err := s.validateTrailS3(); err != nil {
			return fmt.Errorf("config: source %s: %w", s.ID, err)
		}
	}
	if err := c.validateTrailSources(); err != nil {
		return err
	}
	if err := c.validateUnusedRegions(); err != nil {
		return err
	}
	if err := c.Checks.validate(); err != nil {
		return fmt.Errorf("config: checks: %w", err)
	}
	if err := c.validateUserSources(); err != nil {
		return fmt.Errorf("config: checks: %w", err)
	}
	if err := c.validateEndpointSources(); err != nil {
		return fmt.Errorf("config: checks: endpoint_abuse: %w", err)
	}
	if err := c.validateHourlyEndpoints(); err != nil {
		return fmt.Errorf("config: checks: endpoint_abuse: %w", err)
	}
	if err := c.validateLogHygiene(); err != nil {
		return fmt.Errorf("config: checks: log_hygiene: %w", err)
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
		if err := c.validateRecords(p.Records); err != nil {
			return fmt.Errorf("config: profile %s: %w", name, err)
		}
	}
	return nil
}

// MinSeverities はプロファイルの min_severity に書ける値 (ADR 0082)。info は書けない (下限より下が info だけになり、意味が無い)。
var MinSeverities = []string{"critical", "high", "medium", "low"}

// ProfileRecords はプロファイルの records に書ける種類 (ADR 0075)。
// 決定: 今は http_user だけ。ほかの種類は、チェック無しで引く理由が出てから足す
// (log_hygiene を daily で引くと weekly のスナップショットを置き換え、http_access を hourly で引くと費用が増える)。
var ProfileRecords = []string{YieldsHTTPUser}

// validateRecords は profiles.<name>.records を確かめる。書いた種類を出すソースが無ければ拒否する (書いても何も起きない設定を黙って受け取らない)。
func (c *Config) validateRecords(records []string) error {
	seen := map[string]bool{}
	for _, r := range records {
		if !contains(ProfileRecords, r) {
			return fmt.Errorf("records: %q: want %s", r, strings.Join(ProfileRecords, ", "))
		}
		if seen[r] {
			return fmt.Errorf("records: duplicate %q", r)
		}
		seen[r] = true
		if !c.yieldsRecord(r) {
			return fmt.Errorf("records: %s: no source yields %s (a request_lines source with request.user_id)", r, r)
		}
	}
	return nil
}

// yieldsRecord は kind を出すソースがあるか (今は http_user だけを見る)。
func (c *Config) yieldsRecord(kind string) bool {
	for _, s := range c.Sources {
		if kind == YieldsHTTPUser && s.Kind == KindCloudWatchLogs && s.UserIDFrom() != UserIDFromNone {
			return true
		}
	}
	return false
}

// safeName は source の id や profile 名をファイルのパスと S3 のキーに使えるか (ストアの外を指さないか)。ADR 0037
func safeName(s string) bool {
	return s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// validateUnusedRegions は cloudtrail-unused-regions のソースに cloudtrail-lookup のソースがあるかを確かめる。
func (c *Config) validateUnusedRegions() error {
	for _, s := range c.Sources {
		if s.Kind == KindCloudTrailUnusedRegions && len(c.ActiveRegions()) == 0 {
			return fmt.Errorf("config: source %s: %s は cloudtrail-lookup (か cloudtrail-s3) の regions を「ふだん使うリージョン」として使う (それ以外の有効なリージョンを引く)。cloudtrail-lookup か cloudtrail-s3 のソースを足す", s.ID, s.Kind)
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

// PathIDSources は path_ids を書いたソースの ID (利用者ごとのチェックが型を読めるソース。ADR 0071)。
func (c *Config) PathIDSources() []string {
	var out []string
	for _, s := range c.Sources {
		if s.PathRules() != nil {
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

// ActiveRegions はふだん使うリージョン (cloudtrail-lookup・cloudtrail-s3 のソースの regions の和。重複除去、設定順)。
// cloudtrail-unused-regions はアカウントで有効なリージョンからこれを除いたリージョンを引く (ADR 0032)。
func (c *Config) ActiveRegions() []string {
	var out []string
	for _, s := range c.Sources {
		if s.Kind == KindCloudTrailLookup || s.Kind == KindCloudTrailS3 {
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
	// 決定 (ADR 0041。ファズで見つけた): 空の区間は末尾の / を外す前に見る。外した後に見ると s3://b/p// が通り、接頭辞が "p/" になる
	if strings.Contains(prefix, "//") || strings.HasPrefix(prefix, "/") {
		return Store{}, fmt.Errorf("config: store %q: prefix has an empty path segment", u)
	}
	prefix = strings.TrimSuffix(prefix, "/")
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

// MaxDurationDays は `d` (日) で書ける上限 (time.Duration に収まる日数。約 292 年)。
// 決定 (ADR 0041。ファズで見つけた): 超える値は桁あふれで別の長さになる (213504d が 25 分になる) ので、エラーにする。
const MaxDurationDays = int(math.MaxInt64 / (24 * time.Hour))

// ParseDuration は time.ParseDuration に `d` (日) を加えた形式を解釈する。負値は拒否する。
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var d time.Duration
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n > MaxDurationDays || n < -MaxDurationDays {
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
