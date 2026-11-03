// Package record は collect が出力する正規化レコードの型を定義する。
// 設計書 4-1 の record パッケージに相当する。trail_event / principal_seen (CloudTrail) と metric (Logs Insights の日次集計)。
package record

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Kind は正規化レコードの種類。チェックは Needs() でこの種類を宣言する。
type Kind string

const (
	KindTrailEvent    Kind = "trail_event"
	KindPrincipalSeen Kind = "principal_seen"
	// 後続 Step で追加する種類 (チェックの Needs 宣言とカバレッジ判定で使う)。
	KindHTTPAccess  Kind = "http_access"
	KindWAFAction   Kind = "waf_action"
	KindMetric      Kind = "metric"
	KindPostureItem Kind = "posture_item"
	KindGuardDuty   Kind = "guardduty"
	// KindCredentialReport は IAM 認証情報レポートの 1 行 (ユーザー 1 人)。
	KindCredentialReport Kind = "iam_credential_report"
	// KindAccessAnalyzer は IAM Access Analyzer の ACTIVE な finding 1 件。
	KindAccessAnalyzer Kind = "access_analyzer"
	// KindWAFConfig は WAFv2 の WebACL の設定 (WebACL 1 件か、その中のルール 1 件)。
	KindWAFConfig Kind = "waf_config"
)

// SnapshotKinds は「窓に依らない今の状態」を表すレコード種類。collector が取るたびに丸ごと置き換えて保存する (ADR 0015)。
var SnapshotKinds = map[Kind]bool{KindCredentialReport: true, KindGuardDuty: true, KindAccessAnalyzer: true, KindPostureItem: true, KindWAFConfig: true}

// PrincipalKind は主体の種類。principals.kind に対応する。
type PrincipalKind string

const (
	PrincipalUser        PrincipalKind = "user"
	PrincipalRole        PrincipalKind = "role"
	PrincipalAssumedRole PrincipalKind = "assumed-role"
	PrincipalRoot        PrincipalKind = "root"
	PrincipalService     PrincipalKind = "service"
	PrincipalUnknown     PrincipalKind = "unknown"
)

var accountRootRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::(\d{12}):root$`)

// ExternalAccount は主体が「外部アカウントそのもの」(arn:aws:iam::NNN:root で、自アカウントの Root ではないもの) なら
// そのアカウント ID を返す。CloudTrail の userIdentity.type が AWSAccount (SaaS 連携のクロスアカウント AssumeRole など) のとき、
// collector はこの形に正規化する。自アカウントの Root は kind=root なので該当しない。
func ExternalAccount(arn string, kind PrincipalKind) (string, bool) {
	if kind == PrincipalRoot {
		return "", false
	}
	m := accountRootRe.FindStringSubmatch(arn)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// PrincipalLabel はレポートの文面に使う主体の表示。外部アカウントの root は「外部アカウント NNN」と書く (決定: 設計書 6 章)。
func PrincipalLabel(arn string, kind PrincipalKind) string {
	if acct, ok := ExternalAccount(arn, kind); ok {
		return "外部アカウント " + acct
	}
	return arn
}

// Record は JSONL に書き出す 1 行。
type Record interface {
	RecordKind() Kind
	RecordTime() time.Time
}

// TrailEvent は CloudTrail の「注目イベント」1 件。
// 個人特定値 (氏名・メールアドレス) は入れない。セッション名も落とす。
type TrailEvent struct {
	EventID       string         `json:"event_id"`
	Time          time.Time      `json:"time"`
	Source        string         `json:"source"`
	Name          string         `json:"name"`
	EventSource   string         `json:"event_source"`
	PrincipalARN  string         `json:"principal_arn"`
	PrincipalKind PrincipalKind  `json:"principal_kind"`
	IP            string         `json:"ip,omitempty"`
	Region        string         `json:"region,omitempty"`
	Resource      string         `json:"resource,omitempty"`
	ReadOnly      bool           `json:"read_only"`
	ErrorCode     string         `json:"error_code,omitempty"`
	Data          map[string]any `json:"data,omitempty"`
	// CollectedAt は収集した run の時刻 (engine が付ける)。再走査で遅れて届いたイベントを見分ける (ADR 0013)。
	CollectedAt time.Time `json:"collected_at,omitzero"`
}

func (e TrailEvent) RecordKind() Kind      { return KindTrailEvent }
func (e TrailEvent) RecordTime() time.Time { return e.Time }

// PrincipalSeen は窓内で主体 × IP を観測した事実 (件数付き)。
type PrincipalSeen struct {
	Time      time.Time     `json:"time"` // 窓内の最終観測時刻
	FirstTime time.Time     `json:"first_time"`
	Source    string        `json:"source"`
	ARN       string        `json:"arn"`
	Kind      PrincipalKind `json:"kind"`
	IP        string        `json:"ip,omitempty"`
	Region    string        `json:"region,omitempty"`
	Count     int           `json:"count"`
	// RescanCount は再走査の区間 [ScanFrom, From) の件数 (Count には含めない)。前回の run で数え済みかもしれないので、
	// store は (arn, ip) の行を初めて作るときだけ足す (ADR 0013)。
	RescanCount int `json:"rescan_count,omitempty"`
}

func (p PrincipalSeen) RecordKind() Kind      { return KindPrincipalSeen }
func (p PrincipalSeen) RecordTime() time.Time { return p.Time }

// Metric は日次集計 1 件 (metrics テーブルの 1 行)。Logs Insights の集計クエリの結果で、生ログは持たない (ADR 0006)。
// From は集計元の正規化レコード種類 (http_access / waf_action)。Key は IP・パス・ルール ID など (個人特定値は入れない)。
//
// 決定: 日付は UTC。同じ (Date, Source, Metric, Key) は後から来た値で置き換える (collector は日の頭から引き直すので、
// 後の値ほど完全)。raw JSONL には追記されるので、rebuild は行順に適用すれば最後の値になる。
type Metric struct {
	Date   string  `json:"date"` // YYYY-MM-DD (UTC)
	Source string  `json:"source"`
	From   Kind    `json:"from"`
	Metric string  `json:"metric"`
	Key    string  `json:"key"`
	Value  float64 `json:"value"`
}

// cloudtrail collector が出す主体の活動の日次集計 (principal_new_source / secret_access。ADR 0027)。Key は ActivityKey の形。
//
// 決定: Metric の「同じ (Date, Source, Metric, Key) は後から来た値で置き換える」規則のため、値は「その日のうち、最後にその日を
// 引いた run が見た件数」(下限) になる (cloudtrail は日の頭から引き直さない)。判定は「その日に有ったか」と、窓の日の下限値にだけ使う。
const (
	// MetricPrincipalSource は主体 × 送信元 (/24・/48) の件数。
	MetricPrincipalSource = "principal_source"
	// MetricPrincipalSourceWrites はそのうち成功した書き込み (readOnly=false) の件数。0 なら出さない。
	MetricPrincipalSourceWrites = "principal_source_writes"
	// MetricPrincipalWriteRegion は主体 × リージョンの、成功した書き込みの件数。
	MetricPrincipalWriteRegion = "principal_write_region"
)

// ActivityKey は活動の日次集計の Key (主体 ARN と値を "|" でつなぐ。ARN には "|" が入らない)。
func ActivityKey(arn, v string) string { return arn + "|" + v }

// SplitActivityKey は ActivityKey を分ける。
func SplitActivityKey(k string) (arn, v string, ok bool) {
	i := strings.LastIndex(k, "|")
	if i < 0 {
		return "", "", false
	}
	return k[:i], k[i+1:], true
}

// SourcePrefix は送信元 IP を /24 (IPv4) か /48 (IPv6) のネットワークにする。IP でないもの (サービス名・"AWS Internal") は false。
// 決定: 「初めての送信元」はこの単位で比べる (同じ回線・同じ事業者の近い IP の入れ替わりを新しい送信元にしない。ADR 0027)。
func SourcePrefix(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "", false
	}
	return p.String(), true
}

// DateLayout は Metric.Date の書式。
const DateLayout = "2006-01-02"

func (m Metric) RecordKind() Kind { return KindMetric }
func (m Metric) RecordTime() time.Time {
	t, _ := time.Parse(DateLayout, m.Date)
	return t
}

// SnapshotItem はスナップショット (SnapshotKinds) の 1 項目。Key は種類の中で項目を一意に決める (ユーザー名、finding ID、姿勢の項目名など)。
// 決定 (ADR 0015): 種類ごとに型を分けず Data に持つ。保存は (kind, source) 単位で丸ごと置き換え、チェックは Data を読む。
// 個人特定値 (メールアドレスなど) は入れない。IAM ユーザー名は主体の識別子として入れる (ARN と同じ扱い)。
type SnapshotItem struct {
	Kind   Kind           `json:"kind"`
	Time   time.Time      `json:"time"` // 取得した時刻
	Source string         `json:"source"`
	Key    string         `json:"key"`
	Data   map[string]any `json:"data"`
}

func (s SnapshotItem) RecordKind() Kind      { return s.Kind }
func (s SnapshotItem) RecordTime() time.Time { return s.Time }

// String は Data の文字列値 (無ければ "")。
func (s SnapshotItem) String(k string) string {
	v, _ := s.Data[k].(string)
	return v
}

// Bool は Data の真偽値 (無ければ false)。
func (s SnapshotItem) Bool(k string) bool {
	v, _ := s.Data[k].(bool)
	return v
}

// Number は Data の数値 (JSON から戻すと float64、Go から直接入れると int のことがある)。
func (s SnapshotItem) Number(k string) float64 {
	switch v := s.Data[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case int32:
		return float64(v)
	}
	return 0
}

// Envelope は JSONL 1 行の外枠。
type Envelope struct {
	Kind Kind            `json:"kind"`
	Time time.Time       `json:"time"`
	Data json.RawMessage `json:"data"`
}

// Marshal はレコードを JSONL 1 行 (改行なし) に直列化する。
func Marshal(r Record) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{Kind: r.RecordKind(), Time: r.RecordTime().UTC(), Data: data})
}

// Unmarshal は JSONL 1 行をレコードに戻す (rebuild 用)。
func Unmarshal(line []byte) (Record, error) {
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, err
	}
	switch env.Kind {
	case KindTrailEvent:
		var e TrailEvent
		if err := json.Unmarshal(env.Data, &e); err != nil {
			return nil, err
		}
		return e, nil
	case KindPrincipalSeen:
		var p PrincipalSeen
		if err := json.Unmarshal(env.Data, &p); err != nil {
			return nil, err
		}
		return p, nil
	case KindMetric:
		var m Metric
		if err := json.Unmarshal(env.Data, &m); err != nil {
			return nil, err
		}
		return m, nil
	default:
		if SnapshotKinds[env.Kind] {
			var it SnapshotItem
			if err := json.Unmarshal(env.Data, &it); err != nil {
				return nil, err
			}
			return it, nil
		}
		return nil, fmt.Errorf("record: unknown kind %q", env.Kind)
	}
}
