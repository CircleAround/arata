// Package allowlist は既知リスト allowlist.yaml の読み込み (設計書 6-1) と、approve による追記 (write.go、ADR 0010) を担う。
package allowlist

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Status は allowlist 突合の結果。
type Status string

const (
	StatusUnknown  Status = "unknown"
	StatusApproved Status = "approved"
	StatusExpired  Status = "expired"
)

// PrincipalEntry は principals の 1 件。主体の指定は arn / account / arn_pattern のどれか 1 つ。
//
// 決定:
//   - arn: 完全一致
//   - account: 12 桁のアカウント ID。そのアカウントの全主体 (外部アカウントの root を含む) を承認する。監視 SaaS など SaaS 連携用
//   - arn_pattern: glob (`*` は `/` や `:` も含む任意の文字列、`?` は 1 文字)。例: arn:aws:iam::123456789012:role/github-actions-*
//   - 複数のエントリに一致するときは、有効な (expires 前の) 承認が 1 つでもあれば approved。その中で最も具体的なもの (arn > arn_pattern > account) を返す
type PrincipalEntry struct {
	ARN        string   `yaml:"arn"`
	Account    string   `yaml:"account"`
	ARNPattern string   `yaml:"arn_pattern"`
	Note       string   `yaml:"note"`
	ApprovedBy string   `yaml:"approved_by"`
	ApprovedAt string   `yaml:"approved_at"`
	Expires    string   `yaml:"expires"`
	Tags       []string `yaml:"tags"` // 決定: 任意のタグ。`deploy` なら iam_changes を info に下げる
	// ExpectedDenied は access_denied で数えない「想定済みの拒否」(「サービス:操作」の glob。ADR 0022)。
	// 主体の承認とは独立に評価するが、項目そのものは主体を承認する (expected_denied だけの項目でも new_principal などは止まる)。
	ExpectedDenied []string `yaml:"expected_denied"`
	// DynamicSource は送信元が毎回変わる主体 (CI のランナーなど)。principal_new_source の low (新しい送信元だけ) を出さない。
	// medium 以上 (書き込みが多い・新しいリージョン・拒否も出ている) は出す (ADR 0027)。
	DynamicSource bool `yaml:"dynamic_source"`

	expires time.Time
	pattern *regexp.Regexp
	denied  []*regexp.Regexp
}

// active は at 時点で期限内か。
func (e *PrincipalEntry) active(at time.Time) bool {
	return e.expires.IsZero() || at.Before(e.expires)
}

// Subject はエントリが承認する対象の表示 (arn / account:NNN / arn_pattern)。
func (e *PrincipalEntry) Subject() string {
	switch {
	case e.ARN != "":
		return e.ARN
	case e.Account != "":
		return "account:" + e.Account
	default:
		return e.ARNPattern
	}
}

func (e *PrincipalEntry) matches(arn string) bool {
	switch {
	case e.ARN != "":
		return e.ARN == arn
	case e.pattern != nil:
		return e.pattern.MatchString(arn)
	case e.Account != "":
		return AccountOf(arn) == e.Account
	}
	return false
}

// specificity は一致したときの優先順位 (大きいほど具体的)。
func (e *PrincipalEntry) specificity() int {
	switch {
	case e.ARN != "":
		return 3
	case e.ARNPattern != "":
		return 2
	}
	return 1
}

// AccountOf は ARN のアカウント ID (arn:partition:service:region:ACCOUNT:resource) を返す。取れなければ "" 。
func AccountOf(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

var accountRe = regexp.MustCompile(`^\d{12}$`)

// deniedGlobRe は expected_denied の書式 (サービス:操作。空白なし、両側とも空でない)。
var deniedGlobRe = regexp.MustCompile(`^[^:\s]+:[^:\s]+$`)

// CheckDeniedGlob は expected_denied の 1 件の書式を確かめる。
func CheckDeniedGlob(g string) error {
	if !deniedGlobRe.MatchString(g) {
		return fmt.Errorf("%q: want service:Action (the form of access_denied apis, e.g. logs:StartQuery, logs:Get*, secretsmanager:*)", g)
	}
	return nil
}

// FormatExpectedDenied は expected_denied の値を YAML のフロー形式 (["logs:StartQuery", "logs:Get*"]) で書く。
func FormatExpectedDenied(globs []string) string {
	q := make([]string, len(globs))
	for i, g := range globs {
		q[i] = fmt.Sprintf("%q", g)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// MatchPattern は arn_pattern (glob) が arn に一致するか。
func MatchPattern(pattern, arn string) (bool, error) {
	re, err := globToRegexp(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(arn), nil
}

// globToRegexp は glob を先頭から末尾までの一致の正規表現にする。
// 決定 (ADR 0041。ファズで見つけた): UTF-8 として不正な glob はエラーにする。不正なバイトは 1 つの置き換え文字として扱われるので、
// 別々の不正なバイト列が同じものとして一致してしまう (承認の照合を曖昧にしない)。
func globToRegexp(glob string) (*regexp.Regexp, error) {
	if !utf8.ValidString(glob) {
		return nil, fmt.Errorf("pattern %q is not valid UTF-8", glob)
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// HasTag はタグを持つか。nil レシーバでも安全。
func (e *PrincipalEntry) HasTag(tag string) bool {
	if e == nil {
		return false
	}
	for _, t := range e.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// SourceIPEntry は source_ips の 1 件。
type SourceIPEntry struct {
	CIDR string `yaml:"cidr"`
	Note string `yaml:"note"`

	net *net.IPNet
}

// SecretsAccessEntry は secrets_access の 1 件。主体 (ARN の完全一致か principal_pattern) が読んでよい秘匿値 (名前・パスの glob)。
// 決定 (ADR 0027): secret_access は、一致する秘匿値を「初めて読む秘匿値」に数えない (一括読み出しの数には数える)。
// 決定 (ADR 0073): bulk: exempt の項目に一致する秘匿値は、一括読み出しの数からも外す (明示の opt-in。外すかの最後の判定は secret_access)。
// 決定 (ADR 0079): 主体は principal (完全一致) か principal_pattern (CheckPrincipalPattern の形) のどちらか 1 つ。
type SecretsAccessEntry struct {
	Principal string `yaml:"principal"`
	// PrincipalPattern は、CloudFormation が付ける末尾の乱数だけを `-*` にしたロールの ARN (ADR 0079)
	PrincipalPattern string   `yaml:"principal_pattern"`
	Secrets          []string `yaml:"secrets"`
	// Bulk は一括読み出しの数の扱い。空 (今までどおり数える) か BulkExempt だけ
	Bulk string `yaml:"bulk"`
	// Note は理由。bulk: exempt の項目では必須
	Note string `yaml:"note"`

	secrets []*regexp.Regexp
}

// List は allowlist 全体。
type List struct {
	Principals    []PrincipalEntry     `yaml:"principals"`
	SourceIPs     []SourceIPEntry      `yaml:"source_ips"`
	AdminUsers    []string             `yaml:"admin_users"`
	SecretsAccess []SecretsAccessEntry `yaml:"secrets_access"`
	// AssumeDestinations は、外向きの引き受けで行き先として既知のアカウント (ADR 0047)。principals (呼び出し元) とは別。
	AssumeDestinations []DestinationEntry `yaml:"assume_destinations"`
	// OIDCSubjects は、OIDC でのロールの引き受けの既知の入り口 (ADR 0055)。principals (主体の承認) とは別。
	OIDCSubjects []OIDCSubjectEntry `yaml:"oidc_subjects"`

	byARN map[string]*PrincipalEntry
	// broad は account / arn_pattern のエントリ
	broad []*PrincipalEntry
}

// Load は allowlist.yaml を読む。ファイルが無ければ空のリストを返す (init 直後の状態を許す)。
func Load(path string) (*List, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Parse(nil)
		}
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	l, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %s: %w", path, err)
	}
	return l, nil
}

// Parse は YAML バイト列から List を作り検証する。
func Parse(b []byte) (*List, error) {
	var l List
	if len(b) > 0 {
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&l); err != nil {
			return nil, err
		}
	}
	l.byARN = make(map[string]*PrincipalEntry, len(l.Principals))
	for i := range l.Principals {
		e := &l.Principals[i]
		n := 0
		for _, v := range []string{e.ARN, e.Account, e.ARNPattern} {
			if v != "" {
				n++
			}
		}
		if n != 1 {
			return nil, entryErr("principals", i, "exactly one of arn, account, arn_pattern is required")
		}
		if e.Account != "" && !accountRe.MatchString(e.Account) {
			return nil, entryErr("principals", i, "account %q: want a 12-digit account ID", e.Account)
		}
		if e.ARNPattern != "" {
			if !strings.HasPrefix(e.ARNPattern, "arn:") {
				return nil, entryErr("principals", i, "arn_pattern %q must start with \"arn:\"", e.ARNPattern)
			}
			// 決定 (ADR 0037): アカウントの欄は固定する。`arn:*` のようなパターンは new_principal などを全部止めてしまう
			if parts := strings.SplitN(e.ARNPattern, ":", 6); len(parts) < 6 || !accountRe.MatchString(parts[4]) {
				return nil, entryErr("principals", i, "arn_pattern %q must name a 12-digit account (arn:aws:iam::123456789012:role/ci-*)", e.ARNPattern)
			}
			re, err := globToRegexp(e.ARNPattern)
			if err != nil {
				return nil, entryErr("principals", i, "arn_pattern: %w", err)
			}
			e.pattern = re
		}
		if e.Expires != "" {
			t, err := time.Parse("2006-01-02", e.Expires)
			if err != nil {
				return nil, entryErr("principals", i, "expires %q: want YYYY-MM-DD", e.Expires)
			}
			// 期限日の終わりまで有効
			e.expires = t.Add(24 * time.Hour)
		}
		if e.ExpectedDenied != nil {
			if len(e.ExpectedDenied) == 0 {
				return nil, entryErr("principals", i, "expected_denied is empty (remove it or list service:Action globs such as logs:StartQuery)")
			}
			if strings.TrimSpace(e.Note) == "" {
				return nil, entryErr("principals", i, "note is required with expected_denied (why these denials are expected)")
			}
			for j, g := range e.ExpectedDenied {
				if err := CheckDeniedGlob(g); err != nil {
					return nil, entryErr("principals", i, "expected_denied[%d] %w", j, err)
				}
				re, err := globToRegexp(g)
				if err != nil {
					return nil, entryErr("principals", i, "expected_denied[%d]: %w", j, err)
				}
				e.denied = append(e.denied, re)
			}
		}
		if e.ARN != "" {
			l.byARN[e.ARN] = e
		} else {
			l.broad = append(l.broad, e)
		}
	}
	for i := range l.SecretsAccess {
		e := &l.SecretsAccess[i]
		if (e.Principal == "") == (e.PrincipalPattern == "") {
			return nil, entryErr("secrets_access", i, "exactly one of principal, principal_pattern is required")
		}
		if len(e.Secrets) == 0 {
			return nil, entryErr("secrets_access", i, "principal and secrets are required")
		}
		if e.PrincipalPattern != "" {
			if err := CheckPrincipalPattern(e.PrincipalPattern); err != nil {
				return nil, entryErr("secrets_access", i, "%w", err)
			}
		}
		for j, g := range e.Secrets {
			if strings.TrimSpace(g) == "" {
				return nil, entryErr("secrets_access", i, "secrets[%d] is empty", j)
			}
			re, err := globToRegexp(g)
			if err != nil {
				return nil, entryErr("secrets_access", i, "secrets[%d]: %w", j, err)
			}
			e.secrets = append(e.secrets, re)
		}
		if err := checkBulk(e); err != nil {
			return nil, entryErr("secrets_access", i, "%w", err)
		}
	}
	for i := range l.AssumeDestinations {
		if err := l.AssumeDestinations[i].validate(); err != nil {
			return nil, entryErr("assume_destinations", i, "%w", err)
		}
	}
	for i := range l.OIDCSubjects {
		if err := l.OIDCSubjects[i].validate(); err != nil {
			return nil, entryErr("oidc_subjects", i, "%w", err)
		}
	}
	for i := range l.SourceIPs {
		e := &l.SourceIPs[i]
		_, n, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			return nil, entryErr("source_ips", i, "%w", err)
		}
		e.net = n
	}
	return &l, nil
}

// Principal は ARN に一致するエントリを引き、at 時点での状態を返す。unknown のとき entry は nil。
// 有効な承認が 1 つでもあれば approved (最も具体的な有効エントリを返す)。一致したものが全部期限切れなら expired。
func (l *List) Principal(arn string, at time.Time) (*PrincipalEntry, Status) {
	var matched []*PrincipalEntry
	if e, ok := l.byARN[arn]; ok {
		matched = append(matched, e)
	}
	for _, e := range l.broad {
		if e.matches(arn) {
			matched = append(matched, e)
		}
	}
	var approved, expired *PrincipalEntry
	for _, e := range matched {
		if !e.active(at) {
			if expired == nil || e.specificity() > expired.specificity() {
				expired = e
			}
			continue
		}
		if approved == nil || e.specificity() > approved.specificity() {
			approved = e
		}
	}
	switch {
	case approved != nil:
		return approved, StatusApproved
	case expired != nil:
		return expired, StatusExpired
	}
	return nil, StatusUnknown
}

// Account は、アカウント id を承認する account: の項目が at 時点であるか。期限内の項目が 1 つでもあれば approved、
// 期限切れだけなら expired、無ければ unknown。
//
// 決定 (ADR 0045): arn / arn_pattern の項目は数えない。別のアカウントからの AssumeRole は、ロール側の CloudTrail には呼び出し元の
// アカウント ID しか残らない (どの IAM 主体かは残らない) ので、止められるのは account: の項目だけ。
func (l *List) Account(id string, at time.Time) Status {
	st := StatusUnknown
	for i := range l.Principals {
		e := &l.Principals[i]
		if id == "" || e.Account != id {
			continue
		}
		if e.active(at) {
			return StatusApproved
		}
		st = StatusExpired
	}
	return st
}

// DeniedExpected は、arn の api (「サービス:操作」) の拒否が、at 時点で期限内の項目の expected_denied に一致するか。
//
// 決定: 主体に一致する期限内の項目すべての expected_denied の和で判定する。Principal は同じ arn の重複項目を後勝ちで 1 つだけ見るが、
// 想定済みの拒否は項目ごとに理由 (note) と期限が違ってよいので、どれか 1 つの項目に書いてあれば除く。Principal の後勝ちは変えない。
func (l *List) DeniedExpected(arn, api string, at time.Time) bool {
	for i := range l.Principals {
		e := &l.Principals[i]
		if len(e.denied) == 0 || !e.active(at) || !e.matches(arn) {
			continue
		}
		for _, re := range e.denied {
			if re.MatchString(api) {
				return true
			}
		}
	}
	return false
}

// HasExpectedDenied は expected_denied を持つ項目が 1 つでもあるか。
func (l *List) HasExpectedDenied() bool {
	for i := range l.Principals {
		if len(l.Principals[i].denied) > 0 {
			return true
		}
	}
	return false
}

// SecretExpected は arn が secret (Secrets Manager のシークレットの名前か ARN、SSM のパラメータ名かパス) を読むことが
// secrets_access に書いてあるか。シークレットの ARN はシークレット名の部分 (":secret:" の後) でも比べる。
func (l *List) SecretExpected(arn, secret string) bool {
	cands := []string{secret}
	if _, name, ok := strings.Cut(secret, ":secret:"); ok && strings.HasPrefix(secret, "arn:") {
		cands = append(cands, name)
	}
	for i := range l.SecretsAccess {
		e := &l.SecretsAccess[i]
		if !e.matchesPrincipal(arn) {
			continue
		}
		for _, re := range e.secrets {
			for _, c := range cands {
				if re.MatchString(c) {
					return true
				}
			}
		}
	}
	return false
}

// BulkExempt は secrets_access の項目の bulk の値で、一致する秘匿値を一括読み出しの数から外す (ADR 0073)。
const BulkExempt = "exempt"

// checkBulk は secrets_access の項目の bulk を確かめる (ADR 0073 の 1・3 節)。
//
// 決定: bulk: exempt は high を黙らせるので、外す範囲が広い項目は警告ではなく読み込みエラーにする (警告は見落とされ、効き目は静かに high を消すこと)。
// 主体はロール (人の長期のキーで起動時にまとめて読む形は勧めない)、note は必須、secrets は CheckBulkExemptPattern を満たすものだけ。
func checkBulk(e *SecretsAccessEntry) error {
	switch e.Bulk {
	case "":
		return nil
	case BulkExempt:
	default:
		return fmt.Errorf("bulk must be %q or omitted, got %q", BulkExempt, e.Bulk)
	}
	if strings.TrimSpace(e.Note) == "" {
		return fmt.Errorf("bulk: %s requires note (why these secrets may be read in bulk)", BulkExempt)
	}
	// principal_pattern は CheckPrincipalPattern でロールに限っている
	if e.PrincipalPattern == "" && (!strings.HasPrefix(e.Principal, "arn:") || !strings.Contains(e.Principal, ":role/")) {
		return fmt.Errorf("bulk: %s is only for roles (principal must be a role ARN): %q", BulkExempt, e.Principal)
	}
	for j, g := range e.Secrets {
		if err := CheckBulkExemptPattern(g); err != nil {
			return fmt.Errorf("secrets[%d]: %w", j, err)
		}
	}
	return nil
}

// CheckBulkExemptPattern は bulk: exempt の項目の secrets に書ける glob か (ADR 0073 の 3 節)。
// ワイルドカード (* と ?) の無い名前は可。ワイルドカードがあれば、最初のワイルドカードより前の固定の部分に、
// "/" で閉じた空でない区切りが 2 つ以上要る (/a/b/* と a/b/* は可、*・/*・a/*・/a/*・/a/b*・//a/* は不可)。ARN の形 (arn:) は書けない (名前で書く)。
func CheckBulkExemptPattern(g string) error {
	if strings.HasPrefix(g, "arn:") {
		return fmt.Errorf("bulk: %s secrets must be names, not ARNs: %q", BulkExempt, g)
	}
	i := strings.IndexAny(g, "*?")
	if i < 0 {
		return nil
	}
	parts := strings.Split(g[:i], "/")
	// 最後の要素は "/" で閉じていない (ワイルドカードの直前の途中の名前) ので数えない。先頭の "/" の前の空の要素は数えない
	parts = parts[:len(parts)-1]
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	if len(parts) < 2 {
		return fmt.Errorf("bulk: %s pattern is too broad (needs at least two fixed path segments before a wildcard): %q", BulkExempt, g)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("bulk: %s pattern has an empty path segment: %q", BulkExempt, g)
		}
	}
	return nil
}

// HasBulkExempt は bulk: exempt の項目が 1 つでもあるか (secret_access が引き受けの記録を引くかの判断に使う)。
func (l *List) HasBulkExempt() bool {
	for i := range l.SecretsAccess {
		if l.SecretsAccess[i].Bulk == BulkExempt {
			return true
		}
	}
	return false
}

// SecretBulkExempt は arn が secret を読むことが bulk: exempt の項目に書いてあるか。一致した glob (書いたままの値) を返す。
// 比べ方は SecretExpected と同じ (シークレットの ARN は名前の部分でも比べる)。
func (l *List) SecretBulkExempt(arn, secret string) (string, bool) {
	cands := []string{secret}
	if _, name, ok := strings.Cut(secret, ":secret:"); ok && strings.HasPrefix(secret, "arn:") {
		cands = append(cands, name)
	}
	for i := range l.SecretsAccess {
		e := &l.SecretsAccess[i]
		if e.Bulk != BulkExempt || !e.matchesPrincipal(arn) {
			continue
		}
		for k, re := range e.secrets {
			for _, c := range cands {
				if re.MatchString(c) {
					return e.Secrets[k], true
				}
			}
		}
	}
	return "", false
}

// SecretPrincipalPatterns は arn に一致した secrets_access の principal_pattern の値 (書いたままの値。重複なし・整列済み)。
// principal (完全一致) の項目は入れない。finding の data に出す (ADR 0079 の 4 節)。
func (l *List) SecretPrincipalPatterns(arn string) []string {
	seen := map[string]bool{}
	var out []string
	for i := range l.SecretsAccess {
		e := &l.SecretsAccess[i]
		if e.PrincipalPattern != "" && !seen[e.PrincipalPattern] && e.matchesPrincipal(arn) {
			seen[e.PrincipalPattern] = true
			out = append(out, e.PrincipalPattern)
		}
	}
	sort.Strings(out)
	return out
}

// matchesPrincipal は項目の主体が arn か。principal は完全一致、principal_pattern は MatchPrincipalPattern。
func (e *SecretsAccessEntry) matchesPrincipal(arn string) bool {
	if e.PrincipalPattern != "" {
		// Parse が CheckPrincipalPattern で確かめた値なので、固定の部分との照合だけをする
		return matchPrincipalFixed(strings.TrimSuffix(e.PrincipalPattern, "*"), arn)
	}
	return e.Principal == arn
}

// principalPatternPrefixRe は principal_pattern の先頭 (IAM のロールで、アカウントは 12 桁)。
var principalPatternPrefixRe = regexp.MustCompile(`^arn:[a-z][a-z0-9-]*:iam::\d{12}:role/`)

// roleNameCharsRe はロールの ARN の、:role/ より後ろ (パスと名前) に書ける文字 (IAM のロール名・パスの文字)。
var roleNameCharsRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@_/-]+$`)

// CheckPrincipalPattern は secrets_access の principal_pattern に書ける形か (ADR 0079 の 2 節)。
//
// 決定: principals の arn_pattern より狭くする。秘匿値の読み取りの finding を消すので、CloudFormation が付ける末尾の乱数の分だけを許す。
//   - (a) arn:<パーティション>:iam::<12 桁>:role/ で始まる
//   - (b) ワイルドカードは末尾の * の 1 つだけ (? と途中の * は書けない)
//   - (c) * の直前は - (論理 ID と乱数の区切り)
//   - (d) 固定の部分の、最後の / より後ろ (ロールの名前) が、- で区切った空でない部分を 2 つ以上持つ (スタック名と論理 ID)
//
// 照合 (MatchPrincipalPattern) では * は英数字の 1 文字以上にだけ一致する ((e)。/・:・- を越えない)。
func CheckPrincipalPattern(p string) error {
	if !principalPatternPrefixRe.MatchString(p) {
		return fmt.Errorf("principal_pattern %q must be a role ARN with a 12-digit account (arn:aws:iam::123456789012:role/<stack>-<logical id>-*)", p)
	}
	if strings.ContainsRune(p, '?') || strings.Count(p, "*") != 1 || !strings.HasSuffix(p, "-*") {
		return fmt.Errorf("principal_pattern %q: the only wildcard must be a trailing \"-*\" (the random suffix CloudFormation adds)", p)
	}
	rest := p[strings.Index(p, ":role/")+len(":role/") : len(p)-len("-*")]
	if !roleNameCharsRe.MatchString(rest) {
		return fmt.Errorf("principal_pattern %q: invalid characters in the role name", p)
	}
	name := rest[strings.LastIndex(rest, "/")+1:]
	parts := strings.Split(name, "-")
	if len(parts) < 2 {
		return fmt.Errorf("principal_pattern %q is too broad (the role name before \"-*\" needs at least two parts separated by \"-\": <stack>-<logical id>)", p)
	}
	for _, s := range parts {
		if s == "" {
			return fmt.Errorf("principal_pattern %q has an empty part in the role name", p)
		}
	}
	return nil
}

// MatchPrincipalPattern は principal_pattern が arn に一致するか (ADR 0079 の 2 節の (e))。
// 固定の部分 (末尾の * の前) で始まり、残りが英数字 (ASCII) の 1 文字以上のときだけ一致する。CheckPrincipalPattern を通らない値は何にも一致しない。
func MatchPrincipalPattern(pattern, arn string) bool {
	if CheckPrincipalPattern(pattern) != nil {
		return false
	}
	return matchPrincipalFixed(strings.TrimSuffix(pattern, "*"), arn)
}

// matchPrincipalFixed は arn が fixed で始まり、残りが英数字 (ASCII) の 1 文字以上か。
func matchPrincipalFixed(fixed, arn string) bool {
	suffix, ok := strings.CutPrefix(arn, fixed)
	if !ok || suffix == "" {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		c := suffix[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// SourceIPAllowed は IP が source_ips のいずれかに含まれるか。
func (l *List) SourceIPAllowed(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, e := range l.SourceIPs {
		if e.net != nil && e.net.Contains(addr) {
			return true
		}
	}
	return false
}
