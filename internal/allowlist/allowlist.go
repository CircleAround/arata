// Package allowlist は既知リスト allowlist.yaml の読み込み (設計書 6-1) と、approve による追記 (write.go、ADR 0010) を担う。
package allowlist

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

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
func globToRegexp(glob string) (*regexp.Regexp, error) {
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

// SecretsAccessEntry は secrets_access の 1 件。主体 (ARN の完全一致) が読んでよい秘匿値 (名前・パスの glob)。
// 決定 (ADR 0027): secret_access は、一致する秘匿値を「初めて読む秘匿値」に数えない (一括読み出しの数には数える)。
type SecretsAccessEntry struct {
	Principal string   `yaml:"principal"`
	Secrets   []string `yaml:"secrets"`

	secrets []*regexp.Regexp
}

// List は allowlist 全体。
type List struct {
	Principals    []PrincipalEntry     `yaml:"principals"`
	SourceIPs     []SourceIPEntry      `yaml:"source_ips"`
	AdminUsers    []string             `yaml:"admin_users"`
	SecretsAccess []SecretsAccessEntry `yaml:"secrets_access"`

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
			return nil, fmt.Errorf("principals[%d]: exactly one of arn, account, arn_pattern is required", i)
		}
		if e.Account != "" && !accountRe.MatchString(e.Account) {
			return nil, fmt.Errorf("principals[%d]: account %q: want a 12-digit account ID", i, e.Account)
		}
		if e.ARNPattern != "" {
			if !strings.HasPrefix(e.ARNPattern, "arn:") {
				return nil, fmt.Errorf("principals[%d]: arn_pattern %q must start with arn:", i, e.ARNPattern)
			}
			re, err := globToRegexp(e.ARNPattern)
			if err != nil {
				return nil, fmt.Errorf("principals[%d]: arn_pattern: %w", i, err)
			}
			e.pattern = re
		}
		if e.Expires != "" {
			t, err := time.Parse("2006-01-02", e.Expires)
			if err != nil {
				return nil, fmt.Errorf("principals[%d]: expires %q: want YYYY-MM-DD", i, e.Expires)
			}
			// 期限日の終わりまで有効
			e.expires = t.Add(24 * time.Hour)
		}
		if e.ExpectedDenied != nil {
			if len(e.ExpectedDenied) == 0 {
				return nil, fmt.Errorf("principals[%d]: expected_denied is empty (remove it or list service:Action globs such as logs:StartQuery)", i)
			}
			if strings.TrimSpace(e.Note) == "" {
				return nil, fmt.Errorf("principals[%d]: note is required with expected_denied (why these denials are expected)", i)
			}
			for j, g := range e.ExpectedDenied {
				if err := CheckDeniedGlob(g); err != nil {
					return nil, fmt.Errorf("principals[%d]: expected_denied[%d] %w", i, j, err)
				}
				re, err := globToRegexp(g)
				if err != nil {
					return nil, fmt.Errorf("principals[%d]: expected_denied[%d]: %w", i, j, err)
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
		if e.Principal == "" || len(e.Secrets) == 0 {
			return nil, fmt.Errorf("secrets_access[%d]: principal and secrets are required", i)
		}
		for j, g := range e.Secrets {
			if strings.TrimSpace(g) == "" {
				return nil, fmt.Errorf("secrets_access[%d]: secrets[%d] is empty", i, j)
			}
			re, err := globToRegexp(g)
			if err != nil {
				return nil, fmt.Errorf("secrets_access[%d]: secrets[%d]: %w", i, j, err)
			}
			e.secrets = append(e.secrets, re)
		}
	}
	for i := range l.SourceIPs {
		e := &l.SourceIPs[i]
		_, n, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			return nil, fmt.Errorf("source_ips[%d]: %w", i, err)
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
		if e.Principal != arn {
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
