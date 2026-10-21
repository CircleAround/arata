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

	expires time.Time
	pattern *regexp.Regexp
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

// SecretsAccessEntry は secrets_access の 1 件 (Step 1 では読むだけ)。
type SecretsAccessEntry struct {
	Principal string   `yaml:"principal"`
	Secrets   []string `yaml:"secrets"`
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
		if e.ARN != "" {
			l.byARN[e.ARN] = e
		} else {
			l.broad = append(l.broad, e)
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
		if !e.expires.IsZero() && !at.Before(e.expires) {
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
