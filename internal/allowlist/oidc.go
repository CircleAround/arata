package allowlist

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/record"
)

// OIDCSubjectEntry は oidc_subjects の 1 件。OIDC でのロールの引き受け (AssumeRoleWithWebIdentity) の、既知の入り口 (ADR 0055)。
//
// 決定:
//   - principals とは別の節にする (ADR 0047 と同じ理由)。principals は「主体として既知」で、ロールを承認しても、どこから入ってよいかは決まらない。
//     ここに書いてもロールは主体として承認されない
//   - provider (必須) はプロバイダの名前 (ARN の oidc-provider/ より後ろ。ARN は書けない)。role (必須) はロールの ARN の完全一致 (glob は書けない)
//   - GitHub (provider が token.actions.githubusercontent.com) の項目は repo (組織/リポジトリの完全一致。glob は書けない。大文字小文字は区別しない) が必須で、
//     refs (ブランチ・タグの glob。`*` か refs/ で始まる)・environments (名前の完全一致)・pull_request: true のどれか 1 つ以上を必ず書く。
//     「リポジトリの全部」という暗黙の広さを持たせない (全部の ref を許すなら refs: ["*"] と書く。environment と pull_request は別)
//   - GitHub 以外の項目は provider と role だけ (sub は読まない)。repo などは書けない
//   - hours (許す時間帯。UTC の "HH:MM-HH:MM"。終わりは含まない。日をまたぐ書き方も可)・source_ips (許す送信元の CIDR) は任意。書かなければ見ない
//   - note は必須。expires は期限日の終わりまで有効 (assume_destinations と同じ)
//   - 同じ引き受けに一致する期限内の項目が 1 つでもあれば既知。一致するものが全部期限切れなら expired
type OIDCSubjectEntry struct {
	Provider     string   `yaml:"provider"`
	Role         string   `yaml:"role"`
	Repo         string   `yaml:"repo"`
	Refs         []string `yaml:"refs"`
	Environments []string `yaml:"environments"`
	PullRequest  bool     `yaml:"pull_request"`
	Hours        []string `yaml:"hours"`
	SourceIPs    []string `yaml:"source_ips"`
	Note         string   `yaml:"note"`
	ApprovedBy   string   `yaml:"approved_by"`
	ApprovedAt   string   `yaml:"approved_at"`
	Expires      string   `yaml:"expires"`

	expires time.Time
	refs    []*regexp.Regexp
	hours   [][2]int // 始まりと終わり (その日の 0 時からの分。終わりは含まない)
	nets    []*net.IPNet
}

// OIDCAssume は 1 つの引き受けの組。Repo・Kind・Ref・Environment は GitHub の sub を読めたときだけ (record.GitHubSub)。
type OIDCAssume struct {
	Provider    string
	Role        string
	Repo        string
	Kind        string // record.OIDCKindRef / OIDCKindEnvironment / OIDCKindPullRequest
	Ref         string
	Environment string
}

var (
	oidcRoleRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+\z`)
	// refs の 1 件の形: ref に許す文字と glob の `*` `?`
	oidcRefGlobRe = regexp.MustCompile(`^[A-Za-z0-9._/@+=*?-]{1,255}\z`)
	oidcHoursRe   = regexp.MustCompile(`^([0-9]{2}):([0-9]{2})-([0-9]{2}):([0-9]{2})\z`)
)

// Subject は項目が指す入り口の表示。
func (e *OIDCSubjectEntry) Subject() string {
	s := "oidc_subject:" + e.Provider
	if e.Repo != "" {
		s += " " + e.Repo
	}
	return s + " -> " + e.Role
}

func (e *OIDCSubjectEntry) active(at time.Time) bool {
	return e.expires.IsZero() || at.Before(e.expires)
}

func (e *OIDCSubjectEntry) github() bool { return e.Provider == record.GitHubOIDCProvider }

// matches は引き受け a がこの項目の入り口か (期限・時間帯・送信元は見ない)。
func (e *OIDCSubjectEntry) matches(a OIDCAssume) bool {
	if a.Provider == "" || a.Role == "" || e.Provider != a.Provider || e.Role != a.Role {
		return false
	}
	if !e.github() {
		return true
	}
	if a.Repo == "" || !strings.EqualFold(e.Repo, a.Repo) {
		return false
	}
	switch a.Kind {
	case record.OIDCKindRef:
		for _, re := range e.refs {
			if re.MatchString(a.Ref) {
				return true
			}
		}
	case record.OIDCKindEnvironment:
		for _, n := range e.Environments {
			if n == a.Environment {
				return true
			}
		}
	case record.OIDCKindPullRequest:
		return e.PullRequest
	}
	return false
}

// InHours は t が hours の内か (UTC で比べる)。hours を書いていなければ true。
func (e *OIDCSubjectEntry) InHours(t time.Time) bool {
	if len(e.hours) == 0 {
		return true
	}
	u := t.UTC()
	m := u.Hour()*60 + u.Minute()
	for _, h := range e.hours {
		if h[0] < h[1] && m >= h[0] && m < h[1] || h[0] > h[1] && (m >= h[0] || m < h[1]) {
			return true
		}
	}
	return false
}

// SourceAllowed は ip が source_ips の内か。source_ips を書いていなければ true。書いていて ip が IP として読めなければ false。
func (e *OIDCSubjectEntry) SourceAllowed(ip string) bool {
	if len(e.nets) == 0 {
		return true
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, n := range e.nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

// validate は 1 件を検証し、照合に使う値を作る。
func (e *OIDCSubjectEntry) validate() error {
	if strings.HasPrefix(e.Provider, "arn:") || !record.ValidOIDCProvider(e.Provider) {
		return fmt.Errorf("provider %q: want the provider name, the part after \"oidc-provider/\" of its ARN (e.g. %s)", e.Provider, record.GitHubOIDCProvider)
	}
	if !oidcRoleRe.MatchString(e.Role) {
		return fmt.Errorf("role %q: want the full role ARN without globs (e.g. arn:aws:iam::123456789012:role/gha-deploy)", e.Role)
	}
	if strings.TrimSpace(e.Note) == "" {
		return fmt.Errorf("note is required (what this entry point is for)")
	}
	if e.Expires != "" {
		t, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			return fmt.Errorf("expires %q: want YYYY-MM-DD", e.Expires)
		}
		e.expires = t.Add(24 * time.Hour) // 期限日の終わりまで有効
	}
	e.refs, e.hours, e.nets = nil, nil, nil
	if e.github() {
		if !record.ValidGitHubRepo(e.Repo) {
			return fmt.Errorf("repo %q: want owner/repository without globs (e.g. example-org/example-repo)", e.Repo)
		}
		if e.Refs != nil && len(e.Refs) == 0 {
			return fmt.Errorf("refs is empty (remove it, or list refs such as refs/heads/main, refs/tags/v*)")
		}
		if e.Environments != nil && len(e.Environments) == 0 {
			return fmt.Errorf("environments is empty (remove it, or list environment names such as production)")
		}
		if len(e.Refs) == 0 && len(e.Environments) == 0 && !e.PullRequest {
			return fmt.Errorf("one of refs, environments or pull_request: true is required (write refs: [\"*\"] to allow every branch and tag)")
		}
		for j, g := range e.Refs {
			if !oidcRefGlobRe.MatchString(g) || (g != "*" && !strings.HasPrefix(g, "refs/")) {
				return fmt.Errorf("refs[%d] %q: want \"*\" or a ref glob starting with refs/ (e.g. refs/heads/main, refs/tags/v*)", j, g)
			}
			re, err := globToRegexp(g)
			if err != nil {
				return fmt.Errorf("refs[%d]: %w", j, err)
			}
			e.refs = append(e.refs, re)
		}
		for j, n := range e.Environments {
			if !record.ValidGitHubEnvironment(n) {
				return fmt.Errorf("environments[%d] %q: want an environment name without globs (e.g. production)", j, n)
			}
		}
	} else if e.Repo != "" || e.Refs != nil || e.Environments != nil || e.PullRequest {
		return fmt.Errorf("repo, refs, environments and pull_request are only for %s (the sub of other providers is not read; write provider and role only)", record.GitHubOIDCProvider)
	}
	for j, h := range e.Hours {
		m := oidcHoursRe.FindStringSubmatch(h)
		var v [4]int
		ok := m != nil
		for i := 0; ok && i < 4; i++ {
			v[i] = int(m[i+1][0]-'0')*10 + int(m[i+1][1]-'0')
		}
		if !ok || v[0] > 23 || v[2] > 23 || v[1] > 59 || v[3] > 59 || v[0]*60+v[1] == v[2]*60+v[3] {
			return fmt.Errorf("hours[%d] %q: want HH:MM-HH:MM in UTC with different start and end (e.g. 18:00-19:00, 23:30-00:30)", j, h)
		}
		e.hours = append(e.hours, [2]int{v[0]*60 + v[1], v[2]*60 + v[3]})
	}
	for j, c := range e.SourceIPs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return fmt.Errorf("source_ips[%d] %q: want a CIDR (e.g. 203.0.113.0/24)", j, c)
		}
		e.nets = append(e.nets, n)
	}
	return nil
}

// OIDCSubject は、引き受け a に一致する項目と、at 時点での状態を返す。
// 一致する期限内の項目が 1 つでもあれば approved (期限内の項目を全部返す。時間帯・送信元は、どれか 1 つが許せばよい)、
// 一致するものが全部期限切れなら expired (期限切れの項目を返す)、無ければ unknown。principals は見ない。
func (l *List) OIDCSubject(a OIDCAssume, at time.Time) ([]*OIDCSubjectEntry, Status) {
	var active, expired []*OIDCSubjectEntry
	for i := range l.OIDCSubjects {
		e := &l.OIDCSubjects[i]
		if !e.matches(a) {
			continue
		}
		if e.active(at) {
			active = append(active, e)
		} else {
			expired = append(expired, e)
		}
	}
	switch {
	case len(active) > 0:
		return active, StatusApproved
	case len(expired) > 0:
		return expired, StatusExpired
	}
	return nil, StatusUnknown
}

// OIDCRoleKnown は、ロール role が at 時点で期限内の項目のどれかにあるか (入り口は見ない)。
// 既知のロールに、項目に無い入り口から来た引き受けを high にするために使う。
func (l *List) OIDCRoleKnown(role string, at time.Time) bool {
	for i := range l.OIDCSubjects {
		if e := &l.OIDCSubjects[i]; role != "" && e.Role == role && e.active(at) {
			return true
		}
	}
	return false
}

// sameOIDCSubject は 2 つの項目が同じ入り口を書いているか (プロバイダ・ロール・リポジトリ・refs / environments の集合・pull_request が同じ)。
func sameOIDCSubject(a, b *OIDCSubjectEntry) bool {
	set := func(l []string) string {
		s := append([]string(nil), l...)
		sort.Strings(s)
		return strings.Join(s, "\x00")
	}
	return a.Provider == b.Provider && a.Role == b.Role && strings.EqualFold(a.Repo, b.Repo) && a.PullRequest == b.PullRequest &&
		set(a.Refs) == set(b.Refs) && set(a.Environments) == set(b.Environments)
}
