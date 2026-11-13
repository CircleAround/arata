package allowlist

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DestinationEntry は assume_destinations の 1 件。外向きの引き受け (監査対象のアカウントの主体が、別のアカウントのロールを引き受ける) で、
// 行き先として既知のアカウント。
//
// 決定 (ADR 0047):
//   - principals の account: とは別の節にする。あちらは「呼び出し元として既知」(そのアカウントの全主体を承認する) で、意味が逆。
//     行き先を既知にしても、そのアカウントの主体は承認されない。逆も同じ
//   - unknown_assume_role は、外向き・行き先が期限内でここに載っている・MFA あり、の全部を満たす引き受けだけを報告しない。
//     MFA が無い・不明なら、行き先が既知でも今までどおり報告する
//   - account は必須 (12 桁)。roles は任意で、書けばそのロールだけに絞る (ロール名の glob。ARN の role/ より後ろで、パスを含む。
//     先頭から末尾までの一致)。書かなければアカウントの全ロール
//   - note は必須。行き先を既知にするのは「このアカウントに入るのは通常業務」という判断で、理由 (契約・受託の内容) の無い項目は後から外せない
//   - 同じアカウントの項目は複数書ける (ロールごとに理由と期限を分けられる)。期限内の項目が 1 つでも一致すれば既知
type DestinationEntry struct {
	Account    string   `yaml:"account"`
	Roles      []string `yaml:"roles"`
	Note       string   `yaml:"note"`
	ApprovedBy string   `yaml:"approved_by"`
	ApprovedAt string   `yaml:"approved_at"`
	Expires    string   `yaml:"expires"`

	expires time.Time
	roles   []*regexp.Regexp
}

// destinationRoleRe は roles の 1 件の形。IAM がロールの名前とパスに許す文字と、glob の `*` `?` だけ。
// `:` を許さないので ARN は書けない (アカウントは account: だけが決める)。
var destinationRoleRe = regexp.MustCompile(`^[A-Za-z0-9+=,.@_/*?-]+\z`)

// CheckDestinationRole は roles の 1 件の書式を確かめる。
func CheckDestinationRole(g string) error {
	if !destinationRoleRe.MatchString(g) || strings.HasPrefix(g, "role/") {
		return fmt.Errorf("%q: want a role name or glob without the account and without \"role/\" (e.g. ReadOnly, ops-*, support/ReadOnly)", g)
	}
	return nil
}

// Subject は項目が指す行き先の表示 (assume_destination:NNN。ロールを絞っていれば roles: を添える)。
func (e *DestinationEntry) Subject() string {
	return destinationSubject(e.Account, e.Roles)
}

func destinationSubject(account string, roles []string) string {
	s := "assume_destination:" + account
	if len(roles) > 0 {
		s += " roles:" + strings.Join(roles, ",")
	}
	return s
}

func (e *DestinationEntry) active(at time.Time) bool {
	return e.expires.IsZero() || at.Before(e.expires)
}

func (e *DestinationEntry) matches(account, role string) bool {
	if account == "" || e.Account != account {
		return false
	}
	if len(e.roles) == 0 {
		return true
	}
	for _, re := range e.roles {
		if re.MatchString(role) {
			return true
		}
	}
	return false
}

// validate は 1 件を検証し、照合に使う値を作る。
func (e *DestinationEntry) validate() error {
	if !accountRe.MatchString(e.Account) {
		return fmt.Errorf("account %q: want a 12-digit account ID (the account of the roles your principals assume)", e.Account)
	}
	if strings.TrimSpace(e.Note) == "" {
		return fmt.Errorf("note is required (why assuming roles in this account is normal work)")
	}
	if e.Expires != "" {
		t, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			return fmt.Errorf("expires %q: want YYYY-MM-DD", e.Expires)
		}
		e.expires = t.Add(24 * time.Hour) // 期限日の終わりまで有効
	}
	if e.Roles != nil && len(e.Roles) == 0 {
		return fmt.Errorf("roles is empty (remove it to cover every role of the account, or list role names such as ReadOnly, ops-*)")
	}
	e.roles = nil
	for j, g := range e.Roles {
		if err := CheckDestinationRole(g); err != nil {
			return fmt.Errorf("roles[%d] %w", j, err)
		}
		re, err := globToRegexp(g)
		if err != nil {
			return fmt.Errorf("roles[%d]: %w", j, err)
		}
		e.roles = append(e.roles, re)
	}
	return nil
}

// AssumeDestination は、アカウント account のロール role (ARN の role/ より後ろ) が、at 時点で行き先として既知かを返す。
// 一致する期限内の項目が 1 つでもあれば approved (その項目を返す)、一致するものが全部期限切れなら expired、無ければ unknown (entry は nil)。
// principals は見ない (呼び出し元の承認は行き先を既知にしない)。
func (l *List) AssumeDestination(account, role string, at time.Time) (*DestinationEntry, Status) {
	var expired *DestinationEntry
	for i := range l.AssumeDestinations {
		e := &l.AssumeDestinations[i]
		if !e.matches(account, role) {
			continue
		}
		if e.active(at) {
			return e, StatusApproved
		}
		if expired == nil {
			expired = e
		}
	}
	if expired != nil {
		return expired, StatusExpired
	}
	return nil, StatusUnknown
}

// HasAssumeDestination は、アカウント account を行き先とする期限内の項目が 1 つでもあるか (ロールの絞り込みは見ない)。
func (l *List) HasAssumeDestination(account string, at time.Time) bool {
	for i := range l.AssumeDestinations {
		if e := &l.AssumeDestinations[i]; account != "" && e.Account == account && e.active(at) {
			return true
		}
	}
	return false
}

// sameDestination は、同じアカウントの 2 つの項目が重なるか (片方がアカウント全体か、絞ったロールの集合が同じ)。
// Check の重複の警告と、approve の「既にある」の判定が同じ規則を使う。
func sameDestination(accountA string, rolesA []string, accountB string, rolesB []string) bool {
	if accountA != accountB {
		return false
	}
	if len(rolesA) == 0 || len(rolesB) == 0 {
		return true
	}
	a, b := append([]string(nil), rolesA...), append([]string(nil), rolesB...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}

// NewDestination は approve が assume_destinations に追記する 1 件。
type NewDestination struct {
	Account    string
	Roles      []string
	Note       string
	ApprovedBy string
	ApprovedAt string // YYYY-MM-DD
	Expires    string // YYYY-MM-DD、空なら無期限
}

// Subject は追記する行き先の表示 (DestinationEntry.Subject と同じ形)。
func (d NewDestination) Subject() string { return destinationSubject(d.Account, d.Roles) }

// AppendDestination は path の allowlist.yaml の assume_destinations の末尾に d を追記し、追記したテキストを返す (Append と同じ書き方)。
func AppendDestination(path string, d NewDestination) (string, error) {
	return appendFile(path, func(src []byte) ([]byte, string, error) { return AppendDestinationBytes(src, d) })
}

// AppendDestinationBytes は allowlist.yaml のテキストに d を追記した結果と、追記した部分を返す。
//
// 決定 (ADR 0047): 差し込み方は principals と同じ (ADR 0010。ほかの行は変えない)。節が無ければファイルの末尾に足す。
// account は finding の data (ログ由来の値) から来るので、12 桁の数字でなければ書かない。重なる項目 (同じアカウントで、片方がアカウント全体か
// ロールの集合が同じ) が既にあれば ErrAlreadyListed (広げる・期限を延ばすのは人が項目を直す)。
func AppendDestinationBytes(src []byte, d NewDestination) ([]byte, string, error) {
	e := DestinationEntry{Account: d.Account, Roles: d.Roles, Note: d.Note, Expires: d.Expires}
	if err := e.validate(); err != nil {
		return nil, "", fmt.Errorf("allowlist: assume_destinations: %w", err)
	}
	before, err := Parse(src)
	if err != nil {
		return nil, "", fmt.Errorf("allowlist: current file is invalid: %w", err)
	}
	for i := range before.AssumeDestinations {
		x := &before.AssumeDestinations[i]
		if sameDestination(x.Account, x.Roles, d.Account, d.Roles) {
			return nil, "", fmt.Errorf("%w: %s (edit the entry directly to change roles / note / expires)", ErrAlreadyListed, x.Subject())
		}
	}
	result, added, err := appendToSection(src, "assume_destinations", d.render)
	if err != nil {
		return nil, "", err
	}
	after, err := Parse(result)
	if err != nil {
		return nil, "", fmt.Errorf("allowlist: refusing to write an invalid file: %w", err)
	}
	n := len(after.AssumeDestinations)
	if n != len(before.AssumeDestinations)+1 || after.AssumeDestinations[n-1].Subject() != d.Subject() || len(after.Principals) != len(before.Principals) {
		return nil, "", fmt.Errorf("allowlist: refusing to write: the new entry did not land at the end of assume_destinations")
	}
	return result, added, nil
}

// render は列の 1 要素を indent 付きで書く (末尾改行あり)。
func (d NewDestination) render(indent string) string {
	lines := []string{`account: "` + d.Account + `"`} // 数字だけなので文字列として引用する
	if len(d.Roles) > 0 {
		lines = append(lines, "roles: "+FormatExpectedDenied(d.Roles))
	}
	lines = append(lines, "note: "+scalar(d.Note))
	if d.ApprovedBy != "" {
		lines = append(lines, "approved_by: "+scalar(d.ApprovedBy))
	}
	if d.ApprovedAt != "" {
		lines = append(lines, "approved_at: "+d.ApprovedAt)
	}
	if d.Expires != "" {
		lines = append(lines, "expires: "+d.Expires)
	}
	var b strings.Builder
	for i, l := range lines {
		if i == 0 {
			b.WriteString(indent + "- ")
		} else {
			b.WriteString(indent + "  ")
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}
