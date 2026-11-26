package config

import (
	"fmt"
	"strconv"
	"strings"
)

// 利用者ごとのチェック (user_denied・user_id_enumeration・user_path_breadth。ADR 0071・0087) の、日の値を作る集計の条件。
// どれも集計の条件 (日の値の形を決め、全プロファイルで共有する) なので、overrides では変えられない (CollectionParams)。
// 判定の閾値 (min_*・factor・窓など) はチェックの実装と一緒に足す。
//
// 決定 (ADR 0087 の実装。開発リードの判断、2026-11-26):
//   - U1・U2 のクエリは、3 つのどれかの sources に書いたソースだけで流す (暗黙の既定を持たない。ADR 0014)。sources は既定で空
//   - 3xx は user_id_enumeration.denied_statuses にだけ書ける (GET と HEAD の 3xx だけを拒否に数える)。user_denied.statuses には書けない (0087 の 7 節)

// UserDenied は user_denied の集計の条件。
type UserDenied struct {
	// Sources は数える cloudwatch-logs のソース (request_lines で request.user_id のあるもの)。空なら数えない。
	Sources []string `yaml:"sources"`
	// Statuses は拒否として数えるステータス (4xx・5xx)。
	Statuses []int `yaml:"statuses"`
	// StoreMin はストアに残す日の値の下限。StoreTop は日ごとに残す key の数 (値の大きい順)。
	StoreMin int `yaml:"store_min"`
	StoreTop int `yaml:"store_top"`
}

// UserIDEnumeration は user_id_enumeration の集計の条件。
type UserIDEnumeration struct {
	Sources []string `yaml:"sources"`
	// SuccessStatuses は成功として数えるステータス。DeniedStatuses は拒否として数えるステータス (4xx・5xx と、GET・HEAD のときだけの 3xx)。
	SuccessStatuses []int `yaml:"success_statuses"`
	DeniedStatuses  []int `yaml:"denied_statuses"`
	StoreMin        int   `yaml:"store_min"`
	StoreTop        int   `yaml:"store_top"`
}

// UserPathBreadth は user_path_breadth の集計の条件。
type UserPathBreadth struct {
	Sources  []string `yaml:"sources"`
	StoreMin int      `yaml:"store_min"`
	StoreTop int      `yaml:"store_top"`
}

// MaxUserStoreTop は store_top の上限 (Insights の 1 回の結果の行の数)。
const MaxUserStoreTop = 10000

// redirectStatuses は denied_statuses に書ける 3xx。
var redirectStatuses = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

// IsRedirect は s が拒否に数えられる 3xx か。
func IsRedirect(s int) bool { return redirectStatuses[s] }

// CountsRedirects は denied_statuses に 3xx があるか。
func (u UserIDEnumeration) CountsRedirects() bool {
	for _, s := range u.DeniedStatuses {
		if IsRedirect(s) {
			return true
		}
	}
	return false
}

// UserSourceChecks は、あるソースを sources に書いたチェック。
type UserSourceChecks struct {
	Denied, IDs, Breadth bool
}

// Any は 3 つのどれかがそのソースを数えるか。
func (u UserSourceChecks) Any() bool { return u.Denied || u.IDs || u.Breadth }

// UserSources は、ソース id を sources に書いた利用者ごとのチェック。
func (c Checks) UserSources(id string) UserSourceChecks {
	return UserSourceChecks{
		Denied:  containsString(c.UserDenied.Sources, id),
		IDs:     containsString(c.UserIDEnumeration.Sources, id),
		Breadth: containsString(c.UserPathBreadth.Sources, id),
	}
}

func containsString(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func (c *Checks) applyUserDefaults() {
	ud, ue, ub := &c.UserDenied, &c.UserIDEnumeration, &c.UserPathBreadth
	if ud.Statuses == nil {
		ud.Statuses = []int{401, 403}
	}
	setInt(&ud.StoreMin, 3)
	setInt(&ud.StoreTop, 200)
	if ue.SuccessStatuses == nil {
		ue.SuccessStatuses = []int{200}
	}
	if ue.DeniedStatuses == nil {
		ue.DeniedStatuses = []int{401, 403, 404}
	}
	setInt(&ue.StoreMin, 5)
	setInt(&ue.StoreTop, 200)
	setInt(&ub.StoreMin, 20)
	setInt(&ub.StoreTop, 200)
}

func (c Checks) validateUser() error {
	ud, ue, ub := c.UserDenied, c.UserIDEnumeration, c.UserPathBreadth
	if err := validateStatuses(ud.Statuses, func(s int) bool { return s >= 400 && s <= 599 }); err != nil {
		return fmt.Errorf("user_denied: statuses: %w (400-599; 3xx are not denials here: a redirect after a form post is a normal success, ADR 0087)", err)
	}
	if err := validateStatuses(ue.SuccessStatuses, func(s int) bool { return s >= 200 && s <= 399 }); err != nil {
		return fmt.Errorf("user_id_enumeration: success_statuses: %w (200-399)", err)
	}
	if err := validateStatuses(ue.DeniedStatuses, func(s int) bool { return s >= 400 && s <= 599 || IsRedirect(s) }); err != nil {
		return fmt.Errorf("user_id_enumeration: denied_statuses: %w (400-599, or 301, 302, 303, 307, 308 counted for GET and HEAD only)", err)
	}
	for _, s := range ue.SuccessStatuses {
		for _, d := range ue.DeniedStatuses {
			if s == d {
				return fmt.Errorf("user_id_enumeration: %d is in both success_statuses and denied_statuses", s)
			}
		}
	}
	for _, x := range []struct {
		name     string
		min, top int
	}{{"user_denied", ud.StoreMin, ud.StoreTop}, {"user_id_enumeration", ue.StoreMin, ue.StoreTop}, {"user_path_breadth", ub.StoreMin, ub.StoreTop}} {
		if x.min < 1 || x.top < 1 || x.top > MaxUserStoreTop {
			return fmt.Errorf("%s: store_min >= 1, 1 <= store_top <= %d", x.name, MaxUserStoreTop)
		}
	}
	return nil
}

func validateStatuses(l []int, ok func(int) bool) error {
	if len(l) == 0 {
		return fmt.Errorf("at least one status")
	}
	seen := map[int]bool{}
	for _, s := range l {
		if !ok(s) {
			return fmt.Errorf("%d is not allowed", s)
		}
		if seen[s] {
			return fmt.Errorf("%d is listed twice", s)
		}
		seen[s] = true
	}
	return nil
}

// validateUserSources は 3 つのチェックの sources が、ユーザー ID を読む request_lines の cloudwatch-logs のソースかを確かめる。
func (c *Config) validateUserSources() error {
	byID := map[string]Source{}
	for _, s := range c.Sources {
		byID[s.ID] = s
	}
	for _, x := range []struct {
		name string
		ids  []string
	}{{"user_denied", c.Checks.UserDenied.Sources}, {"user_id_enumeration", c.Checks.UserIDEnumeration.Sources}, {"user_path_breadth", c.Checks.UserPathBreadth.Sources}} {
		seen := map[string]bool{}
		for _, id := range x.ids {
			if seen[id] {
				return fmt.Errorf("%s: sources: %q is listed twice", x.name, id)
			}
			seen[id] = true
			s, ok := byID[id]
			if !ok {
				return fmt.Errorf("%s: sources: source %q is not defined", x.name, id)
			}
			if s.Kind != KindCloudWatchLogs || s.UserIDFrom() == UserIDFromNone {
				return fmt.Errorf("%s: sources: source %q must be a cloudwatch-logs request_lines source with request.user_id (from: %s)",
					x.name, id, strings.Join([]string{UserIDFromAppLine, UserIDFromDebugSQL}, " or "))
			}
			// 決定 (レビューの指摘): 3xx は GET と HEAD のときだけ拒否に数えるので、メソッドを取り出さないソースでは 1 件も数えられない。黙って 0 にせず誤りにする
			if ue := c.Checks.UserIDEnumeration; x.name == "user_id_enumeration" && ue.CountsRedirects() && !s.extractsMethod() {
				return fmt.Errorf("%s: denied_statuses has %s, which counts only for GET and HEAD, but source %q does not extract the method: "+
					"add (?P<method>...) to one of its request.lines regexes, or remove the 3xx from denied_statuses", x.name, redirectList(ue.DeniedStatuses), id)
			}
		}
	}
	return nil
}

// redirectList は l の中の 3xx (書いた順)。
func redirectList(l []int) string {
	var out []string
	for _, v := range l {
		if IsRedirect(v) {
			out = append(out, strconv.Itoa(v))
		}
	}
	return strings.Join(out, ", ")
}

// extractsMethod は request_lines のソースが、どれかの行の種類でメソッドを取り出すか。
func (s Source) extractsMethod() bool {
	if s.Request == nil {
		return false
	}
	groups, err := s.Request.Groups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if containsString(g, "method") {
			return true
		}
	}
	return false
}
