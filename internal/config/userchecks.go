package config

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// 利用者ごとのチェック (user_denied・user_id_enumeration・user_path_breadth。ADR 0071・0087) の、日の値を作る集計の条件。
// どれも集計の条件 (日の値の形を決め、全プロファイルで共有する) なので、overrides では変えられない (CollectionParams)。
// 判定の閾値 (min_*・平常帯・窓。ADR 0071 の 11 節の案で、仮の値。実データで見直す) は overrides で変えられる。
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
	// MinCount は 1 日の拒否の件数の下限。
	MinCount   float64 `yaml:"min_count"`
	UserBands  `yaml:",inline"`
	UserWindow `yaml:",inline"`
}

// UserBands は利用者の平常帯 (直近 baseline_days 日の日の値の中央値 × factor) とアプリの平常帯
// (同じ日々の「その日いちばん多かった利用者の値」の中央値 × app_factor) の指定。min_baseline_days は、アプリの記録のある日がこれに満たない間は判定しない日数。
type UserBands struct {
	BaselineDays    int     `yaml:"baseline_days"`
	MinBaselineDays int     `yaml:"min_baseline_days"`
	Factor          float64 `yaml:"factor"`
	AppFactor       float64 `yaml:"app_factor"`
}

// UserWindow はゆっくりした試しを見る窓 (ADR 0071 の 5 節)。window の日の値の和が min_count_window 以上、値のあった日が min_days 以上で、平常帯 (窓の日数倍) も超えたもの。
type UserWindow struct {
	Window         string  `yaml:"window"`
	MinCountWindow float64 `yaml:"min_count_window"`
	MinDays        int     `yaml:"min_days"`
}

// WindowDays は window の日の数 (検証済みの値を前提にする)。
func (w UserWindow) WindowDays() int {
	d, err := ParseDuration(w.Window)
	if err != nil {
		return 0
	}
	return int(d / (24 * time.Hour))
}

// MaxUserWindowDays は window の上限の日数。
const MaxUserWindowDays = 31

// UserIDEnumeration は user_id_enumeration の集計の条件。
type UserIDEnumeration struct {
	Sources []string `yaml:"sources"`
	// SuccessStatuses は成功として数えるステータス。DeniedStatuses は拒否として数えるステータス (4xx・5xx と、GET・HEAD のときだけの 3xx)。
	SuccessStatuses []int `yaml:"success_statuses"`
	DeniedStatuses  []int `yaml:"denied_statuses"`
	StoreMin        int   `yaml:"store_min"`
	StoreTop        int   `yaml:"store_top"`
	// MinDistinct は (利用者, 型) の 1 日の異なる ID の数の下限。HighMinDenied は high にする拒否のあった異なる ID の数の下限 (成功も 1 つ以上あるとき)。
	MinDistinct   float64 `yaml:"min_distinct"`
	HighMinDenied float64 `yaml:"high_min_denied"`
	// ExcludeTemplates は数えない型 (glob。`*` は 1 区間。だれでも見られる公開の画面など)。
	ExcludeTemplates []string `yaml:"exclude_templates"`
	UserBands        `yaml:",inline"`
	UserWindow       `yaml:",inline"`
}

// UserPathBreadth は user_path_breadth の集計の条件。
type UserPathBreadth struct {
	Sources  []string `yaml:"sources"`
	StoreMin int      `yaml:"store_min"`
	StoreTop int      `yaml:"store_top"`
	// MinTemplates は 1 日に触った型の異なりの数の下限。
	MinTemplates float64 `yaml:"min_templates"`
	UserBands    `yaml:",inline"`
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
	setFloat(&ud.MinCount, 30)
	setFloat(&ue.MinDistinct, 50)
	setFloat(&ue.HighMinDenied, 10)
	setFloat(&ub.MinTemplates, 50)
	for _, b := range []*UserBands{&ud.UserBands, &ue.UserBands, &ub.UserBands} {
		setInt(&b.BaselineDays, 14)
		setInt(&b.MinBaselineDays, 7)
		setFloat(&b.Factor, 3)
		setFloat(&b.AppFactor, 2)
	}
	for _, x := range []struct {
		w   *UserWindow
		min float64
	}{{&ud.UserWindow, 100}, {&ue.UserWindow, 150}} {
		if x.w.Window == "" {
			x.w.Window = "7d"
		}
		setFloat(&x.w.MinCountWindow, x.min)
		setInt(&x.w.MinDays, 3)
	}
}

func (b UserBands) validate() error {
	if b.BaselineDays < 1 || b.MinBaselineDays < 1 || b.MinBaselineDays > b.BaselineDays || b.Factor <= 0 || b.AppFactor <= 0 {
		return fmt.Errorf("baseline_days >= 1, 1 <= min_baseline_days <= baseline_days, factor > 0, app_factor > 0")
	}
	return nil
}

func (w UserWindow) validate() error {
	d, err := ParseDuration(w.Window)
	if err != nil || d <= 0 || d%(24*time.Hour) != 0 || d > MaxUserWindowDays*24*time.Hour {
		return fmt.Errorf("window %q must be whole days from 1d to %dd (e.g. 7d)", w.Window, MaxUserWindowDays)
	}
	if w.MinCountWindow < 1 || w.MinDays < 1 || w.MinDays > w.WindowDays() {
		return fmt.Errorf("min_count_window >= 1, 1 <= min_days <= window days")
	}
	return nil
}

// validateGlob は exclude_templates の 1 つを確かめる (/ で始まり、path.Match の書式)。
func validateGlob(g string) error {
	if !strings.HasPrefix(g, "/") {
		return fmt.Errorf("%q must start with /", g)
	}
	if _, err := path.Match(g, "/"); err != nil {
		return fmt.Errorf("%q: %w", g, err)
	}
	return nil
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
	if ud.MinCount < 1 {
		return fmt.Errorf("user_denied: min_count >= 1")
	}
	if ue.MinDistinct < 1 || ue.HighMinDenied < 1 {
		return fmt.Errorf("user_id_enumeration: min_distinct >= 1, high_min_denied >= 1")
	}
	if ub.MinTemplates < 1 {
		return fmt.Errorf("user_path_breadth: min_templates >= 1")
	}
	for _, x := range []struct {
		name string
		b    UserBands
	}{{"user_denied", ud.UserBands}, {"user_id_enumeration", ue.UserBands}, {"user_path_breadth", ub.UserBands}} {
		if err := x.b.validate(); err != nil {
			return fmt.Errorf("%s: %w", x.name, err)
		}
	}
	if err := ud.UserWindow.validate(); err != nil {
		return fmt.Errorf("user_denied: %w", err)
	}
	if err := ue.UserWindow.validate(); err != nil {
		return fmt.Errorf("user_id_enumeration: %w", err)
	}
	for _, g := range ue.ExcludeTemplates {
		if err := validateGlob(g); err != nil {
			return fmt.Errorf("user_id_enumeration: exclude_templates: %w", err)
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
func (s Source) extractsMethod() bool { return s.extractsField("method") }

// extractsField は request_lines のソースが、どれかの行の種類で項目 field を取り出すか。
func (s Source) extractsField(field string) bool {
	if s.Request == nil {
		return false
	}
	groups, err := s.Request.Groups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if containsString(g, field) {
			return true
		}
	}
	return false
}
