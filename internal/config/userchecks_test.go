package config

import (
	"strconv"
	"strings"
	"testing"
)

// 利用者ごとのチェック (ADR 0071・0087) の集計の条件。値はすべて架空。

func userChecksConfig(checks string) string {
	return logsSource(railsRequest+userBlock("app_line", actorRegex)+pathIDsBlock) + "checks:\n" + checks
}

func TestUserChecksDefaults(t *testing.T) {
	c := DefaultChecks()
	ud, ue, ub := c.UserDenied, c.UserIDEnumeration, c.UserPathBreadth
	if len(ud.Sources) != 0 || len(ue.Sources) != 0 || len(ub.Sources) != 0 {
		t.Fatalf("sources は既定で空 (書いたソースだけを読む): %+v %+v %+v", ud, ue, ub)
	}
	if ints(ud.Statuses) != "401,403" || ud.StoreMin != 3 || ud.StoreTop != 200 {
		t.Fatalf("user_denied: %+v", ud)
	}
	if ints(ue.SuccessStatuses) != "200" || ints(ue.DeniedStatuses) != "401,403,404" || ue.StoreMin != 5 || ue.StoreTop != 200 {
		t.Fatalf("user_id_enumeration: %+v", ue)
	}
	if ub.StoreMin != 20 || ub.StoreTop != 200 {
		t.Fatalf("user_path_breadth: %+v", ub)
	}
}

func ints(l []int) string {
	var s []string
	for _, v := range l {
		s = append(s, strconv.Itoa(v))
	}
	return strings.Join(s, ",")
}

func TestUserChecksSources(t *testing.T) {
	cfg, err := Load(write(t, userChecksConfig(`  user_denied:
    sources: [web]
  user_id_enumeration:
    sources: [web]
    denied_statuses: [403, 404, 302]
  user_path_breadth:
    sources: [web]
`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Checks.UserSources("web"); got != (UserSourceChecks{Denied: true, IDs: true, Breadth: true}) {
		t.Fatalf("UserSources(web) = %+v", got)
	}
	if got := cfg.Checks.UserSources("trail"); got.Any() {
		t.Fatalf("UserSources(trail) = %+v", got)
	}
	if !cfg.Checks.UserIDEnumeration.CountsRedirects() {
		t.Fatal("302 を書いたのに 3xx を数えない")
	}
}

func TestUserChecksInvalid(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"知らないソース", "  user_denied:\n    sources: [nope]\n", `source "nope"`},
		{"ユーザー ID の無いソース", "  user_denied:\n    sources: [trail]\n", "request.user_id"},
		{"同じソースを 2 回", "  user_path_breadth:\n    sources: [web, web]\n", "twice"},
		{"user_denied に 3xx", "  user_denied:\n    statuses: [403, 302]\n", "3xx"},
		{"user_denied に 2xx", "  user_denied:\n    statuses: [200]\n", "400-599"},
		{"拒否に 304", "  user_id_enumeration:\n    denied_statuses: [304]\n", "301, 302, 303, 307, 308"},
		{"成功に 4xx", "  user_id_enumeration:\n    success_statuses: [404]\n", "success_statuses"},
		{"成功と拒否の両方", "  user_id_enumeration:\n    success_statuses: [200, 302]\n    denied_statuses: [302]\n", "both"},
		{"同じステータスを 2 回", "  user_id_enumeration:\n    denied_statuses: [403, 403]\n", "twice"},
		{"store_min が負", "  user_denied:\n    store_min: -1\n", "store_min"},
		{"store_top が上限超え", "  user_id_enumeration:\n    store_top: 10001\n", "store_top"},
	} {
		_, err := Load(write(t, userChecksConfig(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
}

// 集計の条件 (ストアの日の値の形を決める) は overrides では変えられず、誤りの文が checks: に書くよう案内する。
func TestUserChecksOverrides(t *testing.T) {
	for _, body := range []string{
		"      user_denied: { statuses: [401] }\n",
		"      user_denied: { sources: [web] }\n",
		"      user_id_enumeration: { success_statuses: [201] }\n",
		"      user_id_enumeration: { denied_statuses: [403] }\n",
		"      user_id_enumeration: { store_min: 10 }\n",
		"      user_path_breadth: { store_top: 50 }\n",
	} {
		cfg := strings.Replace(userChecksConfig(""), "    checks: [default-daily, root_usage]\n", "    checks: [default-daily, root_usage]\n    overrides:\n"+body, 1)
		_, err := Load(write(t, cfg))
		if err == nil || !strings.Contains(err.Error(), "overrides cannot change collection conditions") || !strings.Contains(err.Error(), "set them in checks:") {
			t.Errorf("%q: err = %v", body, err)
		}
	}
}
