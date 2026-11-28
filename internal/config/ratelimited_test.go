package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// rate_limited_ip (ADR 0094 の 2 節) の設定。値はすべて架空。

func TestRateLimitedIPDefaults(t *testing.T) {
	r := DefaultChecks().RateLimitedIP
	if ints(r.Statuses) != "429" || len(r.Paths) != 0 || len(r.UserSources) != 0 {
		t.Fatalf("statuses は [429]、paths と user_sources は既定で空: %+v", r)
	}
	if r.IPUsersStoreMin != 3 || r.IPUsersStoreTop != 200 || r.MinCount != 20 || r.SuggestMinUsers != 10 {
		t.Fatalf("既定: %+v", r)
	}
}

func TestRateLimitedIPUserSources(t *testing.T) {
	cfg, err := Load(write(t, userChecksConfig(`  rate_limited_ip:
    statuses: [429, 503]
    paths: [/users/sign_in, /api/]
    user_sources: [web]
`)))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Checks.RateLimitedIP
	if !r.CountsUsers("web") || r.CountsUsers("trail") || ints(r.Statuses) != "429,503" {
		t.Fatalf("%+v", r)
	}
}

func TestRateLimitedIPInvalid(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"知らないソース", "  rate_limited_ip:\n    user_sources: [nope]\n", `source "nope"`},
		{"ユーザー ID の無いソース", "  rate_limited_ip:\n    user_sources: [trail]\n", "request.user_id"},
		{"同じソースを 2 回", "  rate_limited_ip:\n    user_sources: [web, web]\n", "twice"},
		{"2xx", "  rate_limited_ip:\n    statuses: [200]\n", "400-599"},
		{"同じステータスを 2 回", "  rate_limited_ip:\n    statuses: [429, 429]\n", "twice"},
		{"/ で始まらないパス", "  rate_limited_ip:\n    paths: [api]\n", "must start with /"},
		{"min_count が 0 未満", "  rate_limited_ip:\n    min_count: -1\n", "min_count"},
		{"suggest_min_users が 0 未満", "  rate_limited_ip:\n    suggest_min_users: -1\n", "suggest_min_users"},
		{"ip_users_store_top が上限超え", "  rate_limited_ip:\n    ip_users_store_top: 10001\n", "ip_users_store_top"},
	} {
		_, err := Load(write(t, userChecksConfig(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
}

// ip を取り出さないソース (yields: http_user で ip の無い行) は、IP ごとに数えられないので誤りにする。
func TestRateLimitedIPNeedsIP(t *testing.T) {
	body := strings.Replace(userChecksConfig("  rate_limited_ip:\n    user_sources: [web]\n"),
		` for (?P<ip>\S+) at `, ` for \S+ at `, 1)
	body = strings.Replace(body, "    format: request_lines\n", "    format: request_lines\n    yields: http_user\n", 1)
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "(?P<ip>") {
		t.Fatalf("err = %v", err)
	}
}

// 集計の条件 (statuses・paths・user_sources・ip_users_store_*) は overrides で変えられない。判定の閾値は変えられる。
func TestRateLimitedIPOverrides(t *testing.T) {
	for _, key := range []string{"statuses: [503]", "paths: [/x]", "user_sources: [web]", "ip_users_store_min: 5", "ip_users_store_top: 10"} {
		var o Checks
		if err := yaml.Unmarshal([]byte("rate_limited_ip:\n  "+key+"\n"), &o); err != nil {
			t.Fatal(err)
		}
		if err := validateOverrides(o); err == nil {
			t.Errorf("%s: overrides で変えられてしまう", key)
		}
	}
	for _, key := range []string{"min_count: 50", "suggest_min_users: 5"} {
		var o Checks
		if err := yaml.Unmarshal([]byte("rate_limited_ip:\n  "+key+"\n"), &o); err != nil {
			t.Fatal(err)
		}
		if err := validateOverrides(o); err != nil {
			t.Errorf("%s: %v", key, err)
		}
	}
}
