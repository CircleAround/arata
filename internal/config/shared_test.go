package config

import (
	"strings"
	"testing"
)

// shared_sources (ADR 0094 の 1 節) の下限。login_bruteforce は min_count の 5 倍、rate_limited_ip は 200 が既定。値はすべて架空。
func TestSharedMinCountDefaults(t *testing.T) {
	c := DefaultChecks()
	if c.LoginBruteforce.SharedMinCount != 100 || c.RateLimitedIP.SharedMinCount != 200 {
		t.Fatalf("既定: login_bruteforce %v rate_limited_ip %v", c.LoginBruteforce.SharedMinCount, c.RateLimitedIP.SharedMinCount)
	}
	// min_count だけを書けば、shared_min_count はその 5 倍
	cfg, err := Load(write(t, minimal+"checks:\n  login_bruteforce:\n    min_count: 30\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Checks.LoginBruteforce.SharedMinCount; got != 150 {
		t.Fatalf("min_count 30 の 5 倍: %v", got)
	}
	body := strings.Replace(minimal, "    checks: [default-daily, root_usage]\n",
		"    checks: [default-daily, root_usage]\n    overrides:\n      login_bruteforce: { shared_min_count: 600 }\n", 1) +
		"checks:\n  login_bruteforce:\n    shared_min_count: 400\n  rate_limited_ip:\n    shared_min_count: 500\n"
	cfg, err = Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Checks.LoginBruteforce.SharedMinCount != 400 || cfg.Checks.RateLimitedIP.SharedMinCount != 500 || cfg.ChecksFor("daily").LoginBruteforce.SharedMinCount != 600 {
		t.Fatalf("書いた値と overrides: %+v", cfg.Checks.LoginBruteforce)
	}
}

func TestSharedMinCountInvalid(t *testing.T) {
	for _, body := range []string{
		"checks:\n  login_bruteforce:\n    shared_min_count: -1\n",
		"checks:\n  rate_limited_ip:\n    shared_min_count: -1\n",
	} {
		if _, err := Load(write(t, minimal+body)); err == nil || !strings.Contains(err.Error(), "shared_min_count") {
			t.Errorf("%q: %v", body, err)
		}
	}
}
