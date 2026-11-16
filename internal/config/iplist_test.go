package config

import (
	"strings"
	"testing"
	"time"
)

const ipListBase = `
name: acme
store: dir:///var/lib/arata/acme
sources:
  - id: web
    kind: cloudwatch-logs
    log_group: prod-nginx-access
    format: nginx_access
profiles:
  daily:
    window: 24h
    checks: [default-daily]
`

// ip_list (ADR 0069): 書かなければ一覧を作らない。書けば、書いていない項目はこの版の既定値 (雛形と同じ) で埋める。
func TestIPListAbsent(t *testing.T) {
	c, err := Load(write(t, ipListBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.IPList != nil {
		t.Errorf("IPList = %+v, want nil (no ip_list: no list)", c.IPList)
	}
	if c.Retention.IPList != 30*24*time.Hour {
		t.Errorf("retention.ip_list = %v, want 30d", c.Retention.IPList)
	}
}

func TestIPListDefaults(t *testing.T) {
	c, err := Load(write(t, ipListBase+"ip_list:\n  reasons:\n    probe: {}\n    sign_in_failure: { min_count: 30 }\n"))
	if err != nil {
		t.Fatal(err)
	}
	l := c.IPList
	if l == nil || l.Active != 7*24*time.Hour || l.ActiveDays() != 7 {
		t.Fatalf("IPList = %+v", l)
	}
	if l.Reasons.WAFBlock != nil {
		t.Errorf("waf_block = %+v, want nil (not written)", l.Reasons.WAFBlock)
	}
	if l.Reasons.Probe == nil || l.Reasons.Probe.MinCount != 3 {
		t.Errorf("probe = %+v, want min_count 3", l.Reasons.Probe)
	}
	s := l.Reasons.SignInFailure
	want := IPListSignIn{MinCount: 30, BaselineDays: 14, Factor: 3, MinBaselineDays: 7, MinCountWindow: 50, MinDays: 3}
	if s == nil || *s != want {
		t.Errorf("sign_in_failure = %+v, want %+v", s, want)
	}
}

func TestIPListValidation(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"no reasons":      {"ip_list:\n  active: 7d\n", "ip_list: at least one reason"},
		"empty reasons":   {"ip_list:\n  reasons: {}\n", "ip_list: at least one reason"},
		"active > M":      {"ip_list:\n  active: 40d\n  reasons: { probe: {} }\n", "ip_list.active (40d) must not be longer than retention.ip_list (30d)"},
		"active > M (2)":  {"ip_list:\n  active: 10d\n  reasons: { probe: {} }\nretention:\n  ip_list: 9d\n", "must not be longer than retention.ip_list"},
		"active not days": {"ip_list:\n  active: 36h\n  reasons: { probe: {} }\n", "ip_list.active must be whole days"},
		"min_count 0":     {"ip_list:\n  reasons: { waf_block: { min_count: -1 } }\n", "ip_list.reasons.waf_block: min_count >= 1"},
		"min_days":        {"ip_list:\n  reasons: { sign_in_failure: { min_days: 8 } }\n", "min_days <= active days"},
		"baseline":        {"ip_list:\n  reasons: { sign_in_failure: { baseline_days: 5, min_baseline_days: 6 } }\n", "min_baseline_days <= baseline_days"},
		"unknown reason":  {"ip_list:\n  reasons: { endpoint_abuse: {} }\n", "endpoint_abuse"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, ipListBase+tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestIPListKnownKeys(t *testing.T) {
	keys, err := UnknownKeys([]byte(ipListBase + "ip_list:\n  active: 7d\n  reasons:\n    sign_in_failure: { min_count: 20, min_count_window: 50, typo: 1 }\nretention:\n  ip_list: 30d\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "ip_list.reasons.sign_in_failure.typo" {
		t.Errorf("unknown = %v", keys)
	}
}
