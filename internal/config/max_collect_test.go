package config

import (
	"strings"
	"testing"
	"time"
)

// max_collect (ADR 0064): 1 回の収集でそのソースが集める範囲の上限。書かなければ上限なし (今と同じ)。CloudTrail の種類だけで、1h 以上。
func TestMaxCollect(t *testing.T) {
	body := strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    max_collect: 12h\n", 1)
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].MaxCollect != 12*time.Hour {
		t.Errorf("max_collect = %v", c.Sources[0].MaxCollect)
	}
	if c, _ := Load(write(t, minimal)); c.Sources[0].MaxCollect != 0 {
		t.Errorf("default max_collect = %v, want 0 (no limit)", c.Sources[0].MaxCollect)
	}
	for name, tc := range map[string]struct{ body, want string }{
		"too short": {strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    max_collect: 30m\n", 1), "at least 1h"},
		"invalid":   {strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    max_collect: soon\n", 1), "max_collect"},
		"logs": {strings.Replace(minimal, "profiles:", "  - id: web\n    kind: cloudwatch-logs\n    log_group: prod-nginx-access\n    format: nginx_access\n    max_collect: 12h\nprofiles:", 1),
			"max_collect is only for"},
		"logs hourly is ok": {strings.Replace(minimal, "profiles:", "  - id: web\n    kind: cloudwatch-logs\n    log_group: prod-nginx-access\n    format: nginx_access\n    collect: hourly\n    max_collect: 12h\nprofiles:", 1), ""},
	} {
		_, err := Load(write(t, tc.body))
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
