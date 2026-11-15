package config

import (
	"strings"
	"testing"
)

const hourlyLogs = `
name: acme
store: dir:///var/lib/arata/acme
sources:
  - id: trail
    kind: cloudtrail-lookup
  - id: waf
    kind: cloudwatch-logs
    log_group: aws-waf-logs-prod
    format: wafv2
    collect: hourly
profiles:
  daily:
    window: 24h
    checks: [default-daily, root_usage]
`

// collect: hourly (ADR 0065): cloudwatch-logs を時の単位で続きだけ読む。書かなければ今と同じ (日の頭から読み直す)。
// request_lines と text は対象外。endpoint_abuse の時間幅は 1 時間を割り切る値に限る (幅が時の境目をまたがない)。
func TestCollectHourly(t *testing.T) {
	c, err := Load(write(t, hourlyLogs))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Sources[1].CollectHourly() || c.Sources[0].CollectHourly() {
		t.Errorf("CollectHourly = %v %v", c.Sources[1].CollectHourly(), c.Sources[0].CollectHourly())
	}
	for name, tc := range map[string]struct{ old, new, want string }{
		"unknown value":   {"collect: hourly", "collect: daily", "collect"},
		"not logs":        {"    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    collect: hourly\n", "only for kind cloudwatch-logs"},
		"request_lines":   {"    format: wafv2\n", "    format: request_lines\n    yields: http_access\n    request:\n      id: '^\\[(?P<request_id>[^\\]]+)\\]'\n", "request_lines"},
		"endpoint window": {"profiles:", "checks:\n  endpoint_abuse:\n    window: 45m\n    endpoints:\n      - { name: signup, paths: [/signup], sources: [web] }\nprofiles:", "divide an hour"},
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(hourlyLogs, tc.old, tc.new, 1)
			if name == "endpoint window" {
				body = strings.Replace(body, "  - id: waf\n    kind: cloudwatch-logs\n    log_group: aws-waf-logs-prod\n    format: wafv2\n",
					"  - id: web\n    kind: cloudwatch-logs\n    log_group: prod-nginx-access\n    format: nginx_access\n", 1)
			}
			if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
