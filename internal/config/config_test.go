package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimal = `
name: acme
store: dir:///var/lib/arata/acme
sources:
  - id: trail
    kind: cloudtrail-lookup
profiles:
  daily:
    window: 24h
    checks: [default-daily, root_usage]
`

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "acme" || cfg.Store.Dir != "/var/lib/arata/acme" {
		t.Fatalf("unexpected: %+v", cfg)
	}
	if cfg.Retention.RawJSONL != 365*24*time.Hour || cfg.Retention.Events != 90*24*time.Hour ||
		cfg.Retention.Metrics != 400*24*time.Hour || cfg.Retention.Findings != 180*24*time.Hour || cfg.Retention.Runs != 400*24*time.Hour {
		t.Fatalf("retention defaults: %+v", cfg.Retention)
	}
	if cfg.AWS.Region != "ap-northeast-1" {
		t.Fatalf("region default: %q", cfg.AWS.Region)
	}
	if strings.Join(cfg.Sources[0].Regions, ",") != "ap-northeast-1,us-east-1" {
		t.Fatalf("source regions default to aws.region + us-east-1: %v", cfg.Sources[0].Regions)
	}
	if cfg.Profiles["daily"].Window != 24*time.Hour || cfg.Profiles["daily"].MaxCatchup != 7*24*time.Hour {
		t.Fatalf("window / max_catchup: %+v", cfg.Profiles["daily"])
	}
	// allowlist の既定は設定ファイルと同じディレクトリの allowlist.yaml
	if filepath.Base(cfg.Allowlist) != "allowlist.yaml" || !filepath.IsAbs(cfg.Allowlist) {
		t.Fatalf("allowlist default: %q", cfg.Allowlist)
	}
}

func TestSourceRegions(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		err  bool
	}{
		{"regions list", strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    regions: [us-east-1, ap-northeast-1, us-east-1]\n", 1), "us-east-1,ap-northeast-1", false},
		{"single region compat", strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    region: eu-west-1\n", 1), "eu-west-1", false},
		{"aws.region is us-east-1", "aws:\n  region: us-east-1\n" + minimal, "us-east-1", false},
		{"both", strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    region: eu-west-1\n    regions: [us-east-1]\n", 1), "", true},
		{"max_catchup", strings.Replace(minimal, "    window: 24h\n", "    window: 24h\n    max_catchup: 2d\n", 1), "ap-northeast-1,us-east-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(write(t, tc.body))
			if (err != nil) != tc.err {
				t.Fatalf("err=%v", err)
			}
			if err != nil {
				return
			}
			if got := strings.Join(cfg.Sources[0].Regions, ","); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if tc.name == "max_catchup" && cfg.Profiles["daily"].MaxCatchup != 48*time.Hour {
				t.Fatalf("max_catchup: %v", cfg.Profiles["daily"].MaxCatchup)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"24h", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"1w", 0, true},
		{"", 0, true},
		{"-1d", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseDuration(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("%q: err=%v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("%q: got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"unknown kind", strings.Replace(minimal, "cloudtrail-lookup", "cloudwatch-logz", 1), "unsupported kind"},
		{"bad store scheme", strings.Replace(minimal, "dir://", "s3://", 1), "store"},
		{"no sources", strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n", 1) + "", ""},
		{"duplicate id", minimal + "  - id: trail\n    kind: cloudtrail-lookup\n", ""},
		{"unknown check", strings.Replace(minimal, "root_usage", "nope", 1), ""},
		{"no profiles", strings.Split(minimal, "profiles:")[0], "profiles"},
		{"bad window", strings.Replace(minimal, "24h", "1w", 1), "window"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, tc.body))
			switch tc.name {
			case "no sources", "unknown check":
				// sources の重複は Validate で弾く。unknown check は checks パッケージが判定するので config では通す。
				if tc.name == "unknown check" && err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			case "duplicate id":
				if err == nil || !strings.Contains(err.Error(), "duplicate") {
					t.Fatalf("expected duplicate error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestExpandChecks(t *testing.T) {
	p := Profile{Checks: []string{"default-daily", "root_usage"}}
	got := p.ExpandChecks(map[string][]string{"daily": {"iam_changes", "new_principal"}})
	want := []string{"iam_changes", "new_principal", "root_usage"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v", got)
	}
}

func logsSource(extra string) string {
	return strings.Replace(minimal, "profiles:", "  - id: web\n    kind: cloudwatch-logs\n    log_group: /app/nginx\n"+extra+"profiles:", 1)
}

func TestCloudWatchLogsSource(t *testing.T) {
	cfg, err := Load(write(t, logsSource("    format: nginx_access\n")))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Sources[1]
	if s.Yields != "http_access" || s.ExpectedMatchRate != 0.8 || !s.SampleLines || strings.Join(s.Regions, ",") != "ap-northeast-1" {
		t.Fatalf("defaults: %+v", s)
	}
	cfg, err = Load(write(t, logsSource("    format: json\n    expected_match_rate: 0.6\n    sample_lines: false\n    fields: { ip: remote_ip, path: path, status: status, time: \"@timestamp\" }\n")))
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.Sources[1]; s.ExpectedMatchRate != 0.6 || s.SampleLines {
		t.Fatalf("overrides: %+v", s)
	}
	if _, err := Load(write(t, logsSource("    format: wafv2\n"))); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(write(t, logsSource("    format: regex\n    regex: 'Started (?P<method>\\w+) \"(?P<path>/admin/[^\"]*)\" for (?P<ip>[\\d.]+)'\n"))); err != nil {
		t.Fatal(err)
	}

	bad := []struct{ name, extra, want string }{
		{"no format", "", "format"},
		{"unknown format", "    format: apache\n", "format"},
		{"yields mismatch", "    format: wafv2\n    yields: http_access\n", "cannot yield"},
		{"rate", "    format: nginx_access\n    expected_match_rate: 1.5\n", "expected_match_rate"},
		{"json lacks path", "    format: json\n    fields: { ip: remote_ip }\n", "path is required"},
		{"json unknown field", "    format: json\n    fields: { ip: a, path: b, email: c }\n", "unknown normalized field"},
		{"regex lacks ip", "    format: regex\n    regex: '(?P<path>/\\S+)'\n", "(?P<ip>"},
		{"regex backref", "    format: regex\n    regex: '(?P<ip>\\S+) (?P<path>\\S+) \\1'\n", "regex"},
		{"regex lookahead", "    format: regex\n    regex: '(?P<ip>\\S+)(?=x) (?P<path>\\S+)'\n", "regex"},
		{"two regions", "    format: nginx_access\n    regions: [ap-northeast-1, us-east-1]\n", "single region"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(t, logsSource(tc.extra)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := Load(write(t, strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudwatch-logs\n    format: nginx_access\n", 1))); err == nil || !strings.Contains(err.Error(), "log_group") {
		t.Fatalf("log_group required: %v", err)
	}
}

func TestChecksConfig(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	lb := cfg.Checks.LoginBruteforce
	if strings.Join(lb.Paths, ",") != "/users/sign_in,/login,/signin" || lb.Baseline.BaselineDays != 14 || lb.Baseline.Factor != 3 || lb.Baseline.MinCount != 20 {
		t.Fatalf("login_bruteforce defaults: %+v", lb)
	}
	if cfg.Checks.WAFBlockTrend.TopN != 5 || len(cfg.Checks.ProbePaths.Paths) == 0 || cfg.Checks.ProbePaths.Baseline.MinCount != 10 {
		t.Fatalf("defaults: %+v", cfg.Checks)
	}
	cfg, err = Load(write(t, minimal+"checks:\n  login_bruteforce:\n    paths: [/session]\n    factor: 5\n    min_count: 3\n  probe_paths:\n    exclude_paths: [/admin/assets]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if lb := cfg.Checks.LoginBruteforce; lb.Paths[0] != "/session" || lb.Baseline.Factor != 5 || lb.Baseline.MinCount != 3 || lb.Baseline.BaselineDays != 14 {
		t.Fatalf("overrides: %+v", lb)
	}
	for _, body := range []string{
		minimal + "checks:\n  probe_paths:\n    paths: [admin]\n",
		minimal + "checks:\n  login_bruteforce:\n    min_baseline_days: 30\n",
		minimal + "checks:\n  bogus: {}\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestIngestDelay(t *testing.T) {
	src := func(extra string) string {
		return `
name: acme
store: dir:///var/lib/arata/acme
sources:
  - id: trail
    kind: cloudtrail-lookup
` + extra + `
  - id: nginx
    kind: cloudwatch-logs
    log_group: /app/nginx
    format: nginx_access
profiles:
  daily:
    window: 24h
    checks: [default-daily]
`
	}
	cfg, err := Load(write(t, src("")))
	if err != nil {
		t.Fatal(err)
	}
	// 既定: CloudTrail は記録まで 5〜15 分、CloudWatch Logs は取り込みに数分の遅延がある
	if cfg.Sources[0].IngestDelay != 15*time.Minute || cfg.Sources[1].IngestDelay != 5*time.Minute {
		t.Fatalf("ingest_delay defaults: %v %v", cfg.Sources[0].IngestDelay, cfg.Sources[1].IngestDelay)
	}
	if cfg.MaxIngestDelay() != 15*time.Minute {
		t.Fatalf("max ingest delay: %v", cfg.MaxIngestDelay())
	}
	for raw, want := range map[string]time.Duration{"30m": 30 * time.Minute, "1h": time.Hour, "0": 0, "0s": 0} {
		cfg, err := Load(write(t, src("    ingest_delay: "+raw)))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if cfg.Sources[0].IngestDelay != want {
			t.Fatalf("%s: got %v", raw, cfg.Sources[0].IngestDelay)
		}
	}
	for _, raw := range []string{"-5m", "abc"} {
		if _, err := Load(write(t, src("    ingest_delay: "+raw))); err == nil || !strings.Contains(err.Error(), "ingest_delay") {
			t.Fatalf("%s must be rejected: %v", raw, err)
		}
	}
}

func TestAccessDeniedConfig(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	ad := cfg.Checks.AccessDenied
	if strings.Join(ad.ErrorCodes, ",") != "AccessDenied,AccessDeniedException,UnauthorizedOperation,Client.UnauthorizedOperation" ||
		ad.MinDistinctAPIs != 5 || ad.HighDistinctAPIs != 20 || ad.Baseline.MinCount != 50 || ad.Baseline.Factor != 3 ||
		ad.Baseline.BaselineDays != 14 || ad.Baseline.MinBaselineDays != 7 {
		t.Fatalf("access_denied defaults: %+v", ad)
	}
	cfg, err = Load(write(t, minimal+"checks:\n  access_denied:\n    error_codes: [AccessDenied]\n    min_distinct_apis: 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ad := cfg.Checks.AccessDenied; strings.Join(ad.ErrorCodes, ",") != "AccessDenied" || ad.MinDistinctAPIs != 3 || ad.HighDistinctAPIs != 20 {
		t.Fatalf("access_denied: %+v", ad)
	}
	for _, body := range []string{
		minimal + "checks:\n  access_denied:\n    min_distinct_apis: 30\n", // high_distinct_apis (20) 未満でなければならない
		minimal + "checks:\n  access_denied:\n    min_baseline_days: 30\n",
		minimal + "checks:\n  access_denied:\n    error_codes: [\"\"]\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
	// error_codes は保存する (events に残す) 条件なので overrides では変えられない
	body := strings.Replace(minimal, "    checks: [default-daily, root_usage]\n", "    checks: [default-daily, root_usage]\n    overrides:\n      access_denied: { error_codes: [AccessDenied] }\n", 1)
	if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), "access_denied.error_codes") {
		t.Fatalf("want collection condition error, got %v", err)
	}
}

func TestProfileOverrides(t *testing.T) {
	body := strings.Replace(minimal, "    checks: [default-daily, root_usage]\n",
		"    checks: [default-daily, root_usage]\n    overrides:\n      login_bruteforce: { factor: 5, min_count: 50 }\n  weekly:\n    window: 7d\n    checks: [new_principal]\n", 1) +
		"checks:\n  login_bruteforce:\n    min_count: 30\n    top_ip_min_count: 8\n"
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.ChecksFor("daily").LoginBruteforce
	if d.Baseline.Factor != 5 || d.Baseline.MinCount != 50 || d.TopIPMinCount != 8 || d.Baseline.BaselineDays != 14 {
		t.Fatalf("daily: %+v", d)
	}
	// 上書きしないプロファイルは全体の checks: の値 (全体の値は変わらない)
	if w := cfg.ChecksFor("weekly").LoginBruteforce; w.Baseline.Factor != 3 || w.Baseline.MinCount != 30 {
		t.Fatalf("weekly: %+v", w)
	}
	if cfg.Checks.LoginBruteforce.Baseline.MinCount != 30 {
		t.Fatalf("global must not change: %+v", cfg.Checks.LoginBruteforce)
	}
	origin := map[string]string{}
	for _, p := range cfg.ParamsFor("daily") {
		if p.Check == "login_bruteforce" {
			origin[p.Key] = p.Origin + "=" + fmt.Sprint(p.Value)
		}
	}
	want := map[string]string{"factor": "overrides=5", "min_count": "overrides=50", "top_ip_min_count": "checks=8", "baseline_days": "default=14", "paths": "default=[/users/sign_in /login /signin]"}
	for k, v := range want {
		if origin[k] != v {
			t.Errorf("%s: got %q want %q", k, origin[k], v)
		}
	}

	bad := []struct{ name, overrides, want string }{
		{"collection condition", "      login_bruteforce: { paths: [/x] }\n      probe_paths: { exclude_paths: [/admin] }\n", "login_bruteforce.paths, probe_paths.exclude_paths"},
		{"invalid merged", "      login_bruteforce: { min_baseline_days: 30 }\n", "overrides"},
		{"unknown check", "      root_usage: {}\n", "root_usage"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(minimal, "    checks: [default-daily, root_usage]\n", "    checks: [default-daily, root_usage]\n    overrides:\n"+tc.overrides, 1)
			_, err := Load(write(t, body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParamChecks(t *testing.T) {
	if got := strings.Join(ParamChecks(), ","); got != "login_bruteforce,probe_paths,waf_block_trend,access_denied,credential_hygiene,posture" {
		t.Fatalf("got %s", got)
	}
}

func TestUnknownKeys(t *testing.T) {
	body := minimal + "    overide:\n      x: 1\nchecks:\n  login_bruteforce:\n    factr: 2\n    factor: 3\n  bogus: {}\nretention:\n  raw_jsonl: 30d\nnope: 1\n"
	body = strings.Replace(body, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    regoins: [x]\n", 1)
	got, err := UnknownKeys([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := "sources[0].regoins,profiles.daily.overide,checks.login_bruteforce.factr,checks.bogus,nope"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
	if got, _ := UnknownKeys([]byte(minimal)); len(got) != 0 {
		t.Fatalf("minimal: %v", got)
	}
}

func TestSnapshotSources(t *testing.T) {
	body := strings.Replace(minimal, "profiles:", "  - id: iam\n    kind: iam-credential-report\n  - id: gd\n    kind: guardduty\n    regions: [ap-northeast-1, us-east-1]\n  - id: aa\n    kind: access-analyzer\n  - id: posture\n    kind: posture\nprofiles:", 1)
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"iam": "ap-northeast-1", "gd": "ap-northeast-1,us-east-1", "aa": "ap-northeast-1", "posture": "ap-northeast-1"}
	for _, s := range cfg.Sources[1:] {
		if strings.Join(s.Regions, ",") != want[s.ID] || s.IngestDelay != 0 {
			t.Fatalf("%s: %v %v", s.ID, s.Regions, s.IngestDelay)
		}
	}
	if cfg.Checks.CredentialHygiene.UnusedDays != 90 || cfg.Checks.Posture.MinPasswordLength != 14 {
		t.Fatalf("defaults: %+v", cfg.Checks)
	}
	if _, err := Load(write(t, minimal+"checks:\n  posture:\n    min_password_length: 200\n")); err == nil {
		t.Fatal("min_password_length must be validated")
	}
}
