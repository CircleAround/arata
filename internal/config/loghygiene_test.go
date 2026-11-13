package config

import (
	"strings"
	"testing"
)

const hygieneBase = `
name: acme
store: dir:///var/lib/arata/acme
sources:
  - id: trail
    kind: cloudtrail-lookup
  - id: app_prod
    kind: cloudwatch-logs
    log_group: prod-app
    format: text
    max_scan_gb: 5
  - id: web
    kind: cloudwatch-logs
    log_group: prod-nginx-access
    format: nginx_access
profiles:
  weekly:
    window: 7d
    checks: [default-weekly]
`

func TestLogHygieneConfig(t *testing.T) {
	// 既定は全部空 (暗黙の既定なし。ADR 0014)
	cfg, err := Load(write(t, hygieneBase))
	if err != nil {
		t.Fatal(err)
	}
	if h := cfg.Checks.LogHygiene; len(h.Sources) != 0 || len(h.Kinds) != 0 || len(h.ParamFields) != 0 || h.Covers("app_prod") {
		t.Fatalf("defaults must be empty: %+v", h)
	}
	// format: text は行を解釈しない (正規化レコードを出さない)
	if s := cfg.Sources[1]; s.Format != FormatText || s.Yields != "" {
		t.Fatalf("text source: %+v", s)
	}

	body := hygieneBase + `checks:
  log_hygiene:
    sources: [app_prod, web]
    kinds: [secret_aws_access_key, secret_slack_token, secret_private_key, presigned_url_long_term_key, presigned_url, unfiltered_param, debug_sql]
    param_fields: [name, address, tel, user-name_2]
`
	cfg, err = Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Checks.LogHygiene
	if !h.Covers("app_prod") || !h.Covers("web") || h.Covers("trail") || len(h.Kinds) != 7 || strings.Join(h.ParamFields, ",") != "name,address,tel,user-name_2" {
		t.Fatalf("log_hygiene: %+v", h)
	}
	if strings.Join(LogHygieneKinds(), ",") != strings.Join(h.Kinds, ",") {
		t.Fatalf("kinds: %v", LogHygieneKinds())
	}

	// sources だけ書いて kinds が空なら、何も流さない (エラーにはしない)
	cfg, err = Load(write(t, hygieneBase+"checks:\n  log_hygiene:\n    sources: [app_prod]\n"))
	if err != nil || cfg.Checks.LogHygiene.Covers("app_prod") {
		t.Fatalf("sources without kinds: %v %+v", err, cfg)
	}
}

func TestLogHygieneConfigInvalid(t *testing.T) {
	long := strings.Repeat("a", 65)
	many := make([]string, 33)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i)
	}
	for name, tc := range map[string]struct{ checks, want string }{
		"unknown source":       {"sources: [nope]\n    kinds: [debug_sql]", "nope"},
		"not a logs source":    {"sources: [trail]\n    kinds: [debug_sql]", "cloudwatch-logs"},
		"duplicate source":     {"sources: [app_prod, app_prod]\n    kinds: [debug_sql]", "duplicate"},
		"unknown kind":         {"sources: [app_prod]\n    kinds: [secret_everything]", "secret_everything"},
		"duplicate kind":       {"sources: [app_prod]\n    kinds: [debug_sql, debug_sql]", "duplicate"},
		"field with quote":     {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: ['na\"me']", "param_fields"},
		"field with slash":     {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: [a/b]", "param_fields"},
		"field with space":     {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: ['a b']", "param_fields"},
		"field with dot":       {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: [user.name]", "param_fields"},
		"field not ascii":      {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: [名前]", "param_fields"},
		"empty field":          {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: ['']", "param_fields"},
		"long field":           {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: [" + long + "]", "param_fields"},
		"too many fields":      {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: [" + strings.Join(many, ", ") + "]", "32"},
		"duplicate field":      {"sources: [app_prod]\n    kinds: [unfiltered_param]\n    param_fields: [name, name]", "duplicate"},
		"param without fields": {"sources: [app_prod]\n    kinds: [unfiltered_param]", "param_fields"},
		"fields without param": {"sources: [app_prod]\n    kinds: [debug_sql]\n    param_fields: [name]", "unfiltered_param"},
	} {
		_, err := Load(write(t, hygieneBase+"checks:\n  log_hygiene:\n    "+tc.checks+"\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "log_hygiene") {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}

	// 集計条件なので overrides では変えられない (スナップショットは全プロファイルで共有)
	_, err := Load(write(t, hygieneBase+"    overrides:\n      log_hygiene: { kinds: [debug_sql] }\n"))
	if err == nil || !strings.Contains(err.Error(), "log_hygiene.kinds") {
		t.Errorf("overrides: %v", err)
	}

	// format: text は yields を持てない。他の形式の項目も書けない
	for _, extra := range []string{"    yields: http_access\n", "    regex: 'x'\n", "    fields: { ip: ip, path: path }\n"} {
		body := strings.Replace(hygieneBase, "    format: text\n", "    format: text\n"+extra, 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("text source with %q must be rejected", strings.TrimSpace(extra))
		}
	}
}

// 設定の検査を通った項目名は形の規則どおり (受け入れた値は書いたとおりの意味。ADR 0050)。
func FuzzLogHygieneParamField(f *testing.F) {
	for _, s := range []string{"name", "address", "tel", "user-name_2", "", "a b", `na"me`, "a/b", "a.b", "名前", "name\n", strings.Repeat("a", 64), strings.Repeat("a", 65), `\`, "a|b", "(x)", "[x]", "x*", "-", "_"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h := LogHygiene{Kinds: []string{HygieneUnfilteredParam}, ParamFields: []string{s}}
		if err := h.validate(); err != nil {
			return
		}
		if len(s) < 1 || len(s) > 64 {
			t.Fatalf("長さ %d の項目名を受け入れた: %q", len(s), s)
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				t.Fatalf("英数字・_・- 以外を含む項目名を受け入れた: %q", s)
			}
		}
	})
}
