package config

import (
	"strings"
	"testing"
)

// request_lines のソースが http_user だけを出す指定 (yields: http_user) と、プロファイルの records (ADR 0075)。値はすべて架空。

func TestRequestYieldsHTTPUser(t *testing.T) {
	// 既定は今と同じ http_access (user_id があれば http_user も)
	cfg, err := Load(write(t, logsSource(railsRequest+userBlock("app_line", actorRegex))))
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.Sources[len(cfg.Sources)-1]; s.Yields != YieldsHTTPAccess {
		t.Fatalf("既定: yields=%s", s.Yields)
	}
	body := "    yields: http_user\n" + railsRequest + userBlock("app_line", actorRegex) + authBlock(authRegex)
	cfg, err = Load(write(t, logsSource(body)))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Sources[len(cfg.Sources)-1]
	if s.Yields != YieldsHTTPUser || s.UserIDFrom() != UserIDFromAppLine {
		t.Fatalf("yields: http_user: %+v", s)
	}
	// yields: http_access を明示しても同じ
	if _, err := Load(write(t, logsSource("    yields: http_access\n"+railsRequest))); err != nil {
		t.Fatal(err)
	}
}

func TestRequestYieldsHTTPUserInvalid(t *testing.T) {
	cases := []struct{ name, body, want string }{
		// http_user だけを出すのに、ユーザー ID の取り方が無い (何も出さないソースになる)
		{"user_id が無い", "    yields: http_user\n" + railsRequest, "yields http_user needs request.user_id"},
		{"from: none", "    yields: http_user\n" + railsRequest + userBlock("none", ""), "yields http_user needs request.user_id"},
		{"auth だけ", "    yields: http_user\n" + railsRequest + authBlock(authRegex), "yields http_user needs request.user_id"},
		// ほかの形式は http_user を出せない
		{"nginx", "    format: nginx_access\n    yields: http_user\n", `cannot yield "http_user"`},
		{"json", "    format: json\n    yields: http_user\n    fields: { ip: a, path: b, user_id: c }\n", `cannot yield "http_user"`},
	}
	for _, c := range cases {
		_, err := Load(write(t, logsSource(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}

func TestRequestYieldsHTTPUserNotForEndpoints(t *testing.T) {
	body := logsSource("    yields: http_user\n"+railsRequest+userBlock("app_line", actorRegex)) +
		"checks:\n  endpoint_abuse:\n    endpoints:\n      - { name: signup, paths: [/signup], sources: [web] }\n"
	if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), "yields http_access") {
		t.Fatalf("endpoint_abuse の sources に http_user だけのソース: %v", err)
	}
}

func TestProfileRecords(t *testing.T) {
	userSrc := "    yields: http_user\n" + railsRequest + userBlock("app_line", actorRegex)
	withRecords := func(src, records string) string {
		return strings.Replace(logsSource(src), "    checks: [default-daily, root_usage]\n", "    checks: [default-daily, root_usage]\n    records: "+records+"\n", 1)
	}
	cfg, err := Load(write(t, withRecords(userSrc, "[http_user]")))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Profiles["daily"].Records, ","); got != "http_user" {
		t.Fatalf("records: %q", got)
	}
	// 書かなければ空 (暗黙の既定を持たない。ADR 0014)
	cfg, err = Load(write(t, logsSource(userSrc)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles["daily"].Records) != 0 {
		t.Fatalf("既定: %v", cfg.Profiles["daily"].Records)
	}
	// http_access と http_user の両方を出すソースでも http_user を出すので書ける
	if _, err := Load(write(t, withRecords(railsRequest+userBlock("app_line", actorRegex), "[http_user]"))); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, src, records, want string }{
		{"今は http_user だけ", userSrc, "[http_access]", `records: "http_access"`},
		{"知らない種類", userSrc, "[nginx]", `records: "nginx"`},
		{"重複", userSrc, "[http_user, http_user]", "records: duplicate"},
		{"出すソースが無い", railsRequest, "[http_user]", "no source yields http_user"},
	} {
		_, err := Load(write(t, withRecords(c.src, c.records)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}
