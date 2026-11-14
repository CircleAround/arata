package config

import (
	"regexp"
	"strings"
	"testing"
)

// request.user_id と request.auth (ADR 0052) の設定。アプリが足す 2 種類の行 (actor / auth) の見本。値はすべて架空。
const (
	actorRegex = ` -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})(?: by=(?P<by_kind>[a-z_]{1,32}):(?P<by_id>[A-Za-z0-9_-]{1,64}))?$`
	authRegex  = ` -- : \[[A-Za-z0-9_@-]{1,255}\] auth result=(?P<auth_result>success|failure|impersonate) kind=(?P<auth_kind>[a-z_]{1,32}) id=(?P<auth_id>[A-Za-z0-9_-]{1,64})(?: via=(?P<auth_via>password|remember))?(?: by=(?P<auth_by_kind>[a-z_]{1,32}):(?P<auth_by_id>[A-Za-z0-9_-]{1,64}))?(?: reason=(?P<auth_reason>[a-z_]{1,64}))?$`
)

func userBlock(from, regex string) string {
	s := "      user_id:\n        from: " + from + "\n"
	if regex != "" {
		s += "        regex: '" + regex + "'\n"
	}
	return s
}

func authBlock(regex string) string { return "      auth:\n        regex: '" + regex + "'\n" }

func TestRequestUserID(t *testing.T) {
	// 書かなければ none (段 0)。http_user は出さない
	cfg, err := Load(write(t, logsSource(railsRequest)))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Sources[len(cfg.Sources)-1]
	if s.UserIDFrom() != UserIDFromNone || s.Request.UserID != nil || s.Request.Auth != nil {
		t.Fatalf("既定: %+v", s.Request)
	}

	cfg, err = Load(write(t, logsSource(railsRequest+userBlock("app_line", actorRegex)+authBlock(authRegex))))
	if err != nil {
		t.Fatal(err)
	}
	s = cfg.Sources[len(cfg.Sources)-1]
	if s.UserIDFrom() != UserIDFromAppLine || s.Yields != YieldsHTTPAccess {
		t.Fatalf("app_line: from=%s yields=%s", s.UserIDFrom(), s.Yields)
	}
	ug, err := s.Request.UserGroups()
	if err != nil || strings.Join(ug, ",") != "user_kind,user_id,by_kind,by_id" {
		t.Fatalf("user groups: %v %v", ug, err)
	}
	ag, err := s.Request.AuthGroups()
	if err != nil || strings.Join(ag, ",") != "auth_result,auth_kind,auth_id,auth_via,auth_by_kind,auth_by_id,auth_reason" {
		t.Fatalf("auth groups: %v %v", ag, err)
	}

	// by は任意。debug_sql も同じ仕組み。from: none は書かないのと同じ。auth は user_id が無くても書ける
	for _, body := range []string{
		userBlock("app_line", `\] actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>\d+)$`),
		userBlock("debug_sql", `SELECT "(?P<user_kind>[a-z_]+)"\.\* FROM .* LIMIT \$2  \[\["id", (?P<user_id>\d+)\], \["LIMIT", 1\]\]$`),
		userBlock("none", ""),
		authBlock(`\] auth result=(?P<auth_result>[a-z]+) .*$`),
	} {
		if _, err := Load(write(t, logsSource(railsRequest+body))); err != nil {
			t.Errorf("受け付けるはずの設定を拒否した: %v\n%s", err, body)
		}
	}
}

func TestRequestUserIDInvalid(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"from が無い", "      user_id:\n        regex: '" + actorRegex + "'\n", "request.user_id.from"},
		{"知らない from", userBlock("header", actorRegex), "request.user_id.from"},
		{"none に regex", userBlock("none", actorRegex), "from: none"},
		{"app_line に regex が無い", userBlock("app_line", ""), "regex is required"},
		{"user_id が無い", userBlock("app_line", `actor kind=(?P<user_kind>[a-z_]+)$`), "(?P<user_id>"},
		{"user_kind が無い", userBlock("app_line", `actor id=(?P<user_id>\d+)$`), "(?P<user_kind>"},
		{"知らないキャプチャ", userBlock("app_line", `actor kind=(?P<user_kind>\w+) id=(?P<user_id>\d+) email=(?P<email>\S+)$`), `unknown capture "email"`},
		{"段 0 の項目は書けない", userBlock("app_line", `actor kind=(?P<user_kind>\w+) id=(?P<user_id>\d+) (?P<ip>\S+)$`), `unknown capture "ip"`},
		{"by が片方だけ", userBlock("app_line", `actor kind=(?P<user_kind>\w+) id=(?P<user_id>\d+)(?: by=(?P<by_id>\d+))?$`), "by_kind and by_id"},
		{"行末まで固定していない", userBlock("app_line", `actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>\d+)`), "must end with $"},
		{"エスケープした $ で終わる", userBlock("app_line", `actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>\d+)\$`), "must end with $"},
		{"選択の片方だけが行末", userBlock("app_line", `actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>\d+)|x$`), "must end with $"},
		{"複数行のフラグ", userBlock("app_line", `(?m)actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>\d+)$`), "must end with $"},
		{"RE2 で読めない", userBlock("app_line", `actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>\d+)(?=x)$`), "request.user_id"},
		{"auth に auth_result が無い", authBlock(`auth kind=(?P<auth_kind>\w+)$`), "(?P<auth_result>"},
		{"auth に actor の名前", authBlock(`auth result=(?P<auth_result>\w+) kind=(?P<user_kind>\w+)$`), `unknown capture "user_kind"`},
		{"auth の by が片方だけ", authBlock(`auth result=(?P<auth_result>\w+) by=(?P<auth_by_kind>\w+)$`), "auth_by_kind and auth_by_id"},
		{"auth が行末まで固定していない", authBlock(`auth result=(?P<auth_result>\w+)`), "must end with $"},
		{"auth に regex が無い", "      auth: {}\n", "regex is required"},
	}
	for _, c := range cases {
		_, err := Load(write(t, logsSource(railsRequest+c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
	long := userBlock("app_line", `actor kind=(?P<user_kind>[a-z_]+) id=(?P<user_id>`+strings.Repeat("a", MaxRequestRegexLen)+`)$`)
	if _, err := Load(write(t, logsSource(railsRequest+long))); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long regex: %v", err)
	}
}

// 設定の request.user_id / request.auth の正規表現 (利用者のファイル。LLM が書く) の検証 (ADR 0041・0052)。
// 守る規則: 受け付けた正規表現は RE2 で読め、決まった名前のキャプチャだけを持ち (必須のものは必ずある。by は 2 つとも)、
// **どの入力に対しても、一致は入力の終わりで終わる** (行の途中の同じ並び = 利用者の入力を actor / auth の行として読まない)。
func FuzzRequestUserValidate(f *testing.F) {
	f.Add(actorRegex, authRegex, `I, [2026-11-01T01:02:03.000000 #1]  INFO -- : [5b0c-e1] actor kind=user id=42 by=staff:5`)
	f.Add(`actor kind=(?P<user_kind>\w+) id=(?P<user_id>\d+)`, `auth result=(?P<auth_result>\w+)\$`, `  Parameters: {"q"=>"actor kind=user id=1"}`)
	f.Add(`(?m)actor kind=(?P<user_kind>\w+) id=(?P<user_id>\d+)$`, `auth result=(?P<auth_result>\w+)$|x`, "actor kind=user id=1\nx")
	f.Add(`actor kind=(?P<user_kind>\w+) id=(?P<user_id>\d+)\z`, `(auth result=(?P<auth_result>\w+)$)`, "auth result=success\n")
	f.Add(`\Qactor kind=(?P<user_kind>x) id=(?P<user_id>y)$`, `[$]`, "")
	f.Fuzz(func(t *testing.T, user, auth, input string) {
		r := &Request{UserID: &RequestUserID{From: UserIDFromAppLine, Regex: user}, Auth: &RequestAuth{Regex: auth}}
		check := func(what, expr string, groups []string, err error, known, required []string) {
			if err != nil {
				return
			}
			re, cerr := regexp.Compile(expr)
			if cerr != nil {
				t.Fatalf("%s: RE2 で読めない正規表現を受け付けた: %q", what, expr)
			}
			if len(expr) > MaxRequestRegexLen {
				t.Fatalf("%s: 長すぎる正規表現を受け付けた", what)
			}
			for _, g := range groups {
				if !contains(known, g) {
					t.Fatalf("%s: 知らないキャプチャ %q を受け付けた", what, g)
				}
			}
			for _, g := range required {
				if !contains(groups, g) {
					t.Fatalf("%s: 必須のキャプチャ %q が無い設定を受け付けた", what, g)
				}
			}
			for _, loc := range re.FindAllStringIndex(input, -1) {
				if loc[1] != len(input) {
					t.Fatalf("%s: %q が %q の途中 (%d) で終わる一致をした", what, expr, input, loc[1])
				}
			}
		}
		ug, err := r.UserGroups()
		check("user_id", user, ug, err, RequestUserFields, []string{"user_kind", "user_id"})
		if err == nil && contains(ug, "by_kind") != contains(ug, "by_id") {
			t.Fatalf("by が片方だけの設定を受け付けた: %v", ug)
		}
		ag, err := r.AuthGroups()
		check("auth", auth, ag, err, RequestAuthFields, []string{"auth_result"})
		if err == nil && contains(ag, "auth_by_kind") != contains(ag, "auth_by_id") {
			t.Fatalf("auth の by が片方だけの設定を受け付けた: %v", ag)
		}
	})
}
