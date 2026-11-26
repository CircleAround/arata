package scanscripts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// emailRule は .gitleaks.toml の email-address の規則と許可リストを返す (gitleaks と同じ Go の regexp で当てる)。
func emailRule(t *testing.T) (rule *regexp.Regexp, allow []*regexp.Regexp) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(b), `id = "email-address"`)
	if !ok {
		t.Fatal("email-address の規則が無い")
	}
	section, _, _ = strings.Cut(section, "[[rules]]")
	quoted := regexp.MustCompile(`'''(.*?)'''`)
	for _, line := range strings.Split(section, "\n") {
		switch {
		case strings.HasPrefix(line, "regex = "):
			rule = regexp.MustCompile(quoted.FindStringSubmatch(line)[1])
		case strings.HasPrefix(line, "regexes = "):
			for _, m := range quoted.FindAllStringSubmatch(line, -1) {
				allow = append(allow, regexp.MustCompile(m[1]))
			}
		}
	}
	if rule == nil || len(allow) == 0 {
		t.Fatal("規則か許可リストが読めない")
	}
	return rule, allow
}

func TestEmailRuleReservedDomains(t *testing.T) {
	rule, allow := emailRule(t)
	flagged := func(domain string) bool {
		// このファイル自体が検査に掛からないように、アドレスの形は実行時に組み立てる
		m := rule.FindStringSubmatch(" user" + "@" + domain + " ")
		if m == nil {
			return false
		}
		for _, a := range allow {
			if a.MatchString(m[1]) {
				return false
			}
		}
		return true
	}
	// 予約されたドメイン (RFC 2606・6761)。実在しないので引っかけない
	for _, d := range []string{
		"example.com", "example.org", "example.net", "example.co.jp",
		"mail.example.com", "a.b.example.net", "EXAMPLE.COM",
		"corp.example", "a.b.example", "host.test", "host.invalid", "app.localhost",
	} {
		if flagged(d) {
			t.Errorf("予約されたドメインを引っかけた: %s", d)
		}
	}
	// 予約されたドメインに似ているだけのもの
	for _, d := range []string{
		"corp.com", "notexample.com", "example.com.evil.io", "corp.example.evil.io",
		"myexample.org", "test.io", "invalid.jp", "corp.contest", "corp.examples",
	} {
		if !flagged(d) {
			t.Errorf("予約されていないドメインを見逃した: %s", d)
		}
	}
}
