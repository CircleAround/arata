package store

import "testing"

// S3 のキーは信用しない。一時ディレクトリの外や、求めた接頭辞の外 (SQLite など) のファイルを置き換えさせない。
func TestRelativeKey(t *testing.T) {
	loc := S3Location{Bucket: "b", Prefix: "acme"}
	cases := []struct {
		key, want string
		ok        bool
	}{
		{"acme/reports/daily.json", "reports/daily.json", true},
		{"acme/reports/", "", false},
		{"acme/reports/../audit.sqlite", "", false},
		{"acme/reports/../../etc/passwd", "", false},
		{"acme/reports//daily.json", "", false},
		{"acme/reports/./daily.json", "", false},
		{"acme/raw/x.jsonl", "", false},
		{"other/reports/daily.json", "", false},
	}
	for _, c := range cases {
		got, ok := relativeKey(loc, "reports/", c.key)
		if ok != c.ok || got != c.want {
			t.Errorf("%q: got (%q, %v), want (%q, %v)", c.key, got, ok, c.want, c.ok)
		}
	}
	if got, ok := relativeKey(S3Location{Bucket: "b"}, "raw/", "raw/s/2026-01-01.jsonl"); !ok || got != "raw/s/2026-01-01.jsonl" {
		t.Errorf("接頭辞なし: %q %v", got, ok)
	}
}
