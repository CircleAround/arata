package allowlist

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const sharedYAML = `source_ips:
  - cidr: 203.0.113.0/24
    note: 本社
shared_sources:
  - cidr: 198.51.100.0/24
    note: 試験の会場
    approved_by: alice
    approved_at: 2026-11-28
    expires: 2026-12-20
  - cidr: 198.51.100.128/25
    note: 会場の受付
  - cidr: 203.0.113.0/28
    note: 本社と重なる
  - cidr: 2001:db8:10::/48
    note: IPv6 の学校
`

// shared_sources の照合 (ADR 0094 の 1 節)。期限は期限日の終わりまで、source_ips を優先、狭い項目を返す。
func TestSharedSource(t *testing.T) {
	l, err := Parse([]byte(sharedYAML))
	if err != nil {
		t.Fatal(err)
	}
	in := time.Date(2026, 12, 20, 23, 0, 0, 0, time.UTC)
	after := time.Date(2026, 12, 21, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		ip   string
		at   time.Time
		want string // 返る項目の note。空なら当たらない
	}{
		{"198.51.100.7", in, "試験の会場"},
		{"198.51.100.7", after, ""}, // 期限切れで普通の送信元に戻る
		{"198.51.100.200", in, "会場の受付"},
		{"198.51.100.200", after, "会場の受付"}, // 期限の無い狭い項目
		{"203.0.113.5", in, ""},            // source_ips が優先 (丸ごと外す)
		{"2001:db8:10::1", in, "IPv6 の学校"},
		{"2001:db8:11::1", in, ""},
		{"192.0.2.1", in, ""},
		{"x", in, ""}, {"", in, ""},
	}
	for _, tc := range cases {
		e, ok := l.SharedSource(tc.ip, tc.at)
		got := ""
		if ok {
			got = e.Note
		}
		if got != tc.want {
			t.Errorf("%s at %s: got %q want %q", tc.ip, tc.at, got, tc.want)
		}
	}
	if !l.HasSharedSources() {
		t.Fatal("HasSharedSources")
	}
	var subjects []string
	for _, x := range l.Expiring() {
		subjects = append(subjects, x.Section+" "+x.Subject+" "+x.Expires)
	}
	if strings.Join(subjects, "|") != "shared_sources shared_source:198.51.100.0/24 2026-12-20" {
		t.Fatalf("Expiring: %v", subjects)
	}
}

func TestSharedSourceValidation(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"shared_sources:\n  - cidr: 198.51.100.0/24\n", "shared_sources[0]: note is required"},
		{"shared_sources:\n  - cidr: 198.51.100.300/24\n    note: n\n", "shared_sources[0]: cidr: "},
		{"shared_sources:\n  - cidr: 198.51.100.7\n    note: n\n", "shared_sources[0]: cidr: "},
		{"shared_sources:\n  - cidr: 198.51.100.0/24\n    note: n\n    expires: 2026/12/20\n", `shared_sources[0]: expires "2026/12/20": want YYYY-MM-DD`},
		{"shared_sources:\n  - cidr: 198.51.100.0/24\n    note: n\n    expire: 2026-12-20\n", "field expire not found"},
	} {
		if _, err := Parse([]byte(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v want %q", tc.body, err, tc.want)
		}
	}
}

func TestSharedCIDRTooBroad(t *testing.T) {
	for cidr, want := range map[string]bool{
		"198.51.100.0/24": false, "198.51.100.7/32": false, "192.168.0.0/23": true, "0.0.0.0/0": true,
		"2001:db8::/48": false, "2001:db8::/47": true, "::/0": true,
		"::ffff:198.51.100.0/120": false, "::ffff:0.0.0.0/96": true, // IPv4 射影は IPv4 の広さで見る
		"x": false,
	} {
		if got := SharedCIDRTooBroad(cidr); got != want {
			t.Errorf("%s: got %v want %v", cidr, got, want)
		}
	}
}

func TestCheckSharedSources(t *testing.T) {
	body := "source_ips:\n  - cidr: 203.0.113.0/24\nshared_sources:\n  - cidr: 198.51.100.0/24\n    note: n\n  - cidr: 203.0.113.0/28\n    note: n\n  - cidr: 192.168.0.0/16\n    note: n\n  - cidr: 192.0.2.0/24\n    note: n\n    expires: 2026-11-12\n"
	_, ps := Check([]byte(body), time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
	want := []Problem{
		{Line: 6, Warn: true, Msg: "shared_sources[1]: overlaps source_ips[0] (203.0.113.0/24)"},
		{Line: 8, Warn: true, Msg: "shared_sources[2]: 192.168.0.0/16 is broader than /24"},
		{Line: 10, Warn: true, Msg: "shared_sources[3]: expired on 2026-11-12"},
	}
	if len(ps) != len(want) {
		t.Fatalf("got %+v", ps)
	}
	for i, w := range want {
		if ps[i].Line != w.Line || !ps[i].Warn || !strings.Contains(ps[i].Msg, w.Msg) {
			t.Errorf("[%d] got %+v want %+v", i, ps[i], w)
		}
	}
	_, ps = Check([]byte("shared_sources:\n  - cidr: 198.51.100.0/24\n"), time.Now())
	if len(ps) != 1 || ps[0].Warn || ps[0].Line != 2 {
		t.Fatalf("error with line: %+v", ps)
	}
}

func TestAppendShared(t *testing.T) {
	src := "# 既知リスト\nprincipals: []\n\nsource_ips:\n  - cidr: 203.0.113.0/24\n"
	s := NewSharedSource{CIDR: "198.51.100.0/24", Note: "試験の会場: 12 月", ApprovedBy: "alice", ApprovedAt: "2026-11-28", Expires: "2026-12-20"}
	out, added, err := AppendSharedBytes([]byte(src), s)
	if err != nil {
		t.Fatal(err)
	}
	want := src + "\nshared_sources:\n  - cidr: 198.51.100.0/24\n    note: '試験の会場: 12 月'\n    approved_by: alice\n    approved_at: 2026-11-28\n    expires: 2026-12-20\n"
	if string(out) != want || !strings.HasPrefix(added, "  - cidr: 198.51.100.0/24\n") {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	// 2 つ目は列の末尾に足す
	out2, _, err := AppendSharedBytes(out, NewSharedSource{CIDR: "2001:db8:10::/48", Note: "学校"})
	if err != nil || !strings.HasSuffix(string(out2), "expires: 2026-12-20\n  - cidr: 2001:db8:10::/48\n    note: 学校\n") {
		t.Fatalf("second: %v\n%s", err, out2)
	}
	if _, _, err := AppendSharedBytes(out, s); !errors.Is(err, ErrAlreadyListed) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, tc := range []struct {
		s    NewSharedSource
		want string
	}{
		{NewSharedSource{CIDR: "192.168.0.0/16", Note: "n"}, "broader than /24"},
		{NewSharedSource{CIDR: "198.51.100.7/24", Note: "n"}, "write the network address (198.51.100.0/24)"},
		{NewSharedSource{CIDR: "203.0.113.0/28", Note: "n"}, "overlaps source_ips[0]"},
		{NewSharedSource{CIDR: "198.51.100.0/24"}, "note is required"},
		{NewSharedSource{CIDR: "x", Note: "n"}, "cidr: "},
	} {
		if _, _, err := AppendSharedBytes([]byte(src), tc.s); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: got %v want %q", tc.s, err, tc.want)
		}
	}
}
