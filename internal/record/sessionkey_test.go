package record

import (
	"regexp"
	"testing"
)

// 一時的な認証情報のキー (ASIA + 英大文字・数字 16 桁) だけをハッシュにし、キーそのものは残さない (ADR 0076 の 4 節)。
func TestSessionKeyHash(t *testing.T) {
	const key = "ASIAEXAMPLE000000001"
	h, ok := SessionKeyHash(key)
	if !ok || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(h) {
		t.Fatalf("SessionKeyHash(%q) = %q, %v", key, h, ok)
	}
	if h2, _ := SessionKeyHash(key); h2 != h {
		t.Fatalf("同じキーで違うハッシュ: %q %q", h, h2)
	}
	if h3, _ := SessionKeyHash("ASIAEXAMPLE000000002"); h3 == h {
		t.Fatalf("違うキーで同じハッシュ: %q", h3)
	}
	for _, bad := range []string{"", "AKIAEXAMPLE000000001", "ASIAEXAMPLE00000001", "ASIAEXAMPLE0000000001", "asiaexample000000001",
		"ASIAexample000000001", " ASIAEXAMPLE000000001", "ASIAEXAMPLE000000001\n", "ASIAEXAMPLE00000000-", "alice@example.com"} {
		if h, ok := SessionKeyHash(bad); ok || h != "" {
			t.Fatalf("SessionKeyHash(%q) = %q, %v: 形に合わない値はハッシュにしない", bad, h, ok)
		}
	}
}
