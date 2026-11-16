package engine

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestValidateBy(t *testing.T) {
	for _, ok := range []string{"alice", "a", "ops-bot", "first.last", "user_01", strings.Repeat("a", 64)} {
		if err := ValidateBy(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, ng := range []string{"", "alice@example.com", "Alice Example", "-alice", ".alice", "_x", strings.Repeat("a", 65), "ａｌｉｃｅ", "alice\n", "bot[bot]"} {
		if err := ValidateBy(ng); err == nil {
			t.Errorf("%q must be rejected", ng)
		}
	}
}

func TestValidateReason(t *testing.T) {
	for _, ok := range []string{"", "導入作業で作ったロール", "setup; see the change ticket", strings.Repeat("あ", 300)} {
		if err := ValidateReason(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, ng := range []string{"a\nb", "a\rb", "tab\tinside", strings.Repeat("あ", 301), "zero\u200bwidth", "bidi\u202eabc", "\x00", "line\u2028sep", string([]byte{0xff, 0xfe})} {
		if err := ValidateReason(ng); err == nil {
			t.Errorf("%q must be rejected", ng)
		}
	}
}

// 片付けの理由と操作した人は利用者の入力 (ワークフローの入力も含む)。受け付けた値は、報告と review に 1 行で出せる形であること (ADR 0041・0068)。
func FuzzValidateTriageInput(f *testing.F) {
	for _, s := range []string{"alice", "alice@example.com", "a\nb", "zero\u200bwidth", strings.Repeat("あ", 301), "bot[bot]", "\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ValidateBy(s) == nil {
			if s == "" || len(s) > maxByLen || strings.ContainsAny(s, "@ \t\r\n") {
				t.Fatalf("by %q accepted", s)
			}
			for _, r := range s {
				if r > unicode.MaxASCII {
					t.Fatalf("by %q has a non-ASCII rune", s)
				}
			}
		}
		if ValidateReason(s) == nil {
			if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxReasonRunes {
				t.Fatalf("reason %q accepted", s)
			}
			for _, r := range s {
				if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == ' ' {
					t.Fatalf("reason %q has a control / format rune %U", s, r)
				}
			}
		}
	})
}
