package engine

import (
	"strings"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/store"
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
				if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
					t.Fatalf("reason %q has a control / format rune %U", s, r)
				}
			}
		}
	})
}

// 片付けの表の approve の列 (checks.ApproveChecks) は、arata approve が受け付けるチェックと同じ (ADR 0068 の 4 節)。
// approve の判定 (ApproveTargetOf) は、受け付けないチェックを「主体の指摘ではない」で止め、受け付けるチェックは中身 (主体) を見る。
func TestApproveChecksMatchApprove(t *testing.T) {
	for _, c := range checks.NewRegistry().Names() {
		_, err := ApproveTargetOf(store.Finding{Check: c})
		rejectedByCheck := err != nil && (strings.Contains(err.Error(), "not about a principal") || strings.Contains(err.Error(), "does not write oidc_subjects"))
		switch {
		case c == "access_denied":
			// --expected-denied でだけ approve できる (主体の承認は拒む)
			if !checks.ApproveChecks[c] {
				t.Errorf("access_denied must be approvable (--expected-denied)")
			}
		case checks.ApproveChecks[c] && rejectedByCheck:
			t.Errorf("%s is approvable in the triage table, but arata approve rejects the check: %v", c, err)
		case !checks.ApproveChecks[c] && !rejectedByCheck:
			t.Errorf("%s is not approvable in the triage table, but arata approve looks into it: %v", c, err)
		}
	}
}
