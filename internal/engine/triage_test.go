package engine

import (
	"fmt"
	"regexp"
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
		case sharedChecks[c]:
			// --shared でだけ approve できる (人の多い送信元。主体の承認は拒む。ADR 0094 の 1 節)
			if !checks.ApproveChecks[c] || !rejectedByCheck {
				t.Errorf("%s must be approvable only with --shared: %v", c, err)
			}
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

// ecs_exec は approve できない。主体を既知にするのは new_principal の approve で、ここでは ack も勧めない (ADR 0072 の 8 節)。
func TestApproveRejectsECSExec(t *testing.T) {
	_, err := ApproveTargetOf(store.Finding{Check: "ecs_exec", Data: map[string]any{"principal": "arn:aws:iam::123456789012:user/alice"}})
	if err == nil || !strings.Contains(err.Error(), "new_principal") || strings.Contains(err.Error(), "ack") {
		t.Fatalf("err: %v", err)
	}
}

// secret_access の bulk-exempt-unmatched: の medium は、同じ重大度の初出の medium と違い ack を止める (ADR 0077。Key の接頭辞の行)。
func TestAckGuardedByKeyPrefix(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:role/example-app-task-execution"
	unmatched := store.Finding{Check: "secret_access", Key: checks.BulkExemptUnmatchedKeyPrefix + arn, Severity: "medium"}
	first := store.Finding{Check: "secret_access", Key: arn, Severity: "medium"}
	if !ackGuarded(unmatched) || ackGuarded(first) {
		t.Fatalf("ackGuarded: unmatched %v, first read %v", ackGuarded(unmatched), ackGuarded(first))
	}
	if info := triageOf(unmatched); strings.Join(info.Allowed, ",") != "snooze,resolve" || info.Escalates {
		t.Fatalf("triageOf(unmatched): %+v", info)
	}
	if info := triageOf(first); strings.Join(info.Allowed, ",") != "ack,snooze,resolve" || !info.Escalates {
		t.Fatalf("triageOf(first): %+v", info)
	}
}

// ack / snooze / resolve の ID の並び。引数ごとに、空白 (スペース・タブ・改行) とカンマで分ける (ワークフローの入力と同じ規則)。
// 形 (12 桁の小文字の 16 進)・重複・件数を、ストアを開く前に全部確かめ、通らない値を全部挙げる。
func TestParseFindingIDs(t *testing.T) {
	a, b, c := "0123456789ab", "ffffffffffff", "a1b2c3d4e5f6"
	for name, tc := range map[string]struct {
		args []string
		want []string
	}{
		"one":              {[]string{a}, []string{a}},
		"args":             {[]string{a, b, c}, []string{a, b, c}},
		"comma":            {[]string{a + "," + b + "," + c}, []string{a, b, c}},
		"comma and spaces": {[]string{" " + a + ", " + b + " ,\t" + c + "\n"}, []string{a, b, c}},
		"empty fields":     {[]string{a + ",,", "", b}, []string{a, b}},
		"limit":            {manyIDs(MaxFindingIDs), manyIDs(MaxFindingIDs)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseFindingIDs(tc.args)
			if err != nil || strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
	for name, tc := range map[string]struct {
		args []string
		want []string // エラーの文に全部が出る
	}{
		"none":            {[]string{" , "}, []string{"no finding id"}},
		"no args":         {nil, []string{"no finding id"}},
		"duplicate":       {[]string{a, b, a}, []string{`"` + a + `" appears twice`}},
		"bad shapes":      {[]string{"0123456789AB", a, "--force", "0123456789a"}, []string{`"0123456789AB"`, `"--force"`, `"0123456789a"`}},
		"ideographic":     {[]string{a + "\u3000" + b}, []string{`"` + a + `\u3000fffffff…"`}}, // 全角の空白は区切りにしない。長い値は切って写す
		"carriage return": {[]string{a + "\r"}, []string{`"` + a + `\r"`}},
		"too many":        {manyIDs(MaxFindingIDs + 1), []string{"101 finding ids", "up to 100"}},
	} {
		t.Run("bad/"+name, func(t *testing.T) {
			got, err := ParseFindingIDs(tc.args)
			if err == nil {
				t.Fatalf("must be rejected: %v", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error lacks %q: %v", w, err)
				}
			}
		})
	}
}

func manyIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%012x", i)
	}
	return out
}

var findingIDShape = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ID の並びは利用者の入力 (ワークフローの入力をそのまま渡すこともある)。ADR 0041 の規則:
// 受け付けた並びは 1〜MaxFindingIDs 件で、どれも 12 桁の小文字の 16 進・重複なし・入力に現れた順。
// 並びを書き直して読み直しても同じ。止めたときの文は 1 行で、上限を超える長さにならない (ログと Summary に出す)。
func FuzzParseFindingIDs(f *testing.F) {
	for _, s := range []string{"0123456789ab", "0123456789ab,ffffffffffff", " 0123456789ab ,\tffffffffffff\n", "0123456789ab 0123456789ab",
		"--help", "0123456789AB", "0123456789ab　ffffffffffff", "0123456789ab\r", ",,,", "\xff\xfe", strings.Join(manyIDs(101), ",")} {
		f.Add(s, "")
		f.Add(s, "a1b2c3d4e5f6")
	}
	f.Fuzz(func(t *testing.T, s1, s2 string) {
		got, err := ParseFindingIDs([]string{s1, s2})
		if err != nil {
			msg := err.Error()
			if strings.ContainsAny(msg, "\n\r") || !utf8.ValidString(msg) || len(msg) > maxIDErrorLen {
				t.Fatalf("error must be one short line: %q", msg)
			}
			return
		}
		if len(got) == 0 || len(got) > MaxFindingIDs {
			t.Fatalf("count %d", len(got))
		}
		seen := map[string]bool{}
		rest := s1 + " " + s2
		for _, id := range got {
			if !findingIDShape.MatchString(id) || seen[id] {
				t.Fatalf("id %q (dup %v) accepted from %q %q", id, seen[id], s1, s2)
			}
			seen[id] = true
			i := strings.Index(rest, id)
			if i < 0 {
				t.Fatalf("%q is not in the input order", id)
			}
			rest = rest[i+len(id):]
		}
		again, err := ParseFindingIDs([]string{strings.Join(got, ",")})
		if err != nil || strings.Join(again, " ") != strings.Join(got, " ") {
			t.Fatalf("not stable: %v -> %v %v", got, again, err)
		}
	})
}
