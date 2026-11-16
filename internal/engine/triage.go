package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/store"
)

// 片付けの理由と操作した人の形 (ADR 0068 の 1 節)。

const (
	// maxByLen は --by の上限 (バイト。ASCII だけなので文字数と同じ)。
	maxByLen = 64
	// maxReasonRunes は --reason の上限 (文字数)。見本のワークフローの入力の上限と同じ。
	maxReasonRunes = 300
)

// byPattern は --by の形。メールアドレス (@) と氏名 (空白) を受け付けない (レポートに個人を特定できる値を書かない)。
// GitHub のハンドルと OS のユーザー名はこの形に収まる。
var byPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateBy は操作した人 (--by、approve の approved_by) の形を確かめる。
func ValidateBy(by string) error {
	if !byPattern.MatchString(by) {
		return fmt.Errorf("--by %q: want a handle of letters, digits, '.', '_' or '-' (up to %d, starting with a letter or digit; no e-mail address or name)", by, maxByLen)
	}
	return nil
}

// ValidateReason は片付けの理由 (--reason、approve の --note) の形を確かめる。空は「理由なし」として受け付ける。
// 1 行・300 文字まで。制御文字 (Cc)・書式の文字 (Cf)・行と段落の区切り (U+2028・U+2029) を受け付けない
// (報告・review・Actions の Summary に 1 行で出し、見えない文字で読み違えさせない)。
func ValidateReason(reason string) error {
	if !utf8.ValidString(reason) {
		return errors.New("--reason: not valid UTF-8")
	}
	if n := utf8.RuneCountInString(reason); n > maxReasonRunes {
		return fmt.Errorf("--reason: %d characters (up to %d, one line)", n, maxReasonRunes)
	}
	for _, r := range reason {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return fmt.Errorf("--reason: control or invisible character %U is not allowed (one line of visible text)", r)
		}
	}
	return nil
}

// ackGuarded は ack を止めるか。片付けの表 (checks.TriageRows。正は playbook の「片付け」) が、その check × 重大度で ack を許さなければ止める
// (ADR 0068 の 2 節・6 節)。表は high・critical と、同じ Key で重大度の上がる余地の無い行で ack を許さない。
// 上がる余地が無いまま ack すると、ack 中に出直すのは重大度が上がったときだけ (ADR 0022) なので、後で本物が起きても再報告されない。
func ackGuarded(f store.Finding) bool {
	return !checks.TriageAllows(f.Check, checks.Severity(f.Severity), checks.TriageAck)
}

// TriageInfo は review の各 finding に載せる、許す操作と根拠の文書 (ADR 0068 の 4 節)。
type TriageInfo struct {
	// Allowed は許す操作 (approve・ack・snooze・resolve の順)。片付けの表の行から、この finding で approve できなければ approve を除く。
	Allowed []string `json:"allowed"`
	// Escalates は、同じ Key のまま重大度が上がりうるか (false なら ack は最後になるので許さない)。
	Escalates bool `json:"escalates"`
	// Doc は根拠の文書を引くコマンド、Section はその節。
	Doc     string `json:"doc"`
	Section string `json:"section" jsonschema:"const=片付け"`
}

// triageOf は finding の許す操作。表に無い組 (この版が知らない重大度など) は snooze と resolve だけ。
func triageOf(f store.Finding) TriageInfo {
	info := TriageInfo{Doc: "arata help ai playbook " + f.Check, Section: "片付け"}
	row, ok := checks.TriageRowOf(f.Check, checks.Severity(f.Severity))
	if !ok {
		info.Allowed = []string{checks.TriageSnooze, checks.TriageResolve}
		return info
	}
	info.Escalates = row.Escalates
	for _, a := range row.Allowed {
		if a == checks.TriageApprove && !approvable(f) {
			continue
		}
		info.Allowed = append(info.Allowed, a)
	}
	return info
}

// approvable は finding を arata approve で片付けられるか (主体・行き先の承認、access_denied の想定済みの拒否)。
func approvable(f store.Finding) bool {
	if !checks.ApproveChecks[f.Check] {
		return false
	}
	if _, err := ApproveTargetOf(f); err == nil {
		return true
	}
	if _, _, err := destinationTargetOf(f); err == nil {
		return true
	}
	return f.Check == "access_denied"
}

// AckRefusedError は ack を止めた理由と案内 (code: ACK_REFUSED)。CLI は Guidance を標準出力に出す。
type AckRefusedError struct {
	ID, Check, Severity string
	// Approvable は approve を案内するか。
	Approvable bool
	// NoReason は --force に --reason が無かった。
	NoReason bool
}

func (e *AckRefusedError) Error() string {
	if e.NoReason {
		return fmt.Sprintf("ack --force of finding %s needs --reason (why this %s finding may stay silent)", e.ID, e.Severity)
	}
	return fmt.Sprintf("finding %s (%s, %s) cannot be acked: the triage table allows no ack here (high or critical, or no room for the severity to rise for the same key); use approve / snooze --until / resolve (arata help ai playbook %s), or --force --reason", e.ID, e.Check, e.Severity, e.Check)
}

// Guidance は止めたときに人へ出す案内 (人向け。機械は code の ACK_REFUSED を読む)。
func (e *AckRefusedError) Guidance() string {
	var b strings.Builder
	if e.NoReason {
		fmt.Fprintf(&b, "--force には --reason (なぜ黙らせてよいか、1 行) が要ります。finding %s (%s、%s) は ack していません。\n", e.ID, e.Check, e.Severity)
		return b.String()
	}
	fmt.Fprintf(&b, "finding %s (%s、重大度 %s) は ack できません (ストアは変えていません)。\n", e.ID, e.Check, e.Severity)
	b.WriteString("このチェックのこの重大度は、同じ指摘のまま重大度が上がる余地が無い (または最も重い側) ので、ack すると後で本物が起きても二度と報告されません。次のどれかを使ってください:\n")
	if e.Approvable {
		b.WriteString("  - approve: 正規の主体だと確かめた (arata approve <id> --note \"<理由>\"。Actions の運用では allowlist.yaml を PR で直す)\n")
	}
	b.WriteString("  - snooze --until YYYY-MM-DD: 期日を決めて見直す (期日の後に再び観測されたら再報告される)\n")
	b.WriteString("  - resolve: 直した (再び観測されたら新規として報告される)\n")
	fmt.Fprintf(&b, "根拠: arata help ai playbook %s の「片付け」\n", e.Check)
	b.WriteString("終わった出来事だと確かめたうえでどうしても ack するなら、人が --force --reason \"<理由>\" を付けて実行します (記録に force が残り、週次の報告に出ます)。\n")
	return b.String()
}
