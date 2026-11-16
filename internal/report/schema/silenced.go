package schema

import (
	"fmt"
	"strings"
)

// 「黙らせているもの」の節 (ADR 0068 の 3 節)。プロファイルに silenced: true を書いたときだけ出す (雛形では weekly)。

// 決まった期間 (設定は足さない。ADR 0068)。
const (
	// SnoozeExpiringDays は「期日が近い snooze」に入れる日数。
	SnoozeExpiringDays = 7
	// AllowlistExpiringDays は「期限が近い allowlist の項目」に入れる日数。
	AllowlistExpiringDays = 30
)

// Silenced は ack / snooze で黙らせている finding と、期限の近い・切れた allowlist の項目。
type Silenced struct {
	// Summary は件数 (aratam が通知の 1 行に使う)。
	Summary SilencedSummary `json:"summary"`
	// Findings は acked / snoozed の finding。重大度 (今の重大度と黙らせたときの重大度の重いほう) の高い順 → 黙らせた日の古い順。
	Findings []SilencedFinding `json:"findings"`
	// SnoozeExpiring は次の 7 日で期日が切れる snooze (Findings の一部)。
	SnoozeExpiring []SilencedFinding `json:"snooze_expiring"`
	// SnoozeExpired は期日を過ぎても snoozed のままのもの (Findings の一部)。event 型は期日の後に観測されなければ snoozed のまま残り、
	// review の既定にも報告にも出ないので、ここで見せる (ADR 0068 の 9 節)。
	SnoozeExpired []SilencedFinding `json:"snooze_expired"`
	// AllowlistExpiring は allowlist の expires が次の 30 日で切れる項目と、既に切れた項目 (期限の早い順)。
	AllowlistExpiring []AllowlistExpiry `json:"allowlist_expiring"`
}

// SilencedSummary は節の件数。high 以上は、今の重大度と黙らせたときの重大度の重いほうで数える。
type SilencedSummary struct {
	Acked     int `json:"acked"`
	AckedHigh int `json:"acked_high"`
	// Forced は --force で守りを越えて ack したもの (最後の操作が forced)。
	Forced            int `json:"forced"`
	Snoozed           int `json:"snoozed"`
	SnoozedHigh       int `json:"snoozed_high"`
	SnoozeExpiring    int `json:"snooze_expiring"`
	SnoozeExpired     int `json:"snooze_expired"`
	AllowlistExpiring int `json:"allowlist_expiring"`
	AllowlistExpired  int `json:"allowlist_expired"`
}

// Empty は何も黙らせておらず、期限の近い項目も無い。
func (s SilencedSummary) Empty() bool { return s == SilencedSummary{} }

// SilencedFinding は黙らせている finding 1 件。
type SilencedFinding struct {
	ID       string `json:"id"`
	Check    string `json:"check"`
	Key      string `json:"key"`
	Severity string `json:"severity" jsonschema:"enum=critical|high|medium|low|info"`
	// SuppressedSeverity は ack / snooze したときの重大度 (ADR 0022)。
	SuppressedSeverity string `json:"suppressed_severity"`
	Summary            string `json:"summary"`
	Status             string `json:"status" jsonschema:"enum=acked|snoozed"`
	// SilencedAt は黙らせた時刻 (最後の操作の時刻。記録が無ければ last_changed)。
	SilencedAt  string `json:"silenced_at"`
	SnoozeUntil string `json:"snooze_until,omitempty"`
	// LastAction は最後の片付けの操作。ストアの schema 8 より前の操作には無い。
	LastAction *SilencedAction `json:"last_action,omitempty"`
}

// SilencedAction は片付けの操作の記録。Reason は利用者が書いた文字列 (信用できない入力)。
type SilencedAction struct {
	Action string `json:"action" jsonschema:"enum=ack|snooze|resolve|approve"`
	By     string `json:"by"`
	Reason string `json:"reason"`
	Forced bool   `json:"forced"`
	At     string `json:"at"`
}

// AllowlistExpiry は期限のある allowlist の項目 1 件。
type AllowlistExpiry struct {
	// Section は allowlist.yaml の節 (principals / assume_destinations / oidc_subjects)。
	Section string `json:"section"`
	// Subject は項目の対象 (主体の ARN・アカウント・入り口など)。
	Subject string `json:"subject"`
	Expires string `json:"expires"`
	Expired bool   `json:"expired"`
}

// silencedMarkdown は report.md の「黙らせているもの」の節。理由は利用者の入力なので、コードの中に入れて Markdown として解釈させない。
func silencedMarkdown(b *strings.Builder, s *Silenced) {
	if s == nil {
		return
	}
	n := s.Summary
	fmt.Fprintf(b, "## 黙らせているもの\n\n")
	fmt.Fprintf(b, "- ack %d 件 (high 以上 %d、force %d) / snooze %d 件 (high 以上 %d、%d 日以内に期日 %d、期日を過ぎた %d) / allowlist の期限 %d 日以内 %d・切れた %d\n",
		n.Acked, n.AckedHigh, n.Forced, n.Snoozed, n.SnoozedHigh, SnoozeExpiringDays, n.SnoozeExpiring, n.SnoozeExpired, AllowlistExpiringDays, n.AllowlistExpiring, n.AllowlistExpired)
	if n.AckedHigh > 0 {
		b.WriteString("- **high 以上を ack しています**。後で本物が起きても、重大度が上がらない限り再報告されません。snooze (期日) か resolve に直せないか見直してください\n")
	}
	b.WriteString("\n")
	if len(s.Findings) > 0 {
		b.WriteString("### ack・snooze 中の finding\n\n")
		for _, f := range s.Findings {
			fmt.Fprintf(b, "- **[%s]** %s `%s` `%s` %s", f.Severity, inline(f.Summary), f.Check, f.ID, f.Status)
			if f.SuppressedSeverity != "" && f.SuppressedSeverity != f.Severity {
				fmt.Fprintf(b, " (黙らせたときは %s)", f.SuppressedSeverity)
			}
			if f.SnoozeUntil != "" {
				fmt.Fprintf(b, " 期日 %s", f.SnoozeUntil)
			}
			b.WriteString("\n")
			if a := f.LastAction; a != nil {
				forced := ""
				if a.Forced {
					forced = " (force)"
				}
				fmt.Fprintf(b, "  - %s %s %s%s 理由: %s\n", a.Action, codeSpan(a.By), a.At, forced, codeSpan(orDash(a.Reason)))
			} else {
				fmt.Fprintf(b, "  - 記録なし (ストアの schema 8 より前の操作)。黙らせた日 %s\n", f.SilencedAt)
			}
		}
		b.WriteString("\n")
	}
	if len(s.SnoozeExpiring) > 0 {
		fmt.Fprintf(b, "### %d 日以内に期日が切れる snooze\n\n", SnoozeExpiringDays)
		for _, f := range s.SnoozeExpiring {
			fmt.Fprintf(b, "- %s `%s` `%s` 期日 %s\n", inline(f.Summary), f.Check, f.ID, f.SnoozeUntil)
		}
		b.WriteString("\n")
	}
	if len(s.SnoozeExpired) > 0 {
		b.WriteString("### 期日を過ぎても snooze のままのもの\n\n")
		b.WriteString("期日の後に観測されていないので、snoozed のまま残っています (event 型は観測されなくても解消になりません)。直したなら resolve にします。\n\n")
		for _, f := range s.SnoozeExpired {
			fmt.Fprintf(b, "- %s `%s` `%s` 期日 %s\n", inline(f.Summary), f.Check, f.ID, f.SnoozeUntil)
		}
		b.WriteString("\n")
	}
	if len(s.AllowlistExpiring) > 0 {
		fmt.Fprintf(b, "### allowlist の期限 (%d 日以内・切れた)\n\n", AllowlistExpiringDays)
		for _, e := range s.AllowlistExpiring {
			state := "期限"
			if e.Expired {
				state = "**切れた**"
			}
			fmt.Fprintf(b, "- %s `%s` %s %s\n", e.Section, inline(e.Subject), state, e.Expires)
		}
		b.WriteString("\n")
	}
}

// codeSpan は利用者の入力をコードの中に入れる。バッククォートを含めさせない (囲みを閉じさせない)。
func codeSpan(s string) string {
	return "`" + strings.ReplaceAll(inline(s), "`", "'") + "`"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
