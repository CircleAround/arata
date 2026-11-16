package notify

import (
	"encoding/json"
	"fmt"

	"github.com/CircleAround/arata/internal/report/schema"
)

// silencedLine は「黙らせているもの」(report.json の silenced。ADR 0068 の 3 節) の件数の 1 行。LLM を通さず、規則で作る。
// 理由と操作した人は出さない (利用者が書いた文字列で、通知に要るのは「見直すべきものがある」ことだけ。ADR 0037)。
// highAck は high 以上を ack しているか (on_quiet: silent でも送る)。節が無い・全部 0 なら空。
func silencedLine(r *schema.Report) (line string, highAck bool) {
	if r == nil || r.Silenced == nil || r.Silenced.Summary.Empty() {
		return "", false
	}
	n := r.Silenced.Summary
	line = fmt.Sprintf("黙らせているもの: ack %d 件 (high 以上 %d、force %d)・snooze %d 件 (%d 日以内に期日 %d、期日を過ぎた %d)・allowlist の期限 %d 日以内 %d / 切れた %d (詳しくは report.md の「黙らせているもの」)",
		n.Acked, n.AckedHigh, n.Forced, n.Snoozed, schema.SnoozeExpiringDays, n.SnoozeExpiring, n.SnoozeExpired, schema.AllowlistExpiringDays, n.AllowlistExpiring, n.AllowlistExpired)
	if n.AckedHigh > 0 {
		line += "。high 以上の ack は、後で本物が起きても再報告されません。snooze か resolve に直せないか見直してください"
	}
	return line, n.AckedHigh > 0
}

// withoutSilenced は LLM に渡す report.json から silenced を除く (理由は利用者が書いた文字列。LLM の入力に入れない)。
// silenced が無ければ元のまま返す。読めなければ元のまま返す (読めない入力は ReadInput が先に止める)。
func withoutSilenced(b []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return b
	}
	if _, ok := m["silenced"]; !ok {
		return b
	}
	delete(m, "silenced")
	out, err := json.Marshal(m)
	if err != nil {
		return b
	}
	return out
}
