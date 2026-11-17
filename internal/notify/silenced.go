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

// llmInput は LLM に渡す report.json を作る。次を除き、ほかは原文のまま:
//   - silenced (理由は利用者が書いた文字列。LLM の入力に入れない。ADR 0068 の 3 節)
//   - 各 finding の triage (許す操作)。同じ表は playbook の「片付け」の節として system に入っている。LLM の入力を、triage を足す前の大きさのままにする
//
// どちらも無ければ元のまま返す。読めなければ元のまま返す (読めない入力は ReadInput が先に止める)。
func llmInput(b []byte, r *schema.Report) []byte {
	if r == nil || (r.Silenced == nil && !hasTriage(r)) {
		return b
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return b
	}
	delete(m, "silenced")
	for _, k := range []string{"already_reported", "info"} {
		if v, ok := m[k]; ok {
			m[k] = withoutTriage(v)
		}
	}
	if v, ok := m["findings"]; ok {
		var fs map[string]json.RawMessage
		if err := json.Unmarshal(v, &fs); err == nil {
			for k, l := range fs {
				fs[k] = withoutTriage(l)
			}
			if nb, err := json.Marshal(fs); err == nil {
				m["findings"] = nb
			}
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return b
	}
	return out
}

func hasTriage(r *schema.Report) bool {
	for _, l := range [][]schema.Finding{r.Findings.New, r.Findings.Changed, r.Findings.Recurred, r.Findings.Resolved, r.Findings.StillOpen, r.AlreadyReported, r.Info} {
		for _, f := range l {
			if f.Triage != nil {
				return true
			}
		}
	}
	return false
}

// withoutTriage は finding の配列から triage を除く (配列として読めなければ元のまま)。
func withoutTriage(v json.RawMessage) json.RawMessage {
	var l []map[string]json.RawMessage
	if err := json.Unmarshal(v, &l); err != nil {
		return v
	}
	for _, f := range l {
		delete(f, "triage")
	}
	out, err := json.Marshal(l)
	if err != nil {
		return v
	}
	return out
}
