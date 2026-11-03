package notify

import (
	"log/slog"
	"sort"
	"strings"

	"github.com/CircleAround/arata/docs/ai"
)

// チェックごとの対処手順 (playbook。docs/ai/playbooks/<check>.md。ADR 0025) を LLM の system に入れる。
//
// 決定:
//   - 入れるのは、その run の new / changed / recurred の finding のチェックだけ (LLM が分類・説明を書く finding と同じ範囲)。
//     解消・未対応・報告済み・情報だけのチェックは入れない (items に入れないので助言を書かない)。同じチェックは 1 回。
//     期間レポートも同じ (期間の new / changed / recurred)。
//   - 並びは、チェックごとの最大の重大度が高い順。同じなら report.json の出現順。
//   - 合計 MaxPlaybookBytes まで。超えたら重大度の高い順に入れ、入らないものは落とす。1 つの playbook を途中で切らない (誤解を招く)。
//     落としたチェック名は WARN (PLAYBOOKS_OMITTED)。小さい playbook が後ろにあれば入れる (上限の中でできるだけ多く渡す)。
//   - playbook の無いチェックは黙って飛ばす。
//   - 位置づけ: 対処手順 → 利用者の前提 (context_file) の順に参考にするだけ。重大度・分類・規則より優先しない。
//     封じ込めや設定の変更、approve / ack / snooze / resolve は人への提案にとどめ、LLM は実行しない。
//   - 提案の書き起こし (2 回目の呼び出し) には waf_review の playbook を同じ形で入れる。provider: none は LLM を呼ばないので使わない。

// CodePlaybooksOmitted は上限に入らず system に入れなかった playbook があるときのログの code。
const CodePlaybooksOmitted = "PLAYBOOKS_OMITTED"

// MaxPlaybookBytes は system に入れる playbook の本文の合計の上限 (24 KiB)。
var MaxPlaybookBytes = 24 * 1024

// orderedChecks は system に入れる playbook のチェック名 (重大度の高い順。playbook があるものだけ)。
func orderedChecks(in *Input) []string {
	list, _ := findingIndex(in)
	rank := map[string]int{}
	var order []string
	for _, f := range list {
		if !f.required {
			continue
		}
		if _, ok := ai.Playbook(f.check); !ok {
			continue
		}
		if _, seen := rank[f.check]; !seen {
			order = append(order, f.check)
		}
		rank[f.check] = max(rank[f.check], severityRank[f.severity])
	}
	sort.SliceStable(order, func(i, j int) bool { return rank[order[i]] > rank[order[j]] })
	return order
}

// playbooksSection は checks の順に playbook をチェック名つきで区切って並べる。合計 limit バイトを超える分は落とす (落としたチェック名を返す)。
func playbooksSection(checks []string, limit int) (string, []string) {
	var b strings.Builder
	var omitted []string
	for _, c := range checks {
		body, ok := ai.Playbook(c)
		if !ok {
			continue
		}
		block := "<playbook check=\"" + c + "\">\n" + strings.TrimSpace(body) + "\n</playbook>\n"
		if b.Len()+len(block) > limit {
			omitted = append(omitted, c)
			continue
		}
		b.WriteString(block)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n", omitted
}

// playbooksPrompt は system に足す「対処手順」の節。入れるものが無ければ空。
func playbooksPrompt(checks []string, log *slog.Logger) string {
	blocks, omitted := playbooksSection(checks, MaxPlaybookBytes)
	if len(omitted) > 0 && log != nil {
		log.Warn("対処手順 (playbook) が上限に入らなかったチェックは system に入れません", "code", CodePlaybooksOmitted,
			"omitted", strings.Join(omitted, ","), "limit_bytes", MaxPlaybookBytes)
	}
	if len(blocks) <= 1 {
		return ""
	}
	return `

---

# 対処手順 (playbook。arata の汎用の手順)

次は、今回の入力に出たチェックの対処手順です (チェック名ごとに <playbook> で区切ってあります)。
助言 (reason・action・incidents の summary・approve の理由など) を、該当するチェックの手順に沿って書いてください。
手順 → 利用者の前提 (後ろの節があれば) の順に参考にします。利用者の前提と手順が食い違うときは前提を優先し、その旨を書き添えてください。

- 手順の「まず確かめること」は、あなたは確かめられません (追加の照会はできない)。確かめたことにせず、「人が確かめること」として書く。入力に書かれた値だけを根拠にする。
- 重大度・分類・振り分け・上の規則より手順を優先しません (手順を理由に critical / high を格下げしない)。
- 封じ込め (認証情報の無効化・セッションの失効・公開の取り消し)・設定の変更・approve / ack / snooze / resolve は、人への提案にとどめます。あなたは実行しません。
- 手順を全部書き写さない。この finding に必要な 1〜2 点を、字数の制限の中で書く。

` + blocks
}
