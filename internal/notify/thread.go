package notify

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// slack.details: thread (ADR 0093)。1 通目 (親) に一番伝えたいことと「確認推奨」の概要を、1 通目のスレッドへの返信に詳細を送る。
//
// 決定 (ADR 0093 の 2 節。規則で決める。LLM に任せない):
//   - 1 通目: メンション・注記・警告、見出し、件数 (本日報告済みと情報の件数は除く)、要約 (LLM か規則)、取れていないもの、
//     「まず対応」の項目 (今と同じ形)、「確認推奨」の概要 (見出しと件数を 1 行ずつ)、末尾に「詳細はスレッド」
//   - 返信: 1 通目に入りきらなかった「まず対応」(「まず対応 (続き)」)、「確認推奨」の項目 (主体・値・id・「→」)、
//     本日報告済みと情報の件数、全文と対処手順の案内。上限は 1 通ずつ今と同じで、返信は MaxThreadReplies 通まで。
//     それでも入らないものは「ほか N 件は `arata review` で確認してください」に縮める
//   - 返信に入れるものが無ければ (確認推奨が 0 件で、まず対応も 1 通目に入りきった)、返信しない。そのときは inline と同じ 1 通を送る (呼び出し側)
//   - メンションは 1 通目だけ (返信の本文に head を書かない)
//
// 決定 (docs/aratam.md 3-4 章。開発リードの判断): slack.format: text でも、blocks と同じ規則の分け方 (splitUrgent・groupFindings) を使い、
// mrkdwn の行で書く。振り分けを規則に寄せ、blocks と text で 1 通目の中身をそろえるため。LLM の要約 (headline) は 1 通目の要約に使い、
// LLM の分類 (要対処 / 確認依頼 / 情報) と理由の文は使わない。インシデント候補と approve の提案は返信に載せる。

// MaxThreadReplies はスレッドへの返信の上限 (ADR 0093 の 2 節)。
const MaxThreadReplies = 3

// ThreadNotice は 1 通目の末尾に書く案内。
const ThreadNotice = "詳細はスレッド"

// replyText は返信の通知用の text (プッシュ通知・検索に使われる 1 行)。
func replyText(in *Input) string {
	return clipRunes(Escape(title(in))+": 詳細", maxNotifyRunes)
}

// RunThreadBlocks は slack.details: thread の Block Kit。返信に入れるものが無ければ replies は nil (呼び出し側は inline の RunBlocks を送る)。
func RunThreadBlocks(in *Input, d Decision, r Rules, warnings []string, notes *BlockNotes, notice string) (Message, []Message) {
	top, rest := splitUrgent(in, r.UrgentSeverity)
	head := blocksHead(in, d, r, warnings, notes, notice, top, rest, false)
	extra := []string{ThreadNotice}
	if in.Run != nil && len(in.Run.Proposals) > 0 {
		extra = append(extra, "WAF の改善提案は別のメッセージ")
	}
	if notes != nil {
		extra = append(extra, LLMNotice)
	}
	tail := []Block{contextBlock(strings.Join(extra, "  |  "))}

	groups := groupItems(rest)
	var overview []Block
	if len(groups) > 0 {
		var lines []string
		for _, g := range groups {
			lines = append(lines, g.overview)
		}
		overview = []Block{dividerBlock(), sectionBlock("*確認推奨* (" + ThreadNotice + ")\n" + fitLines(lines, MaxSectionRunes, "ほか %d 項目はスレッド"))}
	}
	urgent, left := fillPieces(itemPieces("*まず対応*", urgentItems(top, notes)), MaxBlocks-len(head)-len(overview)-len(tail), false)
	if len(left) == 0 && len(groups) == 0 {
		return Message{}, nil
	}
	parent := Message{Text: notifyText(in), Blocks: append(append(append(head, urgent...), overview...), tail...)}

	var pieces []piece
	if len(left) > 0 {
		// 続きの先頭には節の見出しを付け直す (1 通目の途中で切れた節)
		cont := append([]Block{sectionBlock("*まず対応 (続き)*")}, left[0].blocks...)
		if left[0].blocks[0].Type == "divider" {
			cont = left[0].blocks
			cont[1] = sectionBlock("*まず対応 (続き)*")
		}
		pieces = append(pieces, piece{blocks: cont, n: left[0].n})
		pieces = append(pieces, left[1:]...)
	}
	pieces = append(pieces, itemPieces("*確認推奨*", groups)...)
	foot := []Block{guideFoot(in)}
	if m := minorCounts(in); len(m) > 0 {
		foot = append([]Block{contextBlock(strings.Join(m, " ・ "))}, foot...)
	}
	var replies []Message
	for k := 0; k < MaxThreadReplies && len(pieces) > 0; k++ {
		last := k == MaxThreadReplies-1
		var body []Block
		body, pieces = fillPieces(pieces, MaxBlocks-len(foot), last)
		if len(body) == 0 { // 1 項目が 1 通に入らない (起きない大きさだが、止まらないように縮める)
			break
		}
		replies = append(replies, Message{Text: replyText(in), Blocks: body})
	}
	lastReply := &replies[len(replies)-1]
	if len(pieces) > 0 {
		lastReply.Blocks = append(lastReply.Blocks, cutBlock(pieces))
	}
	lastReply.Blocks = append(lastReply.Blocks, foot...)
	return parent, replies
}

// fitLines は lines を n 文字までに収める。入らない行は数えて、format (「ほか %d 項目…」) の 1 行にする。
func fitLines(lines []string, n int, format string) string {
	var kept []string
	used := 0
	for i, l := range lines {
		c := utf8.RuneCountInString(l) + 1
		reserve := 0
		if i < len(lines)-1 {
			reserve = utf8.RuneCountInString(fmt.Sprintf(format, len(lines))) + 1
		}
		if used+c+reserve > n {
			kept = append(kept, fmt.Sprintf(format, len(lines)-i))
			break
		}
		kept = append(kept, l)
		used += c
	}
	return strings.Join(kept, "\n")
}

// textPiece は text の書式の、縮めるときの単位 (行のまとまり。n は含む finding の数)。
type textPiece struct {
	text string
	n    int
}

// textSection は節の見出しと項目を textPiece にする (見出しは最初の項目に付ける)。
func textSection(title string, items []textPiece) []textPiece {
	if len(items) == 0 {
		return nil
	}
	out := append([]textPiece(nil), items...)
	out[0].text = "\n" + title + "\n" + out[0].text
	return out
}

// fillText は head の後ろに pieces を順に足し、footer と合わせて MaxTextRunes に収める。入らなくなった後ろを返す。
// cut が真なら、残りがあるときの「ほか N 件」の 1 行の分を残しておく。
func fillText(head string, pieces []textPiece, footer string, cut bool) (string, []textPiece) {
	cutLen := 0
	if cut {
		cutLen = utf8.RuneCountInString(textCut(9999)) + 1
	}
	used := utf8.RuneCountInString(joinNonEmpty(head, footer))
	var kept []string
	for i, p := range pieces {
		c := utf8.RuneCountInString(p.text) + 1
		reserve := 0
		if i < len(pieces)-1 {
			reserve = cutLen
		}
		if used+c+reserve > MaxTextRunes {
			return joinNonEmpty(head, strings.Join(kept, "\n")), pieces[i:]
		}
		kept = append(kept, p.text)
		used += c
	}
	return joinNonEmpty(head, strings.Join(kept, "\n")), nil
}

func textCut(n int) string {
	return fmt.Sprintf("ほか %d 件は `arata review` で確認してください", n)
}

// ThreadText は slack.format: text の slack.details: thread。headline は LLM の要約 (空なら規則の要約)、s は LLM の出力 (インシデント候補と
// approve の提案を返信に載せる。nil なら使わない)。返信に入れるものが無ければ replies は nil (呼び出し側は inline の本文を送る)。
func ThreadText(in *Input, d Decision, r Rules, warnings []string, s *Summary) (string, []string) {
	top, rest := splitUrgent(in, r.UrgentSeverity)
	z := in.Zone
	summary := ruleSummary(top, rest, r.UrgentSeverity)
	if s != nil && strings.TrimSpace(s.Headline) != "" {
		summary = Escape(clipRunes(oneLine(s.Headline), maxReasonRunes))
	}
	lines := head(d.Route, r, "", warnings)
	lines = append(lines, "*"+Escape(title(in))+"* "+Escape(period(in)), counts(in), summary)
	lines = append(lines, coverageLines(in)...)
	headText := strings.Join(lines, "\n")

	groups := groupFindings(rest)
	overview := ""
	if len(groups) > 0 {
		var ls []string
		for _, g := range groups {
			ls = append(ls, g.overviewLine())
		}
		overview = "\n*確認推奨* (" + ThreadNotice + ")\n" + fitLines(ls, MaxTextRunes/2, "ほか %d 項目はスレッド")
	}
	footer := "\n" + ThreadNotice
	if s != nil {
		footer += "  |  " + LLMNotice
	}
	var urgent []textPiece
	for _, f := range top {
		urgent = append(urgent, textPiece{text: f.line(z), n: 1})
	}
	parent, left := fillText(headText, textSection("*まず対応*", urgent), joinNonEmpty(overview, footer), false)
	if len(left) == 0 && len(groups) == 0 {
		return "", nil
	}
	parent = clipLines(joinNonEmpty(parent, overview, footer), MaxTextRunes)

	var pieces []textPiece
	pieces = append(pieces, textSection("*まず対応 (続き)*", trimLeadingTitle(left))...)
	var detail []textPiece
	for _, g := range groups {
		if rl, ok := groupRules[g.key]; ok && len(g.fs) > 1 {
			detail = append(detail, textPiece{text: fmt.Sprintf("%s *%s* %d %s", sevEmoji(g.sev), rl.label, len(g.fs), rl.unit)})
		}
		for _, f := range g.fs {
			detail = append(detail, textPiece{text: f.line(z), n: 1})
		}
	}
	pieces = append(pieces, textSection("*確認推奨*", detail)...)
	pieces = append(pieces, llmTextPieces(s)...)
	pieces = append(pieces, minorTextPieces(in)...)
	foot := "\n全文: " + Escape(filepath.Join(in.Dir, ReportMD))
	var replies []string
	for k := 0; k < MaxThreadReplies && len(pieces) > 0; k++ {
		var body string
		body, pieces = fillText("", pieces, foot, k == MaxThreadReplies-1)
		if body = strings.TrimLeft(body, "\n"); body == "" {
			break
		}
		replies = append(replies, body)
	}
	if len(replies) == 0 {
		replies = []string{""}
	}
	last := len(replies) - 1
	if len(pieces) > 0 {
		n := 0
		for _, p := range pieces {
			n += p.n
		}
		replies[last] = joinNonEmpty(replies[last], textCut(n))
	}
	replies[last] = clipLines(joinNonEmpty(replies[last], foot), MaxTextRunes)
	return parent, replies
}

// trimLeadingTitle は 1 通目で切れた「まず対応」の続きから、先頭に付けた節の見出しを外す (続きの見出しを付け直すため)。
func trimLeadingTitle(left []textPiece) []textPiece {
	if len(left) == 0 {
		return nil
	}
	out := append([]textPiece(nil), left...)
	out[0].text = strings.TrimPrefix(out[0].text, "\n*まず対応*\n")
	return out
}

// llmTextPieces は LLM の text の契約のインシデント候補と approve の提案 (SummaryText と同じ書式)。
func llmTextPieces(s *Summary) []textPiece {
	if s == nil {
		return nil
	}
	var inc, sug []textPiece
	for _, x := range s.Incidents {
		inc = append(inc, textPiece{text: fmt.Sprintf("• %s: %s", Escape(strings.Join(x.FindingIDs, ", ")), Escape(clipRunes(oneLine(x.Summary), maxIncidentRunes)))})
	}
	for _, sg := range s.ApproveSuggestions {
		sug = append(sug, textPiece{text: fmt.Sprintf("• %s: %s\n    `arata approve %s --note \"...\"`", Escape(sg.FindingID), Escape(clipRunes(oneLine(sg.Reason), maxReasonRunes)), Escape(sg.FindingID))})
	}
	return append(textSection("*インシデント候補*", inc), textSection("*approve の提案* (提案のみ。aratam は approve しない。人が判断して実行する)", sug)...)
}

// minorTextPieces は優先度の低い一覧 (解消・未対応・本日報告済み・情報。今の text の本文にあるもの)。
func minorTextPieces(in *Input) []textPiece {
	list, _ := findingIndex(in)
	var out []textPiece
	for _, sec := range []struct{ diff, title string }{{"解消", "解消"}, {"未対応", "未対応"}, {"報告済み", "本日報告済み"}, {"情報", "情報"}} {
		var ps []textPiece
		for _, f := range list {
			if !f.required && f.diff == sec.diff {
				ps = append(ps, textPiece{text: f.line(in.Zone), n: 1})
			}
		}
		out = append(out, textSection(fmt.Sprintf("*%s (%d)*", sec.title, len(ps)), ps)...)
	}
	return out
}
