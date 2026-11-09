package notify

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CircleAround/arata/internal/report/schema"
)

// WAF の改善提案 (2 通目) の Block Kit (slack.format: blocks。ADR 0029)。
//
// 決定 (試験チャンネルで「文章が長く俯瞰しにくい」という意見を受けて):
//   - 提案 1 件 = 見出し (種類の日本語 + 主な数字)・なぜ困るか (規則の固定文 + 数字)・「→ 次の一手」の section と、根拠の context の 2 ブロック (表示は 4 行まで)。
//   - 「→」は「どこに (WebACL・ルール)・何を (パス・条件)・どうする」を具体的に書く (LLM の next、無ければ種類ごとのテンプレート。140 字まで)。
//   - 規則の長い summary・LLM の何を・なぜ・進め方・設定例は Slack に出さない。全文は入力ディレクトリの waf-proposals.md に書き出し、最後の context にパスを書く。
//   - LLM が Slack 用に書くのは「→」の 1 行 (Writeup.Next) だけ。候補に無いことを書かない・BLOCK に強めないの検査は書き起こし全体と同じ。
//   - COUNT のルールの状況は 1 ルール 1 行 (「`名前` 140 件・怪しい 100%・7/7 日」)。一致なしは「一致なし: `a` `b`」の 1 行にまとめる。

// ProposalsMD は提案の全文 (何を・なぜ・進め方・設定例) を書き出すファイル名 (入力ディレクトリの中)。
const ProposalsMD = "waf-proposals.md"

// CodeProposalsFileFailed は waf-proposals.md を書けなかったときのログの code (WARN。通知は続ける)。
const CodeProposalsFileFailed = "PROPOSALS_FILE_FAILED"

var proposalKindLabels = map[string]string{
	"false_positive":     "誤検知の疑い",
	"probe_allowed":      "探索パスが WAF を通過",
	"rate_limit_missing": "レート制限が無い",
	"rate_limit_loose":   "レート制限が緩い",
	"rate_limit_tight":   "レート制限が厳しい",
	"unused_rule":        "一致していないルール",
	// ADR 0028
	"challenge_on_app_path": "正規の画面に Challenge / CAPTCHA",
	"challenge_impact":      "Challenge / CAPTCHA の状況",
}

// aboutChallengeImpact は Challenge / CAPTCHA の状況 (observation の about。ADR 0028)。COUNT のルールの状況と同じく 1 ルール 1 行で出す。
const aboutChallengeImpact = "challenge_impact"

var observationReasonLabels = map[string]string{
	"below_threshold":    "閾値未満",
	"undetermined":       "判断できない",
	"excluded_by_config": "除外設定に一致",
	"excluded_by_rule":   "決まった除外に一致",
	"position_limit":     "数え漏れの可能性",
}

func kindLabel(kind string) string {
	if l, ok := proposalKindLabels[kind]; ok {
		return l
	}
	return kind
}

// evNum は evidence の数値 (無ければ空)。
func evNum(p schema.Proposal, key string) string {
	if v, ok := p.Evidence[key].(float64); ok {
		return fmt.Sprintf("%g", v)
	}
	return ""
}

func ruleName(p schema.Proposal) string {
	if p.RuleInGroup != "" {
		return p.RuleInGroup
	}
	return p.Rule
}

// joinNonEmptyWith は空でないものを sep でつなぐ。
func joinNonEmptyWith(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func withUnit(v, format string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf(format, v)
}

// proposalNumbers は見出しの「— 」の後の主な数字 (mrkdwn。値はエスケープ済み) と、根拠の context の 1 行。
func proposalNumbers(kind string, p schema.Proposal) (head, basis string) {
	days := evNum(p, "days")
	switch kind {
	case "false_positive":
		target := code(ruleName(p))
		if p.Path != "" {
			target += " が " + Escape(oneLine(p.Method+" "+p.Path)) + " で"
		}
		head = joinNonEmptyWith(" ", target, withUnit(evNum(p, "count"), "%s 件")+withUnit(days, " / %s 日"))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "distinct_ips_max_per_day"), "IP 最大 %s/日"),
			withUnit(evNum(p, "matching_days"), "一致した日 %s")+withUnit(days, "/%s 日"), withUnit(Escape(oneLine(p.WebACL)), "ACL %s"))
	case "probe_allowed":
		paths, _ := p.Evidence["paths"].([]any)
		head = joinNonEmptyWith("・", withUnit(evNum(p, "count"), "%s 件")+withUnit(days, " / %s 日"), withUnit(fmt.Sprint(len(paths)), "%s パス"))
		var ps []string
		for i, x := range paths {
			if i == maxListItems {
				ps = append(ps, fmt.Sprintf("ほか %d", len(paths)-maxListItems))
				break
			}
			ps = append(ps, Escape(oneLine(pathCount.ReplaceAllString(fmt.Sprint(x), " $1"))))
		}
		basis = strings.Join(ps, "・")
	case "rate_limit_missing":
		head = joinNonEmptyWith(" ", code(fmt.Sprint(p.Evidence["path_group"]))+" で", withUnit(evNum(p, "max_per_5min"), "1 IP 最大 %s 件 / 5 分"))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "p99_per_5min"), "p99 %s"), withUnit(evNum(p, "proposed_limit"), "提案 limit %s / 5 分"), withUnit(days, "%s 日の観測"))
	case "rate_limit_loose", "rate_limit_tight":
		head = joinNonEmptyWith("・", joinNonEmptyWith(" ", code(ruleName(p)), withUnit(evNum(p, "current_limit_per_5min"), "limit %s / 5 分")),
			withUnit(evNum(p, "max_per_5min"), "観測の最大 %s"))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "p99_per_5min"), "p99 %s"), withUnit(evNum(p, "proposed_limit"), "提案 limit %s"),
			withUnit(Escape(oneLine(fmt.Sprint(p.Evidence["path_group"]))), "パスの群 %s"))
	case "challenge_on_app_path":
		target := code(ruleName(p))
		if p.Path != "" {
			target += " が " + Escape(oneLine(p.Method+" "+p.Path)) + " で"
		}
		head = joinNonEmptyWith("・", joinNonEmptyWith(" ", target, challengeKind(p)+withUnit(evNum(p, "issued"), " %s 件")+withUnit(days, " / %s 日")), solveRatio(p))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "distinct_ips_max_per_day"), "IP 最大 %s/日"), withUnit(Escape(oneLine(p.WebACL)), "ACL %s"))
	case aboutChallengeImpact:
		head = joinNonEmptyWith("・", code(ruleName(p))+" "+challengeKind(p)+withUnit(evNum(p, "issued"), " %s 件"), solveRatio(p),
			withUnit(evNum(p, "issued_non_get"), "GET 以外 %s"))
		paths, _ := p.Evidence["paths"].([]any)
		var ps []string
		for i, x := range paths {
			if i == maxListItems {
				ps = append(ps, fmt.Sprintf("ほか %d", len(paths)-maxListItems))
				break
			}
			ps = append(ps, Escape(oneLine(fmt.Sprint(x))))
		}
		basis = strings.Join(ps, "・")
	case "unused_rule":
		head = joinNonEmptyWith(" ", code(ruleName(p)), withUnit(evNum(p, "days_without_match"), "%s 日一致なし"))
		action, _ := p.Evidence["action"].(string)
		basis = withUnit(Escape(action), "action %s")
	default:
		basis = evidenceText(p)
	}
	return head, basis
}

// challengeKind は evidence の kind (challenge / captcha) の表示。
func challengeKind(p schema.Proposal) string {
	switch k, _ := p.Evidence["kind"].(string); strings.ToLower(k) {
	case "challenge":
		return "Challenge"
	case "captcha":
		return "CAPTCHA"
	case "":
		return "Challenge / CAPTCHA"
	default:
		return Escape(k)
	}
}

// solveRatio は「解かれた 80%」(無ければ空)。
func solveRatio(p schema.Proposal) string {
	if v, ok := p.Evidence["solve_ratio"].(float64); ok {
		return fmt.Sprintf("解かれた %.0f%%", v*100)
	}
	return ""
}

var pathCount = regexp.MustCompile(`\s*\((\d+) 件\)$`)

// maxProposalNextRunes は提案の「→」の上限 (rune 数)。
// 決定: 80 字では「どこに・何を・どうする」が抜けて具体性がなくなった (試験チャンネルでの意見) ので 140 字にする。
const maxProposalNextRunes = 140

// probePaths は probe_allowed の上位のパス (件数を除いて `code` に。3 個まで) と、パスの総数。
func probePaths(p schema.Proposal) ([]string, int) {
	paths, _ := p.Evidence["paths"].([]any)
	var out []string
	for i, x := range paths {
		if i == maxListItems {
			break
		}
		out = append(out, code(pathCount.ReplaceAllString(fmt.Sprint(x), "")))
	}
	return out, len(paths)
}

func evStr(p schema.Proposal, key string) string {
	if v, ok := p.Evidence[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// ruleNext は「→」の規則の文言 (provider: none と、LLM が書かなかった・捨てた候補)。
// 決定: 種類ごとのテンプレートに evidence の値を埋め込み、「どこに (WebACL・ルール)・何を (パス・条件)・どうする (COUNT で何日・何を見る / 対象から外す)」を必ず書く。
// BLOCK に強める書き方はしない (ADR 0023)。
func ruleNext(p schema.Proposal) string {
	acl := "WebACL " + code(p.WebACL)
	limit := evNum(p, "proposed_limit")
	target := code(strings.TrimSpace(p.Method + " " + p.Path))
	switch p.Kind {
	case "false_positive":
		return fmt.Sprintf("%s のルール %s を、%s に限って COUNT にする (RuleActionOverrides か scope-down)。1〜2 週間、この画面の一致が正規の通信かを見る",
			acl, code(ruleName(p)), target)
	case "probe_allowed":
		ps, n := probePaths(p)
		paths := strings.Join(ps, "・")
		if n > len(ps) {
			paths += fmt.Sprintf(" など %d パス", n)
		}
		return fmt.Sprintf("%s に、%s を URI で照合するルールを COUNT で追加し、1〜2 週間、正規の通信が一致しないかを見る", acl, paths)
	case "rate_limit_missing":
		return fmt.Sprintf("%s に、%s を対象とする limit %s / 5 分 (IP 単位) のレートベースのルールを COUNT で追加し、1〜2 週間、正規の利用者が当たらないかを見る",
			acl, code(evStr(p, "path_group")), Escape(limit))
	case "rate_limit_loose", "rate_limit_tight":
		return fmt.Sprintf("%s のルール %s の limit を %s から %s / 5 分に変えるかを、%s の観測 (最大 %s・p99 %s) と照らして見直す",
			acl, code(ruleName(p)), Escape(evNum(p, "current_limit_per_5min")), Escape(limit), code(evStr(p, "path_group")),
			Escape(evNum(p, "max_per_5min")), Escape(evNum(p, "p99_per_5min")))
	case "unused_rule":
		return fmt.Sprintf("%s のルール %s が何を守るためのものかを確かめ、残す理由を記録する (削除は勧めない)", acl, code(ruleName(p)))
	case "challenge_on_app_path":
		return fmt.Sprintf("ルール %s の対象から %s を外す (scope-down) か、条件を Accept-Language などで絞る", code(ruleName(p)), target)
	}
	if s, ok := stageLabels[p.Stage]; ok {
		return acl + " で " + s
	}
	return acl + " を人が見直す"
}

// proposalWhy は「なぜ困るか」の 1 行 (種類ごとの固定文 + 数字。規則)。種類が対応表に無ければ空。
func proposalWhy(p schema.Proposal) string {
	days := evNum(p, "days")
	switch p.Kind {
	case "false_positive":
		return "正規の画面らしい通信が BLOCK されている" + withUnit(joinNonEmptyWith("・", withUnit(days, "%s 日で ")+withUnit(evNum(p, "count"), "%s 件"),
			withUnit(evNum(p, "distinct_ips_max_per_day"), "IP 最大 %s/日")), " (%s)")
	case "probe_allowed":
		return "設定ファイルや管理画面を探す通信が WAF を素通りしている" + withUnit(withUnit(days, "%s 日で ")+withUnit(evNum(p, "count"), "%s 件"), " (%s)")
	case "rate_limit_missing":
		return "1 IP の大量アクセスを止めるルールが無い" + withUnit(evNum(p, "max_per_5min"), " (最大 %s 件 / 5 分)")
	case "rate_limit_loose":
		return "limit が観測よりずっと高く、大量アクセスを止められない" + withUnit(joinNonEmptyWith("・", withUnit(evNum(p, "current_limit_per_5min"), "limit %s"), withUnit(evNum(p, "max_per_5min"), "最大 %s")), " (%s)")
	case "rate_limit_tight":
		return "limit が観測に近く、正規の利用者が止められるおそれがある" + withUnit(joinNonEmptyWith("・", withUnit(evNum(p, "current_limit_per_5min"), "limit %s"), withUnit(evNum(p, "max_per_5min"), "最大 %s")), " (%s)")
	case "unused_rule":
		return "役割が分からないまま残っているルールの可能性がある" + withUnit(evNum(p, "days_without_match"), " (%s 日一致なし)")
	case "challenge_on_app_path":
		return "正規の画面で多くの人が " + challengeKind(p) + " を解かされている" + withUnit(solveRatio(p), " (%s)")
	}
	return ""
}

// observationShortLines は観察と COUNT のルールの状況の短い行 (合わせて maxObservationLines まで)。
func observationShortLines(obs, status []schema.Proposal) []string {
	var lines []string
	n, shown := len(obs)+len(status), 0
	var challenge []schema.Proposal
	var others []schema.Proposal
	for _, p := range obs {
		if p.About == aboutChallengeImpact {
			challenge = append(challenge, p)
		} else {
			others = append(others, p)
		}
	}
	obs = others
	if len(obs) > 0 {
		lines = append(lines, "*観察* (提案はしないが気づいたこと)")
		for _, p := range obs {
			if shown == maxObservationLines {
				break
			}
			head, _ := proposalNumbers(p.About, p)
			reason := observationReasonLabels[p.Reason]
			if reason == "" {
				reason = p.Reason
			}
			lines = append(lines, fmt.Sprintf("• %s (%s)%s", Escape(kindLabel(p.About)), Escape(reason), withUnit(head, " — %s")))
			shown++
		}
	}
	if len(challenge) > 0 && shown < maxObservationLines {
		lines = append(lines, "*Challenge / CAPTCHA* (提案ではない。解かれた割合は解釈せず数字だけ)")
		for _, p := range challenge {
			if shown == maxObservationLines {
				break
			}
			head, _ := proposalNumbers(aboutChallengeImpact, p)
			lines = append(lines, "• "+head)
			shown++
		}
	}
	if len(status) > 0 && shown < maxObservationLines {
		lines = append(lines, "*COUNT のルール* (提案ではない。BLOCK への切り替えは人が計画して決める)")
		var none []string
		for _, p := range status {
			if evNum(p, "matches") == "0" {
				none = append(none, code(ruleName(p)))
				shown++
				continue
			}
			if shown == maxObservationLines {
				continue
			}
			ratio := ""
			if v, ok := p.Evidence["suspect_ratio"].(float64); ok {
				ratio = fmt.Sprintf("怪しい %.0f%%", v*100)
			}
			lines = append(lines, "• "+joinNonEmptyWith("・", code(ruleName(p))+withUnit(evNum(p, "matches"), " %s 件"), ratio,
				withUnit(evNum(p, "matching_days"), "%s")+withUnit(evNum(p, "days"), "/%s 日")))
			shown++
		}
		if len(none) > 0 {
			lines = append(lines, "• 一致なし: "+strings.Join(none, " "))
		}
	}
	if n > shown {
		lines = append(lines, fmt.Sprintf("ほか %d 件は %s", n-shown, ProposalsMD))
	}
	return lines
}

// ProposalsBlocks は WAF の改善提案 (2 通目) の Block Kit。file は waf-proposals.md のパス (書けなかったら空。report.md を案内する)。
func ProposalsBlocks(in *Input, warnings []string, writeups map[string]Writeup, notice, file string) Message {
	if in.Run == nil || len(in.Run.Proposals) == 0 {
		return Message{}
	}
	props, obs, status := splitProposals(in.Run.Proposals)
	var head []Block
	head = append(head, topSection(RouteNormal, Rules{}, notice, warnings)...)
	head = append(head,
		headerBlock("🛡️ WAF の改善提案 — "+in.Run.Name),
		contextBlock(fmt.Sprintf("%s ・ 提案 %d 件 ・ 観察 %d 件", Escape(windowText(in)), len(props), len(obs)+len(status)),
			"arata の規則による候補です。適用は人が判断します (aratam は WAF の設定を変えません)"))
	detail := "設定例と詳しい説明: " + code(file)
	if file == "" {
		detail = "詳しい説明: " + code(filepath.Join(in.Dir, ReportMD))
	}
	guide := "対処手順: `arata help ai playbook waf_review`"
	if len(writeups) > 0 {
		guide += "  |  " + LLMNotice
	}
	tail := []Block{contextBlock(detail, guide)}
	var obsBlocks []Block
	if ls := observationShortLines(obs, status); len(ls) > 0 {
		obsBlocks = []Block{dividerBlock(), sectionBlock(strings.Join(ls, "\n"))}
	}
	budget := MaxBlocks - len(head) - len(tail) - len(obsBlocks)
	body := []Block{dividerBlock()}
	if len(props) == 0 {
		body = append(body, sectionBlock("提案はありません。"))
	}
	for i, p := range props {
		nums, basis := proposalNumbers(p.Kind, p)
		next := ruleNext(p)
		if w, ok := writeups[proposalID(i)]; ok && oneLine(w.Next) != "" {
			next = Escape(clipRunes(strings.TrimPrefix(oneLine(w.Next), "→ "), maxProposalNextRunes))
		}
		lines := []string{fmt.Sprintf("🛡️ *%s*%s", Escape(kindLabel(p.Kind)), withUnit(nums, " — %s"))}
		if why := proposalWhy(p); why != "" {
			lines = append(lines, why)
		}
		lines = append(lines, "→ "+next)
		bs := []Block{sectionBlock(strings.Join(lines, "\n"))}
		if basis != "" {
			bs = append(bs, contextBlock(basis))
		}
		if len(body)+len(bs)+1 > budget {
			body = append(body, sectionBlock(fmt.Sprintf("ほか %d 件の提案は %s", len(props)-i, ProposalsMD)))
			break
		}
		body = append(body, bs...)
	}
	blocks := append(append(append(head, body...), obsBlocks...), tail...)
	return Message{Text: clipRunes(Escape(fmt.Sprintf("%s: WAF の改善提案 %d 件 (観察 %d 件)", title(in), len(props), len(obs)+len(status))), maxNotifyRunes), Blocks: blocks}
}

// ProposalsMarkdown は waf-proposals.md の中身 (提案ごとの概要・根拠・次の一手・何を・なぜ・進め方・設定例の全文。Markdown なのでエスケープしない)。
func ProposalsMarkdown(in *Input, writeups map[string]Writeup, notice string) string {
	props, obs, status := splitProposals(in.Run.Proposals)
	var b strings.Builder
	fmt.Fprintf(&b, "# WAF の改善提案 (%s)\n\n", title(in))
	fmt.Fprintf(&b, "- 期間: %s\n- run: %s\n- arata が規則で作った候補です。適用するかは人が判断します (aratam は WAF の設定を変えません)。\n", period(in), in.Run.RunID)
	if notice != "" {
		fmt.Fprintf(&b, "- %s\n", notice)
	}
	for i, p := range props {
		stage := stageLabels[p.Stage]
		if stage == "" {
			stage = p.Stage
		}
		fmt.Fprintf(&b, "\n## %s. %s (%s)\n\n", proposalID(i), kindLabel(p.Kind), stage)
		fmt.Fprintf(&b, "- 種類: %s\n- 対象: %s\n- 概要: %s\n", p.Kind, oneLine(joinNonEmptyWith(" / ", p.WebACL, p.Rule, p.RuleInGroup, strings.TrimSpace(p.Method+" "+p.Path))), oneLine(p.Summary))
		fmt.Fprintf(&b, "- 根拠: %s\n", rawEvidence(p))
		w, ok := writeups[proposalID(i)]
		next := ""
		if ok {
			next = oneLine(w.Next)
		}
		if next == "" {
			next = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&").Replace(ruleNext(p))
		}
		if why := proposalWhy(p); why != "" {
			fmt.Fprintf(&b, "- なぜ困るか: %s\n", strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&").Replace(why))
		}
		fmt.Fprintf(&b, "- 次の一手: %s\n", next)
		if !ok {
			continue
		}
		for _, f := range []struct{ label, v string }{{"何を", w.What}, {"なぜ", w.Why}, {"進め方", w.How}} {
			if v := oneLine(f.v); v != "" {
				fmt.Fprintf(&b, "- %s: %s\n", f.label, v)
			}
		}
		if ex := strings.Trim(w.Example, "\n"); strings.TrimSpace(ex) != "" {
			fmt.Fprintf(&b, "\n設定例:\n\n```\n%s\n```\n", ex)
		}
	}
	if len(obs) > 0 {
		b.WriteString("\n## 観察 (提案はしないが気づいたこと)\n\n")
		for _, p := range obs {
			fmt.Fprintf(&b, "- [%s / %s] %s\n", p.About, p.Reason, oneLine(p.Summary))
		}
	}
	if len(status) > 0 {
		b.WriteString("\n## COUNT のルールの状況 (提案ではない。COUNT → BLOCK の切り替えは人が計画して決める)\n\n")
		for _, p := range status {
			fmt.Fprintf(&b, "- %s\n", oneLine(p.Summary))
		}
	}
	return b.String()
}

// rawEvidence は evidence の主なキー (エスケープしない。Markdown 用)。
func rawEvidence(p schema.Proposal) string {
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&").Replace(evidenceText(p))
}

// writeProposalsFile は waf-proposals.md を書く (一時ファイルから置き換え。権限は .aratam-notified と同じ 0640)。
func writeProposalsFile(dir, body string) (string, error) {
	path := filepath.Join(dir, ProposalsMD)
	tmp, err := os.CreateTemp(dir, ProposalsMD+".tmp-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return path, nil
}
