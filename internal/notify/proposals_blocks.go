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
//   - 提案 1 件 = 見出し (種類の日本語 + 主な数字) と「→ 次の一手」の section、根拠の context の 2 ブロック (表示は 3 行)。
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
			target += " が " + Escape(strings.TrimSpace(p.Method+" "+p.Path)) + " で"
		}
		head = joinNonEmptyWith(" ", target, withUnit(evNum(p, "count"), "%s 件")+withUnit(days, " / %s 日"))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "distinct_ips_max_per_day"), "IP 最大 %s/日"),
			withUnit(evNum(p, "matching_days"), "一致した日 %s")+withUnit(days, "/%s 日"), withUnit(Escape(p.WebACL), "ACL %s"))
	case "probe_allowed":
		paths, _ := p.Evidence["paths"].([]any)
		head = joinNonEmptyWith("・", withUnit(evNum(p, "count"), "%s 件")+withUnit(days, " / %s 日"), withUnit(fmt.Sprint(len(paths)), "%s パス"))
		var ps []string
		for i, x := range paths {
			if i == maxListItems {
				ps = append(ps, fmt.Sprintf("ほか %d", len(paths)-maxListItems))
				break
			}
			ps = append(ps, Escape(pathCount.ReplaceAllString(fmt.Sprint(x), " $1")))
		}
		basis = strings.Join(ps, "・")
	case "rate_limit_missing":
		head = joinNonEmptyWith(" ", code(fmt.Sprint(p.Evidence["path_group"]))+" で", withUnit(evNum(p, "max_per_5min"), "1 IP 最大 %s 件 / 5 分"))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "p99_per_5min"), "p99 %s"), withUnit(evNum(p, "proposed_limit"), "提案 limit %s / 5 分"), withUnit(days, "%s 日の観測"))
	case "rate_limit_loose", "rate_limit_tight":
		head = joinNonEmptyWith("・", joinNonEmptyWith(" ", code(ruleName(p)), withUnit(evNum(p, "current_limit_per_5min"), "limit %s / 5 分")),
			withUnit(evNum(p, "max_per_5min"), "観測の最大 %s"))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "p99_per_5min"), "p99 %s"), withUnit(evNum(p, "proposed_limit"), "提案 limit %s"),
			withUnit(Escape(fmt.Sprint(p.Evidence["path_group"])), "パスの群 %s"))
	case "challenge_on_app_path":
		target := code(ruleName(p))
		if p.Path != "" {
			target += " が " + Escape(strings.TrimSpace(p.Method+" "+p.Path)) + " で"
		}
		head = joinNonEmptyWith("・", joinNonEmptyWith(" ", target, challengeKind(p)+withUnit(evNum(p, "issued"), " %s 件")+withUnit(days, " / %s 日")), solveRatio(p))
		basis = joinNonEmptyWith("・", withUnit(evNum(p, "distinct_ips_max_per_day"), "IP 最大 %s/日"), withUnit(Escape(p.WebACL), "ACL %s"))
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
			ps = append(ps, Escape(fmt.Sprint(x)))
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

// ruleNext は「→」の規則の文言 (provider: none と、LLM が書かなかった・捨てた候補)。
func ruleNext(p schema.Proposal) string {
	limit := evNum(p, "proposed_limit")
	switch p.Kind {
	case "false_positive":
		return "このパスだけ " + code(ruleName(p)) + " を COUNT にして様子を見る"
	case "probe_allowed":
		return "探索パスのルールを COUNT で追加して様子を見る"
	case "rate_limit_missing":
		return "limit " + Escape(limit) + " のレートベースのルールを COUNT で足して様子を見る"
	case "rate_limit_loose", "rate_limit_tight":
		return "limit " + Escape(limit) + " への見直しを検討する"
	case "unused_rule":
		return "残す理由を確かめる (削除は勧めない)"
	case "challenge_on_app_path":
		return "このパスを " + code(ruleName(p)) + " の対象から外す (scope-down) か条件を絞る"
	}
	if s, ok := stageLabels[p.Stage]; ok {
		return s
	}
	return "人が見直す"
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
	tail := []Block{contextBlock(detail, "対処手順: `arata help ai playbook waf_review`")}
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
			next = Escape(clipRunes(strings.TrimPrefix(oneLine(w.Next), "→ "), maxActionRunes))
		}
		bs := []Block{sectionBlock(fmt.Sprintf("🛡️ *%s*%s\n→ %s", Escape(kindLabel(p.Kind)), withUnit(nums, " — %s"), next))}
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
	return Message{Text: Escape(fmt.Sprintf("%s: WAF の改善提案 %d 件 (観察 %d 件)", title(in), len(props), len(obs)+len(status))), Blocks: blocks}
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
		fmt.Fprintf(&b, "- 種類: %s\n- 対象: %s\n- 概要: %s\n", p.Kind, joinNonEmptyWith(" / ", p.WebACL, p.Rule, p.RuleInGroup, strings.TrimSpace(p.Method+" "+p.Path)), oneLine(p.Summary))
		fmt.Fprintf(&b, "- 根拠: %s\n", rawEvidence(p))
		w, ok := writeups[proposalID(i)]
		next := ""
		if ok {
			next = oneLine(w.Next)
		}
		if next == "" {
			next = strings.ReplaceAll(ruleNext(p), "`", "")
			next = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&").Replace(next)
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
