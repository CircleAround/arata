package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/report/schema"
)

// Summary は LLM に求める出力 (aratam 設計書 3 章)。
type Summary struct {
	Headline           string       `json:"headline"`
	Items              []Item       `json:"items"`
	Incidents          []Incident   `json:"incidents"`
	ApproveSuggestions []Suggestion `json:"approve_suggestions"`
	// Rejected は検査で捨てた項目の理由 (ログ用。内容は書かない)。
	Rejected []string `json:"-"`
}

// Item は finding 1 件の分類と説明。
type Item struct {
	FindingID string `json:"finding_id"`
	Class     string `json:"class"` // action | confirm | info
	Reason    string `json:"reason"`
}

// Incident は同じ主体・同じ時間帯の finding をまとめた見立て。
type Incident struct {
	FindingIDs []string `json:"finding_ids"`
	Summary    string   `json:"summary"`
}

// Suggestion は approve の提案 (表示するだけで、aratam は approve しない)。
type Suggestion struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
}

// 分類 (arata 設計書 9-1 の「要対処 / 確認依頼 / 情報」)。
var classes = []struct{ key, label string }{{"action", "要対処"}, {"confirm", "確認依頼"}, {"info", "情報"}}

// findingRef は report.json の finding 1 件 (表示に使う値は LLM の出力ではなくこちらから取る)。
type findingRef struct {
	id, check, key, severity, summary, diff string
	required                                bool            // new / changed / recurred (LLM の出力から漏れたら規則で足す)
	finding                                 *schema.Finding // data を持つもの (期間レポートの events は持たない)
}

// findingIndex は report.json の finding を出現順に並べる。
func findingIndex(in *Input) ([]findingRef, map[string]findingRef) {
	var list []findingRef
	add := func(diff string, required bool, fs []schema.Finding) {
		for i := range fs {
			f := &fs[i]
			list = append(list, findingRef{id: f.ID, check: f.Check, key: f.Key, severity: f.Severity, summary: f.Summary, diff: diff, required: required, finding: f})
		}
	}
	addEvents := func(diff string, required bool, es []schema.EventRow) {
		for _, e := range es {
			list = append(list, findingRef{id: e.FindingID, check: e.Check, key: e.Key, severity: e.Severity, summary: e.Summary, diff: diff, required: required})
		}
	}
	if r := in.Run; r != nil {
		add("新規", true, r.Findings.New)
		add("変化", true, r.Findings.Changed)
		add("再発", true, r.Findings.Recurred)
		add("解消", false, r.Findings.Resolved)
		add("未対応", false, r.Findings.StillOpen)
		add("報告済み", false, r.AlreadyReported)
		add("情報", false, r.Info)
	} else {
		p := in.Period
		addEvents("新規", true, p.Events.New)
		addEvents("変化", true, p.Events.Changed)
		addEvents("再発", true, p.Events.Recurred)
		addEvents("解消", false, p.Events.Resolved)
		add("未対応", false, p.Open)
	}
	byID := map[string]findingRef{}
	var uniq []findingRef
	for _, f := range list {
		if old, ok := byID[f.id]; ok {
			// 期間レポートでは同じ finding が新規と解消の両方に出ることがある。必須の方を残す
			if f.required && !old.required {
				byID[f.id] = f
			}
			continue
		}
		byID[f.id] = f
		uniq = append(uniq, f)
	}
	for i, f := range uniq {
		uniq[i] = byID[f.id]
	}
	return uniq, byID
}

// ParseSummary は LLM の出力を検証する。形が合わなければエラー (report.md の送信に切り替える)。
//
// 決定:
//   - 出力は JSON のオブジェクト 1 つ。前後の文やコードフェンス (```json) が付いていたら、最初の { から最後の } までを取り出す。
//   - headline が空ならエラー。
//   - report.json に無い finding_id は捨てる (LLM が作った ID を表示しない)。class が action / confirm / info 以外の item も捨てる
//     (捨てた finding が new / changed / recurred なら、規則で組み立てた行として末尾に足される)。同じ finding_id の 2 件目以降も捨てる。
//   - incidents は知らない ID を除き、ID が残らなければ捨てる。approve_suggestions も知らない ID のものを捨てる。
//
// 決定 (ADR 0037): LLM は攻撃者の文に従い得る前提で、規則で次を固定する。
//   - 自由文 (rejectLLMText) に URL・メンション・BLOCK に強める記述があれば、その項目を捨てる (finding は規則の行に戻る)。headline ならエラー。
//   - new / changed / recurred で urgent 以上の finding は info にさせない (confirm に上げ、理由は捨てる)。
//   - urgent 以上の finding への approve の提案は捨てる (approve は主体を以後報告しなくなるので、誘導されたときの被害が最も大きい)。
//
// 決定 (ADR 0041。ファズで見つけた): LLM が任意に増やせる節で本文を埋めさせない。
//   - incidents は maxIncidents 件まで。1 件の中の同じ finding_id は 1 つにする。
//   - approve_suggestions は finding 1 件につき 1 つ (2 件目以降は捨てる)。
//
// 決定 (account_only.go): 主体がアカウントしか分からない finding をルートユーザーの利用と書いた文は、ARN を置き換え、root の語が残れば捨てる。
func ParseSummary(raw []byte, in *Input, urgent string) (*Summary, error) {
	b := bytes.TrimSpace(raw)
	if i, j := bytes.IndexByte(b, '{'), bytes.LastIndexByte(b, '}'); i >= 0 && j > i {
		b = b[i : j+1]
	}
	var s Summary
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("llm output is not the expected JSON: %w", err)
	}
	if strings.TrimSpace(s.Headline) == "" {
		return nil, errors.New("llm output has no headline")
	}
	if why := rejectLLMText(s.Headline); why != "" {
		return nil, fmt.Errorf("llm headline rejected: %s", why)
	}
	all, byID := findingIndex(in)
	// 決定 (account_only.go): アカウントしか分からない主体をルートユーザーと書いた文は直すか捨てる
	var why string
	if s.Headline, why = newRootGuard(all...).apply(s.Headline, false); why != "" {
		return nil, fmt.Errorf("llm headline rejected: %s", why)
	}
	seen := map[string]bool{}
	items := []Item{}
	for _, it := range s.Items {
		if _, ok := byID[it.FindingID]; !ok || seen[it.FindingID] || classLabel(it.Class) == "" {
			continue
		}
		if why := rejectLLMText(it.Reason); why != "" {
			s.Rejected = append(s.Rejected, it.FindingID+": "+why)
			continue
		}
		if it.Reason, why = newRootGuard(byID[it.FindingID]).apply(it.Reason, true); why != "" {
			s.Rejected = append(s.Rejected, it.FindingID+": "+why)
			continue
		}
		seen[it.FindingID] = true
		if f := byID[it.FindingID]; it.Class == "info" && f.required && atLeast(f.severity, urgent) {
			it.Class, it.Reason = "confirm", ""
			s.Rejected = append(s.Rejected, it.FindingID+": info is not allowed at this severity")
		}
		items = append(items, it)
	}
	s.Items = items
	incidents := []Incident{}
	for _, inc := range s.Incidents {
		if why := rejectLLMText(inc.Summary); why != "" {
			s.Rejected = append(s.Rejected, "incident: "+why)
			continue
		}
		var ids []string
		var refs []findingRef
		inIncident := map[string]bool{}
		for _, id := range inc.FindingIDs {
			if f, ok := byID[id]; ok && !inIncident[id] {
				inIncident[id] = true
				ids = append(ids, id)
				refs = append(refs, f)
			}
		}
		if len(ids) == 0 {
			continue
		}
		if inc.Summary, why = newRootGuard(refs...).apply(inc.Summary, true); why != "" {
			s.Rejected = append(s.Rejected, "incident: "+why)
			continue
		}
		if len(incidents) == maxIncidents {
			s.Rejected = append(s.Rejected, "incident: too many")
			break
		}
		inc.FindingIDs = ids
		incidents = append(incidents, inc)
	}
	s.Incidents = incidents
	sugs := []Suggestion{}
	suggested := map[string]bool{}
	for _, sg := range s.ApproveSuggestions {
		f, ok := byID[sg.FindingID]
		if !ok || suggested[sg.FindingID] {
			continue
		}
		if why := rejectLLMText(sg.Reason); why != "" {
			s.Rejected = append(s.Rejected, sg.FindingID+": "+why)
			continue
		}
		if sg.Reason, why = newRootGuard(f).apply(sg.Reason, true); why != "" {
			s.Rejected = append(s.Rejected, sg.FindingID+": "+why)
			continue
		}
		if !atLeast(f.severity, urgent) {
			suggested[sg.FindingID] = true
			sugs = append(sugs, sg)
		}
	}
	s.ApproveSuggestions = sugs
	return &s, nil
}

// atLeast は severity が urgent 以上か。
func atLeast(severity, urgent string) bool { return severityRank[severity] >= severityRank[urgent] }

func classLabel(c string) string {
	for _, x := range classes {
		if x.key == c {
			return x.label
		}
	}
	return ""
}

// Missing は new / changed / recurred のうち、LLM の items に無い finding (report.json の順)。
func (s *Summary) Missing(in *Input) []findingRef {
	list, _ := findingIndex(in)
	has := map[string]bool{}
	for _, it := range s.Items {
		has[it.FindingID] = true
	}
	var out []findingRef
	for _, f := range list {
		if f.required && !has[f.id] {
			out = append(out, f)
		}
	}
	return out
}

// line は finding 1 件の行。重大度・概要・チェック名・主要キー・id は report.json の値を使う (LLM に重大度を変えさせない。id も LLM の出力から取らない)。
func (f findingRef) line() string {
	l := fmt.Sprintf("• *[%s]* %s `%s` (%s)", Escape(f.severity), Escape(oneLine(f.summary)), Escape(f.check), f.diff)
	if f.finding != nil {
		return withDetail(l, detail(*f.finding))
	}
	return withDetail(l, idTag(f.id)) // 期間レポートの events は data を持たない
}

// maxIncidents はインシデント候補の上限。finding の数に依らず LLM が増やせる唯一の節なので、件数を規則で止める。
const maxIncidents = 10

// maxKeptLLMRunes は、本文が上限に収まらないときにも必ず残すインシデント候補と approve の提案の長さ (本文の上限の 2 割ほど)。
const maxKeptLLMRunes = 800

// LLM の文字列の上限 (文字数 = rune 数。バイト数ではない)。system でも短く書くよう指示しているが、守られなくても書式を崩さないよう組み立て側で切る。
const (
	maxReasonRunes   = 200
	maxIncidentRunes = 240
)

// 理由文の削り方 (切り詰めの段階)。
const (
	trimNone        = iota
	trimInfoReason  // 情報の理由文を削る
	trimInfoItems   // 情報を件数だけにする
	trimConfirmText // 確認依頼の理由文を削る
)

// SummaryText は LLM の要約を決まった書式で組み立てる。
// 件数・取れなかったソース・漏れた finding は規則で書く。
// 決定: 3,800 文字に収まらなければ、情報の理由文 → 情報の行 (件数だけ残す) → 確認依頼の理由文 の順に削る。
// 見出し・要対処・インシデント候補・承認の提案・漏れた finding・取れなかったものは削らない。
//
// 決定 (ADR 0041。ファズで見つけた): それでも収まらなければ、緊急の finding と取れなかったものを先に並べ直して、後ろから行の境目で切る。
// 並びは、漏れた finding のうち urgent 以上 → 取れなかったもの → 分類 (urgent 以上を要対処の先頭に。ADR 0037) → 残りの漏れた finding。
// インシデント候補と approve の提案は、合わせて maxKeptLLMRunes 文字までなら以前と同じく必ず残し、超えるなら最後に回して切る。
// 以前は長さに依らず残していたので、LLM がこの節を増やすと規則の行 (緊急の finding) の方が押し出され、本文も上限を超えた。
// 全文の案内と LLM の注記は必ず残す。
func SummaryText(in *Input, d Decision, r Rules, warnings []string, s *Summary) string {
	_, byID := findingIndex(in)
	lines := head(d.Route, r, "", warnings)
	lines = append(lines, "*"+Escape(title(in))+"* "+Escape(period(in)), counts(in), Escape(clipRunes(oneLine(s.Headline), maxReasonRunes)))
	headText := strings.Join(lines, "\n")

	var llmTail []string
	if len(s.Incidents) > 0 {
		llmTail = append(llmTail, "", "*インシデント候補*")
		for _, inc := range s.Incidents {
			llmTail = append(llmTail, fmt.Sprintf("• %s: %s", Escape(strings.Join(inc.FindingIDs, ", ")), Escape(clipRunes(oneLine(inc.Summary), maxIncidentRunes))))
		}
	}
	if len(s.ApproveSuggestions) > 0 {
		llmTail = append(llmTail, "", "*approve の提案* (提案のみ。aratam は approve しない。人が判断して実行する)")
		for _, sg := range s.ApproveSuggestions {
			llmTail = append(llmTail, fmt.Sprintf("• %s: %s\n    `arata approve %s --note \"...\"`", Escape(sg.FindingID), Escape(clipRunes(oneLine(sg.Reason), maxReasonRunes)), Escape(sg.FindingID)))
		}
	}
	miss := s.Missing(in)
	missing := func(fs []findingRef) string {
		if len(fs) == 0 {
			return ""
		}
		out := []string{"", "*要約に含まれていなかった指摘* (規則で追加)"}
		for _, f := range fs {
			out = append(out, f.line())
		}
		return strings.Join(out, "\n")
	}
	llmText, coverage := strings.Join(llmTail, "\n"), strings.Join(coverageLines(in), "\n")
	footer := "\n全文: " + Escape(filepath.Join(in.Dir, ReportMD)) + "  |  " + LLMNotice
	tailText := joinNonEmpty(llmText, missing(miss), coverage, footer)

	var body string
	for level := trimNone; level <= trimConfirmText; level++ {
		body = classBody(s, byID, level)
		if text := joinNonEmpty(headText, body, tailText); utf8.RuneCountInString(text) <= MaxTextRunes {
			return text
		}
	}
	var missUrgent, missRest []findingRef
	for _, f := range miss {
		if atLeast(f.severity, r.UrgentSeverity) {
			missUrgent = append(missUrgent, f)
		} else {
			missRest = append(missRest, f)
		}
	}
	sort.SliceStable(missUrgent, func(i, j int) bool {
		return severityRank[missUrgent[i].severity] > severityRank[missUrgent[j].severity]
	})
	body = classBody(promoteUrgent(s, byID, r.UrgentSeverity), byID, trimConfirmText)
	// インシデント候補と approve の提案は、短ければ (maxKeptLLMRunes まで) 必ず残す。長ければ最後に回して切る
	keep, last := joinNonEmpty(llmText, footer), ""
	if utf8.RuneCountInString(llmText) > maxKeptLLMRunes {
		keep, last = footer, llmText
	}
	return fit(headText, joinNonEmpty(missing(missUrgent), coverage, body, missing(missRest), last), keep, "…(長いため省略)")
}

// promoteUrgent は urgent 以上の finding を要対処の先頭に並べ替えた Summary を返す。
func promoteUrgent(s *Summary, byID map[string]findingRef, urgent string) *Summary {
	var top, rest []Item
	for _, it := range s.Items {
		if f := byID[it.FindingID]; f.required && atLeast(f.severity, urgent) {
			it.Class = "action"
			top = append(top, it)
		} else {
			rest = append(rest, it)
		}
	}
	sort.SliceStable(top, func(i, j int) bool {
		return severityRank[byID[top[i].FindingID].severity] > severityRank[byID[top[j].FindingID].severity]
	})
	c := *s
	c.Items = append(top, rest...)
	return &c
}

// classBody は分類ごとの行。level に応じて理由文や情報の行を削る。
func classBody(s *Summary, byID map[string]findingRef, level int) string {
	var body []string
	for _, c := range classes {
		var ls []string
		for _, it := range s.Items {
			if it.Class != c.key {
				continue
			}
			l := byID[it.FindingID].line()
			withReason := !(c.key == "info" && level >= trimInfoReason) && !(c.key == "confirm" && level >= trimConfirmText)
			if withReason && it.Reason != "" {
				l += "\n    理由: " + Escape(clipRunes(oneLine(it.Reason), maxReasonRunes))
			}
			ls = append(ls, l)
		}
		if len(ls) == 0 {
			continue
		}
		if c.key == "info" && level >= trimInfoItems {
			body = append(body, "", fmt.Sprintf("*%s* %d 件 (長いため省略)", c.label, len(ls)))
			continue
		}
		body = append(body, "", "*"+c.label+"*")
		body = append(body, ls...)
	}
	return strings.Join(body, "\n")
}

func joinNonEmpty(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}

// clipRunes は s を n 文字までにする (超えたら末尾に …)。
func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func period(in *Input) string {
	if in.Run != nil {
		return in.Run.Window.From + " 〜 " + in.Run.Window.To
	}
	return in.Period.Period.From + " 〜 " + in.Period.Period.To + " (UTC)"
}

// counts は件数の行 (report.json の値)。
func counts(in *Input) string {
	if in.Run != nil {
		return runCounts(in.Run)
	}
	p := in.Period.Summary
	return fmt.Sprintf("新規 %d / 変化 %d / 再発 %d / 解消 %d / 未対応の残存 %d", p.New, p.Changed, p.Recurred, p.Resolved, p.Open)
}

// coverageLines は取れなかったもの (run は compact.go と同じ、期間レポートは runs_missing)。LLM を通さず規則で書く。
func coverageLines(in *Input) []string {
	if in.Run != nil {
		return runCoverageLines(in.Run)
	}
	if len(in.Period.RunsMissing) == 0 {
		return nil
	}
	out := []string{"", "*取れなかった run*"}
	for _, m := range in.Period.RunsMissing {
		l := fmt.Sprintf("• %s `%s` %s", Escape(m.Profile), Escape(m.Kind), Escape(m.At))
		if m.Until != "" {
			l += " 〜 " + Escape(m.Until)
		}
		out = append(out, l)
	}
	return out
}

// oneLine はログ由来の値と LLM の説明を 1 行にする (改行で偽の行を作らせない)。
// 決定 (ADR 0037): 目に見えない文字 (制御文字、向きの制御、ゼロ幅) も除く。表示を入れ替えたり、後の検査をすり抜けたりさせないため。
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsSpace(r) && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// SystemPrompt は LLM に渡す system。出力の契約と、arata が `arata help ai report` で出すのと同じ文書 (docs/ai/report.md)。
// playbooks は playbooksPrompt の節 (空なら足さない。ADR 0025)。
// context は利用者が書いた「この監査対象の前提」(空なら足さない。ADR 0024)。
// 決定: 期間レポート用の文書は足さない。docs/ai/report.md の「期間レポート」の節で足りるため (aratam 設計書 8 章の未決を閉じる)。
func SystemPrompt(kind, context, playbooks string) string {
	t, err := ai.Lookup("report")
	if err != nil {
		panic(err) // 埋め込んだ文書なので起きない
	}
	input := "arata の report.json (日次などのプロファイル実行の結果)"
	if kind == KindPeriod {
		input = "arata の期間レポートの report.json (\"kind\": \"period\")"
	}
	return fmt.Sprintf(`あなたは AWS 監査ツール arata の通知を書く担当です。ユーザーのメッセージは %s です。
下の「report.json の読み方と要約の手順」に従って読み、次の JSON だけを出力してください (前後に文章やコードフェンスを付けない)。

{
  "headline": "1 行の要約 (日本語)",
  "items": [{"finding_id": "report.json の id", "class": "action | confirm | info", "reason": "根拠 (data のどの値か) 付きの説明"}],
  "incidents": [{"finding_ids": ["...", "..."], "summary": "同じ主体・同じ時間帯の finding をまとめた見立て"}],
  "approve_suggestions": [{"finding_id": "...", "reason": "正当と思われる理由"}]
}

規則:
- class は action (要対処: 今動く) / confirm (確認依頼: 人が判断する) / info (情報: 記録のみ) のどれか。
- 新規・変化・再発の finding は必ず 1 件ずつ items に入れる。finding_id は report.json にあるものだけを使い、作らない。
- 重大度は変えない (表示は report.json の値を使う)。critical / high を info に格下げして沈黙させない。
- approve は提案するだけ。あなたは approve しない。
- 個人を特定できる値 (氏名・メールアドレスなど) を書かない。主体は ARN で書く。
- 追加の照会はできない。report.json に書かれていることだけで判断し、推測は「可能性」と書く。
%s
%s
- reason は 1〜2 文 (120 字程度)、incidents の summary は 200 字程度、approve_suggestions の reason も 1〜2 文にする。
  重大度・data の値は通知に別に表示されるので繰り返さない (「severity high。」や data.xxx= の書き方をしない)。何がなぜ問題かだけを書く。

---

%s%s%s`, input, untrustedInputRule, accountOnlyRule, t.Markdown(), playbooks, contextSection(context))
}
