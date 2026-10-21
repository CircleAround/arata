package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/report/schema"
)

// Summary は LLM に求める出力 (aratam 設計書 3 章)。
type Summary struct {
	Headline           string       `json:"headline"`
	Items              []Item       `json:"items"`
	Incidents          []Incident   `json:"incidents"`
	ApproveSuggestions []Suggestion `json:"approve_suggestions"`
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
	id, check, severity, summary, diff string
	required                           bool            // new / changed / recurred (LLM の出力から漏れたら規則で足す)
	finding                            *schema.Finding // data を持つもの (期間レポートの events は持たない)
}

// findingIndex は report.json の finding を出現順に並べる。
func findingIndex(in *Input) ([]findingRef, map[string]findingRef) {
	var list []findingRef
	add := func(diff string, required bool, fs []schema.Finding) {
		for i := range fs {
			f := &fs[i]
			list = append(list, findingRef{id: f.ID, check: f.Check, severity: f.Severity, summary: f.Summary, diff: diff, required: required, finding: f})
		}
	}
	addEvents := func(diff string, required bool, es []schema.EventRow) {
		for _, e := range es {
			list = append(list, findingRef{id: e.FindingID, check: e.Check, severity: e.Severity, summary: e.Summary, diff: diff, required: required})
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
func ParseSummary(raw []byte, in *Input) (*Summary, error) {
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
	_, byID := findingIndex(in)
	seen := map[string]bool{}
	items := []Item{}
	for _, it := range s.Items {
		if _, ok := byID[it.FindingID]; !ok || seen[it.FindingID] || classLabel(it.Class) == "" {
			continue
		}
		seen[it.FindingID] = true
		items = append(items, it)
	}
	s.Items = items
	incidents := []Incident{}
	for _, inc := range s.Incidents {
		var ids []string
		for _, id := range inc.FindingIDs {
			if _, ok := byID[id]; ok {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			inc.FindingIDs = ids
			incidents = append(incidents, inc)
		}
	}
	s.Incidents = incidents
	sugs := []Suggestion{}
	for _, sg := range s.ApproveSuggestions {
		if _, ok := byID[sg.FindingID]; ok {
			sugs = append(sugs, sg)
		}
	}
	s.ApproveSuggestions = sugs
	return &s, nil
}

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

// line は finding 1 件の行。重大度・概要・チェック名・主要キーは report.json の値を使う (LLM に重大度を変えさせない)。
func (f findingRef) line() string {
	l := fmt.Sprintf("• *[%s]* %s `%s` (%s)", Escape(f.severity), Escape(f.summary), Escape(f.check), f.diff)
	if f.finding != nil {
		return l + "\n    " + detail(*f.finding)
	}
	return l + "\n    id " + Escape(f.id)
}

// SummaryText は LLM の要約を決まった書式で組み立てる。
// 件数・取れなかったソース・漏れた finding は規則で書き、切り詰めでも落とさない (LLM の分類と説明の部分だけを切る)。
func SummaryText(in *Input, d Decision, r Rules, warnings []string, s *Summary) string {
	_, byID := findingIndex(in)
	lines := head(d.Route, r, "", warnings)
	lines = append(lines, "*"+Escape(title(in))+"* "+Escape(period(in)), counts(in), Escape(strings.TrimSpace(s.Headline)))

	var body []string
	for _, c := range classes {
		var ls []string
		for _, it := range s.Items {
			if it.Class == c.key {
				ls = append(ls, byID[it.FindingID].line()+"\n    理由: "+Escape(oneLine(it.Reason)))
			}
		}
		if len(ls) > 0 {
			body = append(body, "", "*"+c.label+"*")
			body = append(body, ls...)
		}
	}
	if len(s.Incidents) > 0 {
		body = append(body, "", "*インシデント候補*")
		for _, inc := range s.Incidents {
			body = append(body, fmt.Sprintf("• %s: %s", Escape(strings.Join(inc.FindingIDs, ", ")), Escape(oneLine(inc.Summary))))
		}
	}
	if len(s.ApproveSuggestions) > 0 {
		body = append(body, "", "*approve の提案* (提案のみ。aratam は approve しない。人が判断して実行する)")
		for _, sg := range s.ApproveSuggestions {
			body = append(body, fmt.Sprintf("• %s: %s\n    `arata approve %s --note \"...\"`", Escape(sg.FindingID), Escape(oneLine(sg.Reason)), Escape(sg.FindingID)))
		}
	}

	var tail []string
	if miss := s.Missing(in); len(miss) > 0 {
		tail = append(tail, "", "*要約に含まれていなかった指摘* (規則で追加)")
		for _, f := range miss {
			tail = append(tail, f.line())
		}
	}
	tail = append(tail, coverageLines(in)...)
	tail = append(tail, "全文: "+Escape(filepath.Join(in.Dir, ReportMD)))
	return fit(strings.Join(lines, "\n"), strings.Join(body, "\n"), strings.Join(tail, "\n"), "…(長いため省略)")
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

// oneLine は LLM の説明を 1 行にする (改行で書式を崩させない)。
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// SystemPrompt は LLM に渡す system。出力の契約と、arata が `arata help ai report` で出すのと同じ文書 (docs/ai/report.md)。
// 決定: 期間レポート用の文書は足さない。docs/ai/report.md の「期間レポート」の節で足りるため (aratam 設計書 8 章の未決を閉じる)。
func SystemPrompt(kind string) string {
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

---

%s`, input, t.Markdown())
}
