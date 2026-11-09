package notify

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 決定: 通知 (provider: none と、LLM が使えなかったときの原文) では、finding の data を全部は出さず、チェックごとの主要キーだけを 1 行に出す。
// report.md は data の全キーを列挙するので 1 件が 10 行を超え、Slack では読めないため。全部見たい人向けに末尾へ report.md のパスを添える。
// 対応表に無いチェックは count と ips だけ。summary の文に既に入っている値は繰り返さない。
var keyFields = map[string][]string{
	"root_usage":          {"count", "ips", "event_names", "last_time"},
	"unknown_assume_role": {"caller", "count", "ips", "last_time"},
	"new_principal":       {"kind", "count", "ips", "external_account"},
	"iam_changes":         {"principal", "target", "policy_arn", "count", "ips"},
	"login_bruteforce":    {"ip", "count", "date", "reason", "threshold"},
	"probe_paths":         {"ip", "count", "date", "reason", "top_paths_of_day"},
	"waf_block_trend":     {"rule", "ip", "count", "date", "reason"},
	"guardduty_findings":  {"type", "count", "region"},
	"access_analyzer":     {"resource", "is_public"},
	"credential_hygiene":  {"key", "last_used", "days_unused"},
	"ai_path_usage":       {"ip", "last_seen"},
	"access_denied":       {"apis", "ips", "allowlist_status"},
}

var defaultKeyFields = []string{"count", "ips"}

// maxListItems はリストの値を何個まで出すか (残りは「他 N」)。
const maxListItems = 3

// detail は finding の主要キー・初出と、末尾の id の表記 (`id: …`。blocks と同じ。aratam 設計書 3-5 章) の 1 行。何も無ければ空。
// 値のバッククォートは ' にする (末尾の id のコード表記を崩させない)。
func detail(f schema.Finding) string {
	keys, ok := keyFields[f.Check]
	if !ok {
		keys = defaultKeyFields
	}
	var parts []string
	for _, k := range keys {
		v, ok := f.Data[k]
		if !ok || v == nil {
			continue
		}
		s, ok := valueText(v, f.Summary)
		if !ok {
			continue
		}
		if k == "date" {
			s += " (UTC)"
		}
		parts = append(parts, k+" "+s)
	}
	if f.FirstSeen != "" {
		parts = append(parts, "初出 "+f.FirstSeen)
	}
	var out []string
	if s := Escape(noTick(oneLine(strings.Join(parts, " · ")))); s != "" {
		out = append(out, s)
	}
	if tag := idTag(f.ID); tag != "" {
		out = append(out, tag)
	}
	return strings.Join(out, " · ")
}

// valueText は値を短い文字列にする。summary に既に入っている値なら false。
func valueText(v any, summary string) (string, bool) {
	switch x := v.(type) {
	case []any:
		var items []string
		for _, e := range x {
			items = append(items, fmt.Sprint(e))
		}
		all := len(items) > 0
		for _, it := range items {
			all = all && strings.Contains(summary, it)
		}
		if len(items) == 0 || all {
			return "", false
		}
		if len(items) > maxListItems {
			return fmt.Sprintf("%s 他 %d", strings.Join(items[:maxListItems], ", "), len(items)-maxListItems), true
		}
		return strings.Join(items, ", "), true
	case float64:
		s := fmt.Sprintf("%g", x)
		// 数値は「52 件」「3 回」の形で summary にあれば繰り返さない (日付などの数字と取り違えないよう単位付きで見る)
		for _, unit := range []string{" 件", " 回", "件", "回"} {
			if strings.Contains(summary, s+unit) {
				return "", false
			}
		}
		return s, true
	case string:
		if x == "" || strings.Contains(summary, x) {
			return "", false
		}
		return x, true
	default:
		return fmt.Sprint(x), true
	}
}

// findingLines は finding 1 件の 2 行 (重大度・概要・チェック名の行と、主要キー・id の行)。値は report.json のもの。
func findingLines(f schema.Finding) string {
	return withDetail(fmt.Sprintf("• *[%s]* %s `%s`", Escape(f.Severity), Escape(oneLine(f.Summary)), Escape(f.Check)), detail(f))
}

// withDetail は finding の行の下に、字下げした 2 行目を足す (空なら足さない)。
func withDetail(line, detail string) string {
	if detail == "" {
		return line
	}
	return line + "\n    " + detail
}

// RunText は run の report.json から作る通知の本文 (件数が 0 の区分は出さない)。
func RunText(r *schema.Report) string {
	lines := []string{"*" + Escape(fmt.Sprintf("arata %s (%s)", r.Profile, r.Name)) + "* " + Escape(r.Window.From+" 〜 "+r.Window.To), runCounts(r)}
	for _, s := range []struct {
		title string
		l     []schema.Finding
	}{
		{"新規", r.Findings.New}, {"変化", r.Findings.Changed}, {"再発", r.Findings.Recurred},
		{"解消", r.Findings.Resolved}, {"未対応", r.Findings.StillOpen}, {"本日報告済み", r.AlreadyReported}, {"情報", r.Info},
	} {
		if len(s.l) == 0 {
			continue
		}
		lines = append(lines, "", fmt.Sprintf("*%s (%d)*", s.title, len(s.l)))
		for _, f := range s.l {
			lines = append(lines, findingLines(f))
		}
	}
	lines = append(lines, runCoverageLines(r)...)
	return strings.Join(lines, "\n")
}

// runCounts は件数の行。
func runCounts(r *schema.Report) string {
	s := fmt.Sprintf("新規 %d / 変化 %d / 再発 %d / 解消 %d / 未対応 %d", r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.Resolved, r.Summary.StillOpen)
	if r.Summary.MaxSeverity != "" {
		s += " / 最大重大度 *" + Escape(r.Summary.MaxSeverity) + "*"
	}
	return s
}

// runCoverageLines は取れていなかったもの (取得に失敗したソース、解釈率の警告、スキップしたチェック)。問題が無ければ何も出さない。
func runCoverageLines(r *schema.Report) []string {
	var out []string
	if len(r.Coverage.SourcesFailed) > 0 {
		out = append(out, "", "*取れなかったソース*")
		for _, f := range r.Coverage.SourcesFailed {
			l := fmt.Sprintf("• %s: `%s`", Escape(f.Source), Escape(f.Code))
			if f.Action != "" {
				l += " (不足: " + Escape(f.Action) + ")"
			}
			switch {
			case f.Partial:
				l += " 一部の項目だけ取れず"
			case f.CoveredFrom != "":
				l += fmt.Sprintf(" 取れた期間 %s 〜 %s", Escape(f.CoveredFrom), Escape(f.CoveredUntil))
			default:
				l += " 取れた期間なし"
			}
			out = append(out, l)
		}
	}
	var fmts []string
	for _, f := range r.Coverage.Formats {
		if f.Code == "" {
			continue
		}
		rate := "行なし"
		if f.MatchRate != nil {
			rate = fmt.Sprintf("%.2f", *f.MatchRate)
		}
		fmts = append(fmts, fmt.Sprintf("• %s (%s): 解釈率 %s、閾値 %.2f `%s`", Escape(f.Source), Escape(f.Format), rate, f.Expected, Escape(f.Code)))
	}
	if len(fmts) > 0 {
		out = append(out, "", "*形式の解釈率の警告*")
		out = append(out, fmts...)
	}
	if len(r.Coverage.ChecksSkipped) > 0 {
		var ss []string
		for _, s := range r.Coverage.ChecksSkipped {
			ss = append(ss, s.Check+" ("+s.Reason+")")
		}
		sort.Strings(ss)
		out = append(out, "", "*スキップしたチェック*: "+Escape(strings.Join(ss, ", ")))
	}
	return out
}

var emptySection = regexp.MustCompile(`^## .* \(0\)$`)

// dropEmptySections は Markdown から件数 0 の節 (`## 見出し (0)` から次の `## ` の手前まで) を除く。
func dropEmptySections(md string) string {
	var out []string
	skip := false
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "## ") {
			skip = emptySection.MatchString(l)
		}
		if !skip {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
