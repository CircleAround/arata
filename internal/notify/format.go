package notify

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxTextRunes は 1 通の本文の上限 (文字数)。
// 決定: Slack はメッセージの text を 4,000 文字程度までにするよう求めているため、余裕を見て 3,800 文字で切り詰める (aratam 設計書 8 章: まずは本文だけ)。
const MaxTextRunes = 3800

// Escape は report 由来の文字列を Slack の mrkdwn で文字どおりに表示させる。
// `<!channel>` やリンクの書式 (`<url|text>`) は < > で始まるので、ログ由来の値がメンションやリンクとして働かないようにする。
func Escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

var (
	mdHeading = regexp.MustCompile(`^#{1,6}\s+(.*)$`)
	mdBold    = regexp.MustCompile(`\*\*(.+?)\*\*`)
)

// Mrkdwn は report.md (Markdown) を Slack の mrkdwn に整形する。見出しと太字だけを置き換え、それ以外はそのまま。
func Mrkdwn(md string) string {
	lines := strings.Split(Escape(strings.TrimRight(md, "\n")), "\n")
	for i, l := range lines {
		if m := mdHeading.FindStringSubmatch(l); m != nil {
			l = "*" + strings.ReplaceAll(m[1], "**", "") + "*"
		}
		lines[i] = mdBold.ReplaceAllString(l, "*$1*")
	}
	return strings.Join(lines, "\n")
}

// title は通知の 1 行目に出す報告の名前。
func title(in *Input) string {
	if in.Run != nil {
		return fmt.Sprintf("arata %s (%s)", in.Run.Profile, in.Run.Name)
	}
	return fmt.Sprintf("arata 期間レポート (%s)", in.Period.Name)
}

// head はメンション・注記・警告の行。メンションは緊急用を通常用に送るときだけ付ける。
func head(route Route, r Rules, notice string, warnings []string) []string {
	var out []string
	if route == RouteUrgent && r.UrgentMention != "" {
		out = append(out, r.UrgentMention) // 設定に書いたメンションなのでエスケープしない
	}
	if notice != "" {
		out = append(out, notice)
	}
	for _, w := range warnings {
		out = append(out, ":warning: "+Escape(w))
	}
	return out
}

// QuietText は新規・変化・再発が無く、取れなかったものも無いときの 1 行 (on_quiet: short)。
func QuietText(in *Input, d Decision, r Rules, warnings []string) string {
	lines := head(d.Route, r, "", warnings)
	lines = append(lines, fmt.Sprintf("*%s* %s 〜 %s: 新規なし (変化・再発なし、取得の失敗なし。未対応 %d 件)",
		Escape(title(in)), Escape(in.Run.Window.From), Escape(in.Run.Window.To), in.Run.Summary.StillOpen))
	return strings.Join(lines, "\n")
}

// ReportText は通知の本文 (provider: none、または LLM が使えなかったときの原文)。
// run は report.json から主要キーだけの短い形で作り (compact.go)、期間レポートは report.md から件数 0 の節を除いて整形する。
// notice は冒頭に書く注記 (LLM が使えなかったときの「要約に失敗したため原文を送ります」)。
func ReportText(in *Input, d Decision, r Rules, warnings []string, notice string) string {
	lines := head(d.Route, r, notice, warnings)
	var body string
	if in.Run != nil {
		body = RunText(in.Run)
	} else {
		body = Mrkdwn(dropEmptySections(in.Markdown))
	}
	full := Escape(filepath.Join(in.Dir, ReportMD))
	return fit(strings.Join(lines, "\n"), body, "全文: "+full, "…(長いため省略)")
}

// InputProblemText は arata の出力が無い・読めない・古いときの通知 (LLM を通さず、緊急用に送る)。
func InputProblemText(dir string, e *InputError, r Rules) string {
	lines := head(RouteUrgent, r, "", nil)
	lines = append(lines,
		fmt.Sprintf("*arata の出力が無いか古いため、監査結果を通知できません (%s)*", Escape(r.Name)),
		"- 理由: "+Escape(e.Reason)+" (`"+e.Code+"`)",
		"- 入力: "+Escape(dir),
		"arata が実行されていないか、失敗しています。cron と arata のログを確認してください。")
	return strings.Join(lines, "\n")
}

// fit は head + body + footer を MaxTextRunes に収める。収まらなければ body を行の境目で切り、cut を足す。
func fit(head, body, footer, cut string) string {
	join := func(parts ...string) string {
		var out []string
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, "\n")
	}
	if s := join(head, body, footer); utf8.RuneCountInString(s) <= MaxTextRunes {
		return s
	}
	budget := MaxTextRunes - utf8.RuneCountInString(join(head, cut, footer)) - 1
	var kept []string
	n := 0
	for _, l := range strings.Split(body, "\n") {
		c := utf8.RuneCountInString(l) + 1
		if n+c > budget {
			break
		}
		kept = append(kept, l)
		n += c
	}
	return join(head, strings.Join(kept, "\n"), cut, footer)
}
