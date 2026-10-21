package report

import (
	"fmt"
	"sort"
	"strings"
)

// Markdown は人向けの report.md を返す。新規 / 変化 / 解消 / 未対応 / 報告済み / 情報 / カバレッジ の順。
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# arata %s レポート (%s)\n\n", r.Profile, r.Name)
	fmt.Fprintf(&b, "- 期間: %s 〜 %s\n", r.Window.From, r.Window.To)
	fmt.Fprintf(&b, "- 新規 %d / 変化 %d / 再発 %d / 解消 %d / 未対応 %d", r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.Resolved, r.Summary.StillOpen)
	if r.Summary.MaxSeverity != "" {
		fmt.Fprintf(&b, " / 最大重大度 **%s**", r.Summary.MaxSeverity)
	}
	b.WriteString("\n")
	if len(r.Summary.CollectErrors) > 0 {
		fmt.Fprintf(&b, "- **収集エラー %d 件** (カバレッジ参照)\n", len(r.Summary.CollectErrors))
	}
	b.WriteString("\n")
	section(&b, "新規", r.Findings.New, "新規の指摘はありません。")
	section(&b, "変化", r.Findings.Changed, "変化した指摘はありません。")
	section(&b, "再発", r.Findings.Recurred, "再発した指摘はありません。")
	section(&b, "解消", r.Findings.Resolved, "解消した指摘はありません。")
	section(&b, "未対応", r.Findings.StillOpen, "未対応の指摘はありません。")
	if len(r.AlreadyReported) > 0 {
		section(&b, "本日報告済み", r.AlreadyReported, "")
	}
	if len(r.Info) > 0 {
		section(&b, "情報", r.Info, "")
	}
	b.WriteString("## カバレッジ\n\n")
	fmt.Fprintf(&b, "- 取得できたソース: %s\n", orNone(r.Coverage.SourcesOK))
	if len(r.Coverage.SourcesFailed) == 0 {
		b.WriteString("- 取得に失敗したソース: なし\n")
	} else {
		b.WriteString("- 取得に失敗したソース:\n")
		for _, e := range r.Summary.CollectErrors {
			fmt.Fprintf(&b, "  - %s: `%s` %s\n", e.Source, e.Code, e.Message)
			if e.Partial {
				b.WriteString("    - 一部の項目だけ取れなかった (取れた項目で評価し、取れなかった項目は前回の状態を維持)\n")
				continue
			}
			if e.CoveredFrom != "" {
				fmt.Fprintf(&b, "    - 取得できた期間: %s 〜 %s (それより古い側は未取得)\n", e.CoveredFrom, e.CoveredUntil)
			} else {
				b.WriteString("    - 取得できた期間: なし\n")
			}
		}
	}
	if len(r.Coverage.Formats) > 0 {
		b.WriteString("- 形式の解釈率:\n")
		for _, f := range r.Coverage.Formats {
			rate := "行なし"
			if f.MatchRate != nil {
				rate = fmt.Sprintf("%.2f (%d/%d)", *f.MatchRate, f.Matched, f.Total)
			}
			fmt.Fprintf(&b, "  - %s (%s): %s、閾値 %.2f", f.Source, f.Format, rate, f.Expected)
			if f.RecentAverage != nil {
				fmt.Fprintf(&b, "、直近平均 %.2f", *f.RecentAverage)
			}
			if f.Code != "" {
				fmt.Fprintf(&b, " `%s`", f.Code)
			}
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(&b, "- 実行したチェック: %s\n", orNone(r.Coverage.ChecksRun))
	if len(r.Coverage.ChecksSkipped) == 0 {
		b.WriteString("- スキップしたチェック: なし\n")
	} else {
		b.WriteString("- スキップしたチェック:\n")
		for _, s := range r.Coverage.ChecksSkipped {
			fmt.Fprintf(&b, "  - %s: %s\n", s.Check, s.Reason)
		}
	}
	return b.String()
}

func section(b *strings.Builder, title string, l []Finding, empty string) {
	fmt.Fprintf(b, "## %s (%d)\n\n", title, len(l))
	if len(l) == 0 {
		b.WriteString(empty + "\n\n")
		return
	}
	for _, f := range l {
		fmt.Fprintf(b, "- **[%s]** %s `%s`\n", f.Severity, f.Summary, f.Check)
		keys := make([]string, 0, len(f.Data))
		for k := range f.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "date" {
				// 決定: 日次集計の日は UTC (設計書 3 章)。日本の顧客が JST の日と取り違えないよう明示する
				fmt.Fprintf(b, "  - %s: %v (UTC)\n", k, f.Data[k])
				continue
			}
			fmt.Fprintf(b, "  - %s: %v\n", k, f.Data[k])
		}
		fmt.Fprintf(b, "  - id: %s (初出 %s)\n", f.ID, f.FirstSeen)
	}
	b.WriteString("\n")
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "なし"
	}
	return strings.Join(l, ", ")
}
