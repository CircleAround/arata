package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// PeriodReport は期間レポート (`report --from --to`、月次は `--month`) の report.json。
// 決定 (ADR 0016): 収集も評価もせず、ストア (finding_events / findings / principals / metrics / runs) だけから作る。
type PeriodReport struct {
	Kind        string `json:"kind"` // "period"
	Name        string `json:"name"`
	Period      Period `json:"period"`
	GeneratedAt string `json:"generated_at"`
	// HistorySince は状態遷移の履歴を記録し始めた時刻。Notes にこれより前は履歴が無いことを書く。
	HistorySince  string          `json:"history_since,omitempty"`
	Notes         []string        `json:"notes"`
	Summary       PeriodSummary   `json:"summary"`
	Events        PeriodEvents    `json:"events"`
	NewPrincipals []PrincipalRow  `json:"new_principals"`
	Open          []Finding       `json:"open"`
	Metrics       MetricTable     `json:"metrics"`
	RunsMissing   []RunProblem    `json:"runs_missing"`
	Profiles      []ProfileRunSum `json:"profiles"`
}

// Period は対象の日付 (UTC、両端を含む)。
type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// PeriodSummary は件数。severity=info は数えない。
type PeriodSummary struct {
	New      int `json:"new"`
	Changed  int `json:"changed"`
	Recurred int `json:"recurred"`
	Resolved int `json:"resolved"`
	// BySeverity は期間内に新規・再発した finding (重複なし) の重大度別件数。
	BySeverity map[string]int `json:"by_severity"`
	// Open は期間の終わりの時点ではなく、レポート生成時点で未対応 (open / acked) の件数。
	Open int `json:"open"`
}

// PeriodEvents は期間内の状態遷移 (時刻順)。
type PeriodEvents struct {
	New      []EventRow `json:"new"`
	Changed  []EventRow `json:"changed"`
	Recurred []EventRow `json:"recurred"`
	Resolved []EventRow `json:"resolved"`
}

// EventRow は状態遷移 1 件。Profile が空なら人の操作 (resolve / approve) か allowlist の編集による解消。
type EventRow struct {
	FindingID string `json:"finding_id"`
	Check     string `json:"check"`
	Key       string `json:"key"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	At        string `json:"at"`
	Profile   string `json:"profile,omitempty"`
}

// PrincipalRow は期間内に初めて観測した主体。
type PrincipalRow struct {
	ARN       string `json:"arn"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	FirstSeen string `json:"first_seen"`
	Status    string `json:"status"`
}

// MetricTable はアプリ層の日次集計の推移 (日 × 指標、全ソース・全 key の合計)。日は UTC。
type MetricTable struct {
	Metrics []string    `json:"metrics"`
	Rows    []MetricRow `json:"rows"`
}

// MetricRow は 1 日分。Values は Metrics と同じ順。
type MetricRow struct {
	Date   string    `json:"date"`
	Values []float64 `json:"values"`
}

// RunProblem は取れなかった run (partial / failed) か、走らなかった期間 (RUN_MISSED)。
type RunProblem struct {
	Profile string `json:"profile"`
	Kind    string `json:"kind"` // partial / failed / RUN_MISSED
	RunID   string `json:"run_id,omitempty"`
	At      string `json:"at"`              // run の開始時刻、RUN_MISSED なら空いた期間の始まり
	Until   string `json:"until,omitempty"` // RUN_MISSED の空いた期間の終わり
	Detail  string `json:"detail,omitempty"`
}

// ProfileRunSum はプロファイルごとの run の件数。
type ProfileRunSum struct {
	Profile string `json:"profile"`
	Runs    int    `json:"runs"`
	OK      int    `json:"ok"`
	Partial int    `json:"partial"`
	Failed  int    `json:"failed"`
}

// PeriodInput は BuildPeriod への入力 (engine がストアから集める)。
type PeriodInput struct {
	Name         string
	From, To     string    // YYYY-MM-DD (UTC、両端を含む)
	Start, End   time.Time // [Start, End)
	Now          time.Time
	HistorySince time.Time
	Events       []store.FindingEvent
	Open         []store.Finding
	Principals   []store.Principal // first_seen が期間内のもの
	Metrics      []record.Metric
	Runs         []store.Run
	// Windows はプロファイルの窓 (RUN_MISSED の判定: 連続する run の間が窓の 2 倍以上空いた)。
	Windows map[string]time.Duration
}

// 期間レポートの推移表に出さない指標 (他の指標の内訳・解釈率の分子)。
var periodHiddenMetrics = map[string]bool{"lines_matched": true, "probe_paths": true, "waf_block_ip": true}

// BuildPeriod は期間レポートを組み立てる。
func BuildPeriod(in PeriodInput) *PeriodReport {
	r := &PeriodReport{Kind: "period", Name: in.Name, Period: Period{From: in.From, To: in.To}, GeneratedAt: ts(in.Now), Notes: []string{},
		Summary:       PeriodSummary{BySeverity: map[string]int{}},
		Events:        PeriodEvents{New: []EventRow{}, Changed: []EventRow{}, Recurred: []EventRow{}, Resolved: []EventRow{}},
		NewPrincipals: []PrincipalRow{}, Open: []Finding{}, Metrics: MetricTable{Metrics: []string{}, Rows: []MetricRow{}}, RunsMissing: []RunProblem{}, Profiles: []ProfileRunSum{}}
	switch {
	case in.HistorySince.IsZero():
		r.Notes = append(r.Notes, "状態遷移の履歴がまだ無い (この版で run を一度も実行していない)。new / changed / recurred / resolved は空")
	case in.HistorySince.After(in.Start):
		r.HistorySince = ts(in.HistorySince)
		r.Notes = append(r.Notes, fmt.Sprintf("%s 以前は状態遷移の履歴なし (履歴は %s の run から記録)。それより前の new / changed / recurred / resolved は数えていない",
			in.HistorySince.UTC().Format(record.DateLayout), ts(in.HistorySince)))
	}

	appeared := map[string]string{} // finding ID → 重大度 (新規・再発)
	for _, e := range in.Events {
		if e.Severity == string(checks.Info) {
			continue
		}
		row := EventRow{FindingID: e.FindingID, Check: e.Check, Key: e.Key, Severity: e.Severity, Summary: e.Summary, At: ts(e.At), Profile: e.Profile}
		switch checks.Class(e.Class) {
		case checks.ClassNew:
			r.Events.New = append(r.Events.New, row)
			appeared[e.FindingID] = e.Severity
		case checks.ClassChanged:
			r.Events.Changed = append(r.Events.Changed, row)
		case checks.ClassRecurred:
			r.Events.Recurred = append(r.Events.Recurred, row)
			appeared[e.FindingID] = e.Severity
		case checks.ClassResolved:
			r.Events.Resolved = append(r.Events.Resolved, row)
		}
	}
	for _, sev := range appeared {
		r.Summary.BySeverity[sev]++
	}
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.Resolved = len(r.Events.New), len(r.Events.Changed), len(r.Events.Recurred), len(r.Events.Resolved)

	for _, p := range in.Principals {
		r.NewPrincipals = append(r.NewPrincipals, PrincipalRow{ARN: p.ARN, Label: record.PrincipalLabel(p.ARN, p.Kind), Kind: string(p.Kind), FirstSeen: ts(p.FirstSeen), Status: p.Status})
	}
	for _, f := range in.Open {
		if f.Severity == string(checks.Info) {
			continue
		}
		r.Open = append(r.Open, toFinding(f))
	}
	sortFindings(r.Open)
	r.Summary.Open = len(r.Open)

	r.Metrics = metricTable(in.Metrics)
	r.RunsMissing, r.Profiles = runProblems(in)
	return r
}

func metricTable(ms []record.Metric) MetricTable {
	t := MetricTable{Metrics: []string{}, Rows: []MetricRow{}}
	sums := map[string]map[string]float64{} // date → metric → 合計
	names := map[string]bool{}
	for _, m := range ms {
		if periodHiddenMetrics[m.Metric] {
			continue
		}
		if sums[m.Date] == nil {
			sums[m.Date] = map[string]float64{}
		}
		sums[m.Date][m.Metric] += m.Value
		names[m.Metric] = true
	}
	for n := range names {
		t.Metrics = append(t.Metrics, n)
	}
	sort.Strings(t.Metrics)
	dates := make([]string, 0, len(sums))
	for d := range sums {
		dates = append(dates, d)
	}
	sort.Strings(dates)
	for _, d := range dates {
		row := MetricRow{Date: d, Values: make([]float64, len(t.Metrics))}
		for i, n := range t.Metrics {
			row.Values[i] = sums[d][n]
		}
		t.Rows = append(t.Rows, row)
	}
	return t
}

// runProblems は partial / failed の run と、連続する run の間が窓の 2 倍以上空いた期間 (RUN_MISSED) を返す。
// 決定: 期間内に run が 1 つも無いプロファイルは「使っていない」とみなして RUN_MISSED にしない (導入前や手動運用のプロファイルで鳴らないように)。
func runProblems(in PeriodInput) ([]RunProblem, []ProfileRunSum) {
	out := []RunProblem{}
	byProfile := map[string][]store.Run{}
	for _, run := range in.Runs {
		if run.Profile == "init" {
			continue
		}
		byProfile[run.Profile] = append(byProfile[run.Profile], run)
		switch run.Status {
		case "partial", "failed":
			detail := ""
			if e, ok := run.Stats["error"].(string); ok {
				detail = e
			} else if n, ok := run.Stats["sources_failed"].(float64); ok && n > 0 {
				detail = fmt.Sprintf("失敗したソース %d", int(n))
			}
			out = append(out, RunProblem{Profile: run.Profile, Kind: run.Status, RunID: run.ID, At: ts(run.StartedAt), Detail: detail})
		}
	}
	names := make([]string, 0, len(byProfile))
	for n := range byProfile {
		names = append(names, n)
	}
	sort.Strings(names)
	sums := []ProfileRunSum{}
	end := in.End
	if in.Now.Before(end) {
		end = in.Now
	}
	for _, n := range names {
		runs := byProfile[n]
		s := ProfileRunSum{Profile: n, Runs: len(runs)}
		for _, run := range runs {
			switch run.Status {
			case "ok":
				s.OK++
			case "partial":
				s.Partial++
			case "failed":
				s.Failed++
			}
		}
		sums = append(sums, s)
		w := in.Windows[n]
		if w <= 0 {
			continue
		}
		for i := range runs {
			next := end
			if i+1 < len(runs) {
				next = runs[i+1].StartedAt
			}
			if gap := next.Sub(runs[i].StartedAt); gap >= 2*w {
				out = append(out, RunProblem{Profile: n, Kind: "RUN_MISSED", At: ts(runs[i].StartedAt), Until: ts(next), Detail: fmt.Sprintf("%s 空いた (窓 %s)", humanDuration(gap), humanDuration(w))})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out, sums
}

// humanDuration は 13 日 / 36 時間 / 45 分 のように書く。
func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.1f 日", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0f 時間", d.Hours())
	}
	return fmt.Sprintf("%.0f 分", d.Minutes())
}

// JSON は整形済み JSON を返す。
func (r *PeriodReport) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Markdown は人向けの期間レポート。
func (r *PeriodReport) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# arata 期間レポート (%s)\n\n", r.Name)
	fmt.Fprintf(&b, "- 期間: %s 〜 %s (UTC、両端を含む)\n", r.Period.From, r.Period.To)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "- **注意**: %s\n", n)
	}
	fmt.Fprintf(&b, "- 新規 %d / 変化 %d / 再発 %d / 解消 %d / 未対応の残存 %d (info は数えない)\n", r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.Resolved, r.Summary.Open)
	var sevs []string
	for _, s := range []checks.Severity{checks.Critical, checks.High, checks.Medium, checks.Low} {
		if n := r.Summary.BySeverity[string(s)]; n > 0 {
			sevs = append(sevs, fmt.Sprintf("%s %d", s, n))
		}
	}
	if len(sevs) > 0 {
		fmt.Fprintf(&b, "- 期間内に新規・再発した指摘の重大度: %s\n", strings.Join(sevs, " / "))
	}
	b.WriteString("\n")
	eventSection(&b, "新規", r.Events.New)
	eventSection(&b, "再発", r.Events.Recurred)
	eventSection(&b, "変化", r.Events.Changed)
	eventSection(&b, "解消", r.Events.Resolved)

	fmt.Fprintf(&b, "## 新規の主体 (%d)\n\n", len(r.NewPrincipals))
	if len(r.NewPrincipals) == 0 {
		b.WriteString("期間内に初めて観測した主体はありません。\n\n")
	} else {
		b.WriteString("| 主体 | 種類 | 初出 | 状態 |\n|---|---|---|---|\n")
		for _, p := range r.NewPrincipals {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", p.Label, p.Kind, p.FirstSeen, p.Status)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## 未対応の残存 (%d)\n\n", len(r.Open))
	if len(r.Open) == 0 {
		b.WriteString("未対応 (open / acked) の指摘はありません。\n\n")
	} else {
		for _, f := range r.Open {
			fmt.Fprintf(&b, "- **[%s]** %s `%s` (%s、初出 %s、id %s)\n", f.Severity, f.Summary, f.Check, f.Status, f.FirstSeen, f.ID)
		}
		b.WriteString("\n")
	}

	b.WriteString("## アプリ層の日次推移 (UTC)\n\n")
	if len(r.Metrics.Rows) == 0 {
		b.WriteString("日次集計はありません (cloudwatch-logs ソースが無いか、期間内に集計していない)。\n\n")
	} else {
		fmt.Fprintf(&b, "| 日 | %s |\n|---|%s\n", strings.Join(r.Metrics.Metrics, " | "), strings.Repeat("---:|", len(r.Metrics.Metrics)))
		for _, row := range r.Metrics.Rows {
			vals := make([]string, len(row.Values))
			for i, v := range row.Values {
				vals[i] = fmt.Sprintf("%.0f", v)
			}
			fmt.Fprintf(&b, "| %s | %s |\n", row.Date, strings.Join(vals, " | "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 実行の状況\n\n")
	if len(r.Profiles) == 0 {
		b.WriteString("期間内に run がありません。\n")
	}
	for _, p := range r.Profiles {
		fmt.Fprintf(&b, "- %s: run %d (ok %d / partial %d / failed %d)\n", p.Profile, p.Runs, p.OK, p.Partial, p.Failed)
	}
	if len(r.RunsMissing) == 0 {
		b.WriteString("- 取れなかった run: なし\n")
	} else {
		b.WriteString("- 取れなかった run:\n")
		for _, m := range r.RunsMissing {
			line := fmt.Sprintf("  - %s `%s` %s", m.Profile, m.Kind, m.At)
			if m.Until != "" {
				line += " 〜 " + m.Until
			}
			if m.Detail != "" {
				line += " (" + m.Detail + ")"
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func eventSection(b *strings.Builder, title string, l []EventRow) {
	fmt.Fprintf(b, "## %s (%d)\n\n", title, len(l))
	if len(l) == 0 {
		b.WriteString("ありません。\n\n")
		return
	}
	for _, e := range l {
		by := e.Profile
		if by == "" {
			by = "人の操作 / allowlist"
		}
		fmt.Fprintf(b, "- %s **[%s]** %s `%s` (%s、id %s)\n", e.At, e.Severity, e.Summary, e.Check, by, e.FindingID)
	}
	b.WriteString("\n")
}
