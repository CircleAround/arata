package report

import (
	"fmt"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

// 期間レポートの型 (schema パッケージの型エイリアス)。
type (
	PeriodReport  = schema.PeriodReport
	Period        = schema.Period
	PeriodSummary = schema.PeriodSummary
	PeriodEvents  = schema.PeriodEvents
	EventRow      = schema.EventRow
	PrincipalRow  = schema.PrincipalRow
	MetricTable   = schema.MetricTable
	MetricRow     = schema.MetricRow
	RunProblem    = schema.RunProblem
	ProfileRunSum = schema.ProfileRunSum
)

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

// 期間レポートの推移表に出さない指標 (他の指標の内訳・解釈率の分子・主体の活動の日次集計 (判定の材料で、値は下限。ADR 0027))。
var periodHiddenMetrics = map[string]bool{"lines_matched": true, "probe_paths": true, "waf_block_ip": true,
	record.MetricPrincipalSource: true, record.MetricPrincipalSourceWrites: true, record.MetricPrincipalWriteRegion: true}

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
		row := EventRow{FindingID: e.FindingID, Check: e.Check, Key: record.MaskIdentity(e.Key), Severity: e.Severity, Summary: record.MaskIdentity(e.Summary), At: ts(e.At), Profile: e.Profile}
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
