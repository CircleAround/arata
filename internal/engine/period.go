package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

// PeriodReport は [from, to] (UTC の日付、両端を含む) の期間レポートをストアだけから作る (収集・評価はしない。ADR 0016)。
func (e *Engine) PeriodReport(ctx context.Context, from, to string) (*report.PeriodReport, error) {
	start, err := time.Parse(record.DateLayout, from)
	if err != nil {
		return nil, e.configErr(fmt.Errorf("--from %q: want YYYY-MM-DD", from))
	}
	last, err := time.Parse(record.DateLayout, to)
	if err != nil {
		return nil, e.configErr(fmt.Errorf("--to %q: want YYYY-MM-DD", to))
	}
	if last.Before(start) {
		return nil, e.configErr(fmt.Errorf("--to %s is before --from %s", to, from))
	}
	end := last.AddDate(0, 0, 1)
	in := report.PeriodInput{Name: e.cfg.Name, From: from, To: to, Start: start, End: end, Now: e.deps.Now(), Windows: map[string]time.Duration{}}
	for name, p := range e.cfg.Profiles {
		in.Windows[name] = p.Window
	}
	if in.HistorySince, err = e.st.HistorySince(ctx); err != nil {
		return nil, err
	}
	if in.Events, err = e.st.FindingEvents(ctx, start, end); err != nil {
		return nil, err
	}
	if in.Open, err = e.st.Findings(ctx, "", []string{store.FindingOpen, store.FindingAcked}); err != nil {
		return nil, err
	}
	ps, err := e.st.Principals(ctx, store.PrincipalFilter{})
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if !p.FirstSeen.Before(start) && p.FirstSeen.Before(end) {
			in.Principals = append(in.Principals, p)
		}
	}
	if in.Metrics, err = e.st.Metrics(ctx, store.MetricFilter{From: from, To: to}); err != nil {
		return nil, err
	}
	if in.Runs, err = e.st.Runs(ctx, start, end); err != nil {
		return nil, err
	}
	return report.BuildPeriod(in), nil
}

// MonthRange は YYYY-MM をその月の初日と末日にする (`report --month` の糖衣)。
func MonthRange(month string) (from, to string, err error) {
	t, err := time.Parse("2006-01", month)
	if err != nil {
		return "", "", fmt.Errorf("--month %q: want YYYY-MM", month)
	}
	return t.Format(record.DateLayout), t.AddDate(0, 1, -1).Format(record.DateLayout), nil
}
