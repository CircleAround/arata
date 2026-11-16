package engine

import (
	"context"
	"time"

	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/iplist"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ipListStats は 1 回の収集で作り直した一覧の数 (run の stats の ip_list。理由ごとの、載った (日, ソース, IP) の数)。
type ipListStats map[string]int

// updateIPList は収集が成功した cloudwatch-logs のソースについて、[from, to] の日の一覧を日の値から作り直す (ADR 0069 の 1・2 節)。
// 決定: 一覧は日の値と同じ単位で作り直す (日の値は途中の値として毎回作り直されるので、(date, source) ごとに丸ごと置き換える)。
// 決定: 保持の期間 (retention.ip_list) より前の日は作らない。消すのは書くときに行う (prune はまだ無い。ADR 0065 の部分の行と同じ)。
func (e *Engine) updateIPList(ctx context.Context, src config.Source, from, to time.Time, st ipListStats) error {
	l := e.cfg.IPList
	if l == nil || src.Kind != config.KindCloudWatchLogs || to.Before(from) {
		return nil
	}
	st.touch()
	today := dayStart(e.deps.Now())
	keep := today.Add(-e.cfg.Retention.IPList).Add(24 * time.Hour).Format(record.DateLayout) // 今日を含めて M 日
	first, last := dayStart(from).Format(record.DateLayout), dayStart(to).Format(record.DateLayout)
	if first < keep {
		first = keep
	}
	if last < first {
		return nil
	}
	s := iplist.Series{}
	for _, m := range iplist.Metrics {
		ms, err := e.st.Metrics(ctx, store.MetricFilter{Metric: m, From: iplist.From(l, first), To: last, Sources: []string{src.ID}})
		if err != nil {
			return err
		}
		for _, x := range ms {
			if s[x.Date] == nil {
				s[x.Date] = iplist.Day{}
			}
			if s[x.Date][m] == nil {
				s[x.Date][m] = map[string]float64{}
			}
			s[x.Date][m][x.Key] += x.Value
		}
	}
	known := func(ip string) bool { return e.al != nil && e.al.SourceIPAllowed(ip) }
	for d := first; d <= last; d = nextDay(d) {
		res := iplist.Build(l, src.ID, d, s, known)
		if err := e.st.ReplaceIPListDay(ctx, src.ID, d, res.Rows, keep); err != nil {
			return err
		}
		for _, r := range res.Rows {
			st[r.Reason]++
		}
		st["invalid_ip"] += res.Invalid
		st["known_ip"] += res.Known
		st["sign_in_by_day"] += res.SignInByDay
		st["sign_in_by_window"] += res.SignInByWindow
	}
	return nil
}

func dayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func nextDay(d string) string {
	t, err := time.Parse(record.DateLayout, d)
	if err != nil {
		return "9999-12-31"
	}
	return t.AddDate(0, 0, 1).Format(record.DateLayout)
}

// touch は一覧を作ったことを残す (理由で 1 件も載らなくても stats に出す)。
func (st ipListStats) touch() {
	if _, ok := st["invalid_ip"]; !ok {
		st["invalid_ip"] = 0
	}
}

// addIPListStats は一覧を作ったとき (ip_list: があり、cloudwatch-logs のソースを読んだとき) だけ、run の stats に ip_list を足す。
func (r CollectResult) addIPListStats(stats map[string]any) {
	if len(r.ipList) == 0 {
		return
	}
	stats["ip_list"] = map[string]int(r.ipList)
}
