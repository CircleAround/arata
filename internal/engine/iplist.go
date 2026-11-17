package engine

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
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

// listedLookbackDays は listed を流す確定した日の数 (直近の確定した日から遡る)。導入した日や失敗の後に、古い日を何日も読み直して費用を増やさない。
const listedLookbackDays = 2

// updateListed は wafv2 のソースについて、確定した UTC の日ごとに 1 回、一覧の上位 K 個の IP に絞った問い合わせを流し、
// count_rule_status の listed と、数えた範囲を日の値に残す (ADR 0069 の 4 節)。until はそのソースが読み終えた時刻。
// from がゼロなら直近の確定した listedLookbackDays 日、ゼロでなければ from の日から確定した日までの全部 (collect --window で過去を足すとき)。
// read はこの収集で読み始めた時刻。
//
// 決定 (実データで直した): 流す (印を書く) のは、その日の日の値がそろった日だけ。時の単位で読むソースは部分の行が 24 時間分ある日、
// 日の頭から読み直すソースはこの収集でその日の 0 時から読んだ日。読んでいない日に空の一覧で印を書くと、後でその日を集めても listed が流れない。
//
// 決定: 流した日の印は waf_listed_ips_total (日の値。raw にも残るので rebuild の後も流し直さない)。一覧が空の日も印だけ残し、問い合わせない。
// 決定: 問い合わせの失敗はソースの失敗にしない (失敗したソースは全部を引き直すので、listed 1 本のために読み取りを増やさない)。
// LISTED_QUERY_FAILED の WARN を出し、印を残さず、次の run で流し直す。
func (e *Engine) updateListed(ctx context.Context, src config.Source, c *cwlogs.Collector, from, read, until time.Time, runID string) error {
	l := e.cfg.IPList
	if l == nil || l.CountSuspect == nil || src.Format != config.FormatWAFv2 {
		return nil
	}
	cs := l.CountSuspect
	last := dayStart(until.Add(-src.IngestDelay)).AddDate(0, 0, -1) // 終わりまで読めた日
	keep := dayStart(e.deps.Now()).Add(-e.cfg.Retention.IPList).Add(24 * time.Hour)
	first := last.AddDate(0, 0, -(listedLookbackDays - 1))
	if !from.IsZero() {
		first = dayStart(from)
	}
	for d := first; !d.After(last); d = d.AddDate(0, 0, 1) {
		date := d.Format(record.DateLayout)
		if d.Before(keep) {
			continue
		}
		done, err := e.st.Metrics(ctx, store.MetricFilter{Metric: cwlogs.MetricWAFListedIPsTotal, From: date, To: date, Sources: []string{src.ID}})
		if err != nil {
			return err
		}
		if len(done) > 0 {
			continue
		}
		if src.CollectHourly() {
			ok, err := c.HourlyDayComplete(ctx, d)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
		} else if d.Before(dayStart(read)) {
			continue
		}
		rows, err := e.st.IPListDays(ctx, d.AddDate(0, 0, -(l.ActiveDays()-1)).Format(record.DateLayout), date)
		if err != nil {
			return err
		}
		sel := iplist.Select(rows, date, l.ActiveDays(), cs.Reasons, func(ip string) bool { return e.al != nil && e.al.SourceIPAllowed(ip) })
		ips := sel.IPs
		if len(ips) > cs.MaxIPs {
			ips = ips[:cs.MaxIPs]
		}
		counts, used := map[string]float64{}, 0
		if len(ips) > 0 {
			counts, used, err = c.CollectListed(ctx, d, ips, cs.MaxQueries)
			if err != nil {
				e.log.Warn("listed query failed; count_rule_status uses suspect without the IP list for this day until the next run", "code", codes.ListedQueryFailed,
					"source", src.ID, "date", date, "error", record.MaskIdentity(err.Error()), "run_id", runID)
				continue
			}
		}
		m := func(name, key string, v float64) record.Metric {
			return record.Metric{Date: date, Source: src.ID, From: record.KindWAFAction, Metric: name, Key: key, Value: v}
		}
		var out []record.Metric
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, m(cwlogs.MetricWAFCountMatchListed, k, counts[k]))
		}
		out = append(out, m(cwlogs.MetricWAFListedIPsQueried, "", float64(used)))
		block, probe := sel.Share(used)
		if block >= 0 {
			out = append(out, m(cwlogs.MetricWAFListedBlockShare, "", math.Round(block*1000)/1000))
			if block < cs.MinBlockShare {
				out = append(out, m(cwlogs.MetricWAFListedCoverageLow, "", 1))
			}
		}
		if probe >= 0 {
			out = append(out, m(cwlogs.MetricWAFListedProbeShare, "", math.Round(probe*1000)/1000))
		}
		// 印は最後に書く (途中で止まったら次の run で流し直す)
		out = append(out, m(cwlogs.MetricWAFListedIPsTotal, "", float64(len(sel.IPs))))
		for _, r := range out {
			if err := e.ingest(ctx, src.ID, r, ""); err != nil {
				return err
			}
		}
		e.log.Info("listed counted", "source", src.ID, "date", date, "ips_total", len(sel.IPs), "ips_queried", used, "block_share", block, "run_id", runID)
	}
	return nil
}
