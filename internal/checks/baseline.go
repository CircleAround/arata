package checks

import (
	"context"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// アプリ層チェックの共通部: metrics (日次集計) から平常帯を作り、窓内の日の値と比べる。
//
// 決定:
//   - 評価する日は窓に重なる UTC の日 (daily の窓 [D-1 09:00, D 09:00) なら D-1 と D)。D は途中までの値だが、翌日の run で丸 1 日分として再評価される。
//   - 平常帯は「その key 自身の」直近 baseline_days 日のうち、ログを収集した日の日次値 (収集した日で値の無い日は 0) の中央値 × factor。
//     ただし min_count を下限にする。収集した日は http_access のソースの lines_total のある日と、その metric の値のある日 (ADR 0090)。
//     攻撃元の IP は過去に現れないので閾値は min_count、毎日一定数失敗する社内 NAT などは自分の中央値で吸収される。
//   - 「Top IP 初出」は、その日の最多 key が過去 baseline_days 日に一度も無く、件数が top_ip_min_count 以上のとき。
//     データのある過去日が min_baseline_days 未満の間 (導入直後) は判定しない。
//   - 複数ソースが同じ metric を出す場合は合算する。

// series は date → key → value。
type series map[string]map[string]float64

func loadSeries(ctx context.Context, q store.Query, metric, from, to string) (series, error) {
	ms, err := q.Metrics(ctx, store.MetricFilter{Metric: metric, From: from, To: to})
	if err != nil {
		return nil, err
	}
	s := series{}
	for _, m := range ms {
		if s[m.Date] == nil {
			s[m.Date] = map[string]float64{}
		}
		s[m.Date][m.Key] += m.Value
	}
	return s, nil
}

// windowDates は窓に重なる日 (UTC, YYYY-MM-DD) を古い順に返す。
func windowDates(w collect.Window) []string {
	var out []string
	last := w.To.Add(-time.Nanosecond).UTC()
	for d := dayOf(w.From); !d.After(last); d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format(record.DateLayout))
	}
	return out
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func addDays(date string, n int) string {
	t, _ := time.Parse(record.DateLayout, date)
	return t.AddDate(0, 0, n).Format(record.DateLayout)
}

// baseDates は date の前日から n 日分。
func baseDates(date string, n int) []string {
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, addDays(date, -i))
	}
	return out
}

// collectedVals は bds のうち収集した日 (collected) の値を返す (ADR 0090)。収集していない日は数えず、収集した日で値の無い日は val が 0 を返す。
func collectedVals(bds []string, collected map[string]bool, val func(date string) float64) []float64 {
	out := make([]float64, 0, len(bds))
	for _, bd := range bds {
		if collected[bd] {
			out = append(out, val(bd))
		}
	}
	return out
}

func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	v := append([]float64(nil), vals...)
	sort.Float64s(v)
	n := len(v)
	if n%2 == 1 {
		return v[n/2]
	}
	return (v[n/2-1] + v[n/2]) / 2
}

// topKeys は値の大きい順に最大 n 個 (同数は key 順)。min 未満は含めない。
func topKeys(m map[string]float64, n int, min float64) []string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v >= min {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// 平常帯比較の理由 (Data の reason と Fingerprint に入る)。
const (
	reasonAboveBaseline = "above_baseline"
	reasonNewTopIP      = "new_top_ip"
	reasonNewRule       = "new_rule"
)

// spike は平常帯を超えた key 1 つ。
type spike struct {
	Key          string
	Date         string
	Count        float64
	Median       float64
	Threshold    float64
	Reason       string
	BaselineDays int  // データのあった過去日数
	Collected    int  // 収集した過去日数 (中央値に入れた日数。ADR 0090)
	Shared       bool // その日に人の多い送信元 (allowlist の shared_sources) だった (ADR 0094 の 1 節)
}

// spikeShared は、key がその日 (date) に人の多い送信元か (ADR 0094 の 1 節)。nil なら人の多い送信元は無い。
type spikeShared func(key, date string) bool

func (s spike) data(keyName string) map[string]any {
	return map[string]any{
		keyName: s.Key, "date": s.Date, "count": s.Count, "baseline_median": s.Median, "threshold": s.Threshold,
		"reason": s.Reason, "baseline_days_with_data": s.BaselineDays, "baseline_days_collected": s.Collected,
	}
}

// detectSpikes は metric の窓内の日について平常帯超過と Top key 初出を探す。key ごとに件数が最大の日を 1 件返す (key 順)。
//
// shared がその日に真を返す key は、平常帯の下限を sharedMin にし、Top key 初出を報告しない (ADR 0094 の 1 節)。
// その日の Top key は shared の key も含めて決める (shared の key が最多の日は、ほかの key も初出の最多にならない。skip の key と同じ扱い)。
func detectSpikes(ctx context.Context, q store.Query, metric string, w collect.Window, b config.Baseline, topMin float64, skip func(string) bool, shared spikeShared, sharedMin float64) ([]spike, error) {
	dates := windowDates(w)
	if len(dates) == 0 {
		return nil, nil
	}
	s, err := loadSeries(ctx, q, metric, addDays(dates[0], -b.BaselineDays), dates[len(dates)-1])
	if err != nil {
		return nil, err
	}
	collected, err := httpCollectedSet(ctx, q, addDays(dates[0], -b.BaselineDays), addDays(dates[len(dates)-1], -1))
	if err != nil {
		return nil, err
	}
	best := map[string]spike{}
	for _, d := range dates {
		today := s[d]
		if len(today) == 0 {
			continue
		}
		bds := baseDates(d, b.BaselineDays)
		withData, seen := 0, map[string]bool{}
		for _, bd := range bds {
			if len(s[bd]) > 0 {
				withData++
				collected[bd] = true // 値のある日は収集した日
			}
			for k := range s[bd] {
				seen[k] = true
			}
		}
		top := topKeys(today, 1, topMin)
		for k, v := range today {
			if skip != nil && skip(k) {
				continue
			}
			vals := collectedVals(bds, collected, func(bd string) float64 { return s[bd][k] })
			med := median(vals)
			isShared := shared != nil && shared(k, d)
			floor := b.MinCount
			if isShared {
				floor = sharedMin
			}
			thr := med * b.Factor
			if thr < floor {
				thr = floor
			}
			sp := spike{Key: k, Date: d, Count: v, Median: med, Threshold: thr, BaselineDays: withData, Collected: len(vals), Shared: isShared}
			switch {
			case v > thr:
				sp.Reason = reasonAboveBaseline
			case !isShared && len(top) == 1 && top[0] == k && !seen[k] && withData >= b.MinBaselineDays:
				sp.Reason = reasonNewTopIP
			default:
				continue
			}
			if cur, ok := best[k]; !ok || v > cur.Count {
				best[k] = sp
			}
		}
	}
	keys := make([]string, 0, len(best))
	for k := range best {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]spike, 0, len(keys))
	for _, k := range keys {
		out = append(out, best[k])
	}
	return out, nil
}
