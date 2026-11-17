package cwlogs

import (
	"context"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// 時の単位で続きだけを読む (sources[].collect: hourly。ADR 0065)。
//
// 決定:
//   - 集計のクエリの軸を bin(1d) から bin(1h) にし、[位置の時, (今 − ingest_delay) を切り捨てた時) だけを読む。終わっていない時は読まない
//     (同じ時を 2 度読まないので、1 日に読む量は「本数 × 1 日分」で、実行の時刻にも間隔にも依らない)
//   - クエリが返した行 (部分の行) を (ソース, クエリ, 時) ごとに丸ごと置き換えてストアに残し、日の値は「その日の全部の時の行」を
//     今までの振り分け (collectWAF・collectHTTP・collectEndpoints) に通して作る。振り分けは同じ組の行の件数を足し、IP は集合で取るので、
//     時ごとの行を合わせても 1 日分を 1 本で引いたときと同じ値になる (シミュレーターで固定)
//   - 時の単位で読み始める日にその日の 0 時からの部分の行が無ければ、その日の頭から読む (移った日の値を一部だけの値で置き換えない)
//   - レート (waf_ip_rate_*) は 2 段目を「5 分あたりの件数 n の度数」にして時ごとに引き、日の度数を足して Go で分位数を取る
//     (Insights の pct は近似なので、値が少し変わる。Release の本文に書く)
//   - 部分の行は raw に書かない。確定した日から PartRetentionDays 日 (既定 3) より古いものは書くときに消す
//   - 時ごとの sign-in の失敗の和を sign_in_failures_hourly (metrics_hourly) に書く (速報 sign_in_failure_spike の材料。ADR 0066)

// PartStore は部分の行の置き場所 (ストア。engine が渡す)。
type PartStore interface {
	PutParts(ctx context.Context, source, query string, hour time.Time, rows []map[string]string, retentionDays int) error
	Parts(ctx context.Context, source, query string, from, to time.Time) ([]map[string]string, int, error)
}

// DefaultPartRetentionDays は部分の行を残す日数の既定。
const DefaultPartRetentionDays = 3

// MetricSignInFailuresHourly は時ごとの sign-in の失敗の和 (key なし。Metric.Hour 付き)。
const MetricSignInFailuresHourly = "sign_in_failures_hourly"

// wafRateHist はレートの度数のクエリの名前 (部分の行のクエリの名前)。
const wafRateHist = "waf_ip_rate_hist"

func (c *Collector) hourly() bool { return c.src.CollectHourly() && c.Parts != nil }

// Limited は、時の単位で読むソースが max_collect で止めたか (CoveredTo が今 − ingest_delay より前)。
func (c *Collector) Limited() bool { return c.limited }

// CoveredTo は時の単位で読むソースが、この収集で読み終えた時 (位置はここまで進める。ゼロなら位置を変えない)。engine が読む。
func (c *Collector) CoveredTo() time.Time { return c.coveredTo }

// hourlyQuery は日の軸を時の軸にしたクエリ。
func hourlyQuery(q string) string { return strings.ReplaceAll(q, "by bin(1d) as ", "by bin(1h) as ") }

// hourlyRange は時の単位で読む範囲。ok が false なら読む時が無い。
func (c *Collector) hourlyRange(ctx context.Context, w collect.Window, first string) (from, to time.Time, ok bool, err error) {
	from = w.From.UTC().Truncate(time.Hour)
	// 終わりは窓の終わりと「今 − ingest_delay」の早い方 (まだ取り込み中の時を読まない)
	to = w.To.UTC()
	if lim := c.Now().UTC().Add(-c.src.IngestDelay); to.After(lim) {
		to = lim
	}
	to = to.Truncate(time.Hour)
	if day := DayStart(from); from.After(day) {
		if _, n, err := c.Parts.Parts(ctx, c.src.ID, first, day, from); err != nil {
			return from, to, false, err
		} else if n == 0 {
			from = day
		}
	}
	c.readFrom = DayStart(from)
	// max_collect (ADR 0064): 古い側から決めた時間の分だけ読む (日の頭からの読み直しを含む)
	if m := c.src.MaxCollect; m > 0 && to.Sub(from) > m {
		to, c.limited = from.Add(m).Truncate(time.Hour), true
	}
	return from, to, to.After(from), nil
}

// fetch は q の行を返す。日の頭から読み直す読み方では [from, to) を流した行。時の単位で読む読み方では、[from, to) を流して時ごとに部分の行として残し、
// [from の日の頭, to) の部分の行 (その日の全部の時の行) を返す。
func (c *Collector) fetch(ctx context.Context, q MergedQuery, from, to time.Time, align time.Duration, perDay bool) ([]map[string]string, error) {
	if !c.hourly() {
		return c.splitQuery(ctx, q, from, to, align, perDay)
	}
	for h := from; h.Before(to); h = h.Add(time.Hour) {
		r, err := c.queryHour(ctx, q, h)
		if err != nil {
			return nil, err
		}
		// 流した時の外の行 (時の軸が読めない・別の時) は捨てる (Insights の結果は信用できない入力。ADR 0037)
		if err := c.putHours(ctx, q.Name, r, h, h.Add(time.Hour)); err != nil {
			return nil, err
		}
	}
	all, _, err := c.Parts.Parts(ctx, c.src.ID, q.Name, DayStart(from), to)
	return all, err
}

// queryHour は q を 1 時間 [h, h+1h) に流す。
//
// 決定 (ADR 0065。実データで直した): 初めから 1 時間ずつ流し、各時を 1 回だけ読む。行数の上限に当たっても範囲を割らない。
// 割ると、上限に当たるたびに同じ範囲を読み直し、読み取り量 (費用) が上がる (大きなアカウントの WAF で、36 時間を 1 本で流してから
// 18・9・4・2 時間と割って、2 時間でも上限に当たった)。上限に当たった時は、クエリの sort desc + limit で件数の多い組が残るので、
// その metric を truncated (下限) にする (日の頭から読むときに 1h まで割ってもなお当たったときと同じ扱い)
func (c *Collector) queryHour(ctx context.Context, q MergedQuery, h time.Time) ([]map[string]string, error) {
	end := h.Add(time.Hour)
	rows, err := c.Query(ctx, q.Query, h, c.queryEnd(end))
	c.stats.BytesScanned = c.scanned
	if err != nil {
		return nil, err
	}
	if len(rows) >= MaxRows {
		c.Logger.Warn("aggregate truncated at row limit; counts are lower bounds", "code", codes.AggregateTruncated, "source", c.src.ID, "query", q.Name,
			"metrics", strings.Join(q.Metrics, ","), "limit", MaxRows, "hour", h.Format(time.RFC3339), "rows_by_action", rowsByAction(rows))
		for _, m := range q.Metrics {
			c.stats.AddTruncated(m)
		}
	}
	return inRange(rows, q.Bin, end), nil
}

// rowsByAction は、上限に当たった結果の行を action ごとに数える (どの種類の行が上限を埋めたかを、軸を減らす判断に使う。人向けの属性)。
// action の軸を持たないクエリでは nil。
func rowsByAction(rows []map[string]string) map[string]int {
	var out map[string]int
	for _, r := range rows {
		a, ok := r["action"]
		if !ok {
			continue
		}
		if out == nil {
			out = map[string]int{}
		}
		if a == "" {
			a = "-"
		}
		out[a]++
	}
	return out
}

// putHours は行を時ごとに分けて部分の行として書く (行の無い時も空で書く)。
func (c *Collector) putHours(ctx context.Context, name string, rows []map[string]string, from, to time.Time) error {
	byHour := map[time.Time][]map[string]string{}
	for _, r := range rows {
		t, ok := rowTime(r)
		if !ok {
			continue
		}
		h := t.Truncate(time.Hour)
		byHour[h] = append(byHour[h], r)
	}
	days := c.PartRetentionDays
	if days == 0 {
		days = DefaultPartRetentionDays
	}
	for h := from; h.Before(to); h = h.Add(time.Hour) {
		// 決定 (実データで直した): 1 回の収集で読んでいる範囲 (その日の頭から) の部分の行は消さない。日の値はその日の全部の時の行から作るので、
		// 部分の行を残す日数より長い範囲を 1 回で読むと (collect --window 8d・追いつき)、後の時を書くときに前の日の行が消え、その日の値が空になった
		keep := days
		if !c.readFrom.IsZero() {
			if n := int(DayStart(h).Sub(c.readFrom)/(24*time.Hour)) + 1; n > keep {
				keep = n
			}
		}
		if err := c.Parts.PutParts(ctx, c.src.ID, name, h, byHour[h], keep); err != nil {
			return err
		}
	}
	return nil
}

// rowTime は行の時の軸 (集計の "day" = bin(1h)、endpoint の "t" = 時間幅) を読む。
func rowTime(r map[string]string) (time.Time, bool) {
	for _, k := range []string{"day", "t"} {
		if v, ok := r[k]; ok {
			if t, ok := parseTime(v); ok {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

// WAFRateHistQuery はレートの度数のクエリ (1 段目は WAFRateQuery と同じ。2 段目は n の度数)。
func WAFRateHistQuery(q string) string {
	i := strings.LastIndex(q, "\n| stats pct(")
	if i < 0 {
		return q
	}
	return q[:i] + "\n| stats count(*) as k by acl, grp, n"
}

// collectRateHourly は時ごとにレートの度数を引いて部分の行に残し、日の度数から waf_ip_rate_p50・p99・max を出す。
func (c *Collector) collectRateHourly(ctx context.Context, rate string, from, to time.Time, sink collect.RecordSink) error {
	q := WAFRateHistQuery(rate)
	for h := from; h.Before(to); h = h.Add(time.Hour) {
		rows, err := c.Query(ctx, q, h, c.queryEnd(h.Add(time.Hour)))
		c.stats.BytesScanned = c.scanned
		if err != nil {
			return err
		}
		stamp := h.Format("2006-01-02 15:04:05.000")
		for _, r := range rows {
			r["day"] = stamp
		}
		if err := c.putHours(ctx, wafRateHist, rows, h, h.Add(time.Hour)); err != nil {
			return err
		}
	}
	all, _, err := c.Parts.Parts(ctx, c.src.ID, wafRateHist, DayStart(from), to)
	if err != nil {
		return err
	}
	// 日 → acl|grp → n → 度数
	hist := map[string]map[string]map[float64]float64{}
	for _, r := range all {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		grp := r["grp"]
		if grp == "" {
			grp = RateGroupOther
		}
		key := r["acl"] + "|" + grp
		if hist[day] == nil {
			hist[day] = map[string]map[float64]float64{}
		}
		if hist[day][key] == nil {
			hist[day][key] = map[float64]float64{}
		}
		hist[day][key][num(r["n"])] += num(r["k"])
	}
	days := make([]string, 0, len(hist))
	for d := range hist {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, day := range days {
		keys := make([]string, 0, len(hist[day]))
		for k := range hist[day] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			p50, p99, mx := HistPercentiles(hist[day][key])
			for _, m := range []struct {
				name string
				v    float64
			}{{MetricWAFIPRateP50, p50}, {MetricWAFIPRateP99, p99}, {MetricWAFIPRateMax, mx}} {
				if err := sink.Emit(ctx, c.metric(day, m.name, key, m.v)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// HistPercentiles は度数 (値 → 件数) の 50・99 パーセンタイル (最も近い順位: 小さい方から数えて ceil(p × 件数) 番目) と最大を返す。
func HistPercentiles(h map[float64]float64) (p50, p99, max float64) {
	vals := make([]float64, 0, len(h))
	var total float64
	for v, k := range h {
		if k <= 0 {
			continue
		}
		vals = append(vals, v)
		total += k
	}
	if total == 0 {
		return 0, 0, 0
	}
	sort.Float64s(vals)
	at := func(p float64) float64 {
		rank := math.Ceil(p * total)
		var cum float64
		for _, v := range vals {
			cum += h[v]
			if cum >= rank {
				return v
			}
		}
		return vals[len(vals)-1]
	}
	return at(0.5), at(0.99), vals[len(vals)-1]
}

// emitSignInHourly は時ごとの sign-in の失敗の和を出す (metrics_hourly)。hours は時の印 ("2006-01-02 15:04:05.000" の形) → 件数。
func (c *Collector) emitSignInHourly(ctx context.Context, hours map[string]float64, sink collect.RecordSink) error {
	keys := make([]string, 0, len(hours))
	for k := range hours {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t, ok := parseTime(k)
		if !ok {
			continue
		}
		m := c.metric(t.Format(record.DateLayout), MetricSignInFailuresHourly, "", hours[k])
		m.Hour = t.Format(record.HourLayout)
		if err := sink.Emit(ctx, m); err != nil {
			return err
		}
	}
	return nil
}
