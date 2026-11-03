package checks

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// EndpointAbuse は画面 (会員登録・メッセージ送信など) への多数の IP からの短時間の集中と、「A の画面のあと B の画面」の連鎖を、
// ふだんと比べて報告する (ADR 0030)。材料は cwlogs の endpoint_abuse_* の日次集計 (時間幅ごと)。
//
// 決定:
//   - 結果は事実 (件数・異なり IP・同じ UA の広がり・ふだんの上限) として伝え、遮断の提案にしない。重大度は medium まで
//   - 分散した集中: 幅の異なり IP 数が min_distinct_ips 以上かつ平常帯 × factor を超える → medium。
//     量: 幅の件数が min_count 以上かつ平常帯 × factor を超える → low (両方なら 1 件にまとめて medium)。
//     同じ UA の広がり: 根拠に添えるだけ (単独では報告しない)。連鎖: 異なり IP 数が min_ips 以上かつ平常帯 × factor を超える → medium
//   - 平常帯は評価する最初の日の前日から baseline_days 日のうち、ログを収集した日 (http_access のソースの lines_total のある日) の
//     全部の幅 (値の無い幅は 0) の p99。収集した日が min_baseline_days 未満の間は平常帯を使わず、絶対の閾値 (min_*) だけで判定する。
//     lines_total はロググループ全体の行数なので、画面に来ない日も「収集した日」として数える (ADR 0027 の「収集し終えた日」の考え方)
//   - 評価する幅は終わりが窓 (From, To] に入るもの (完了した幅を 1 回だけ)。連鎖は幅の終わり + within が窓に入るもの (to に来るのを待つ)
//   - 報告は run ごとに endpoint 1 件 (key = endpoint 名) と連鎖 1 件 (key = from>to)。Summary は最も異なり IP の多い幅、
//     超えた幅の一覧は Data の bins (最大 maxAbuseBins)。Fingerprint は重大度と理由だけ (別の日の再発は recurred)
//   - IP は保存していないので出さない。UA はハッシュの先頭 8 文字と IP 数だけ
type EndpointAbuse struct {
	Config config.EndpointAbuse
}

func (EndpointAbuse) Name() string         { return "endpoint_abuse" }
func (EndpointAbuse) Cadence() Cadence     { return Daily }
func (EndpointAbuse) Mode() Mode           { return ModeEvent }
func (EndpointAbuse) Needs() []record.Kind { return []record.Kind{record.KindHTTPAccess} }

const maxAbuseBins = 10

// endpoint_abuse の理由 (Data の reasons)。
const (
	reasonDistributed = "distributed_burst"
	reasonVolume      = "volume"
	reasonSameUA      = "same_user_agent"
	reasonFollowUp    = "follow_up"
)

// abuseSeries は metric → 日 → key → 値。
type abuseSeries map[string]series

func (c EndpointAbuse) Evaluate(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, error) {
	ea := c.Config
	if len(ea.Endpoints) == 0 {
		return nil, nil
	}
	bin := ea.WindowDuration()
	if bin <= 0 {
		return nil, fmt.Errorf("endpoint_abuse: invalid window %q", ea.Window)
	}
	var maxWithin time.Duration
	for _, f := range ea.FollowUps {
		maxWithin = max(maxWithin, f.WithinDuration())
	}
	first := dayOf(w.From.Add(-bin - maxWithin))
	last := dayOf(w.To.Add(-time.Nanosecond))
	day0 := first.Format(record.DateLayout)
	bds := baseDates(day0, ea.BaselineDays)
	from, to := addDays(day0, -ea.BaselineDays), last.Format(record.DateLayout)

	collectedDays, err := httpCollectedDays(ctx, q, bds)
	if err != nil {
		return nil, err
	}
	useBaseline := len(collectedDays) >= ea.MinBaselineDays && len(collectedDays) > 0
	s := abuseSeries{}
	for _, m := range []string{cwlogs.MetricEndpointCount, cwlogs.MetricEndpointIPs, cwlogs.MetricEndpointUAIPs, cwlogs.MetricEndpointFollow} {
		if s[m], err = loadSeries(ctx, q, m, from, to); err != nil {
			return nil, err
		}
	}
	perDay := int(24 * time.Hour / bin)
	base := baselineOf{days: collectedDays, perDay: perDay, use: useBaseline}

	var obs []Observation
	for _, ep := range ea.Endpoints {
		if o, ok := c.evalEndpoint(ep.Name, s, base, w, first, last, bin); ok {
			obs = append(obs, o)
		}
	}
	for _, f := range ea.FollowUps {
		if o, ok := c.evalFollow(f, s, base, w, first, last, bin); ok {
			obs = append(obs, o)
		}
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Key < obs[j].Key })
	return obs, nil
}

// httpCollectedDays は dates のうち、http_access のソースの lines_total (ログの総行数) がある日。
func httpCollectedDays(ctx context.Context, q store.Query, dates []string) ([]string, error) {
	if len(dates) == 0 {
		return nil, nil
	}
	lo, hi := dates[0], dates[0]
	for _, d := range dates {
		lo, hi = min(lo, d), max(hi, d)
	}
	ms, err := q.Metrics(ctx, store.MetricFilter{Metric: cwlogs.MetricLinesTotal, From: lo, To: hi})
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, m := range ms {
		if m.From == record.KindHTTPAccess && m.Value > 0 {
			has[m.Date] = true
		}
	}
	var out []string
	for _, d := range dates {
		if has[d] {
			out = append(out, d)
		}
	}
	return out, nil
}

// baselineOf は平常帯の材料 (収集した過去日と 1 日の幅の数)。
type baselineOf struct {
	days   []string
	perDay int
	use    bool
}

// p99 は key の接頭辞 prefix (`<endpoint>|`) の、収集した過去日の全部の幅の値の p99 (値の無い幅は 0)。
// pick は 1 つの幅に複数の key があるとき (UA のハッシュ違い) に値を選ぶ (最大)。
func (b baselineOf) p99(sr series, prefix string) float64 {
	if !b.use {
		return 0
	}
	var vals []float64
	for _, d := range b.days {
		perBin := map[string]float64{}
		for k, v := range sr[d] {
			rest, ok := strings.CutPrefix(k, prefix)
			if !ok {
				continue
			}
			hm, _, _ := strings.Cut(rest, "|")
			perBin[hm] = max(perBin[hm], v)
		}
		for _, v := range perBin {
			vals = append(vals, v)
		}
		for i := len(perBin); i < b.perDay; i++ {
			vals = append(vals, 0)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	idx := int(math.Ceil(0.99*float64(len(vals)))) - 1
	return vals[max(idx, 0)]
}

// binsIn は first〜last の日の、prefix の key を持つ幅の始まりと値 (同じ幅に複数の key があれば最大と、そのときの key の残り)。
type binVal struct {
	start time.Time
	v     float64
	tail  string // key の HH:MM より後ろ (UA のハッシュ)
}

func binsIn(sr series, prefix string, first, last time.Time) map[time.Time]binVal {
	out := map[time.Time]binVal{}
	for d := first; !d.After(last); d = d.AddDate(0, 0, 1) {
		for k, v := range sr[d.Format(record.DateLayout)] {
			rest, ok := strings.CutPrefix(k, prefix)
			if !ok {
				continue
			}
			hm, tail, _ := strings.Cut(rest, "|")
			t, err := time.Parse("15:04", hm)
			if err != nil {
				continue
			}
			start := d.Add(time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute)
			if cur, ok := out[start]; !ok || v > cur.v || (v == cur.v && tail < cur.tail) {
				out[start] = binVal{start: start, v: v, tail: tail}
			}
		}
	}
	return out
}

// above は v が下限以上かつ平常帯 × factor を超えるか。
func above(v, minimum, p99, factor float64) bool {
	return v >= minimum && v > p99*factor
}

func inWindow(end time.Time, w collect.Window) bool {
	return end.After(w.From) && !end.After(w.To)
}

func hm(t time.Time) string { return t.UTC().Format("15:04") }

func (c EndpointAbuse) evalEndpoint(name string, s abuseSeries, base baselineOf, w collect.Window, first, last time.Time, bin time.Duration) (Observation, bool) {
	ea := c.Config
	prefix := name + "|"
	p99IPs := base.p99(s[cwlogs.MetricEndpointIPs], prefix)
	p99Count := base.p99(s[cwlogs.MetricEndpointCount], prefix)
	p99UA := base.p99(s[cwlogs.MetricEndpointUAIPs], prefix)
	ips := binsIn(s[cwlogs.MetricEndpointIPs], prefix, first, last)
	counts := binsIn(s[cwlogs.MetricEndpointCount], prefix, first, last)
	uas := binsIn(s[cwlogs.MetricEndpointUAIPs], prefix, first, last)

	type hitBin struct {
		start              time.Time
		count, ips, uaIPs  float64
		ua                 string
		dist, volume, same bool
	}
	starts := map[time.Time]bool{}
	for t := range ips {
		starts[t] = true
	}
	for t := range counts {
		starts[t] = true
	}
	var hits []hitBin
	for t := range starts {
		if !inWindow(t.Add(bin), w) {
			continue
		}
		h := hitBin{start: t, count: counts[t].v, ips: ips[t].v}
		h.dist = above(h.ips, ea.MinDistinctIPs, p99IPs, ea.Factor)
		h.volume = above(h.count, ea.MinCount, p99Count, ea.Factor)
		if !h.dist && !h.volume {
			continue
		}
		if u, ok := uas[t]; ok && above(u.v, ea.UAConcentration.MinIPs, p99UA, ea.Factor) {
			h.same, h.uaIPs, h.ua = true, u.v, u.tail
		}
		hits = append(hits, h)
	}
	if len(hits) == 0 {
		return Observation{}, false
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].start.Before(hits[j].start) })
	peak := hits[0]
	reasons := map[string]bool{}
	for _, h := range hits {
		if h.ips > peak.ips || (h.ips == peak.ips && h.count > peak.count) {
			peak = h
		}
		reasons[reasonDistributed] = reasons[reasonDistributed] || h.dist
		reasons[reasonVolume] = reasons[reasonVolume] || h.volume
		reasons[reasonSameUA] = reasons[reasonSameUA] || h.same
	}
	sev := Low
	if reasons[reasonDistributed] {
		sev = Medium
	}
	var bins []map[string]any
	for i, h := range hits {
		if i >= maxAbuseBins {
			break
		}
		b := map[string]any{"start": h.start.Format(time.RFC3339), "count": h.count, "distinct_ips": h.ips}
		if h.same {
			b["ua_hash"], b["ua_ips"] = h.ua, h.uaIPs
		}
		bins = append(bins, b)
	}
	summary := fmt.Sprintf("%s: %s %s〜%s UTC に %.0f 件、異なり IP %.0f", name, peak.start.Format(record.DateLayout), hm(peak.start), hm(peak.start.Add(bin)), peak.count, peak.ips)
	if base.use {
		summary += fmt.Sprintf(" (ふだんの上限 %.0f IP・%.0f 件)", p99IPs, p99Count)
	} else {
		summary += fmt.Sprintf(" (平常帯は未確立: ログを収集した過去日 %d 日。絶対の閾値で判定)", len(base.days))
	}
	if peak.same {
		summary += fmt.Sprintf("、同じ UA が %.0f IP", peak.uaIPs)
	}
	if len(hits) > 1 {
		summary += fmt.Sprintf("。閾値を超えた幅は %d 個", len(hits))
	}
	data := map[string]any{
		"endpoint": name, "window": ea.Window, "date": peak.start.Format(record.DateLayout),
		"bin_start": peak.start.Format(time.RFC3339), "bin_end": peak.start.Add(bin).Format(time.RFC3339),
		"count": peak.count, "distinct_ips": peak.ips,
		"baseline_p99_ips": p99IPs, "baseline_p99_count": p99Count, "baseline_p99_ua_ips": p99UA,
		"min_distinct_ips": ea.MinDistinctIPs, "min_count": ea.MinCount, "factor": ea.Factor,
		"baseline_used": base.use, "baseline_days_collected": len(base.days),
		"reasons": orderedReasons(reasons, reasonDistributed, reasonVolume, reasonSameUA),
		"bins":    bins, "bins_total": len(hits),
	}
	if peak.same {
		data["ua_hash"], data["ua_ips"] = peak.ua, peak.uaIPs
	}
	return Observation{Check: c.Name(), Key: name, Severity: sev, Summary: summary, Data: data,
		Fingerprint: fingerprint(sev, nil, strings.Join(orderedReasons(reasons, reasonDistributed, reasonVolume, reasonSameUA), ","))}, true
}

func (c EndpointAbuse) evalFollow(f config.FollowUp, s abuseSeries, base baselineOf, w collect.Window, first, last time.Time, bin time.Duration) (Observation, bool) {
	ea := c.Config
	pair := f.From + ">" + f.To
	within := f.WithinDuration()
	p99 := base.p99(s[cwlogs.MetricEndpointFollow], pair+"|")
	var hits []binVal
	for t, v := range binsIn(s[cwlogs.MetricEndpointFollow], pair+"|", first, last) {
		if inWindow(t.Add(bin+within), w) && above(v.v, f.MinIPs, p99, ea.Factor) {
			hits = append(hits, v)
		}
	}
	if len(hits) == 0 {
		return Observation{}, false
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].start.Before(hits[j].start) })
	peak := hits[0]
	var bins []map[string]any
	for i, h := range hits {
		if h.v > peak.v {
			peak = h
		}
		if i < maxAbuseBins {
			bins = append(bins, map[string]any{"start": h.start.Format(time.RFC3339), "ips": h.v})
		}
	}
	summary := fmt.Sprintf("%s のあと %s: %s %s〜%s UTC に %s に来た IP のうち %.0f IP が %s 以内に %s に来た",
		f.From, f.To, peak.start.Format(record.DateLayout), hm(peak.start), hm(peak.start.Add(bin)), f.From, peak.v, f.Within, f.To)
	if base.use {
		summary += fmt.Sprintf(" (ふだんの上限 %.0f IP)", p99)
	} else {
		summary += fmt.Sprintf(" (平常帯は未確立: ログを収集した過去日 %d 日。絶対の閾値で判定)", len(base.days))
	}
	if len(hits) > 1 {
		summary += fmt.Sprintf("。閾値を超えた幅は %d 個", len(hits))
	}
	data := map[string]any{
		"from": f.From, "to": f.To, "within": f.Within, "window": ea.Window, "date": peak.start.Format(record.DateLayout),
		"bin_start": peak.start.Format(time.RFC3339), "bin_end": peak.start.Add(bin).Format(time.RFC3339), "ips": peak.v,
		"baseline_p99_ips": p99, "min_ips": f.MinIPs, "factor": ea.Factor,
		"baseline_used": base.use, "baseline_days_collected": len(base.days),
		"reasons": []string{reasonFollowUp}, "bins": bins, "bins_total": len(hits),
	}
	return Observation{Check: c.Name(), Key: pair, Severity: Medium, Summary: summary, Data: data,
		Fingerprint: fingerprint(Medium, nil, reasonFollowUp)}, true
}

func orderedReasons(set map[string]bool, order ...string) []string {
	var out []string
	for _, r := range order {
		if set[r] {
			out = append(out, r)
		}
	}
	return out
}
