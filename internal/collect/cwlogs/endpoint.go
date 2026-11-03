package cwlogs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// endpoint_abuse (画面への分散した集中と「A のあと B」の連鎖) の日次集計 (ADR 0030)。key は `|` 区切り、時刻は UTC の HH:MM (時間幅の始まり)。
//
// 決定:
//   - Insights のクエリは endpoint ごとに 1 本。`(時間幅, IP, UA)` ごとの件数と最初・最後の時刻を返させ、件数・異なり IP・UA の広がり・連鎖を
//     Go で数える。指標ごとに分けると endpoint × 3 回スキャンするうえ、Insights の count_distinct は概数のため
//   - UA は結果を受け取った直後に sha256 の先頭 8 文字にし、原文は保存・ログ出力しない。UA が無い ("" / "-") 行は UA を数えない
//   - IP は保存しない (件数だけ)。リクエストの本文・クエリ・ヘッダーは引かない
//   - 1 回の結果は 10000 行まで。UTC の 1 日ずつ流し、上限に当たればその範囲を時間幅に揃えて半分に分けて引き直す (1h まで)。
//     それでも当たれば WARN と run の stats (truncated) に残す (件数の多い組が残り、1 件ずつの分散した集中は少なめに数える)
//   - パスの照合は glob を正規表現にして Insights で行う。Insights に正規表現の置換が無いので、NormalizePath と同じ意味の正規表現にする
//     (`:id` と数字だけの区間は数字か UUID、`*` は 1 区間、`**` は 0 区間以上。クエリ文字列は無視する)
//   - 連鎖は、from の画面の (時間幅, IP) の最初の時刻 f に対し、同じ IP の to の行で最後 > f かつ最初 <= f + within のものがあれば 1 と数える
//     (行は時間幅ごとにまとまっているので近似)。その IP の from の時間幅に数える。同じ問い合わせの範囲の中だけで突き合わせる
//   - 拡張: 集計の軸 (endpointGroupFields) にフィールドを足せば、行ごとの値として Go に渡る (メールのドメインなど。今は ip / ua だけ)
const (
	MetricEndpointCount  = "endpoint_abuse_count"  // key = <endpoint>|<HH:MM> (件数)
	MetricEndpointIPs    = "endpoint_abuse_ips"    // key = <endpoint>|<HH:MM> (異なり IP 数)
	MetricEndpointUAIPs  = "endpoint_abuse_ua_ips" // key = <endpoint>|<HH:MM>|<UA のハッシュ> (その幅で最も多くの IP にまたがった UA 1 つ。2 IP 以上のときだけ)
	MetricEndpointFollow = "endpoint_abuse_follow" // key = <from>><to>|<HH:MM> (from の幅のうち within 以内に to に来た異なり IP 数。1 以上のときだけ)
)

// endpointHits はクエリの件数の列名 (フェイクの振り分けにも使う)。
const endpointHits = "endpoint_hits"

// endpointTruncatedPrefix は行数の上限に当たった endpoint を FormatStats.Truncated に残すときの接頭辞。
const endpointTruncatedPrefix = "endpoint_abuse:"

// minSplit は上限に当たったときに分ける範囲の下限。
const minSplit = time.Hour

const idSegment = `([0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`

// EndpointPathRegex は glob を、Insights の /.../ にそのまま入れられ Go の regexp でも同じ意味になる正規表現にする。
// prefix (strip_path_prefix) はパターンの前に必須で付く。
func EndpointPathRegex(prefix, glob string) string {
	var b strings.Builder
	b.WriteString("^" + regexLiteral(prefix))
	segs := strings.Split(glob, "/")[1:] // 先頭の空を除く
	for _, s := range segs {
		switch {
		case s == "**":
			b.WriteString(`(\/[^\/?#]+)*`)
		case s == "*":
			b.WriteString(`\/[^\/?#]+`)
		case s == ":id" || numRe.MatchString(s) || uuidRe.MatchString(s):
			b.WriteString(`\/` + idSegment)
		default:
			parts := strings.Split(s, "*")
			for i, p := range parts {
				parts[i] = regexLiteral(p)
			}
			b.WriteString(`\/` + strings.Join(parts, `[^\/?#]*`))
		}
	}
	b.WriteString(`([?#].*)?$`)
	return b.String()
}

// EndpointQuery は endpoint 1 つ分のクエリ。
type EndpointQuery struct {
	Endpoint string
	Query    string
}

// endpointGroupFields は集計の軸 (時間幅の後ろ)。ip は必須、ua は形式が出すときだけ。
func endpointGroupFields(p Profile) []string {
	out := []string{"ip"}
	if p.Has("ua") {
		out = append(out, "ua")
	}
	return out
}

// EndpointQueries はソース srcID が数える endpoint のクエリ (設定順)。endpoints が空なら空。
func EndpointQueries(p Profile, srcID string, ea config.EndpointAbuse) []EndpointQuery {
	if p.Yields != record.KindHTTPAccess {
		return nil
	}
	bin := strconv.Itoa(int(ea.WindowDuration()/time.Minute)) + "m"
	var exclude string
	if len(ea.ExcludePaths) > 0 {
		exclude = "path not like /" + pathAlternation(p.StripPrefix, ea.ExcludePaths) + "/"
	}
	var out []EndpointQuery
	for _, ep := range ea.Endpoints {
		if len(ep.Sources) > 0 && !containsStr(ep.Sources, srcID) {
			continue
		}
		var paths []string
		for _, g := range ep.Paths {
			paths = append(paths, "path like /"+EndpointPathRegex(p.StripPrefix, g)+"/")
		}
		cond := and("("+strings.Join(paths, " or ")+")", inList("method", quoteAll(ep.Methods)), inList("status", intsToStrings(ep.Statuses)), exclude)
		q := p.Prelude + "\n| filter " + cond +
			"\n| stats count(*) as " + endpointHits + ", min(@timestamp) as first_seen, max(@timestamp) as last_seen by bin(" + bin + ") as t, " +
			strings.Join(endpointGroupFields(p), ", ") +
			"\n| sort " + endpointHits + " desc\n| limit " + strconv.Itoa(MaxRows)
		out = append(out, EndpointQuery{Endpoint: ep.Name, Query: q})
	}
	return out
}

func pathAlternation(prefix string, globs []string) string {
	parts := make([]string, len(globs))
	for i, g := range globs {
		parts[i] = EndpointPathRegex(prefix, g)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "|") + ")"
}

func containsStr(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// UAHash は User-Agent のハッシュ (sha256 の先頭 8 文字)。原文は残さない。
func UAHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(sum[:])[:8]
}

// endpointHit は結果の 1 行 (UA はハッシュにしたもの)。
type endpointHit struct {
	bin         time.Time
	ip, ua      string
	n           float64
	first, last time.Time
}

// collectEndpoints は endpoint_abuse 用の集計を流して metric を出す。
func (c *Collector) collectEndpoints(ctx context.Context, from, to time.Time, sink collect.RecordSink) error {
	ea := c.checks.EndpointAbuse
	qs := EndpointQueries(c.prof, c.src.ID, ea)
	if len(qs) == 0 {
		return nil
	}
	bin := ea.WindowDuration()
	hits := map[string][]endpointHit{}
	for _, q := range qs {
		for d := from; d.Before(to); d = DayStart(d).Add(24 * time.Hour) {
			end := DayStart(d).Add(24 * time.Hour)
			if end.After(to) {
				end = to
			}
			hs, err := c.endpointQuery(ctx, q, d, end, bin)
			if err != nil {
				return err
			}
			hits[q.Endpoint] = append(hits[q.Endpoint], hs...)
		}
	}
	for _, q := range qs {
		if err := c.emitEndpoint(ctx, sink, q.Endpoint, hits[q.Endpoint]); err != nil {
			return err
		}
	}
	for _, f := range ea.FollowUps {
		_, okFrom := hits[f.From]
		_, okTo := hits[f.To]
		if !okFrom || !okTo {
			continue
		}
		if err := c.emitFollow(ctx, sink, f, hits[f.From], hits[f.To]); err != nil {
			return err
		}
	}
	return nil
}

// endpointQuery は [from, to) を 1 本流し、行数の上限に当たれば時間幅に揃えて半分に分けて引き直す。
func (c *Collector) endpointQuery(ctx context.Context, q EndpointQuery, from, to time.Time, bin time.Duration) ([]endpointHit, error) {
	rows, err := c.Query(ctx, q.Query, from, to)
	c.stats.BytesScanned = c.scanned
	if err != nil {
		return nil, err
	}
	if len(rows) >= MaxRows {
		span := to.Sub(from)
		mid := from.Add(span / 2).Truncate(bin)
		if span > minSplit && mid.After(from) && mid.Before(to) {
			c.Logger.Info("endpoint aggregate hit row limit; splitting the range", "source", c.src.ID, "endpoint", q.Endpoint,
				"from", from.Format(time.RFC3339), "to", to.Format(time.RFC3339))
			a, err := c.endpointQuery(ctx, q, from, mid, bin)
			if err != nil {
				return nil, err
			}
			b, err := c.endpointQuery(ctx, q, mid, to, bin)
			if err != nil {
				return nil, err
			}
			return append(a, b...), nil
		}
		c.Logger.Warn("endpoint aggregate truncated at row limit; counts are lower bounds", "source", c.src.ID, "endpoint", q.Endpoint, "limit", MaxRows)
		c.stats.AddTruncated(endpointTruncatedPrefix + q.Endpoint)
	}
	out := make([]endpointHit, 0, len(rows))
	for _, r := range rows {
		t, ok := parseTime(r["t"])
		if !ok || r["ip"] == "" {
			continue
		}
		h := endpointHit{bin: t, ip: r["ip"], n: num(r[endpointHits])}
		h.first, _ = parseTime(r["first_seen"])
		h.last, _ = parseTime(r["last_seen"])
		if ua := r["ua"]; ua != "" && ua != "-" {
			h.ua = UAHash(ua)
		}
		out = append(out, h)
	}
	return out, nil
}

func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func binKey(t time.Time) (day, hm string) {
	return t.Format(record.DateLayout), t.Format("15:04")
}

type binAgg struct {
	n   float64
	ips map[string]bool
	ua  map[string]map[string]bool
}

func (c *Collector) emitEndpoint(ctx context.Context, sink collect.RecordSink, name string, hits []endpointHit) error {
	bins := map[time.Time]*binAgg{}
	for _, h := range hits {
		a := bins[h.bin]
		if a == nil {
			a = &binAgg{ips: map[string]bool{}, ua: map[string]map[string]bool{}}
			bins[h.bin] = a
		}
		a.n += h.n
		a.ips[h.ip] = true
		if h.ua != "" {
			if a.ua[h.ua] == nil {
				a.ua[h.ua] = map[string]bool{}
			}
			a.ua[h.ua][h.ip] = true
		}
	}
	for _, t := range sortedTimes(bins) {
		a := bins[t]
		day, hm := binKey(t)
		key := name + "|" + hm
		if err := sink.Emit(ctx, c.metric(day, MetricEndpointCount, key, a.n)); err != nil {
			return err
		}
		if err := sink.Emit(ctx, c.metric(day, MetricEndpointIPs, key, float64(len(a.ips)))); err != nil {
			return err
		}
		top, topN := "", 0
		for ua, ips := range a.ua {
			if len(ips) > topN || (len(ips) == topN && ua < top) {
				top, topN = ua, len(ips)
			}
		}
		if topN >= 2 {
			if err := sink.Emit(ctx, c.metric(day, MetricEndpointUAIPs, key+"|"+top, float64(topN))); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Collector) emitFollow(ctx context.Context, sink collect.RecordSink, f config.FollowUp, from, to []endpointHit) error {
	within := f.WithinDuration()
	type span struct{ first, last time.Time }
	toByIP := map[string][]span{}
	for _, h := range to {
		toByIP[h.ip] = append(toByIP[h.ip], span{h.first, h.last})
	}
	// (時間幅, IP) ごとの from の最初の時刻
	type binIP struct {
		bin time.Time
		ip  string
	}
	firsts := map[binIP]time.Time{}
	for _, h := range from {
		k := binIP{h.bin, h.ip}
		if cur, ok := firsts[k]; !ok || h.first.Before(cur) {
			firsts[k] = h.first
		}
	}
	counts := map[time.Time]float64{}
	for k, first := range firsts {
		for _, s := range toByIP[k.ip] {
			if s.last.After(first) && !s.first.After(first.Add(within)) {
				counts[k.bin]++
				break
			}
		}
	}
	for _, t := range sortedTimes(counts) {
		day, hm := binKey(t)
		if err := sink.Emit(ctx, c.metric(day, MetricEndpointFollow, f.From+">"+f.To+"|"+hm, counts[t])); err != nil {
			return err
		}
	}
	return nil
}

func sortedTimes[T any](m map[time.Time]T) []time.Time {
	out := make([]time.Time, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}
