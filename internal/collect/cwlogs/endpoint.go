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
	return "^" + regexLiteral(prefix) + strings.Join(globParts(glob), "") + endpointSuffix
}

// endpointSuffix はクエリ文字列とフラグメントを無視する末尾。
const endpointSuffix = `([?#].*)?$`

// globParts は glob の区間ごとの正規表現。`**` 以外は必ず `\/` で始まる。
func globParts(glob string) []string {
	var out []string
	for _, s := range strings.Split(glob, "/")[1:] { // 先頭の空を除く
		switch {
		case s == "**":
			out = append(out, `(\/[^\/?#]+)*`)
		case s == "*":
			out = append(out, `\/[^\/?#]+`)
		case s == ":id" || numRe.MatchString(s) || uuidRe.MatchString(s):
			out = append(out, `\/`+idSegment)
		default:
			parts := strings.Split(s, "*")
			for i, p := range parts {
				parts[i] = regexLiteral(p)
			}
			out = append(out, `\/`+strings.Join(parts, `[^\/?#]*`))
		}
	}
	return out
}

// endpointGroupFields は集計の軸 (時間幅の後ろ)。ip は必須、ua は形式が出すときだけ。
func endpointGroupFields(p Profile) []string {
	out := []string{"ip"}
	if p.Has("ua") {
		out = append(out, "ua")
	}
	return out
}

// endpointAbuse はまとめた endpoint のクエリの名前。
const endpointAbuse = "endpoint_abuse"

// endpointSpec はソースが数える画面 1 つと、そのパスの glob ごとの印のフィールド (parse の名前付き捕獲)。
type endpointSpec struct {
	ep    config.AbuseEndpoint
	flags []string
}

// endpointSpecs はソース srcID が数える画面 (設定順)。http_access 以外・endpoints が空なら空。
func endpointSpecs(p Profile, srcID string, ea config.EndpointAbuse) []endpointSpec {
	if p.Yields != record.KindHTTPAccess {
		return nil
	}
	var out []endpointSpec
	for i, ep := range ea.Endpoints {
		if len(ep.Sources) > 0 && !containsStr(ep.Sources, srcID) {
			continue
		}
		s := endpointSpec{ep: ep}
		for j := range ep.Paths {
			s.flags = append(s.flags, "ep"+strconv.Itoa(i)+"_"+strconv.Itoa(j))
		}
		out = append(out, s)
	}
	return out
}

// flagRegex は glob に一致したときだけ flag に先頭の "/" を捕獲する parse 用の正規表現 (EndpointPathRegex と同じ行に一致する)。
// 捕獲は常に "/" なので group by の行は増えない。中のグループは名前付きにする (parse は名前付きの捕獲をフィールドにする。
// 名前の無いグループを parse に入れたときの扱いに頼らない)。
// 先頭の "/" を捕獲に回すため、先頭の `**` (`(\/s)*\/next`) は同じ意味の `\/(s\/)*next` に書き換える (空のパスには一致しない)。
func flagRegex(flag, prefix, glob string) string {
	parts := globParts(glob)
	var body string
	switch {
	case prefix != "":
		body = strings.TrimPrefix(regexLiteral(prefix), `\/`) + strings.Join(parts, "")
	default:
		k := 0
		for k < len(parts) && strings.HasPrefix(parts[k], "(") {
			k++
		}
		if k == len(parts) {
			body = `[^\/?#]+(\/[^\/?#]+)*`
		} else {
			body = strings.Repeat(`([^\/?#]+\/)*`, k) + strings.TrimPrefix(parts[k], `\/`) + strings.Join(parts[k+1:], "")
		}
	}
	body += endpointSuffix
	var b strings.Builder
	b.WriteString("^(?<" + flag + `>\/)`)
	g := 0
	for i := 0; i < len(body); i++ {
		switch {
		case body[i] == '\\' && i+1 < len(body):
			b.WriteString(body[i : i+2])
			i++
		case body[i] == '(' && (i+1 >= len(body) || body[i+1] != '?'):
			g++
			b.WriteString("(?<" + flag + "_g" + strconv.Itoa(g) + ">")
		default:
			b.WriteByte(body[i])
		}
	}
	return b.String()
}

// EndpointsQuery はソース srcID が数える全画面のクエリ (1 本)。endpoints が空なら ok = false。
//
// 決定 (ADR 0031): 画面ごとに 1 本流すと画面の数だけ範囲を読むので、1 本にまとめる。filter は画面ごとの条件の和、
// group by は (時間幅, IP, UA) に、method・status (条件に使う画面があるとき) と glob ごとの印を足し、Go で画面に振り分ける。
// 除外のパスは全画面に共通なので filter だけで外す。
func EndpointsQuery(p Profile, srcID string, ea config.EndpointAbuse) (MergedQuery, bool) {
	specs := endpointSpecs(p, srcID, ea)
	if len(specs) == 0 {
		return MergedQuery{}, false
	}
	bin := strconv.Itoa(int(ea.WindowDuration()/time.Minute)) + "m"
	var exclude string
	if len(ea.ExcludePaths) > 0 {
		exclude = "path not like /" + pathAlternation(p.StripPrefix, ea.ExcludePaths) + "/"
	}
	var conds, parses, metrics []string
	group := endpointGroupFields(p)
	methods, statuses := false, false
	var flags []string
	for _, s := range specs {
		var paths []string
		for j, g := range s.ep.Paths {
			re := EndpointPathRegex(p.StripPrefix, g)
			paths = append(paths, "path like /"+re+"/")
			parses = append(parses, "\n| parse path /"+flagRegex(s.flags[j], p.StripPrefix, g)+"/")
		}
		conds = append(conds, "("+and("("+strings.Join(paths, " or ")+")", inList("method", quoteAll(s.ep.Methods)), inList("status", intsToStrings(s.ep.Statuses)))+")")
		methods = methods || len(s.ep.Methods) > 0
		statuses = statuses || len(s.ep.Statuses) > 0
		flags = append(flags, s.flags...)
		metrics = append(metrics, endpointTruncatedPrefix+s.ep.Name)
	}
	if methods {
		group = append(group, "method")
	}
	if statuses {
		group = append(group, "status")
	}
	group = append(group, flags...)
	cond := strings.Join(conds, " or ")
	if exclude != "" {
		cond = "(" + cond + ") and " + exclude
	}
	q := p.Prelude + "\n| filter " + cond + strings.Join(parses, "") +
		"\n| stats count(*) as " + endpointHits + ", min(@timestamp) as first_seen, max(@timestamp) as last_seen by bin(" + bin + ") as t, " +
		strings.Join(group, ", ") +
		"\n| sort " + endpointHits + " desc\n| limit " + strconv.Itoa(MaxRows)
	return MergedQuery{Name: endpointAbuse, Query: q, Metrics: metrics}, true
}

// matches は結果の行がこの画面の条件 (glob のどれか・method・status) に当たるか。
func (s endpointSpec) matches(r map[string]string) bool {
	hit := false
	for _, f := range s.flags {
		hit = hit || r[f] != ""
	}
	return hit && (len(s.ep.Methods) == 0 || containsStr(s.ep.Methods, r["method"])) && statusIn(r["status"], s.ep.Statuses)
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

// collectEndpoints は endpoint_abuse 用の集計 (EndpointsQuery) を流して metric を出す。
func (c *Collector) collectEndpoints(ctx context.Context, q MergedQuery, from, to time.Time, sink collect.RecordSink) error {
	ea := c.checks.EndpointAbuse
	specs := endpointSpecs(c.prof, c.src.ID, ea)
	rows, err := c.splitQuery(ctx, q, from, to, ea.WindowDuration(), true)
	if err != nil {
		return err
	}
	hits := map[string][]endpointHit{}
	for _, s := range specs {
		hits[s.ep.Name] = nil
	}
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
		for _, s := range specs {
			if s.matches(r) {
				hits[s.ep.Name] = append(hits[s.ep.Name], h)
			}
		}
	}
	for _, s := range specs {
		if err := c.emitEndpoint(ctx, sink, s.ep.Name, hits[s.ep.Name]); err != nil {
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
