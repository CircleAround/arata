package cwlogs

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// wafv2 の日次集計のうち waf_review (WAF の修正提案の候補) が使うもの (ADR 0023)。key は `|` 区切り。
//
// 決定:
//   - 生ログ・ヘッダー・クエリ文字列・Cookie・User-Agent・本文は引かない。集計の結果 (件数・異なり IP 数・p50 など) だけを保存する
//   - パスはクエリ (`?` 以降) を落とし、数字だけ・UUID の区間を `:id` にしてから合算する (Insights に正規表現の置換が無いので Go 側で行う)。
//     そのため Insights では (パス, IP) で集計し、Go で正規化してから異なり IP を数える。生パスごとの異なり IP を足すと、
//     1 IP が /items/1..500 を列挙したときに 500 IP と数え、攻撃を「誤検知の疑い」と取り違えるため
//   - 1 回の結果は 10000 行まで。超えたら件数の多い組だけが残り (少なめに数える。候補は出にくい側に倒れる)、WARN と run の stats に残す
//   - 正規の送信元 (checks.waf_review.trusted_cidrs) は waf_rule_action 以外の集計から外す。waf_rule_action は「使われていないルール」の判定に使うので外さない
const (
	MetricWAFRuleAction        = "waf_rule_action"              // key = <WebACL>|<終了ルール>|<action>
	MetricWAFBlockPath         = "waf_block_path"               // key = <WebACL>|<ルール>|<method>|<正規化パス> (件数)
	MetricWAFBlockPathIPs      = "waf_block_path_ips"           // 同じ key の異なり IP 数
	MetricWAFAllowProbe        = "waf_allow_probe"              // key = <WebACL>|<正規化パス> (許可された探索の件数)
	MetricWAFAllowProbeIPs     = "waf_allow_probe_ips"          // 同じ key の異なり IP 数
	MetricWAFCountMatch        = "waf_rule_count_match"         // key = <WebACL>|<ルール> (カウントモードの一致)
	MetricWAFCountMatchSuspect = "waf_rule_count_match_suspect" // 同じ key のうち探索パスか、その日 BLOCK された IP からの一致
	MetricWAFIPRateP50         = "waf_ip_rate_p50"              // key = <WebACL>|<パスの群> (1 IP あたり 5 分間の件数)
	MetricWAFIPRateP99         = "waf_ip_rate_p99"
	MetricWAFIPRateMax         = "waf_ip_rate_max"
)

// RateGroupOther は rate_path_groups のどれにも当たらないパスの群の名前。
const RateGroupOther = "*"

// カウントの一致を数える配列の位置の上限 (Insights は JSON の配列を `name.0.field` に平坦化する)。
// 決定: トップレベルの nonTerminatingMatchingRules は先頭 3 個、ruleGroupList は先頭 5 グループの先頭 1 個を見る。
// これを超える位置の一致は数え漏れる (1 リクエストが 4 つ以上の COUNT ルールに同時に当たることは少ない)。
const (
	countTopPositions   = 3
	countGroupPositions = 5
)

// WAFQuery は wafv2 の集計 1 本。PerDay なら UTC の 1 日ずつ流す (2 段の stats で日を切らないため)。
type WAFQuery struct {
	Name   string
	Query  string
	PerDay bool
}

// WAFQueries は wafv2 ソースの waf_review 用の集計クエリ。前処理の後ろに WebACL 名の取り出しを付ける。
func WAFQueries(p Profile, c config.Checks) []WAFQuery {
	head := p.Prelude + "\n" + `| parse webaclId /webacl\/(?<acl>[^\/]+)\//`
	trusted := trustedFilter(c.WAFReview.TrustedCIDRs)
	pp := c.ProbePaths
	probe := "path like /^(" + prefixAlternation(pp.Paths) + ")/"
	notProbe := "path not like /^(" + prefixAlternation(pp.Paths) + ")/"
	if len(pp.ExcludePaths) > 0 {
		ex := prefixAlternation(pp.ExcludePaths)
		probe = and(probe, "path not like /^("+ex+")/")
		notProbe = "(" + notProbe + " or path like /^(" + ex + ")/)"
	}
	tail := func(metric string) string {
		return "\n| sort " + metric + " desc\n| limit " + strconv.Itoa(MaxRows)
	}
	filter := func(conds ...string) string {
		if f := and(conds...); f != "" {
			return "\n| filter " + f
		}
		return ""
	}

	ruleAction := head + "\n| stats count(*) as " + MetricWAFRuleAction + " by bin(1d) as day, acl, rule, action" + tail(MetricWAFRuleAction)

	blockPath := head + filter(`action = "BLOCK"`, notProbe, trusted) +
		"\n" + `| parse @message /"terminatingRule":\{"ruleId":"(?<inner>[^"]+)"/` +
		"\n" + `| parse @message /"terminatingRule":\{"ruleId":"[^"]+".*"terminatingRule":\{"ruleId":"(?<inner2>[^"]+)"/` +
		"\n| stats count(*) as " + MetricWAFBlockPath + " by bin(1d) as day, acl, rule, inner, inner2, method, path, ip" + tail(MetricWAFBlockPath)

	allowProbe := head + filter(`action = "ALLOW"`, probe, trusted) +
		"\n| stats count(*) as " + MetricWAFAllowProbe + " by bin(1d) as day, acl, path, ip" + tail(MetricWAFAllowProbe)

	fields := countFields()
	var present []string
	for _, f := range fields {
		if strings.HasSuffix(f, ".ruleId") {
			present = append(present, "ispresent("+f+")")
		}
	}
	count := head + filter("("+strings.Join(present, " or ")+")", trusted) +
		"\n| parse path /^(?<probe>" + prefixAlternation(pp.Paths) + ")/"
	group := "day, acl, " + strings.Join(fields, ", ") + ", probe, "
	if len(pp.ExcludePaths) > 0 {
		count += "\n| parse path /^(?<probe_ex>" + prefixAlternation(pp.ExcludePaths) + ")/"
		group += "probe_ex, "
	}
	count += "\n| stats count(*) as " + MetricWAFCountMatch + " by bin(1d) as " + group + "ip" + tail(MetricWAFCountMatch)

	groups := append([]string(nil), c.WAFReview.RatePathGroups...)
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i]) > len(groups[j]) }) // 最長一致
	rate := head + filter(trusted) +
		"\n| parse path /^(?<grp>" + prefixAlternation(groups) + ")/" +
		"\n| stats count(*) as n by bin(5m) as t, acl, grp, ip" +
		"\n| stats pct(n, 50) as " + MetricWAFIPRateP50 + ", pct(n, 99) as " + MetricWAFIPRateP99 + ", max(n) as " + MetricWAFIPRateMax + " by acl, grp"

	return []WAFQuery{
		{Name: MetricWAFRuleAction, Query: ruleAction},
		{Name: MetricWAFBlockPath, Query: blockPath},
		{Name: MetricWAFAllowProbe, Query: allowProbe},
		{Name: MetricWAFCountMatch, Query: count},
		{Name: "waf_ip_rate", Query: rate, PerDay: true},
	}
}

// countFields はカウントの一致を見る平坦化されたフィールド (トップレベルのルール ID、グループ ID とその中のルール ID)。
func countFields() []string {
	var out []string
	for i := 0; i < countTopPositions; i++ {
		out = append(out, "nonTerminatingMatchingRules."+strconv.Itoa(i)+".ruleId")
	}
	for i := 0; i < countGroupPositions; i++ {
		g := "ruleGroupList." + strconv.Itoa(i)
		out = append(out, g+".ruleGroupId", g+".nonTerminatingMatchingRules.0.ruleId")
	}
	return out
}

func trustedFilter(cidrs []string) string {
	var parts []string
	for _, c := range cidrs {
		parts = append(parts, "not isIpInSubnet(ip, "+stringLiteral(c)+")")
	}
	return strings.Join(parts, " and ")
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numRe  = regexp.MustCompile(`^[0-9]+$`)
)

// NormalizePath はパスからクエリとフラグメントを落とし、数字だけ・UUID の区間を `:id` にし、メールアドレスらしき文字列を伏せる。
func NormalizePath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if numRe.MatchString(s) || uuidRe.MatchString(s) {
			segs[i] = ":id"
		}
	}
	return Mask(strings.Join(segs, "/"))
}

// pathAgg は正規化した key ごとの件数と IP の集合。
type pathAgg map[string]map[string]*struct {
	n   float64
	ips map[string]bool
}

func (a pathAgg) add(day, key, ip string, n float64) {
	if a[day] == nil {
		a[day] = map[string]*struct {
			n   float64
			ips map[string]bool
		}{}
	}
	v := a[day][key]
	if v == nil {
		v = &struct {
			n   float64
			ips map[string]bool
		}{ips: map[string]bool{}}
		a[day][key] = v
	}
	v.n += n
	if ip != "" {
		v.ips[ip] = true
	}
}

// emitTop は日ごとに件数の多い順に top 個の key の件数と異なり IP 数を出す。
func (c *Collector) emitTop(ctx context.Context, sink collect.RecordSink, a pathAgg, top int, count, ips string) error {
	days := make([]string, 0, len(a))
	for d := range a {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, d := range days {
		keys := make([]string, 0, len(a[d]))
		for k := range a[d] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if a[d][keys[i]].n != a[d][keys[j]].n {
				return a[d][keys[i]].n > a[d][keys[j]].n
			}
			return keys[i] < keys[j]
		})
		if len(keys) > top {
			keys = keys[:top]
		}
		for _, k := range keys {
			if err := sink.Emit(ctx, c.metric(d, count, k, a[d][k].n)); err != nil {
				return err
			}
			if err := sink.Emit(ctx, c.metric(d, ips, k, float64(len(a[d][k].ips)))); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectWAF は waf_review 用の集計を流して metric を出す。blocked は日 → その日 BLOCK された IP (waf_block_ip の結果)。
func (c *Collector) collectWAF(ctx context.Context, from, to time.Time, blocked map[string]map[string]bool, sink collect.RecordSink) error {
	wr := c.checks.WAFReview
	for _, q := range WAFQueries(c.prof, c.checks) {
		if q.PerDay {
			for d := from; d.Before(to); d = d.Add(24 * time.Hour) {
				end := d.Add(24 * time.Hour)
				if end.After(to) {
					end = to
				}
				rows, err := c.wafQuery(ctx, q.Name, q.Query, d, end)
				if err != nil {
					return err
				}
				day := d.UTC().Format(record.DateLayout)
				for _, r := range rows {
					grp := r["grp"]
					if grp == "" {
						grp = RateGroupOther
					}
					key := r["acl"] + "|" + grp
					for _, m := range []string{MetricWAFIPRateP50, MetricWAFIPRateP99, MetricWAFIPRateMax} {
						if err := sink.Emit(ctx, c.metric(day, m, key, num(r[m]))); err != nil {
							return err
						}
					}
				}
			}
			continue
		}
		rows, err := c.wafQuery(ctx, q.Name, q.Query, from, to)
		if err != nil {
			return err
		}
		switch q.Name {
		case MetricWAFRuleAction:
			block := map[string]map[string]float64{}
			for _, r := range rows {
				day, ok := parseDay(r["day"])
				if !ok {
					continue
				}
				n := num(r[MetricWAFRuleAction])
				if err := sink.Emit(ctx, c.metric(day, MetricWAFRuleAction, r["acl"]+"|"+r["rule"]+"|"+r["action"], n)); err != nil {
					return err
				}
				if r["action"] == "BLOCK" {
					if block[day] == nil {
						block[day] = map[string]float64{}
					}
					block[day][r["rule"]] += n
				}
			}
			// 既存の waf_block (ルール別。waf_block_trend が使う) はここから作り、クエリを 1 本減らす
			for _, day := range sortedDays(block) {
				for _, rule := range sortedNames(block[day]) {
					if err := sink.Emit(ctx, c.metric(day, MetricWAFBlock, Mask(rule), block[day][rule])); err != nil {
						return err
					}
				}
			}
		case MetricWAFBlockPath:
			agg := pathAgg{}
			for _, r := range rows {
				day, ok := parseDay(r["day"])
				if !ok {
					continue
				}
				rule := r["rule"]
				// 止めたグループの中のルール。止めたグループが 2 つ以上見えた行は (COUNT に上書きしたグループかもしれず) どれか決めない
				if r["inner"] != "" && r["inner2"] == "" {
					rule += "/" + r["inner"]
				}
				agg.add(day, r["acl"]+"|"+rule+"|"+r["method"]+"|"+NormalizePath(r["path"]), r["ip"], num(r[MetricWAFBlockPath]))
			}
			if err := c.emitTop(ctx, sink, agg, wr.TopPaths, MetricWAFBlockPath, MetricWAFBlockPathIPs); err != nil {
				return err
			}
		case MetricWAFAllowProbe:
			agg := pathAgg{}
			for _, r := range rows {
				if day, ok := parseDay(r["day"]); ok {
					agg.add(day, r["acl"]+"|"+NormalizePath(r["path"]), r["ip"], num(r[MetricWAFAllowProbe]))
				}
			}
			if err := c.emitTop(ctx, sink, agg, wr.TopPaths, MetricWAFAllowProbe, MetricWAFAllowProbeIPs); err != nil {
				return err
			}
		case MetricWAFCountMatch:
			if err := c.emitCountMatches(ctx, rows, blocked, sink); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitCountMatches は平坦化された位置ごとのルール ID を分解して、ルールごとの一致の件数を出す。
// ルールはトップレベルなら WebACL のルール名、グループの中なら `<ruleGroupId>/<ルール>`。
func (c *Collector) emitCountMatches(ctx context.Context, rows []map[string]string, blocked map[string]map[string]bool, sink collect.RecordSink) error {
	total, suspect := map[string]map[string]float64{}, map[string]map[string]float64{}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		n := num(r[MetricWAFCountMatch])
		bad := (r["probe"] != "" && r["probe_ex"] == "") || blocked[day][r["ip"]]
		seen := map[string]bool{}
		for i := 0; i < countTopPositions; i++ {
			if id := r["nonTerminatingMatchingRules."+strconv.Itoa(i)+".ruleId"]; id != "" {
				seen[id] = true
			}
		}
		for i := 0; i < countGroupPositions; i++ {
			g := "ruleGroupList." + strconv.Itoa(i)
			if id := r[g+".nonTerminatingMatchingRules.0.ruleId"]; id != "" {
				seen[r[g+".ruleGroupId"]+"/"+id] = true
			}
		}
		for id := range seen {
			key := r["acl"] + "|" + id
			if total[day] == nil {
				total[day], suspect[day] = map[string]float64{}, map[string]float64{}
			}
			total[day][key] += n
			if bad {
				suspect[day][key] += n
			}
		}
	}
	for _, day := range sortedDays(total) {
		for _, key := range sortedNames(total[day]) {
			if err := sink.Emit(ctx, c.metric(day, MetricWAFCountMatch, key, total[day][key])); err != nil {
				return err
			}
			if err := sink.Emit(ctx, c.metric(day, MetricWAFCountMatchSuspect, key, suspect[day][key])); err != nil {
				return err
			}
		}
	}
	return nil
}

// wafQuery は 1 本流し、行の上限に当たったら WARN を出して FormatStats.Truncated に残す。
func (c *Collector) wafQuery(ctx context.Context, name, query string, from, to time.Time) ([]map[string]string, error) {
	rows, err := c.Query(ctx, query, from, to)
	c.stats.BytesScanned = c.scanned
	if err != nil {
		return nil, err
	}
	if len(rows) >= MaxRows {
		c.Logger.Warn("aggregate truncated at row limit; counts are lower bounds", "source", c.src.ID, "metric", name, "limit", MaxRows)
		c.stats.AddTruncated(name)
	}
	return rows, nil
}

func sortedDays[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNames(m map[string]float64) []string { return sortedDays(m) }
