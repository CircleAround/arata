package cwlogs

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// MaxQueryLen は Logs Insights の問い合わせの文の上限 (StartQuery の queryString は 10,000 文字まで。API Reference で確かめた)。
const MaxQueryLen = 10000

// 決定 (実データで直した): 一覧の問い合わせは上限まで詰めない。実 AWS で、9,988〜9,993 バイト (ASCII だけ) の文が
// 「Query string must be less than or equal to 10000」で断られ、同じ文を送り直すと通ることもあった (数え方は公式の文書から分からない)。
// 1 割の余裕を取って ListedQueryLen に収め、長さ・形の理由 (QUERY_INVALID) で断られたら ListedRetryLen に短くして 1 度だけ流し直す。
const (
	ListedQueryLen = 9000
	ListedRetryLen = 8000
)

// MetricWAFCountMatchListed は、一覧の IP からの、BLOCK 以外のリクエストでのカウントのルールの一致 (探索パスを除く)。
// key は waf_rule_count_match と同じ。waf_review の suspect は waf_rule_count_match_suspect との和 (ADR 0069 の 4 節)。
const MetricWAFCountMatchListed = "waf_rule_count_match_listed"

// listed を流した日の印と、数えた範囲 (key は空。ADR 0069 の 4 節)。waf_listed_ips_total がある (日, ソース) は流し終えている。
//   - waf_listed_ips_total: その日の終わりにアクティブだった一覧の IP の数 (選んだ理由の分)
//   - waf_listed_ips_queried: 問い合わせに渡した IP の数 (上位から)
//   - waf_listed_block_share / waf_listed_probe_share: 渡した IP が占める、直近 N 日の waf_block / probe の件数の割合 (分母が 0 なら出さない)
//   - waf_listed_coverage_low: block_share が count_suspect.min_block_share より低い日に 1 (上位に偏っておらず、下限の意味が弱い)
const (
	MetricWAFListedIPsTotal    = "waf_listed_ips_total"
	MetricWAFListedIPsQueried  = "waf_listed_ips_queried"
	MetricWAFListedBlockShare  = "waf_listed_block_share"
	MetricWAFListedProbeShare  = "waf_listed_probe_share"
	MetricWAFListedCoverageLow = "waf_listed_coverage_low"
)

const wafListed = "waf_listed" // 一覧の IP に絞った問い合わせの件数の列

// ListedQueries は、一覧の IP (ips。並べた順に詰める) に絞った問い合わせの文を、maxLen 文字に収まる組ごとに最大 maxQueries 本作る。
// 返す used は文に入れた IP の数 (ips の先頭から。読めない値は飛ばして数えない)。
//
// 決定 (ADR 0069 の 4 節): 一覧の IP からの、BLOCK 以外のリクエストでのカウントのルールの一致を数える。軸に ip を持たない
// (行はルールの組の数で、上限に当たらない)。探索パスの印は軸に入れ、Go で除く (探索パスへの一致は waf_lines の側で数え済み)。
// 決定: IP は netip で読み直した正規の形だけを `"` で囲んで入れる (一覧はストアから読む値。書き換えられていても文の構造を変えさせない)。
func ListedQueries(p Profile, c config.Checks, ips []string, maxQueries, maxLen int) (queries []string, used int) {
	if maxLen > MaxQueryLen {
		maxLen = MaxQueryLen
	}
	head, tail := listedParts(p, c)
	room := maxLen - len(head) - len(tail)
	var cur []string
	size := 0
	flush := func() {
		if len(cur) > 0 {
			queries = append(queries, head+strings.Join(cur, ", ")+tail)
			cur, size = nil, 0
		}
	}
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			continue
		}
		lit := `"` + a.Unmap().String() + `"`
		add := len(lit)
		if len(cur) > 0 {
			add += len(", ")
		}
		if size+add > room {
			flush()
			if len(queries) >= maxQueries {
				return queries, used
			}
			add = len(lit)
		}
		if len(queries) >= maxQueries {
			return queries, used
		}
		cur = append(cur, lit)
		size += add
		used++
	}
	flush()
	return queries, used
}

// listedParts は問い合わせの文の、IP の並びの前と後ろ。
func listedParts(p Profile, c config.Checks) (head, tail string) {
	sp := regexLiteral(p.StripPrefix)
	pp := c.ProbePaths
	fields := countFields()
	var present []string
	for _, f := range fields {
		if strings.HasSuffix(f, ".ruleId") {
			present = append(present, "ispresent("+f+")")
		}
	}
	cond := and(`action != "BLOCK"`, "("+strings.Join(present, " or ")+")", trustedFilter(c.WAFReview.TrustedCIDRs))
	probeParse := "\n| parse path /^" + sp + "(?<probe>" + prefixAlternation(pp.Paths) + ")/"
	axes := strings.Join(fields, ", ") + ", probe"
	if len(pp.ExcludePaths) > 0 {
		probeParse += "\n| parse path /^" + sp + "(?<probe_ex>" + prefixAlternation(pp.ExcludePaths) + ")/"
		axes += ", probe_ex"
	}
	head = wafHead(p) + "\n| filter ip in ["
	tail = "]\n| filter " + cond + probeParse +
		"\n| stats count(*) as " + wafListed + " by bin(1d) as day, acl, " + axes +
		"\n| sort " + wafListed + " desc\n| limit " + strconv.Itoa(MaxRows)
	return head, tail
}

// CollectListed は day (UTC の 1 日) について、ips に絞った問い合わせを流し、カウントのルールごとの一致 (key <WebACL>|<ルール>) を返す。
// used は数えた IP の数 (ips の先頭から)。組ごとに 1 日分を読む (絞っても Insights は範囲の全部を読む)。
func (c *Collector) CollectListed(ctx context.Context, day time.Time, ips []string, maxQueries int) (map[string]float64, int, error) {
	out, used, err := c.collectListed(ctx, day, ips, maxQueries, ListedQueryLen)
	var ce *collect.Error
	if err != nil && errors.As(err, &ce) && ce.Code == collect.CodeQueryInvalid {
		c.Logger.Info("listed query was refused; retrying once with shorter queries", "source", c.src.ID, "date", DayStart(day).Format(record.DateLayout),
			"max_len", ListedRetryLen, "error", record.MaskIdentity(ce.Err.Error()))
		return c.collectListed(ctx, day, ips, maxQueries, ListedRetryLen)
	}
	return out, used, err
}

func (c *Collector) collectListed(ctx context.Context, day time.Time, ips []string, maxQueries, maxLen int) (map[string]float64, int, error) {
	qs, used := ListedQueries(c.prof, c.checks, ips, maxQueries, maxLen)
	out := map[string]float64{}
	from := day.UTC().Truncate(24 * time.Hour)
	for _, q := range qs {
		rows, err := c.Query(ctx, q, from, from.Add(24*time.Hour))
		if c.stats != nil {
			c.stats.BytesScanned = c.scanned
		}
		if err != nil {
			return nil, 0, err
		}
		for _, r := range rows {
			if r["probe"] != "" && r["probe_ex"] == "" {
				continue
			}
			n := num(r[wafListed])
			for id := range countRules(r) {
				out[r["acl"]+"|"+id] += n
			}
		}
	}
	return out, used, nil
}

// HourlyDayComplete は、時の単位で読むソースで、day (UTC の日) の部分の行が 24 時間分そろっているか (日の値が確定しているか)。
// 先頭のクエリ (解釈率を兼ねる) の部分の行で見る。行の無い時も空で書くので、読んだ時の数と同じ。
func (c *Collector) HourlyDayComplete(ctx context.Context, day time.Time) (bool, error) {
	if !c.hourly() {
		return false, nil
	}
	d := DayStart(day)
	_, hours, err := c.Parts.Parts(ctx, c.src.ID, c.queries()[0].Name, d, d.Add(24*time.Hour))
	return hours == 24, err
}
