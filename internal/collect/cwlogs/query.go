package cwlogs

import (
	"strconv"
	"strings"

	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// 集計の metric 名 (metrics.metric)。チェックはこの名前で metrics を引く。
const (
	MetricLinesTotal     = "lines_total"      // 総行数 (key なし)
	MetricLinesMatched   = "lines_matched"    // 形式プロファイルで解釈できた行数 (key なし)
	MetricSignInFailures = "sign_in_failures" // http_access: sign-in 失敗 (key = ip)
	MetricProbeHits      = "probe_hits"       // http_access: 機密パスへの 403/404 (key = ip)
	MetricProbePaths     = "probe_paths"      // http_access: 機密パスへの 403/404 (key = path)
	MetricWAFBlock       = "waf_block"        // waf_action: BLOCK (key = rule)。waf_rule_action から作る (waf.go)
	MetricWAFBlockIP     = "waf_block_ip"     // waf_action: BLOCK (key = ip)
)

// MaxRows は 1 クエリで受け取る行数の上限 (GetQueryResults の 1 回の上限)。
const MaxRows = 10000

// Aggregate は正規化レコードに対する日次集計 1 種。前処理の後ろに付ける。
type Aggregate struct {
	Metric   string
	KeyField string // group by する正規化フィールド
	Filter   string // `filter` の条件式 (空なら絞り込まない)
}

// Aggregates は正規化レコードの種類ごとの集計 (= クエリテンプレート集)。パスや閾値はアプリ層チェックの設定から入れる。
func Aggregates(kind record.Kind, c config.Checks) []Aggregate {
	switch kind {
	case record.KindHTTPAccess:
		lb, pp := c.LoginBruteforce, c.ProbePaths
		signIn := and(
			inList("method", quoteAll(lb.Methods)),
			inList("path", quoteAll(lb.Paths)),
			inList("status", intsToStrings(lb.FailureStatuses)),
		)
		probe := and(
			inList("status", intsToStrings(pp.Statuses)),
			"path like /^("+prefixAlternation(pp.Paths)+")/",
		)
		if len(pp.ExcludePaths) > 0 {
			probe = and(probe, "path not like /^("+prefixAlternation(pp.ExcludePaths)+")/")
		}
		return []Aggregate{
			{Metric: MetricSignInFailures, KeyField: "ip", Filter: signIn},
			{Metric: MetricProbeHits, KeyField: "ip", Filter: probe},
			{Metric: MetricProbePaths, KeyField: "path", Filter: probe},
		}
	case record.KindWAFAction:
		// waf_block (rule 別) は waf_rule_action (WAFQueries) から作る。ここは IP 別だけ
		return []Aggregate{{Metric: MetricWAFBlockIP, KeyField: "ip", Filter: `action = "BLOCK"`}}
	}
	return nil
}

// LinesQuery は解釈率の計測クエリ。日ごとの総行数と解釈できた行数を返す (設計書 2-2)。
func LinesQuery(p Profile) string {
	return p.Prelude + "\n| stats count(*) as " + MetricLinesTotal + ", count(" + p.MatchField + ") as " + MetricLinesMatched + " by bin(1d) as day"
}

// AggregateQuery は集計 1 種のクエリ。結果の列は day / <KeyField> / <Metric>。
func AggregateQuery(p Profile, a Aggregate) string {
	var b strings.Builder
	b.WriteString(p.Prelude)
	if a.Filter != "" {
		b.WriteString("\n| filter " + a.Filter)
	}
	b.WriteString("\n| stats count(*) as " + a.Metric + " by bin(1d) as day, " + a.KeyField)
	b.WriteString("\n| sort " + a.Metric + " desc")
	b.WriteString("\n| limit " + strconv.Itoa(MaxRows))
	return b.String()
}

// SampleQuery は解釈できなかった行の例を最大 n 行返すクエリ (FORMAT_MISMATCH の原因特定用)。
func SampleQuery(p Profile, n int) string {
	return p.Prelude + "\n| filter not ispresent(" + p.MatchField + ")\n| fields @message\n| limit " + strconv.Itoa(n)
}

// DoctorMatchedField は DoctorQuery が解釈できたかを返す列の名前。
const DoctorMatchedField = "arata_matched"

// DoctorQuery は直近 n 行と解釈結果を返すクエリ (doctor の解釈率。生ログを引くのはここだけ)。
//
// 決定: 前処理 (parse / fields ... as) で定義したフィールドを後段の `fields` で列挙し直すと、Insights は
// `Ephemeral field is already defined` で拒否する (本番の doctor で確認)。判定フィールドそのものは列挙せず、
// `ispresent(<判定フィールド>)` を新しい名前の列にして返す。
func DoctorQuery(p Profile, n int) string {
	return p.Prelude + "\n| fields @timestamp, @message, ispresent(" + p.MatchField + ") as " + DoctorMatchedField + "\n| sort @timestamp desc\n| limit " + strconv.Itoa(n)
}

// Matched は DoctorQuery の結果行が解釈できた行か。
func Matched(p Profile, row map[string]string) bool {
	switch row[DoctorMatchedField] {
	case "1", "true":
		return true
	case "0", "false":
		return false
	}
	return row[p.MatchField] != ""
}

func and(conds ...string) string {
	var parts []string
	for _, c := range conds {
		if c != "" {
			parts = append(parts, c)
		}
	}
	return strings.Join(parts, " and ")
}

func inList(field string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	return field + " in [" + strings.Join(values, ", ") + "]"
}

func quoteAll(l []string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = stringLiteral(s)
	}
	return out
}

func intsToStrings(l []int) []string {
	out := make([]string, len(l))
	for i, n := range l {
		out[i] = strconv.Itoa(n)
	}
	return out
}

func prefixAlternation(prefixes []string) string {
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = regexLiteral(p)
	}
	return strings.Join(parts, "|")
}
