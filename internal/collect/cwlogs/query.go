package cwlogs

import (
	"strconv"
	"strings"

	"github.com/CircleAround/arata/internal/config"
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

// MergedQuery は 1 本の Insights クエリ。1 本の細かい group by の結果から、Go で複数の metric を作る (ADR 0031)。
// UTC の 1 日ずつ流し、行数の上限に当たればその範囲を半分に分けて引き直す (splitQuery)。分けても当たれば Metrics を truncated に残す。
type MergedQuery struct {
	Name    string
	Query   string
	Metrics []string // この結果から作る metric の名前 (truncated に残す名前)
	// Bin は結果の行の「最初の行の時刻の区切り」の列 (request_lines だけ。空なら無い)。
	// 区切りが範囲の終わり以降の行は、余白の中で始まったリクエストなので捨てる (request.go)。
	Bin string
}

// http_access のまとめた集計の名前 (保存しない。クエリの列名)。
const (
	httpLines = "http_lines" // 解釈率 + probe_paths
	httpHits  = "http_hits"  // sign_in_failures + probe_hits
)

// 決定 (ADR 0031): 集計を 1 本ずつ流すと、Insights は 1 本ごとに範囲のログ全体を読む (費用は本数に比例する)。
// そこで同じソースの集計を細かい group by の 1 本にまとめ、振り分けを Go で行う。行が爆発する組み合わせ (ip × path) はまとめない。
//   - lines + probe_paths: 全行を (日, status, 探索パスのときだけ値を持つ probe_path) で数える。行は日 × status × (1 + 探索パスの数) 程度
//   - sign_in_failures + probe_hits: どちらも IP 別。filter で両方の行に絞り、(日, ip, method, status, パスの印) で数える
//     (パスの印は parse の名前付き捕獲。sign-in は完全一致、探索は接頭辞)
//
// HTTPLinesQuery は解釈率と probe_paths のクエリ。結果の列は day / status / probe_path / lines_total / lines_matched。
func HTTPLinesQuery(p Profile, c config.Checks) string {
	var b strings.Builder
	var marks []mark
	group := ""
	if pp := c.ProbePaths; len(pp.Paths) > 0 {
		alts := make([]string, len(pp.Paths))
		for i, s := range pp.Paths {
			alts[i] = regexLiteral(s) + ".*"
		}
		marks = append(marks, mark{"probe_path", func(name string) string { return "^(?<" + name + ">" + strings.Join(alts, "|") + ")" }})
		group = ", status, probe_path"
	}
	b.WriteString(p.head("1d", "day", "", marks, true, false, true))
	if p.req != nil {
		// request_lines: 1 段目の結果 (request_id ごとの 1 行) を、日・status・探索パス・最初の行の数で数える。
		// 行数は 1 段目で数えた行数の和。行の種類ごとの当たった数も返す (doctor 用)
		aggs := []string{"sum(" + rlLines + ") as " + MetricLinesTotal, "sum(" + rlTagged + ") as " + MetricLinesMatched, "count(*) as " + rlRequests}
		for i := range p.req.kinds {
			aggs = append(aggs, "sum("+kindCount(i)+") as "+kindTotal(i))
		}
		if group == "" && p.Has("status") {
			group = ", status"
		}
		// ユーザー ID と auth の割合は、専用のクエリを足さずにこの 2 段目の軸で数える (user.go。ADR 0052)
		ua, ug := p.req.userLines()
		aggs = append(aggs, ua...)
		for _, g := range ug {
			group += ", " + g
		}
		b.WriteString("\n| stats " + strings.Join(aggs, ", ") + " by day" + group + ", " + rlStarts)
	} else {
		b.WriteString("\n| stats count(*) as " + MetricLinesTotal + ", count(" + p.MatchField + ") as " + MetricLinesMatched + " by bin(1d) as day" + group)
	}
	b.WriteString("\n| sort " + MetricLinesTotal + " desc")
	b.WriteString("\n| limit " + strconv.Itoa(MaxRows))
	return b.String()
}

// HTTPHitsQuery は sign_in_failures と probe_hits のクエリ。結果の列は day / ip / method / status / sign_in / probe / probe_ex / http_hits。
func HTTPHitsQuery(p Profile, c config.Checks) string {
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
	var b strings.Builder
	cond := ""
	if signIn != "" && probe != "" {
		cond = "(" + signIn + ") or (" + probe + ")"
	}
	var marks []mark
	group := ", ip, method, status"
	if len(lb.Paths) > 0 {
		marks = append(marks, mark{"sign_in", func(name string) string { return "^(?<" + name + ">" + prefixAlternation(lb.Paths) + ")$" }})
		group += ", sign_in"
	}
	if len(pp.Paths) > 0 {
		marks = append(marks, mark{"probe", func(name string) string { return "^(?<" + name + ">" + prefixAlternation(pp.Paths) + ")" }})
		group += ", probe"
	}
	if len(pp.ExcludePaths) > 0 {
		marks = append(marks, mark{"probe_ex", func(name string) string { return "^(?<" + name + ">" + prefixAlternation(pp.ExcludePaths) + ")" }})
		group += ", probe_ex"
	}
	b.WriteString(p.head("1d", "day", cond, marks, false, false, false))
	b.WriteString("\n| stats " + p.count() + " as " + httpHits + " by " + p.binBy("1d", "day") + group)
	b.WriteString("\n| sort " + httpHits + " desc")
	b.WriteString("\n| limit " + strconv.Itoa(MaxRows))
	return b.String()
}

// LinesQuery は解釈率だけの計測クエリ。日ごとの総行数と解釈できた行数を返す (設計書 2-2)。
// Collect は解釈率を集計とまとめたクエリ (HTTPLinesQuery / WAFLinesQuery) で測る。これは doctor の費用の実測に使う。
func LinesQuery(p Profile) string {
	return p.Prelude + "\n| stats count(*) as " + MetricLinesTotal + ", count(" + p.MatchField + ") as " + MetricLinesMatched + " by bin(1d) as day"
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
