package cwlogs

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
)

// request_lines 形式 (ADR 0051): 1 リクエストが複数行に分かれるログを、Insights の中で request_id ごとにまとめてから集計する。
//
// クエリの形 (1 行 = 1 リクエストの形式との違いは、集計の stats の前に 1 段目を挟むことだけ):
//
//	parse @message /<鍵>/                         … rl_request_id
//	| parse @message /(?<rl_k0><行の種類 0>)/ …   … rl_ip, rl_method, rl_path, rl_status … と、行の種類の印 rl_k<i>
//	| fields bin(1d) as rl_bin                    … 行の時刻の区切り (1 段目で作った時刻は 2 段目の bin() に渡せないので、先に作る)
//	| parse rl_path /<印>/                        … 集計が使うパスの印 (探索パス・画面の glob)。最初の行のパスから作る
//	| filter ispresent(rl_request_id)             … 解釈率のクエリ以外
//	| stats count(rl_path) as rl_starts, min(rl_bin) as day, earliest(rl_ip) as ip, … latest(rl_status) as status … by rl_request_id
//	| fields if(rl_n2 > 0 and not ispresent(rl_status_0), "404", rl_status_0) as status   … set の補い
//	| filter <リクエスト単位の条件>
//	| stats sum(rl_starts) as <件数> by day, <軸>  … 1 行 = 1 リクエストの形式と同じ集計。件数だけ最初の行の数の和にする
//
// 決定:
//   - 件数は「まとめた件数」ではなく最初の行 (ip と path を取り出す行) の数で数える。同じ request_id を使い回されても数が減らない。
//     1 つの request_id に最初の行が 2 つ以上あるものは項目が混ざる (どの値になるかは下の規則) ので、その数を request_id_reused に残す
//   - 行をまたいで値を拾う規則: status と duration は最後の値 (latest)、それ以外は最初の値 (earliest)。どちらも項目の無い行を飛ばす
//   - リクエストは最初の行の時刻の日 (endpoint_abuse は時間幅) に数える。問い合わせの範囲は後ろに request.max_duration だけ広げ、
//     区切りが範囲の終わり以降の行 (余白の中で始まったリクエスト) は捨てる (次の範囲が数える)。
//     前には広げない: 最初の行が範囲に無いリクエストは最初の行の数が 0 で、どの件数にも入らない (前の日の分)。
//     前に広げると、前の日の集計を一部だけの値で置き換えてしまう
//   - 範囲を分けるのは、区切りに揃う境目だけ (日次の集計は日、endpoint_abuse は時間幅)。境目が区切りの途中だと、
//     余白の中で始まったリクエストを両方の範囲が数える。そのため日次の集計は、行数の上限に当たっても 1 日より細かくは分けない
//   - 解釈率のクエリだけは request_id の無い行も 1 段目に通す (全行を数えるため)。無い行は 1 つの組 (null) にまとまり、
//     その組の区切りは範囲の最初の区切りになる。行数が最初の日に寄らないよう、解釈率のクエリは 1 日ずつ流す (スキャン量は変わらない)。
//     行数 (lines_total / lines_matched) は、日の境目の余白の分だけ概数になる
//   - 一時フィールドは rl_ で始める (Insights は同じ名前を 2 度定義できない。設定の正規表現のキャプチャも rl_<項目> に付け替える)
const (
	rlPrefix   = "rl_"
	rlID       = rlPrefix + config.RequestIDCapture
	rlBin      = "rl_bin"
	rlLines    = "rl_lines"
	rlTagged   = "rl_tagged"
	rlStarts   = "rl_starts"
	rlFirst    = "rl_first"
	rlRequests = "rl_requests"
	rlMark     = "rl_m_"
)

// request_lines のソースが出す日次の metric (key なし)。
const (
	MetricRequestsTotal    = "requests_total"    // request_id の異なりの数 (その日に最初の行があるもの + 最初の行が無いもの)
	MetricRequestsComplete = "requests_complete" // 最初の行 (ip と path) のある request_id の数
	MetricRequestIDReused  = "request_id_reused" // 最初の行が 2 つ以上ある request_id の数
)

// FORMAT_MISMATCH の details.reason (request_lines)。
const (
	// RequestProblemComplete はまとめられた割合が expected_complete_rate 未満。
	RequestProblemComplete = "complete_rate"
	// RequestProblemID は request_id の異なりの数が最初の行の数の半分未満 (鍵の取り違えか、大量の使い回し)。
	RequestProblemID = "request_id"
)

// maxRequestCount は結果の 1 行から読む件数の上限 (積が int64 に収まる大きさ)。
const maxRequestCount = 1e9

// requestStage は request_lines の 1 段目の材料。
type requestStage struct {
	margin time.Duration
	kinds  []string // 行の種類の名前 (設定順)
	fields []string // 取り出す項目 (config.RequestLineFields の順)
	sets   []requestSet
}

// requestSet は「行の種類 kind があり、status が取れなかったリクエスト」に補う値。
type requestSet struct {
	kind   int
	status int
}

// RequestLines は request_lines 形式か (集計の前にリクエスト単位にまとめる)。
func (p Profile) RequestLines() bool { return p.req != nil }

// requestProfile は設定から前処理 (行ごとの parse) と 1 段目の材料を作る。
func requestProfile(p *Profile, r *config.Request) (string, error) {
	groups, err := r.Groups()
	if err != nil {
		return "", err
	}
	st := &requestStage{margin: r.MaxDuration}
	parts := []string{"parse @message /" + escapeSlashes(prefixCaptures(r.ID, rlPrefix)) + "/"}
	has := map[string]bool{}
	for i, l := range r.Lines {
		st.kinds = append(st.kinds, l.Name)
		// 行の種類ごとに全体を名前付きのキャプチャで包む (何も取り出さない行にも印が付き、種類ごとの当たった数を数えられる)
		parts = append(parts, "parse @message /(?<"+kindFlag(i)+">"+escapeSlashes(prefixCaptures(l.Regex, rlPrefix))+")/")
		for _, g := range groups[i] {
			has[g] = true
		}
		if v, ok := l.Set["status"]; ok {
			st.sets = append(st.sets, requestSet{kind: i, status: v})
		}
	}
	for _, f := range config.RequestLineFields {
		if has[f] {
			st.fields = append(st.fields, f)
			p.setFields(f)
		}
	}
	p.req = st
	return strings.Join(parts, "\n| "), nil
}

func kindFlag(i int) string  { return "rl_k" + strconv.Itoa(i) }
func kindCount(i int) string { return "rl_n" + strconv.Itoa(i) }
func kindTotal(i int) string { return "rl_kind_" + strconv.Itoa(i) }

// prefixCaptures は正規表現の名前付きキャプチャ (?P<name>…) / (?<name>…) を (?<prefix+name>…) に付け替える。
// エスケープ (\( と \Q…\E) と文字クラスの中の `(` は触らない。RE2 で読める正規表現 (config が検証済み) を前提とする。
func prefixCaptures(expr, prefix string) string {
	var b strings.Builder
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case c == '\\' && strings.HasPrefix(expr[i:], `\Q`):
			end := strings.Index(expr[i:], `\E`)
			if end < 0 {
				b.WriteString(expr[i:])
				return b.String()
			}
			b.WriteString(expr[i : i+end+2])
			i += end + 1
		case c == '\\' && i+1 < len(expr):
			b.WriteString(expr[i : i+2])
			i++
		case c == '[':
			j := classEnd(expr, i)
			b.WriteString(expr[i:j])
			i = j - 1
		case strings.HasPrefix(expr[i:], "(?P<"):
			b.WriteString("(?<" + prefix)
			i += 3
		case strings.HasPrefix(expr[i:], "(?<"):
			b.WriteString("(?<" + prefix)
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// classEnd は i から始まる文字クラス `[...]` の終わりの次の位置を返す (閉じていなければ末尾)。
func classEnd(expr string, i int) int {
	j := i + 1
	if j < len(expr) && expr[j] == '^' {
		j++
	}
	if j < len(expr) && expr[j] == ']' { // 先頭の ] は文字どおり
		j++
	}
	for j < len(expr) {
		switch {
		case expr[j] == '\\' && j+1 < len(expr):
			j += 2
		case strings.HasPrefix(expr[j:], "[:"):
			if end := strings.Index(expr[j+2:], ":]"); end >= 0 {
				j += end + 4
			} else {
				j++
			}
		case expr[j] == ']':
			return j + 1
		default:
			j++
		}
	}
	return len(expr)
}

// mark は集計が使うパスの印 (parse の名前付きキャプチャ)。re は印の名前から正規表現を作る。
type mark struct {
	name string
	re   func(name string) string
}

// head は集計の stats の手前までを組み立てる。cond はリクエスト単位の条件 (空なら絞らない)。
// 1 行 = 1 リクエストの形式では、前処理 → filter → 印。request_lines では 1 段目を挟む (bin は最初の行の時刻の区切り。lines は解釈率のクエリか)。
func (p Profile) head(bin, binName, cond string, marks []mark, lines, first bool) string {
	var b strings.Builder
	b.WriteString(p.Prelude)
	if p.req == nil {
		if cond != "" {
			b.WriteString("\n| filter " + cond)
		}
		for _, m := range marks {
			b.WriteString("\n| parse path /" + m.re(m.name) + "/")
		}
		return b.String()
	}
	b.WriteString("\n| fields bin(" + bin + ") as " + rlBin)
	for _, m := range marks {
		b.WriteString("\n| parse " + rlPrefix + "path /" + m.re(rlMark+m.name) + "/")
	}
	var aggs []string
	if lines {
		aggs = append(aggs, "count(*) as "+rlLines, "count("+rlID+") as "+rlTagged)
	} else {
		b.WriteString("\n| filter ispresent(" + rlID + ")")
	}
	aggs = append(aggs, "count("+rlPrefix+"path) as "+rlStarts, "min("+rlBin+") as "+binName)
	if first {
		aggs = append(aggs, "min(@timestamp) as "+rlFirst)
	}
	for _, f := range p.req.fields {
		fn, name := "earliest", f
		if f == "status" || f == "duration" {
			fn = "latest"
		}
		if f == "status" && len(p.req.sets) > 0 {
			name = "rl_status_0"
		}
		aggs = append(aggs, fn+"("+rlPrefix+f+") as "+name)
	}
	isSet := map[int]bool{}
	for _, s := range p.req.sets {
		isSet[s.kind] = true
	}
	for i := range p.req.kinds {
		if lines || isSet[i] {
			aggs = append(aggs, "count("+kindFlag(i)+") as "+kindCount(i))
		}
	}
	for _, m := range marks {
		aggs = append(aggs, "earliest("+rlMark+m.name+") as "+m.name)
	}
	b.WriteString("\n| stats " + strings.Join(aggs, ", ") + " by " + rlID)
	for j, s := range p.req.sets {
		src, dst := "rl_status_"+strconv.Itoa(j), "rl_status_"+strconv.Itoa(j+1)
		if j == len(p.req.sets)-1 {
			dst = "status"
		}
		b.WriteString("\n| fields if(" + kindCount(s.kind) + " > 0 and not ispresent(" + src + `), "` + strconv.Itoa(s.status) + `", ` + src + ") as " + dst)
	}
	if cond != "" {
		b.WriteString("\n| filter " + cond)
	}
	return b.String()
}

// count は集計の件数の式。request_lines では最初の行の数の和 (同じ request_id の使い回しで減らない)。
func (p Profile) count() string {
	if p.req != nil {
		return "sum(" + rlStarts + ")"
	}
	return "count(*)"
}

// binBy は集計の軸の時刻の区切り。request_lines では 1 段目が作った列をそのまま使う。
func (p Profile) binBy(bin, name string) string {
	if p.req != nil {
		return name
	}
	return "bin(" + bin + ") as " + name
}

// binName は結果の行の、最初の行の時刻の区切りの列 (request_lines だけ。それ以外は空)。
func (p Profile) binName(name string) string {
	if p.req != nil {
		return name
	}
	return ""
}

// requestRow は解釈率のクエリの結果の 1 行 (日 × status × 探索パス × 最初の行の数) を読んだもの。
type requestRow struct {
	Requests float64 // この行にまとまった request_id の数 (request_id の無い行の組は除く)
	Starts   float64 // 1 つの request_id あたりの最初の行の数
	Untagged bool    // request_id の無い行の組を含む (Starts はその組の最初の行の数でもある)
	Status   bool    // ステータスが取れている
}

// readRequestRow は Insights の結果の 1 行を読む。読めない値・負の値・NaN は 0、大きすぎる値は上限に丸める。
//
// 決定: request_id の無い行の組 (null) は 1 段目の結果に 1 行として混ざる。その組だけ「行数 > request_id の付いた行数」になるので、
// そうなっている行からリクエストを 1 つ引く (リクエストではない)。その組の最初の行の数は「タグの無い最初の行」として別に残す。
func readRequestRow(r map[string]string) requestRow {
	clamp := func(s string) float64 { return math.Min(math.Floor(num(s)), maxRequestCount) }
	rr := requestRow{Requests: clamp(r[rlRequests]), Starts: clamp(r[rlStarts]), Status: strings.TrimSpace(r["status"]) != ""}
	if num(r[MetricLinesTotal]) > num(r[MetricLinesMatched]) {
		rr.Untagged = true
		if rr.Requests >= 1 {
			rr.Requests--
		}
	}
	return rr
}

// Hits はこの行のリクエストの数 (最初の行の数の和)。最初の行のあるリクエストの数より小さくならない。
func (rr requestRow) Hits() float64 { return rr.Requests * rr.Starts }

// add は rr を集計に足す。
func addRequestRow(st *collect.RequestStats, rr requestRow) {
	n := int64(rr.Requests)
	st.Total += n
	if rr.Starts >= 1 {
		st.Complete += n
		st.Starts += int64(rr.Hits())
	}
	if rr.Starts >= 2 {
		st.Reused += n
	}
	if rr.Status {
		st.WithStatus += n
	}
	if rr.Untagged {
		st.StartsUntagged += int64(rr.Starts)
	}
}

// requestStats は解釈率のクエリの結果から、リクエスト単位の集計を作る。
func requestStats(rows []map[string]string, expected float64) collect.RequestStats {
	st := collect.RequestStats{Expected: expected}
	for _, r := range rows {
		addRequestRow(&st, readRequestRow(r))
	}
	return st
}

// RequestProblem はリクエスト単位の集計が使えない理由 (RequestProblem*)。使えるなら空。
//
// 決定 (ADR 0051): request_id の異なりの数が最初の行の数の半分未満なら、鍵を取り違えている (時刻やホスト名の角括弧を鍵にして、
// 全部の行が少数の鍵にまとまった) とみなす。行の解釈率もまとめられた割合も高く出て、黙って数が壊れる形なので、ここで止める。
// 送る側が request_id を大量に使い回してもこの検査に当たるが、そのときも黙って数えずに失敗として報告に出す。
// 閾値 (半分) は実データで見直す。
func RequestProblem(st collect.RequestStats) string {
	if st.Total <= 0 {
		return ""
	}
	if st.Total*2 < st.Starts {
		return RequestProblemID
	}
	if rate, ok := st.CompleteRate(); ok && rate < st.Expected {
		return RequestProblemComplete
	}
	return ""
}

func (c *Collector) requestMismatch(reason string) error {
	rs := *c.stats.Requests
	rate, _ := rs.CompleteRate()
	details := map[string]any{
		"log_group": c.src.LogGroup, "format": c.src.Format, "reason": reason,
		"requests_total": rs.Total, "requests_complete": rs.Complete, "complete_rate": round(rate), "expected_complete_rate": rs.Expected,
		"request_starts": rs.Starts, "request_id_reused": rs.Reused,
	}
	err := fmt.Errorf("complete rate %.2f is below expected_complete_rate %.2f (format %s, %d/%d requests have the first line)", rate, rs.Expected, c.src.Format, rs.Complete, rs.Total)
	if reason == RequestProblemID {
		err = fmt.Errorf("%d distinct request ids for %d first lines (format %s): request.id seems to capture something else (e.g. the first bracket), or ids are heavily reused",
			rs.Total, rs.Starts, c.src.Format)
	}
	return &collect.Error{Code: collect.CodeFormatMismatch, Source: c.src.ID, Details: details, Err: err}
}

// queryEnd は範囲の終わり to の問い合わせの終わり。request_lines では max_duration だけ後ろに広げる (今より先には広げない)。
func (c *Collector) queryEnd(to time.Time) time.Time {
	if c.prof.req == nil || c.prof.req.margin <= 0 {
		return to
	}
	limit := c.Now()
	if limit.Before(to) {
		limit = to
	}
	if end := to.Add(c.prof.req.margin); end.Before(limit) {
		return end
	}
	return limit
}

// inRange は、最初の行の時刻の区切りが範囲の終わり以降の行 (余白の中で始まったリクエスト) を捨てる。
func inRange(rows []map[string]string, bin string, to time.Time) []map[string]string {
	if bin == "" {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		if t, ok := parseBin(r[bin]); ok && !t.Before(to) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func parseBin(s string) (time.Time, bool) {
	if t, ok := parseTime(s); ok {
		return t, true
	}
	if d, ok := parseDay(s); ok {
		t, err := time.Parse("2006-01-02", d)
		return t, err == nil
	}
	return time.Time{}, false
}

// epochMillis は 12〜14 桁の数字だけの値をエポックからのミリ秒として読む (2001 年〜5138 年)。
// 1 段目で作った時刻 (min(@timestamp) など) は、2 段目では時刻の型ではなく数として渡る。
func epochMillis(s string) (time.Time, bool) {
	if len(s) < 12 || len(s) > 14 {
		return time.Time{}, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return time.Time{}, false
		}
	}
	ms, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(ms).UTC(), true
}

// KindCount は行の種類ごとの当たった行の数。
type KindCount struct {
	Name  string
	Lines int64
}

// RequestSummary は request_lines のソースの、ある範囲のまとめの結果 (doctor 用)。
type RequestSummary struct {
	Stats  collect.RequestStats
	Lines  int64 // 全行
	Tagged int64 // request_id の付いた行
	Kinds  []KindCount
}

// RequestSummary は [from, to) の行をリクエスト単位にまとめた結果を返す (解釈率のクエリを 1 本流す)。request_lines でなければ nil。
func (c *Collector) RequestSummary(ctx context.Context, from, to time.Time) (*RequestSummary, error) {
	if c.prof.req == nil {
		return nil, nil
	}
	rows, err := c.Query(ctx, HTTPLinesQuery(c.prof, c.checks), from, c.queryEnd(to))
	if err != nil {
		return nil, err
	}
	s := &RequestSummary{Stats: requestStats(rows, c.src.ExpectedCompleteRate)}
	for i, name := range c.prof.req.kinds {
		k := KindCount{Name: name}
		for _, r := range rows {
			k.Lines += int64(math.Min(num(r[kindTotal(i)]), maxRequestCount))
		}
		s.Kinds = append(s.Kinds, k)
	}
	for _, r := range rows {
		s.Lines += int64(math.Min(num(r[MetricLinesTotal]), maxRequestCount))
		s.Tagged += int64(math.Min(num(r[MetricLinesMatched]), maxRequestCount))
	}
	return s, nil
}

// Fields は前処理が取り出す項目 (ip / path を含む。request_lines だけ。doctor が「取れている項目」として出す)。
func (p Profile) Fields() []string {
	if p.req == nil {
		return nil
	}
	return append([]string{}, p.req.fields...)
}
