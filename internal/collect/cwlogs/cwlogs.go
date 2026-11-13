package cwlogs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// API は SDK クライアントのうち使う部分。テストではフェイク (cwlogstest) を注入する。
type API interface {
	StartQuery(ctx context.Context, params *cwl.StartQueryInput, optFns ...func(*cwl.Options)) (*cwl.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, params *cwl.GetQueryResultsInput, optFns ...func(*cwl.Options)) (*cwl.GetQueryResultsOutput, error)
	StopQuery(ctx context.Context, params *cwl.StopQueryInput, optFns ...func(*cwl.Options)) (*cwl.StopQueryOutput, error)
	DescribeLogGroups(ctx context.Context, params *cwl.DescribeLogGroupsInput, optFns ...func(*cwl.Options)) (*cwl.DescribeLogGroupsOutput, error)
}

// IAM action (doctor が列挙し、ACCESS_DENIED に添える)。
const (
	ActionStartQuery        = "logs:StartQuery"
	ActionGetQueryResults   = "logs:GetQueryResults"
	ActionStopQuery         = "logs:StopQuery"
	ActionDescribeLogGroups = "logs:DescribeLogGroups"
)

// RequiredActions は cloudwatch-logs ソースに必要な IAM action。
var RequiredActions = []string{ActionDescribeLogGroups, ActionStartQuery, ActionGetQueryResults, ActionStopQuery}

const (
	// SampleLines は FORMAT_MISMATCH に添えるサンプルの最大行数。
	SampleLines = 3
	// maxStartRetries は同時実行上限 (LimitExceededException) に当たった時の再試行回数。
	maxStartRetries = 5
	// DefaultMaxWait は 1 クエリの完了を待つ上限。超えたら StopQuery して QUERY_LIMIT。
	DefaultMaxWait = 15 * time.Minute
)

// Collector は cloudwatch-logs ソース 1 つ分。
type Collector struct {
	src     config.Source
	prof    Profile
	checks  config.Checks
	api     API
	Sleep   func(ctx context.Context, d time.Duration) error
	Logger  *slog.Logger
	MaxWait time.Duration
	// Now は保持期間の判定に使う今。
	Now func() time.Time

	stats   *collect.FormatStats
	scanned float64
	// group はロググループの作成時刻と保持期間 (DescribeLogGroups から 1 回だけ引く。取れなければ nil で範囲を判定しない)。
	group       *types.LogGroup
	groupLoaded bool
	// HygieneFrom は log_hygiene の範囲の始まり (ゼロなら窓の From)。engine が run の窓の始まりを渡す。
	// 決定 (ADR 0050): 範囲は run の窓 (weekly なら 7 日)。失敗したソースの追いつき (ADR 0038) の分は足さない: 状態を見るチェックなので
	// 追いつく必要が無く、足すと読み取りが倍になって max_scan_gb を超え、失敗が続く (1 度の失敗から抜けられなくなる)。
	HygieneFrom time.Time
	// selected は Select で絞った、この収集で出す種類 (nil なら形式の集計だけ)。
	selected map[record.Kind]bool
}

// 問い合わせ範囲が Insights に拒否される理由 (FormatStats.OutOfRange)。
const (
	OutOfRangeBeforeCreation = "before_log_group_creation"
	OutOfRangeRetention      = "beyond_retention"
)

// ErrOutOfRange は問い合わせの終わりがロググループの作成時刻より前、または保持期間より古いため問い合わせなかったことを表す。
var ErrOutOfRange = errors.New("query range is outside the log group's lifetime")

var (
	_ collect.Collector      = (*Collector)(nil)
	_ collect.FormatReporter = (*Collector)(nil)
)

// New は collector を作る。checks はアプリ層チェックの設定 (集計クエリのパス・ステータスに使う)。
func New(src config.Source, checks config.Checks, api API) (*Collector, error) {
	p, err := ProfileFor(src)
	if err != nil {
		return nil, err
	}
	return &Collector{src: src, prof: p, checks: checks, api: api, Sleep: sleepFor, Now: time.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), MaxWait: DefaultMaxWait}, nil
}

func sleepFor(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Collector) ID() string       { return c.src.ID }
func (c *Collector) Profile() Profile { return c.prof }

// Yields はこの収集で出す種類。既定は形式の集計 (http_access / waf_action) だけで、log_hygiene は Select で求められたときだけ出す。
func (c *Collector) Yields() []record.Kind {
	var out []record.Kind
	if c.formatSelected() {
		out = append(out, c.prof.Yields)
	}
	if c.hygieneSelected() {
		out = append(out, record.KindLogHygiene)
	}
	return out
}

// Select はこの収集で出す種類を、needs (プロファイルのチェックが必要とする種類) にあるものだけに絞る。
//
// 決定 (ADR 0050): 1 つのソースが形式の集計と log_hygiene の両方を出せる。weekly の run は衛生のクエリだけを、daily の run は
// 今までどおりの集計だけを流す (必要としない側のクエリを流さず、そのスナップショット・日次集計も置き換えない)。
// Select しない収集 (collect・init) は log_hygiene を流さない: 過去の期間を区切って引く用途で、状態のスナップショットを古い期間の値で置き換えないため。
func (c *Collector) Select(needs map[record.Kind]bool) {
	c.selected = map[record.Kind]bool{}
	for k, v := range needs {
		c.selected[k] = v
	}
}

func (c *Collector) formatSelected() bool {
	return c.prof.Yields != "" && (c.selected == nil || c.selected[c.prof.Yields])
}

func (c *Collector) hygieneSelected() bool {
	return c.selected[record.KindLogHygiene] && c.hygieneCovered()
}

// Queries は Collect が流すクエリ (名前 → クエリ。doctor の構文検査用)。サンプルは含まない。
func (c *Collector) Queries() map[string]string {
	out := map[string]string{}
	if c.hygieneCovered() {
		if q, _, err := HygieneQuery(c.src, c.checks.LogHygiene); err == nil {
			out["log_hygiene"] = q
		}
	}
	if c.prof.Yields == "" {
		return out
	}
	for _, q := range c.queries() {
		out[q.Name] = q.Query
	}
	if c.prof.Yields == record.KindWAFAction {
		out["waf_ip_rate"] = WAFRateQuery(c.prof, c.checks)
	}
	return out
}

// queries は Collect が範囲全体に流すクエリ (解釈率を含む。順番どおり。レートは含まない)。
func (c *Collector) queries() []MergedQuery {
	switch c.prof.Yields {
	case record.KindWAFAction:
		return WAFQueries(c.prof, c.checks)
	case record.KindHTTPAccess:
		qs := []MergedQuery{
			{Name: httpLines, Query: HTTPLinesQuery(c.prof, c.checks), Metrics: []string{MetricProbePaths}},
			{Name: httpHits, Query: HTTPHitsQuery(c.prof, c.checks), Metrics: []string{MetricSignInFailures, MetricProbeHits}},
		}
		if q, ok := EndpointsQuery(c.prof, c.src.ID, c.checks.EndpointAbuse); ok {
			qs = append(qs, q)
		}
		return qs
	}
	return []MergedQuery{{Name: MetricLinesTotal, Query: LinesQuery(c.prof)}}
}

// SetLogGroup は DescribeLogGroups で引き済みのロググループを渡す (doctor が同じ API を 2 回呼ばないため)。
func (c *Collector) SetLogGroup(g types.LogGroup) {
	c.group, c.groupLoaded = &g, true
}

// loadGroup はロググループの作成時刻と保持期間を引く。失敗・見つからないときは WARN を出し、範囲を判定しない (従来どおり問い合わせる)。
func (c *Collector) loadGroup(ctx context.Context) {
	if c.groupLoaded {
		return
	}
	c.groupLoaded = true
	// 名前の前方一致で引くと、完全一致の名前は最も短いので名前順の先頭のページに入る
	out, err := c.api.DescribeLogGroups(ctx, &cwl.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String(c.src.LogGroup)})
	if err != nil {
		c.Logger.Warn("failed to describe log group; querying without range check", "source", c.src.ID, "log_group", c.src.LogGroup,
			"action", ActionDescribeLogGroups, "error", err.Error())
		return
	}
	for _, g := range out.LogGroups {
		if aws.ToString(g.LogGroupName) == c.src.LogGroup {
			g := g
			c.group = &g
			return
		}
	}
	c.Logger.Warn("log group not found by DescribeLogGroups; querying without range check", "source", c.src.ID, "log_group", c.src.LogGroup)
}

// queryRange は [from, to) を Insights が受け付ける範囲にする。
//
// 決定: Insights は問い合わせの終わり (EndTime) がロググループの作成時刻より前、または保持期間 (今 - retentionInDays) より古いと
// MalformedQueryException で拒否する。始まりがそれより前でも終わりが範囲内なら受理される (2026-11 に実 AWS で確認)。
// そこで判定は終わりだけで行い、外れていれば reason を返して問い合わせない (データなし。エラーにしない)。
// 始まりは作成時刻までは寄せる (作成前のデータは無いので結果は同じ)。保持期間の境界には寄せない
// (日次集計は後の値で置き換えるので、日の頭を寄せると完全な日の値を一部だけの値で上書きし得る)。
func (c *Collector) queryRange(ctx context.Context, from, to time.Time) (time.Time, string) {
	c.loadGroup(ctx)
	if c.group == nil {
		return from, ""
	}
	end := time.Unix(to.Unix()-1, 0) // start() の EndTime と同じ
	if ms := aws.ToInt64(c.group.CreationTime); ms > 0 {
		created := time.UnixMilli(ms)
		if end.Before(created) {
			return from, OutOfRangeBeforeCreation
		}
		if from.Before(created) {
			from = created
		}
	}
	if days := aws.ToInt32(c.group.RetentionInDays); days > 0 && end.Before(c.Now().Add(-time.Duration(days)*24*time.Hour)) {
		return from, OutOfRangeRetention
	}
	return from, ""
}

// Scanned はこの collector がこれまでに Insights でスキャンした量 (バイト。Statistics.BytesScanned の合計)。doctor の費用の見積もりに使う。
func (c *Collector) Scanned() float64 { return c.scanned }

// QueryCount は 1 回の Collect で流すクエリの本数 (解釈率 + 集計。範囲全体のスキャン量で何本分かを表す。
// 日ごとに分けて流すクエリ・行数の上限で分けたクエリも 1 本と数える)。
func (c *Collector) QueryCount() int {
	if c.prof.Yields == "" {
		return 0
	}
	n := len(c.queries())
	if c.prof.Yields == record.KindWAFAction {
		n++ // レート
	}
	return n
}

// FormatStats は直近の Collect で計測した解釈率。計測前なら nil。
func (c *Collector) FormatStats() *collect.FormatStats { return c.stats }

// DayStart は t の UTC の 0 時。
func DayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// Collect は窓の始まり (再走査を含む w.Start()) を含む日の 0 時 (UTC) から窓の終わりまでを集計し、日次の metric を出す。
//
// 決定: 日次集計を置き換えで保存するため、問い合わせは日の頭からにする (同じ日を何度引いても後の値ほど完全で、重複加算しない)。
// その代わり 1 回のスキャンは最大で窓 + 24h になる。
// 解釈率は最初のクエリ (集計とまとめたもの) で測り、expected_match_rate を下回ったら残りのクエリを流さず、metrics も出さずに
// FORMAT_MISMATCH を返す (誤った集計で平常帯を汚さないため)。
// 決定 (ADR 0031): 集計はソースごとに数本にまとめる (MergedQuery)。
// 決定 (ADR 0050): log_hygiene を求められていれば (Select)、最後に衛生のクエリを 1 本流す (hygiene.go)。どちらかが失敗すればソースの失敗。
func (c *Collector) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.scanned = 0
	c.stats = nil
	if c.formatSelected() {
		if err := c.collectFormat(ctx, w, sink); err != nil {
			return err
		}
	}
	if c.hygieneSelected() {
		return c.collectHygiene(ctx, w, sink)
	}
	return nil
}

// collectFormat は形式プロファイルの集計 (解釈率と日次の metric)。
func (c *Collector) collectFormat(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	from, to := DayStart(w.Start()), w.To
	c.stats = &collect.FormatStats{Source: c.src.ID, Format: c.src.Format, LogGroup: c.src.LogGroup, Expected: c.src.ExpectedMatchRate}
	from, reason := c.queryRange(ctx, from, to)
	if reason != "" {
		c.stats.OutOfRange = reason
		c.Logger.Info("query range is outside the log group's lifetime; treating as no data", "source", c.src.ID, "log_group", c.src.LogGroup,
			"reason", reason, "from", from.Format(time.RFC3339), "to", to.Format(time.RFC3339))
		return nil
	}
	qs := c.queries()
	linesRows, err := c.splitQuery(ctx, qs[0], from, to, time.Hour, false)
	if err != nil {
		return err
	}
	lines := dayCounts{}
	for _, r := range linesRows {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		total, matched := num(r[MetricLinesTotal]), num(r[MetricLinesMatched])
		c.stats.Total += int64(total)
		c.stats.Matched += int64(matched)
		lines.add(day, MetricLinesTotal, total)
		lines.add(day, MetricLinesMatched, matched)
	}
	if rate, ok := c.stats.Rate(); ok && rate < c.src.ExpectedMatchRate {
		return c.mismatch(ctx, from, to, rate)
	}
	if c.stats.Total == 0 {
		c.Logger.Warn("no log lines in window; check log_group / stream_prefix", "source", c.src.ID, "log_group", c.src.LogGroup,
			"from", from.Format(time.RFC3339), "to", to.Format(time.RFC3339))
	}
	for _, day := range sortedDays(lines) {
		for _, m := range []string{MetricLinesTotal, MetricLinesMatched} {
			if err := sink.Emit(ctx, c.metric(day, m, "", lines[day][m])); err != nil {
				return err
			}
		}
	}
	if c.stats.Total == 0 {
		return nil
	}
	switch c.prof.Yields {
	case record.KindWAFAction:
		return c.collectWAF(ctx, qs, linesRows, from, to, sink)
	case record.KindHTTPAccess:
		return c.collectHTTP(ctx, qs, linesRows, from, to, sink)
	}
	return nil
}

// collectHTTP は http_access のまとめた集計から sign_in_failures / probe_hits / probe_paths と endpoint_abuse の metric を出す。
func (c *Collector) collectHTTP(ctx context.Context, qs []MergedQuery, linesRows []map[string]string, from, to time.Time, sink collect.RecordSink) error {
	lb, pp := c.checks.LoginBruteforce, c.checks.ProbePaths
	out := map[string]dayCounts{MetricSignInFailures: {}, MetricProbeHits: {}, MetricProbePaths: {}}
	if len(pp.Paths) > 0 {
		for _, r := range linesRows {
			day, ok := parseDay(r["day"])
			if !ok || r["probe_path"] == "" || !statusIn(r["status"], pp.Statuses) || hasPrefixAny(r["probe_path"], "", pp.ExcludePaths) {
				continue
			}
			out[MetricProbePaths].add(day, Mask(r["probe_path"]), num(r[MetricLinesTotal]))
		}
	}
	rows, err := c.splitQuery(ctx, qs[1], from, to, time.Hour, false)
	if err != nil {
		return err
	}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		n, ip := num(r[httpHits]), Mask(r["ip"])
		if (len(lb.Methods) == 0 || containsStr(lb.Methods, r["method"])) && (len(lb.Paths) == 0 || r["sign_in"] != "") && statusIn(r["status"], lb.FailureStatuses) {
			out[MetricSignInFailures].add(day, ip, n)
		}
		if statusIn(r["status"], pp.Statuses) && (len(pp.Paths) == 0 || r["probe"] != "") && r["probe_ex"] == "" {
			out[MetricProbeHits].add(day, ip, n)
		}
	}
	for _, m := range []string{MetricSignInFailures, MetricProbeHits, MetricProbePaths} {
		for _, day := range sortedDays(out[m]) {
			for _, k := range sortedNames(out[m][day]) {
				if err := sink.Emit(ctx, c.metric(day, m, k, out[m][day][k])); err != nil {
					return err
				}
			}
		}
	}
	if len(qs) > 2 {
		return c.collectEndpoints(ctx, qs[2], from, to, sink)
	}
	return nil
}

// statusIn は status が l に入るか (l が空なら絞らない。Insights の `status in [...]` と同じく数値として比べる)。
func statusIn(s string, l []int) bool {
	if len(l) == 0 {
		return true
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	for _, v := range l {
		if v == n {
			return true
		}
	}
	return false
}

// hasPrefixAny は s が prefix + l のどれかで始まるか (`like /^prefix(l1|l2)/` と同じ。l は文字どおり)。
func hasPrefixAny(s, prefix string, l []string) bool {
	for _, p := range l {
		if strings.HasPrefix(s, prefix+p) {
			return true
		}
	}
	return false
}

// splitQuery は q を [from, to) に流す (perDay なら UTC の 1 日ずつ)。行数の上限に当たればその範囲を align に揃えて半分に分けて引き直し (1h まで)、
// それでも当たれば WARN を出して q.Metrics を truncated に残す (件数の多い組が残り、少なめに数える)。
// 決定 (ADR 0031): スキャン量は範囲に比例するので、分けて流しても増えない。増えるのは上限に当たって引き直した分だけ (INFO に残す)。
// 日次 (bin(1d)) の集計は範囲全体を 1 本で流し、当たったときだけ分ける (多くの日は上限に遠く、API の呼び出しを増やさない)。
func (c *Collector) splitQuery(ctx context.Context, q MergedQuery, from, to time.Time, align time.Duration, perDay bool) ([]map[string]string, error) {
	if !perDay {
		return c.splitRange(ctx, q, from, to, align)
	}
	var out []map[string]string
	for d := from; d.Before(to); d = DayStart(d).Add(24 * time.Hour) {
		end := DayStart(d).Add(24 * time.Hour)
		if end.After(to) {
			end = to
		}
		rows, err := c.splitRange(ctx, q, d, end, align)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

func (c *Collector) splitRange(ctx context.Context, q MergedQuery, from, to time.Time, align time.Duration) ([]map[string]string, error) {
	rows, err := c.Query(ctx, q.Query, from, to)
	c.stats.BytesScanned = c.scanned
	if err != nil {
		return nil, err
	}
	if len(rows) < MaxRows {
		return rows, nil
	}
	span := to.Sub(from)
	mid := from.Add(span / 2).Truncate(align)
	if span > minSplit && mid.After(from) && mid.Before(to) {
		c.Logger.Info("aggregate hit row limit; splitting the range", "source", c.src.ID, "query", q.Name,
			"from", from.Format(time.RFC3339), "to", to.Format(time.RFC3339))
		a, err := c.splitRange(ctx, q, from, mid, align)
		if err != nil {
			return nil, err
		}
		b, err := c.splitRange(ctx, q, mid, to, align)
		if err != nil {
			return nil, err
		}
		return append(a, b...), nil
	}
	c.Logger.Warn("aggregate truncated at row limit; counts are lower bounds", "source", c.src.ID, "query", q.Name, "metrics", strings.Join(q.Metrics, ","), "limit", MaxRows)
	for _, m := range q.Metrics {
		c.stats.AddTruncated(m)
	}
	return rows, nil
}

func (c *Collector) metric(day, name, key string, v float64) record.Metric {
	return record.Metric{Date: day, Source: c.src.ID, From: c.prof.Yields, Metric: name, Key: key, Value: v}
}

func (c *Collector) mismatch(ctx context.Context, from, to time.Time, rate float64) error {
	details := map[string]any{
		"log_group": c.src.LogGroup, "format": c.src.Format, "match_rate": round(rate), "expected": c.src.ExpectedMatchRate,
		"total": c.stats.Total, "matched": c.stats.Matched,
	}
	if c.src.SampleLines {
		samples := []string{}
		rows, err := c.Query(ctx, SampleQuery(c.prof, SampleLines), from, to)
		c.stats.BytesScanned = c.scanned
		if err != nil {
			c.Logger.Warn("failed to fetch sample lines", "source", c.src.ID, "error", err.Error())
		}
		for _, r := range rows {
			samples = append(samples, MaskSample(r["@message"]))
		}
		details["samples"] = samples
	}
	return &collect.Error{Code: collect.CodeFormatMismatch, Source: c.src.ID, Details: details,
		Err: fmt.Errorf("match rate %.2f is below expected_match_rate %.2f (format %s, %d/%d lines)", rate, c.src.ExpectedMatchRate, c.src.Format, c.stats.Matched, c.stats.Total)}
}

// Query は Insights クエリを 1 本流し、結果の行 (フィールド名 → 値、@ptr は除く) を返す。
// 同時実行上限は待って再試行し、それでも駄目なら QUERY_LIMIT。スキャン量が max_scan_gb を超えたら StopQuery して QUERY_LIMIT。
//
// 範囲がロググループの作成前 / 保持期間外なら問い合わせず ErrOutOfRange を返す (queryRange)。
func (c *Collector) Query(ctx context.Context, query string, from, to time.Time) ([]map[string]string, error) {
	from, reason := c.queryRange(ctx, from, to)
	if reason != "" {
		return nil, fmt.Errorf("%w (%s)", ErrOutOfRange, reason)
	}
	id, err := c.start(ctx, query, from, to)
	if err != nil {
		return nil, err
	}
	wait, waited := time.Second, time.Duration(0)
	for {
		out, err := c.api.GetQueryResults(ctx, &cwl.GetQueryResultsInput{QueryId: aws.String(id)})
		if err != nil {
			return nil, collect.Classify(c.src.ID, ActionGetQueryResults, err)
		}
		bytes := 0.0
		if out.Statistics != nil {
			bytes = out.Statistics.BytesScanned
		}
		switch out.Status {
		case types.QueryStatusComplete:
			c.scanned += bytes
			if err := c.checkScan(0); err != nil {
				return nil, err
			}
			return rowsOf(out.Results), nil
		case types.QueryStatusFailed, types.QueryStatusCancelled, types.QueryStatusUnknown:
			c.scanned += bytes
			return nil, &collect.Error{Code: collect.CodeCollectFailed, Source: c.src.ID, Err: fmt.Errorf("query %s ended with status %s", id, out.Status)}
		case types.QueryStatusTimeout:
			c.scanned += bytes
			return nil, &collect.Error{Code: collect.CodeQueryLimit, Source: c.src.ID, Err: fmt.Errorf("query %s timed out in Logs Insights", id)}
		}
		if err := c.checkScan(bytes); err != nil {
			c.stop(ctx, id)
			c.scanned += bytes
			return nil, err
		}
		if waited >= c.MaxWait {
			c.stop(ctx, id)
			c.scanned += bytes
			return nil, &collect.Error{Code: collect.CodeQueryLimit, Source: c.src.ID, Err: fmt.Errorf("query %s did not finish within %s", id, c.MaxWait)}
		}
		if err := c.Sleep(ctx, wait); err != nil {
			return nil, err
		}
		waited += wait
		if wait < 5*time.Second {
			wait *= 2
		}
	}
}

func (c *Collector) start(ctx context.Context, query string, from, to time.Time) (string, error) {
	in := &cwl.StartQueryInput{
		LogGroupName: aws.String(c.src.LogGroup),
		QueryString:  aws.String(query),
		StartTime:    aws.Int64(from.Unix()),
		EndTime:      aws.Int64(to.Unix() - 1), // Insights の EndTime は含むので [from, to) にする
		Limit:        aws.Int32(MaxRows),
	}
	backoff := 2 * time.Second
	for attempt := 0; ; attempt++ {
		out, err := c.api.StartQuery(ctx, in)
		if err == nil {
			return aws.ToString(out.QueryId), nil
		}
		ce := collect.Classify(c.src.ID, ActionStartQuery, err)
		if ce.Code != collect.CodeQueryLimit || attempt >= maxStartRetries {
			if ce.Code == collect.CodeQueryLimit {
				ce.Err = fmt.Errorf("concurrent query limit (after %d retries): %w", attempt, ce.Err)
			}
			return "", ce
		}
		c.Logger.Warn("insights query limit; retrying", "source", c.src.ID, "attempt", attempt+1, "wait", backoff.String())
		if err := c.Sleep(ctx, backoff); err != nil {
			return "", err
		}
		backoff *= 2
	}
}

// checkScan は実行中のクエリの bytes を足すと上限を超えるか。
func (c *Collector) checkScan(running float64) error {
	if c.src.MaxScanGB <= 0 {
		return nil
	}
	limit := c.src.MaxScanGB * 1e9
	if c.scanned+running <= limit {
		return nil
	}
	return &collect.Error{Code: collect.CodeQueryLimit, Source: c.src.ID,
		Details: map[string]any{"bytes_scanned": c.scanned + running, "max_scan_gb": c.src.MaxScanGB},
		Err:     fmt.Errorf("scanned %.2f GB exceeds max_scan_gb %.2f", (c.scanned+running)/1e9, c.src.MaxScanGB)}
}

func (c *Collector) stop(ctx context.Context, id string) {
	if _, err := c.api.StopQuery(ctx, &cwl.StopQueryInput{QueryId: aws.String(id)}); err != nil {
		c.Logger.Warn("failed to stop query", "source", c.src.ID, "query_id", id, "error", err.Error())
	}
}

func rowsOf(results [][]types.ResultField) []map[string]string {
	out := make([]map[string]string, 0, len(results))
	for _, row := range results {
		m := map[string]string{}
		for _, f := range row {
			name := aws.ToString(f.Field)
			if name == "@ptr" {
				continue
			}
			m[name] = aws.ToString(f.Value)
		}
		out = append(out, m)
	}
	return out
}

// parseDay は bin(1d) の値 ("2026-10-21 00:00:00.000") を YYYY-MM-DD にする。
func parseDay(s string) (string, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339, record.DateLayout} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(record.DateLayout), true
		}
	}
	return "", false
}

// num は Insights の結果の数値 (件数・パーセンタイル・時刻) を読む。読めない値は 0。
// 決定 (ADR 0041。ファズで見つけた): NaN・無限大・負の値も 0 にする。fmt.Sscan は "NaN" や "Inf" を数として読むので、
// そのまま metric の値にすると JSON に書けず、その run の保存が失敗する。件数に負の値は無い。
func num(s string) float64 {
	var f float64
	if _, err := fmt.Sscan(s, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0
	}
	return f
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }

// Validate はクエリを StartQuery して直ちに StopQuery する。Insights の構文検査と StartQuery / StopQuery の権限だけを確かめる (doctor 用)。
// 範囲がロググループの作成前 / 保持期間外なら検査できないので ErrOutOfRange を返す。
func (c *Collector) Validate(ctx context.Context, query string, from, to time.Time) error {
	from, reason := c.queryRange(ctx, from, to)
	if reason != "" {
		return fmt.Errorf("%w (%s)", ErrOutOfRange, reason)
	}
	id, err := c.start(ctx, query, from, to)
	if err != nil {
		return err
	}
	if _, err := c.api.StopQuery(ctx, &cwl.StopQueryInput{QueryId: aws.String(id)}); err != nil {
		ce := collect.Classify(c.src.ID, ActionStopQuery, err)
		// 既に完了したクエリの StopQuery は InvalidParameterException になる。それは問題ではない
		if ce.Code == collect.CodeAccessDenied {
			return ce
		}
	}
	return nil
}
