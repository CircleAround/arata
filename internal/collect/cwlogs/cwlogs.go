package cwlogs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
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
	aggs    []Aggregate
	api     API
	Sleep   func(ctx context.Context, d time.Duration) error
	Logger  *slog.Logger
	MaxWait time.Duration

	stats   *collect.FormatStats
	scanned float64
}

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
	return &Collector{src: src, prof: p, aggs: Aggregates(p.Yields, checks), api: api, Sleep: sleepFor,
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

func (c *Collector) ID() string              { return c.src.ID }
func (c *Collector) Yields() []record.Kind   { return []record.Kind{c.prof.Yields} }
func (c *Collector) Profile() Profile        { return c.prof }
func (c *Collector) Aggregates() []Aggregate { return c.aggs }

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
// 解釈率が expected_match_rate を下回ったら集計クエリを流さず FORMAT_MISMATCH を返す (誤った集計で平常帯を汚さないため)。
func (c *Collector) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	from, to := DayStart(w.Start()), w.To
	c.scanned = 0
	c.stats = &collect.FormatStats{Source: c.src.ID, Format: c.src.Format, LogGroup: c.src.LogGroup, Expected: c.src.ExpectedMatchRate}
	rows, err := c.Query(ctx, LinesQuery(c.prof), from, to)
	c.stats.BytesScanned = c.scanned
	if err != nil {
		return err
	}
	var lines []record.Metric
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		total, matched := num(r[MetricLinesTotal]), num(r[MetricLinesMatched])
		c.stats.Total += int64(total)
		c.stats.Matched += int64(matched)
		lines = append(lines,
			c.metric(day, MetricLinesTotal, "", total),
			c.metric(day, MetricLinesMatched, "", matched))
	}
	if rate, ok := c.stats.Rate(); ok && rate < c.src.ExpectedMatchRate {
		return c.mismatch(ctx, from, to, rate)
	}
	if c.stats.Total == 0 {
		c.Logger.Warn("no log lines in window; check log_group / stream_prefix", "source", c.src.ID, "log_group", c.src.LogGroup,
			"from", from.Format(time.RFC3339), "to", to.Format(time.RFC3339))
	}
	for _, m := range lines {
		if err := sink.Emit(ctx, m); err != nil {
			return err
		}
	}
	if c.stats.Total == 0 {
		return nil
	}
	for _, a := range c.aggs {
		rows, err := c.Query(ctx, AggregateQuery(c.prof, a), from, to)
		c.stats.BytesScanned = c.scanned
		if err != nil {
			return err
		}
		if len(rows) >= MaxRows {
			c.Logger.Warn("aggregate truncated at row limit", "source", c.src.ID, "metric", a.Metric, "limit", MaxRows)
		}
		for _, r := range rows {
			day, ok := parseDay(r["day"])
			if !ok {
				continue
			}
			if err := sink.Emit(ctx, c.metric(day, a.Metric, Mask(r[a.KeyField]), num(r[a.Metric]))); err != nil {
				return err
			}
		}
	}
	return nil
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
func (c *Collector) Query(ctx context.Context, query string, from, to time.Time) ([]map[string]string, error) {
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

func num(s string) float64 {
	var f float64
	if _, err := fmt.Sscan(s, &f); err != nil {
		return 0
	}
	return f
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }

// Validate はクエリを StartQuery して直ちに StopQuery する。Insights の構文検査と StartQuery / StopQuery の権限だけを確かめる (doctor 用)。
func (c *Collector) Validate(ctx context.Context, query string, from, to time.Time) error {
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
