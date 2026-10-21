// Package cwlogstest は Logs Insights (StartQuery / GetQueryResults) のフェイクを提供する。
// Insights のクエリ言語は解釈しない。クエリ文字列に含まれる部分文字列 (集計の metric 名など) で応答を選ぶ。
package cwlogstest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
)

// Response はクエリ 1 本への応答。
type Response struct {
	Rows []map[string]string
	// RowsFor が非 nil なら Rows の代わりに使う (問い合わせ範囲に応じた結果を返すため)。
	RowsFor func(in *cwl.StartQueryInput) []map[string]string
	// Status は完了時の状態 (空なら Complete)。
	Status types.QueryStatus
	// Polls は Complete を返すまでに Running を返す回数。
	Polls int
	// BytesScanned は Statistics.BytesScanned。
	BytesScanned float64
	// StartErr は StartQuery のエラー。StartErrTimes > 0 ならその回数だけ返して以後は成功する。
	StartErr      error
	StartErrTimes int
}

type handler struct {
	contains string
	resp     Response
}

type running struct {
	resp  Response
	polls int
}

// Fake は API のフェイク。
type Fake struct {
	mu       sync.Mutex
	handlers []handler
	queries  map[string]*running
	// Started は StartQuery に渡された入力 (順番どおり)。
	Started []*cwl.StartQueryInput
	Stopped []string
	// LogGroups は DescribeLogGroups が返すロググループ名。
	LogGroups []string
	// DescribeErr / StartErr / ResultsErr は全呼び出しで返すエラー。
	DescribeErr error
	StartErr    error
	ResultsErr  error
	nextID      int
}

// On はクエリ文字列に contains を含むクエリへの応答を登録する。後から登録したものが優先。
func (f *Fake) On(contains string, resp Response) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers = append([]handler{{contains: contains, resp: resp}}, f.handlers...)
}

// Rows は On に渡す行を組み立てる。kv は field, value, field, value, ...
func Rows(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// Queries は StartQuery に渡されたクエリ文字列の一覧。
func (f *Fake) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.Started))
	for _, in := range f.Started {
		out = append(out, aws.ToString(in.QueryString))
	}
	return out
}

func (f *Fake) StartQuery(_ context.Context, in *cwl.StartQueryInput, _ ...func(*cwl.Options)) (*cwl.StartQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.StartErr != nil {
		return nil, f.StartErr
	}
	q := aws.ToString(in.QueryString)
	var resp Response
	idx := -1
	for i, h := range f.handlers {
		if strings.Contains(q, h.contains) {
			resp, idx = h.resp, i
			break
		}
	}
	if idx >= 0 && resp.StartErr != nil {
		if resp.StartErrTimes > 0 {
			f.handlers[idx].resp.StartErrTimes--
			if f.handlers[idx].resp.StartErrTimes == 0 {
				f.handlers[idx].resp.StartErr = nil
			}
		}
		return nil, resp.StartErr
	}
	f.Started = append(f.Started, in)
	f.nextID++
	id := fmt.Sprintf("q-%03d", f.nextID)
	if f.queries == nil {
		f.queries = map[string]*running{}
	}
	if resp.RowsFor != nil {
		resp.Rows = resp.RowsFor(in)
	}
	f.queries[id] = &running{resp: resp}
	return &cwl.StartQueryOutput{QueryId: aws.String(id)}, nil
}

func (f *Fake) GetQueryResults(_ context.Context, in *cwl.GetQueryResultsInput, _ ...func(*cwl.Options)) (*cwl.GetQueryResultsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ResultsErr != nil {
		return nil, f.ResultsErr
	}
	r, ok := f.queries[aws.ToString(in.QueryId)]
	if !ok {
		return nil, APIError{Code: "InvalidParameterException"}
	}
	stats := &types.QueryStatistics{BytesScanned: r.resp.BytesScanned}
	if r.polls < r.resp.Polls {
		r.polls++
		return &cwl.GetQueryResultsOutput{Status: types.QueryStatusRunning, Statistics: stats}, nil
	}
	status := r.resp.Status
	if status == "" {
		status = types.QueryStatusComplete
	}
	out := &cwl.GetQueryResultsOutput{Status: status, Statistics: stats}
	for _, row := range r.resp.Rows {
		var fields []types.ResultField
		for k, v := range row {
			fields = append(fields, types.ResultField{Field: aws.String(k), Value: aws.String(v)})
		}
		fields = append(fields, types.ResultField{Field: aws.String("@ptr"), Value: aws.String("ptr")})
		out.Results = append(out.Results, fields)
	}
	return out, nil
}

func (f *Fake) StopQuery(_ context.Context, in *cwl.StopQueryInput, _ ...func(*cwl.Options)) (*cwl.StopQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Stopped = append(f.Stopped, aws.ToString(in.QueryId))
	return &cwl.StopQueryOutput{Success: true}, nil
}

func (f *Fake) DescribeLogGroups(_ context.Context, in *cwl.DescribeLogGroupsInput, _ ...func(*cwl.Options)) (*cwl.DescribeLogGroupsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DescribeErr != nil {
		return nil, f.DescribeErr
	}
	out := &cwl.DescribeLogGroupsOutput{}
	for _, name := range f.LogGroups {
		if strings.HasPrefix(name, aws.ToString(in.LogGroupNamePrefix)) {
			out.LogGroups = append(out.LogGroups, types.LogGroup{LogGroupName: aws.String(name)})
		}
	}
	return out, nil
}

// APIError は smithy.APIError を満たす最小のエラー。
type APIError struct{ Code string }

func (e APIError) Error() string                 { return e.Code }
func (e APIError) ErrorCode() string             { return e.Code }
func (e APIError) ErrorMessage() string          { return e.Code }
func (e APIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

var _ smithy.APIError = APIError{}
