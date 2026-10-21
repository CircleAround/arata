package account

import (
	"context"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	aa "github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// UnavailableAnalyzer はアナライザーが無いときの skip の理由。
const UnavailableAnalyzer = "IAM Access Analyzer のアナライザーが無い (ACTIVE な外部アクセスのアナライザーを作ると検査できる)"

// AccessAnalyzer は ACTIVE なアナライザーの ACTIVE な findings を取り、finding ごとに 1 項目を出す collector (access_analyzer)。
// アナライザーが無ければ Unavailable を返し、access_analyzer チェックは skip される。
type AccessAnalyzer struct {
	base
	unavailable map[record.Kind]string
}

var (
	_ collect.Collector            = (*AccessAnalyzer)(nil)
	_ collect.AvailabilityReporter = (*AccessAnalyzer)(nil)
)

// NewAccessAnalyzer は collector を作る。
func NewAccessAnalyzer(id string, clients ...Clients) *AccessAnalyzer {
	return &AccessAnalyzer{base: newBase(id, clients)}
}

func (c *AccessAnalyzer) Yields() []record.Kind { return []record.Kind{record.KindAccessAnalyzer} }

func (c *AccessAnalyzer) Unavailable() map[record.Kind]string { return c.unavailable }

func (c *AccessAnalyzer) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.unavailable = nil
	at := snapshotTime(w)
	found := 0
	for _, cl := range c.clients {
		analyzers, err := activeAnalyzers(ctx, cl.AccessAnalyzer)
		if err != nil {
			return c.fail(ActionListAnalyzers, err)
		}
		found += len(analyzers)
		for _, an := range analyzers {
			in := &aa.ListFindingsInput{AnalyzerArn: an.Arn, Filter: map[string]aatypes.Criterion{"status": {Eq: []string{string(aatypes.FindingStatusActive)}}}}
			for {
				out, err := cl.AccessAnalyzer.ListFindings(ctx, in)
				if err != nil {
					return c.fail(ActionListAAFindings, err)
				}
				for _, f := range out.Findings {
					if err := sink.Emit(ctx, item(record.KindAccessAnalyzer, at, c.id, aws.ToString(f.Id), analyzerData(f, aws.ToString(an.Name), cl.Region))); err != nil {
						return err
					}
				}
				if out.NextToken == nil || *out.NextToken == "" {
					break
				}
				in.NextToken = out.NextToken
			}
		}
	}
	if found == 0 {
		c.unavailable = map[record.Kind]string{record.KindAccessAnalyzer: UnavailableAnalyzer}
	}
	return nil
}

// activeAnalyzers は ACTIVE な外部アクセスのアナライザー (ACCOUNT / ORGANIZATION)。未使用アクセスのアナライザーは対象外。
func activeAnalyzers(ctx context.Context, api AccessAnalyzerAPI) ([]aatypes.AnalyzerSummary, error) {
	var out []aatypes.AnalyzerSummary
	in := &aa.ListAnalyzersInput{}
	for {
		res, err := api.ListAnalyzers(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, a := range res.Analyzers {
			if a.Status == aatypes.AnalyzerStatusActive && (a.Type == aatypes.TypeAccount || a.Type == aatypes.TypeOrganization) {
				out = append(out, a)
			}
		}
		if res.NextToken == nil || *res.NextToken == "" {
			return out, nil
		}
		in.NextToken = res.NextToken
	}
}

func analyzerData(f aatypes.FindingSummary, analyzer, region string) map[string]any {
	actions := append([]string(nil), f.Action...)
	sort.Strings(actions)
	var principals []string
	for k, v := range f.Principal {
		principals = append(principals, k+"="+v)
	}
	sort.Strings(principals)
	return map[string]any{
		"analyzer":      analyzer,
		"region":        region,
		"resource":      aws.ToString(f.Resource),
		"resource_type": string(f.ResourceType),
		"is_public":     aws.ToBool(f.IsPublic),
		"actions":       strings.Join(actions, ","),
		"principal":     strings.Join(principals, ","),
	}
}

// Probe は ListAnalyzers を試す。
func (c *AccessAnalyzer) Probe(ctx context.Context) []collect.ProbeResult {
	var out []collect.ProbeResult
	for _, cl := range c.clients {
		as, err := activeAnalyzers(ctx, cl.AccessAnalyzer)
		r := collect.ProbeResult{Action: ActionListAnalyzers, Detail: cl.Region, Err: err}
		if err == nil && len(as) == 0 {
			r.Detail += ": " + UnavailableAnalyzer
		}
		out = append(out, r)
	}
	return out
}
