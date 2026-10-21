package account

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// UnavailableGuardDuty は GuardDuty が有効でないときの skip の理由。
const UnavailableGuardDuty = "GuardDuty が有効でない (detector が無い / 停止中)。posture の guardduty_enabled を見る"

// GuardDuty はアーカイブされていない GuardDuty の findings を取り、finding ごとに 1 項目を出す collector (guardduty)。
// detector が無い (無効) なら Unavailable を返し、guardduty_findings は skip される (無効であること自体は posture が報告する)。
type GuardDuty struct {
	base
	unavailable map[record.Kind]string
}

var (
	_ collect.Collector            = (*GuardDuty)(nil)
	_ collect.AvailabilityReporter = (*GuardDuty)(nil)
)

// NewGuardDuty は collector を作る。リージョンごとの clients を順に引く。
func NewGuardDuty(id string, clients ...Clients) *GuardDuty {
	return &GuardDuty{base: newBase(id, clients)}
}

func (c *GuardDuty) Yields() []record.Kind { return []record.Kind{record.KindGuardDuty} }

func (c *GuardDuty) Unavailable() map[record.Kind]string { return c.unavailable }

func (c *GuardDuty) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.unavailable = nil
	at := snapshotTime(w)
	enabled := 0
	for _, cl := range c.clients {
		ids, err := enabledDetectors(ctx, cl.GuardDuty)
		if err != nil {
			return c.fail(err.action, err.err)
		}
		enabled += len(ids)
		for _, det := range ids {
			if err := c.collectDetector(ctx, cl, det, at, sink); err != nil {
				return err
			}
		}
	}
	if enabled == 0 {
		c.unavailable = map[record.Kind]string{record.KindGuardDuty: UnavailableGuardDuty}
	}
	return nil
}

func (c *GuardDuty) collectDetector(ctx context.Context, cl Clients, det string, at time.Time, sink collect.RecordSink) error {
	in := &gd.ListFindingsInput{DetectorId: aws.String(det), MaxResults: aws.Int32(50),
		FindingCriteria: &gdtypes.FindingCriteria{Criterion: map[string]gdtypes.Condition{"service.archived": {Eq: []string{"false"}}}}}
	for {
		out, err := cl.GuardDuty.ListFindings(ctx, in)
		if err != nil {
			return c.fail(ActionListGDFindings, err)
		}
		if len(out.FindingIds) > 0 {
			got, err := cl.GuardDuty.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: aws.String(det), FindingIds: out.FindingIds})
			if err != nil {
				return c.fail(ActionGetGDFindings, err)
			}
			for _, f := range got.Findings {
				if err := sink.Emit(ctx, item(record.KindGuardDuty, at, c.id, aws.ToString(f.Id), guardDutyData(f, cl.Region))); err != nil {
					return err
				}
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil
		}
		in.NextToken = out.NextToken
	}
}

func guardDutyData(f gdtypes.Finding, region string) map[string]any {
	d := map[string]any{
		"type":       aws.ToString(f.Type),
		"title":      aws.ToString(f.Title),
		"severity":   aws.ToFloat64(f.Severity),
		"region":     aws.ToString(f.Region),
		"updated_at": aws.ToString(f.UpdatedAt),
		"count":      0,
	}
	if d["region"] == "" {
		d["region"] = region
	}
	if f.Resource != nil {
		d["resource_type"] = aws.ToString(f.Resource.ResourceType)
	}
	if f.Service != nil {
		d["count"] = int(aws.ToInt32(f.Service.Count))
	}
	return d
}

type actionErr struct {
	action string
	err    error
}

// enabledDetectors は ENABLED の detector ID。detector が無ければ空。
func enabledDetectors(ctx context.Context, api GuardDutyAPI) ([]string, *actionErr) {
	out, err := api.ListDetectors(ctx, &gd.ListDetectorsInput{})
	if err != nil {
		return nil, &actionErr{ActionListDetectors, err}
	}
	var ids []string
	for _, id := range out.DetectorIds {
		det, err := api.GetDetector(ctx, &gd.GetDetectorInput{DetectorId: aws.String(id)})
		if err != nil {
			return nil, &actionErr{ActionGetDetector, err}
		}
		if det.Status == gdtypes.DetectorStatusEnabled {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// Probe は ListDetectors / GetDetector と、detector があれば ListFindings を 1 件だけ試す。
func (c *GuardDuty) Probe(ctx context.Context) []collect.ProbeResult {
	var out []collect.ProbeResult
	for _, cl := range c.clients {
		ids, err := enabledDetectors(ctx, cl.GuardDuty)
		if err != nil {
			return append(out, collect.ProbeResult{Action: err.action, Detail: cl.Region, Err: err.err})
		}
		out = append(out, collect.ProbeResult{Action: ActionListDetectors, Detail: cl.Region})
		if len(ids) == 0 {
			out = append(out, collect.ProbeResult{Action: ActionListGDFindings, Detail: cl.Region + ": " + UnavailableGuardDuty})
			continue
		}
		_, lerr := cl.GuardDuty.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: aws.String(ids[0]), MaxResults: aws.Int32(1)})
		out = append(out, collect.ProbeResult{Action: ActionListGDFindings, Detail: cl.Region, Err: lerr})
	}
	return out
}
