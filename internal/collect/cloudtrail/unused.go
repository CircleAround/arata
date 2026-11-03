package cloudtrail

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	acc "github.com/aws/aws-sdk-go-v2/service/account"
	acctypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// IAM の action (doctor と読み取りロールの突き合わせに使う)。
const (
	ActionLookupEvents = "cloudtrail:LookupEvents"
	ActionListRegions  = "account:ListRegions"
)

// RegionLister は Account Management の ListRegions (有効なリージョンの一覧)。テストではフェイクを注入する。
type RegionLister interface {
	ListRegions(ctx context.Context, in *acc.ListRegionsInput, optFns ...func(*acc.Options)) (*acc.ListRegionsOutput, error)
}

// UnusedRegions は、アカウントで有効なリージョンのうちふだん使わないリージョン (Active に無いもの) の書き込みを引く collector
// (cloudtrail-unused-regions → unused_region_activity。ADR 0032)。
//
// 決定:
//   - 対象のリージョンは毎回 ListRegions (ENABLED / ENABLED_BY_DEFAULT) から Active (cloudtrail-lookup の regions) を除いて決める。
//     opt-in していないリージョンは使えないので引かない。opt-in したリージョンは次の run から対象になる
//   - 各リージョンで LookupEvents を ReadOnly=false で窓 (再走査を含む) の分だけ引く。使っていないリージョンは 0〜数件なので 1 回で済む。
//     レート制限は cloudtrail-lookup と同じ Limiter を共有する
//   - AWS のサービスの主体 (と AWS 内部の記録) は出さない。それ以外は失敗 (拒否) も含めて trail_event として出し、events に残す
//     (source はこのソースの ID。既存のチェックはこのソースのイベントを見ない)。principal_seen と主体の活動の集計は出さない
//     (new_principal / principal_new_source の結果を変えない)
//   - Yields は unused_region_event (このソースが失敗したら unused_region_activity を skip する)
type UnusedRegions struct {
	id      string
	regions RegionLister
	active  map[string]bool
	newAPI  func(ctx context.Context, region string) (API, error)
	Limiter Limiter
	Sleep   func(ctx context.Context, d time.Duration) error
	Logger  *slog.Logger
	scanned []string
}

var _ collect.Collector = (*UnusedRegions)(nil)

// NewUnusedRegions は collector を作る。active はふだん使うリージョン、newAPI はリージョンの LookupEvents のクライアントを作る。
func NewUnusedRegions(id string, regions RegionLister, active []string, newAPI func(ctx context.Context, region string) (API, error)) *UnusedRegions {
	a := map[string]bool{}
	for _, r := range active {
		a[r] = true
	}
	return &UnusedRegions{id: id, regions: regions, active: a, newAPI: newAPI, Limiter: NewLimiter(), Sleep: sleepFor,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (c *UnusedRegions) ID() string { return c.id }

func (c *UnusedRegions) Yields() []record.Kind { return []record.Kind{record.KindUnusedRegionEvent} }

// ScannedRegions は直近の Collect で引いた (引こうとした) リージョン (ソート済み)。
func (c *UnusedRegions) ScannedRegions() []string { return append([]string(nil), c.scanned...) }

// Targets は有効なリージョンのうちふだん使わないもの (ソート済み)。
func (c *UnusedRegions) Targets(ctx context.Context) ([]string, error) {
	_, out, err := c.Regions(ctx)
	return out, err
}

// Regions は有効なリージョン (enabled) と、そのうちふだん使わないもの (targets) を返す (どちらもソート済み)。
func (c *UnusedRegions) Regions(ctx context.Context) (enabled, targets []string, err error) {
	in := &acc.ListRegionsInput{RegionOptStatusContains: []acctypes.RegionOptStatus{acctypes.RegionOptStatusEnabled, acctypes.RegionOptStatusEnabledByDefault}}
	for {
		res, err := c.regions.ListRegions(ctx, in)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range res.Regions {
			name := aws.ToString(r.RegionName)
			if name == "" || (r.RegionOptStatus != acctypes.RegionOptStatusEnabled && r.RegionOptStatus != acctypes.RegionOptStatusEnabledByDefault) {
				continue
			}
			enabled = append(enabled, name)
			if !c.active[name] {
				targets = append(targets, name)
			}
		}
		if res.NextToken == nil || *res.NextToken == "" {
			break
		}
		in.NextToken = res.NextToken
	}
	sort.Strings(enabled)
	sort.Strings(targets)
	return enabled, targets, nil
}

// Probe は doctor の権限検査: ListRegions と、ふだん使わない各リージョンの LookupEvents (1 件) を試す。
func (c *UnusedRegions) Probe(ctx context.Context, now time.Time) (enabled, targets []string, results []collect.ProbeResult) {
	enabled, targets, err := c.Regions(ctx)
	if err != nil {
		return nil, nil, []collect.ProbeResult{{Action: ActionListRegions, Err: err}}
	}
	results = append(results, collect.ProbeResult{Action: ActionListRegions})
	inner := &Collector{id: c.id, Limiter: c.Limiter, Sleep: c.Sleep, Logger: c.Logger}
	for _, region := range targets {
		api, err := c.newAPI(ctx, region)
		if err == nil {
			_, err = inner.lookup(ctx, RegionClient{Region: region, API: api}, &ct.LookupEventsInput{StartTime: aws.Time(now.Add(-time.Hour)), EndTime: aws.Time(now), MaxResults: aws.Int32(1),
				LookupAttributes: []types.LookupAttribute{{AttributeKey: types.LookupAttributeKeyReadOnly, AttributeValue: aws.String("false")}}})
		}
		results = append(results, collect.ProbeResult{Action: ActionLookupEvents, Detail: region, Err: err})
	}
	return enabled, targets, results
}

func (c *UnusedRegions) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.scanned = nil
	targets, err := c.Targets(ctx)
	if err != nil {
		return collect.Classify(c.id, ActionListRegions, err)
	}
	c.scanned = targets
	inner := &Collector{id: c.id, Limiter: c.Limiter, Sleep: c.Sleep, Logger: c.Logger}
	done := map[string]bool{}
	for _, region := range targets {
		api, err := c.newAPI(ctx, region)
		if err != nil {
			return collect.Classify(c.id, ActionLookupEvents, fmt.Errorf("region %s: %w", region, err))
		}
		n, err := c.collectRegion(ctx, inner, RegionClient{Region: region, API: api}, w, sink, done)
		if err != nil {
			return err
		}
		c.Logger.Info("unused region scanned", "source", c.id, "region", region, "writes", n)
	}
	return nil
}

func (c *UnusedRegions) collectRegion(ctx context.Context, inner *Collector, rc RegionClient, w collect.Window, sink collect.RecordSink, done map[string]bool) (int, error) {
	in := &ct.LookupEventsInput{
		StartTime:        aws.Time(w.Start()),
		EndTime:          aws.Time(w.To),
		MaxResults:       aws.Int32(50),
		LookupAttributes: []types.LookupAttribute{{AttributeKey: types.LookupAttributeKeyReadOnly, AttributeValue: aws.String("false")}},
	}
	n, pages := 0, 0
	for {
		out, err := inner.lookup(ctx, rc, in)
		if err != nil {
			ce := collect.Classify(c.id, ActionLookupEvents, err)
			ce.Err = fmt.Errorf("region %s (after %d pages): %w", rc.Region, pages, ce.Err)
			return n, ce
		}
		pages++
		for _, raw := range out.Events {
			e, ok := inner.normalize(raw)
			if !ok || done[e.EventID] || e.ReadOnly || e.PrincipalKind == record.PrincipalService {
				continue
			}
			done[e.EventID] = true
			if err := sink.Emit(ctx, e); err != nil {
				return n, err
			}
			n++
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return n, nil
		}
		in.NextToken = out.NextToken
	}
}
