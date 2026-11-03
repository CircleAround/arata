package cloudtrail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	acc "github.com/aws/aws-sdk-go-v2/service/account"
	acctypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/record"
)

type fakeRegions struct {
	regions map[string]acctypes.RegionOptStatus
	err     error
	calls   []*acc.ListRegionsInput
}

func (f *fakeRegions) ListRegions(_ context.Context, in *acc.ListRegionsInput, _ ...func(*acc.Options)) (*acc.ListRegionsOutput, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	// 1 件ずつページに分けて返す (ページングを確かめる)
	var names []string
	for n := range f.regions {
		names = append(names, n)
	}
	sortStrings(names)
	i := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &i)
	}
	out := &acc.ListRegionsOutput{}
	if i < len(names) {
		st := f.regions[names[i]]
		if len(in.RegionOptStatusContains) == 0 || containsStatus(in.RegionOptStatusContains, st) {
			out.Regions = append(out.Regions, acctypes.Region{RegionName: aws.String(names[i]), RegionOptStatus: st})
		}
	}
	if i+1 < len(names) {
		out.NextToken = aws.String(fmt.Sprint(i + 1))
	}
	return out, nil
}

func containsStatus(l []acctypes.RegionOptStatus, s acctypes.RegionOptStatus) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

type sinkRecs struct{ recs []record.Record }

func (s *sinkRecs) Emit(_ context.Context, r record.Record) error {
	s.recs = append(s.recs, r)
	return nil
}

type countLimiter struct{ n int }

func (l *countLimiter) Wait(context.Context) error { l.n++; return nil }

const acctID = "123456789012"

// 対象 = 有効なリージョン (ENABLED / ENABLED_BY_DEFAULT) − ふだん使うリージョン。各リージョンで書き込みだけを引き、
// サービスの主体を除いた書き込みを trail_event として出す (principal_seen と活動の集計は出さない)。
func TestUnusedRegionsCollect(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	regions := &fakeRegions{regions: map[string]acctypes.RegionOptStatus{
		"ap-northeast-1": acctypes.RegionOptStatusEnabledByDefault,
		"us-east-1":      acctypes.RegionOptStatusEnabledByDefault,
		"eu-west-1":      acctypes.RegionOptStatusEnabledByDefault,
		"sa-east-1":      acctypes.RegionOptStatusEnabledByDefault,
		"af-south-1":     acctypes.RegionOptStatusDisabled, // opt-in していない
		"me-central-1":   acctypes.RegionOptStatusEnabled,  // opt-in 済み
	}}
	fakes := map[string]*cloudtrailtest.Fake{}
	for _, r := range []string{"eu-west-1", "sa-east-1", "me-central-1"} {
		fakes[r] = &cloudtrailtest.Fake{}
	}
	user := cloudtrailtest.User(acctID, "alice")
	fakes["eu-west-1"].Add(
		cloudtrailtest.Event("e1", t0.Add(time.Hour), user, "ec2.amazonaws.com", "RunInstances", "eu-west-1", "198.51.100.7", false, map[string]any{"instanceType": "p3.16xlarge"}),
		cloudtrailtest.Event("e2", t0.Add(2*time.Hour), cloudtrailtest.Service("config.amazonaws.com"), "config.amazonaws.com", "PutEvaluations", "eu-west-1", "config.amazonaws.com", false, nil),
		cloudtrailtest.Event("e3", t0.Add(3*time.Hour), user, "ec2.amazonaws.com", "DescribeInstances", "eu-west-1", "198.51.100.7", true, nil),
	)
	fakes["me-central-1"].Add(cloudtrailtest.WithError(
		cloudtrailtest.Event("e4", t0.Add(4*time.Hour), user, "lambda.amazonaws.com", "CreateFunction20150331", "me-central-1", "198.51.100.7", false, nil), "AccessDeniedException"))
	var asked []string
	lim := &countLimiter{}
	c := NewUnusedRegions("unused", regions, []string{"ap-northeast-1", "us-east-1"}, func(_ context.Context, region string) (API, error) {
		asked = append(asked, region)
		return fakes[region], nil
	})
	c.Limiter = lim
	sink := &sinkRecs{}
	w := collect.Window{From: t0, To: t0.Add(24 * time.Hour), ScanFrom: t0.Add(-15 * time.Minute)}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(asked, ","); got != "eu-west-1,me-central-1,sa-east-1" {
		t.Fatalf("scanned regions: %q", got)
	}
	if got := strings.Join(c.ScannedRegions(), ","); got != "eu-west-1,me-central-1,sa-east-1" {
		t.Fatalf("ScannedRegions: %q", got)
	}
	// ListRegions は有効なものだけを問い合わせる
	if st := regions.calls[0].RegionOptStatusContains; len(st) != 2 {
		t.Fatalf("ListRegions filter: %v", st)
	}
	// LookupEvents は ReadOnly=false で、窓 (再走査を含む) を引く。使っていないリージョンは 1 回で済む
	for r, f := range fakes {
		if len(f.Calls) != 1 {
			t.Fatalf("%s: calls %d", r, len(f.Calls))
		}
		in := f.Calls[0]
		if len(in.LookupAttributes) != 1 || in.LookupAttributes[0].AttributeKey != types.LookupAttributeKeyReadOnly || aws.ToString(in.LookupAttributes[0].AttributeValue) != "false" {
			t.Fatalf("%s: attributes %+v", r, in.LookupAttributes)
		}
		if !aws.ToTime(in.StartTime).Equal(w.ScanFrom) || !aws.ToTime(in.EndTime).Equal(w.To) {
			t.Fatalf("%s: range %v %v", r, in.StartTime, in.EndTime)
		}
	}
	if lim.n != 3 {
		t.Fatalf("limiter waits: %d", lim.n)
	}
	var ids []string
	for _, r := range sink.recs {
		e, ok := r.(record.TrailEvent)
		if !ok {
			t.Fatalf("only trail events are emitted: %T", r)
		}
		if e.Source != "unused" {
			t.Fatalf("source: %q", e.Source)
		}
		ids = append(ids, e.EventID)
	}
	// サービスの主体 (e2) は出さない。読み取り (e3) は ReadOnly=false の問い合わせで来ない。拒否された試行 (e4) は出す
	if got := strings.Join(ids, ","); got != "e1,e4" {
		t.Fatalf("emitted: %q", got)
	}
}

func TestUnusedRegionsErrors(t *testing.T) {
	denied := cloudtrailtest.APIError{Code: "AccessDeniedException"}
	c := NewUnusedRegions("unused", &fakeRegions{err: denied}, []string{"ap-northeast-1"}, nil)
	c.Limiter = &countLimiter{}
	err := c.Collect(context.Background(), collect.Window{From: time.Now().Add(-time.Hour), To: time.Now()}, &sinkRecs{})
	var ce *collect.Error
	if !errors.As(err, &ce) || ce.Code != collect.CodeAccessDenied || ce.Action != "account:ListRegions" {
		t.Fatalf("ListRegions denied: %v", err)
	}

	regions := &fakeRegions{regions: map[string]acctypes.RegionOptStatus{"ap-northeast-1": acctypes.RegionOptStatusEnabledByDefault, "eu-west-1": acctypes.RegionOptStatusEnabledByDefault}}
	c = NewUnusedRegions("unused", regions, []string{"ap-northeast-1"}, func(context.Context, string) (API, error) {
		return &cloudtrailtest.Fake{Err: denied}, nil
	})
	c.Limiter = &countLimiter{}
	err = c.Collect(context.Background(), collect.Window{From: time.Now().Add(-time.Hour), To: time.Now()}, &sinkRecs{})
	if !errors.As(err, &ce) || ce.Code != collect.CodeAccessDenied || ce.Action != "cloudtrail:LookupEvents" || !strings.Contains(err.Error(), "eu-west-1") {
		t.Fatalf("LookupEvents denied: %v", err)
	}
	if c.Yields()[0] != record.KindUnusedRegionEvent || len(c.Yields()) != 1 {
		t.Fatalf("yields: %v", c.Yields())
	}
}
