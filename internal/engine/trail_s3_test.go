package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/config"
)

// newS3Harness は cloudtrail-s3 だけをソースにした設定で harness を作る (ADR 0063)。S3 は偽物で、実 AWS には繋がない。
func newS3Harness(t *testing.T) (*harness, *cloudtrailtest.S3) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`
name: acme
store: dir://%s/store
sources:
  - id: trail
    kind: cloudtrail-s3
    bucket: example-trail-logs
    account_id: "%s"
    regions: [ap-northeast-1, us-east-1]
    bucket_region: us-west-2
profiles:
  daily:
    window: 24h
    checks: [default-daily, root_usage, unknown_assume_role, oidc_assume_role]
`, dir, acct)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg = cfg
	bucket := &cloudtrailtest.S3{}
	h.deps.CloudTrail = func(context.Context, *config.Config, config.Source, string) (cloudtrail.API, error) {
		t.Fatal("cloudtrail-s3 must not call LookupEvents")
		return nil, nil
	}
	h.deps.CloudTrailS3 = func(_ context.Context, _ *config.Config, src config.Source) (cloudtrail.S3API, error) {
		h.regions = append(h.regions, src.BucketRegion)
		return bucket, nil
	}
	return h, bucket
}

func putTrail(b *cloudtrailtest.S3, region string, delivered time.Time, suffix string, evs ...cttypes.Event) {
	b.Put(cloudtrailtest.TrailKey("", "", acct, region, delivered, suffix), cloudtrailtest.TrailFile("Management", evs...))
}

// trail の S3 から読んだ記録で、LookupEvents のときと同じチェックが動く (root_usage・new_principal・access_denied)。
func TestRunCloudTrailS3(t *testing.T) {
	h, bucket := newS3Harness(t)
	ctx := context.Background()
	at := h.now.Add(-2 * time.Hour)
	scanner := cloudtrailtest.AssumedRole(acct, "example-scanner", "s1")
	var denied []cttypes.Event
	for i, api := range [][2]string{{"iam.amazonaws.com", "ListUsers"}, {"s3.amazonaws.com", "ListBuckets"}, {"secretsmanager.amazonaws.com", "ListSecrets"},
		{"iam.amazonaws.com", "ListRoles"}, {"ec2.amazonaws.com", "DescribeInstances"}, {"kms.amazonaws.com", "ListKeys"}} {
		denied = append(denied, cloudtrailtest.WithError(cloudtrailtest.Event(fmt.Sprintf("d%d", i), at, scanner, api[0], api[1], "ap-northeast-1", "198.51.100.1", true, nil), "AccessDenied"))
	}
	putTrail(bucket, "ap-northeast-1", at.Add(5*time.Minute), "A000000000000000", denied...)
	putTrail(bucket, "us-east-1", h.now.Add(-time.Hour+5*time.Minute), "B000000000000000",
		cloudtrailtest.Event("root", h.now.Add(-time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
	// data event は数えない
	bucket.Put(cloudtrailtest.TrailKey("", "", acct, "ap-northeast-1", at.Add(6*time.Minute), "C000000000000000"),
		cloudtrailtest.TrailFile("Data", cloudtrailtest.Event("data", at, cloudtrailtest.User(acct, "mallory"), "s3.amazonaws.com", "GetObject", "ap-northeast-1", "198.51.100.9", true, nil)))

	e := h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != ExitOK || len(r.Report.Coverage.SourcesOK) != 1 {
		t.Fatalf("exit = %d, coverage = %+v", r.Exit, r.Report.Coverage)
	}
	got := map[string]string{}
	for _, f := range r.Report.Findings.New {
		got[f.Check] = f.Key
	}
	if !strings.HasPrefix(got["root_usage"], "arn:aws:iam::"+acct+":root|") {
		t.Errorf("root_usage: %+v", got)
	}
	if got["access_denied"] != "arn:aws:iam::"+acct+":role/example-scanner" {
		t.Errorf("access_denied: %+v", got)
	}
	if got["new_principal"] != "arn:aws:iam::"+acct+":role/example-scanner" {
		t.Errorf("new_principal should see the scanner but not the data event's principal: %+v", got)
	}
	// クライアントはバケットのリージョンに向ける
	if strings.Join(h.regions, ",") != "us-west-2" {
		t.Errorf("bucket regions = %v", h.regions)
	}
	// 収集の時刻と読んだファイルの数が INFO に残る
	if !strings.Contains(h.stderr.String(), `"files":2`) {
		t.Errorf("want the number of files read in the log: %s", h.stderr.String())
	}
}

// trailInfo は DescribeTrails と GetEventSelectors の偽物。
type trailInfo struct {
	trails []cttypes.Trail
	sel    *ct.GetEventSelectorsOutput
	selErr error
}

func (f *trailInfo) DescribeTrails(context.Context, *ct.DescribeTrailsInput, ...func(*ct.Options)) (*ct.DescribeTrailsOutput, error) {
	return &ct.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f *trailInfo) GetEventSelectors(context.Context, *ct.GetEventSelectorsInput, ...func(*ct.Options)) (*ct.GetEventSelectorsOutput, error) {
	return f.sel, f.selErr
}

func TestDoctorCloudTrailS3(t *testing.T) {
	h, bucket := newS3Harness(t)
	trailARN := "arn:aws:cloudtrail:ap-northeast-1:" + acct + ":trail/main"
	info := &trailInfo{
		trails: []cttypes.Trail{{Name: aws.String("main"), TrailARN: aws.String(trailARN), S3BucketName: aws.String("example-trail-logs"), HomeRegion: aws.String("ap-northeast-1"), IsMultiRegionTrail: aws.Bool(false)}},
		sel:    &ct.GetEventSelectorsOutput{EventSelectors: []cttypes.EventSelector{{ReadWriteType: cttypes.ReadWriteTypeWriteOnly, IncludeManagementEvents: aws.Bool(true), ExcludeManagementEventSources: []string{"kms.amazonaws.com"}}}},
	}
	h.deps.TrailInfo = func(context.Context, *config.Config, string) (cloudtrail.TrailInfoAPI, error) { return info, nil }
	putTrail(bucket, "ap-northeast-1", h.now.Add(-10*time.Minute), "A000000000000000",
		cloudtrailtest.Event("a", h.now.Add(-15*time.Minute), cloudtrailtest.User(acct, "alice"), "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "198.51.100.7", true, nil))
	k := cloudtrailtest.TrailKey("", "", acct, "us-east-1", h.now.Add(-10*time.Minute), "B000000000000000")
	bucket.Put(k, cloudtrailtest.TrailFile("Management"))
	bucket.GetErrFor = map[string]error{k: cloudtrailtest.APIError{Code: "AccessDenied"}}

	res := Doctor(context.Background(), h.cfg, h.deps, time.Hour)
	var lines []string
	for _, row := range doctorRows(res, "trail") {
		lines = append(lines, row.Item+" "+row.Status+" "+row.Detail)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"permission ok s3:ListBucket (ap-northeast-1)",
		"permission ok s3:GetObject (ap-northeast-1。直近のファイルの記録 1 件)",
		"permission ng s3:GetObject が拒否された: s3:GetObject (us-east-1): AccessDenied",
		"キーポリシーの kms:Decrypt",
		"trail warn " + trailARN + " はマルチリージョンの trail でなく、us-east-1 を記録しない",
		"trail warn " + trailARN + ": 読み取りの管理イベントを記録していない",
		"kms.amazonaws.com を除いている",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor rows lack %q:\n%s", want, got)
		}
	}
	for _, a := range []string{"s3:GetObject", "s3:ListBucket", "cloudtrail:GetEventSelectors", "cloudtrail:DescribeTrails"} {
		if !slices.Contains(res.RequiredActions, a) {
			t.Errorf("required_actions lacks %s: %v", a, res.RequiredActions)
		}
	}
	if slices.Contains(res.RequiredActions, "cloudtrail:LookupEvents") {
		t.Errorf("cloudtrail-s3 alone does not need LookupEvents: %v", res.RequiredActions)
	}

	// 全部を記録しているマルチリージョンの trail なら ok。ファイルが無いリージョンは warn
	info.trails[0].IsMultiRegionTrail = aws.Bool(true)
	info.sel = &ct.GetEventSelectorsOutput{EventSelectors: []cttypes.EventSelector{{ReadWriteType: cttypes.ReadWriteTypeAll, IncludeManagementEvents: aws.Bool(true)}}}
	bucket.Objects = nil
	res = Doctor(context.Background(), h.cfg, h.deps, time.Hour)
	lines = nil
	for _, row := range doctorRows(res, "trail") {
		lines = append(lines, row.Item+" "+row.Status+" "+row.Detail)
	}
	got = strings.Join(lines, "\n")
	for _, want := range []string{
		"permission warn s3:ListBucket (ap-northeast-1): s3://example-trail-logs/AWSLogs/" + acct + "/CloudTrail/ap-northeast-1/ の下に直近 2 日のファイルが無い",
		"trail ok " + trailARN + ": 管理イベントの読み取りと書き込みを全部記録している",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor rows lack %q:\n%s", want, got)
		}
	}
}

func TestTrailSelectorProblems(t *testing.T) {
	adv := func(fs ...cttypes.AdvancedFieldSelector) cttypes.AdvancedEventSelector {
		return cttypes.AdvancedEventSelector{FieldSelectors: fs}
	}
	field := func(name string, eq []string, ne []string) cttypes.AdvancedFieldSelector {
		return cttypes.AdvancedFieldSelector{Field: aws.String(name), Equals: eq, NotEquals: ne}
	}
	for name, tc := range map[string]struct {
		in   ct.GetEventSelectorsOutput
		want string
	}{
		"basic all":        {ct.GetEventSelectorsOutput{EventSelectors: []cttypes.EventSelector{{ReadWriteType: cttypes.ReadWriteTypeAll}}}, ""},
		"basic read+write": {ct.GetEventSelectorsOutput{EventSelectors: []cttypes.EventSelector{{ReadWriteType: cttypes.ReadWriteTypeReadOnly}, {ReadWriteType: cttypes.ReadWriteTypeWriteOnly}}}, ""},
		"basic no mgmt":    {ct.GetEventSelectorsOutput{EventSelectors: []cttypes.EventSelector{{ReadWriteType: cttypes.ReadWriteTypeAll, IncludeManagementEvents: aws.Bool(false)}}}, "管理イベントを記録していない"},
		"advanced all":     {ct.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{adv(field("eventCategory", []string{"Management"}, nil))}}, ""},
		"advanced write only": {ct.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{
			adv(field("eventCategory", []string{"Management"}, nil), field("readOnly", []string{"false"}, nil))}}, "読み取りの管理イベントを記録していない"},
		"advanced excludes kms": {ct.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{
			adv(field("eventCategory", []string{"Management"}, nil), field("eventSource", nil, []string{"kms.amazonaws.com", "rdsdata.amazonaws.com"}))}}, "kms.amazonaws.com, rdsdata.amazonaws.com を除いている"},
		"advanced data only": {ct.GetEventSelectorsOutput{AdvancedEventSelectors: []cttypes.AdvancedEventSelector{adv(field("eventCategory", []string{"Data"}, nil))}}, "管理イベントを記録していない"},
	} {
		t.Run(name, func(t *testing.T) {
			got := strings.Join(TrailSelectorProblems(&tc.in), "。")
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
