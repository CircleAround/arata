package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const s3Trail = `
name: acme
store: dir:///var/lib/arata/acme
aws:
  region: ap-northeast-1
sources:
  - id: trail
    kind: cloudtrail-s3
    bucket: example-trail-logs
    account_id: "123456789012"
    regions: [ap-northeast-1, us-east-1]
profiles:
  daily:
    window: 24h
    checks: [default-daily, root_usage]
`

func TestLoadCloudTrailS3(t *testing.T) {
	c, err := Load(write(t, s3Trail))
	if err != nil {
		t.Fatal(err)
	}
	s := c.Sources[0]
	if s.Bucket != "example-trail-logs" || s.AccountID != "123456789012" || s.Prefix != "" || s.OrganizationID != "" {
		t.Errorf("source = %+v", s)
	}
	// 決定 (ADR 0063): 記録の遅れの見込みは cloudtrail-lookup と同じ 15m。バケットのリージョンの既定は aws.region
	if s.IngestDelay != 15*time.Minute || s.BucketRegion != "ap-northeast-1" {
		t.Errorf("ingest_delay = %v, bucket_region = %q", s.IngestDelay, s.BucketRegion)
	}
	// ふだん使うリージョン (cloudtrail-unused-regions が除く) に cloudtrail-s3 の regions も入る
	if got := c.ActiveRegions(); !reflect.DeepEqual(got, []string{"ap-northeast-1", "us-east-1"}) {
		t.Errorf("ActiveRegions = %v", got)
	}
	unused := strings.Replace(s3Trail, "profiles:", "  - id: unused\n    kind: cloudtrail-unused-regions\nprofiles:", 1)
	if _, err := Load(write(t, unused)); err != nil {
		t.Errorf("cloudtrail-unused-regions with cloudtrail-s3: %v", err)
	}
}

func TestLoadCloudTrailS3Organization(t *testing.T) {
	body := strings.Replace(s3Trail, "    bucket: example-trail-logs\n",
		"    bucket: example-trail-logs\n    prefix: logs/\n    organization_id: o-exampleorg1\n    bucket_region: us-west-2\n", 1)
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if s := c.Sources[0]; s.Prefix != "logs/" || s.OrganizationID != "o-exampleorg1" || s.BucketRegion != "us-west-2" {
		t.Errorf("source = %+v", s)
	}
}

func TestLoadCloudTrailS3Invalid(t *testing.T) {
	for name, tc := range map[string]struct{ old, new, want string }{
		"bucket missing":         {"    bucket: example-trail-logs\n", "", "bucket is required"},
		"bucket name":            {"bucket: example-trail-logs", "bucket: Example_Trail", "bucket"},
		"bucket arn":             {"bucket: example-trail-logs", "bucket: arn:aws:s3:::example-trail-logs", "bucket"},
		"account missing":        {"    account_id: \"123456789012\"\n", "", "account_id is required"},
		"account form":           {`account_id: "123456789012"`, `account_id: "12345"`, "account_id"},
		"organization form":      {"    bucket: example-trail-logs\n", "    bucket: example-trail-logs\n    organization_id: org-1\n", "organization_id"},
		"prefix leading slash":   {"    bucket: example-trail-logs\n", "    bucket: example-trail-logs\n    prefix: /logs\n", "prefix"},
		"prefix dot dot":         {"    bucket: example-trail-logs\n", "    bucket: example-trail-logs\n    prefix: logs/../x\n", "prefix"},
		"prefix with AWSLogs":    {"    bucket: example-trail-logs\n", "    bucket: example-trail-logs\n    prefix: logs/AWSLogs/\n", "prefix"},
		"regions missing":        {"    regions: [ap-northeast-1, us-east-1]\n", "", "regions is required"},
		"with cloudtrail-lookup": {"profiles:", "  - id: lookup\n    kind: cloudtrail-lookup\nprofiles:", "cloudtrail-lookup"},
		"two s3 sources":         {"profiles:", "  - id: trail2\n    kind: cloudtrail-s3\n    bucket: example-trail-logs\n    account_id: \"123456789012\"\n    regions: [us-east-1]\nprofiles:", "only one"},
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(s3Trail, tc.old, tc.new, 1)
			if body == s3Trail {
				t.Fatalf("replacement %q did not apply", tc.old)
			}
			_, err := Load(write(t, body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// 効かない設定を黙って受け取らない: bucket などは cloudtrail-s3 だけ。
func TestTrailS3FieldsOnlyForS3(t *testing.T) {
	body := strings.Replace(minimal, "    kind: cloudtrail-lookup\n", "    kind: cloudtrail-lookup\n    bucket: example-trail-logs\n", 1)
	if _, err := Load(write(t, body)); err == nil || !strings.Contains(err.Error(), "cloudtrail-s3") {
		t.Errorf("err = %v", err)
	}
}
