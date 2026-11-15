package config

import (
	"fmt"
	"regexp"
	"strings"
)

// cloudtrail-s3 のソースの検証 (ADR 0063)。
//
// 決定:
//   - bucket・account_id・regions は必須。account_id は**監査されるアカウント** (trail のキーの AWSLogs/[<o-id>/]<account-id>/ に入る)。
//     ADR 0063 の設定の例は「省略すると監査する側のアカウント (audit_account)」と書いたが、audit_account は監査する側 (引き受ける側) のアカウントで、
//     読む記録のアカウントとは違う。取り違えると別のアカウントの記録を読むか、何も読まないので、省略させない
//   - 同じ設定に cloudtrail-lookup と cloudtrail-s3 を並べない。cloudtrail-s3 も 1 つだけ。どれも trail_event と principal_seen を出し、
//     同じ run が両方を引くと events は event_id で重複しないが、principal_ips の件数と主体の活動の集計が二重に足される
//   - bucket・prefix・organization_id・account_id・bucket_region は cloudtrail-s3 だけ (効かない設定を黙って受け取らない)

var (
	// bucketName は S3 の汎用バケットの名前の規則 (3〜63 文字、小文字・数字・. ・-、先頭と末尾は英数字)。ARN や s3:// は通さない。
	bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	accountID  = regexp.MustCompile(`^\d{12}$`)
	orgID      = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	// trailPrefix は trail の S3 キーの接頭辞に使える文字 (公式のキーの例と同じ範囲に絞る)。
	trailPrefix = regexp.MustCompile(`^[A-Za-z0-9!_.'()/-]*$`)
)

func (s *Source) validateTrailS3() error {
	if s.Kind != KindCloudTrailS3 {
		for name, v := range map[string]string{"bucket": s.Bucket, "prefix": s.Prefix, "organization_id": s.OrganizationID, "account_id": s.AccountID, "bucket_region": s.BucketRegion} {
			if v != "" {
				return fmt.Errorf("%s is only for kind %s", name, KindCloudTrailS3)
			}
		}
		return nil
	}
	if s.Bucket == "" {
		return fmt.Errorf("bucket is required for kind %s (the bucket the trail delivers to)", KindCloudTrailS3)
	}
	if !bucketName.MatchString(s.Bucket) {
		return fmt.Errorf("bucket %q: write the bucket name only (lowercase letters, digits, . and -; not an ARN or s3:// URL)", s.Bucket)
	}
	if s.AccountID == "" {
		return fmt.Errorf("account_id is required for kind %s (the 12-digit ID of the audited account, as in the trail's keys AWSLogs/<account-id>/)", KindCloudTrailS3)
	}
	if !accountID.MatchString(s.AccountID) {
		return fmt.Errorf("account_id %q: want a 12-digit account ID", s.AccountID)
	}
	if s.OrganizationID != "" && !orgID.MatchString(s.OrganizationID) {
		return fmt.Errorf("organization_id %q: want o- followed by 10 to 32 lowercase letters or digits", s.OrganizationID)
	}
	if err := validTrailPrefix(s.Prefix); err != nil {
		return err
	}
	return nil
}

// validTrailPrefix は trail の S3 キーの接頭辞 (trail の S3KeyPrefix。AWSLogs/ の手前まで) を確かめる。
func validTrailPrefix(p string) error {
	if p == "" {
		return nil
	}
	if strings.HasPrefix(p, "/") || !trailPrefix.MatchString(p) {
		return fmt.Errorf("prefix %q: write the trail's S3 key prefix without a leading / (letters, digits and !_.'()/-; no wildcards)", p)
	}
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg == "." || seg == ".." || seg == "" {
			return fmt.Errorf("prefix %q: must not contain empty, . or .. segments", p)
		}
		if seg == "AWSLogs" {
			return fmt.Errorf("prefix %q: write only the part before AWSLogs/ (arata adds AWSLogs/[<organization_id>/]<account_id>/CloudTrail/)", p)
		}
	}
	return nil
}

// validateTrailSources は CloudTrail の記録を出すソースが二重にならないかを確かめる。
func (c *Config) validateTrailSources() error {
	var lookup, s3 []string
	for _, s := range c.Sources {
		switch s.Kind {
		case KindCloudTrailLookup:
			lookup = append(lookup, s.ID)
		case KindCloudTrailS3:
			s3 = append(s3, s.ID)
		}
	}
	if len(s3) > 1 {
		return fmt.Errorf("config: sources %s: write only one %s source (each reads every management event of the account; two would count principals twice)", strings.Join(s3, ", "), KindCloudTrailS3)
	}
	if len(s3) > 0 && len(lookup) > 0 {
		return fmt.Errorf("config: sources %s and %s: use either %s or %s, not both (both yield the same events; principal counts would be added twice). Remove the cloudtrail-lookup source when you move to cloudtrail-s3",
			strings.Join(lookup, ", "), s3[0], KindCloudTrailLookup, KindCloudTrailS3)
	}
	return nil
}
