package cloudtrail

import (
	"encoding/json"
	"testing"

	"github.com/CircleAround/arata/internal/record"
)

// 全開放を複数の CIDR に分けても、広い範囲は公開として拾う。私設の範囲は公開ではない。
func TestPublicCIDR(t *testing.T) {
	for _, c := range []string{"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "0:0:0:0:0:0:0:0/0", "64.0.0.0/2", "1.0.0.0/8"} {
		if !publicCIDR(c) {
			t.Errorf("%s は公開", c)
		}
	}
	for _, c := range []string{"10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24", "192.0.2.1/32", "fc00::/7", "fe80::/10", "2001:db8::/32", "not-a-cidr", ""} {
		if publicCIDR(c) {
			t.Errorf("%s は公開ではない", c)
		}
	}
}

func policy(t *testing.T, statement string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(`{"Statement":[`+statement+`]}`), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// 条件キーがあるだけでは絞り込みとみなさない。値と演算子を見る。
func TestPublicStatementsLooksAtConditionValues(t *testing.T) {
	allow := `"Effect":"Allow","Action":"s3:GetObject","Resource":"*"`
	public := []string{
		`{` + allow + `,"Principal":"*"}`,
		`{` + allow + `,"Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":["192.0.2.0/24","::/0"]}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"192.0.2.1/32"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-1"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringLike":{"aws:PrincipalArn":"*"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/x"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringEqualsIfExists":{"aws:SourceVpce":"vpce-1"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"Null":{"aws:SourceIp":"false"}}}`,
		`{` + allow + `,"NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"}}`,
	}
	for _, s := range public {
		if ok, _ := publicStatements(policy(t, s)); !ok {
			t.Errorf("公開なのに見逃した: %s", s)
		}
	}
	limited := []string{
		`{` + allow + `,"Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::123456789012:role/app-*"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"ForAnyValue:StringEquals":{"aws:PrincipalAccount":"123456789012"}}}`,
		`{"Effect":"Deny","Action":"s3:*","Resource":"*","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"}}`,
		`{` + allow + `,"Principal":{"AWS":"arn:aws:iam::111122223333:root"}}`,
	}
	for _, s := range limited {
		if ok, _ := publicStatements(policy(t, s)); ok {
			t.Errorf("絞り込まれているのに公開とした: %s", s)
		}
	}
}

// 文書で見つけた別名も残す。名前の根拠は docs/cloudtrail-event-names.md。
func TestNotableEventNameVariants(t *testing.T) {
	cases := []struct{ source, name string }{
		{"s3.amazonaws.com", "PutBucketPublicAccessBlock"}, {"s3.amazonaws.com", "DeleteBucketPublicAccessBlock"},
		{"s3.amazonaws.com", "PutPublicAccessBlock"}, {"s3.amazonaws.com", "DeletePublicAccessBlock"},
		// アカウント単位も eventSource は s3control ではなく s3 (実際の記録で確認)
		{"s3.amazonaws.com", "PutAccountPublicAccessBlock"}, {"s3.amazonaws.com", "DeleteAccountPublicAccessBlock"},
		{"sts.amazonaws.com", "AssumeRoot"},
		{"securityhub.amazonaws.com", "DisableSecurityHubV2"},
		{"config.amazonaws.com", "DeleteServiceLinkedConfigurationRecorder"},
	}
	for _, c := range cases {
		if !notable(record.TrailEvent{EventSource: c.source, Name: c.name}) {
			t.Errorf("%s を残していない", c.name)
		}
	}
}
