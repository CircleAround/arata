package cloudtrail

import (
	"encoding/json"
	"testing"

	"github.com/CircleAround/arata/internal/record"
)

func parseRaw(t *testing.T, s string) rawEvent {
	t.Helper()
	var r rawEvent
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPrincipalOfInternalRecords(t *testing.T) {
	cases := []struct {
		name, json, arn string
		kind            record.PrincipalKind
	}{
		{"type 無し・AWS Internal (ECR PolicyExecutionEvent の形)",
			`{"userIdentity":{"accountId":"123456789012"},"sourceIPAddress":"AWS Internal","userAgent":"AWS Internal","eventSource":"ecr.amazonaws.com"}`,
			"ecr.amazonaws.com", record.PrincipalService},
		{"type 無し・userAgent だけ AWS Internal",
			`{"userIdentity":{"accountId":"123456789012"},"sourceIPAddress":"203.0.113.9","userAgent":"AWS Internal","eventSource":"ecr.amazonaws.com"}`,
			"ecr.amazonaws.com", record.PrincipalService},
		{"type 無し・invokedBy あり",
			`{"userIdentity":{"accountId":"123456789012","invokedBy":"backup.amazonaws.com"},"eventSource":"s3.amazonaws.com"}`,
			"backup.amazonaws.com", record.PrincipalService},
		{"外部アカウントの AssumeRole (type AWSAccount) は今までどおり",
			`{"userIdentity":{"type":"AWSAccount","accountId":"111122223333","principalId":"AROAEXAMPLE"},"sourceIPAddress":"198.51.100.7","eventSource":"sts.amazonaws.com"}`,
			"arn:aws:iam::111122223333:root", record.PrincipalUnknown},
		{"type 無しでも外部 IP で AWS Internal でなければ従来どおり",
			`{"userIdentity":{"accountId":"111122223333"},"sourceIPAddress":"198.51.100.7","eventSource":"sts.amazonaws.com"}`,
			"arn:aws:iam::111122223333:root", record.PrincipalUnknown},
		{"知らない種類でも、セッションの ARN はロールに寄せる (セッション名を主体に残さない)",
			`{"userIdentity":{"type":"FutureType","arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com","accountId":"123456789012"}}`,
			"arn:aws:iam::123456789012:role/Admin", record.PrincipalAssumedRole},
		{"アカウントの欄が無い壊れた ARN からロールの ARN を作らない",
			`{"userIdentity":{"arn":"arn:aws:sts::assumed-role/0"}}`,
			"arn:aws:sts::assumed-role/0", record.PrincipalUnknown},
	}
	for _, tc := range cases {
		arn, kind := principalOf(parseRaw(t, tc.json))
		if arn != tc.arn || kind != tc.kind {
			t.Errorf("%s: got %s %s, want %s %s", tc.name, arn, kind, tc.arn, tc.kind)
		}
	}
}
