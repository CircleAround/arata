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

// AssumeRole の向きと MFA の判定に使う値 (設計書 6 章)。recipientAccountId は 12 桁の数字だけ、
// requestParameters.serialNumber は有無だけを残す (値には MFA デバイスの名前 = 利用者名が入る)。
func TestNormalizeAssumeRoleDirectionFields(t *testing.T) {
	body := func(extraParams, tail string) string {
		return `{"userIdentity":{"type":"IAMUser","principalId":"AID","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},
		  "eventSource":"sts.amazonaws.com","eventName":"AssumeRole","sourceIPAddress":"203.0.113.2",
		  "requestParameters":{"roleArn":"arn:aws:iam::111122223333:role/partner-admin"` + extraParams + `}` + tail + `}`
	}
	cases := []struct {
		name, json    string
		wantRecipient any
		wantSerial    any
	}{
		{"外向き・MFA あり", body(`,"serialNumber":"arn:aws:iam::123456789012:mfa/alice"`, `,"recipientAccountId":"123456789012"`), "123456789012", true},
		{"どちらも無い", body(``, ``), nil, nil},
		{"serialNumber が空", body(`,"serialNumber":""`, `,"recipientAccountId":""`), nil, nil},
		{"serialNumber が文字列でない", body(`,"serialNumber":123`, `,"recipientAccountId":123456789012`), nil, nil},
		{"recipientAccountId が 12 桁でない", body(``, `,"recipientAccountId":"1234 <!here>"`), nil, nil},
		{"recipientAccountId に改行", body(``, `,"recipientAccountId":"123456789012\n"`), nil, nil},
	}
	c := New("trail")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := c.normalize(ev("e1", fuzzEventTime, tc.json))
			if !ok {
				t.Fatal("normalize failed")
			}
			if e.Data["recipient_account"] != tc.wantRecipient || e.Data["mfa_serial"] != tc.wantSerial {
				t.Fatalf("recipient_account=%v mfa_serial=%v", e.Data["recipient_account"], e.Data["mfa_serial"])
			}
			for _, v := range e.Data {
				if s, _ := v.(string); s == "arn:aws:iam::123456789012:mfa/alice" {
					t.Fatal("serialNumber の値を残した")
				}
			}
		})
	}
	// AssumeRole 以外の serialNumber は残さない
	e, _ := c.normalize(ev("e2", fuzzEventTime, `{"eventSource":"iam.amazonaws.com","eventName":"DeactivateMFADevice","requestParameters":{"serialNumber":"x"}}`))
	if _, has := e.Data["mfa_serial"]; has {
		t.Fatal("AssumeRole 以外に mfa_serial を付けた")
	}
}
