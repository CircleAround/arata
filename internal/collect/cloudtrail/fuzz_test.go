package cloudtrail

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/record"
)

// ファズテスト (ADR 0041)。CloudTrail のイベントの本文 (JSON) は API を呼んだ側が書ける値 (requestParameters・userAgent・ポリシーの本文) を含む。
// 形が想定と違ってもパニックせず、取り出す値の上限と、公開の判定の規則 (ADR 0037) が保たれることを確かめる。

var fuzzEventTime = time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)

func FuzzNormalizeEvent(f *testing.F) {
	for _, s := range []string{rootLogin, assumeRole, iamChange, readOnlyNoise, serviceEvent,
		`{"userIdentity":{"accountId":"123456789012"},"sourceIPAddress":"AWS Internal","userAgent":"AWS Internal","eventSource":"ecr.amazonaws.com"}`,
		`{"userIdentity":{"type":"AWSAccount","accountId":"111122223333","principalId":"AROAEXAMPLE"},"sourceIPAddress":"198.51.100.7","eventSource":"sts.amazonaws.com"}`,
		`{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com"},"eventTime":"2026-10-21T03:00:00Z","eventID":"e"}`,
		`{"eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","requestParameters":{"groupId":"sg-1","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]},"ipv6Ranges":{"items":[{"cidrIpv6":"::/0"}]}}]}}}`,
		`{"eventSource":"ec2.amazonaws.com","eventName":"ModifySecurityGroupRules","requestParameters":{"ModifySecurityGroupRulesRequest":{"GroupId":"sg-1","SecurityGroupRule":{"SecurityGroupRuleId":"sgr-1","SecurityGroupRule":{"CidrIpv4":"0.0.0.0/1","IpProtocol":-1,"FromPort":1e99,"ToPort":null}}}}}`,
		`{"eventSource":"ec2.amazonaws.com","eventName":"DeleteFlowLogs","requestParameters":{"DeleteFlowLogsRequest":{"FlowLogId":[{"content":"fl-1"},"x",1]}}}`,
		`{"eventSource":"ec2.amazonaws.com","eventName":"ModifySnapshotAttribute","requestParameters":{"snapshotId":"snap-1","createVolumePermission":{"add":{"items":[{"group":"all"}]}}}}`,
		`{"eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","requestParameters":{"bucketName":"example-bucket","bucketPolicy":{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","a","b","c","d","e"],"Resource":"*"}]}}}`,
		`{"eventSource":"s3.amazonaws.com","eventName":"PutBucketPolicy","requestParameters":{"bucketName":"example-bucket","bucketPolicy":"{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"*\"]},\"Action\":\"s3:*\"}}"}}`,
		`{"eventSource":"s3.amazonaws.com","eventName":"PutBucketAcl","requestParameters":{"x-amz-acl":["public-read"],"x-amz-grant-read":"uri=http://acs.amazonaws.com/groups/global/AllUsers","AccessControlPolicy":{"AccessControlList":{"Grant":{"Grantee":{"URI":"http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},"Permission":"READ"}}}}}`,
		`{"eventSource":"s3.amazonaws.com","eventName":"PutBucketPublicAccessBlock","requestParameters":{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":"x"}}}`,
		`{"eventSource":"s3.amazonaws.com","eventName":"PutBucketLifecycle","requestParameters":{"LifecycleConfiguration":{"Rule":[{"Expiration":{"Days":1}},{"Expiration":{"Days":-3}},{"Expiration":"x"}]}}}`,
		`{"eventSource":"guardduty.amazonaws.com","eventName":"UpdateDetector","requestParameters":{"detectorId":"d","enable":false,"features":[{"name":"S3_DATA_EVENTS","status":"DISABLED"},7]}}`,
		`{"eventSource":"cloudtrail.amazonaws.com","eventName":"PutEventSelectors","requestParameters":{"trailName":"main","eventSelectors":[{"readWriteType":"WriteOnly","includeManagementEvents":true,"excludeManagementEventSources":["kms.amazonaws.com"]}],"advancedEventSelectors":[{"fieldSelectors":[{"field":"eventCategory","equals":["Management"]}]}]}}`,
		`{"eventSource":"logs.amazonaws.com","eventName":"PutRetentionPolicy","requestParameters":{"logGroupName":"prod-nginx-access","retentionInDays":1}}`,
		`{"eventSource":"secretsmanager.amazonaws.com","eventName":"BatchGetSecretValue","requestParameters":{"secretIdList":["prod/db",1,null],"filters":[{"key":"name","values":["prod/"]}]}}`,
		`{"eventSource":"ssm.amazonaws.com","eventName":"GetParameters","requestParameters":{"names":["/example/prod/a"],"withDecryption":"yes"}}`,
		`{"userIdentity":{"type":"Root","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012","invokedBy":"sso.amazonaws.com"},"sourceIPAddress":"sso.amazonaws.com","eventSource":"sso.amazonaws.com"}`,
		`{"userIdentity":{"type":"Root","accountId":"123456789012","invokedBy":"x) <!here> (.amazonaws.com"},"sourceIPAddress":"a\nb.amazonaws.com"}`,
		`{"userIdentity":{"type":"FutureType","arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com","accountId":"123456789012"}}`,
		`{"userIdentity":{"arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com"}}`,
		`{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},"eventSource":"sts.amazonaws.com","eventName":"AssumeRole","requestParameters":{"roleArn":"arn:aws:iam::111122223333:role/partner-admin","serialNumber":"arn:aws:iam::123456789012:mfa/alice"},"recipientAccountId":"123456789012"}`,
		`{"eventSource":"sts.amazonaws.com","eventName":"AssumeRole","requestParameters":{"serialNumber":["x"]},"recipientAccountId":"123456789012\n<!here>"}`,
		`{"requestParameters":[],"responseElements":"x","additionalEventData":1,"resources":{}}`, `{"userIdentity":null,"resources":[null,{"ARN":1}]}`, `[]`, `null`, ``,
	} {
		f.Add(s)
	}
	kinds := map[record.PrincipalKind]bool{record.PrincipalRoot: true, record.PrincipalUser: true, record.PrincipalAssumedRole: true, record.PrincipalRole: true,
		record.PrincipalService: true, record.PrincipalUnknown: true}
	c := New("trail")
	f.Fuzz(func(t *testing.T, body string) {
		// 時刻と ID を API が返さないとき (本文から読む) も通す
		if e, ok := c.normalize(types.Event{CloudTrailEvent: &body}); ok && (e.EventID == "" || e.Time.IsZero()) {
			t.Fatalf("ID か時刻の無いイベントを受け入れた: %+v", e)
		}
		e, ok := c.normalize(ev("e-fuzz", fuzzEventTime, body))
		if !ok {
			var v any
			if json.Unmarshal([]byte(body), &v) == nil {
				if _, isObj := v.(map[string]any); isObj {
					var r rawEvent
					if json.Unmarshal([]byte(body), &r) == nil {
						t.Fatalf("読める本文を捨てた: %q", body)
					}
				}
			}
			return
		}
		if e.EventID != "e-fuzz" || !e.Time.Equal(fuzzEventTime) || e.Source != "trail" || e.Data == nil {
			t.Fatalf("API の ID・時刻を使っていない: %+v", e)
		}
		if !kinds[e.PrincipalKind] {
			t.Fatalf("知らない主体の種類: %q", e.PrincipalKind)
		}
		if strings.HasSuffix(e.IP, ".amazonaws.com") || e.IP == "AWS Internal" {
			t.Fatalf("サービス名を IP に入れた: %q", e.IP)
		}
		// invoked_by は決まった形のサービス名だけ (ログ由来の値を見出しに出さない)。サービスの主体の記録には足さない
		if v, has := e.Data["invoked_by"]; has {
			name, _ := v.(string)
			if got, ok := record.ServiceName(name); !ok || got != name || e.PrincipalKind == record.PrincipalService || e.IP != "" && e.IP == name {
				t.Fatalf("data.invoked_by が規則に合わない: %q (kind %s)", v, e.PrincipalKind)
			}
		}
		// 受け取ったアカウントは 12 桁の数字だけ。serialNumber は有無 (true) だけで、AssumeRole* 以外には付けない
		if v, has := e.Data["recipient_account"]; has {
			if s, _ := v.(string); !recipientAccountRe.MatchString(s) || strings.ContainsAny(s, "\n\r ") {
				t.Fatalf("data.recipient_account が 12 桁の数字でない: %q", v)
			}
		}
		if v, has := e.Data["mfa_serial"]; has && (v != true || !strings.HasPrefix(e.Name, "AssumeRole")) {
			t.Fatalf("data.mfa_serial が規則に合わない: %v (%s)", v, e.Name)
		}
		if _, err := json.Marshal(e); err != nil {
			t.Fatalf("イベントを JSON にできない: %v", err)
		}
		// 一覧の値は上限まで。入れ子は public_ingress の 1 段だけ (ポリシー全文などの大きな値を残さない。ADR 0026)
		for k, v := range e.Data {
			switch x := v.(type) {
			case string, bool, int, float64:
			case []string:
				if len(x) == 0 || len(x) > maxDetailItems {
					t.Fatalf("data.%s が %d 個", k, len(x))
				}
			case []any:
				if len(x) == 0 || len(x) > maxDetailItems || k != "public_ingress" {
					t.Fatalf("data.%s が %d 個", k, len(x))
				}
				for _, it := range x {
					for kk, vv := range it.(map[string]any) {
						switch vv.(type) {
						case string, int:
						default:
							t.Fatalf("data.%s.%s が入れ子: %T", k, kk, vv)
						}
					}
				}
			default:
				t.Fatalf("data.%s が想定外の型 %T", k, v)
			}
		}
		DefaultNotable(e)
		// セッション名には個人名やメールアドレスが入る。種類が AssumedRole のときも、知らない種類のときも、ロールに寄せる
		// (IAMUser・Role・Root は AWS が決める種類で、その ARN はセッションの形にならない)
		if k := e.PrincipalKind; k == record.PrincipalAssumedRole || k == record.PrincipalUnknown {
			if role := roleARNFromSession(e.PrincipalARN); role != "" {
				t.Fatalf("セッションの ARN が主体に残った (ロールに寄せられる形なのに): %q (%s)", e.PrincipalARN, k)
			}
		}
	})
}

func FuzzRoleARNFromSession(f *testing.F) {
	for _, s := range []string{"arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com", "arn:aws:sts::123456789012:assumed-role/Admin", "arn:aws:sts::123456789012:assumed-role//x",
		"arn:aws:iam::123456789012:role/Admin", "arn:aws:sts:::assumed-role/a/b/c", "x:assumed-role/a/b", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, arn string) {
		role := roleARNFromSession(arn)
		if role == "" {
			return
		}
		rest, ok := strings.CutPrefix(role, "arn:aws:iam::")
		acct, name, ok2 := strings.Cut(rest, ":role/")
		if !ok || !ok2 || name == "" || strings.Contains(name, "/") {
			t.Fatalf("roleARNFromSession(%q) = %q: ロールの ARN の形でない", arn, role)
		}
		// セッション名 (ロール名の次の区間) は結果に入らない
		if want := "arn:aws:sts::" + acct + ":assumed-role/" + name; arn != want && !strings.HasPrefix(arn, want+"/") {
			t.Fatalf("roleARNFromSession(%q) = %q: 元の ARN と対応しない", arn, role)
		}
	})
}

// バケットポリシーとセキュリティグループの公開の判定。見逃す側に倒れない性質を確かめる。
func FuzzPublicStatements(f *testing.F) {
	allow := `"Effect":"Allow","Action":"s3:GetObject","Resource":"*"`
	for _, s := range []string{
		`{` + allow + `,"Principal":"*"}`,
		`{` + allow + `,"Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"IpAddress":{"aws:SourceIp":["192.0.2.0/24","::/0"]}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"192.0.2.1/32"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringLike":{"aws:PrincipalArn":"*"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/x"}}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringEqualsIfExists":{"aws:SourceVpce":"vpce-1"}}}`,
		`{` + allow + `,"NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"}}`,
		`{` + allow + `,"Principal":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}`,
		`{` + allow + `,"Principal":{"AWS":"arn:aws:iam::123456789012:root"}}`,
		`{"Effect":"Deny","Principal":"*","Action":"s3:*"}`, `{"Sid":"x","Effect":"Allow","Principal":{"AWS":["*"]},"Action":["a","b","c","d","e","f","g"],"Condition":{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":["o-1/*"]}}}`,
		`{"Condition":[],"Principal":7,"Action":{}}`, `7`,
	} {
		f.Add(`{"Statement":[`+s+`]}`, "0.0.0.0/0")
	}
	for _, c := range []string{"::/0", "0.0.0.0/1", "128.0.0.0/1", "8000::/1", "1.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24", "fc00::/7", "fe80::/10", "::ffff:0.0.0.0/96", "not-a-cidr", ""} {
		f.Add(`{"Statement":{"Effect":"Allow","Principal":"*"}}`, c)
	}
	open := map[string]any{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
	f.Fuzz(func(t *testing.T, policy, cidr string) {
		var v any
		_ = json.Unmarshal([]byte(policy), &v)
		public, sts := publicStatements(v)
		if public != (len(sts) > 0) || len(sts) > maxDetailItems {
			t.Fatalf("public=%v、ステートメント %d 個", public, len(sts))
		}
		// CloudTrail は本文を文字列で持つこともある。同じ判定になる
		if _, isObj := v.(map[string]any); isObj {
			if p2, s2 := publicStatements(policy); p2 != public || strings.Join(s2, "\n") != strings.Join(sts, "\n") {
				t.Fatalf("文字列のポリシーで判定が変わった: %v %v / %v %v", public, sts, p2, s2)
			}
		}
		pol := objectOf(v)
		all := objects(pol["Statement"])
		// 条件を外すと公開の範囲は広がるだけ (公開だったものが公開でなくなることは無い)
		// 条件なしで誰にでも許可するステートメントを足せば、必ず公開
		var bare, plus []any
		for _, st := range all {
			c := map[string]any{}
			for k, x := range st {
				if k != "Condition" {
					c[k] = x
				}
			}
			bare = append(bare, c)
			plus = append(plus, st)
		}
		if p, _ := publicStatements(map[string]any{"Statement": bare}); public && !p {
			t.Fatalf("条件を外したら公開でなくなった: %s", policy)
		}
		if p, _ := publicStatements(map[string]any{"Statement": append(plus, open)}); !p {
			t.Fatalf("誰にでも許可するステートメントを足しても公開にならない: %s", policy)
		}

		// 広い CIDR は公開で、送信元の条件にしても絞り込みにならない
		if publicCIDR(cidr) {
			p, err := netip.ParsePrefix(cidr)
			if err != nil || (p.Addr().Is4() && p.Bits() > maxPublicBits4) || (!p.Addr().Is4() && p.Bits() > maxPublicBits6) {
				t.Fatalf("publicCIDR(%q) が広くない範囲を公開とした", cidr)
			}
			if restricted(map[string]any{"IpAddress": map[string]any{"aws:SourceIp": []any{"192.0.2.0/24", cidr}}}) {
				t.Fatalf("広い CIDR %q を絞り込みとみなした", cidr)
			}
		} else if p, err := netip.ParsePrefix(cidr); err == nil && p.Bits() == 0 {
			t.Fatalf("publicCIDR(%q) が全開放を公開としなかった", cidr)
		}
		// 条件の値が何であっても、否定の演算子と IfExists は絞り込みにならない
		for _, op := range []string{"NotIpAddress", "StringNotEquals", "StringEqualsIfExists", "Null", cidr} {
			if restricted(map[string]any{op: map[string]any{"aws:SourceIp": cidr}}) && !restrictingOperator(op) {
				t.Fatalf("演算子 %q を絞り込みとみなした", op)
			}
		}
	})
}
