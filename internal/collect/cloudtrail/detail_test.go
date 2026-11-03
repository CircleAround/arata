package cloudtrail

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// normalizeReq は eventSource / eventName / requestParameters (JSON) から 1 件を正規化する。
func normalizeReq(t *testing.T, source, name, params string) record.TrailEvent {
	t.Helper()
	body := fmt.Sprintf(`{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},
	  "eventTime":"2026-10-21T01:00:00Z","eventSource":%q,"eventName":%q,"awsRegion":"ap-northeast-1","sourceIPAddress":"203.0.113.1",
	  "requestParameters":%s,"readOnly":false,"eventID":"e1"}`, source, name, params)
	c := New("trail")
	e, ok := c.normalize(ev("e1", time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC), body))
	if !ok {
		t.Fatalf("normalize failed: %s", body)
	}
	// ストアの JSON の往復と同じ形で比べる (数値は float64、配列は []any)
	b, _ := json.Marshal(e.Data)
	var d map[string]any
	_ = json.Unmarshal(b, &d)
	e.Data = d
	return e
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// 判定に要る値だけを Data に取り出す。ポリシー全文や不要な値は残さない。
func TestNormalizeDetail(t *testing.T) {
	cases := []struct {
		source, name, params string
		want                 map[string]any // Data に含まれるべきキーと値 (JSON の形で比べる)
		absent               []string
	}{
		// defense_evasion
		{"cloudtrail.amazonaws.com", "UpdateTrail", `{"name":"main","isMultiRegionTrail":false,"enableLogFileValidation":false,"s3BucketName":"example-trail-bucket"}`,
			map[string]any{"name": "main", "multi_region": false, "log_validation": false, "s3_bucket": "example-trail-bucket"}, nil},
		{"cloudtrail.amazonaws.com", "UpdateTrail", `{"name":"main","snsTopicName":"t"}`, map[string]any{"name": "main"}, []string{"multi_region", "log_validation", "s3_bucket"}},
		{"cloudtrail.amazonaws.com", "CreateTrail", `{"name":"main","s3BucketName":"example-trail-bucket"}`, map[string]any{"s3_bucket": "example-trail-bucket"}, nil},
		{"cloudtrail.amazonaws.com", "PutEventSelectors", `{"trailName":"main","eventSelectors":[{"readWriteType":"WriteOnly","includeManagementEvents":true,"excludeManagementEventSources":["kms.amazonaws.com"]}]}`,
			map[string]any{"trail": "main", "selectors_reduced": []any{"read_write_type=WriteOnly", "exclude_management_event_sources=kms.amazonaws.com"}}, []string{"eventSelectors"}},
		{"cloudtrail.amazonaws.com", "PutEventSelectors", `{"trailName":"main","eventSelectors":[{"readWriteType":"All","includeManagementEvents":false}]}`,
			map[string]any{"selectors_reduced": []any{"include_management_events=false"}}, nil},
		{"cloudtrail.amazonaws.com", "PutEventSelectors", `{"trailName":"main","eventSelectors":[{"readWriteType":"All","includeManagementEvents":true,"dataResources":[{"type":"AWS::S3::Object","values":["arn:aws:s3"]}]}]}`,
			map[string]any{"trail": "main"}, []string{"selectors_reduced"}},
		{"cloudtrail.amazonaws.com", "PutEventSelectors", `{"trailName":"main","advancedEventSelectors":[{"fieldSelectors":[{"field":"eventCategory","equals":["Data"]},{"field":"resources.type","equals":["AWS::S3::Object"]}]}]}`,
			map[string]any{"selectors_reduced": []any{"no_management_selector"}}, nil},
		{"cloudtrail.amazonaws.com", "PutEventSelectors", `{"trailName":"main","advancedEventSelectors":[{"fieldSelectors":[{"field":"eventCategory","equals":["Management"]},{"field":"readOnly","equals":["false"]}]}]}`,
			map[string]any{"selectors_reduced": []any{"management_filtered=readOnly"}}, nil},
		{"cloudtrail.amazonaws.com", "PutEventSelectors", `{"trailName":"main","advancedEventSelectors":[{"fieldSelectors":[{"field":"eventCategory","equals":["Management"]}]}]}`,
			map[string]any{"trail": "main"}, []string{"selectors_reduced"}},
		{"cloudtrail.amazonaws.com", "PutInsightSelectors", `{"trailName":"main","insightSelectors":[]}`, map[string]any{"insights_cleared": true}, nil},
		{"cloudtrail.amazonaws.com", "PutInsightSelectors", `{"trailName":"main","insightSelectors":[{"insightType":"ApiCallRateInsight"}]}`, map[string]any{"trail": "main"}, []string{"insights_cleared"}},
		{"guardduty.amazonaws.com", "UpdateDetector", `{"detectorId":"d1","enable":false}`, map[string]any{"detector_id": "d1", "enable": false}, nil},
		{"guardduty.amazonaws.com", "UpdateDetector", `{"detectorId":"d1","features":[{"name":"S3_DATA_EVENTS","status":"DISABLED"},{"name":"EKS_AUDIT_LOGS","status":"ENABLED"}]}`,
			map[string]any{"features_disabled": []any{"S3_DATA_EVENTS"}}, []string{"enable"}},
		{"guardduty.amazonaws.com", "CreateFilter", `{"detectorId":"d1","name":"quiet","action":"ARCHIVE","findingCriteria":{"criterion":{}}}`,
			map[string]any{"name": "quiet", "filter_action": "ARCHIVE"}, []string{"findingCriteria"}},
		{"access-analyzer.amazonaws.com", "CreateArchiveRule", `{"analyzerName":"a1","ruleName":"r1","filter":{}}`, map[string]any{"analyzer": "a1", "rule": "r1"}, nil},
		{"logs.amazonaws.com", "PutRetentionPolicy", `{"logGroupName":"prod-nginx-access","retentionInDays":1}`, map[string]any{"log_group": "prod-nginx-access", "retention_days": 1.0}, nil},
		{"logs.amazonaws.com", "DeleteLogStream", `{"logGroupName":"prod-nginx-access","logStreamName":"i-0abc"}`, map[string]any{"log_group": "prod-nginx-access"}, nil},
		{"logs.amazonaws.com", "DeleteSubscriptionFilter", `{"logGroupName":"prod-nginx-access","filterName":"f1"}`, map[string]any{"log_group": "prod-nginx-access", "filter_name": "f1"}, nil},
		{"ec2.amazonaws.com", "DeleteFlowLogs", `{"DeleteFlowLogsRequest":{"FlowLogId":{"tag":1,"content":"fl-0abc"}}}`, map[string]any{"flow_log_ids": []any{"fl-0abc"}}, nil},
		{"ec2.amazonaws.com", "DeleteFlowLogs", `{"DeleteFlowLogsRequest":{"FlowLogId":[{"tag":1,"content":"fl-1"},{"tag":2,"content":"fl-2"}]}}`, map[string]any{"flow_log_ids": []any{"fl-1", "fl-2"}}, nil},
		{"config.amazonaws.com", "StopConfigurationRecorder", `{"configurationRecorderName":"default"}`, map[string]any{"recorder": "default"}, nil},
		{"config.amazonaws.com", "DeleteDeliveryChannel", `{"deliveryChannelName":"default"}`, map[string]any{"delivery_channel": "default"}, nil},
		{"securityhub.amazonaws.com", "BatchDisableStandards", `{"StandardsSubscriptionArns":["arn:aws:securityhub:ap-northeast-1:123456789012:subscription/cis/1.2.0"]}`,
			map[string]any{"standards": []any{"arn:aws:securityhub:ap-northeast-1:123456789012:subscription/cis/1.2.0"}}, nil},
		{"wafv2.amazonaws.com", "DeleteLoggingConfiguration", `{"ResourceArn":"arn:aws:wafv2:ap-northeast-1:123456789012:regional/webacl/acl/x"}`,
			map[string]any{"resource_arn": "arn:aws:wafv2:ap-northeast-1:123456789012:regional/webacl/acl/x"}, nil},
		{"wafv2.amazonaws.com", "PutLoggingConfiguration", `{"LoggingConfiguration":{"ResourceArn":"arn:x","LogDestinationConfigs":["arn:y"],"LoggingFilter":{"DefaultBehavior":"DROP","Filters":[]}}}`,
			map[string]any{"resource_arn": "arn:x", "logging_filter": true}, nil},
		{"wafv2.amazonaws.com", "PutLoggingConfiguration", `{"LoggingConfiguration":{"ResourceArn":"arn:x","LogDestinationConfigs":["arn:y"]}}`,
			map[string]any{"resource_arn": "arn:x"}, []string{"logging_filter"}},
		{"s3.amazonaws.com", "PutBucketLifecycle", `{"bucketName":"example-trail-bucket","LifecycleConfiguration":{"Rule":[{"Expiration":{"Days":1}},{"Expiration":{"Days":30}}]}}`,
			map[string]any{"bucket": "example-trail-bucket", "lifecycle_expiration_days": 1.0}, []string{"LifecycleConfiguration"}},
		{"s3.amazonaws.com", "DeleteBucketPolicy", `{"bucketName":"example-trail-bucket","policy":""}`, map[string]any{"bucket": "example-trail-bucket"}, nil},

		// public_exposure
		{"ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", `{"groupId":"sg-1","ipPermissions":{"items":[
			{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"},{"cidrIp":"10.0.0.0/8"}]}},
			{"ipProtocol":"-1","ipv6Ranges":{"items":[{"cidrIpv6":"::/0"}]}},
			{"ipProtocol":"tcp","fromPort":443,"toPort":443,"groups":{"items":[{"groupId":"sg-2"}]}}]}}`,
			map[string]any{"group_id": "sg-1", "public_ingress": []any{
				map[string]any{"protocol": "tcp", "from_port": 22.0, "to_port": 22.0, "cidr": "0.0.0.0/0"},
				map[string]any{"protocol": "-1", "from_port": -1.0, "to_port": -1.0, "cidr": "::/0"}}}, []string{"ipPermissions"}},
		{"ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", `{"groupId":"sg-1","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"10.0.0.0/8"}]}}]}}`,
			map[string]any{"group_id": "sg-1"}, []string{"public_ingress"}},
		{"ec2.amazonaws.com", "ModifySecurityGroupRules", `{"ModifySecurityGroupRulesRequest":{"GroupId":"sg-1","SecurityGroupRule":{"tag":1,"SecurityGroupRuleId":"sgr-1","SecurityGroupRule":{"IpProtocol":"tcp","FromPort":3389,"ToPort":3389,"CidrIpv4":"0.0.0.0/0"}}}}`,
			map[string]any{"group_id": "sg-1", "public_ingress": []any{map[string]any{"protocol": "tcp", "from_port": 3389.0, "to_port": 3389.0, "cidr": "0.0.0.0/0", "rule_id": "sgr-1"}}}, nil},
		{"s3.amazonaws.com", "PutBucketPolicy", `{"bucketName":"b1","bucketPolicy":{"Version":"2012-10-17","Statement":[
			{"Sid":"Public","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b1/*"},
			{"Sid":"TLS","Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:GetObject","s3:ListBucket"],"Resource":"arn:aws:s3:::b1/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
			{"Sid":"Vpce","Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}},
			{"Sid":"Deny","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"},
			{"Sid":"Acct","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:GetObject","Resource":"*"}]}}`,
			map[string]any{"bucket": "b1", "policy_public": true, "public_statements": []any{"Public: s3:GetObject", "TLS: s3:GetObject,s3:ListBucket"}}, []string{"bucketPolicy"}},
		{"s3.amazonaws.com", "PutBucketPolicy", `{"bucketName":"b1","bucketPolicy":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"203.0.113.0/24\"}}}]}"}`,
			map[string]any{"bucket": "b1", "policy_public": false}, []string{"public_statements"}},
		{"s3.amazonaws.com", "PutBucketAcl", `{"bucketName":"b1","AccessControlPolicy":{"AccessControlList":{"Grant":[
			{"Grantee":{"xsi:type":"Group","URI":"http://acs.amazonaws.com/groups/global/AllUsers"},"Permission":"READ"},
			{"Grantee":{"xsi:type":"CanonicalUser","ID":"abc"},"Permission":"FULL_CONTROL"}]}}}`,
			map[string]any{"bucket": "b1", "acl_public_grants": []any{"AllUsers:READ"}}, nil},
		{"s3.amazonaws.com", "PutBucketAcl", `{"bucketName":"b1","x-amz-acl":["public-read"]}`, map[string]any{"acl_public_grants": []any{"canned:public-read"}}, nil},
		{"s3.amazonaws.com", "PutBucketAcl", `{"bucketName":"b1","x-amz-grant-read":"uri=\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\""}`,
			map[string]any{"acl_public_grants": []any{"AuthenticatedUsers:READ"}}, nil},
		{"s3.amazonaws.com", "PutBucketAcl", `{"bucketName":"b1","x-amz-acl":["private"]}`, map[string]any{"bucket": "b1"}, []string{"acl_public_grants"}},
		{"s3.amazonaws.com", "PutPublicAccessBlock", `{"bucketName":"b1","PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":false,"RestrictPublicBuckets":false}}`,
			map[string]any{"bucket": "b1", "pab_disabled": []any{"BlockPublicPolicy", "RestrictPublicBuckets"}}, nil},
		{"s3.amazonaws.com", "PutAccountPublicAccessBlock", `{"PublicAccessBlockConfiguration":{"BlockPublicAcls":false,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}}`,
			map[string]any{"pab_disabled": []any{"BlockPublicAcls"}}, nil},
		{"rds.amazonaws.com", "ModifyDBInstance", `{"dBInstanceIdentifier":"db1","publiclyAccessible":true}`, map[string]any{"db_instance": "db1", "publicly_accessible": true}, nil},
		{"rds.amazonaws.com", "ModifyDBCluster", `{"dBClusterIdentifier":"c1","publiclyAccessible":true}`, map[string]any{"db_cluster": "c1", "publicly_accessible": true}, nil},
		{"ec2.amazonaws.com", "ModifySnapshotAttribute", `{"snapshotId":"snap-1","attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"group":"all"}]}}}`,
			map[string]any{"snapshot_id": "snap-1", "shared_public": true}, nil},
		{"ec2.amazonaws.com", "ModifySnapshotAttribute", `{"snapshotId":"snap-1","createVolumePermission":{"add":{"items":[{"userId":"111122223333"}]}}}`,
			map[string]any{"snapshot_id": "snap-1"}, []string{"shared_public"}},
		{"ec2.amazonaws.com", "ModifyImageAttribute", `{"imageId":"ami-1","launchPermission":{"add":{"items":[{"group":"all"}]}}}`, map[string]any{"image_id": "ami-1", "shared_public": true}, nil},
		{"rds.amazonaws.com", "ModifyDBSnapshotAttribute", `{"dBSnapshotIdentifier":"s1","attributeName":"restore","valuesToAdd":["all"]}`, map[string]any{"db_snapshot": "s1", "shared_public": true}, nil},
		{"rds.amazonaws.com", "ModifyDBClusterSnapshotAttribute", `{"dBClusterSnapshotIdentifier":"cs1","attributeName":"restore","valuesToAdd":["111122223333"]}`,
			map[string]any{"db_cluster_snapshot": "cs1"}, []string{"shared_public"}},
		{"lambda.amazonaws.com", "AddPermission20150331v2", `{"functionName":"fn1","statementId":"s","action":"lambda:InvokeFunctionUrl","principal":"*","functionUrlAuthType":"NONE"}`,
			map[string]any{"function": "fn1", "lambda_principal": "*", "function_url_auth_type": "NONE"}, []string{"lambda_conditions"}},
		{"lambda.amazonaws.com", "AddPermission20150331v2", `{"functionName":"fn1","statementId":"s","action":"lambda:InvokeFunction","principal":"s3.amazonaws.com","sourceArn":"arn:aws:s3:::b1","sourceAccount":"123456789012"}`,
			map[string]any{"lambda_principal": "s3.amazonaws.com", "lambda_conditions": []any{"sourceAccount", "sourceArn"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := normalizeReq(t, tc.source, tc.name, tc.params)
			for k, v := range tc.want {
				if !reflect.DeepEqual(e.Data[k], v) {
					t.Errorf("%s: Data[%q] = %s, want %s (all: %s)", tc.params, k, jsonOf(e.Data[k]), jsonOf(v), jsonOf(e.Data))
				}
			}
			for _, k := range tc.absent {
				if _, ok := e.Data[k]; ok {
					t.Errorf("%s: Data[%q] must be absent: %s", tc.params, k, jsonOf(e.Data))
				}
			}
			// ポリシー全文などの大きな値を残さない
			if s := jsonOf(e.Data); len(s) > 1024 || strings.Contains(s, "Statement") || strings.Contains(s, "findingCriteria") {
				t.Errorf("Data too large or holds raw policy: %s", s)
			}
		})
	}
}

// 2 つのチェックが見る操作は、すべて注目イベントとして残る (一覧のずれを防ぐ)。
// 読み取りやほかの書き込みは足さない。
func TestNotableCoversSecurityChecks(t *testing.T) {
	for _, api := range append(checks.DefenseEvasionAPIs(), checks.PublicExposureAPIs()...) {
		name := api.Name
		if api.Prefix {
			name += "20150331v2"
		}
		if !DefaultNotable(record.TrailEvent{EventSource: api.Source, Name: name}) {
			t.Errorf("%s:%s must be notable", api.Source, name)
		}
	}
	for _, e := range []record.TrailEvent{
		{EventSource: "logs.amazonaws.com", Name: "CreateLogGroup"},
		{EventSource: "logs.amazonaws.com", Name: "PutLogEvents"},
		{EventSource: "logs.amazonaws.com", Name: "DescribeLogGroups", ReadOnly: true},
		{EventSource: "ec2.amazonaws.com", Name: "CreateFlowLogs"},
		{EventSource: "config.amazonaws.com", Name: "PutConfigRule"},
		{EventSource: "securityhub.amazonaws.com", Name: "BatchImportFindings"},
		{EventSource: "wafv2.amazonaws.com", Name: "UpdateWebACL"},
		{EventSource: "s3.amazonaws.com", Name: "PutObject"},
		{EventSource: "lambda.amazonaws.com", Name: "Invoke"},
		{EventSource: "lambda.amazonaws.com", Name: "UpdateFunctionCode20150331v2"},
	} {
		if DefaultNotable(e) {
			t.Errorf("%s:%s must not be notable", e.EventSource, e.Name)
		}
	}
}

// 注目イベントを足しても principal_seen (主体 × IP の集計) は変わらない (全イベントから数えるため)。
func TestNotableDoesNotChangePrincipalSeen(t *testing.T) {
	base := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	body := func(id, source, name string) string {
		return fmt.Sprintf(`{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},
		  "eventTime":"2026-10-21T01:00:00Z","eventSource":%q,"eventName":%q,"awsRegion":"ap-northeast-1","sourceIPAddress":"203.0.113.1","readOnly":false,"eventID":%q}`, source, name, id)
	}
	pages := [][]types.Event{{
		ev("x1", base.Add(time.Hour), body("x1", "logs.amazonaws.com", "DeleteLogGroup")),
		ev("x2", base.Add(2*time.Hour), body("x2", "ec2.amazonaws.com", "RunInstances")),
	}}
	run := func(notable func(record.TrailEvent) bool) *captured {
		c, _, _ := testCollector("trail", RegionClient{Region: "ap-northeast-1", API: &Fake{Pages: pages}})
		c.Notable = notable
		sink := &captured{}
		if err := c.Collect(t.Context(), collectWindow(base), sink); err != nil {
			t.Fatal(err)
		}
		return sink
	}
	before := run(func(record.TrailEvent) bool { return false })
	after := run(DefaultNotable)
	if !reflect.DeepEqual(before.principals, after.principals) {
		t.Fatalf("principal_seen changed:\n%+v\n%+v", before.principals, after.principals)
	}
	if len(after.events) != 1 || after.events[0].EventID != "x1" {
		t.Fatalf("events: %+v", after.events)
	}
}

func collectWindow(base time.Time) collect.Window {
	return collect.Window{From: base, To: base.Add(24 * time.Hour)}
}
