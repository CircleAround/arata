package cloudtrail

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/record"
)

// ECS が実行用のロールを引き受けた記録と、その認証情報での秘匿値の読み取り (ADR 0076)。形は実際の記録で確かめたもの。値は架空。
const (
	ecsKey        = "ASIAEXAMPLE000000001"
	ecsTaskAssume = `{"userIdentity":{"type":"AWSService","invokedBy":"ecs-tasks.amazonaws.com"},
	  "eventTime":"2026-11-19T01:00:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"ap-northeast-1",
	  "sourceIPAddress":"ecs-tasks.amazonaws.com","userAgent":"ecs-tasks.amazonaws.com","readOnly":true,"eventID":"e-ecs-assume",
	  "requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/example-app-task-execution","roleSessionName":"0123456789abcdef0123456789abcdef"},
	  "responseElements":{"credentials":{"accessKeyId":"` + ecsKey + `","sessionToken":"not-a-real-token","expiration":"Nov 19, 2026, 7:00:00 AM"},
	    "assumedRoleUser":{"assumedRoleId":"AROAEXAMPLE:0123456789abcdef0123456789abcdef","arn":"arn:aws:sts::123456789012:assumed-role/example-app-task-execution/0123456789abcdef0123456789abcdef"}}}`
	ecsStartupRead = `{"userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:0123456789abcdef0123456789abcdef",
	    "arn":"arn:aws:sts::123456789012:assumed-role/example-app-task-execution/0123456789abcdef0123456789abcdef","accountId":"123456789012","accessKeyId":"` + ecsKey + `",
	    "sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/example-app-task-execution"}}},
	  "eventTime":"2026-11-19T01:00:01Z","eventSource":"ssm.amazonaws.com","eventName":"GetParameters","awsRegion":"ap-northeast-1",
	  "sourceIPAddress":"198.51.100.20","userAgent":"Amazon Fargate Agent - v1.0.0 (+http://aws.amazon.com/ecs/)","readOnly":true,"eventID":"e-ecs-read",
	  "requestParameters":{"names":["/example-app/prod/secrets/DB_PASSWORD"],"withDecryption":true}}`
)

func TestNormalizeSessionKeyHash(t *testing.T) {
	want, _ := record.SessionKeyHash(ecsKey)
	issue := normalizeBody(t, ecsTaskAssume)
	if issue.Data["issued_key_hash"] != want || issue.Data["session_key_hash"] != nil {
		t.Fatalf("ECS の AssumeRole: %+v", issue.Data)
	}
	read := normalizeBody(t, ecsStartupRead)
	if read.Data["session_key_hash"] != want || read.Data["issued_key_hash"] != nil {
		t.Fatalf("秘匿値の読み取り: %+v", read.Data)
	}
	// キーそのもの・セッション名・セッショントークンは残さない
	taskID := strings.Repeat("0123456789abcdef", 2) // セッション名 (タスクの ID)
	for _, e := range []record.TrailEvent{issue, read} {
		b, _ := json.Marshal(e)
		for _, s := range []string{ecsKey, taskID, "not-a-real-token"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s に %q が残った: %s", e.Name, s, b)
			}
		}
	}

	// 残さない形: 呼び出し側が ECS でない・失敗した・キーの形でない・人の読み取り (IAM ユーザー)・秘匿値の読み取りでない
	for name, body := range map[string]string{
		"ec2 の AssumeRole":  strings.Replace(ecsTaskAssume, `"invokedBy":"ecs-tasks.amazonaws.com"`, `"invokedBy":"ec2.amazonaws.com"`, 1),
		"人の AssumeRole":     strings.Replace(ecsTaskAssume, `{"type":"AWSService","invokedBy":"ecs-tasks.amazonaws.com"}`, `{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"}`, 1),
		"失敗した AssumeRole":   strings.Replace(ecsTaskAssume, `"readOnly":true`, `"errorCode":"AccessDenied","readOnly":true`, 1),
		"WebIdentity の引き受け": strings.Replace(ecsTaskAssume, `"eventName":"AssumeRole"`, `"eventName":"AssumeRoleWithWebIdentity"`, 1),
		"長期のキー":             strings.ReplaceAll(ecsStartupRead, ecsKey, "AKIAEXAMPLE000000001"),
		"形の合わないキー":          strings.ReplaceAll(ecsStartupRead, ecsKey, "alice@example.com"),
		"IAM ユーザーの読み取り":     strings.Replace(ecsStartupRead, `"type":"AssumedRole"`, `"type":"IAMUser"`, 1),
		"秘匿値の読み取りでない":       strings.Replace(ecsStartupRead, `"eventName":"GetParameters"`, `"eventName":"DescribeParameters"`, 1),
	} {
		e := normalizeBody(t, body)
		if e.Data["issued_key_hash"] != nil || e.Data["session_key_hash"] != nil {
			t.Errorf("%s: ハッシュを残した: %+v", name, e.Data)
		}
	}
}

// session_key_hash を残す操作は、secret_access が見る操作と同じ (一覧のずれを防ぐ)。
func TestSessionKeyOpsMatchSecretReads(t *testing.T) {
	got := map[string]bool{}
	for _, a := range checks.SecretReadAPIs() {
		if a.Prefix {
			t.Fatalf("前方一致の操作は想定していない: %+v", a)
		}
		got[a.Source+" "+a.Name] = true
		if !secretReadOps[a.Source+" "+a.Name] {
			t.Errorf("%s:%s が secretReadOps に無い", a.Source, a.Name)
		}
	}
	for k := range secretReadOps {
		if !got[k] {
			t.Errorf("%s は secret_access が見ない", k)
		}
	}
}
