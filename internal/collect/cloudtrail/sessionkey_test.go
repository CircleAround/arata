package cloudtrail

import (
	"encoding/json"
	"strings"
	"testing"

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

	// 残さない形: 呼び出し側が ECS でも役割の連鎖でもない・失敗した・キーの形でない・人の読み取り (IAM ユーザー)
	for name, body := range map[string]string{
		"ec2 の AssumeRole": strings.Replace(ecsTaskAssume, `"invokedBy":"ecs-tasks.amazonaws.com"`, `"invokedBy":"ec2.amazonaws.com"`, 1),
		"人の AssumeRole":    strings.Replace(ecsTaskAssume, `{"type":"AWSService","invokedBy":"ecs-tasks.amazonaws.com"}`, `{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"}`, 1),
		"失敗した AssumeRole":  strings.Replace(ecsTaskAssume, `"readOnly":true`, `"errorCode":"AccessDenied","readOnly":true`, 1),
		"長期のキー":            strings.ReplaceAll(ecsStartupRead, ecsKey, "AKIAEXAMPLE000000001"),
		"形の合わないキー":         strings.ReplaceAll(ecsStartupRead, ecsKey, "alice@example.com"),
		"IAM ユーザーの読み取り":    strings.Replace(ecsStartupRead, `"type":"AssumedRole"`, `"type":"IAMUser"`, 1),
	} {
		e := normalizeBody(t, body)
		if e.Data["issued_key_hash"] != nil || e.Data["session_key_hash"] != nil {
			t.Errorf("%s: ハッシュを残した: %+v", name, e.Data)
		}
	}
	// 決定 (ADR 0081): session_key_hash は秘匿値の読み取りに限らず、AssumedRole の記録の全部に付く
	other := normalizeBody(t, strings.Replace(ecsStartupRead, `"eventName":"GetParameters"`, `"eventName":"DescribeParameters"`, 1))
	if other.Data["session_key_hash"] != want {
		t.Errorf("秘匿値の読み取りでない AssumedRole の記録: %+v", other.Data)
	}
}

// GitHub の OIDC の 1 段目と、そのセッションで引き受けた 2 段目、2 段目のセッションの IAM の操作 (ADR 0081)。値は架空。
const (
	ghaKey    = "ASIAEXAMPLE000000002"
	deployKey = "ASIAEXAMPLE000000003"
	ghaAssume = `{"userIdentity":{"type":"WebIdentityUser","principalId":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com:sts.amazonaws.com:repo:example-org/example-repo:environment:production",
	    "userName":"repo:example-org/example-repo:environment:production","identityProvider":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
	  "eventTime":"2026-11-21T01:00:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRoleWithWebIdentity","awsRegion":"ap-northeast-1",
	  "sourceIPAddress":"203.0.113.10","userAgent":"aws-sdk-js/3.0.0 exec-env/GitHubActions md/run_id#1234567","readOnly":true,"eventID":"e-gha-assume",
	  "requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/gha-deploy","roleSessionName":"GitHubActions","durationSeconds":3600},
	  "responseElements":{"credentials":{"accessKeyId":"` + ghaKey + `","sessionToken":"not-a-real-token","expiration":"Nov 21, 2026, 2:00:00 AM"},
	    "subjectFromWebIdentityToken":"repo:example-org/example-repo:environment:production"}}`
	ghaChainedAssume = `{"userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:GitHubActions",
	    "arn":"arn:aws:sts::123456789012:assumed-role/gha-deploy/GitHubActions","accountId":"123456789012","accessKeyId":"` + ghaKey + `",
	    "sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/gha-deploy"}}},
	  "eventTime":"2026-11-21T01:01:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"ap-northeast-1",
	  "sourceIPAddress":"203.0.113.10","userAgent":"aws-cdk/2.0.0","readOnly":true,"eventID":"e-chained-assume",
	  "requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/cdk-deploy-role","roleSessionName":"aws-cdk-runner"},
	  "responseElements":{"credentials":{"accessKeyId":"` + deployKey + `","sessionToken":"not-a-real-token","expiration":"Nov 21, 2026, 2:01:00 AM"}}}`
)

func TestNormalizeChainedKeyHash(t *testing.T) {
	gha, _ := record.SessionKeyHash(ghaKey)
	deploy, _ := record.SessionKeyHash(deployKey)
	first := normalizeBody(t, ghaAssume)
	if first.Data["issued_key_hash"] != gha || first.Data["session_key_hash"] != nil {
		t.Fatalf("1 段目: %+v", first.Data)
	}
	second := normalizeBody(t, ghaChainedAssume)
	if second.Data["issued_key_hash"] != deploy || second.Data["session_key_hash"] != gha {
		t.Fatalf("2 段目: %+v", second.Data)
	}
	for _, e := range []record.TrailEvent{first, second} {
		b, _ := json.Marshal(e)
		for _, s := range []string{ghaKey, deployKey, "not-a-real-token", "aws-cdk-runner"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s に %q が残った: %s", e.Name, s, b)
			}
		}
	}
	// 失敗した 1 段目・2 段目は発行しない
	for name, body := range map[string]string{
		"失敗した 1 段目": strings.Replace(ghaAssume, `"readOnly":true`, `"errorCode":"AccessDenied","readOnly":true`, 1),
		"失敗した 2 段目": strings.Replace(ghaChainedAssume, `"readOnly":true`, `"errorCode":"AccessDenied","readOnly":true`, 1),
	} {
		if e := normalizeBody(t, body); e.Data["issued_key_hash"] != nil {
			t.Errorf("%s: issued_key_hash を残した: %+v", name, e.Data)
		}
	}
}
