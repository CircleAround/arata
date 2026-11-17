package cloudtrail

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/record"
)

// ECS Exec の記録 (ADR 0072)。形は実際の記録で確かめたもの (docs/cloudtrail-event-names.md の「記録の形を確かめた操作」)。値は架空。
const ecsExecOK = `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice","accountId":"123456789012"},
  "eventTime":"2026-11-17T01:00:00Z","eventSource":"ecs.amazonaws.com","eventName":"ExecuteCommand","awsRegion":"ap-northeast-1",
  "sourceIPAddress":"203.0.113.1","eventType":"AwsApiCall","managementEvent":true,"readOnly":false,"eventID":"e-exec",
  "requestParameters":{"cluster":"prod-cluster","container":"app","command":"/bin/sh","interactive":true,"task":"0123456789abcdef0123456789abcdef","dryrun":false},
  "responseElements":{"clusterArn":"arn:aws:ecs:ap-northeast-1:123456789012:cluster/prod-cluster",
    "containerArn":"arn:aws:ecs:ap-northeast-1:123456789012:container/prod-cluster/0123456789abcdef0123456789abcdef/11111111-2222-3333-4444-555555555555",
    "containerName":"app","interactive":true,"taskArn":"arn:aws:ecs:ap-northeast-1:123456789012:task/prod-cluster/0123456789abcdef0123456789abcdef",
    "session":{"sessionId":"ecs-execute-command-0a1b2c3d4e5f67890","streamUrl":"wss://ssmmessages.ap-northeast-1.amazonaws.com/v1/data-channel/ecs-execute-command-0a1b2c3d4e5f67890?role=publish_subscribe&cell-number=SECRET-STREAM",
      "tokenValue":"HIDDEN_DUE_TO_SECURITY_REASONS"}}}`

func normalizeBody(t *testing.T, body string) record.TrailEvent {
	t.Helper()
	e, ok := New("trail").normalize(ev("e-exec", time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC), body))
	if !ok {
		t.Fatalf("normalize failed: %s", body)
	}
	return e
}

func TestNormalizeECSExec(t *testing.T) {
	e := normalizeBody(t, ecsExecOK)
	want := map[string]any{
		"ecs_cluster": "prod-cluster", "ecs_container": "app", "ecs_task": "0123456789abcdef0123456789abcdef",
		"ecs_command": "/bin/sh", "ecs_interactive": true, "ecs_session_id": "ecs-execute-command-0a1b2c3d4e5f67890",
	}
	for k, v := range want {
		if e.Data[k] != v {
			t.Errorf("data.%s = %v, want %v", k, e.Data[k], v)
		}
	}
	for _, k := range []string{"ecs_command_truncated", "ecs_dryrun"} {
		if _, has := e.Data[k]; has {
			t.Errorf("data.%s must not be set", k)
		}
	}
	// 接続の認証に使う値は、伏せられていても、伏せられていなくても残さない
	b, _ := json.Marshal(e)
	for _, s := range []string{"HIDDEN_DUE_TO_SECURITY_REASONS", "wss://", "SECRET-STREAM", "tokenValue", "streamUrl"} {
		if strings.Contains(string(b), s) {
			t.Errorf("normalized event contains %q: %s", s, b)
		}
	}
	if !DefaultNotable(e) {
		t.Error("ExecuteCommand must be notable")
	}
}

func TestNormalizeECSExecVariants(t *testing.T) {
	cases := []struct {
		name, body string
		want       map[string]any
		absent     []string
	}{
		{
			// 拒否された呼び出し: 応答が無い。要求に ARN で書かれたクラスターとタスク
			name: "denied with ARNs in request",
			body: `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice"},"eventSource":"ecs.amazonaws.com","eventName":"ExecuteCommand",
			  "errorCode":"AccessDeniedException","requestParameters":{"cluster":"arn:aws:ecs:ap-northeast-1:123456789012:cluster/prod-cluster",
			  "task":"arn:aws:ecs:ap-northeast-1:123456789012:task/prod-cluster/0123456789abcdef0123456789abcdef","command":"ls","interactive":true}}`,
			want:   map[string]any{"ecs_cluster": "prod-cluster", "ecs_task": "0123456789abcdef0123456789abcdef", "ecs_command": "ls", "ecs_interactive": true},
			absent: []string{"ecs_container", "ecs_session_id"},
		},
		{
			name:   "no parameters",
			body:   `{"eventSource":"ecs.amazonaws.com","eventName":"ExecuteCommand","errorCode":"AccessDeniedException"}`,
			absent: []string{"ecs_cluster", "ecs_container", "ecs_task", "ecs_command", "ecs_interactive", "ecs_session_id"},
		},
		{
			// 決まった形でない名前・セッション ID は残さない (ログ由来の値を Key と見出しに使うため)。
			// SSM のセッション ID は利用者名から作られることがあるので、ECS Exec の形 (ecs-execute-command-) だけを残す
			name: "malformed values",
			body: `{"eventSource":"ecs.amazonaws.com","eventName":"ExecuteCommand","requestParameters":{"cluster":"a|b","container":"x\ny","task":"../t","interactive":"yes"},
			  "responseElements":{"session":{"sessionId":"alice@example.com-0123456789abcdef"}}}`,
			absent: []string{"ecs_cluster", "ecs_container", "ecs_task", "ecs_interactive", "ecs_session_id"},
		},
		{
			// 応答の値を要求より優先する
			name: "response wins",
			body: `{"eventSource":"ecs.amazonaws.com","eventName":"ExecuteCommand","requestParameters":{"cluster":"other","task":"t1","command":"sh"},
			  "responseElements":{"clusterArn":"arn:aws:ecs:ap-northeast-1:123456789012:cluster/prod-cluster","containerName":"app",
			  "taskArn":"arn:aws:ecs:ap-northeast-1:123456789012:task/prod-cluster/0123456789abcdef0123456789abcdef"}}`,
			want: map[string]any{"ecs_cluster": "prod-cluster", "ecs_container": "app", "ecs_task": "0123456789abcdef0123456789abcdef"},
		},
		{
			// コマンドは制御文字・書式の文字を除いて 1 行にし、256 文字で切る
			name: "long command",
			body: `{"eventSource":"ecs.amazonaws.com","eventName":"ExecuteCommand","requestParameters":{"command":"sh -c \"echo\u0007 a\nb\u200b` + strings.Repeat("x", 300) + `\""}}`,
			want: map[string]any{"ecs_command_truncated": true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := normalizeBody(t, strings.Replace(tc.body, `"eventSource"`, `"eventTime":"2026-11-17T01:00:00Z","eventID":"e","eventSource"`, 1))
			for k, v := range tc.want {
				if e.Data[k] != v {
					t.Errorf("data.%s = %v, want %v", k, e.Data[k], v)
				}
			}
			for _, k := range tc.absent {
				if v, has := e.Data[k]; has {
					t.Errorf("data.%s = %v, want absent", k, v)
				}
			}
			if c, ok := e.Data["ecs_command"].(string); ok {
				if !record.CleanECSCommandOK(c) {
					t.Errorf("command not clean: %q", c)
				}
			}
		})
	}
}

// 別の操作には ecs_ の値を付けない。
func TestNormalizeECSOnlyExecuteCommand(t *testing.T) {
	e := normalizeReq(t, "ecs.amazonaws.com", "RunTask", `{"cluster":"prod-cluster","command":"x"}`)
	for k := range e.Data {
		if strings.HasPrefix(k, "ecs_") {
			t.Errorf("data.%s on RunTask", k)
		}
	}
}

func TestNotableCoversECSExec(t *testing.T) {
	for _, api := range checks.ECSExecAPIs() {
		if !DefaultNotable(record.TrailEvent{EventSource: api.Source, Name: api.Name}) {
			t.Errorf("%s:%s must be notable", api.Source, api.Name)
		}
		// 失敗した呼び出しも残す (拒否のコードでないものも。ADR 0072 の 6 節)
		if !DefaultNotable(record.TrailEvent{EventSource: api.Source, Name: api.Name, ErrorCode: "TargetNotConnectedException"}) {
			t.Errorf("%s:%s failed must be notable", api.Source, api.Name)
		}
	}
	if DefaultNotable(record.TrailEvent{EventSource: "ecs.amazonaws.com", Name: "DescribeTasks", ReadOnly: true}) {
		t.Error("other ECS calls must not be notable")
	}
}
