package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

func TestIAMChangesDenied(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	in := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	const role = "arn:aws:iam::123456789012:role/example-role"
	ev := func(id string, h int, name, code string, data map[string]any) record.TrailEvent {
		return record.TrailEvent{EventID: id, Time: in(h), Name: name, EventSource: "iam.amazonaws.com", Source: "trail",
			PrincipalARN: role, PrincipalKind: record.PrincipalAssumedRole, IP: "198.51.100.1", ErrorCode: code, Data: data}
	}
	for _, e := range []record.TrailEvent{
		ev("d1", 1, "CreateUser", "AccessDenied", nil),
		ev("d2", 2, "CreateUser", "AccessDenied", nil),
		ev("d3", 3, "CreateUser", "Client.UnauthorizedOperation", nil),
		ev("m1", 4, "CreateAccessKey", "AccessDenied", map[string]any{"user_name": "alice"}),
		ev("m2", 5, "CreateAccessKey", "", map[string]any{"user_name": "alice"}),
	} {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	al, _ := allowlist.Parse([]byte("principals: []\n"))
	obs, err := IAMChanges{}.Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, al)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("%+v", obs)
	}
	mixed, denied := obs[0], obs[1] // CreateAccessKey, CreateUser
	if denied.Key != "CreateUser|"+role+"|" {
		t.Fatalf("key must stay unchanged: %q", denied.Key)
	}
	if denied.Severity != Medium || denied.Data["denied"] != true || denied.Data["has_errors"] != true {
		t.Fatalf("%+v", denied)
	}
	if got := strings.Join(denied.Data["error_codes"].([]string), ","); got != "AccessDenied,Client.UnauthorizedOperation" {
		t.Fatalf("error_codes: %q", got)
	}
	if !strings.HasPrefix(denied.Summary, "IAM 変更の試行 (拒否) CreateUser:") {
		t.Fatalf("summary: %q", denied.Summary)
	}
	if !strings.Contains(denied.Summary, "不明 (拒否された呼び出しは内容が記録されない)") {
		t.Fatalf("summary target: %q", denied.Summary)
	}
	if mixed.Data["denied"] != nil || mixed.Data["has_errors"] != true || !strings.HasPrefix(mixed.Summary, "IAM 変更 CreateAccessKey:") {
		t.Fatalf("mixed: %+v", mixed)
	}
}
