package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

type regionEv struct {
	id, source, region, evSource, name, principal, code string
	kind                                                record.PrincipalKind
	readOnly                                            bool
}

func unusedRegionCheck() UnusedRegionActivity {
	return UnusedRegionActivity{Config: config.DefaultChecks().UnusedRegionActivity, Sources: []string{"unused"}}
}

// ふだん使わないリージョンの書き込みは high、計算資源の作成は critical、計算資源の作成の試行 (拒否) は medium。
// サービスの主体・グローバルサービス・他のソースのイベントは見ない。deploy タグの主体は 1 段下げる。
func TestUnusedRegionActivity(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	evs := []regionEv{
		{id: "run", region: "eu-west-1", evSource: "ec2.amazonaws.com", name: "RunInstances"},
		{id: "sg", region: "eu-west-1", evSource: "ec2.amazonaws.com", name: "CreateSecurityGroup"},
		{id: "ssm", region: "sa-east-1", evSource: "ssm.amazonaws.com", name: "PutParameter"},
		{id: "lambda-denied", region: "me-central-1", evSource: "lambda.amazonaws.com", name: "CreateFunction20150331", code: "AccessDeniedException"},
		{id: "other-denied", region: "me-central-1", evSource: "ssm.amazonaws.com", name: "PutParameter", code: "AccessDeniedException", principal: "arn:aws:iam::123456789012:user/bob"},
		{id: "svc", region: "sa-east-1", evSource: "config.amazonaws.com", name: "PutEvaluations", principal: "config.amazonaws.com", kind: record.PrincipalService},
		{id: "iam", region: "us-east-1", evSource: "iam.amazonaws.com", name: "CreateUser"},
		{id: "deploy", region: "ca-central-1", evSource: "lambda.amazonaws.com", name: "CreateFunction20150331", principal: secDeploy, kind: record.PrincipalAssumedRole},
		// cloudtrail-lookup (ふだん使うリージョン) のイベントは見ない
		{id: "active", source: "trail", region: "ap-northeast-1", evSource: "ec2.amazonaws.com", name: "RunInstances"},
	}
	for i, e := range evs {
		src, p, k := e.source, e.principal, e.kind
		if src == "" {
			src = "unused"
		}
		if p == "" {
			p = secUser
		}
		if k == "" {
			k = record.PrincipalUser
		}
		te := record.TrailEvent{EventID: e.id, Time: now.Add(-time.Duration(i+1) * time.Minute), Source: src, Name: e.name, EventSource: e.evSource, Region: e.region,
			PrincipalARN: p, PrincipalKind: k, IP: "198.51.100.7", ErrorCode: e.code, ReadOnly: e.readOnly, Data: map[string]any{}}
		if err := st.InsertEvent(ctx, te); err != nil {
			t.Fatal(err)
		}
	}
	al, err := allowlist.Parse([]byte(secAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	c := unusedRegionCheck()
	obs, err := c.Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, al)
	if err != nil {
		t.Fatal(err)
	}
	got := byKeyObs(obs)
	want := map[string]Severity{
		"eu-west-1|" + secUser:      Critical,
		"sa-east-1|" + secUser:      High,
		"me-central-1|" + secUser:   Medium,
		"ca-central-1|" + secDeploy: High,
	}
	if len(got) != len(want) {
		t.Fatalf("keys: %v", bySev(obs))
	}
	for k, s := range want {
		if got[k].Severity != s {
			t.Fatalf("%s: %s (want %s) %v", k, got[k].Severity, s, bySev(obs))
		}
	}
	eu := got["eu-west-1|"+secUser]
	if strings.Join(eu.Data["apis"].([]string), ",") != "ec2:CreateSecurityGroup,ec2:RunInstances" ||
		strings.Join(eu.Data["compute_apis"].([]string), ",") != "ec2:RunInstances" || eu.Data["region"] != "eu-west-1" || eu.Data["count"] != 2 {
		t.Fatalf("data: %+v", eu.Data)
	}
	if !strings.Contains(eu.Summary, "eu-west-1") || !strings.Contains(eu.Summary, "計算資源") {
		t.Fatalf("summary: %s", eu.Summary)
	}
	me := got["me-central-1|"+secUser]
	if me.Data["failed"] != 1 || strings.Join(me.Data["compute_apis"].([]string), ",") != "lambda:CreateFunction" {
		t.Fatalf("attempt data: %+v", me.Data)
	}
	if got["ca-central-1|"+secDeploy].Data["known_deploy_principal"] != true {
		t.Fatalf("deploy: %+v", got["ca-central-1|"+secDeploy].Data)
	}
	// 重大度か操作の集合が変われば changed
	if eu.Fingerprint == got["sa-east-1|"+secUser].Fingerprint {
		t.Fatal("fingerprint must include severity and apis")
	}

	// ソースが無ければ (設定に cloudtrail-unused-regions が無い) 何も見ない
	none, err := UnusedRegionActivity{Config: c.Config}.Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, al)
	if err != nil || len(none) != 0 {
		t.Fatalf("without sources: %v %v", none, err)
	}
}

func TestComputeAPIMatch(t *testing.T) {
	c := unusedRegionCheck()
	for _, tc := range []struct {
		src, name string
		want      bool
	}{
		{"ec2.amazonaws.com", "RunInstances", true},
		{"lambda.amazonaws.com", "CreateFunction20150331", true},
		{"lambda.amazonaws.com", "CreateFunction20150331v2", true},
		{"lambda.amazonaws.com", "CreateFunctionUrlConfig20211031", false},
		{"ecs.amazonaws.com", "CreateCluster", true},
		{"redshift.amazonaws.com", "CreateCluster", false},
		{"ec2.amazonaws.com", "RunInstancesX", false},
	} {
		if got := c.isCompute(record.TrailEvent{EventSource: tc.src, Name: tc.name}); got != tc.want {
			t.Errorf("%s %s: %v", tc.src, tc.name, got)
		}
	}
	if got := apiOf(record.TrailEvent{EventSource: "lambda.amazonaws.com", Name: "CreateFunction20150331"}); got != "lambda:CreateFunction" {
		t.Fatalf("label: %q", got)
	}
}

// サービスリンクロール (role/aws-service-role/<サービス>/<名前>) の書き込みは、利用者が機能を有効にした結果として AWS が行うことが多い。
// 重大度は下げず、見出しと data で分かるようにする。Fingerprint は変えない。
func TestUnusedRegionActivityServiceLinkedRole(t *testing.T) {
	const slr = "arn:aws:iam::123456789012:role/aws-service-role/sso.amazonaws.com/AWSServiceRoleForSSO"
	st := newStore(t)
	ctx := context.Background()
	for i, p := range []string{slr, secUser} {
		te := record.TrailEvent{EventID: fmt.Sprint("e", i), Time: now.Add(-time.Duration(i+1) * time.Minute), Source: "unused", Name: "RunInstances", EventSource: "ec2.amazonaws.com",
			Region: "eu-west-1", PrincipalARN: p, PrincipalKind: record.PrincipalAssumedRole, Data: map[string]any{}}
		if err := st.InsertEvent(ctx, te); err != nil {
			t.Fatal(err)
		}
	}
	al, err := allowlist.Parse([]byte(secAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := unusedRegionCheck().Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, al)
	if err != nil {
		t.Fatal(err)
	}
	got := byKeyObs(obs)
	o, other := got["eu-west-1|"+slr], got["eu-west-1|"+secUser]
	if o.Severity != Critical || other.Severity != Critical {
		t.Fatalf("severity: %v", bySev(obs))
	}
	if o.Data["service_linked_role"] != true || o.Data["service_linked_service"] != "sso.amazonaws.com" {
		t.Fatalf("data: %+v", o.Data)
	}
	if want := "ふだん使わないリージョン eu-west-1 での書き込み: " + slr + " (1 件: ec2:RunInstances)。計算資源の作成を含む (ec2:RunInstances)" +
		"。主体は sso.amazonaws.com のサービスリンクロール (人の操作に付随することが多い)"; o.Summary != want {
		t.Fatalf("summary: %q", o.Summary)
	}
	if _, ok := other.Data["service_linked_role"]; ok || strings.Contains(other.Summary, "サービスリンクロール") {
		t.Fatalf("other: %q %+v", other.Summary, other.Data)
	}
	if o.Fingerprint != other.Fingerprint {
		t.Fatalf("fingerprint: %q / %q", o.Fingerprint, other.Fingerprint)
	}
}
