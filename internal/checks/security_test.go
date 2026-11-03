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
	"github.com/CircleAround/arata/internal/store"
)

const (
	secUser   = "arn:aws:iam::123456789012:user/alice"
	secDeploy = "arn:aws:iam::123456789012:role/Deploy"
)

const secAllowlist = `
principals:
  - arn: arn:aws:iam::123456789012:role/Deploy
    tags: [deploy]
`

type secEv struct {
	id, source, name, principal, code string
	data                              map[string]any
}

func secFixture(t *testing.T, evs []secEv) (*store.Dir, *allowlist.List, collect.Window) {
	t.Helper()
	st := newStore(t)
	ctx := context.Background()
	for i, e := range evs {
		p := e.principal
		if p == "" {
			p = secUser
		}
		kind := record.PrincipalUser
		if p == secDeploy {
			kind = record.PrincipalAssumedRole
		}
		te := record.TrailEvent{EventID: e.id, Time: now.Add(-time.Duration(i+1) * time.Minute), Source: "trail", Name: e.name, EventSource: e.source,
			PrincipalARN: p, PrincipalKind: kind, IP: "198.51.100.1", ErrorCode: e.code, Data: e.data}
		if err := st.InsertEvent(ctx, te); err != nil {
			t.Fatal(err)
		}
	}
	al, err := allowlist.Parse([]byte(secAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	return st, al, collect.Window{From: now.Add(-24 * time.Hour), To: now}
}

func bySev(obs []Observation) map[string]Severity {
	out := map[string]Severity{}
	for _, o := range obs {
		out[o.Key] = o.Severity
	}
	return out
}

func defenseConfig() DefenseEvasion {
	c := config.DefaultChecks()
	return DefenseEvasion{Config: c.DefenseEvasion, AuditLogGroups: []string{"prod-nginx-access"}, LogBaselineDays: 14}
}

func TestDefenseEvasion(t *testing.T) {
	const ct, gd, logs = "cloudtrail.amazonaws.com", "guardduty.amazonaws.com", "logs.amazonaws.com"
	st, al, w := secFixture(t, []secEv{
		{id: "1", source: ct, name: "StopLogging", data: map[string]any{"name": "main"}},
		{id: "2", source: ct, name: "StopLogging", principal: secDeploy, data: map[string]any{"name": "main"}},
		{id: "3", source: ct, name: "StopLogging", code: "AccessDenied", data: map[string]any{"name": "other"}}, // 失敗は access_denied が扱う
		{id: "4", source: ct, name: "UpdateTrail", data: map[string]any{"name": "main", "multi_region": false}},
		{id: "5", source: ct, name: "UpdateTrail", data: map[string]any{"name": "sns-only"}}, // 弱める変更ではない
		{id: "6", source: ct, name: "PutEventSelectors", data: map[string]any{"trail": "main", "selectors_reduced": []any{"include_management_events=false"}}},
		{id: "7", source: ct, name: "PutEventSelectors", data: map[string]any{"trail": "data-only"}},
		{id: "8", source: gd, name: "UpdateDetector", data: map[string]any{"detector_id": "d1", "enable": false}},
		{id: "9", source: gd, name: "UpdateDetector", data: map[string]any{"detector_id": "d2", "enable": true}},
		{id: "10", source: gd, name: "CreateFilter", data: map[string]any{"name": "quiet", "filter_action": "ARCHIVE"}},
		{id: "11", source: gd, name: "CreateFilter", data: map[string]any{"name": "noop", "filter_action": "NOOP"}},
		{id: "12", source: "access-analyzer.amazonaws.com", name: "CreateArchiveRule", data: map[string]any{"analyzer": "a1", "rule": "r1"}},
		{id: "13", source: logs, name: "DeleteLogGroup", data: map[string]any{"log_group": "prod-nginx-access"}},          // 監査対象 → critical
		{id: "14", source: logs, name: "DeleteLogGroup", data: map[string]any{"log_group": "scratch"}},                    // high
		{id: "15", source: logs, name: "PutRetentionPolicy", data: map[string]any{"log_group": "prod-nginx-access", "retention_days": 7}}, // critical、平常帯より短い
		{id: "16", source: logs, name: "PutRetentionPolicy", data: map[string]any{"log_group": "scratch", "retention_days": 30}},          // high
		{id: "17", source: logs, name: "PutRetentionPolicy", data: map[string]any{"log_group": "scratch2", "retention_days": 365}},        // 下限以上
		{id: "18", source: logs, name: "DeleteLogStream", data: map[string]any{"log_group": "prod-nginx-access"}},                         // 監査対象だけ
		{id: "19", source: logs, name: "DeleteLogStream", data: map[string]any{"log_group": "scratch"}},
		{id: "20", source: "ec2.amazonaws.com", name: "DeleteFlowLogs", principal: secDeploy, data: map[string]any{"flow_log_ids": []any{"fl-1"}}}, // deploy → medium
		{id: "21", source: "s3.amazonaws.com", name: "DeleteBucketPolicy", data: map[string]any{"bucket": "example-trail-bucket"}}, // trail_buckets にある
		{id: "22", source: "s3.amazonaws.com", name: "PutBucketLifecycle", data: map[string]any{"bucket": "seen-trail-bucket", "lifecycle_expiration_days": 1}},
		{id: "23", source: "s3.amazonaws.com", name: "PutBucketLifecycle", data: map[string]any{"bucket": "app-bucket"}}, // 宛先でない
		{id: "24", source: ct, name: "CreateTrail", data: map[string]any{"name": "second", "s3_bucket": "seen-trail-bucket"}}, // 宛先として覚える
		{id: "25", source: "wafv2.amazonaws.com", name: "PutLoggingConfiguration", data: map[string]any{"resource_arn": "arn:x"}},
		{id: "26", source: "wafv2.amazonaws.com", name: "PutLoggingConfiguration", data: map[string]any{"resource_arn": "arn:y", "logging_filter": true}},
		{id: "27", source: "securityhub.amazonaws.com", name: "DisableSecurityHub"},
		{id: "28", source: "config.amazonaws.com", name: "StopConfigurationRecorder", data: map[string]any{"recorder": "default"}},
		{id: "29", source: "iam.amazonaws.com", name: "CreateUser", data: map[string]any{"user_name": "x"}}, // 対象外
	})
	c := defenseConfig()
	c.Config.TrailBuckets = []string{"example-trail-bucket"}
	obs, err := c.Evaluate(context.Background(), st, w, al)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Severity{
		"cloudtrail:StopLogging|" + secUser + "|main":                         Critical,
		"cloudtrail:StopLogging|" + secDeploy + "|main":                       High,
		"cloudtrail:UpdateTrail|" + secUser + "|main":                         High,
		"cloudtrail:PutEventSelectors|" + secUser + "|main":                   High,
		"guardduty:UpdateDetector|" + secUser + "|d1":                         High,
		"guardduty:CreateFilter|" + secUser + "|quiet":                        High,
		"access-analyzer:CreateArchiveRule|" + secUser + "|a1/r1":             High,
		"logs:DeleteLogGroup|" + secUser + "|prod-nginx-access":               Critical,
		"logs:DeleteLogGroup|" + secUser + "|scratch":                         High,
		"logs:PutRetentionPolicy|" + secUser + "|prod-nginx-access":           Critical,
		"logs:PutRetentionPolicy|" + secUser + "|scratch":                     High,
		"logs:DeleteLogStream|" + secUser + "|prod-nginx-access":              Critical,
		"ec2:DeleteFlowLogs|" + secDeploy + "|fl-1":                           Medium,
		"s3:DeleteBucketPolicy|" + secUser + "|example-trail-bucket":          High,
		"s3:PutBucketLifecycle|" + secUser + "|seen-trail-bucket":             High,
		"wafv2:PutLoggingConfiguration|" + secUser + "|arn:y":                 High,
		"securityhub:DisableSecurityHub|" + secUser + "|":                     High,
		"config:StopConfigurationRecorder|" + secUser + "|default":            High,
	}
	got := bySev(obs)
	for k, s := range want {
		if got[k] != s {
			t.Errorf("%s: got %q want %q", k, got[k], s)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected: %s (%s)", k, got[k])
		}
	}
	for _, o := range obs {
		switch o.Key {
		case "logs:PutRetentionPolicy|" + secUser + "|prod-nginx-access":
			if o.Data["audit_log_group"] != true || o.Data["shorter_than_baseline_days"] != true || o.Data["retention_days"] != 7 ||
				!strings.Contains(o.Summary, "平常帯") {
				t.Errorf("retention: %+v", o)
			}
		case "logs:PutRetentionPolicy|" + secUser + "|scratch":
			if _, ok := o.Data["shorter_than_baseline_days"]; ok {
				t.Errorf("not an audit group: %+v", o.Data)
			}
		case "cloudtrail:StopLogging|" + secDeploy + "|main":
			if o.Data["known_deploy_principal"] != true {
				t.Errorf("deploy: %+v", o.Data)
			}
		case "cloudtrail:UpdateTrail|" + secUser + "|main":
			if strings.Join(o.Data["changes"].([]string), ",") != "multi_region=false" {
				t.Errorf("changes: %+v", o.Data)
			}
		}
		if o.Check != "defense_evasion" || o.Fingerprint == "" || !strings.HasPrefix(o.Summary, "監査・検知の無効化") {
			t.Errorf("obs: %+v", o)
		}
	}
}

func TestPublicExposure(t *testing.T) {
	const ec2, s3, rds = "ec2.amazonaws.com", "s3.amazonaws.com", "rds.amazonaws.com"
	rule := func(proto string, from, to int, cidr string) map[string]any {
		return map[string]any{"protocol": proto, "from_port": from, "to_port": to, "cidr": cidr}
	}
	st, al, w := secFixture(t, []secEv{
		{id: "1", source: ec2, name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-1", "public_ingress": []any{rule("tcp", 22, 22, "0.0.0.0/0")}}},
		{id: "2", source: ec2, name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-2", "public_ingress": []any{rule("tcp", 443, 443, "0.0.0.0/0")}}},
		{id: "3", source: ec2, name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-3", "public_ingress": []any{rule("-1", -1, -1, "::/0")}}},
		{id: "4", source: ec2, name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-4", "public_ingress": []any{rule("tcp", 3000, 3400, "0.0.0.0/0")}}}, // 3306・3389 を含む範囲
		{id: "5", source: ec2, name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-5"}},                                                       // 公開でない
		{id: "6", source: ec2, name: "AuthorizeSecurityGroupIngress", principal: secDeploy, data: map[string]any{"group_id": "sg-6", "public_ingress": []any{rule("tcp", 22, 22, "0.0.0.0/0")}}}, // deploy でも下げない
		{id: "7", source: ec2, name: "AuthorizeSecurityGroupIngress", code: "InvalidPermission.Duplicate", data: map[string]any{"group_id": "sg-7", "public_ingress": []any{rule("tcp", 22, 22, "0.0.0.0/0")}}},
		{id: "8", source: ec2, name: "ModifySecurityGroupRules", data: map[string]any{"group_id": "sg-8", "public_ingress": []any{map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0", "rule_id": "sgr-1"}}}},
		{id: "9", source: ec2, name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-9", "public_ingress": []any{rule("icmp", 8, -1, "0.0.0.0/0")}}},
		{id: "10", source: s3, name: "PutBucketPolicy", data: map[string]any{"bucket": "b1", "policy_public": true, "public_statements": []any{"Public: s3:GetObject"}}},
		{id: "11", source: s3, name: "PutBucketPolicy", data: map[string]any{"bucket": "b2", "policy_public": false}},
		{id: "12", source: s3, name: "PutBucketAcl", data: map[string]any{"bucket": "b3", "acl_public_grants": []any{"AllUsers:READ"}}},
		{id: "13", source: s3, name: "PutBucketAcl", data: map[string]any{"bucket": "b4"}},
		{id: "14", source: s3, name: "PutPublicAccessBlock", data: map[string]any{"bucket": "b5", "pab_disabled": []any{"BlockPublicPolicy"}}},
		{id: "15", source: s3, name: "PutPublicAccessBlock", data: map[string]any{"bucket": "b6"}},
		{id: "16", source: s3, name: "DeleteAccountPublicAccessBlock"},
		{id: "17", source: rds, name: "ModifyDBInstance", data: map[string]any{"db_instance": "db1", "publicly_accessible": true}},
		{id: "18", source: rds, name: "ModifyDBInstance", data: map[string]any{"db_instance": "db2", "publicly_accessible": false}},
		{id: "19", source: rds, name: "ModifyDBSnapshotAttribute", data: map[string]any{"db_snapshot": "s1", "shared_public": true}},
		{id: "20", source: ec2, name: "ModifySnapshotAttribute", data: map[string]any{"snapshot_id": "snap-1"}},
		{id: "21", source: "lambda.amazonaws.com", name: "AddPermission20150331v2", data: map[string]any{"function": "fn1", "lambda_principal": "*", "function_url_auth_type": "NONE"}},
		{id: "22", source: "lambda.amazonaws.com", name: "AddPermission20150331v2", data: map[string]any{"function": "fn2", "lambda_principal": "*", "lambda_conditions": []any{"sourceArn"}}},
		{id: "23", source: "lambda.amazonaws.com", name: "AddPermission20150331v2", data: map[string]any{"function": "fn3", "lambda_principal": "s3.amazonaws.com"}},
	})
	c := PublicExposure{Config: config.DefaultChecks().PublicExposure}
	obs, err := c.Evaluate(context.Background(), st, w, al)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Severity{
		"ec2:AuthorizeSecurityGroupIngress|sg-1|tcp/22 0.0.0.0/0":        High,
		"ec2:AuthorizeSecurityGroupIngress|sg-2|tcp/443 0.0.0.0/0":       Low,
		"ec2:AuthorizeSecurityGroupIngress|sg-3|all ::/0":                High,
		"ec2:AuthorizeSecurityGroupIngress|sg-4|tcp/3000-3400 0.0.0.0/0": High,
		"ec2:AuthorizeSecurityGroupIngress|sg-6|tcp/22 0.0.0.0/0":        High,
		"ec2:ModifySecurityGroupRules|sg-8|tcp/22 0.0.0.0/0":             Medium, // 向き (ingress / egress) が記録に無いので 1 段下げる
		"ec2:AuthorizeSecurityGroupIngress|sg-9|icmp 0.0.0.0/0":          Low,
		"s3:PutBucketPolicy|b1|public_policy":                            High,
		"s3:PutBucketAcl|b3|AllUsers:READ":                               High,
		"s3:PutPublicAccessBlock|b5|BlockPublicPolicy=false":             High,
		"s3:DeleteAccountPublicAccessBlock|account|deleted":              High,
		"rds:ModifyDBInstance|db1|publicly_accessible":                   High,
		"rds:ModifyDBSnapshotAttribute|s1|all":                           High,
		"lambda:AddPermission|fn1|principal=* auth=NONE":                 Medium,
	}
	got := bySev(obs)
	for k, s := range want {
		if got[k] != s {
			t.Errorf("%s: got %q want %q", k, got[k], s)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected: %s (%s)", k, got[k])
		}
	}
	for _, o := range obs {
		if o.Check != "public_exposure" || o.Fingerprint == "" || !strings.HasPrefix(o.Summary, "公開設定の変更") || o.Data["principal"] == nil {
			t.Errorf("obs: %+v", o)
		}
		if strings.Contains(o.Key, "sg-6") && o.Data["known_deploy_principal"] != true {
			t.Errorf("deploy fact must be kept: %+v", o.Data)
		}
		if strings.Contains(o.Key, "sg-1") && o.Data["sensitive"] != true {
			t.Errorf("sensitive: %+v", o.Data)
		}
		if strings.Contains(o.Key, "sg-8") && o.Data["direction_unknown"] != true {
			t.Errorf("direction: %+v", o.Data)
		}
	}
}

// 設定の機微なポートを変えられる。
func TestPublicExposureSensitivePorts(t *testing.T) {
	st, al, w := secFixture(t, []secEv{
		{id: "1", source: "ec2.amazonaws.com", name: "AuthorizeSecurityGroupIngress", data: map[string]any{"group_id": "sg-1",
			"public_ingress": []any{map[string]any{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "cidr": "0.0.0.0/0"}}}},
	})
	cfg := config.DefaultChecks().PublicExposure
	cfg.SensitivePorts = []int{8080}
	obs, err := PublicExposure{Config: cfg}.Evaluate(context.Background(), st, w, al)
	if err != nil || len(obs) != 1 || obs[0].Severity != High {
		t.Fatalf("%v %+v", err, obs)
	}
}

// 注目イベントが増えても (防御の無効化・公開設定の変更が events に入っても)、既存のチェックの結果は変わらない。
func TestSecurityEventsDoNotChangeExistingChecks(t *testing.T) {
	ctx := context.Background()
	extra := []record.TrailEvent{}
	for i, api := range append(DefenseEvasionAPIs(), PublicExposureAPIs()...) {
		for _, p := range []struct {
			arn  string
			kind record.PrincipalKind
		}{{"arn:aws:iam::1:user/unknown", record.PrincipalUser}, {"arn:aws:iam::1:role/Deploy", record.PrincipalAssumedRole}} {
			extra = append(extra, record.TrailEvent{EventID: "sec-" + api.Source + api.Name + p.arn, Time: now.Add(-time.Duration(i+1) * time.Minute), Source: "trail",
				Name: api.Name, EventSource: api.Source, PrincipalARN: p.arn, PrincipalKind: p.kind, IP: "198.51.100.1",
				Data: map[string]any{"bucket": "b", "log_group": "g", "public_ingress": []any{map[string]any{"protocol": "-1", "from_port": -1, "to_port": -1, "cidr": "0.0.0.0/0"}}}})
		}
	}
	reg := NewRegistry()
	for _, name := range reg.Names() {
		ch, _ := reg.Get(name)
		if name == "defense_evasion" || name == "public_exposure" {
			continue
		}
		if !needsTrail(ch) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			st1, al, w := fixture(t)
			before, err := ch.Evaluate(ctx, st1, w, al)
			if err != nil {
				t.Fatal(err)
			}
			st2, _, _ := fixture(t)
			for _, e := range extra {
				if err := st2.InsertEvent(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			after, err := ch.Evaluate(ctx, st2, w, al)
			if err != nil {
				t.Fatal(err)
			}
			if b, a := fmt.Sprintf("%+v", before), fmt.Sprintf("%+v", after); b != a {
				t.Fatalf("changed:\n before %s\n after  %s", b, a)
			}
		})
	}
}

func needsTrail(c Check) bool {
	for _, k := range c.Needs() {
		if k == record.KindTrailEvent {
			return true
		}
	}
	return false
}
