package checks

import (
	"context"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

func snapshot(t *testing.T, st *store.Dir, kind record.Kind, items ...record.SnapshotItem) {
	t.Helper()
	if err := st.ReplaceSnapshot(context.Background(), kind, "src", items, now); err != nil {
		t.Fatal(err)
	}
}

func snap(kind record.Kind, key string, kv ...any) record.SnapshotItem {
	d := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		d[kv[i].(string)] = kv[i+1]
	}
	return record.SnapshotItem{Kind: kind, Key: key, Data: d}
}

func byKeyObs(obs []Observation) map[string]Observation {
	m := map[string]Observation{}
	for _, o := range obs {
		m[o.Key] = o
	}
	return m
}

func weekly() collect.Window { return collect.Window{From: now.Add(-7 * 24 * time.Hour), To: now} }

func TestCredentialHygiene(t *testing.T) {
	st := newStore(t)
	day := func(n int) string { return now.AddDate(0, 0, -n).Format(time.RFC3339) }
	key := func(n string, active bool, lastUsed, rotated string) map[string]any {
		return map[string]any{"key": n, "active": active, "last_used": lastUsed, "last_rotated": rotated}
	}
	snapshot(t, st, record.KindCredentialReport,
		snap(record.KindCredentialReport, account.RootUser, "access_keys", []any{key("1", true, day(1), day(400)), key("2", false, "", "")}),
		snap(record.KindCredentialReport, "alice", "password_enabled", true, "mfa_active", false, "access_keys", []any{key("1", true, day(91), day(200)), key("2", true, day(5), day(200))}),
		snap(record.KindCredentialReport, "bot", "password_enabled", false, "access_keys", []any{key("1", true, "", day(120)), key("2", false, "", day(500))}),
		snap(record.KindCredentialReport, "carol", "password_enabled", true, "mfa_active", true, "access_keys", []any{key("1", true, day(90), day(90))}),
	)
	obs, err := CredentialHygiene{Config: config.CredentialHygiene{UnusedDays: 90}}.Evaluate(context.Background(), st, weekly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := byKeyObs(obs)
	if keys(obs) != "root_access_key|1;unused_key|alice|1;no_mfa|alice;unused_key|bot|1" {
		t.Fatalf("keys: %s", keys(obs))
	}
	if m["root_access_key|1"].Severity != High || m["no_mfa|alice"].Severity != Medium || m["unused_key|bot|1"].Data["days_unused"] != 120 {
		t.Fatalf("%+v", m)
	}
	// 経過日数は毎週変わるが Fingerprint は変わらない
	obs2, _ := CredentialHygiene{Config: config.CredentialHygiene{UnusedDays: 90}}.Evaluate(context.Background(), st, collect.Window{From: now, To: now.AddDate(0, 0, 7)}, nil)
	if byKeyObs(obs2)["unused_key|bot|1"].Fingerprint != m["unused_key|bot|1"].Fingerprint || byKeyObs(obs2)["unused_key|bot|1"].Data["days_unused"] != 127 {
		t.Fatal("fingerprint must be stable")
	}
}

func TestGuardDutyFindings(t *testing.T) {
	st := newStore(t)
	snapshot(t, st, record.KindGuardDuty,
		snap(record.KindGuardDuty, "f1", "type", "Recon:EC2/PortProbeUnprotectedPort", "severity", 2.0, "count", 5, "resource_type", "Instance", "region", "ap-northeast-1"),
		snap(record.KindGuardDuty, "f2", "type", "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "severity", 8.0, "count", 1),
		snap(record.KindGuardDuty, "f3", "type", "CryptoCurrency:EC2/BitcoinTool.B", "severity", 5.0, "count", 3),
	)
	ctx := context.Background()
	obs, err := GuardDutyFindings{}.Evaluate(ctx, st, weekly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := byKeyObs(obs)
	if m["f1"].Severity != Low || m["f2"].Severity != High || m["f3"].Severity != Medium {
		t.Fatalf("%+v", m)
	}
	// 差分判定: count の増加は changed、アーカイブ (スナップショットから消える) は resolved
	newID := seqID()
	diff := func(obs []Observation, at time.Time) map[string]Class {
		res, err := Diff(ctx, st, DiffParams{Check: "guardduty_findings", Mode: ModeState, Window: weekly(), Now: at, NewID: newID}, obs)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]Class{}
		var ids []string
		for _, r := range res {
			out[r.Finding.Key] = r.Class
			ids = append(ids, r.Finding.ID)
		}
		if err := st.MarkReported(ctx, ids, at); err != nil {
			t.Fatal(err)
		}
		return out
	}
	diff(obs, now)
	snapshot(t, st, record.KindGuardDuty,
		snap(record.KindGuardDuty, "f1", "type", "Recon:EC2/PortProbeUnprotectedPort", "severity", 2.0, "count", 9),
		snap(record.KindGuardDuty, "f2", "type", "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "severity", 8.0, "count", 1),
	)
	obs, _ = GuardDutyFindings{}.Evaluate(ctx, st, weekly(), nil)
	if got := diff(obs, now.Add(7*24*time.Hour)); got["f1"] != ClassChanged || got["f2"] != ClassStillOpen || got["f3"] != ClassResolved {
		t.Fatalf("diff: %v", got)
	}
}

func TestAccessAnalyzerCheck(t *testing.T) {
	st := newStore(t)
	snapshot(t, st, record.KindAccessAnalyzer,
		snap(record.KindAccessAnalyzer, "a1", "resource", "arn:aws:s3:::public", "resource_type", "AWS::S3::Bucket", "is_public", true, "principal", "AWS=*", "actions", "s3:GetObject"),
		snap(record.KindAccessAnalyzer, "a2", "resource", "arn:aws:iam::1:role/Partner", "resource_type", "AWS::IAM::Role", "is_public", false, "principal", "AWS=999999999999", "actions", "sts:AssumeRole"),
	)
	obs, err := AccessAnalyzer{}.Evaluate(context.Background(), st, weekly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := byKeyObs(obs)
	if m["a1"].Severity != High || m["a2"].Severity != Medium {
		t.Fatalf("%+v", m)
	}
}

func TestPostureCheck(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	c := Posture{Config: config.Posture{MinPasswordLength: 14}}
	snapshot(t, st, record.KindPostureItem,
		snap(record.KindPostureItem, account.PostureCloudTrail, "trails", 1, "logging", []any{"old"}, "multi_region_logging", false, "without_validation", []any{"old"}),
		snap(record.KindPostureItem, "guardduty|ap-northeast-1", "enabled", false),
		snap(record.KindPostureItem, "guardduty|us-east-1", "enabled", true),
		snap(record.KindPostureItem, account.PostureRootMFA, "mfa_enabled", false),
		snap(record.KindPostureItem, account.PostureS3PublicAccess, "configured", true, "block_public_acls", true, "ignore_public_acls", true, "block_public_policy", false, "restrict_public_buckets", true),
		snap(record.KindPostureItem, account.PosturePasswordPolicy, "configured", true, "minimum_length", 8),
	)
	obs, err := c.Evaluate(ctx, st, weekly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys(obs) != "cloudtrail_logging;cloudtrail_log_validation;guardduty_enabled|ap-northeast-1;password_policy;root_mfa;s3_public_access_block" {
		t.Fatalf("keys: %s", keys(obs))
	}
	m := byKeyObs(obs)
	if m["s3_public_access_block"].Summary != "S3 のアカウント単位の Public Access Block に無効な項目がある: block_public_policy" || m["password_policy"].Severity != Medium || m["root_mfa"].Severity != High {
		t.Fatalf("%+v", m)
	}
	first, err := Diff(ctx, st, DiffParams{Check: "posture", Mode: ModeState, Window: weekly(), Now: now, NewID: seqID()}, obs)
	if err != nil {
		t.Fatal(err)
	}
	var reported []string
	for _, r := range first {
		reported = append(reported, r.Finding.ID)
	}
	if err := st.MarkReported(ctx, reported, now); err != nil {
		t.Fatal(err)
	}
	// 翌週: S3 とルート MFA の項目が権限不足で取れない → 前回の finding を維持 (resolved にしない)。直ったものは resolved
	snapshot(t, st, record.KindPostureItem,
		snap(record.KindPostureItem, account.PostureCloudTrail, "trails", 1, "logging", []any{"main"}, "multi_region_logging", true, "without_validation", []any{}),
		snap(record.KindPostureItem, "guardduty|ap-northeast-1", "enabled", false),
		snap(record.KindPostureItem, account.PostureRootMFA, "unknown", true, "action", account.ActionGetAccountSummary),
		snap(record.KindPostureItem, account.PostureS3PublicAccess, "unknown", true, "action", account.ActionGetPublicAccessBlock),
		snap(record.KindPostureItem, account.PosturePasswordPolicy, "configured", true, "minimum_length", 14),
	)
	obs, _ = c.Evaluate(ctx, st, weekly(), nil)
	res, err := Diff(ctx, st, DiffParams{Check: "posture", Mode: ModeState, Window: weekly(), Now: now.Add(7 * 24 * time.Hour), NewID: seqID()}, obs)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Class{}
	for _, r := range res {
		got[r.Finding.Key] = r.Class
	}
	want := map[string]Class{"cloudtrail_log_validation": ClassResolved, "cloudtrail_logging": ClassResolved, "guardduty_enabled|ap-northeast-1": ClassStillOpen,
		"password_policy": ClassResolved, "root_mfa": ClassStillOpen, "s3_public_access_block": ClassStillOpen}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %s want %s", k, got[k], v)
		}
	}
}

func TestAIPathUsage(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	al, err := allowlist.Parse([]byte("principals:\n  - arn: arn:aws:iam::1:role/arata-audit\n    tags: [ai]\n  - arn: arn:aws:iam::1:role/Deploy\n    tags: [deploy]\n"))
	if err != nil {
		t.Fatal(err)
	}
	seen := func(arn, ip string, at time.Time) {
		if err := st.UpsertPrincipalSeen(ctx, record.PrincipalSeen{Time: at, FirstTime: at, Source: "trail", ARN: arn, Kind: record.PrincipalAssumedRole, IP: ip, Count: 2}, store.PrincipalApproved); err != nil {
			t.Fatal(err)
		}
	}
	seen("arn:aws:iam::1:role/arata-audit", "203.0.113.10", now.Add(-time.Hour))
	seen("arn:aws:iam::1:role/arata-audit", "198.51.100.66", now.Add(-2*time.Hour))
	seen("arn:aws:iam::1:role/arata-audit", "203.0.113.99", now.Add(-48*time.Hour)) // 窓外
	seen("arn:aws:iam::1:role/Deploy", "203.0.113.10", now.Add(-time.Hour))         // ai タグが無い
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	obs, err := AIPathUsage{}.Evaluate(ctx, st, w, al)
	if err != nil {
		t.Fatal(err)
	}
	if keys(obs) != "arn:aws:iam::1:role/arata-audit|198.51.100.66;arn:aws:iam::1:role/arata-audit|203.0.113.10" || obs[0].Severity != Info || obs[0].Data["count_total"] != 2 {
		t.Fatalf("%+v", obs)
	}
}
