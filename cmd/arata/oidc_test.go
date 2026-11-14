package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
)

const (
	oidcProviderARN = "arn:aws:iam::" + acct + ":oidc-provider/token.actions.githubusercontent.com"
	oidcRole        = "arn:aws:iam::" + acct + ":role/gha-deploy"
)

// webIdentity は GitHub Actions の OIDC のトークンでロールを引き受けた記録 (CloudTrail の AssumeRoleWithWebIdentity の形)。
func webIdentity(id string, at time.Time, sub, role string) types.Event {
	who := cloudtrailtest.Identity{"type": "WebIdentityUser", "principalId": oidcProviderARN + ":sts.amazonaws.com:" + sub, "userName": sub, "identityProvider": oidcProviderARN}
	return cloudtrailtest.Event(id, at, who, "sts.amazonaws.com", "AssumeRoleWithWebIdentity", "ap-northeast-1", "203.0.113.9", true,
		map[string]any{"roleArn": role, "roleSessionName": "GitHubActions"})
}

func oidcReview(t *testing.T, c *cli) map[string]destItem {
	t.Helper()
	if code := c.run("review", "--config", c.cfg, "--format", "json"); code != 0 {
		t.Fatalf("review exit %d: %s", code, c.stderr)
	}
	var items []destItem
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil {
		t.Fatalf("%v\n%s", err, c.stdout)
	}
	out := map[string]destItem{}
	for _, it := range items {
		// OIDC の引き受けを出すのは oidc_assume_role だけ (unknown_assume_role・new_principal に引き受けそのものは出ない)
		if strings.Contains(it.Key, "repo:") && it.Check != "oidc_assume_role" || it.Check == "unknown_assume_role" {
			t.Fatalf("OIDC の引き受けが %s に出た: %+v", it.Check, it)
		}
		if it.Check == "oidc_assume_role" {
			out[it.Key] = it
		}
	}
	return out
}

// 収集 → 評価 → 既知リストに入り口を書く → 解消、の流れ (ADR 0055)。
func TestOIDCAssumeRoleEndToEnd(t *testing.T) {
	c := newCLI(t)
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	const mainSub = "repo:example-org/example-repo:ref:refs/heads/main"
	const key = "token.actions.githubusercontent.com|"
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		webIdentity("w1", c.now.Add(-3*time.Hour), mainSub, oidcRole),
		webIdentity("w2", c.now.Add(-2*time.Hour), "repo:example-org@1234567/example-repo@7654321:ref:refs/heads/main", oidcRole),
	)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	c.assertCodesInVocabulary()
	items := oidcReview(t, c)
	first := items[key+mainSub+"|"+oidcRole]
	// 既知リストに無いロール → medium。ID 入りの sub も同じ組にまとまる
	if len(items) != 1 || first.Severity != "medium" || first.Data["count"] != float64(2) || first.Data["repo"] != "example-org/example-repo" || first.Data["ref"] != "refs/heads/main" ||
		first.Data["provider_account"] != acct || first.Data["role_known"] != false {
		t.Fatalf("%+v", items)
	}
	// sub そのもの・セッション名は finding に残さない
	if b, _ := json.Marshal(first.Data); strings.Contains(string(b), "GitHubActions") || strings.Contains(string(b), "@1234567") {
		t.Fatalf("data: %s", b)
	}
	// approve は対応しない (既知リストに手で書く)
	if code := c.run("approve", first.ID, "--config", c.cfg, "--note", "n"); code == 0 || !strings.Contains(c.stderr.String(), "oidc_subjects") {
		t.Fatalf("approve exit %d: %s", code, c.stderr)
	}
	// ロールを主体として承認しても、入り口は既知にならない
	appendAllowlist(t, c, "  - arn: "+oidcRole+"\n    note: デプロイのロール\n    tags: [deploy]\n    dynamic_source: true\n")
	// 人が入り口を書く
	appendAllowlist(t, c, "oidc_subjects:\n  - provider: token.actions.githubusercontent.com\n    role: "+oidcRole+"\n    repo: example-org/example-repo\n    refs: [\"refs/heads/main\"]\n    note: 本番のデプロイ\n    approved_by: alice\n")
	if code := c.run("config", "check", "--config", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "oidc_subjects 1") {
		t.Fatalf("config check exit %d:\n%s%s", code, c.stdout, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		webIdentity("w3", c.now.Add(-3*time.Hour), mainSub, oidcRole),
		webIdentity("w4", c.now.Add(-2*time.Hour), "repo:example-org/example-repo:ref:refs/heads/feature", oidcRole),
	)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	var rep struct {
		Findings struct {
			Resolved []struct {
				Check, Key string
				Data       map[string]any
			}
		}
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings.Resolved) != 1 || rep.Findings.Resolved[0].Key != first.Key || rep.Findings.Resolved[0].Data["resolved_reason"] != "known_oidc_subject" ||
		rep.Findings.Resolved[0].Data["allowlist_subject"] != "oidc_subject:token.actions.githubusercontent.com example-org/example-repo -> "+oidcRole {
		t.Fatalf("resolved: %+v", rep.Findings.Resolved)
	}
	items = oidcReview(t, c)
	feature := items[key+"repo:example-org/example-repo:ref:refs/heads/feature|"+oidcRole]
	// 既知のロールに、知らないブランチから → high。既知の入り口の分は info の行
	if len(items) != 2 || feature.Severity != "high" || feature.Data["role_known"] != true || items["known:"+oidcRole].Severity != "info" || items["known:"+oidcRole].Data["count"] != float64(1) {
		t.Fatalf("%+v", items)
	}
	// 入り口の項目を消すと、info の行は解消する
	b, err := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, "allowlist.yaml"), []byte(strings.Split(string(b), "oidc_subjects:")[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(24 * time.Hour)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	items = oidcReview(t, c)
	if _, ok := items["known:"+oidcRole]; ok || len(items) != 1 {
		t.Fatalf("info の行が残った: %+v", items)
	}
}
