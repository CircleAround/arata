package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
)

const saas = "111122223333"

type reviewItem struct {
	ID, Check, Key, Severity, Status, Summary string
	SnoozeUntil                               string `json:"snooze_until"`
	Approve                                   *struct {
		ARN, Account, Label string
	}
}

// seedFindings は init → 静かな run → 新規の主体・外部アカウントの AssumeRole・root ログインが出る run まで進める。
func seedFindings(t *testing.T, c *cli) map[string]reviewItem {
	t.Helper()
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		cloudtrailtest.Event("n1", c.now.Add(-2*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}),
		cloudtrailtest.Event("n2", c.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
		cloudtrailtest.Event("n3", c.now.Add(-3*time.Hour), cloudtrailtest.Identity{"type": "AWSAccount", "principalId": "AIDAEXAMPLESAAS", "accountId": saas}, "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.202", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/ExampleSaaSRole"}),
	)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "外部アカウント "+saas) {
		t.Fatalf("report must label the external account:\n%s", c.stdout)
	}
	return review(t, c)
}

func review(t *testing.T, c *cli, args ...string) map[string]reviewItem {
	t.Helper()
	if code := c.run(append([]string{"review", "--config", c.cfg, "--format", "json"}, args...)...); code != 0 {
		t.Fatalf("review exit %d: %s", code, c.stderr)
	}
	var items []reviewItem
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil {
		t.Fatalf("%v\n%s", err, c.stdout)
	}
	out := map[string]reviewItem{}
	for _, it := range items {
		out[it.Check+"|"+it.Key] = it
	}
	return out
}

func TestReviewAndApprove(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	ext := items["unknown_assume_role|arn:aws:iam::"+saas+":root->arn:aws:iam::"+acct+":role/ExampleSaaSRole"]
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	if np.ID == "" || ext.ID == "" || root.ID == "" || len(items) != 5 {
		t.Fatalf("review items: %+v", items)
	}
	if np.Approve == nil || np.Approve.ARN != "arn:aws:iam::"+acct+":user/mallory" || ext.Approve == nil || ext.Approve.Account != saas || ext.Approve.Label != "外部アカウント "+saas || root.Approve != nil {
		t.Fatalf("approve targets: np=%+v ext=%+v root=%+v", np.Approve, ext.Approve, root.Approve)
	}
	// 表形式は重大度の高い順
	if code := c.run("review", "--config", c.cfg); code != 0 || !strings.HasPrefix(strings.Split(c.stdout.String(), "\n")[1], root.ID+"  critical") {
		t.Fatalf("table exit %d:\n%s", code, c.stdout)
	}

	// approve: 期限付き + タグ。allowlist.yaml の既存部分は変えずに末尾へ追記
	if code := c.run("approve", np.ID, "--config", c.cfg, "--note", "外注: 調査用", "--expires", "2026-12-31", "--by", "tester"); code != 0 {
		t.Fatalf("approve exit %d: %s", code, c.stderr)
	}
	uar := items["unknown_assume_role|arn:aws:iam::"+acct+":user/mallory->arn:aws:iam::"+acct+":role/Admin"]
	if !strings.Contains(c.stdout.String(), "resolved") || !strings.Contains(c.stdout.String(), "git commit は行っていません") ||
		!strings.Contains(c.stdout.String(), "他の 1 件も resolved") || !strings.Contains(c.stdout.String(), uar.ID+" unknown_assume_role") {
		t.Fatalf("approve stdout (same principal's other finding must be resolved too): %s", c.stdout)
	}
	// 外部アカウントは account: で承認する
	if code := c.run("approve", ext.ID, "--config", c.cfg, "--note", "SaaS の監視連携", "--by", "tester"); code != 0 {
		t.Fatalf("approve exit %d: %s", code, c.stderr)
	}
	extNP := items["new_principal|arn:aws:iam::"+saas+":root"]
	if !strings.Contains(c.stdout.String(), "他の 1 件も resolved") || !strings.Contains(c.stdout.String(), extNP.ID+" new_principal") {
		t.Fatalf("account approve must resolve the account's other findings: %s", c.stdout)
	}
	// 未対応一覧に残るのは root_usage だけ (event 型の unknown_assume_role も消える)
	if left := review(t, c); len(left) != 1 || left["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"].ID == "" {
		t.Fatalf("review after approve: %+v", left)
	}
	al, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))
	compareGolden(t, "allowlist_approved.yaml", al)

	// 主体に関しない finding は approve できない。二重の approve もできない
	if code := c.run("approve", root.ID, "--config", c.cfg, "--note", "x"); code != 2 {
		t.Fatalf("approve root_usage exit %d", code)
	}
	if code := c.run("approve", np.ID, "--config", c.cfg, "--note", "x"); code != 2 {
		t.Fatalf("approve resolved exit %d", code)
	}
	if code := c.run("approve", root.ID, "--config", c.cfg, "--note", "x", "--expected-denied", "s3:*"); code != 2 || !strings.Contains(c.stderr.String(), "only for access_denied") {
		t.Fatalf("--expected-denied on root_usage exit %d: %s", code, c.stderr)
	}
	if code := c.run("approve", "nope", "--config", c.cfg, "--note", "x"); code != 2 {
		t.Fatalf("approve unknown id exit %d", code)
	}
	c.assertCodesInVocabulary()

	// 翌日: 承認済みの主体は鳴らない (mallory の AssumeRole は再び起きても approved)
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(cloudtrailtest.Event("n4", c.now.Add(-1*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}))
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	var rep struct {
		Summary  struct{ New, Recurred, Resolved int }
		Findings struct{ Resolved []struct{ Check, Key string } }
	}
	_ = json.Unmarshal(c.stdout.Bytes(), &rep)
	if rep.Summary.New != 0 || rep.Summary.Recurred != 0 {
		t.Fatalf("approved principals must be quiet: %+v", rep.Summary)
	}
	after := review(t, c)
	if _, ok := after["new_principal|arn:aws:iam::"+acct+":user/mallory"]; ok {
		t.Fatalf("approved new_principal must not be open: %+v", after)
	}
	if _, ok := after["new_principal|arn:aws:iam::"+saas+":root"]; ok {
		t.Fatalf("account-approved external principal must be resolved: %+v", after)
	}
}

func TestAckSnoozeResolve(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	ext := items["new_principal|arn:aws:iam::"+saas+":root"]

	if code := c.run("ack", root.ID, "--config", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "acked") {
		t.Fatalf("ack exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("snooze", np.ID, "--config", c.cfg); code != 2 {
		t.Fatalf("snooze without --until exit %d", code)
	}
	if code := c.run("snooze", np.ID, "--config", c.cfg, "--until", "2026-10-01"); code != 2 {
		t.Fatalf("snooze in the past exit %d", code)
	}
	if code := c.run("snooze", np.ID, "--config", c.cfg, "--until", "2026-11-01"); code != 0 || !strings.Contains(c.stdout.String(), "2026-11-01 (UTC) 以降") {
		t.Fatalf("snooze exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("resolve", ext.ID, "--config", c.cfg); code != 0 {
		t.Fatalf("resolve exit %d: %s", code, c.stderr)
	}
	if code := c.run("resolve", ext.ID, "--config", c.cfg); code != 2 {
		t.Fatalf("resolve twice exit %d", code)
	}
	got := review(t, c)
	if got["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"].Status != "acked" {
		t.Fatalf("acked stays in review: %+v", got)
	}
	if _, ok := got["new_principal|arn:aws:iam::"+acct+":user/mallory"]; ok {
		t.Fatal("snoozed is not in the default review")
	}
	if s := review(t, c, "--status", "snoozed")["new_principal|arn:aws:iam::"+acct+":user/mallory"]; s.SnoozeUntil != "2026-11-01T00:00:00Z" {
		t.Fatalf("snoozed: %+v", s)
	}
	if code := c.run("review", "--config", c.cfg, "--status", "bogus"); code != 2 {
		t.Fatalf("bad status exit %d", code)
	}
	c.assertCodesInVocabulary()
}

func TestApproveCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	c := newCLI(t)
	// 利用者の git 設定 (署名など) に左右されないようにする。arata が呼ぶ git もこの環境を引き継ぐ
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(k, "t")
	}
	for _, k := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, "t@invalid")
	}
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", c.dir}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	// --commit は git の外では書く前に失敗する
	items := seedFindings(t, c)
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	before, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))
	if code := c.run("approve", np.ID, "--config", c.cfg, "--note", "x", "--commit"); code != 2 {
		t.Fatalf("--commit outside git exit %d", code)
	}
	if after, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml")); string(after) != string(before) {
		t.Fatal("allowlist must not change when --commit is impossible")
	}

	git("init", "-q")
	git("add", "allowlist.yaml")
	git("commit", "-q", "-m", "init")
	if err := os.WriteFile(filepath.Join(c.dir, "other.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "other.txt") // stage 済みの無関係な変更は巻き込まない
	if code := c.run("approve", np.ID, "--config", c.cfg, "--note", "外注", "--by", "tester", "--commit"); code != 0 {
		t.Fatalf("approve --commit exit %d: %s", code, c.stderr)
	}
	log := git("log", "--format=%s", "-n", "1")
	if strings.TrimSpace(log) != "allowlist: approve arn:aws:iam::"+acct+":user/mallory" {
		t.Fatalf("log: %s", log)
	}
	if files := git("show", "--name-only", "--format=", "HEAD"); strings.TrimSpace(files) != "allowlist.yaml" {
		t.Fatalf("commit must contain only allowlist.yaml: %s", files)
	}
	if st := git("status", "--porcelain"); !strings.Contains(st, "A  other.txt") {
		t.Fatalf("other staged change must stay staged: %s", st)
	}
}

// TestAllowlistEditResolves は、人が allowlist.yaml を直接編集して承認した主体の finding が、次の evaluate で resolved になることを確かめる。
func TestAllowlistEditResolves(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	if code := c.run("approve", np.ID, "--config", c.cfg); code != 2 {
		t.Fatalf("approve without --note exit %d", code)
	}
	if code := c.run("ack", np.ID, "--config", c.cfg); code != 0 { // acked でも解消の対象
		t.Fatalf("ack exit %d", code)
	}
	p := filepath.Join(c.dir, "allowlist.yaml")
	b, _ := os.ReadFile(p)
	b = append(b, []byte("  - arn_pattern: arn:aws:iam::"+acct+":user/mal*\n    note: 手で追記\n")...)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(time.Hour)
	if code := c.run("evaluate", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("evaluate exit %d: %s", code, c.stderr)
	}
	var rep struct {
		Findings struct {
			Resolved []struct {
				ID, Check string
				Data      map[string]any
			}
		}
	}
	_ = json.Unmarshal(c.stdout.Bytes(), &rep)
	got := map[string]string{}
	for _, f := range rep.Findings.Resolved {
		got[f.Check] = f.ID
		if f.Data["resolved_reason"] != "allowlisted" || f.Data["allowlist_subject"] != "arn:aws:iam::"+acct+":user/mal*" {
			t.Fatalf("resolved data: %+v", f.Data)
		}
	}
	if len(got) != 2 || got["new_principal"] != np.ID || got["unknown_assume_role"] == "" {
		t.Fatalf("resolved: %+v", rep.Findings.Resolved)
	}
	left := review(t, c)
	for k := range left {
		if strings.Contains(k, "mallory") {
			t.Fatalf("mallory must not be in review: %v", left)
		}
	}
	// 次の evaluate では二重に resolved として出ない
	c.now = c.now.Add(time.Hour)
	_ = c.run("evaluate", "--config", c.cfg, "--profile", "daily")
	rep.Findings.Resolved = nil
	_ = json.Unmarshal(c.stdout.Bytes(), &rep)
	if len(rep.Findings.Resolved) != 0 {
		t.Fatalf("resolved twice: %+v", rep.Findings.Resolved)
	}
}

// GitHub Actions の見本 (examples/github-actions/arata-triage.yml) が渡す引数の並び (フラグが先、ID が最後) で動く。
// 見本の側のテストは偽の arata で引数を確かめるだけなので、本物が同じ並びを受け付けることをここで確かめる。
func TestTriageWorkflowArguments(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	ext := items["new_principal|arn:aws:iam::"+saas+":root"]
	if code := c.run("ack", "-c", c.cfg, root.ID); code != 0 || !strings.Contains(c.stdout.String(), "acked") {
		t.Fatalf("ack exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("snooze", "-c", c.cfg, "--until", "2026-11-01", np.ID); code != 0 || !strings.Contains(c.stdout.String(), "snoozed") {
		t.Fatalf("snooze exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("resolve", "-c", c.cfg, ext.ID); code != 0 || !strings.Contains(c.stdout.String(), "resolved") {
		t.Fatalf("resolve exit %d: %s%s", code, c.stdout, c.stderr)
	}
	// 無い ID は CONFIG_INVALID (見本の README の「失敗の見分け」)
	if code := c.run("ack", "-c", c.cfg, "0123456789ab"); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("unknown id: exit %d %v", code, c.codes())
	}
}
