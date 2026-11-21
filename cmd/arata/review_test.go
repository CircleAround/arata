package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/report/schema"
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
	// 実際の出力が review スキーマ (版 1。最上位は配列) に合い、型に無い項目を持たない (ADR 0054)
	schematest.Conforms(t, engine.ReviewSchema, c.stdout.Bytes(), &[]engine.ReviewItem{})
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
	// approve の --note / --by は片付けの記録にも残る (ADR 0068)
	if code := c.run("review", "-c", c.cfg, "--format", "json", "--status", "resolved"); code != 0 ||
		!strings.Contains(c.stdout.String(), `"action": "approve"`) || !strings.Contains(c.stdout.String(), `"by": "tester"`) || !strings.Contains(c.stdout.String(), `"reason": "外注: 調査用"`) {
		t.Fatalf("approve must be recorded: exit %d\n%s", code, c.stdout)
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

	if code := c.run("ack", root.ID, "--config", c.cfg, "--force", "--reason", "known setup work"); code != 0 || !strings.Contains(c.stdout.String(), "acked") {
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
	if code := c.run("ack", np.ID, "--config", c.cfg, "--force", "--reason", "pending approval"); code != 0 { // acked でも解消の対象
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

// GitHub Actions のワークフロー (arata repo init が書き出す arata-triage.yml。見本は examples/audit-repo) が渡す引数の並び (フラグが先、ID が最後) で動く。
// 見本の側のテストは偽の arata で引数を確かめるだけなので、本物が同じ並びを受け付けることをここで確かめる。
func TestTriageWorkflowArguments(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	ext := items["new_principal|arn:aws:iam::"+saas+":root"]
	if code := c.run("ack", "-c", c.cfg, "--force", "--reason", "known setup work", root.ID); code != 0 || !strings.Contains(c.stdout.String(), "acked") {
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

// ack / snooze / resolve の理由と操作した人はストアに残り、review の json と table に最後の操作として出る (ADR 0068 の 1 節)。
func TestTriageRecordsReasonAndBy(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	ext := items["new_principal|arn:aws:iam::"+saas+":root"]

	if code := c.run("ack", "-c", c.cfg, "--force", "--reason", "setup work by the team", "--by", "alice", root.ID); code != 0 {
		t.Fatalf("ack exit %d: %s%s", code, c.stdout, c.stderr)
	}
	if code := c.run("snooze", "-c", c.cfg, "--until", "2026-11-01", "--by", "bob", np.ID); code != 0 {
		t.Fatalf("snooze exit %d: %s%s", code, c.stdout, c.stderr)
	}
	// --by を省けば OS のユーザー名 (approve と同じ)。ここでは空でないことだけを見る
	if code := c.run("ack", "-c", c.cfg, "--force", "--reason", "known SaaS", ext.ID); code != 0 {
		t.Fatalf("ack exit %d: %s%s", code, c.stdout, c.stderr)
	}
	var items2 []struct {
		ID         string
		LastAction *struct {
			Action, By, Reason, At, Severity string
			Forced                           bool
		} `json:"last_action"`
	}
	if code := c.run("review", "-c", c.cfg, "--format", "json", "--status", "acked,snoozed"); code != 0 {
		t.Fatalf("review exit %d: %s", code, c.stderr)
	}
	schematest.Conforms(t, engine.ReviewSchema, c.stdout.Bytes(), &[]engine.ReviewItem{})
	if err := json.Unmarshal(c.stdout.Bytes(), &items2); err != nil {
		t.Fatal(err)
	}
	got := map[string]struct{ action, by, reason, at, sev string }{}
	for _, it := range items2 {
		if it.LastAction == nil {
			t.Fatalf("%s has no last_action: %s", it.ID, c.stdout)
		}
		got[it.ID] = struct{ action, by, reason, at, sev string }{it.LastAction.Action, it.LastAction.By, it.LastAction.Reason, it.LastAction.At, it.LastAction.Severity}
	}
	if g := got[root.ID]; g.action != "ack" || g.by != "alice" || g.reason != "setup work by the team" || g.sev != root.Severity || g.at == "" {
		t.Fatalf("ack: %+v", g)
	}
	if g := got[np.ID]; g.action != "snooze" || g.by != "bob" || g.reason != "" {
		t.Fatalf("snooze: %+v", g)
	}
	if g := got[ext.ID]; g.action != "ack" || g.by == "" {
		t.Fatalf("default --by: %+v", g)
	}
	if code := c.run("review", "-c", c.cfg, "--status", "acked"); code != 0 || !strings.Contains(c.stdout.String(), "LAST_ACTION") || !strings.Contains(c.stdout.String(), "ack alice ") {
		t.Fatalf("table exit %d:\n%s", code, c.stdout)
	}

	// 形の誤りは CONFIG_INVALID で止め、ストアを変えない
	for _, args := range [][]string{
		{"--by", "alice@example.com"}, // メールアドレスは受け付けない
		{"--by", "Alice Example"},     // 空白 (氏名) も
		{"--reason", "line1\nline2"},  // 1 行だけ
		{"--reason", strings.Repeat("あ", 301)},
		{"--reason", "zero\u200bwidth"}, // 書式の文字 (Cf)
	} {
		if code := c.run(append([]string{"resolve", "-c", c.cfg}, append(args, ext.ID)...)...); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("%q: exit %d %v", args, code, c.codes())
		}
	}
	if s := review(t, c, "--status", "acked")["new_principal|arn:aws:iam::"+saas+":root"]; s.Status != "acked" {
		t.Fatalf("a rejected resolve must not change the finding: %+v", s)
	}
	c.assertCodesInVocabulary()
}

// 重大度が high・critical の finding は ack を受け付けない。案内と playbook の場所を出し、ACK_REFUSED で止める。
// --force は --reason が必須で、記録に forced を残す (ADR 0068 の 2 節)。
func TestAckRefusesHighSeverity(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]                                      // critical。approve できない
	uar := items["unknown_assume_role|arn:aws:iam::"+acct+":user/mallory->arn:aws:iam::"+acct+":role/Admin"] // high。approve できる
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]                                          // medium
	if root.Severity != "critical" || uar.Severity != "high" || np.Severity != "medium" {
		t.Fatalf("scenario: %+v %+v %+v", root, uar, np)
	}

	if code := c.run("ack", "-c", c.cfg, "--reason", "known", root.ID); code != 2 || strings.Join(c.codes(), ",") != "ACK_REFUSED" {
		t.Fatalf("ack critical: exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	out := c.stdout.String()
	for _, want := range []string{"critical", "snooze", "--until", "resolve", "arata help ai playbook root_usage", "片付け", "--force"} {
		if !strings.Contains(out, want) {
			t.Errorf("guidance lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "approve") {
		t.Errorf("root_usage cannot be approved; do not suggest it:\n%s", out)
	}
	if code := c.run("ack", "-c", c.cfg, uar.ID); code != 2 || !strings.Contains(c.stdout.String(), "approve") || !strings.Contains(c.stdout.String(), "arata help ai playbook unknown_assume_role") {
		t.Fatalf("ack high: exit %d\n%s", code, c.stdout)
	}
	// 止めた ack はストアを変えない
	if got := review(t, c); got["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"].Status != "open" || got["unknown_assume_role|arn:aws:iam::"+acct+":user/mallory->arn:aws:iam::"+acct+":role/Admin"].Status != "open" {
		t.Fatalf("refused acks must not change the findings: %+v", got)
	}
	// --force には --reason が要る
	for _, reason := range []string{"", "   "} {
		if code := c.run("ack", "-c", c.cfg, "--force", "--reason", reason, root.ID); code != 2 || strings.Join(c.codes(), ",") != "ACK_REFUSED" {
			t.Fatalf("--force without a reason %q: exit %d %v", reason, code, c.codes())
		}
	}
	if code := c.run("ack", "-c", c.cfg, "--force", "--reason", "setup work, confirmed with the owner", "--by", "alice", root.ID); code != 0 {
		t.Fatalf("ack --force: exit %d %s%s", code, c.stdout, c.stderr)
	}
	// medium でも、同じ Key で重大度の上がる余地の無いもの (new_principal) は止める (ADR 0068 の 6 節。片付けの表)
	if code := c.run("ack", "-c", c.cfg, np.ID); code != 2 || strings.Join(c.codes(), ",") != "ACK_REFUSED" ||
		!strings.Contains(c.stdout.String(), "approve") || !strings.Contains(c.stdout.String(), "arata help ai playbook new_principal") {
		t.Fatalf("ack medium without room to escalate: exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	if code := c.run("ack", "-c", c.cfg, "--force", "--reason", "kept for the migration", np.ID); code != 0 {
		t.Fatalf("ack medium --force: exit %d %s", code, c.stderr)
	}
	// snooze と resolve は止めない
	if code := c.run("snooze", "-c", c.cfg, "--until", "2026-11-01", uar.ID); code != 0 {
		t.Fatalf("snooze high: exit %d %s", code, c.stderr)
	}
	if code := c.run("review", "-c", c.cfg, "--format", "json", "--status", "acked"); code != 0 {
		t.Fatal(c.stderr.String())
	}
	var acked []engine.ReviewItem
	if err := json.Unmarshal(c.stdout.Bytes(), &acked); err != nil {
		t.Fatal(err)
	}
	forced := map[string]bool{}
	for _, it := range acked {
		if it.LastAction == nil {
			t.Fatalf("%s has no record", it.ID)
		}
		forced[it.ID] = it.LastAction.Forced
	}
	if len(forced) != 2 || !forced[root.ID] || !forced[np.ID] {
		t.Fatalf("forced must be recorded for the acks that passed the guard: %v", forced)
	}
	if code := c.run("review", "-c", c.cfg, "--status", "acked"); code != 0 || !strings.Contains(c.stdout.String(), "ack alice ") || !strings.Contains(c.stdout.String(), "(force)") {
		t.Fatalf("table:\n%s", c.stdout)
	}
	c.assertCodesInVocabulary()
}

// review --format json の各 finding に、許す操作と根拠の文書が載る (ADR 0068 の 4 節)。表は checks の片付けの表 (正は playbook)。
func TestReviewTriage(t *testing.T) {
	c := newCLI(t)
	seedFindings(t, c)
	if code := c.run("review", "-c", c.cfg, "--format", "json"); code != 0 {
		t.Fatal(c.stderr.String())
	}
	schematest.Conforms(t, engine.ReviewSchema, c.stdout.Bytes(), &[]engine.ReviewItem{})
	var items []engine.ReviewItem
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"root_usage|arn:aws:iam::" + acct + ":root|198.51.100.8":                                           "snooze,resolve",
		"unknown_assume_role|arn:aws:iam::" + acct + ":user/mallory->arn:aws:iam::" + acct + ":role/Admin": "approve,snooze,resolve",
		"new_principal|arn:aws:iam::" + acct + ":user/mallory":                                             "approve,snooze,resolve",
	}
	for _, it := range items {
		w, ok := want[it.Check+"|"+it.Key]
		if !ok {
			continue
		}
		delete(want, it.Check+"|"+it.Key)
		if got := strings.Join(it.Triage.Allowed, ","); got != w || it.Triage.Escalates || it.Triage.Doc != "arata help ai playbook "+it.Check || it.Triage.Section != "片付け" {
			t.Errorf("%s: %+v (want %s)", it.Check, it.Triage, w)
		}
	}
	if len(want) != 0 {
		t.Fatalf("not in review: %v", want)
	}
}

// ack / snooze / resolve の --dry-run は、本番と同じ検査 (形・finding の有無・片付けの表) を行い、何をどう変えるかを出して、ストアを書かない (ADR 0068 の 8 節)。
func TestTriageDryRun(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]

	if code := c.run("resolve", "-c", c.cfg, "--dry-run", "--reason", "checked", root.ID); code != 0 {
		t.Fatalf("resolve --dry-run: exit %d %s%s", code, c.stdout, c.stderr)
	}
	for _, w := range []string{"試し", root.ID, "root_usage", "critical", "open", "resolved", "ストアは変えていません"} {
		if !strings.Contains(c.stdout.String(), w) {
			t.Errorf("dry-run output lacks %q:\n%s", w, c.stdout)
		}
	}
	if code := c.run("snooze", "-c", c.cfg, "--dry-run", "--until", "2026-11-01", np.ID); code != 0 || !strings.Contains(c.stdout.String(), "2026-11-01") {
		t.Fatalf("snooze --dry-run: exit %d %s", code, c.stdout)
	}
	// 守りも本番と同じに効く
	if code := c.run("ack", "-c", c.cfg, "--dry-run", np.ID); code != 2 || strings.Join(c.codes(), ",") != "ACK_REFUSED" {
		t.Fatalf("ack --dry-run must be refused like the real one: exit %d %v", code, c.codes())
	}
	if code := c.run("ack", "-c", c.cfg, "--dry-run", "--force", "--reason", "kept", np.ID); code != 0 || !strings.Contains(c.stdout.String(), "force") {
		t.Fatalf("ack --dry-run --force: exit %d %s", code, c.stdout)
	}
	if code := c.run("snooze", "-c", c.cfg, "--dry-run", "--until", "2026-10-01", np.ID); code != 2 {
		t.Fatalf("snooze --dry-run in the past: exit %d", code)
	}
	// 何も変わっていない (状態も、片付けの記録も)
	got := review(t, c)
	if got["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"].Status != "open" || got["new_principal|arn:aws:iam::"+acct+":user/mallory"].Status != "open" {
		t.Fatalf("dry-run must not change the store: %+v", got)
	}
	if code := c.run("review", "-c", c.cfg, "--format", "json"); code != 0 || strings.Contains(c.stdout.String(), `"last_action"`) {
		t.Fatalf("dry-run must not record an action:\n%s", c.stdout)
	}
	c.assertCodesInVocabulary()
}

// report.json の各 finding にも、review と同じ triage (許す操作と根拠の文書) を載せる。Slack や report から片付けの案を作る人が、
// review を引かずに表に無い操作を避けられるように。
func TestReportCarriesTriage(t *testing.T) {
	c := newCLI(t)
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		cloudtrailtest.Event("n1", c.now.Add(-2*time.Hour), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}),
		cloudtrailtest.Event("n2", c.now.Add(-1*time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil),
	)
	out := t.TempDir()
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--out", out); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	b, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	schematest.Conforms(t, schema.ReportSchema, b, &schema.Report{})
	var rep schema.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if code := c.run("review", "-c", c.cfg, "--format", "json"); code != 0 {
		t.Fatal(c.stderr.String())
	}
	var items []engine.ReviewItem
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	byID := map[string]engine.TriageInfo{}
	for _, it := range items {
		byID[it.ID] = it.Triage
	}
	if len(rep.Findings.New) == 0 {
		t.Fatalf("want new findings: %s", b)
	}
	for _, f := range rep.Findings.New {
		if f.Triage == nil {
			t.Fatalf("%s: report.json must carry triage", f.Check)
		}
		if want, ok := byID[f.ID]; !ok || !reflect.DeepEqual(*f.Triage, want) {
			t.Errorf("%s: report %+v, review %+v", f.Check, *f.Triage, want)
		}
	}
}

// ack / snooze / resolve は複数の finding ID を取る (ADR 0080)。同じ status・reason・until・force・by を全部に当て、ストアへの確定は 1 回。
// 検査 (形・finding の有無・片付けの表・期日) は書く前に全部済ませ、1 件でも通らなければ何も書かずに止め、止めた ID と理由を全部出す。
func TestTriageManyIDs(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]                                      // critical。ack は止まる
	uar := items["unknown_assume_role|arn:aws:iam::"+acct+":user/mallory->arn:aws:iam::"+acct+":role/Admin"] // high。ack は止まる
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]                                          // medium。ack は止まる
	ext := items["new_principal|arn:aws:iam::"+saas+":root"]
	missing := "0000000000ff"
	statuses := func() map[string]string {
		out := map[string]string{}
		for _, it := range review(t, c, "--status", "open,acked,snoozed,resolved") {
			out[it.ID] = it.Status
		}
		return out
	}
	unchanged := func(what string) {
		t.Helper()
		for id, s := range statuses() {
			if s != "open" {
				t.Fatalf("%s must not write anything: %s is %s", what, id, s)
			}
		}
		if code := c.run("review", "-c", c.cfg, "--format", "json"); code != 0 || strings.Contains(c.stdout.String(), `"last_action"`) {
			t.Fatalf("%s must not record an action:\n%s", what, c.stdout)
		}
	}

	// 形・重複・件数は、ストアを開く前に止める。通らない値を全部挙げる
	for _, tc := range []struct {
		args, want []string
	}{
		{[]string{np.ID, root.ID + "," + np.ID}, []string{np.ID + `\" appears twice`}},
		{[]string{np.ID, "0123456789AB", "--", "zz"}, []string{`\"0123456789AB\"`, `\"zz\"`}},
	} {
		if code := c.run(append([]string{"resolve", "-c", c.cfg, "--reason", "x"}, tc.args...)...); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
			t.Fatalf("%v: exit %d %v", tc.args, code, c.codes())
		}
		for _, w := range tc.want {
			if !strings.Contains(c.stderr.String(), w) {
				t.Errorf("every bad value must be named (%q):\n%s", w, c.stderr)
			}
		}
	}
	unchanged("a bad list")

	// 1 件が見つからない・1 件が既に resolved → 何も書かない。止めた ID を全部出す
	if code := c.run("snooze", "-c", c.cfg, "--until", "2026-11-01", np.ID, missing, root.ID); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("snooze with a missing id: exit %d %v\n%s", code, c.codes(), c.stdout)
	}
	for _, w := range []string{missing, "見つかりません", "何も変えていません", "1 件"} {
		if !strings.Contains(c.stdout.String(), w) {
			t.Errorf("stdout lacks %q:\n%s", w, c.stdout)
		}
	}
	unchanged("a list with a missing id")

	// ack の守りは ID ごとに効き、止めた ID を全部出す (ACK_REFUSED を ID ごとに 1 行)
	if code := c.run("ack", "-c", c.cfg, "--reason", "known", np.ID, uar.ID, root.ID, missing); code != 2 {
		t.Fatalf("ack of guarded findings: exit %d", code)
	}
	if got := strings.Join(c.codes(), ","); got != "ACK_REFUSED,ACK_REFUSED,ACK_REFUSED,CONFIG_INVALID" {
		t.Fatalf("one code per stopped id: %s", got)
	}
	for _, w := range []string{np.ID, uar.ID, root.ID, missing, "4 件", "snooze", "resolve", "approve", "arata help ai playbook <check>", "--force"} {
		if !strings.Contains(c.stdout.String(), w) {
			t.Errorf("ack guidance lacks %q:\n%s", w, c.stdout)
		}
	}
	unchanged("refused acks")

	// 試しも複数を取り、ID ごとに何がどう変わるかを出す
	if code := c.run("ack", "-c", c.cfg, "--dry-run", "--force", "--reason", "kept", np.ID, root.ID); code != 0 {
		t.Fatalf("ack --dry-run: exit %d %s%s", code, c.stdout, c.stderr)
	}
	for _, w := range []string{"試し", np.ID, "new_principal", root.ID, "root_usage", "open から acked", "force", "2 件", "ストアは変えていません"} {
		if !strings.Contains(c.stdout.String(), w) {
			t.Errorf("dry-run lacks %q:\n%s", w, c.stdout)
		}
	}
	unchanged("a dry run")

	// 通れば、全部を同じ記録で 1 回に書く
	if code := c.run("ack", "-c", c.cfg, "--force", "--reason", "setup work", "--by", "alice", np.ID+","+root.ID); code != 0 {
		t.Fatalf("ack --force: exit %d %s%s", code, c.stdout, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "2 件を acked にしました") {
		t.Errorf("stdout:\n%s", c.stdout)
	}
	if code := c.run("resolve", "-c", c.cfg, "--reason", "fixed", uar.ID, ext.ID); code != 0 {
		t.Fatalf("resolve: exit %d %s%s", code, c.stdout, c.stderr)
	}
	got := statuses()
	if got[np.ID] != "acked" || got[root.ID] != "acked" || got[uar.ID] != "resolved" || got[ext.ID] != "resolved" {
		t.Fatalf("statuses: %v", got)
	}
	if code := c.run("review", "-c", c.cfg, "--format", "json", "--status", "acked"); code != 0 {
		t.Fatal(c.stderr.String())
	}
	var acked []engine.ReviewItem
	if err := json.Unmarshal(c.stdout.Bytes(), &acked); err != nil {
		t.Fatal(err)
	}
	for _, it := range acked {
		if a := it.LastAction; a == nil || a.By != "alice" || a.Reason != "setup work" || !a.Forced {
			t.Fatalf("%s: the same record for every id: %+v", it.ID, a)
		}
	}
	c.assertCodesInVocabulary()
}

// --format json は ID ごとの結果を出す (ワークフローの Summary が読む。ADR 0054・0080)。止めたときも、止めた ID と code を出す。
func TestTriageManyIDsJSON(t *testing.T) {
	c := newCLI(t)
	items := seedFindings(t, c)
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	ext := items["new_principal|arn:aws:iam::"+saas+":root"]
	missing := "0000000000ff"
	read := func() engine.TriageResult {
		t.Helper()
		schematest.Conforms(t, engine.TriageResultSchema, c.stdout.Bytes(), &engine.TriageResult{})
		var r engine.TriageResult
		if err := json.Unmarshal(c.stdout.Bytes(), &r); err != nil {
			t.Fatalf("%v\n%s", err, c.stdout)
		}
		return r
	}
	type row struct{ result, before, after, code string }
	rows := func(r engine.TriageResult) map[string]row {
		out := map[string]row{}
		for _, it := range r.Items {
			out[it.ID] = row{it.Result, it.Before, it.After, it.Code}
		}
		return out
	}

	if code := c.run("ack", "-c", c.cfg, "--format", "json", "--reason", "known", np.ID, root.ID, missing); code != 2 {
		t.Fatalf("exit %d", code)
	}
	r := read()
	if r.Action != "ack" || r.Written || r.DryRun || len(r.Items) != 3 {
		t.Fatalf("refused: %+v", r)
	}
	want := map[string]row{np.ID: {"refused", "open", "", "ACK_REFUSED"}, root.ID: {"refused", "open", "", "ACK_REFUSED"}, missing: {"refused", "", "", "CONFIG_INVALID"}}
	if got := rows(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("items: %+v", got)
	}

	// 通らない 1 件があれば、通った ID は not_written
	if code := c.run("resolve", "-c", c.cfg, "--format", "json", "--reason", "x", ext.ID, missing); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if got := rows(read()); got[ext.ID] != (row{"not_written", "open", "resolved", ""}) || got[missing].result != "refused" {
		t.Fatalf("items: %+v", got)
	}

	if code := c.run("snooze", "-c", c.cfg, "--format", "json", "--dry-run", "--until", "2026-11-01", ext.ID, np.ID); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	r = read()
	if r.Written || !r.DryRun || r.SnoozeUntil != "2026-11-01" {
		t.Fatalf("dry run: %+v", r)
	}
	if got := rows(r); got[ext.ID] != (row{"would_change", "open", "snoozed", ""}) || got[np.ID] != (row{"would_change", "open", "snoozed", ""}) {
		t.Fatalf("items: %+v", got)
	}

	if code := c.run("resolve", "-c", c.cfg, "--format", "json", "--reason", "fixed", ext.ID, np.ID); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	r = read()
	if !r.Written || r.Action != "resolve" {
		t.Fatalf("written: %+v", r)
	}
	if got := rows(r); got[ext.ID] != (row{"changed", "open", "resolved", ""}) || got[np.ID] != (row{"changed", "open", "resolved", ""}) {
		t.Fatalf("items: %+v", got)
	}
	if code := c.run("resolve", "-c", c.cfg, "--format", "yaml", ext.ID); code != 2 {
		t.Fatalf("unknown format: exit %d", code)
	}
	c.assertCodesInVocabulary()
}
