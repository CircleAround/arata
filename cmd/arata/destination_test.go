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
	knownDest   = "111122223333" // 既知リストの assume_destinations に書く行き先
	unknownDest = "444455556666"
)

type destItem struct {
	ID, Check, Key, Severity, Status, Summary string
	Data                                      map[string]any
	ApproveDestination                        string `json:"approve_destination"`
}

func destReview(t *testing.T, c *cli, args ...string) map[string]destItem {
	t.Helper()
	if code := c.run(append([]string{"review", "--config", c.cfg, "--format", "json"}, args...)...); code != 0 {
		t.Fatalf("review exit %d: %s", code, c.stderr)
	}
	var items []destItem
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil {
		t.Fatalf("%v\n%s", err, c.stdout)
	}
	out := map[string]destItem{}
	for _, it := range items {
		if it.Check == "unknown_assume_role" {
			out[it.Key] = it
		}
	}
	return out
}

// switchRole は、自アカウントの IAM ユーザーが外部アカウントのロールを引き受けた記録 (呼び出し側の CloudTrail の形)。
// mfa なら呼び出しに MFA デバイス (requestParameters.serialNumber) がある。
func switchRole(id string, at time.Time, user, destAcct, role string, mfa bool) types.Event {
	req := map[string]any{"roleArn": "arn:aws:iam::" + destAcct + ":role/" + role}
	if mfa {
		req["serialNumber"] = "arn:aws:iam::" + acct + ":mfa/" + user
	}
	return cloudtrailtest.Event(id, at, cloudtrailtest.User(acct, user), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, req)
}

func appendAllowlist(t *testing.T, c *cli, text string) {
	t.Helper()
	p := filepath.Join(c.dir, "allowlist.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, text...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func uarKey(user, destAcct, role string) string {
	return "arn:aws:iam::" + acct + ":user/" + user + "->arn:aws:iam::" + destAcct + ":role/" + role
}

// 3 通り (ADR 0047): 既知の行き先 + MFA あり → 出ない (info の 1 行に残る) / 知らない行き先 → high / 既知の行き先 + MFA 不明 → high。
func TestKnownAssumeDestination(t *testing.T) {
	c := newCLI(t)
	appendAllowlist(t, c, "assume_destinations:\n  - account: \""+knownDest+"\"\n    note: 運用を受託しているアカウント\n    approved_by: alice\n    approved_at: 2026-10-21\n")
	if code := c.run("config", "check", "--config", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "assume_destinations 1") {
		t.Fatalf("config check exit %d:\n%s", code, c.stdout)
	}
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		switchRole("d1", c.now.Add(-3*time.Hour), "alice", knownDest, "ops", true),
		switchRole("d2", c.now.Add(-2*time.Hour), "alice", knownDest, "ops", true),
		switchRole("d3", c.now.Add(-2*time.Hour), "alice", unknownDest, "ops", true),
		switchRole("d4", c.now.Add(-1*time.Hour), "bob", knownDest, "ops", false),
	)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	report := c.stdout.String()
	items := destReview(t, c)
	if it, ok := items[uarKey("alice", knownDest, "ops")]; ok {
		t.Fatalf("既知の行き先 + MFA ありを報告した: %+v", it)
	}
	unk := items[uarKey("alice", unknownDest, "ops")]
	if unk.Severity != "high" || !strings.HasSuffix(unk.Summary, "外部アカウント "+unknownDest+" のロール ops を 1 回引き受け (外向き、MFA あり)") {
		t.Fatalf("知らない行き先は high: %+v", unk)
	}
	noMFA := items[uarKey("bob", knownDest, "ops")]
	if noMFA.Severity != "high" || !strings.HasSuffix(noMFA.Summary, "(外向き、MFA 不明。行き先は既知だが、MFA ありと確かめられないので報告)") || noMFA.Data["destination_status"] != "approved" {
		t.Fatalf("既知の行き先でも MFA 不明は high: %+v", noMFA)
	}
	info := items["known-destination:"+knownDest]
	if info.Severity != "info" || info.Summary != "既知の行き先 (外部アカウント "+knownDest+") への MFA ありの引き受け 2 回は報告していない (呼び出し元 1、ロール 1)" {
		t.Fatalf("報告しなかった分は info に残す: %+v", info)
	}
	if !strings.Contains(report, info.Summary) {
		t.Fatalf("レポートに info の行が無い:\n%s", report)
	}
	if len(items) != 3 {
		t.Fatalf("unknown_assume_role: %+v", items)
	}
	// review は、--destination で行き先を既知にできる finding (外向き・MFA あり) にだけ行き先を示す
	if unk.ApproveDestination != unknownDest || noMFA.ApproveDestination != "" || info.ApproveDestination != "" {
		t.Fatalf("approve_destination: unk=%q noMFA=%q info=%q", unk.ApproveDestination, noMFA.ApproveDestination, info.ApproveDestination)
	}

	// approve --destination: MFA ありと確かめられない finding は、行き先を足しても報告が続くので断る (何も書かない)
	before, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))
	if code := c.run("approve", noMFA.ID, "--config", c.cfg, "--destination", "--note", "x"); code != 2 || !strings.Contains(c.stderr.String(), "MFA") {
		t.Fatalf("--destination on a finding without MFA exit %d: %s", code, c.stderr)
	}
	// info の行は主体でも行き先でも approve できない
	for _, args := range [][]string{{"--destination"}, {}} {
		if code := c.run(append([]string{"approve", info.ID, "--config", c.cfg, "--note", "x"}, args...)...); code != 2 {
			t.Fatalf("approve the info line %v exit %d", args, code)
		}
	}
	// ほかの指定と一緒には使えない
	for _, args := range [][]string{{"--account"}, {"--arn-pattern", "arn:aws:iam::" + acct + ":user/*"}, {"--tag", "deploy"}, {"--expected-denied", "sts:AssumeRole"}} {
		if code := c.run(append([]string{"approve", unk.ID, "--config", c.cfg, "--destination", "--note", "x"}, args...)...); code != 2 {
			t.Fatalf("--destination with %v exit %d", args, code)
		}
	}
	// ロールに絞るなら、finding のロール (ops) に一致するものを求める。ARN は書けない
	for _, g := range []string{"admin-*", "arn:aws:iam::" + unknownDest + ":role/ops"} {
		if code := c.run("approve", unk.ID, "--config", c.cfg, "--destination-role", g, "--note", "x"); code != 2 {
			t.Fatalf("--destination-role %s exit %d", g, code)
		}
	}
	if after, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml")); string(after) != string(before) {
		t.Fatalf("断ったのに既知リストが変わった:\n%s", after)
	}
	// 知らない行き先を既知にする: assume_destinations の末尾に足し、finding は resolved。主体 (alice) は承認されない
	if code := c.run("approve", unk.ID, "--config", c.cfg, "--destination", "--note", "保守を受託 (契約 B)", "--expires", "2027-03-31", "--by", "alice"); code != 0 {
		t.Fatalf("approve --destination exit %d: %s", code, c.stderr)
	}
	if out := c.stdout.String(); !strings.Contains(out, "assume_destination:"+unknownDest) || !strings.Contains(out, "resolved") {
		t.Fatalf("approve stdout: %s", out)
	}
	al, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))
	compareGolden(t, "allowlist_destination.yaml", al)
	left := destReview(t, c)
	if _, ok := left[uarKey("alice", unknownDest, "ops")]; ok || left[uarKey("bob", knownDest, "ops")].ID == "" {
		t.Fatalf("review after approve --destination: %+v", left)
	}
	// 二重には足せない
	if code := c.run("approve", noMFA.ID, "--config", c.cfg, "--note", "x", "--destination"); code != 2 {
		t.Fatalf("exit %d", code)
	}

	// 翌日: 足した行き先への MFA ありの引き受けは出ない。MFA の無い引き受けは出る。alice は承認されていないので、内部の引き受けは出る
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		switchRole("d5", c.now.Add(-2*time.Hour), "alice", unknownDest, "ops", true),
		switchRole("d6", c.now.Add(-2*time.Hour), "alice", unknownDest, "admin", false),
		switchRole("d7", c.now.Add(-1*time.Hour), "alice", acct, "Admin", true),
	)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	next := destReview(t, c)
	if _, ok := next[uarKey("alice", unknownDest, "ops")]; ok {
		t.Fatalf("既知にした行き先を報告した: %+v", next)
	}
	if next[uarKey("alice", unknownDest, "admin")].Severity != "high" || next[uarKey("alice", acct, "Admin")].Severity != "high" || next["known-destination:"+unknownDest].Severity != "info" {
		t.Fatalf("翌日: %+v", next)
	}
	c.assertCodesInVocabulary()
}

// 既に ack 済みの finding: 人が既知リストに行き先を足すと、次の run で (外向き・MFA ありのものだけ) 解消する。
// 行き先を外す (期限が切れる) と、次の引き受けは新規として報告される。
func TestKnownAssumeDestinationResolvesAckedFindings(t *testing.T) {
	c := newCLI(t)
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(
		switchRole("a1", c.now.Add(-3*time.Hour), "alice", knownDest, "ops", true),
		switchRole("a2", c.now.Add(-2*time.Hour), "bob", knownDest, "ops", false),
	)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	items := destReview(t, c)
	withMFA, noMFA := items[uarKey("alice", knownDest, "ops")], items[uarKey("bob", knownDest, "ops")]
	if withMFA.Severity != "high" || noMFA.Severity != "high" || len(items) != 2 {
		t.Fatalf("行き先が既知リストに無ければ今までどおり: %+v", items)
	}
	for _, id := range []string{withMFA.ID, noMFA.ID} {
		if code := c.run("ack", id, "--config", c.cfg); code != 0 {
			t.Fatalf("ack exit %d: %s", code, c.stderr)
		}
	}
	// 人が既知リストを直す (PR の運用)。期限は 2 日後まで
	appendAllowlist(t, c, "assume_destinations:\n  - account: \""+knownDest+"\"\n    note: 運用を受託しているアカウント\n    expires: 2026-10-24\n")
	c.now = c.now.Add(24 * time.Hour)
	c.fake.Add(switchRole("a2b", c.now.Add(-time.Hour), "alice", knownDest, "ops", true))
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
	if len(rep.Findings.Resolved) != 1 || rep.Findings.Resolved[0].Key != withMFA.Key || rep.Findings.Resolved[0].Data["resolved_reason"] != "known_destination" ||
		rep.Findings.Resolved[0].Data["allowlist_subject"] != "assume_destination:"+knownDest {
		t.Fatalf("resolved: %+v", rep.Findings.Resolved)
	}
	left := destReview(t, c)
	if _, ok := left[withMFA.Key]; ok || left[noMFA.Key].Status != "acked" || left["known-destination:"+knownDest].Severity != "info" || len(left) != 2 {
		t.Fatalf("MFA ありの ack 済みだけが解消し、以後の引き受けは info の行に残る: %+v", left)
	}
	// 期限が切れた後の引き受けは、新規の high として報告される (行き先の承認は期限切れ)
	c.now = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	c.fake.Add(switchRole("a3", c.now.Add(-time.Hour), "alice", knownDest, "ops", true))
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run exit %d: %s", code, c.stderr)
	}
	again := destReview(t, c)[withMFA.Key]
	if again.Status != "open" || again.Severity != "high" || !strings.HasSuffix(again.Summary, "(外向き、MFA あり。行き先の承認は期限切れ)") {
		t.Fatalf("期限切れの後: %+v", again)
	}
	// 行き先が期限切れになったら、「報告していない」という info の行は解消する (未対応一覧に残さない)
	if all := destReview(t, c, "--status", "open,acked,resolved"); all["known-destination:"+knownDest].Status != "resolved" || all["known-destination:"+knownDest].Data["resolved_reason"] != "destination_removed" {
		t.Fatalf("info の行: %+v", all["known-destination:"+knownDest])
	}
	if code := c.run("config", "check", "--config", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), "warn") || !strings.Contains(c.stdout.String(), "expired on 2026-10-24") {
		t.Fatalf("config check は期限切れを warn で知らせる (exit %d):\n%s", code, c.stdout)
	}
}

// doctor は、assume_destinations に監査対象のアカウントそのものを書いた誤りを ng にする (オフラインの config check では分からない)。
func TestDoctorAssumeDestinationOwnAccount(t *testing.T) {
	c := newCLI(t)
	row := func() string {
		for _, l := range strings.Split(c.stdout.String(), "\n") {
			if strings.Contains(l, "assume_destinations") {
				return l
			}
		}
		return ""
	}
	// 行き先が無ければ行を出さない (sts にも聞かない)
	if code := c.run("doctor", "-c", c.cfg); code != 0 || row() != "" {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	c.writeAllowlist("assume_destinations:\n  - account: \"" + knownDest + "\"\n    note: 運用を受託しているアカウント\n")
	if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(row(), "ok") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	// フェイクの sts:GetCallerIdentity は 123456789012 (監査対象) を返す
	c.writeAllowlist("assume_destinations:\n  - account: \"" + knownDest + "\"\n    note: 運用を受託しているアカウント\n  - account: \"" + acct + "\"\n    note: 自アカウント\n")
	if code := c.run("doctor", "-c", c.cfg); code != 2 || !strings.Contains(row(), "ng") || !strings.Contains(row(), "CONFIG_INVALID") || !strings.Contains(row(), acct) {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	c.assertCodesInVocabulary()
}
