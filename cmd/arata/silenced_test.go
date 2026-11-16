package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/internal/report/schema"
)

// silenced: true のプロファイル (雛形では weekly) の報告にだけ「黙らせているもの」が出る (ADR 0068 の 3 節・9 節)。
func TestWeeklySilencedSection(t *testing.T) {
	c := newCLI(t)
	b, _ := os.ReadFile(c.cfg)
	cfg := strings.Replace(string(b), "  weekly:\n    window: 7d\n", "  weekly:\n    window: 7d\n    silenced: true\n", 1)
	if cfg == string(b) {
		t.Fatal("scenario: no weekly profile")
	}
	if err := os.WriteFile(c.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	items := seedFindings(t, c) // c.now は 2026-10-22 09:00 UTC
	root := items["root_usage|arn:aws:iam::"+acct+":root|198.51.100.8"]
	uar := items["unknown_assume_role|arn:aws:iam::"+acct+":user/mallory->arn:aws:iam::"+acct+":role/Admin"]
	ext := items["unknown_assume_role|arn:aws:iam::"+saas+":root->arn:aws:iam::"+acct+":role/ExampleSaaSRole"]
	np := items["new_principal|arn:aws:iam::"+acct+":user/mallory"]
	extNP := items["new_principal|arn:aws:iam::"+saas+":root"]
	for _, args := range [][]string{
		{"ack", "--force", "--reason", "setup work", "--by", "alice", root.ID},
		{"ack", "--reason", "asked mallory@example.com directly", "--by", "bob", np.ID},
		{"snooze", "--until", "2026-10-25", "--by", "alice", uar.ID},   // 7 日以内に期日
		{"snooze", "--until", "2026-11-20", "--by", "alice", ext.ID},   // 期日は遠い
		{"snooze", "--until", "2026-10-23", "--by", "alice", extNP.ID}, // 期日を過ぎる (下で時計を進める)
	} {
		if code := c.run(append([]string{args[0], "-c", c.cfg}, args[1:]...)...); code != 0 {
			t.Fatalf("%v: exit %d %s%s", args, code, c.stdout, c.stderr)
		}
	}
	al := filepath.Join(c.dir, "allowlist.yaml")
	ab, _ := os.ReadFile(al)
	ab = append(ab, []byte(`  - arn: arn:aws:iam::`+acct+`:user/contractor
    note: 委託
    expires: 2026-11-10
  - arn: arn:aws:iam::`+acct+`:user/former
    note: 終わった委託
    expires: 2026-10-20
  - arn: arn:aws:iam::`+acct+`:user/longterm
    note: 長期の委託
    expires: 2027-06-30
`)...)
	if err := os.WriteFile(al, ab, 0o600); err != nil {
		t.Fatal(err)
	}

	// daily には節が無い
	if code := c.run("run", "-c", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("daily: exit %d %s", code, c.stderr)
	}
	if strings.Contains(c.stdout.String(), `"silenced"`) {
		t.Fatal("daily must not have the silenced section")
	}

	c.now = c.now.AddDate(0, 0, 2) // 2026-10-24: extNP の期日を過ぎ、uar の期日は 1 日後
	if code := c.run("run", "-c", c.cfg, "--profile", "weekly"); code != 0 && code != 3 {
		t.Fatalf("weekly: exit %d %s", code, c.stderr)
	}
	schematest.Conforms(t, schema.ReportSchema, c.stdout.Bytes(), &schema.Report{})
	var rep schema.Report
	if err := json.Unmarshal(c.stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	s := rep.Silenced
	if s == nil {
		t.Fatalf("weekly must have the silenced section:\n%s", c.stdout)
	}
	want := schema.SilencedSummary{Acked: 2, AckedHigh: 1, Forced: 1, Snoozed: 3, SnoozedHigh: 2, SnoozeExpiring: 1, SnoozeExpired: 1, AllowlistExpiring: 1, AllowlistExpired: 1}
	if s.Summary != want {
		t.Fatalf("summary: %+v\nwant %+v", s.Summary, want)
	}
	// high 以上が先頭 (critical の root → high の 2 件 → medium)
	var order []string
	for _, f := range s.Findings {
		order = append(order, f.Severity)
	}
	if strings.Join(order, ",") != "critical,high,high,medium,medium" || s.Findings[0].ID != root.ID {
		t.Fatalf("order: %v", order)
	}
	a := s.Findings[0].LastAction
	if a == nil || a.Action != "ack" || a.By != "alice" || a.Reason != "setup work" || !a.Forced || s.Findings[0].SuppressedSeverity != "critical" {
		t.Fatalf("root: %+v %+v", s.Findings[0], a)
	}
	if len(s.SnoozeExpiring) != 1 || s.SnoozeExpiring[0].ID != uar.ID || len(s.SnoozeExpired) != 1 || s.SnoozeExpired[0].ID != extNP.ID {
		t.Fatalf("snooze: expiring %+v expired %+v", s.SnoozeExpiring, s.SnoozeExpired)
	}
	if len(s.AllowlistExpiring) != 2 || !s.AllowlistExpiring[0].Expired || s.AllowlistExpiring[0].Expires != "2026-10-20" ||
		s.AllowlistExpiring[1].Expired || s.AllowlistExpiring[1].Section != "principals" || !strings.Contains(s.AllowlistExpiring[1].Subject, "contractor") {
		t.Fatalf("allowlist: %+v", s.AllowlistExpiring)
	}

	// 個人を特定できる値 (理由に書かれたメールアドレス) は伏せる (ADR 0037)
	if strings.Contains(c.stdout.String(), "mallory@example.com") {
		t.Fatalf("an e-mail address in the reason must be masked:\n%s", c.stdout)
	}
	// report.md にも同じ節。理由はコードの中に入れる
	if code := c.run("report", "-c", c.cfg, "--profile", "weekly", "--format", "md"); code != 0 {
		t.Fatalf("report md: exit %d %s", code, c.stderr)
	}
	md := c.stdout.String()
	for _, w := range []string{"## 黙らせているもの", "high 以上を ack しています", "`setup work`", "(force)", "期日を過ぎても snooze のままのもの", "**切れた** 2026-10-20"} {
		if !strings.Contains(md, w) {
			t.Errorf("report.md lacks %q:\n%s", w, md)
		}
	}
	if strings.Contains(md, "mallory@example.com") {
		t.Errorf("report.md must mask the e-mail address:\n%s", md)
	}
}
