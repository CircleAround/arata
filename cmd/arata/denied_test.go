package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
)

// 想定済みの拒否 (approve --expected-denied) と、ack 中の重大度の上昇の再報告 (ADR 0022)。
func TestExpectedDeniedAndEscalation(t *testing.T) {
	c := newCLI(t)
	const role = "ai-investigation-readonly"
	roleARN := "arn:aws:iam::" + acct + ":role/" + role
	n := 0
	deny := func(apis ...string) {
		for _, api := range apis {
			svc, name, _ := strings.Cut(api, ":")
			n++
			ev := cloudtrailtest.Event(fmt.Sprintf("d%03d", n), c.now.Add(-2*time.Hour), cloudtrailtest.AssumedRole(acct, role, "s1"), svc+".amazonaws.com", name, "ap-northeast-1", "198.51.100.9", true, nil)
			c.fake.Add(cloudtrailtest.WithError(ev, "AccessDenied"))
		}
	}
	type rep struct {
		Summary  struct{ New, Changed int }
		Findings struct {
			New, Changed []struct {
				ID, Check, Severity, Summary string
				Data                         map[string]any
			}
		}
	}
	runDaily := func() rep {
		t.Helper()
		if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
			t.Fatalf("run exit %d: %s", code, c.stderr)
		}
		var r rep
		if err := json.Unmarshal(c.stdout.Bytes(), &r); err != nil {
			t.Fatalf("%v\n%s", err, c.stdout)
		}
		return r
	}
	if code := c.run("init", "--config", c.cfg, "--window", "1d"); code != 0 {
		t.Fatalf("init exit %d: %s", code, c.stderr)
	}

	// 1 日目: 6 種類の拒否 → access_denied (medium)
	c.now = c.now.Add(24 * time.Hour)
	deny("logs:StartQuery", "logs:GetLogEvents", "iam:ListUsers", "s3:ListBuckets", "kms:ListKeys", "ec2:DescribeVpcs")
	runDaily()
	ad := review(t, c)["access_denied|"+roleARN]
	if ad.ID == "" || ad.Severity != "medium" {
		t.Fatalf("access_denied: %+v", review(t, c))
	}

	// access_denied は主体ごとには approve できない (承認は権限を探ってよいではない)
	if code := c.run("approve", ad.ID, "--config", c.cfg, "--note", "x"); code != 2 || !strings.Contains(c.stderr.String(), "--expected-denied") {
		t.Fatalf("plain approve of access_denied exit %d: %s", code, c.stderr)
	}
	// approve --expected-denied: 主体の項目を追記する。access_denied の finding は resolved にしない
	if code := c.run("approve", ad.ID, "--config", c.cfg, "--expected-denied", "logs:StartQuery", "--expected-denied", "logs:Get*", "--note", "個人情報を含むロググループは IAM で Deny している", "--by", "alice"); code != 0 {
		t.Fatalf("approve exit %d: %s", code, c.stderr)
	}
	if out := c.stdout.String(); !strings.Contains(out, "open のまま") || strings.Contains(out, "finding "+ad.ID+" は resolved") {
		t.Fatalf("approve stdout: %s", out)
	}
	al, _ := os.ReadFile(filepath.Join(c.dir, "allowlist.yaml"))
	if !strings.Contains(string(al), "  - arn: "+roleARN+"\n") || !strings.Contains(string(al), `    expected_denied: ["logs:StartQuery", "logs:Get*"]`+"\n") {
		t.Fatalf("allowlist:\n%s", al)
	}
	if got := review(t, c)["access_denied|"+roleARN]; got.Status != "open" {
		t.Fatalf("access_denied must stay open: %+v", got)
	}
	// 既に項目がある主体には追記しない。足す行をエラーに示す
	if code := c.run("approve", ad.ID, "--config", c.cfg, "--expected-denied", "logs:FilterLogEvents", "--note", "x"); code != 2 ||
		!strings.Contains(c.stderr.String(), `expected_denied: [\"logs:FilterLogEvents\"]`) {
		t.Fatalf("approve on a listed principal exit %d: %s", code, c.stderr)
	}
	// 書式の誤りは受け付けない
	if code := c.run("approve", ad.ID, "--config", c.cfg, "--expected-denied", "StartQuery", "--note", "x"); code != 2 || !strings.Contains(c.stderr.String(), "want service:Action") {
		t.Fatalf("bad glob exit %d: %s", code, c.stderr)
	}

	// 2 日目: 同じ 6 種類 → 想定内の 2 種類を除くと 4 種類で閾値未満
	c.now = c.now.Add(24 * time.Hour)
	deny("logs:StartQuery", "logs:GetLogEvents", "iam:ListUsers", "s3:ListBuckets", "kms:ListKeys", "ec2:DescribeVpcs")
	if r := runDaily(); r.Summary.New+r.Summary.Changed != 0 {
		t.Fatalf("expected denials must be excluded: %+v", r)
	}

	// ack した後、同じ重大度 (medium) は再報告しない
	if code := c.run("ack", ad.ID, "--config", c.cfg); code != 0 {
		t.Fatalf("ack exit %d: %s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	deny("iam:ListUsers", "iam:ListRoles", "s3:ListBuckets", "kms:ListKeys", "ec2:DescribeVpcs", "sts:GetSessionToken")
	if r := runDaily(); r.Summary.Changed != 0 || r.Summary.New != 0 {
		t.Fatalf("acked medium must stay suppressed: %+v", r)
	}

	// 20 種類以上 (high) に上がったら changed として再報告し、open に戻す
	c.now = c.now.Add(24 * time.Hour)
	for i := 0; i < 22; i++ {
		deny(fmt.Sprintf("ssm:Describe%02d", i))
	}
	r := runDaily()
	if r.Summary.Changed != 1 || len(r.Findings.Changed) != 1 {
		t.Fatalf("escalation must be reported as changed: %+v", r)
	}
	ch := r.Findings.Changed[0]
	if ch.ID != ad.ID || ch.Severity != "high" || ch.Data["escalated_from_suppressed"] != true || ch.Data["suppressed_status"] != "acked" ||
		ch.Data["suppressed_severity"] != "medium" || !strings.HasPrefix(ch.Summary, "(確認済み (ack) だったが重大度が medium → high に上昇) ") {
		t.Fatalf("changed: %+v", ch)
	}
	if got := review(t, c)["access_denied|"+roleARN]; got.Status != "open" {
		t.Fatalf("escalated finding must be open: %+v", got)
	}
	c.assertCodesInVocabulary()
}
