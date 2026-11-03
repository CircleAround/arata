package engine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/store"
	"github.com/CircleAround/arata/internal/store/storetest"
)

// 2 つ目の cloudtrail のソースは同じフェイクを引く (同じイベント・同じ主体 × IP が 2 つのソースに見える)。
const rebuildSources = `  - id: trail2
    kind: cloudtrail-lookup
` + nginxSource + weeklySources

// run を重ねたストアと、その raw から rebuild したストアで、表の中身が一致する (ADR 0033)。
// init (baseline)・再走査・同じ日の集計の引き直し・スナップショットの 0 件の置き換え・人の判断を通す。
func TestRebuildMatchesRuns(t *testing.T) {
	h := newHarnessWith(t, rebuildSources, weeklyProfiles)
	ctx := context.Background()
	healthyAccount(h.acct, h.now)
	h.acct.GDFindings = append(h.acct.GDFindings, accounttest.GDFinding("g1", "Recon:EC2/Portscan", 5, 1))
	h.acct.AAFindings = append(h.acct.AAFindings, accounttest.AAFinding("a1", "arn:aws:s3:::public", true, "s3:GetObject"))
	h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 950))
	h.logs.On("as sign_in_failures", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "sign_in_failures", "30")}})
	alice := cloudtrailtest.User(acct, "alice")
	h.fake.Add(
		cloudtrailtest.Event("b1", h.now.Add(-5*time.Hour), alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
		cloudtrailtest.Event("b2", h.now.Add(-4*time.Hour), cloudtrailtest.AssumedRole(acct, "Deploy", "gha"), "iam.amazonaws.com", "PutRolePolicy", "us-east-1", "203.0.113.2", false, map[string]any{"roleName": "AppRole", "policyName": "inline"}),
	)
	e := h.open(t)
	if _, err := e.Init(ctx, InitOptions{}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// daily: 窓の末尾に root のログイン (次の run の再走査の区間に入る)
	h.now = h.now.Add(time.Hour)
	h.fake.Add(cloudtrailtest.Event("r1", h.now.Add(-5*time.Minute), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
	e = h.open(t)
	if _, err := e.Run(ctx, "daily"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(ctx, "weekly"); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// 翌日: 遅れて記録された mallory、同じ日の集計の引き直し (後の値で置き換え)、Access Analyzer の finding がなくなる (0 件で置き換え)
	prev := h.now
	h.now = h.now.Add(24 * time.Hour)
	h.fake.Add(
		cloudtrailtest.Event("late", prev.Add(-3*time.Minute), cloudtrailtest.User(acct, "mallory"), "sts.amazonaws.com", "AssumeRole", "ap-northeast-1", "198.51.100.7", true, map[string]any{"roleArn": "arn:aws:iam::" + acct + ":role/Admin"}),
		cloudtrailtest.Event("a2", h.now.Add(-2*time.Hour), alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "203.0.113.1", true, nil),
	)
	h.logs.On("as sign_in_failures", cwlogstest.Response{Rows: []map[string]string{cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "ip", "198.51.100.7", "sign_in_failures", "45")}})
	h.acct.AAFindings = nil
	e = h.open(t)
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Run(ctx, "weekly"); err != nil {
		t.Fatal(err)
	}
	// 人の判断 (raw に無い): finding を ack する
	if len(r.Report.Findings.New) == 0 {
		t.Fatalf("scenario: the second daily run must have new findings")
	}
	if _, err := e.SetStatus(ctx, r.Report.Findings.New[0].ID, store.FindingAcked, time.Time{}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	before, err := storetest.Dump(h.cfg.Store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	// 前提: 0 件の置き換え・集計の置き換え・2 つのソースのイベントと主体が入っている
	joined := func(tb string) string { return strings.Join(before[tb], "\n") }
	if strings.Contains(joined("snapshot_items"), "kind=access_analyzer") || !strings.Contains(joined("snapshot_items"), "kind=guardduty") {
		t.Fatalf("scenario snapshot_items: %s", joined("snapshot_items"))
	}
	if !strings.Contains(joined("metrics"), "metric=sign_in_failures|key=198.51.100.7|value=45") {
		t.Fatalf("scenario metrics: %s", joined("metrics"))
	}
	if !strings.Contains(joined("principals"), "status=baseline") || !strings.Contains(joined("findings"), "status=acked") {
		t.Fatalf("scenario principals/findings: %s\n%s", joined("principals"), joined("findings"))
	}

	res, err := Rebuild(ctx, h.cfg, h.deps, store.RebuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 || res.Malformed != 0 || len(res.UnknownKinds) != 0 || res.Backup == "" {
		t.Fatalf("result: %+v", res)
	}
	after, err := storetest.Dump(h.cfg.Store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for tb := range before {
		if !reflect.DeepEqual(before[tb], after[tb]) {
			t.Errorf("table %s differs after rebuild:\nbefore:\n  %s\nafter:\n  %s", tb, strings.Join(before[tb], "\n  "), strings.Join(after[tb], "\n  "))
		}
	}

	// 作り直したストアで run を続けられる (再走査の区間のイベントは再報告しない)
	h.now = h.now.Add(time.Hour)
	e = h.open(t)
	r, err = e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Summary.New != 0 || r.Report.Summary.Recurred != 0 {
		t.Fatalf("run after rebuild must be quiet: %+v", r.Report.Summary)
	}
	e.Close()

	// --from-scratch: raw 由来の表は同じ、主体は unknown、raw に無いものは空
	if _, err := Rebuild(ctx, h.cfg, h.deps, store.RebuildOptions{FromScratch: true}); err != nil {
		t.Fatal(err)
	}
	scratch, err := storetest.Dump(h.cfg.Store.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scratch["runs"]) != 0 || len(scratch["findings"]) != 0 || strings.Contains(strings.Join(scratch["principals"], "\n"), "status=baseline") {
		t.Fatalf("from scratch: runs=%v findings=%v principals=%v", scratch["runs"], scratch["findings"], scratch["principals"])
	}
}

func TestRebuildErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// ストアがまだ無い: 引き継ぎは STORE_CORRUPT ではなく、--from-scratch を案内する
	_, err := Rebuild(ctx, h.cfg, h.deps, store.RebuildOptions{})
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Exit != ExitConfig || !errors.Is(err, store.ErrNoDatabase) {
		t.Fatalf("missing database: %v", err)
	}
	if !strings.Contains(h.stderr.String(), "--from-scratch") {
		t.Fatalf("log must suggest --from-scratch: %s", h.stderr.String())
	}
	e := h.open(t)
	_, err = Rebuild(ctx, h.cfg, h.deps, store.RebuildOptions{})
	if !errors.As(err, &xe) || xe.Code != CodeStoreLocked {
		t.Fatalf("locked: %v", err)
	}
	e.Close()
}
