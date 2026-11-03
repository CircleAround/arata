package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/CircleAround/arata/internal/collect/account/accounttest"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/report/schema"
)

const wafSources = `  - id: waf
    kind: cloudwatch-logs
    log_group: aws-waf-logs-prod
    format: wafv2
  - id: waf_config
    kind: waf-config
`

// daily は wafv2 を集計して metrics に貯め、weekly の waf_review は wafv2 を引かずに保存済みの metrics と WebACL の設定から候補を作る。
func TestWAFReviewRun(t *testing.T) {
	h := newHarnessWith(t, wafSources, "")
	h.acct.WAF = &accounttest.WAF{WebACLs: map[string][]waftypes.WebACL{
		"REGIONAL|ap-northeast-1": {accounttest.WebACL(waftypes.ScopeRegional, "ap-northeast-1", "prod-waf")},
		"CLOUDFRONT|us-east-1":    {accounttest.WebACL(waftypes.ScopeCloudfront, "us-east-1", "cdn-waf")},
	},
		// 本物の読み取りロールでは COGNITO_USER_POOL の種類が拒否される (sandbox で起きた)。それでも weekly は成功し waf_review が走る
		ResourceTypeErrs: map[waftypes.ResourceType]error{waftypes.ResourceTypeCognitioUserPool: accounttest.DeniedCognito}}
	day := "2026-10-21 00:00:00.000"
	h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 1000))
	h.logs.On("as waf_actions", cwlogstest.Response{Rows: []map[string]string{
		cwlogstest.Rows("day", day, "acl", "prod-waf", "action", "ALLOW", "rule", "Default_Action", "path", "/.env", "ip", "198.51.100.9", "waf_actions", "12"),
	}})
	e := h.open(t)
	ctx := context.Background()
	if res, err := e.Run(ctx, "daily"); err != nil || res.Exit != ExitOK {
		t.Fatalf("daily: %v %+v", err, res)
	}
	if res, _ := e.Run(ctx, "daily"); len(res.Report.Proposals) != 0 {
		t.Fatalf("daily must not have proposals: %+v", res.Report.Proposals)
	}
	queries := len(h.logs.Started)

	h.now = h.now.Add(time.Hour)
	res, err := e.Run(ctx, "weekly")
	if err != nil || res.Exit != ExitOK {
		t.Fatalf("weekly: %v %+v", err, res)
	}
	if len(h.logs.Started) != queries {
		t.Fatalf("weekly must not query wafv2 logs: %d -> %d", queries, len(h.logs.Started))
	}
	if !contains(res.Report.Coverage.ChecksRun, "waf_review") {
		t.Fatalf("checks_run: %v / skipped %v", res.Report.Coverage.ChecksRun, res.Report.Coverage.ChecksSkipped)
	}
	var kinds []string
	for _, p := range res.Report.Proposals {
		kinds = append(kinds, p.Kind+":"+p.WebACL+":"+p.Scope)
	}
	if strings.Join(kinds, ",") != "probe_allowed:prod-waf:REGIONAL" {
		t.Fatalf("proposals: %v", kinds)
	}
	// CLOUDFRONT の WebACL は us-east-1 で引く
	items, _ := e.Store().Snapshot(ctx, "waf_config")
	var keys []string
	for _, it := range items {
		keys = append(keys, it.Key)
	}
	if strings.Join(keys, ",") != "acl|CLOUDFRONT|us-east-1|cdn-waf,acl|REGIONAL|ap-northeast-1|prod-waf" {
		t.Fatalf("snapshot: %v", keys)
	}
	// 保存したレポート (report.json / report.md) にも出る。aratam が読む schema で戻せる
	b, err := os.ReadFile(filepath.Join(h.cfg.Store.Dir, "reports", "weekly.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := schema.Parse(b)
	if err != nil || len(rep.Proposals) != 1 || rep.Proposals[0].Evidence["count"] != 12.0 {
		t.Fatalf("%v %+v", err, rep)
	}
	md, _ := os.ReadFile(filepath.Join(h.cfg.Store.Dir, "reports", "weekly.md"))
	if !strings.Contains(string(md), "## WAF の修正提案の候補 (1)") || !strings.Contains(string(md), "[probe_allowed / count_first]") {
		t.Fatalf("report.md:\n%s", md)
	}
}

// wafv2 の集計が行の上限に当たったら、run の stats と coverage.formats に残す。止めた・出した系は 1 本にまとめたので、そこから作る集計の名前を全部残す (ADR 0031)。
func TestWAFTruncatedStats(t *testing.T) {
	h := newHarnessWith(t, wafSources, "")
	h.logs.On("as lines_total", linesRows("2026-10-21", 1000, 1000))
	rows := make([]map[string]string, cwlogs.MaxRows)
	for i := range rows {
		rows[i] = cwlogstest.Rows("day", "2026-10-21 00:00:00.000", "acl", "prod-waf", "action", "ALLOW", "path", "/.env", "ip", fmt.Sprintf("10.0.%d.%d", i/256, i%256), "waf_actions", "1")
	}
	h.logs.On("as waf_actions", cwlogstest.Response{Rows: rows})
	e := h.open(t)
	res, err := e.Run(context.Background(), "daily")
	if err != nil {
		t.Fatal(err)
	}
	if f := res.Report.Coverage.Formats; len(f) != 1 || strings.Join(f[0].Truncated, ",") != "waf_block_ip,waf_block_path,waf_allow_probe,waf_suspect_block_ip,waf_challenge_issued,waf_challenge_solved" {
		t.Fatalf("formats: %+v", f)
	}
	runs, _ := e.Store().RecentRuns(context.Background(), 1)
	tr, _ := runs[0].Stats["truncated_aggregates"].(map[string]any)
	if fmt.Sprint(tr["waf"]) != "[waf_block_ip waf_block_path waf_allow_probe waf_suspect_block_ip waf_challenge_issued waf_challenge_solved]" {
		t.Fatalf("stats: %+v", runs[0].Stats)
	}
}

// waf_review は wafv2 のソースが無ければ skip (weekly は wafv2 を引かないので、日次集計の元が設定に要る)。
func TestWAFReviewSkippedWithoutLogs(t *testing.T) {
	h := newHarnessWith(t, "  - id: waf_config\n    kind: waf-config\n", "")
	h.acct.WAF = &accounttest.WAF{WebACLs: map[string][]waftypes.WebACL{"REGIONAL|ap-northeast-1": {accounttest.WebACL(waftypes.ScopeRegional, "ap-northeast-1", "prod-waf")}}}
	res, err := h.open(t).Run(context.Background(), "weekly")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Report.Coverage.ChecksSkipped {
		if s.Check == "waf_review" && strings.Contains(s.Reason, "no waf_action source") {
			return
		}
	}
	t.Fatalf("skipped: %+v", res.Report.Coverage.ChecksSkipped)
}
