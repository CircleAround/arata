package engine

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	ai "github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// logsGuideSources は、この版が持つソースの種類を全部 (cloudwatch-logs は形式ごとに 1 つ) 書いた設定。
// ソースの種類や形式を足したら、ここにも足す (足さないと TestLogsGuideTable が落ちる)。
const logsGuideSources = `
  - { id: unused, kind: cloudtrail-unused-regions }
  - { id: cost, kind: cost-anomaly }
  - { id: iam, kind: iam-credential-report }
  - { id: guardduty, kind: guardduty }
  - { id: analyzer, kind: access-analyzer }
  - { id: posture, kind: posture }
  - { id: waf_config, kind: waf-config }
  - { id: nginx, kind: cloudwatch-logs, log_group: prod-nginx-access, format: nginx_access }
  - { id: alb, kind: cloudwatch-logs, log_group: prod-alb-access, format: alb_access }
  - { id: waf, kind: cloudwatch-logs, log_group: aws-waf-logs-prod, format: wafv2 }
  - { id: app, kind: cloudwatch-logs, log_group: prod-app, format: json, fields: { ip: remote_ip, path: path } }
  - { id: app_re, kind: cloudwatch-logs, log_group: prod-app, format: regex, regex: '(?P<ip>\S+) (?P<path>\S+)' }
`

// logsGuideTable は「チェックと記録の対応」の表を、Registry (チェックの Needs / StoredNeeds) とソースの種類 (kindsOf) から作る。
// 行は「要るソースの組」ごと。並びは Registry の登録順で最初に出た順。
func logsGuideTable(t *testing.T) string {
	t.Helper()
	h := newHarnessWith(t, logsGuideSources, "")
	// 形式を全部書いているか (形式を足したのに上の設定に足していなければ落とす)
	formats := map[string]bool{}
	for _, src := range h.cfg.Sources {
		if src.Kind == config.KindCloudWatchLogs {
			formats[src.Format] = true
		}
	}
	for _, f := range config.Formats() {
		if !formats[f] {
			t.Fatalf("format %s is not in logsGuideSources", f)
		}
	}
	// レコードの種類 → それを出すソースの書き方 (cloudwatch-logs は形式を名前順に並べる)
	labels := map[record.Kind][]string{}
	logFormats := map[record.Kind][]string{}
	for _, src := range h.cfg.Sources {
		for _, k := range kindsOf(src) {
			if src.Kind == config.KindCloudWatchLogs {
				if !contains(logFormats[k], src.Format) {
					logFormats[k] = append(logFormats[k], src.Format)
				}
				continue
			}
			if !contains(labels[k], src.Kind) {
				labels[k] = append(labels[k], src.Kind)
			}
		}
	}
	for k, fs := range logFormats {
		sort.Strings(fs)
		labels[k] = append(labels[k], config.KindCloudWatchLogs+" ("+strings.Join(fs, " / ")+")")
	}
	reg := checks.NewRegistry()
	type row struct{ kinds, checks []string }
	rows := map[string]*row{}
	var order []string
	for _, name := range reg.Names() {
		c, _ := reg.Get(name)
		needs := append([]record.Kind{}, c.Needs()...)
		if sn, ok := c.(checks.StoredNeeder); ok {
			needs = append(needs, sn.StoredNeeds()...)
		}
		var srcs, kinds []string
		for _, k := range needs {
			if len(labels[k]) == 0 {
				t.Fatalf("%s needs %s, which no source in logsGuideSources yields (add the new source kind there)", name, k)
			}
			kinds = append(kinds, string(k))
			if l := strings.Join(labels[k], " か "); !contains(srcs, l) {
				srcs = append(srcs, l)
			}
		}
		key := strings.Join(srcs, " + ")
		if rows[key] == nil {
			rows[key] = &row{}
			order = append(order, key)
		}
		for _, k := range kinds {
			if !contains(rows[key].kinds, k) {
				rows[key].kinds = append(rows[key].kinds, k)
			}
		}
		rows[key].checks = append(rows[key].checks, fmt.Sprintf("%s (%s)", name, c.Cadence()))
	}
	var b strings.Builder
	b.WriteString("| ソース (kind。括弧は format) | 出る記録 | 動くチェック (周期) |\n|---|---|---|\n")
	for _, key := range order {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", key, strings.Join(rows[key].kinds, ", "), strings.Join(rows[key].checks, ", "))
	}
	return b.String()
}

// doctorSample は doctor の解釈率のサンプル (直近の行) の応答。
func doctorSample(matched, unmatched int) cwlogstest.Response {
	var rows []map[string]string
	for i := 0; i < matched; i++ {
		rows = append(rows, cwlogstest.Rows("@timestamp", "2026-10-21 08:00:00.000", "@message", "ok", "arata_matched", "1"))
	}
	for i := 0; i < unmatched; i++ {
		rows = append(rows, cwlogstest.Rows("@timestamp", "2026-10-21 08:00:00.000", "@message", "Started GET", "arata_matched", "0"))
	}
	return cwlogstest.Response{Rows: rows}
}

// TestLogsGuideTable は arata help ai logs の「チェックと記録の対応」の表が、コードから作った表と一字一句同じであることを固定する。
// チェックを足す・Needs を変える・ソースの種類や形式を足すと落ちる。落ちたら、出力された表を docs/ai/logs.md に貼る。
func TestLogsGuideTable(t *testing.T) {
	tp, err := ai.Lookup("logs")
	if err != nil {
		t.Fatal(err)
	}
	want := logsGuideTable(t)
	var got []string
	for _, s := range tp.Parse().Sections {
		if s.Title != "チェックと記録の対応" {
			continue
		}
		for _, line := range strings.Split(s.Body, "\n") {
			if strings.HasPrefix(line, "|") {
				got = append(got, line)
			}
		}
	}
	if strings.Join(got, "\n")+"\n" != want {
		t.Fatalf("docs/ai/logs.md の「チェックと記録の対応」の表がコードと違う。次の表に置き換える:\n%s", want)
	}
}

// TestDoctorLogsGuideHints は doctor が「足りない記録」を出す行に、arata help ai logs の該当の節を添えることを確かめる。
// 節の名前は文書に実在するものだけ。
func TestDoctorLogsGuideHints(t *testing.T) {
	tp, err := ai.Lookup("logs")
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]bool{}
	for _, s := range tp.Parse().Sections {
		titles[s.Title] = true
	}
	for _, sec := range []string{LogsGuideChecks, LogsGuideCollect, LogsGuideVerify, LogsGuidePitfalls} {
		if !titles[sec] {
			t.Errorf("arata help ai logs has no section %q", sec)
		}
	}
	// ロググループが無い (web)、解釈率が低い (app)、行が無い (quiet)、ソースが無くチェックが skip (waf_block_trend など)
	h := newHarnessWith(t, `
  - { id: web, kind: cloudwatch-logs, log_group: prod-nginx-access, format: nginx_access }
  - { id: app, kind: cloudwatch-logs, log_group: prod-app, format: json, fields: { ip: remote_ip, path: path } }
`, "")
	h.logs.LogGroups = []string{"prod-app"}
	h.logs.On("sort @timestamp desc", doctorSample(10, 90))
	res := Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour)
	hints := map[string]string{}
	for _, row := range res.Rows {
		switch {
		case row.Code == "LOG_GROUP_MISSING", row.Code == "FORMAT_MISMATCH":
			hints[row.Code] = row.Hint
		case row.Item == "check" && strings.Contains(row.Detail, "skip される"):
			hints["skip"] = row.Hint
		case row.Hint != "":
			t.Errorf("unexpected hint on %+v", row)
		}
	}
	for key, sec := range map[string]string{"LOG_GROUP_MISSING": LogsGuideCollect, "FORMAT_MISMATCH": LogsGuidePitfalls, "skip": LogsGuideChecks} {
		if want := "arata help ai logs (「" + sec + "」)"; hints[key] != want {
			t.Errorf("%s: hint %q, want %q", key, hints[key], want)
		}
	}
	// 表: 案内は表の後ろに 1 行ずつ (同じものは 1 回)。足りない記録が無ければ出さない
	var out bytes.Buffer
	if err := res.WriteTable(&out); err != nil {
		t.Fatal(err)
	}
	for _, sec := range []string{LogsGuideCollect, LogsGuidePitfalls, LogsGuideChecks} {
		if n := strings.Count(out.String(), "arata help ai logs (「"+sec+"」)"); n != 1 {
			t.Errorf("table must show the hint for %q once, got %d:\n%s", sec, n, out.String())
		}
	}
	ok := &DoctorResult{Rows: []DoctorRow{{Source: "trail", Kind: "cloudtrail-lookup", Item: "permission", Status: DoctorOK}}}
	out.Reset()
	if err := ok.WriteTable(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "arata help ai logs") {
		t.Errorf("no hint when nothing is missing:\n%s", out.String())
	}

	// 行が無い (warn) にも、確かめ方の節を添える
	h2 := newHarnessWith(t, `
  - { id: quiet, kind: cloudwatch-logs, log_group: prod-nginx-access, format: nginx_access }
`, "")
	h2.logs.LogGroups = []string{"prod-nginx-access"}
	res = Doctor(t.Context(), h2.cfg, h2.deps, 24*time.Hour)
	found := false
	for _, row := range res.Rows {
		if row.Source == "quiet" && row.Item == "match_rate" {
			found = true
			if want := "arata help ai logs (「" + LogsGuideVerify + "」)"; row.Status != DoctorWarn || row.Hint != want {
				t.Errorf("no lines: %+v, want hint %q", row, want)
			}
		}
	}
	if !found {
		t.Fatal("no match_rate row for the source without lines")
	}
}
