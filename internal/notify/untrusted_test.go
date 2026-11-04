package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 攻撃者が書ける文字列 (パス、JSON のログの項目) の例。改行で偽の行を作り、向きの制御文字で表示を入れ替え、メンションとリンクを狙う。
const hostile = "/x\r\n*偽の見出し* @here\u202e<!channel> <http://evil.example|公式>\u200b"

func hostileReport() *Input {
	r := &schema.Report{Name: "n", Profile: "daily", RunID: "r1"}
	f := schema.Finding{ID: "f1", Check: "probe_paths", Key: hostile, Severity: "low", Summary: hostile, Data: map[string]any{"ip": hostile, "top_paths_of_day": []any{hostile}}}
	r.Findings.New = []schema.Finding{f}
	r.Summary.New = 1
	r.Proposals = []schema.Proposal{
		{Kind: "false_positive", Stage: "count_first", WebACL: "acl", Rule: "r", Method: "GET", Path: hostile, Summary: hostile, Evidence: map[string]any{"count": 1.0, "path_group": hostile}},
		{Kind: kindObservation, About: "false_positive", Reason: "below_threshold", Summary: hostile},
	}
	return &Input{Kind: KindRun, Run: r, Dir: "/tmp/in"}
}

func checkInert(t *testing.T, name, s string) {
	t.Helper()
	for _, bad := range []string{"\u202e", "\u200b", "\r", "<!channel>", "<http://"} {
		if strings.Contains(s, bad) {
			t.Errorf("%s: %q が残っている: %q", name, bad, s)
		}
	}
	if strings.Contains(s, "\n*偽の見出し*") {
		t.Errorf("%s: ログの改行で行が作られた: %q", name, s)
	}
}

// ログ由来の値は 1 行のまま、制御文字を除いて、どの書式の通知にも出る。
func TestLogValuesStayInert(t *testing.T) {
	in := hostileReport()
	d, r := Decision{Route: RouteNormal}, Rules{Name: "n", UrgentSeverity: "high"}
	checkInert(t, "ReportText", ReportText(in, d, r, nil, ""))
	checkInert(t, "blocks", allText(RunBlocks(in, d, r, nil, nil, "")))
	checkInert(t, "ProposalsText", ProposalsText(in, nil, nil, ""))
	checkInert(t, "ProposalsBlocks", allText(ProposalsBlocks(in, nil, nil, "", "/tmp/in/waf-proposals.md")))
	for _, l := range strings.Split(ProposalsMarkdown(in, nil, ""), "\n") {
		if strings.HasPrefix(l, "*偽の見出し*") {
			t.Errorf("waf-proposals.md: ログの改行で行が作られた: %q", l)
		}
	}
}

func TestOneLineDropsInvisibleCharacters(t *testing.T) {
	if got, want := oneLine("a\u202eb\u200b\x07 c\nd"), "ab c d"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// mrkdwn は verbatim にする (Slack が URL・チャンネル名・メンションを自動で解釈しない)。設定の <!channel> は verbatim でも効くので文字はそのまま。
func TestMrkdwnIsVerbatim(t *testing.T) {
	in := hostileReport()
	m := RunBlocks(in, Decision{Route: RouteUrgent}, Rules{Name: "n", UrgentSeverity: "high", UrgentMention: "<!channel>"}, nil, nil, "")
	ms := []Message{m, ProposalsBlocks(in, nil, nil, "", "f"), QuietBlocks(in, Decision{}, Rules{}, nil)}
	for _, msg := range ms {
		for _, b := range msg.Blocks {
			objs := append(append([]*TextObj{}, b.Fields...), b.Elements...)
			if b.Text != nil {
				objs = append(objs, b.Text)
			}
			for _, o := range objs {
				if o.Type == "mrkdwn" && !o.Verbatim {
					t.Errorf("verbatim でない: %+v", o)
				}
			}
		}
	}
	if m.Blocks[0].Text.Text != "<!channel>" {
		t.Fatalf("設定のメンションが変わった: %+v", m.Blocks[0].Text)
	}
}

// 本文に攻撃者の URL が混ざっても Slack に取りに行かせない (プレビューの偽装を防ぐ)。text の書式でも同じ。
func TestMessagesDoNotUnfurl(t *testing.T) {
	b, err := json.Marshal(Message{Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"unfurl_links", "unfurl_media"} {
		if v, ok := got[k]; !ok || v != false {
			t.Errorf("%s = %v (ok=%v), want false", k, v, ok)
		}
	}
}
