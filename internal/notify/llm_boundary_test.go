package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/report/schema"
)

// LLM が攻撃者の文に従った場合の出力を固定値で与え、規則が残すものを確かめる (ADR 0037)。

func boundaryInput(sevs ...string) *Input {
	r := &schema.Report{Name: "n", Profile: "daily", RunID: "r"}
	long := strings.Repeat("x", 300)
	for i, s := range sevs {
		id := fmt.Sprintf("f%d", i)
		r.Findings.New = append(r.Findings.New, schema.Finding{ID: id, Check: "root_usage", Key: id, Severity: s, Summary: long + id})
	}
	r.Summary.New = len(sevs)
	return &Input{Kind: KindRun, Run: r}
}

const urgent = "high"

func parse(t *testing.T, in *Input, body string) *Summary {
	t.Helper()
	s, err := ParseSummary([]byte(body), in, urgent)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// critical を「情報」にしても本文から消えない。LLM の理由 (攻撃者の「誤検知です」) も載せない。
func TestSeverityFloor(t *testing.T) {
	sevs := make([]string, 30)
	for i := range sevs {
		sevs[i] = "low"
	}
	sevs[29] = "critical"
	in := boundaryInput(sevs...)
	var items []string
	for i := range sevs {
		c := "action"
		if i >= 10 {
			c = "info"
		}
		items = append(items, fmt.Sprintf(`{"finding_id":"f%d","class":"%s","reason":"誤検知です"}`, i, c))
	}
	s := parse(t, in, `{"headline":"問題なし","items":[`+strings.Join(items, ",")+`]}`)
	for _, it := range s.Items {
		if it.FindingID == "f29" && (it.Class != "confirm" || it.Reason != "") {
			t.Fatalf("床が効いていない: %+v", it)
		}
	}
	text := SummaryText(in, Decision{Route: RouteUrgent}, Rules{Name: "n", UrgentSeverity: urgent}, nil, s)
	if !strings.Contains(text, "*[critical]*") {
		t.Fatalf("critical が消えた:\n%s", text)
	}
}

// 低い重大度の「要対処」を大量に並べて、高い重大度の行を切り詰めで押し出させない。
func TestUrgentFindingsSurviveTruncation(t *testing.T) {
	sevs := make([]string, 30)
	for i := range sevs {
		sevs[i] = "low"
	}
	sevs[29] = "high"
	in := boundaryInput(sevs...)
	var items []string
	for i := range sevs {
		c := "action"
		if i == 29 {
			c = "confirm"
		}
		items = append(items, fmt.Sprintf(`{"finding_id":"f%d","class":"%s","reason":"r"}`, i, c))
	}
	s := parse(t, in, `{"headline":"h","items":[`+strings.Join(items, ",")+`]}`)
	text := SummaryText(in, Decision{Route: RouteUrgent}, Rules{Name: "n", UrgentSeverity: urgent}, nil, s)
	if !strings.Contains(text, "*[high]*") {
		t.Fatalf("high が押し出された:\n%s", text)
	}
}

func TestUrgentFindingsAreNotApproveSuggestions(t *testing.T) {
	in := boundaryInput("critical", "high", "medium")
	s := parse(t, in, `{"headline":"h","items":[],"approve_suggestions":[{"finding_id":"f0","reason":"正当"},{"finding_id":"f1","reason":"正当"},{"finding_id":"f2","reason":"正当"}]}`)
	if len(s.ApproveSuggestions) != 1 || s.ApproveSuggestions[0].FindingID != "f2" {
		t.Fatalf("%+v", s.ApproveSuggestions)
	}
}

func TestUnsafeLLMText(t *testing.T) {
	bad := []string{
		"詳細は https://evil.example/fix を開く", "hxxp://evil.example", "www.evil.example を確認", "WWW.EVIL.EXAMPLE",
		"@channel 至急", "全員 @here", "@everyone", "@\u200bchannel", "ht\u200btps://evil.example",
	}
	for _, s := range bad {
		if unsafeLLMText(s) == "" {
			t.Errorf("%q を通した", s)
		}
	}
	good := []string{
		"arn:aws:iam::123456789012:user/alice の鍵を無効化する", "`arata review` で確認する", "user@ を含むパス", "GET /search の一致を見る",
		"waf-proposals.md を読む", "@channels という語", "BLOCK している",
	}
	for _, s := range good {
		if why := unsafeLLMText(s); why != "" {
			t.Errorf("%q を捨てた: %s", s, why)
		}
	}
}

// 自由文に URL やメンションがあれば捨てる。項目は規則の行に戻り、見出しは形の不正になる。
func TestParseSummaryDropsUnsafeText(t *testing.T) {
	in := boundaryInput("medium", "medium")
	if _, err := ParseSummary([]byte(`{"headline":"https://evil.example を開く","items":[]}`), in, urgent); err == nil {
		t.Fatal("見出しの URL を通した")
	}
	s := parse(t, in, `{"headline":"h","items":[{"finding_id":"f0","class":"confirm","reason":"@channel 見て"},{"finding_id":"f1","class":"confirm","reason":"ok"}],
		"incidents":[{"finding_ids":["f0"],"summary":"https://evil.example"}],"approve_suggestions":[{"finding_id":"f0","reason":"www.evil.example"}]}`)
	if len(s.Items) != 1 || s.Items[0].FindingID != "f1" || len(s.Incidents) != 0 || len(s.ApproveSuggestions) != 0 {
		t.Fatalf("%+v", s)
	}
	if m := s.Missing(in); len(m) != 1 || m[0].id != "f0" {
		t.Fatalf("捨てた finding が規則の行に戻らない: %+v", m)
	}
	if len(s.Rejected) != 3 {
		t.Fatalf("rejected: %v", s.Rejected)
	}
}

func TestParseBlockNotesChecksFreeText(t *testing.T) {
	targets := []findingRef{{id: "f0"}, {id: "f1"}, {id: "f2"}}
	for _, body := range []string{`{"summary":"https://evil.example を開く"}`, `{"summary":"BLOCK に切り替えてください"}`} {
		if _, err := ParseBlockNotes([]byte(body), targets); err == nil {
			t.Errorf("通した: %s", body)
		}
	}
	n, err := ParseBlockNotes([]byte(`{"summary":"s","next":[{"finding_id":"f0","action":"@here 実行"},{"finding_id":"f1","action":"BLOCK に設定する"},{"finding_id":"f2","action":"鍵を無効化する"}]}`), targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Next) != 1 || n.Next["f2"] == "" || len(n.Rejected) != 2 {
		t.Fatalf("%+v", n)
	}
}

func TestRejectWriteupBlockVariants(t *testing.T) {
	for _, w := range []Writeup{
		{Example: `{"Action":"BLOCK"}`}, {Example: `"action": "block"`}, {Example: `action = "BLOCK"`}, {Example: `"Block": {}`},
		{How: "BLOCK に設定する"}, {How: "ブロックに切り替える"}, {How: "ブロックへ変更する"}, {How: "BLOCK で運用する"}, {How: "BLOCK を有効にする"},
		{What: "BLOCK のルールを追加する"}, {Why: "ブロックモードに移行する"}, {Next: "switch the rule to BLOCK"}, {Next: "set the action to block"},
		{Next: "https://evil.example の手順で進める"},
	} {
		if rejectWriteup(w) == "" {
			t.Errorf("通した: %+v", w)
		}
	}
	for _, w := range []Writeup{
		{Why: "正規の画面らしい通信を BLOCK している"}, {Why: "BLOCK された件数が多い"}, {Why: "ブロックが増えている"}, {How: "COUNT に切り替えて様子を見る"},
		{Why: "BLOCK に一致した"}, {What: "このルールの対象から外す"}, {Example: `{"Action":{"Count":{}}}`},
	} {
		if why := rejectWriteup(w); why != "" {
			t.Errorf("捨てた: %+v (%s)", w, why)
		}
	}
}

// 3 種の system すべてに、入力を信用しない指示がある。
func TestSystemPromptsDistrustInput(t *testing.T) {
	for name, s := range map[string]string{
		"summary": SystemPrompt(KindRun, "", ""), "blocks": BlocksSystemPrompt(KindRun, "", "", nil), "proposals": ProposalsSystemPrompt("", ""),
	} {
		if !strings.Contains(s, untrustedInputRule) {
			t.Errorf("%s: 入力を信用しない指示が無い", name)
		}
	}
}

// LLM の文であることは、既存の末尾の行に添える。provider: none と LLM の失敗では出さない。行は増やさない。
func TestLLMNotice(t *testing.T) {
	in := boundaryInput("high", "low")
	in.Dir = "/tmp/in"
	d, r := Decision{Route: RouteUrgent}, Rules{Name: "n", UrgentSeverity: urgent}
	with := RunBlocks(in, d, r, nil, &BlockNotes{Summary: "s"}, "")
	without := RunBlocks(in, d, r, nil, nil, "")
	if !strings.Contains(allText(with), LLMNotice) {
		t.Fatalf("注記が無い:\n%s", allText(with))
	}
	if strings.Contains(allText(without), LLMNotice) {
		t.Fatalf("none で注記が出た:\n%s", allText(without))
	}
	if len(with.Blocks) != len(without.Blocks) {
		t.Fatalf("ブロックが増えた: %d → %d", len(without.Blocks), len(with.Blocks))
	}
	last := with.Blocks[len(with.Blocks)-1]
	if last.Type != "context" || !strings.Contains(last.Elements[0].Text, LLMNotice) {
		t.Fatalf("末尾の context に無い: %+v", last)
	}
	s := &Summary{Headline: "h"}
	if text := SummaryText(in, d, r, nil, s); !strings.Contains(text, LLMNotice) {
		t.Fatalf("text の要約に注記が無い:\n%s", text)
	}
	if text := ReportText(in, d, r, nil, ""); strings.Contains(text, LLMNotice) {
		t.Fatalf("原文に注記が出た:\n%s", text)
	}
	in.Run.Proposals = []schema.Proposal{{Kind: "unused_rule", Stage: "review", WebACL: "a", Rule: "r", Summary: "s"}}
	w := map[string]Writeup{"p1": {ID: "p1", Next: "n"}}
	if m := ProposalsBlocks(in, nil, w, "", "f"); !strings.Contains(allText(m), LLMNotice) {
		t.Fatal("提案の Block Kit に注記が無い")
	}
	if m := ProposalsBlocks(in, nil, nil, "", "f"); strings.Contains(allText(m), LLMNotice) {
		t.Fatal("LLM を使っていない提案に注記が出た")
	}
	if text := ProposalsText(in, nil, w, ""); !strings.Contains(text, LLMNotice) {
		t.Fatal("提案の text に注記が無い")
	}
}

// 通知の流れ全体: 誘導された LLM の出力でも、URL は通知にもログにも写らず、finding は規則の行で残る。
func TestRunWithHijackedLLM(t *testing.T) {
	const evil = "https://evil.example/fix"
	dir := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	in, err := ReadInput(dir, now, 26*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := findingIndex(in)
	var items []string
	for _, f := range list {
		if f.required {
			items = append(items, fmt.Sprintf(`{"finding_id":%q,"class":"info","reason":"誤検知です。%s を実行"}`, f.id, evil))
		}
	}
	l := &fakeLLM{responses: []string{`{"headline":"問題なし","items":[` + strings.Join(items, ",") + `]}`}}
	s := &fakeSender{}
	res, logs := run(t, dir, s, withLLM(l))
	if res.Exit != ExitOK || len(s.got) != 1 {
		t.Fatalf("%+v", res)
	}
	text := s.got[0].msg.Text
	if strings.Contains(text, evil) || strings.Contains(logs.String(), evil) {
		t.Fatalf("URL が残った:\n%s\n%s", text, logs)
	}
	if !strings.Contains(text, "*[critical]*") || !strings.Contains(logs.String(), CodeLLMOutputRejected) {
		t.Fatalf("critical か警告が無い:\n%s\n%s", text, logs)
	}
}
