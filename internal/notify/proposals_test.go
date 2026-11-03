package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/report/schema"
)

func testProposals(t *testing.T) []schema.Proposal {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "proposals.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ps []schema.Proposal
	if err := json.Unmarshal(b, &ps); err != nil {
		t.Fatal(err)
	}
	return ps
}

// withProposals は arata のゴールデンの report.json に proposals を足す (weekly の waf_review が走った run)。
func withProposals(t *testing.T, r *schema.Report, ps []schema.Proposal) []byte {
	t.Helper()
	r.Proposals = ps
	return marshal(t, r)
}

// sendFailOn は n 通目 (1 始まり) の送信だけ失敗する Sender。
type sendFailOn struct {
	fakeSender
	n, calls int
}

func (f *sendFailOn) Send(ctx context.Context, r Route, text string) error {
	f.calls++
	if f.calls == f.n {
		return errors.New("slack: 500")
	}
	return f.fakeSender.Send(ctx, r, text)
}

// provider: none: 本文は今までどおり (緊急用) に送り、提案は通常用に 2 通目として送る。
// 提案 (kind が observation 以外) を先に、observation を後ろに、count_rule_status を最後に 1 行ずつ。数字は report.json の値。
func TestProposalsNone(t *testing.T) {
	base := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	s0 := &fakeSender{}
	run(t, base, s0)

	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), string(golden(t, "report.md")))
	s := &fakeSender{}
	res, _ := run(t, dir, s)
	if res != (Result{Exit: ExitOK, Route: RouteUrgent, Sent: true}) || len(s.got) != 2 {
		t.Fatalf("%+v %d", res, len(s.got))
	}
	if s.got[0].route != RouteUrgent || s.got[1].route != RouteNormal {
		t.Fatalf("main goes by the rules, proposals always go to the normal webhook: %s %s", s.got[0].route, s.got[1].route)
	}
	if got, want := strings.ReplaceAll(s.got[0].text, dir, "<dir>"), strings.ReplaceAll(s0.got[0].text, base, "<dir>"); got != want {
		t.Fatalf("the main message must not change:\n%s", got)
	}
	text := strings.ReplaceAll(s.got[1].text, dir, "<dir>")
	checkGolden(t, "proposals_none.txt", text)
	if strings.Contains(text, "<!channel>") {
		t.Fatal("the proposals message is not urgent and must not mention")
	}
	order := []string{"[false_positive", "[probe_allowed", "[rate_limit_missing", "[rate_limit_loose", "[unused_rule", "excluded_by_config", "KnownBadInputsRuleSet: 直近", "count-geo"}
	last := -1
	for _, o := range order {
		i := strings.Index(text, o)
		if i <= last {
			t.Fatalf("%q must come after the previous item:\n%s", o, text)
		}
		last = i
	}
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
		t.Fatalf(".aratam-notified: %q", b)
	}
}

// proposals が無い・空の run は 2 通目を送らない。
func TestProposalsAbsentSendsOneMessage(t *testing.T) {
	for _, ps := range [][]schema.Proposal{nil, {}} {
		s := &fakeSender{}
		run(t, inputDir(t, withProposals(t, goldenRun(t), ps), ""), s)
		if len(s.got) != 1 {
			t.Fatalf("%d messages", len(s.got))
		}
	}
}

// observation だけの run も 2 通目を送る (「提案 0 件」と観察)。
func TestProposalsObservationsOnly(t *testing.T) {
	var obs []schema.Proposal
	for _, p := range testProposals(t) {
		if p.Kind == "observation" {
			obs = append(obs, p)
		}
	}
	s := &fakeSender{}
	run(t, inputDir(t, withProposals(t, goldenRun(t), obs), ""), s)
	if len(s.got) != 2 || !strings.Contains(s.got[1].text, "提案 0 件 / 観察 3 件") || !strings.Contains(s.got[1].text, "提案はありません") {
		t.Fatalf("%+v", s.got)
	}
}

// 静かな run: short は 1 行の後に 2 通目、silent は 2 通目だけを送る (週 1 回の改善提案のまとめ)。
func TestProposalsQuiet(t *testing.T) {
	quiet := func() []byte {
		var r schema.Report
		if err := json.Unmarshal(quietReport(t), &r); err != nil {
			t.Fatal(err)
		}
		return withProposals(t, &r, testProposals(t))
	}
	s := &fakeSender{}
	res, _ := run(t, inputDir(t, quiet(), ""), s)
	if res.Exit != ExitOK || len(s.got) != 2 || !strings.Contains(s.got[0].text, "新規なし") || !strings.Contains(s.got[1].text, "*WAF の改善提案*") {
		t.Fatalf("short: %+v %+v", res, s.got)
	}

	dir := inputDir(t, quiet(), "")
	s = &fakeSender{}
	res, _ = run(t, dir, s, func(o *Options) { o.Rules.OnQuiet = "silent" })
	if res != (Result{Exit: ExitOK, Route: RouteNormal, Sent: true}) || len(s.got) != 1 || s.got[0].route != RouteNormal || !strings.Contains(s.got[0].text, "*WAF の改善提案*") {
		t.Fatalf("silent must send only the proposals: %+v %+v", res, s.got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
		t.Fatalf(".aratam-notified: %q", b)
	}

	// silent で提案の送信に失敗したら、何も送れていないので記録しない (次回もう一度送る)
	dir = inputDir(t, quiet(), "")
	f := &sendFailOn{n: 1}
	res, _ = run(t, dir, &f.fakeSender, func(o *Options) { o.Rules.OnQuiet = "silent"; o.Sender = f })
	if res.Exit != ExitSend {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, NotifiedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing was sent, must not mark: %v", err)
	}
}

// 2 通目の送信に失敗したら終了コード 5。1 通目は送れているので .aratam-notified は書く (本文を二重に送らない)。
func TestProposalsSendFailure(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	f := &sendFailOn{n: 2}
	res, logs := run(t, dir, &f.fakeSender, func(o *Options) { o.Sender = f })
	if res.Exit != ExitSend || !res.Sent || len(f.got) != 1 || !strings.Contains(logs.String(), CodeSendFailed) {
		t.Fatalf("%+v %s", res, logs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
		t.Fatalf("the main message was sent, must mark: %q", b)
	}
}

// observation が多ければ 10 行までにして、残りは件数だけ (全部は report.json)。
func TestProposalsManyObservations(t *testing.T) {
	ps := testProposals(t)
	for i := range 15 {
		ps = append(ps, schema.Proposal{Kind: "observation", About: "count_rule_status", Reason: "informational", Stage: "none", WebACL: "prod-waf",
			Rule: fmt.Sprintf("count-%02d", i), Summary: fmt.Sprintf("prod-waf: COUNT の count-%02d: 直近 7 日で一致なし", i), Evidence: map[string]any{"matches": 0}})
	}
	s := &fakeSender{}
	run(t, inputDir(t, withProposals(t, goldenRun(t), ps), ""), s)
	text := s.got[1].text
	if !strings.Contains(text, "count-06") || strings.Contains(text, "count-07") || !strings.Contains(text, "ほか 8 件は report.json") {
		t.Fatalf("observations must be capped at 10 lines:\n%s", text)
	}
	if !strings.Contains(text, "観察 18 件") {
		t.Fatalf("the header must count all observations:\n%s", text)
	}
}

// report 由来の文字列はエスケープする (メンションやリンクとして働かせない)。
func TestProposalsEscaped(t *testing.T) {
	ps := testProposals(t)[1:2] // probe_allowed (根拠に paths を出す)
	ps[0].Summary = "<!channel> & <https://example.com|x>"
	ps[0].Evidence = map[string]any{"count": 1, "paths": []any{"/<!here>"}}
	s := &fakeSender{}
	run(t, inputDir(t, withProposals(t, goldenRun(t), ps), ""), s)
	text := s.got[1].text
	if strings.Contains(text, "<!") || !strings.Contains(text, "&lt;!channel&gt; &amp; &lt;https://example.com|x&gt;") || !strings.Contains(text, "/&lt;!here&gt;") {
		t.Fatalf("%s", text)
	}
}

// LLM: 要約とは別の呼び出しで、提案の候補だけ (observation を除き id p1.. を振ったもの) を渡して書き起こさせる。
// 表示する種類・段階・概要・根拠の数字は report.json の値で、LLM の文字列は何を・なぜ・進め方・設定例だけ。
func TestProposalsLLM(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), string(golden(t, "report.md")))
	l := &fakeLLM{responses: []string{fixture(t, "ok.json"), fixture(t, "proposals_ok.json")}}
	s := &fakeSender{}
	res, _ := run(t, dir, s, withLLM(l))
	if res != (Result{Exit: ExitOK, Route: RouteUrgent, Sent: true}) || l.calls != 2 || len(s.got) != 2 {
		t.Fatalf("%+v calls %d sent %d", res, l.calls, len(s.got))
	}
	var got []map[string]any
	if err := json.Unmarshal(l.inputs[1], &got); err != nil {
		t.Fatalf("the proposals input must be a JSON array: %v\n%s", err, l.inputs[1])
	}
	if len(got) != 5 || got[0]["id"] != "p1" || got[4]["id"] != "p5" || got[0]["kind"] != "false_positive" {
		t.Fatalf("only proposals (not observations) with ids: %s", l.inputs[1])
	}
	in := string(l.inputs[1])
	for _, no := range []string{"observation", "count_rule_status", "checkout", "findings", "run-1"} {
		if strings.Contains(in, no) {
			t.Fatalf("the proposals input must not contain %q: %s", no, in)
		}
	}
	sys := l.systems[1]
	for _, want := range []string{"候補に無い提案を作らない", "BLOCK", "## WAF の修正提案の候補 (proposals)", `"proposals"`} {
		if !strings.Contains(sys, want) {
			t.Fatalf("the proposals system must contain %q:\n%s", want, sys)
		}
	}
	if strings.Contains(sys, "## 相関付け") {
		t.Fatal("the proposals system embeds only the proposals section of docs/ai/report.md")
	}
	checkGolden(t, "proposals_llm.txt", strings.ReplaceAll(s.got[1].text, dir, "<dir>"))
}

// LLM の出力の検査: 知らない id・重複は捨て、BLOCK に強める記述を含む項目は捨てて規則の行にする。
// ``` を含む設定例は例だけ捨てる (コードブロックを抜けさせない)。漏れた候補は規則の行で補う。LLM の文字列もエスケープする。
func TestProposalsLLMOutputIsChecked(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	l := &fakeLLM{responses: []string{fixture(t, "ok.json"), fixture(t, "proposals_mixed.json")}}
	s := &fakeSender{}
	res, logs := run(t, dir, s, withLLM(l))
	if res.Exit != ExitOK || len(s.got) != 2 {
		t.Fatalf("%+v", res)
	}
	text := s.got[1].text
	for _, no := range []string{"BLOCK に切り替える", "Block", "rm -rf", "候補に無い提案", "2 件目", "<!channel>"} {
		if strings.Contains(text, no) {
			t.Fatalf("must not contain %q:\n%s", no, text)
		}
	}
	for _, want := range []string{"何を: レート制限を足す &lt;!channel&gt;", "何を: rate-login の limit を見直す"} {
		if !strings.Contains(text, want) {
			t.Fatalf("must contain %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "何を:"); n != 2 {
		t.Fatalf("only p3 and p4 are written up by the LLM, got %d:\n%s", n, text)
	}
	// 規則の行は全候補ぶんある (LLM の書き起こしが捨てられても候補は消えない)
	for _, k := range []string{"*[false_positive", "*[probe_allowed", "*[rate_limit_missing", "*[rate_limit_loose", "*[unused_rule"} {
		if strings.Count(text, k) != 1 {
			t.Fatalf("%s must appear once:\n%s", k, text)
		}
	}
	if !strings.Contains(logs.String(), CodeLLMProposalRejected) {
		t.Fatalf("rejected writeups must be logged: %s", logs)
	}
}

// 提案の書き起こしだけが失敗したら (再試行 1 回の後)、none の書式に縮退して冒頭に注記する。本文の要約は成功しているので終了コードは 0。
func TestProposalsLLMFailureFallsBack(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	l := &fakeLLM{responses: []string{fixture(t, "ok.json"), "not json", "error"}}
	s := &fakeSender{}
	res, logs := run(t, dir, s, withLLM(l))
	if res.Exit != ExitOK || l.calls != 3 || len(s.got) != 2 {
		t.Fatalf("%+v calls %d", res, l.calls)
	}
	if !strings.Contains(logs.String(), CodeLLMProposalsFailed) || !strings.Contains(logs.String(), CodeLLMRetry) {
		t.Fatalf("%s", logs)
	}
	text := s.got[1].text
	if !strings.Contains(text, ProposalsFallbackNotice) || strings.Contains(text, "何を:") || !strings.Contains(text, "[false_positive") {
		t.Fatalf("%s", text)
	}
}

// 本文の要約が失敗したら (LLM が使えない)、提案の書き起こしは呼ばずに none の書式で送る。終了コードは 3 のまま。
func TestProposalsNotWrittenUpWhenSummaryFails(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	l := &fakeLLM{responses: []string{"error"}}
	s := &fakeSender{}
	res, _ := run(t, dir, s, withLLM(l))
	if res.Exit != ExitFallback || l.calls != 2 || len(s.got) != 2 || strings.Contains(s.got[1].text, "何を:") {
		t.Fatalf("%+v calls %d", res, l.calls)
	}
}

// 静かな run で本文の要約を呼ばないときも、提案の書き起こしは LLM で行う。
func TestProposalsLLMOnQuietRun(t *testing.T) {
	var r schema.Report
	if err := json.Unmarshal(quietReport(t), &r); err != nil {
		t.Fatal(err)
	}
	l := &fakeLLM{responses: []string{fixture(t, "proposals_ok.json")}}
	s := &fakeSender{}
	res, _ := run(t, inputDir(t, withProposals(t, &r, testProposals(t)), ""), s, withLLM(l))
	if res.Exit != ExitOK || l.calls != 1 || len(s.got) != 2 || !strings.Contains(s.got[1].text, "何を:") {
		t.Fatalf("%+v calls %d", res, l.calls)
	}
}

// アプリの事情 (context_file) は、要約と提案の書き起こしの両方の system に「この監査対象の前提」として入る。
func TestContextIsGivenToBothPrompts(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	l := &fakeLLM{responses: []string{fixture(t, "ok.json"), fixture(t, "proposals_ok.json")}}
	s := &fakeSender{}
	ctxText := "- 決済画面 /checkout/* はリクエストが多いのが仕様"
	run(t, dir, s, withLLM(l), func(o *Options) { o.Context = ctxText })
	if len(l.systems) != 2 {
		t.Fatalf("calls %d", len(l.systems))
	}
	for i, sys := range l.systems {
		if !strings.Contains(sys, "この監査対象の前提") || !strings.Contains(sys, ctxText) {
			t.Fatalf("system %d must include the context:\n%s", i, sys)
		}
	}
	// 前提が無ければ節も出さない
	l2 := &fakeLLM{responses: []string{fixture(t, "ok.json"), fixture(t, "proposals_ok.json")}}
	run(t, inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), ""), &fakeSender{}, withLLM(l2))
	for _, sys := range l2.systems {
		if strings.Contains(sys, "この監査対象の前提") {
			t.Fatal("no context, no section")
		}
	}
}

// 3,800 文字を超えたら、設定例 → LLM の文 の順に削る。候補の規則の行は残す。
func TestProposalsLongTextIsTrimmed(t *testing.T) {
	ps := testProposals(t)
	var writeups []string
	for i := range 5 {
		long := strings.Repeat("長い説明。", 30)
		writeups = append(writeups, fmt.Sprintf(`{"id":"p%d","what":%q,"why":%q,"how":%q,"example":%q}`, i+1, long, long, long, strings.Repeat("{\"Count\": {}}\n", 19)))
	}
	resp := `{"proposals":[` + strings.Join(writeups, ",") + `]}`
	l := &fakeLLM{responses: []string{fixture(t, "ok.json"), resp}}
	s := &fakeSender{}
	run(t, inputDir(t, withProposals(t, goldenRun(t), ps), ""), s, withLLM(l))
	text := s.got[1].text
	if n := utf8.RuneCountInString(text); n > MaxTextRunes || !utf8.ValidString(text) {
		t.Fatalf("%d runes", n)
	}
	if strings.Contains(text, "設定例") {
		t.Fatalf("examples are trimmed first:\n%s", text)
	}
	for _, k := range []string{"*[false_positive", "*[probe_allowed", "*[rate_limit_missing", "*[rate_limit_loose", "*[unused_rule"} {
		if !strings.Contains(text, k) {
			t.Fatalf("%s must remain:\n%s", k, text)
		}
	}
}
