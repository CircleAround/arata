package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/report/schema"
)

// ファズテスト (ADR 0041)。LLM の出力・ログ由来の値・report.json を信用しない入力として与え、
// パニックしないことと、規則で固定した守り (ADR 0037) が入力に依らず残ることを確かめる。
// ふだんの `go test` は seed (f.Add と testdata/fuzz) だけを走らせる。探索は `go test -fuzz` (CI の fuzz.yml)。

// fuzzRules はメンションを付けない設定 (設定に書いた <!channel> は検査の対象ではないため)。
var fuzzRules = Rules{Name: "acme", MaxAge: 26 * time.Hour, UrgentSeverity: "high", OnQuiet: "short"}

// invisible は通知に出てはいけない文字 (改行以外の制御文字、向きの制御・ゼロ幅、行と段落の区切り)。
func invisible(r rune, allowTab bool) bool {
	switch {
	case r == '\n', r == '\t' && allowTab:
		return false
	case r == '\u2028', r == '\u2029':
		return true
	}
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// inertProblems は Slack に出す文字列が守りを破っていれば、その内容を返す。
//   - < > が残っていない (メンション・リンクの書式にならない)。規則の文言の `<check>` だけは除く
//   - 目に見えない文字が無い (allowTab は設定例のコードブロックがある書式だけ)
func inertProblems(name, s string, allowTab bool) []string {
	var out []string
	if rest := strings.ReplaceAll(s, "playbook <check>", ""); strings.ContainsAny(rest, "<>") {
		out = append(out, fmt.Sprintf("%s: エスケープされていない < > がある: %q", name, s))
	}
	for _, r := range s {
		if invisible(r, allowTab) {
			out = append(out, fmt.Sprintf("%s: 目に見えない文字 %U がある: %q", name, r, s))
			break
		}
	}
	return out
}

// llmTextProblems は LLM の文が載る通知に URL・メンションが残っていれば返す (規則の文言と seed の report.json には無い)。
func llmTextProblems(name, s string) []string {
	var out []string
	if llmLink.MatchString(s) {
		out = append(out, fmt.Sprintf("%s: URL が残っている: %q", name, s))
	}
	if llmMention.MatchString(s) {
		out = append(out, fmt.Sprintf("%s: メンションが残っている: %q", name, s))
	}
	return out
}

// limitProblems は Slack の Block Kit の上限 (checkLimits と同じ) を破っていれば返す。
func limitProblems(name string, m Message) []string {
	var out []string
	bad := func(format string, a ...any) { out = append(out, name+": "+fmt.Sprintf(format, a...)) }
	if m.Text == "" {
		bad("通知用の text が空")
	}
	if n := utf8.RuneCountInString(m.Text); n > maxNotifyRunes+1 {
		bad("通知用の text が %d 文字", n)
	}
	if len(m.Blocks) == 0 || len(m.Blocks) > MaxBlocks {
		bad("blocks が %d 個", len(m.Blocks))
	}
	for i, b := range m.Blocks {
		switch b.Type {
		case "header":
			if n := utf8.RuneCountInString(b.Text.Text); n == 0 || n > MaxHeaderRunes || b.Text.Type != "plain_text" {
				bad("block %d: header が %d 文字 (%s)", i, n, b.Text.Type)
			}
		case "section":
			if b.Text == nil && len(b.Fields) == 0 {
				bad("block %d: 空の section", i)
			}
			if b.Text != nil && (b.Text.Text == "" || utf8.RuneCountInString(b.Text.Text) > MaxSectionRunes) {
				bad("block %d: section が %d 文字", i, utf8.RuneCountInString(b.Text.Text))
			}
			if len(b.Fields) > MaxFields {
				bad("block %d: fields が %d 個", i, len(b.Fields))
			}
			for _, f := range b.Fields {
				if n := utf8.RuneCountInString(f.Text); n == 0 || n > MaxFieldRunes {
					bad("block %d: field が %d 文字", i, n)
				}
			}
		case "context":
			if len(b.Elements) == 0 || len(b.Elements) > 10 {
				bad("block %d: context の要素が %d 個", i, len(b.Elements))
			}
			for _, e := range b.Elements {
				if n := utf8.RuneCountInString(e.Text); n == 0 || n > maxContextRunes {
					bad("block %d: context の要素が %d 文字", i, n)
				}
			}
		case "divider":
		default:
			bad("block %d: 知らない種類 %q", i, b.Type)
		}
		objs := append(append([]*TextObj{}, b.Fields...), b.Elements...)
		if b.Text != nil {
			objs = append(objs, b.Text)
		}
		for _, o := range objs {
			if o.Type == "mrkdwn" && !o.Verbatim {
				bad("block %d: verbatim でない mrkdwn", i)
			}
		}
	}
	if m.UnfurlLinks || m.UnfurlMedia {
		bad("リンクの展開が有効")
	}
	return out
}

// logProblems はログに書く理由 (捨てた項目) に、行を増やす文字や端末を操作する文字があれば返す。
func logProblems(rejected []string) []string {
	var out []string
	for _, s := range rejected {
		for _, r := range s {
			if r == '\n' || invisible(r, false) {
				out = append(out, fmt.Sprintf("捨てた理由に %U がある: %q", r, s))
				break
			}
		}
	}
	return out
}

func report(t *testing.T, problems ...[]string) {
	t.Helper()
	for _, ps := range problems {
		for _, p := range ps {
			t.Error(clipRunes(p, 1500))
		}
	}
}

func readFile(f *testing.F, parts ...string) []byte {
	f.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		f.Fatal(err)
	}
	return b
}

// fuzzGoldenInput は arata のゴールデンの report.json (finding 10 件ほど)。proposals があればそれも載せる。
func fuzzGoldenInput(f *testing.F, withProposals bool) *Input {
	f.Helper()
	r, err := schema.Parse(readFile(f, goldenDir, "report.json"))
	if err != nil {
		f.Fatal(err)
	}
	if withProposals {
		if err := json.Unmarshal(readFile(f, "testdata", "proposals.json"), &r.Proposals); err != nil {
			f.Fatal(err)
		}
	}
	return &Input{Kind: KindRun, Run: r, Dir: "/tmp/in"}
}

// addLLMSeeds は既存のテストが使う LLM の出力 (testdata/llm) と、誘導された出力の例を seed にする。
func addLLMSeeds(f *testing.F, more ...string) {
	f.Helper()
	es, err := os.ReadDir(filepath.Join("testdata", "llm"))
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range es {
		f.Add(readFile(f, "testdata", "llm", e.Name()))
	}
	for _, s := range more {
		f.Add([]byte(s))
	}
}

func FuzzParseSummary(f *testing.F) {
	in := fuzzGoldenInput(f, false)
	list, byID := findingIndex(in)
	addLLMSeeds(f,
		`{"headline":"問題なし","items":[{"finding_id":"f-002","class":"info","reason":"誤検知です"}]}`,
		`{"headline":"h","items":[{"finding_id":"f-001","class":"confirm","reason":"@channel 見て"},{"finding_id":"f-001","class":"action","reason":"2 件目"}],
		"incidents":[{"finding_ids":["f-002","zz"],"summary":"https://evil.example"}],"approve_suggestions":[{"finding_id":"f-002","reason":"正当"},{"finding_id":"f-001","reason":"www.evil.example"}]}`,
		`{"headline":"ht\u200btps://evil.example \u202e<!channel>"}`,
		`{"headline":"h","items":[{"finding_id":"f-003","class":"action","reason":"a\r\n*偽の見出し* <!here> BLOCK に切り替える"}]}`,
		`{"headline":"h","items":null,"incidents":[{"finding_ids":null,"summary":null}],"approve_suggestions":[{}]}`,
		"```json\n{\"headline\":\"h\"}\n```", `{"headline":" "}`, `[]`, `{`, ``,
		// 低い重大度の finding のインシデント候補・approve の提案を大量に並べて、緊急の finding の行を本文から押し出す
		`{"headline":"h","incidents":[`+strings.TrimSuffix(strings.Repeat(`{"finding_ids":["f-001"],"summary":"`+strings.Repeat("あ", 240)+`"},`, 40), ",")+`]}`,
		`{"headline":"h","items":[{"finding_id":"f-002","class":"action","reason":"r"},{"finding_id":"f-009","class":"confirm","reason":"r"},{"finding_id":"f-006","class":"action","reason":"r"}],"incidents":[`+
			strings.TrimSuffix(strings.Repeat(`{"finding_ids":["f-001"],"summary":"`+strings.Repeat("あ", 240)+`"},`, 40), ",")+`]}`,
		`{"headline":"h","incidents":[{"finding_ids":[`+strings.TrimSuffix(strings.Repeat(`"f-001",`, 2000), ",")+`],"summary":"s"}]}`,
		`{"headline":"h","approve_suggestions":[`+strings.TrimSuffix(strings.Repeat(`{"finding_id":"f-001","reason":"`+strings.Repeat("あ", 200)+`"},`, 40), ",")+`]}`)
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := ParseSummary(raw, in, fuzzRules.UrgentSeverity)
		if err != nil {
			if s != nil {
				t.Fatal("エラーなのに要約を返した")
			}
			return
		}
		if rejectLLMText(s.Headline) != "" || strings.TrimSpace(s.Headline) == "" {
			t.Errorf("見出しが検査を通っていない: %q", s.Headline)
		}
		seen := map[string]bool{}
		for _, it := range s.Items {
			f, ok := byID[it.FindingID]
			if !ok || seen[it.FindingID] || classLabel(it.Class) == "" {
				t.Errorf("知らない・重複した・分類の無い item: %+v", it)
			}
			seen[it.FindingID] = true
			if rejectLLMText(it.Reason) != "" {
				t.Errorf("理由が検査を通っていない: %+v", it)
			}
			if it.Class == "info" && f.required && atLeast(f.severity, fuzzRules.UrgentSeverity) {
				t.Errorf("重大度の床が効いていない: %+v", it)
			}
		}
		for _, inc := range s.Incidents {
			if len(inc.FindingIDs) == 0 || rejectLLMText(inc.Summary) != "" {
				t.Errorf("インシデント候補が検査を通っていない: %+v", inc)
			}
			for _, id := range inc.FindingIDs {
				if _, ok := byID[id]; !ok {
					t.Errorf("インシデント候補に知らない id: %q", id)
				}
			}
		}
		for _, sg := range s.ApproveSuggestions {
			f, ok := byID[sg.FindingID]
			if !ok || atLeast(f.severity, fuzzRules.UrgentSeverity) || rejectLLMText(sg.Reason) != "" {
				t.Errorf("approve の提案が検査を通っていない: %+v", sg)
			}
		}
		// 欠落の補完: new / changed / recurred は items か「要約に含まれていなかった指摘」のどちらかに必ずある
		missing := map[string]bool{}
		for _, m := range s.Missing(in) {
			missing[m.id] = true
		}
		for _, f := range list {
			if f.required && seen[f.id] == missing[f.id] {
				t.Errorf("%s: items=%v missing=%v", f.id, seen[f.id], missing[f.id])
			}
		}
		report(t, logProblems(s.Rejected))

		text := SummaryText(in, Decision{Route: RouteUrgent}, fuzzRules, nil, s)
		report(t, inertProblems("SummaryText", text, false), llmTextProblems("SummaryText", text))
		if n := utf8.RuneCountInString(text); n > MaxTextRunes {
			t.Errorf("本文が %d 文字 (上限 %d)", n, MaxTextRunes)
		}
		// LLM が何を書いても、緊急の finding の行 (重大度と概要は report.json の値) は本文に残る
		for _, f := range list {
			if !f.required || !atLeast(f.severity, fuzzRules.UrgentSeverity) {
				continue
			}
			if want := fmt.Sprintf("*[%s]* %s", Escape(f.severity), Escape(oneLine(f.summary))); !strings.Contains(text, want) {
				t.Errorf("緊急の finding %s が本文に無い:\n%s", f.id, text)
			}
		}
		if !strings.Contains(text, LLMNotice) {
			t.Errorf("LLM の文である注記が無い:\n%s", text)
		}
	})
}

func FuzzParseBlockNotes(f *testing.F) {
	in := fuzzGoldenInput(f, false)
	top, _ := splitUrgent(in, fuzzRules.UrgentSeverity)
	if len(top) == 0 {
		f.Fatal("「まず対応」の finding が無い")
	}
	allowed := map[string]findingRef{}
	for _, t := range top {
		allowed[t.id] = t
	}
	addLLMSeeds(f,
		`{"summary":"root の利用が 2 件あります。","next":[{"finding_id":"f-002","action":"→ root の利用者に確認する"},{"finding_id":"f-002","action":"2 件目"},{"finding_id":"f-001","action":"まず対応ではない"}]}`,
		`{"summary":"s","next":[{"finding_id":"f-002","action":"@here 実行"},{"finding_id":"f-009","action":"BLOCK に設定する"},{"finding_id":"f-003","action":"a\r\nb\u202e<!channel>"}]}`,
		`{"summary":"https://evil.example を開く"}`, `{"summary":"s\u2028*偽の行*","next":[{}]}`, `{"summary":"s","next":null}`, `{}`, ``)
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := ParseBlockNotes(raw, top)
		if err != nil {
			if n != nil {
				t.Fatal("エラーなのに結果を返した")
			}
			return
		}
		if rejectLLMText(n.Summary) != "" || strings.TrimSpace(n.Summary) == "" {
			t.Errorf("要約が検査を通っていない: %q", n.Summary)
		}
		for id, a := range n.Next {
			if _, ok := allowed[id]; !ok {
				t.Errorf("「まず対応」に無い id: %q", id)
			}
			if a == "" || a != oneLine(a) || rejectLLMText(a) != "" || utf8.RuneCountInString(a) > maxActionRunes+1 {
				t.Errorf("「→」が検査を通っていない: %q", a)
			}
		}
		report(t, logProblems(n.Rejected))
		m := RunBlocks(in, Decision{Route: RouteUrgent}, fuzzRules, nil, n, "")
		text := allText(m)
		report(t, limitProblems("RunBlocks", m), inertProblems("RunBlocks", text, false), inertProblems("text", m.Text, false), llmTextProblems("RunBlocks", text))
		for _, f := range top {
			if want := "*" + Escape(oneLine(f.summary)) + "*"; !strings.Contains(text, want) {
				t.Errorf("「まず対応」の finding %s が無い:\n%s", f.id, text)
			}
		}
		if !strings.Contains(text, LLMNotice) {
			t.Errorf("LLM の文である注記が無い:\n%s", text)
		}
	})
}

// fenceLines は ``` だけの行の数 (コードブロックの開始と終了)。
func fenceLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "```") {
			n++
		}
	}
	return n
}

// outline は Markdown のコードブロックの外にある見出しと箇条書きの先頭 (構成)。LLM の文で構成が変わらないことを見る。
func outline(md string) []string {
	var out []string
	inFence := false
	for _, l := range strings.Split(md, "\n") {
		switch {
		case strings.HasPrefix(l, "```"):
			inFence = !inFence
		case inFence:
		case strings.HasPrefix(l, "#"):
			out = append(out, l)
		}
	}
	return out
}

func FuzzParseWriteups(f *testing.F) {
	in := fuzzGoldenInput(f, true)
	props, _, _ := splitProposals(in.Run.Proposals)
	known := map[string]bool{}
	for i := range props {
		known[proposalID(i)] = true
	}
	baseOutline := strings.Join(outline(ProposalsMarkdown(in, nil, "")), "\n")
	addLLMSeeds(f,
		`{"proposals":[{"id":"p1","what":"w","why":"y","how":"BLOCK に設定する","example":"","next":"n"},{"id":"p2","example":"{\"Action\":\"BLOCK\"}"},{"id":"p9","what":"知らない id"}]}`,
		"{\"proposals\":[{\"id\":\"p1\",\"what\":\"w\",\"example\":\"a\\n```\\n*偽の見出し*\"},{\"id\":\"p1\",\"what\":\"2 件目\"}]}",
		`{"proposals":[{"id":"p1","what":"a\r\n## 偽の見出し","why":"\u202e<!channel>","how":"ht\u200btps://evil.example","example":"\t{\"Action\": {\"Count\": {}}}\r\n## 偽の見出し","next":"→ @here"}]}`,
		`{"proposals":[{"id":"p2","example":"{\"Act\u200bion\":\"BL\u200bOCK\"}"},{"id":"p3","example":"\u0060\u200b\u0060\u0060\n## x"}]}`,
		`{"proposals":null}`, `{"proposals":[{}]}`, `{}`, ``)
	f.Fuzz(func(t *testing.T, raw []byte) {
		ws, rejected, err := ParseWriteups(raw, props)
		if err != nil {
			if ws != nil {
				t.Fatal("エラーなのに結果を返した")
			}
			return
		}
		for id, w := range ws {
			if !known[id] || w.ID != id {
				t.Errorf("知らない id: %q %+v", id, w)
			}
			if why := rejectWriteup(w); why != "" {
				t.Errorf("書き起こしが検査を通っていない (%s): %+v", why, w)
			}
			// 設定例は改行を残すので、目に見えない文字を挟んで検査をすり抜けていないかを、除いた形でも見る
			visible := strings.Map(func(r rune) rune {
				if invisible(r, true) {
					return -1
				}
				return r
			}, w.Example)
			if strings.Contains(visible, "```") || blockAction.MatchString(visible) {
				t.Errorf("設定例が検査をすり抜けた: %q", w.Example)
			}
		}
		report(t, logProblems(rejected))

		text := ProposalsText(in, nil, ws, "")
		report(t, inertProblems("ProposalsText", text, true))
		if n := utf8.RuneCountInString(text); n > MaxTextRunes {
			t.Errorf("本文が %d 文字 (上限 %d)", n, MaxTextRunes)
		}
		if n := fenceLines(text); n%2 != 0 {
			t.Errorf("コードブロックが閉じていない (``` が %d 行):\n%s", n, text)
		}
		m := ProposalsBlocks(in, nil, ws, "", "/tmp/in/"+ProposalsMD)
		bt := allText(m)
		report(t, limitProblems("ProposalsBlocks", m), inertProblems("ProposalsBlocks", bt, false), inertProblems("text", m.Text, false), llmTextProblems("ProposalsBlocks", bt))
		// 規則の行 (種類・数字) は LLM の文に依らず全部の提案について残る
		for _, p := range props {
			if want := "*" + Escape(kindLabel(p.Kind)) + "*"; !strings.Contains(bt, want) {
				t.Errorf("提案 %s の行が無い:\n%s", p.Kind, bt)
			}
		}
		// waf-proposals.md: LLM の文で見出しを足せない。端末を操作する制御文字を書かない
		md := ProposalsMarkdown(in, ws, "")
		if got := strings.Join(outline(md), "\n"); got != baseOutline {
			t.Errorf("waf-proposals.md の構成が LLM の文で変わった:\n%s\n--- 規則だけのとき:\n%s", got, baseOutline)
		}
		for _, r := range md {
			if invisible(r, true) {
				t.Errorf("waf-proposals.md に目に見えない文字 %U がある: %q", r, md)
				break
			}
		}
	})
}

// fuzzSender は送った通知を集める (実 Slack には接続しない)。
type fuzzSender struct{ got []Message }

func (s *fuzzSender) Send(_ context.Context, _ Route, m Message) error {
	s.got = append(s.got, m)
	return nil
}

// report.json は arata が書くが、中の値はログに由来する。壊れた・想定外の形でも、通知の本体はパニックせず、
// Slack の上限を守り、< > をエスケープして送る (provider: none。LLM を呼ばない)。
func FuzzRunWithReport(f *testing.F) {
	f.Add(readFile(f, goldenDir, "report.json"))
	for _, name := range []string{"period.json", "monthly.json", "report_period.json"} {
		if b, err := os.ReadFile(filepath.Join(goldenDir, name)); err == nil {
			f.Add(b)
		}
	}
	in := fuzzGoldenInput(f, true)
	b, err := json.Marshal(in.Run)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	hostileJSON, err := json.Marshal(hostileReport().Run)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(strings.Replace(string(hostileJSON), "{", `{"generated_at":"2026-10-21T09:00:00Z",`, 1)))
	f.Add([]byte(`{"kind":"period","generated_at":"2026-10-21T09:00:00Z","name":"acme","events":{"new":[{"finding_id":"f1","check":"probe_paths","key":"<!channel>","severity":"high","summary":"s"}]},"runs_missing":[{"profile":"daily","kind":"missing","at":"x"}]}`))
	f.Add([]byte(`{"generated_at":"2026-10-21T09:00:00Z","name":"acme","profile":"daily","summary":{"new":0}}`))
	f.Add([]byte(`{"generated_at":"2026-10-21T09:00:00Z","findings":{"new":[{"id":"a","check":"endpoint_abuse","key":"a>b","severity":"low","data":{"ips":1e300,"window":"10m"}},{"id":"b","check":"credential_hygiene","key":"no_mfa","data":null}]},"proposals":[{"kind":"probe_allowed","evidence":{"paths":["/.env",1,null]}},{"kind":"observation","about":"challenge_impact"}]}`))
	f.Add([]byte(`{"kind":"unknown"}`))
	// 名前・プロファイル・kind・時刻が極端に長くても、どの通知も Slack の上限に収まる
	long := strings.Repeat("長い名前", 1200)
	f.Add([]byte(`{"kind":"` + long + `"}`))
	f.Add([]byte(`{"generated_at":"` + long + `"}`))
	f.Add([]byte(`{"generated_at":"2026-10-21T09:00:00Z","name":"` + long + `","profile":"` + long + `","window":{"from":"` + long + `"}}`))
	f.Add([]byte(`{"generated_at":"2026-10-21T09:00:00Z","name":"` + long + `","profile":"` + long + `","summary":{"new":1,"max_severity":"` + long + `"},"proposals":[{"kind":"unused_rule"}],"coverage":{"sources_failed":[{"source":"` + long + `"}]}}`))
	f.Add([]byte(`{"kind":"period","generated_at":"2026-10-21T09:00:00Z","name":"` + long + `","period":{"from":"` + long + `"}}`))
	f.Add([]byte(`null`))

	dir, err := os.MkdirTemp("", "aratam-fuzz-*")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { os.RemoveAll(dir) })
	f.Fuzz(func(t *testing.T, reportJSON []byte) {
		if err := os.WriteFile(filepath.Join(dir, ReportJSON), reportJSON, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Remove(filepath.Join(dir, ReportMD))
		for _, format := range []string{FormatText, FormatBlocks} {
			s := &fuzzSender{}
			res := Run(context.Background(), Options{Dir: dir, Now: now, Rules: fuzzRules, Sender: s, Format: format, Force: true, DryRun: true})
			if res.Sent != (len(s.got) > 0) {
				t.Errorf("%s: Sent=%v なのに %d 通", format, res.Sent, len(s.got))
			}
			for i, m := range s.got {
				name := fmt.Sprintf("%s[%d]", format, i)
				if format == FormatBlocks {
					report(t, limitProblems(name, m))
				} else if n := utf8.RuneCountInString(m.Text); n == 0 || n > MaxTextRunes {
					t.Errorf("%s: 本文が %d 文字 (上限 %d)", name, n, MaxTextRunes)
				}
				// 入力の問題の通知は、設定のディレクトリ名 (一時ディレクトリ) を含むだけで、検査は同じ
				if rest := strings.ReplaceAll(m.Text+"\n"+allText(m), "playbook <check>", ""); strings.ContainsAny(rest, "<>") {
					t.Errorf("%s: エスケープされていない < > がある: %q", name, rest)
				}
			}
		}
	})
}

// ログ由来の値 (パス・IP・JSON のログの項目) がどんな文字列でも、通知の行を増やせず、目に見えない文字も < > も残らない。
// TestLogValuesStayInert の固定値を任意の文字列に広げたもの。
func FuzzLogValuesStayInert(f *testing.F) {
	for _, s := range []string{hostile, "/users/sign_in", "203.0.113.1", "a|b|c", "x\ny", "`code` *bold* _i_ ~s~", "\u2028## 見出し", "&lt;!channel&gt;", "→ 偽の一手", "\t", ""} {
		f.Add(s)
	}
	build := func(v string) *Input {
		r := &schema.Report{Name: "acme", Profile: "daily", RunID: "r1"}
		for i, c := range []struct{ check, sev string }{{"probe_paths", "low"}, {"login_bruteforce", "low"}, {"root_usage", "critical"}, {"waf_block_trend", "medium"}, {"new_principal", "low"}} {
			r.Findings.New = append(r.Findings.New, schema.Finding{ID: fmt.Sprintf("f%d", i), Check: c.check, Key: v, Severity: c.sev, Summary: v,
				Data: map[string]any{"ip": v, "rule": v, "top_paths_of_day": []any{v, v}, "ips": []any{v}, "event_names": []any{v}, "external_account": v}})
		}
		r.Summary.New, r.Summary.MaxSeverity = len(r.Findings.New), "critical"
		r.Proposals = []schema.Proposal{
			{Kind: "false_positive", Stage: "count_first", WebACL: "acl", Rule: "r", Method: v, Path: v, Summary: v, Evidence: map[string]any{"count": 1.0, "path_group": v}},
			{Kind: "probe_allowed", Stage: "count_first", WebACL: "acl", Summary: v, Evidence: map[string]any{"count": 2.0, "paths": []any{v, v}}},
			{Kind: "rate_limit_missing", Stage: "count_first", WebACL: "acl", Summary: v, Evidence: map[string]any{"path_group": v}},
			{Kind: kindObservation, About: "false_positive", Reason: "below_threshold", Method: v, Path: v, Summary: v},
			{Kind: kindObservation, About: aboutCountRule, Summary: v},
		}
		return &Input{Kind: KindRun, Run: r, Dir: "/tmp/in"}
	}
	// 期間レポートは report.md (arata が同じ値から書く) を整形して送る
	buildPeriod := func(v string) *Input {
		p := &schema.PeriodReport{Kind: "period", Name: "acme"}
		e := schema.EventRow{At: "2026-10-21T09:00:00Z", FindingID: "f1", Check: "probe_paths", Key: v, Severity: "high", Summary: v}
		p.Events.New, p.Events.Resolved = []schema.EventRow{e}, []schema.EventRow{e}
		p.Open = []schema.Finding{{ID: "f2", Check: "probe_paths", Key: v, Severity: "low", Summary: v}}
		p.NewPrincipals = []schema.PrincipalRow{{Label: v}}
		p.Summary.New = 1
		return &Input{Kind: KindPeriod, Period: p, Dir: "/tmp/in", Markdown: p.Markdown()}
	}
	d := Decision{Route: RouteUrgent}
	render := func(in *Input) map[string]string {
		if in.Period != nil {
			blocks := RunBlocks(in, d, fuzzRules, nil, nil, "")
			return map[string]string{
				"period/ReportText":     ReportText(in, d, fuzzRules, nil, ""),
				"period/SummaryText":    SummaryText(in, d, fuzzRules, nil, &Summary{Headline: "h"}),
				"period/RunBlocks":      allText(blocks),
				"period/RunBlocks.text": blocks.Text,
			}
		}
		blocks, pblocks := RunBlocks(in, d, fuzzRules, nil, nil, ""), ProposalsBlocks(in, nil, nil, "", "/tmp/in/"+ProposalsMD)
		return map[string]string{
			"ReportText":        ReportText(in, d, fuzzRules, nil, ""),
			"SummaryText":       SummaryText(in, d, fuzzRules, nil, &Summary{Headline: "h"}),
			"RunBlocks":         allText(blocks),
			"RunBlocks.text":    blocks.Text,
			"ProposalsText":     ProposalsText(in, nil, nil, ""),
			"ProposalsBlocks":   allText(pblocks),
			"ProposalsMarkdown": ProposalsMarkdown(in, nil, ""),
		}
	}
	// 値が 1 文字のときの行数が基準。値を変えても行数は変わらない (切り詰めが起きない長さで比べる)
	base := render(build("x"))
	for k, v := range render(buildPeriod("x")) {
		base[k] = v
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := render(build(v))
		for k, s := range render(buildPeriod(v)) {
			got[k] = s
		}
		short := utf8.RuneCountInString(v) <= 40 && oneLine(v) != ""
		for name, s := range got {
			if name == "ProposalsMarkdown" {
				for _, r := range s {
					if invisible(r, false) {
						t.Errorf("%s: 目に見えない文字 %U がある: %q", name, r, s)
						break
					}
				}
			} else {
				report(t, inertProblems(name, s, false))
			}
			if short && strings.Count(s, "\n") != strings.Count(base[name], "\n") {
				t.Errorf("%s: ログの値で行数が変わった (%d → %d):\n%s", name, strings.Count(base[name], "\n"), strings.Count(s, "\n"), s)
			}
		}
		report(t, limitProblems("RunBlocks", RunBlocks(build(v), d, fuzzRules, nil, nil, "")))
	})
}

// oneLine と Escape は通知の守りの土台。出力に改行・目に見えない文字・< > が残らず、2 度かけても変わらない。
func FuzzOneLineAndEscape(f *testing.F) {
	for _, s := range []string{hostile, "a\u202eb\u200b\x07 c\nd", " a  b ", "a\u00a0b", "<!channel> & <http://evil.example|x>", "\xff\xfe", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		one := oneLine(s)
		for _, r := range one {
			if r == '\n' || invisible(r, false) {
				t.Fatalf("oneLine(%q) に %U が残った: %q", s, r, one)
			}
		}
		if again := oneLine(one); again != one {
			t.Fatalf("oneLine が冪等でない: %q → %q → %q", s, one, again)
		}
		if one != strings.TrimSpace(one) {
			t.Fatalf("oneLine の前後に空白が残った: %q", one)
		}
		esc := Escape(s)
		if strings.ContainsAny(esc, "<>") {
			t.Fatalf("Escape(%q) に < > が残った: %q", s, esc)
		}
		if back := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&").Replace(esc); back != s {
			t.Fatalf("Escape が元に戻らない (二重の解釈の余地がある): %q → %q → %q", s, esc, back)
		}
		for _, n := range []int{1, 10, 200} {
			if c := clipRunes(s, n); utf8.RuneCountInString(c) > n+1 {
				t.Fatalf("clipRunes(%q, %d) が %d 文字", s, n, utf8.RuneCountInString(c))
			}
			if c := clipLines(s, n+2); utf8.RuneCountInString(c) > n+2 {
				t.Fatalf("clipLines(%q, %d) が %d 文字", s, n+2, utf8.RuneCountInString(c))
			}
		}
	})
}

// max_age などの長さ。受け入れた値は正で、日数は桁あふれで別の長さにならない。
func FuzzParseDuration(f *testing.F) {
	for _, s := range []string{"26h", "30d", "0d", "-1d", "1h30m", "d", "", "106751d", "106752d", "213504d", "-213504d", "9223372036854775807d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDuration(s)
		if err != nil {
			return
		}
		if d <= 0 {
			t.Fatalf("ParseDuration(%q) = %v: 正でない", s, d)
		}
		if n, ok := strings.CutSuffix(s, "d"); ok {
			if days, err := strconv.Atoi(n); err != nil || d/(24*time.Hour) != time.Duration(days) || d%(24*time.Hour) != 0 {
				t.Fatalf("ParseDuration(%q) = %v: 書いた日数と違う", s, d)
			}
		}
	})
}
