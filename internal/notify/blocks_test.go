package notify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/report/schema"
)

func withBlocks(o *Options) { o.Format = FormatBlocks }

func indentJSON(t *testing.T, m Message) string {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// checkLimits は Slack の Block Kit の上限 (blocks 50 個、section の text 3000 字、header 150 字、fields 10 個・各 2000 字) を確かめる。
func checkLimits(t *testing.T, m Message) {
	t.Helper()
	if m.Text == "" {
		t.Error("notification text is required with blocks")
	}
	if len(m.Blocks) == 0 || len(m.Blocks) > MaxBlocks {
		t.Fatalf("blocks: %d", len(m.Blocks))
	}
	for i, b := range m.Blocks {
		switch b.Type {
		case "header":
			if n := utf8.RuneCountInString(b.Text.Text); n == 0 || n > MaxHeaderRunes || b.Text.Type != "plain_text" {
				t.Errorf("block %d header: %d runes %q", i, n, b.Text.Type)
			}
		case "section":
			if b.Text == nil && len(b.Fields) == 0 {
				t.Errorf("block %d: empty section", i)
			}
			if b.Text != nil && utf8.RuneCountInString(b.Text.Text) > MaxSectionRunes {
				t.Errorf("block %d: section text %d runes", i, utf8.RuneCountInString(b.Text.Text))
			}
			if len(b.Fields) > MaxFields {
				t.Errorf("block %d: %d fields", i, len(b.Fields))
			}
			for _, f := range b.Fields {
				if utf8.RuneCountInString(f.Text) > MaxFieldRunes {
					t.Errorf("block %d: field %d runes", i, utf8.RuneCountInString(f.Text))
				}
			}
		case "context":
			if len(b.Elements) == 0 || len(b.Elements) > 10 {
				t.Errorf("block %d: %d context elements", i, len(b.Elements))
			}
		case "divider":
		default:
			t.Errorf("block %d: unknown type %q", i, b.Type)
		}
	}
}

func allText(m Message) string {
	var b strings.Builder
	for _, bl := range m.Blocks {
		if bl.Text != nil {
			b.WriteString(bl.Text.Text + "\n")
		}
		for _, f := range bl.Fields {
			b.WriteString(f.Text + "\n")
		}
		for _, e := range bl.Elements {
			b.WriteString(e.Text + "\n")
		}
	}
	return b.String()
}

// provider: none の Block Kit。high 以上 (urgent_severity) は「まず対応」に 1 件ずつ「→」付きで、それ未満は「確認推奨」。
func TestBlocksNone(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	s := &fakeSender{}
	res, _ := run(t, dir, s, withBlocks)
	if res.Exit != ExitOK || len(s.got) != 1 || s.got[0].route != RouteUrgent {
		t.Fatalf("%+v %+v", res, s.got)
	}
	m := s.got[0].msg
	checkLimits(t, m)
	checkGolden(t, "blocks_none.json", strings.ReplaceAll(indentJSON(t, m), dir, "<dir>"))
	checkGolden(t, "blocks_none.txt", strings.ReplaceAll(PlainText(m), dir, "<dir>"))
	// 緊急用を通常用へ送る設定 (rules の UrgentMention) なので、先頭にメンション
	if m.Blocks[0].Type != "section" || m.Blocks[0].Text.Text != "<!channel>" || m.Blocks[1].Type != "header" {
		t.Fatalf("mention first: %+v", m.Blocks[:2])
	}
	txt := allText(m)
	for _, want := range []string{"*まず対応*", "*確認推奨*", "→ ", "`arata review`"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func groupReport(t *testing.T) []byte {
	t.Helper()
	r := goldenRun(t)
	mk := func(id, check, key, sev, summary string, data map[string]any) schema.Finding {
		return schema.Finding{ID: id, Check: check, Key: key, Severity: sev, Summary: summary, FirstSeen: "2026-10-21T09:00:00Z", Data: data}
	}
	var fs []schema.Finding
	for i, u := range []string{"alice", "bob", "carol", "dave", "erin"} {
		fs = append(fs, mk(fmt.Sprintf("m-%d", i), "credential_hygiene", "no_mfa|"+u, "medium", u+" に MFA が無い", map[string]any{"user": u, "arn": "arn:aws:iam::123456789012:user/" + u}))
	}
	fs = append(fs,
		mk("k-1", "credential_hygiene", "unused_key|alice|1", "medium", "alice のキー 1 が使われていない", map[string]any{"user": "alice", "days_unused": float64(469)}),
		mk("k-2", "credential_hygiene", "unused_key|bob|2", "medium", "bob のキー 2 が使われていない", map[string]any{"user": "bob", "days_unused": float64(120)}),
		mk("g-1", "guardduty_findings", "gd-1", "high", "GuardDuty: インスタンスの認証情報が AWS の外で使われた", map[string]any{"type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"}),
		mk("n-1", "new_principal", "arn:aws:iam::111122223333:role/vendor-reader", "medium", "新しい主体", map[string]any{"count": float64(3), "external_account": "111122223333"}),
		mk("n-2", "new_principal", "arn:aws:iam::123456789012:user/deploy", "medium", "新しい主体", map[string]any{"count": float64(1)}),
	)
	r.Findings.New = fs
	r.Findings.Changed, r.Findings.Recurred = nil, nil
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.MaxSeverity = len(fs), 0, 0, "high"
	r.Coverage.SourcesFailed = nil
	return marshal(t, r)
}

// 同じチェック (と key の種類) の指摘は、対応表に従って 1 項目にまとめ、主体を `code` で並べる (規則。LLM に任せない)。
func TestBlocksGroupSameCheck(t *testing.T) {
	s := &fakeSender{}
	dir := inputDir(t, groupReport(t), "")
	run(t, dir, s, withBlocks)
	m := s.got[0].msg
	checkLimits(t, m)
	txt := allText(m)
	for _, want := range []string{
		"🟠 *MFA の無いコンソールユーザー* 5 人\n`alice` `bob` `carol` `dave` `erin`",
		"🟠 *使われていないアクセスキー* 2 本\n`alice` 469 日 ・ `bob` 120 日",
		"🟠 *新しく観測した主体* 2 件\n`role/vendor-reader` (111122223333) ・ `user/deploy`",
		"🔴 *GuardDuty: インスタンスの認証情報が AWS の外で使われた* `id: g-1`\n→ ",
		"🔴 high 1 ・ 🟠 medium 9",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "alice に MFA が無い") {
		t.Error("grouped findings must not be listed one by one")
	}
	checkGolden(t, "blocks_group.txt", strings.ReplaceAll(PlainText(m), dir, "<dir>"))
}

// ブロックが 50 個を超えるときは、後ろの項目を「ほか N 件は arata review」に縮める。件数は落とさない。
func TestBlocksManyFindingsAreCut(t *testing.T) {
	r := goldenRun(t)
	var fs []schema.Finding
	for i := range 120 {
		sev := "medium"
		if i%3 == 0 {
			sev = "high"
		}
		fs = append(fs, schema.Finding{ID: fmt.Sprintf("x-%03d", i), Check: fmt.Sprintf("custom_%03d", i), Key: "k", Severity: sev, Summary: fmt.Sprintf("指摘 %03d", i)})
	}
	r.Findings.New = fs
	r.Findings.Changed, r.Findings.Recurred = nil, nil
	r.Summary.New = len(fs)
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s, withBlocks)
	m := s.got[0].msg
	checkLimits(t, m)
	txt := allText(m)
	shown := strings.Count(txt, "*指摘 ")
	var rest int
	for _, l := range strings.Split(txt, "\n") {
		if strings.HasPrefix(l, "ほか ") {
			if _, err := fmt.Sscanf(l, "ほか %d 件", &rest); err != nil {
				t.Fatal(err)
			}
		}
	}
	if shown == 0 || rest == 0 || shown+rest != 120 {
		t.Fatalf("shown %d + rest %d != 120\n%s", shown, rest, txt)
	}
	if !strings.Contains(txt, "`arata review`") {
		t.Fatal("cut notice must point to arata review")
	}
	// high は「まず対応」に優先して残す
	if !strings.Contains(txt, "指摘 000") {
		t.Fatal("first urgent item must remain")
	}
}

// 長い文字列は上限で切る (header 150 字、section 3000 字)。report 由来の値はエスケープする。
func TestBlocksClipAndEscape(t *testing.T) {
	r := goldenRun(t)
	r.Name = strings.Repeat("名", 200)
	r.Findings.New[0].Summary = "<!channel> & <https://example.com|x> " + strings.Repeat("長", 5000)
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s, withBlocks, func(o *Options) { o.Rules.Name = r.Name; o.Rules.UrgentMention = "" })
	m := s.got[0].msg
	checkLimits(t, m)
	txt := allText(m)
	if strings.Contains(txt, "<!channel>") || !strings.Contains(txt, "&lt;!channel&gt; &amp;") {
		t.Fatalf("not escaped:\n%.300s", txt)
	}
	if strings.Contains(m.Text, "<!channel>") {
		t.Fatal("notification text must be escaped too")
	}
}

// 期間レポートも Block Kit (events は data を持たないので key から主体を並べる)。
func TestBlocksPeriod(t *testing.T) {
	dir := inputDir(t, golden(t, "period.json"), string(golden(t, "period.md")))
	s := &fakeSender{}
	res, _ := run(t, dir, s, withBlocks)
	if res.Exit != ExitOK || len(s.got) != 1 {
		t.Fatalf("%+v", res)
	}
	checkLimits(t, s.got[0].msg)
	checkGolden(t, "blocks_period.txt", strings.ReplaceAll(PlainText(s.got[0].msg), dir, "<dir>"))
}

// 静か・入力の問題も Block Kit。
func TestBlocksQuietAndInputProblem(t *testing.T) {
	s := &fakeSender{}
	run(t, inputDir(t, quietReport(t), ""), s, withBlocks)
	checkLimits(t, s.got[0].msg)
	if !strings.Contains(s.got[0].msg.Blocks[0].Text.Text, "✅") || !strings.Contains(allText(s.got[0].msg), "新規なし") {
		t.Fatalf("%+v", s.got[0].msg)
	}
	s = &fakeSender{}
	res, _ := run(t, inputDir(t, nil, ""), s, withBlocks)
	if res.Exit != ExitInput {
		t.Fatal(res)
	}
	m := s.got[0].msg
	checkLimits(t, m)
	if !strings.Contains(allText(m), "INPUT_MISSING") || !strings.Contains(m.Text, "監査結果を通知できません") {
		t.Fatalf("%s", allText(m))
	}
}

// 規則の「→」は playbook の対処の選択肢の先頭 (太字・コマンドを除き、最初の文まで、80 字まで)。
func TestRuleAction(t *testing.T) {
	if got := ruleAction("credential_hygiene"); got != "封じ込め (不審な使用がある): キーを無効化する" {
		t.Fatalf("%q", got)
	}
	for _, c := range ai.PlaybookNames() {
		a := ruleAction(c)
		if a == "" || utf8.RuneCountInString(a) > maxActionRunes+1 || strings.ContainsAny(a, "*`") {
			t.Errorf("%s: %q", c, a)
		}
	}
	if got := ruleAction("no_such_check"); got != "" {
		t.Fatalf("%q", got)
	}
}

// LLM は要約 1〜2 文と「まず対応」の「→」だけを書く。知らない ID・「まず対応」以外の ID は捨て、漏れは規則の「→」で補う。
func TestBlocksLLM(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	l := &fakeLLM{responses: []string{`前置き {"summary": "ルートの利用が 2 件 <!here>。引き受けの変化も 1 件。", "next": [
		{"finding_id": "f-002", "action": "ルートの利用者を確かめ、心当たりが無ければパスワードを変える"},
		{"finding_id": "f-002", "action": "重複は捨てる"},
		{"finding_id": "f-010", "action": "確認推奨の項目には書かない"},
		{"finding_id": "f-999", "action": "知らない ID"}]} 後書き`}}
	s := &fakeSender{}
	res, _ := run(t, dir, s, withBlocks, withLLM(l))
	if res.Exit != ExitOK || l.calls != 1 {
		t.Fatalf("%+v calls %d", res, l.calls)
	}
	m := s.got[0].msg
	checkLimits(t, m)
	txt := allText(m)
	for _, want := range []string{
		"ルートの利用が 2 件 &lt;!here&gt;。引き受けの変化も 1 件。",
		"→ ルートの利用者を確かめ、心当たりが無ければパスワードを変える",
		"→ " + ruleAction("root_usage"), // f-009 は LLM の出力に無いので規則
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q\n%s", want, txt)
		}
	}
	for _, bad := range []string{"重複は捨てる", "確認推奨の項目には書かない", "知らない ID"} {
		if strings.Contains(txt, bad) {
			t.Errorf("must drop %q", bad)
		}
	}
	// system は blocks の契約と、「まず対応」の ID の一覧、playbook
	for _, want := range []string{`"summary"`, `"next"`, "f-002", "f-003", "f-009", `<playbook check="root_usage">`} {
		if !strings.Contains(l.system, want) {
			t.Errorf("system lacks %q", want)
		}
	}
	if strings.Contains(l.system, `"approve_suggestions"`) {
		t.Error("blocks must not ask for the text contract")
	}
	checkGolden(t, "blocks_llm.txt", strings.ReplaceAll(PlainText(m), dir, "<dir>"))
}

// 形が合わない出力は 1 回だけ再試行し、だめなら規則で組み立てた Block Kit を送る (終了コード 3)。
func TestBlocksLLMFailureFallsBack(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	l := &fakeLLM{responses: []string{`{"next": []}`, "not json"}}
	s := &fakeSender{}
	res, _ := run(t, dir, s, withBlocks, withLLM(l))
	if res.Exit != ExitFallback || l.calls != 2 || len(s.got) != 1 {
		t.Fatalf("%+v calls %d", res, l.calls)
	}
	m := s.got[0].msg
	checkLimits(t, m)
	txt := allText(m)
	if !strings.Contains(txt, BlocksFallbackNotice) || !strings.Contains(txt, "→ "+ruleAction("root_usage")) {
		t.Fatalf("%s", txt)
	}
}

// WAF の改善提案の 2 通目も Block Kit。提案 1 件 = 見出し (種類 + 主な数字) と「→」の section と、根拠の context だけ。
// 規則の長い summary・設定例は Slack に出さず、全文は入力ディレクトリの waf-proposals.md に書いてパスを添える。
func TestBlocksProposals(t *testing.T) {
	ps := append(testProposals(t), schema.Proposal{Kind: "observation", About: "count_rule_status", Reason: "informational", Stage: "none", WebACL: "prod-waf",
		Rule: "AWS-AWSManagedRulesCommonRuleSet", RuleInGroup: "SizeRestrictions_BODY", Summary: "一致なし",
		Evidence: map[string]any{"matches": float64(0), "matching_days": float64(0), "days": float64(7)}})
	dir := inputDir(t, withProposals(t, goldenRun(t), ps), "")
	s := &fakeSender{}
	run(t, dir, s, withBlocks)
	if len(s.got) != 2 || s.got[1].route != RouteNormal {
		t.Fatalf("%+v", s.got)
	}
	m := s.got[1].msg
	checkLimits(t, m)
	checkGolden(t, "blocks_proposals.txt", strings.ReplaceAll(PlainText(m), dir, "<dir>"))
	txt := allText(m)
	for _, want := range []string{
		"🛡️ *探索パスが WAF を通過* — 14 件 / 7 日・2 パス\n設定ファイルや管理画面を探す通信が WAF を素通りしている (7 日で 14 件)\n" +
			"→ WebACL `prod-waf` に、`/.env`・`/.git/config` を URI で照合するルールを COUNT で追加し、1〜2 週間、正規の通信が一致しないかを見る",
		"→ WebACL `prod-waf` のルール `CrossSiteScripting_BODY` を、`POST /posts/:id` に限って COUNT にする",
		"→ WebACL `prod-waf` に、`/api/*` を対象とする limit 100 / 5 分 (IP 単位) のレートベースのルールを COUNT で追加し",
		"→ WebACL `prod-waf` のルール `rate-login` の limit を 1000 から 100 / 5 分に変えるかを、`/login` の観測 (最大 9・p99 4) と照らして見直す",
		"/.env 13・/.git/config 1",
		"🛡️ *誤検知の疑い* — `CrossSiteScripting_BODY` が POST /posts/:id で 250 件 / 7 日",
		"• `AWS-AWSManagedRulesKnownBadInputsRuleSet` 140 件・怪しい 100%・7/7 日",
		"• 一致なし: `SizeRestrictions_BODY`",
		"設定例と詳しい説明: `" + filepath.Join(dir, ProposalsMD) + "`",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q\n%s", want, txt)
		}
	}
	// 規則の長い summary は出さない
	for _, no := range []string{"→ 様子を見て除外を確定する", "見直しの候補 (守りとして残す価値"} {
		if strings.Contains(txt, no) {
			t.Errorf("must not contain the long summary %q", no)
		}
	}
	// 提案の section は 3 行 (見出し・なぜ困るか・→)。「様子を見る」だけで終わる抽象的な「→」にしない
	for _, b := range m.Blocks {
		if b.Type == "section" && b.Text != nil && strings.HasPrefix(b.Text.Text, "🛡️") {
			if strings.Count(b.Text.Text, "\n") != 2 {
				t.Errorf("a proposal section must be 3 lines: %q", b.Text.Text)
			}
			if !strings.Contains(b.Text.Text, "`prod-waf`") || strings.HasSuffix(b.Text.Text, "様子を見る") {
				t.Errorf("the next step must name the WebACL and how to check: %q", b.Text.Text)
			}
		}
	}
	if !strings.Contains(allText(s.got[0].msg), "WAF の改善提案は別のメッセージ") {
		t.Error("the first message should point to the proposals message")
	}
	md, err := os.ReadFile(filepath.Join(dir, ProposalsMD))
	if err != nil || !strings.Contains(string(md), "## p1. 誤検知の疑い") || !strings.Contains(string(md), "RuleActionOverrides") {
		t.Fatalf("waf-proposals.md: %v\n%s", err, md)
	}
}

// LLM は「→」の 1 行 (next) を書く。何を・なぜ・進め方・設定例は waf-proposals.md にだけ書き、Slack には出さない。
// BLOCK に強める next はその項目ごと捨てて規則の「→」にする。--dry-run では waf-proposals.md を書かない。
func TestBlocksProposalsLLM(t *testing.T) {
	resp := `{"proposals": [
		{"id": "p1", "what": "誤検知を除外する", "why": "250 件", "how": "COUNT で様子を見る", "example": "\"RuleActionOverrides\": []", "next": "投稿画面だけ XSS のルールを COUNT にする <!here>"},
		{"id": "p2", "what": "探索を止める", "why": "14 件", "how": "COUNT で足す", "example": "", "next": "BLOCK に切り替える"}]}`
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	l := &fakeLLM{responses: []string{`{"summary": "要約", "next": []}`, resp}}
	s := &fakeSender{}
	_, logs := run(t, dir, s, withBlocks, withLLM(l))
	if len(s.got) != 2 {
		t.Fatalf("%+v", s.got)
	}
	m := s.got[1].msg
	checkLimits(t, m)
	txt := allText(m)
	if !strings.Contains(txt, "→ 投稿画面だけ XSS のルールを COUNT にする &lt;!here&gt;") || !strings.Contains(txt, "→ WebACL `prod-waf` に、`/.env`・`/.git/config` を URI で照合する") {
		t.Fatalf("%s", txt)
	}
	for _, no := range []string{"何を:", "\"RuleActionOverrides\"", "BLOCK に切り替える", "```"} {
		if strings.Contains(txt, no) {
			t.Errorf("slack must not contain %q", no)
		}
	}
	if !strings.Contains(logs.String(), CodeLLMProposalRejected) {
		t.Error("the BLOCK writeup must be rejected")
	}
	md, _ := os.ReadFile(filepath.Join(dir, ProposalsMD))
	for _, want := range []string{"- 何を: 誤検知を除外する", "設定例:\n\n```\n\"RuleActionOverrides\": []\n```", "- 次の一手: 投稿画面だけ XSS のルールを COUNT にする <!here>"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("waf-proposals.md lacks %q\n%s", want, md)
		}
	}
	if strings.Contains(string(md), "BLOCK に切り替える") {
		t.Error("rejected writeups must not reach the file")
	}

	dir = inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	run(t, dir, &fakeSender{}, withBlocks, func(o *Options) { o.DryRun = true })
	if _, err := os.Stat(filepath.Join(dir, ProposalsMD)); !os.IsNotExist(err) {
		t.Fatalf("--dry-run must not write %s: %v", ProposalsMD, err)
	}
}

// waf-proposals.md を書けなくても通知は続け、report.md を案内する。
func TestBlocksProposalsFileFailure(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	if err := os.Mkdir(filepath.Join(dir, ProposalsMD), 0o700); err != nil { // 同名のディレクトリで置き換えを失敗させる
		t.Fatal(err)
	}
	s := &fakeSender{}
	res, logs := run(t, dir, s, withBlocks)
	if res.Exit != ExitOK || len(s.got) != 2 || !strings.Contains(logs.String(), CodeProposalsFileFailed) {
		t.Fatalf("%+v %s", res, logs)
	}
	if txt := allText(s.got[1].msg); !strings.Contains(txt, "詳しい説明: `"+filepath.Join(dir, ReportMD)+"`") {
		t.Fatalf("%s", txt)
	}
}

// PlainText は --dry-run の人が読む簡易表示。text だけのメッセージは text をそのまま。
func TestPlainTextOfTextMessage(t *testing.T) {
	if got := PlainText(Message{Text: "abc"}); got != "abc" {
		t.Fatalf("%q", got)
	}
}

// challenge_on_app_path (提案) と challenge_impact (Challenge / CAPTCHA の状況。observation) も見出し・主な数字・根拠を規則で書く (ADR 0028)。
func TestBlocksProposalsChallenge(t *testing.T) {
	ps := []schema.Proposal{
		{Kind: "challenge_on_app_path", Stage: "review", WebACL: "prod-waf", Rule: "AWS-AWSManagedRulesBotControlRuleSet", RuleInGroup: "CategoryHttpLibrary",
			Method: "GET", Path: "/products/:id", Summary: "長い概要",
			Evidence: map[string]any{"kind": "challenge", "issued": 160.0, "distinct_ips_max_per_day": 30.0, "solve_ratio": 0.8, "days": 7.0}},
		{Kind: "observation", About: "challenge_on_app_path", Reason: "below_threshold", Stage: "none", WebACL: "prod-waf", Rule: "captcha-login",
			Method: "GET", Path: "/login", Summary: "閾値未満", Evidence: map[string]any{"kind": "captcha", "issued": 12.0, "solve_ratio": 0.5, "days": 7.0}},
		{Kind: "observation", About: "challenge_impact", Reason: "informational", Stage: "none", WebACL: "prod-waf", Rule: "challenge-all",
			Summary: "状況", Evidence: map[string]any{"kind": "challenge", "issued": 900.0, "solve_ratio": 0.05, "issued_non_get": 40.0,
				"paths": []any{"GET /a (500 件、2%)", "POST /b (300 件、0%)", "GET /c (50 件、10%)", "GET /d (50 件、10%)"}, "days": 7.0}},
	}
	dir := inputDir(t, withProposals(t, goldenRun(t), ps), "")
	s := &fakeSender{}
	run(t, dir, s, withBlocks)
	m := s.got[1].msg
	checkLimits(t, m)
	txt := allText(m)
	for _, want := range []string{
		"🛡️ *正規の画面に Challenge / CAPTCHA* — `CategoryHttpLibrary` が GET /products/:id で Challenge 160 件 / 7 日・解かれた 80%\n" +
			"正規の画面で多くの人が Challenge を解かされている (解かれた 80%)\n" +
			"→ ルール `CategoryHttpLibrary` の対象から `GET /products/:id` を外す (scope-down) か、条件を Accept-Language などで絞る",
		"IP 最大 30/日・ACL prod-waf",
		"• 正規の画面に Challenge / CAPTCHA (閾値未満) — `captcha-login` が GET /login で CAPTCHA 12 件 / 7 日・解かれた 50%",
		"*Challenge / CAPTCHA*",
		"• `challenge-all` Challenge 900 件・解かれた 5%・GET 以外 40",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "長い概要") {
		t.Error("the long summary must not be in slack")
	}
}

// endpoint_abuse (ADR 0030) は 1 件でも「*画面への分散した集中* — `signup` 25 IP / 10 分」の形にし、
// playbook どおり確認・保留の運用へ回す「→」を添える (遮断は勧めない)。「A のあと B」は key (from>to) で別の項目にまとめる。
func TestBlocksEndpointAbuse(t *testing.T) {
	r := goldenRun(t)
	mk := func(id, key string, data map[string]any) schema.Finding {
		return schema.Finding{ID: id, Check: "endpoint_abuse", Key: key, Severity: "medium", Summary: "長い summary " + key, Data: data}
	}
	r.Findings.New = []schema.Finding{
		mk("e-1", "signup", map[string]any{"endpoint": "signup", "window": "10m", "distinct_ips": 25.0, "count": 300.0}),
		mk("e-2", "signup>post", map[string]any{"from": "signup", "to": "post", "window": "10m", "ips": 12.0}),
		mk("e-3", "login>reset", map[string]any{"from": "login", "to": "reset", "window": "1h", "ips": 8.0}),
	}
	r.Findings.Changed, r.Findings.Recurred = nil, nil
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.MaxSeverity = 3, 0, 0, "medium"
	r.Coverage.SourcesFailed = nil
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s, withBlocks)
	m := s.got[0].msg
	checkLimits(t, m)
	txt := allText(m)
	for _, want := range []string{
		"🟠 *画面への分散した集中* — `signup` 25 IP / 10 分 `id: e-1`\n→ " + abuseNext,
		"🟠 *「A のあと B」の連鎖* 2 件\n`signup → post` 12 IP / 10 分 ・ `login → reset` 8 IP / 1 時間\nid: `e-2` `e-3`\n→ " + abuseNext,
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "長い summary") {
		t.Error("endpoint_abuse must not show the long summary")
	}
}

// LLM の固定応答 (testdata/llm/proposals_ok.json) の next は具体的な名前と確認方法を含む見本。Slack の「→」にそのまま出る (140 字まで)。
func TestBlocksProposalsLLMConcreteNext(t *testing.T) {
	dir := inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), "")
	l := &fakeLLM{responses: []string{`{"summary": "要約", "next": []}`, fixture(t, "proposals_ok.json")}}
	s := &fakeSender{}
	run(t, dir, s, withBlocks, withLLM(l))
	txt := allText(s.got[1].msg)
	if !strings.Contains(txt, "→ WebACL `prod-waf` のルール `CrossSiteScripting_BODY` を `POST /posts/:id` に限って COUNT にし、1〜2 週間、一致した投稿が正規の利用者のものかを見る") {
		t.Fatalf("%s", txt)
	}
	if !strings.Contains(l.systems[1], "抽象的な言い回しを避け") {
		t.Fatal("the proposals system must ask for a concrete next step")
	}
}
