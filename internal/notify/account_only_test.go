package notify

import (
	"regexp"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 呼び出し元がアカウントしか分からない finding (CloudTrail に呼び出し元のアカウント ID しか無い記録) を、LLM が「ルートユーザー」と書いても通知に出さない。
// 守りはプロンプトだけにせず、規則 (置換と検査) に置く (ADR 0037)。値はすべて架空。

const (
	aoRoot = "arn:aws:iam::111122223333:root"
	aoRole = "arn:aws:iam::123456789012:role/Admin"
)

// aoInput は f0 = アカウントしか分からない呼び出し元の unknown_assume_role (high)、f1 = IAM ユーザーの new_principal。withRoot なら f2 = 本物の root_usage。
func aoInput(withRoot bool) *Input {
	r := &schema.Report{Name: "n", Profile: "hourly", RunID: "r"}
	r.Findings.New = []schema.Finding{
		{ID: "f0", Check: "unknown_assume_role", Key: aoRoot + "->" + aoRole, Severity: "high",
			Summary: "既知リストに無い外部アカウント 111122223333 (呼び出した主体は記録に無い) が自アカウントのロール Admin を 3 回引き受け (内向き、MFA 不明)",
			Data:    map[string]any{"caller": aoRoot, "caller_kind": "unknown", "caller_identity": "account_only", "external_account": "111122223333", "count": 3.0}},
		{ID: "f1", Check: "new_principal", Key: "arn:aws:iam::123456789012:user/alice", Severity: "medium", Summary: "新規の主体 arn:aws:iam::123456789012:user/alice (user)", Data: map[string]any{"kind": "user"}},
	}
	if withRoot {
		r.Findings.New = append(r.Findings.New, schema.Finding{ID: "f2", Check: "root_usage", Key: "arn:aws:iam::123456789012:root|203.0.113.1", Severity: "critical",
			Summary: "ルートアカウント arn:aws:iam::123456789012:root が 203.0.113.1 から 1 件の操作", Data: map[string]any{"count": 1.0}})
	}
	r.Summary.New = len(r.Findings.New)
	return &Input{Kind: KindRun, Run: r}
}

func TestAccountOnlyOf(t *testing.T) {
	in := aoInput(true)
	_, byID := findingIndex(in)
	if a, ok := accountOnlyOf(byID["f0"]); !ok || a != "111122223333" {
		t.Fatalf("f0: %q %v", a, ok)
	}
	for _, id := range []string{"f1", "f2"} {
		if a, ok := accountOnlyOf(byID[id]); ok {
			t.Fatalf("%s: %q", id, a)
		}
	}
	// 期間レポートの events は data を持たない。主体のチェックの key の形で見分ける (root_usage の key は対象にしない)
	for _, c := range []struct {
		check, key string
		want       string
	}{
		{"unknown_assume_role", aoRoot + "->" + aoRole, "111122223333"},
		{"new_principal", aoRoot, "111122223333"},
		{"access_denied", aoRoot, "111122223333"},
		{"root_usage", "arn:aws:iam::123456789012:root|203.0.113.1", ""},
		{"unknown_assume_role", "arn:aws:iam::123456789012:user/root->" + aoRole, ""},
		{"new_principal", aoRoot + "x", ""},
		{"iam_changes", aoRoot, ""},
	} {
		if a, _ := accountOnlyOf(findingRef{check: c.check, key: c.key}); a != c.want {
			t.Errorf("%s %s: %q, want %q", c.check, c.key, a, c.want)
		}
	}
}

// 起きたこと: LLM が「111122223333 の root から引き受けられた」と書いた。
func TestParseSummaryAccountOnlyCallerIsNotRoot(t *testing.T) {
	in := aoInput(false)
	// finding に付く文 (理由・提案・インシデント候補) に root の語があれば、その項目を捨てる (finding は規則の行に戻る)
	s := parse(t, in, `{"headline":"外部アカウントからの引き受けが 1 件","items":[
		{"finding_id":"f0","class":"action","reason":"111122223333 の root から引き受けられた。想定の経路と異なる。急いで確かめる"},
		{"finding_id":"f1","class":"confirm","reason":"新しい IAM ユーザー"}],
		"incidents":[{"finding_ids":["f0","f1"],"summary":"外部アカウントのルートユーザーによる引き受けと新規ユーザー"}],
		"approve_suggestions":[{"finding_id":"f1","reason":"ok"}]}`)
	if len(s.Items) != 1 || s.Items[0].FindingID != "f1" || len(s.Incidents) != 0 {
		t.Fatalf("%+v", s)
	}
	if m := s.Missing(in); len(m) != 1 || m[0].id != "f0" {
		t.Fatalf("捨てた finding が規則の行に戻らない: %+v", m)
	}
	if len(s.Rejected) != 2 || !strings.Contains(s.Rejected[0], "f0: ") || !strings.Contains(s.Rejected[0], "root user") {
		t.Fatalf("rejected: %v", s.Rejected)
	}
	text := SummaryText(in, Decision{Route: RouteUrgent}, Rules{UrgentSeverity: urgent}, nil, s)
	if strings.Contains(text, "の root") || strings.Contains(text, "ルートユーザー") {
		t.Fatalf("通知に root の文が残った:\n%s", text)
	}
	if !strings.Contains(text, "外部アカウント 111122223333 (呼び出した主体は記録に無い)") {
		t.Fatalf("規則の行 (見出し) が無い:\n%s", text)
	}

	// ARN をそのまま書いた文は捨てず、表記を置き換える (root と読めない文にする)
	s = parse(t, in, `{"headline":"`+aoRoot+` が Admin を引き受け","items":[
		{"finding_id":"f0","class":"confirm","reason":"`+aoRoot+` の信頼ポリシーを確かめる"},{"finding_id":"f1","class":"confirm","reason":"r"}]}`)
	const label = "外部アカウント 111122223333 (呼び出した主体は記録に無い)"
	if s.Headline != label+" が Admin を引き受け" || len(s.Items) != 2 || s.Items[0].Reason != label+" の信頼ポリシーを確かめる" || len(s.Rejected) != 0 {
		t.Fatalf("%+v", s)
	}

	// 見出し: アカウント ID の近くの root、ルートユーザーの利用と書いたものは形の不正 (再試行し、だめなら report.md を送る)
	for _, h := range []string{"111122223333 の root から引き受けられた", "外部アカウントのルートユーザーが使われた", "Root user による AssumeRole", "外部アカウントの root アカウントから引き受け"} {
		if _, err := ParseSummary([]byte(`{"headline":"`+h+`","items":[]}`), in, urgent); err == nil {
			t.Errorf("見出しを通した: %s", h)
		}
	}
	// 見出しの root の語だけでは捨てない (cost_anomaly の root_causes、ルートテーブルなど)
	for _, h := range []string{"費用の異常の root_causes は us-east-1", "ルートテーブルの変更が 1 件"} {
		if _, err := ParseSummary([]byte(`{"headline":"`+h+`","items":[]}`), in, urgent); err != nil {
			t.Errorf("見出しを捨てた: %s (%v)", h, err)
		}
	}
}

// 本物のルートユーザーの指摘 (root_usage) が同じ報告にあるときは、その話として root と書ける。アカウントしか分からない finding に付く文と、アカウント ID の近くは通さない。
func TestParseSummaryGenuineRootStillAllowed(t *testing.T) {
	in := aoInput(true)
	s := parse(t, in, `{"headline":"ルートユーザーの利用が 1 件、外部アカウントからの引き受けが 1 件","items":[
		{"finding_id":"f2","class":"action","reason":"ルートユーザーが使われた"},
		{"finding_id":"f0","class":"action","reason":"root による引き受け"},
		{"finding_id":"f1","class":"confirm","reason":"r"}],
		"incidents":[{"finding_ids":["f0","f2"],"summary":"ルートユーザーの利用と同じ時間帯に外部アカウントからの引き受け"},
			{"finding_ids":["f0","f2"],"summary":"111122223333 のルートユーザーが引き受けた"}]}`)
	if len(s.Items) != 2 || s.Items[0].FindingID != "f2" || s.Items[1].FindingID != "f1" || len(s.Incidents) != 1 {
		t.Fatalf("%+v", s)
	}
	if _, err := ParseSummary([]byte(`{"headline":"111122223333 の root と自アカウントの root の利用","items":[]}`), in, urgent); err == nil {
		t.Error("アカウント ID の近くの root を通した")
	}
}

// アカウントしか分からない finding が無い報告では、何も変えない。
func TestParseSummaryWithoutAccountOnlyIsUnchanged(t *testing.T) {
	in := boundaryInput("critical")
	s := parse(t, in, `{"headline":"root の利用 `+aoRoot+`","items":[{"finding_id":"f0","class":"action","reason":"ルートユーザーが使われた `+aoRoot+`"}]}`)
	if len(s.Items) != 1 || !strings.Contains(s.Items[0].Reason, aoRoot) || !strings.Contains(s.Headline, aoRoot) {
		t.Fatalf("%+v", s)
	}
}

func TestParseBlockNotesAccountOnlyCallerIsNotRoot(t *testing.T) {
	in := aoInput(false)
	top, _ := splitUrgent(in, urgent)
	n, err := ParseBlockNotes([]byte(`{"summary":"`+aoRoot+` が Admin を引き受けました。","next":[{"finding_id":"f0","action":"111122223333 の root の利用者に確かめる"}]}`), in, top)
	if err != nil {
		t.Fatal(err)
	}
	if n.Summary != "外部アカウント 111122223333 (呼び出した主体は記録に無い) が Admin を引き受けました。" || len(n.Next) != 0 || len(n.Rejected) != 1 {
		t.Fatalf("%+v", n)
	}
	n, err = ParseBlockNotes([]byte(`{"summary":"s","next":[{"finding_id":"f0","action":"`+aoRoot+` の信頼ポリシーを確かめる"}]}`), in, top)
	if err != nil || n.Next["f0"] != "外部アカウント 111122223333 (呼び出した主体は記録に無い) の信頼ポリシーを確かめる" {
		t.Fatalf("%+v %v", n, err)
	}
	if _, err := ParseBlockNotes([]byte(`{"summary":"111122223333 の root から引き受けられました"}`), in, top); err == nil {
		t.Error("要約を通した")
	}
}

// 3 つの system のうち、finding を読む 2 つに規則がある。
func TestSystemPromptsAccountOnlyRule(t *testing.T) {
	for name, s := range map[string]string{"summary": SystemPrompt(KindRun, "", ""), "blocks": BlocksSystemPrompt(KindRun, "", "", nil)} {
		if !strings.Contains(s, accountOnlyRule) {
			t.Errorf("%s: アカウントしか分からない主体の規則が無い", name)
		}
	}
	for _, want := range []string{"account_only", "external_account", "ルートユーザー", "外部アカウント NNN"} {
		if !strings.Contains(accountOnlyRule, want) {
			t.Errorf("規則に %q が無い", want)
		}
	}
}

// 規則で組み立てる行 (provider: none、LLM の失敗、漏れた finding、blocks のまとめ) にも ARN の root を出さない。
func TestRuleLinesShowAccountOnly(t *testing.T) {
	in := aoInput(false)
	_, byID := findingIndex(in)
	if l := byID["f0"].line(); strings.Contains(l, ":root") || strings.Contains(l, "caller ") {
		t.Errorf("line: %s", l)
	}
	// 以前の版の見出し (注記が無い) でも、caller は置き換えた表記で出す
	old := in.Run.Findings.New[0]
	old.Summary = "既知リストに無い外部アカウント 111122223333 が自アカウントのロール Admin を 3 回引き受け (内向き、MFA 不明)"
	if d := detail(old); !strings.Contains(d, "caller 外部アカウント 111122223333 (呼び出した主体は記録に無い)") || strings.Contains(d, ":root") {
		t.Errorf("detail: %s", d)
	}
	f := findingRef{check: "new_principal", key: aoRoot, finding: &schema.Finding{Data: map[string]any{"external_account": "111122223333"}}}
	if got := principalName(f); got != "`外部アカウント 111122223333`" {
		t.Errorf("principalName: %s", got)
	}
	if got := principalName(findingRef{check: "new_principal", key: aoRoot}); got != "`外部アカウント 111122223333`" {
		t.Errorf("principalName (期間レポート): %s", got)
	}
	if got := principalName(findingRef{check: "new_principal", key: "arn:aws:iam::123456789012:user/alice"}); got != "`user/alice`" {
		t.Errorf("principalName: %s", got)
	}
}

// LLM の文は信用できない入力 (ADR 0041)。守る規則:
//   - 通した文に、アカウントしか分からない主体の ARN (`arn:aws:iam::NNN:root`) が残らない
//   - finding に付く文 (scoped) を通したなら、root・ルートの語が無い
//   - 通した文で、そのアカウント ID の近くに root・ルートの語が無い
//   - 対象のアカウントが無ければ、文を変えず、捨てない
func FuzzAccountOnlyText(f *testing.F) {
	for _, s := range []string{"111122223333 の root から引き受けられた", aoRoot + " が引き受け", "arn:aws-cn:iam::111122223333:root", "ROOT ユーザー", "ル\u200bート ユーザー",
		"外部アカウント 111122223333 (呼び出した主体は記録に無い) がロール role/root-admin を引き受け", "root_causes", "r\u202eoot 111122223333", "", "１１１１２２２２３３３３ の root",
		"arn:aws:iam::111122223333:rootarn:aws:iam::111122223333:root", "111122223333。root"} {
		f.Add(s, true, false)
		f.Add(s, false, true)
		f.Add(s, false, false)
	}
	word := regexp.MustCompile(`(?i)root|ルート`)
	near := regexp.MustCompile(`(?i)111122223333[^。]{0,8}(root|ルート)|(root|ルート)[^。]{0,8}111122223333`)
	f.Fuzz(func(t *testing.T, s string, scoped, genuine bool) {
		g := rootGuard{accounts: map[string]bool{"111122223333": true}, genuine: genuine}
		out, why := g.apply(s, scoped)
		if why == "" {
			if strings.Contains(out, aoRoot) {
				t.Fatalf("ARN が残った: %q -> %q", s, out)
			}
			plain := strings.ReplaceAll(out, schema.AccountOnlyLabel("111122223333"), "111122223333")
			if scoped && !genuine && word.MatchString(plain) {
				t.Fatalf("root の語を通した: %q -> %q", s, out)
			}
			if near.MatchString(plain) {
				t.Fatalf("アカウント ID の近くの root を通した: %q -> %q", s, out)
			}
		}
		if out2, why2 := (rootGuard{}).apply(s, scoped); out2 != s || why2 != "" {
			t.Fatalf("対象が無いのに変えた: %q -> %q (%s)", s, out2, why2)
		}
	})
}
