package notify

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 通知の finding の行には、report.json の id を `id: …` の形で末尾に出す (triage や作業の記録に結びつけるため)。

func TestIDTag(t *testing.T) {
	for _, c := range []struct{ id, want string }{
		{"7f16a4507445", "`id: 7f16a4507445`"},
		{"", ""},
		{" \n\u200b", ""},
		// report.json の値も信用しない: 書式・メンション・改行にならない
		{"a`b<!channel>\nc", "`id: a'b&lt;!channel&gt; c`"},
		{strings.Repeat("f", 100), "`id: " + strings.Repeat("f", maxIDRunes) + "…`"},
	} {
		if got := idTag(c.id); got != c.want {
			t.Errorf("idTag(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

func blocksText(t *testing.T, report []byte, mod ...func(*Options)) string {
	t.Helper()
	s := &fakeSender{}
	run(t, inputDir(t, report, ""), s, append([]func(*Options){withBlocks}, mod...)...)
	if len(s.got) == 0 {
		t.Fatal("not sent")
	}
	checkLimits(t, s.got[0].msg)
	return allText(s.got[0].msg)
}

// blocks: 1 件ずつの項目は見出しの行の末尾に、まとめた項目は主体の行の下に主体と同じ順で出す。
func TestBlocksFindingID(t *testing.T) {
	txt := blocksText(t, golden(t, "report.json"))
	for _, want := range []string{
		"🚨 *summary of arn:aws:iam::1:root|203.0.113.1* `id: f-002`\n→ ",
		"🚨 *summary of arn:aws:iam::1:root|192.0.2.1* (再発) `id: f-009`\n→ ",
		"🔴 *summary of a-&gt;b* (変化) `id: f-003`\n→ ",
		"🟠 *summary of 198.51.100.7* `id: f-010`\n",
		"🟠 *summary of arn:aws:iam::1:user/x* `id: f-001`\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	// 件数だけの区分 (解消・未対応・報告済み・情報) の id は出さない
	for _, bad := range []string{"f-004", "f-005", "f-006", "f-007"} {
		if strings.Contains(txt, bad) {
			t.Errorf("%s must not appear", bad)
		}
	}

	txt = blocksText(t, groupReport(t))
	for _, want := range []string{
		"🔴 *GuardDuty: インスタンスの認証情報が AWS の外で使われた* `id: g-1`\n→ ",
		"🟠 *MFA の無いコンソールユーザー* 5 人\n`alice` `bob` `carol` `dave` `erin`\nid: `m-0` `m-1` `m-2` `m-3` `m-4`\n",
		"🟠 *使われていないアクセスキー* 2 本\n`alice` 469 日 ・ `bob` 120 日\nid: `k-1` `k-2`\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
}

// まとめた項目の id は maxGroupIDs 個まで。残りは件数と `arata review` (ID を並べすぎない)。
func TestBlocksGroupIDsAreCapped(t *testing.T) {
	r := goldenRun(t)
	var fs []schema.Finding
	for i := range 7 {
		u := fmt.Sprintf("user%d", i)
		fs = append(fs, schema.Finding{ID: fmt.Sprintf("f%011x", i+1), Check: "credential_hygiene", Key: "no_mfa|" + u, Severity: "medium", Summary: u, Data: map[string]any{"user": u}})
	}
	// まとめた項目に「→」があるとき、id は「→」の前
	for i := range 2 {
		fs = append(fs, schema.Finding{ID: fmt.Sprintf("e-%d", i), Check: "endpoint_abuse", Key: fmt.Sprintf("signup%d", i), Severity: "medium", Summary: "s", Data: map[string]any{"distinct_ips": 25.0, "window": "10m"}})
	}
	r.Findings.New, r.Findings.Changed, r.Findings.Recurred = fs, nil, nil
	r.Summary.New, r.Summary.MaxSeverity = len(fs), "medium"
	txt := blocksText(t, marshal(t, r))
	for _, want := range []string{
		"`user6`\nid: `f00000000001` `f00000000002` `f00000000003` `f00000000004` `f00000000005` ほか 2 件は `arata review`\n",
		"`signup0` 25 IP / 10 分 ・ `signup1` 25 IP / 10 分\nid: `e-0` `e-1`\n→ ",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "f00000000006") {
		t.Errorf("ids beyond the cap must not be listed:\n%s", txt)
	}
}

// 1 件だけでも「*見出し* — 名前」で出すチェック (endpoint_abuse) も同じ。
func TestBlocksSingleRuleItemHasID(t *testing.T) {
	r := goldenRun(t)
	r.Findings.New = []schema.Finding{{ID: "e-1", Check: "endpoint_abuse", Key: "signup", Severity: "medium", Summary: "s", Data: map[string]any{"distinct_ips": 25.0, "window": "10m"}}}
	r.Findings.Changed, r.Findings.Recurred = nil, nil
	if txt, want := blocksText(t, marshal(t, r)), "*画面への分散した集中* — `signup` 25 IP / 10 分 `id: e-1`\n→ "; !strings.Contains(txt, want) {
		t.Errorf("missing %q in\n%s", want, txt)
	}
}

// 概要や主体がどれだけ長くても、またバッククォートを含んでいても、id の表記は切れず、コード表記も崩れない。
func TestBlocksFindingIDSurvivesLongAndBacktickValues(t *testing.T) {
	r := goldenRun(t)
	long := "`開いたまま " + strings.Repeat("長", 5000)
	r.Findings.New = []schema.Finding{
		{ID: "u-1", Check: "root_usage", Key: long, Severity: "critical", Summary: long},
		{ID: "s-1", Check: "custom", Key: long, Severity: "low", Summary: long},
		{ID: "e-1", Check: "endpoint_abuse", Key: long, Severity: "low", Summary: long},
		{ID: "g-1", Check: "probe_paths", Key: long, Severity: "low", Summary: long, Data: map[string]any{"ip": long}},
		{ID: "g-2", Check: "probe_paths", Key: long, Severity: "low", Summary: long, Data: map[string]any{"ip": long}},
	}
	r.Findings.Changed, r.Findings.Recurred = nil, nil
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s, withBlocks)
	checkLimits(t, s.got[0].msg)
	txt := allText(s.got[0].msg)
	for _, want := range []string{" `id: u-1`\n→ ", " `id: s-1`\n", " `id: e-1`\n→ ", "\nid: `g-1` `g-2`\n"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, l := range strings.Split(txt, "\n") {
		if strings.Contains(l, "id: ") && strings.Count(l, "`")%2 != 0 {
			t.Errorf("unbalanced backticks break the id: %.80s … %s", l, l[max(0, len(l)-40):])
		}
	}
}

// 期間レポートの events も id を持つ (finding_id)。
func TestBlocksPeriodFindingID(t *testing.T) {
	txt := blocksText(t, golden(t, "period.json"), func(o *Options) {})
	for _, want := range []string{"🚨 *ルートユーザーの利用* `id: f1`\n→ ", "🟠 *GuardDuty: Recon (4 回)* (変化) `id: f4`\n"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
}

// text: 主要キーの行の末尾に同じ表記で出す (provider: none・LLM の失敗時の原文・LLM の要約のどれも)。
func TestTextFindingID(t *testing.T) {
	f := schema.Finding{ID: "7f16a4507445", Check: "root_usage", Severity: "critical", Summary: "s", FirstSeen: "2026-10-21T09:00:00Z",
		Data: map[string]any{"count": 2.0, "ips": []any{"`203.0.113.1"}}}
	if got, want := findingLines(f), "• *[critical]* s `root_usage`\n    count 2 · ips '203.0.113.1 · 初出 2026-10-21T09:00:00Z · `id: 7f16a4507445`"; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	// 初出や id が無い値でも、空の表記を残さない
	if got, want := findingLines(schema.Finding{Check: "c", Severity: "low", Summary: "s"}), "• *[low]* s `c`"; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	// 期間レポートの events (data を持たない)
	if got, want := (findingRef{id: "7f16a4507445", check: "c", severity: "low", summary: "s", diff: "新規"}).line(), "• *[low]* s `c` (新規)\n    `id: 7f16a4507445`"; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// 切り詰め (約 3,800 字) では行の境目で切るので、残った id の表記は欠けない。上限も超えない。
func TestTextFindingIDSurvivesTruncation(t *testing.T) {
	r := goldenRun(t)
	var fs []schema.Finding
	for i := range 200 {
		fs = append(fs, schema.Finding{ID: fmt.Sprintf("f%011x", i+1), Check: "custom", Key: "k", Severity: "medium", Summary: strings.Repeat("長", 40), FirstSeen: "2026-10-21T09:00:00Z"})
	}
	r.Findings.New = fs
	in := &Input{Kind: KindRun, Run: r, Dir: "/tmp/in"}
	text := ReportText(in, Decision{Route: RouteUrgent}, rules, nil, FallbackNotice)
	if n := utf8.RuneCountInString(text); n > MaxTextRunes {
		t.Fatalf("%d runes", n)
	}
	if !strings.Contains(text, "…(長いため省略)") {
		t.Fatal("expected truncation")
	}
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if !strings.Contains(l, "id: ") {
			continue
		}
		n++
		if !wholeIDTag.MatchString(l) {
			t.Errorf("broken id line: %q", l)
		}
	}
	if n == 0 {
		t.Fatal("no id lines")
	}
}

// wholeIDTag は text の主要キーの行の末尾にある、欠けていない id の表記。
var wholeIDTag = regexp.MustCompile("(^    | · )`id: [0-9a-f]{12}`$")

// LLM の文に id の表記 (`id: …`) をまねた文字列があれば、その項目を捨てる (規則の行に戻る)。
// 通知の `id: …` は report.json の値だけ、という前提を LLM の出力 (ログの文に誘導され得る) で崩させない。
func TestLLMCannotImitateFindingID(t *testing.T) {
	for _, s := range []string{"次を ack する `id: 0123456789ab`", "x `ID :deadbeef0000` y", "`\u200bid: 0123456789ab`"} {
		if rejectLLMText(s) == "" {
			t.Errorf("%q must be rejected", s)
		}
	}
	for _, s := range []string{"id f-002 の主体を確認する", "`arata review` で valid: な値を見る", "キーの ID: を確認する"} {
		if why := rejectLLMText(s); why != "" {
			t.Errorf("%q must pass: %s", s, why)
		}
	}
	in := &Input{Kind: KindRun, Run: goldenRun(t), Dir: "/tmp/in"}
	top, _ := splitUrgent(in, rules.UrgentSeverity)
	n, err := ParseBlockNotes([]byte("{\"summary\":\"s\",\"next\":[{\"finding_id\":\"f-002\",\"action\":\"`id: f-001` を resolve する\"}]}"), in, top)
	if err != nil || len(n.Next) != 0 || len(n.Rejected) != 1 {
		t.Fatalf("%+v %v", n, err)
	}
	if _, err := ParseBlockNotes([]byte("{\"summary\":\"`id: f-001` は誤検知\"}"), in, top); err == nil {
		t.Fatal("summary imitating an id must be rejected")
	}
}
