package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/report/schema"
)

// slack.details: thread (ADR 0093)。1 通目に一番伝えたいことと確認推奨の概要、1 通目のスレッドへの返信 (3 通まで) に詳細。

// threadSender は送った順に記録し、1 通ごとに ts を返す。failAt 通目 (1 始まり) で失敗する。ts を tsOf で差し替えられる。
type threadSender struct {
	got    []sent
	failAt int
	tsOf   func(n int) string
}

func (s *threadSender) Send(_ context.Context, r Route, m Message) (string, error) {
	n := len(s.got) + 1
	if n == s.failAt {
		s.failAt = -1
		return "", errors.New("slack: chat.postMessage failed: not_in_channel")
	}
	s.got = append(s.got, sent{r, m.Text, m})
	if s.tsOf != nil {
		return s.tsOf(n), nil
	}
	return fmt.Sprintf("1700000000.%06d", n), nil
}

func runThread(t *testing.T, dir string, s *threadSender, mod ...func(*Options)) Result {
	t.Helper()
	o := Options{Dir: dir, Now: now, Rules: rules, Sender: s, Details: DetailsThread}
	for _, m := range mod {
		m(&o)
	}
	return Run(context.Background(), o)
}

// manyReport は、まず対応 2 件 (high) と、確認推奨 (medium。まとめるものと 1 件ずつのもの) が多い報告。
func manyReport(t *testing.T, singles int) []byte {
	t.Helper()
	r := goldenRun(t)
	mk := func(id, check, key, sev, summary string, data map[string]any) schema.Finding {
		return schema.Finding{ID: id, Check: check, Key: key, Severity: sev, Summary: summary, FirstSeen: "2026-10-21T09:00:00Z", Data: data}
	}
	fs := []schema.Finding{
		mk("g-1", "guardduty_findings", "gd-1", "high", "GuardDuty: インスタンスの認証情報が AWS の外で使われた", map[string]any{"type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"}),
		mk("r-1", "root_usage", "root", "critical", "ルートユーザーが使われた", map[string]any{"count": float64(2)}),
	}
	for i, u := range []string{"alice", "bob", "carol", "dave", "erin"} {
		fs = append(fs, mk(fmt.Sprintf("m-%d", i), "credential_hygiene", "no_mfa|"+u, "medium", u+" に MFA が無い", map[string]any{"user": u}))
	}
	for i := range singles {
		fs = append(fs, mk(fmt.Sprintf("x-%03d", i), fmt.Sprintf("custom_%03d", i), "k", "low", fmt.Sprintf("指摘 %03d", i), nil))
	}
	r.Findings.New = fs
	r.Findings.Changed, r.Findings.Recurred = nil, nil
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.MaxSeverity = len(fs), 0, 0, "critical"
	r.Coverage.SourcesFailed = []schema.SourceFailure{{Source: "cloudtrail", Code: "ACCESS_DENIED"}}
	r.AlreadyReported = []schema.Finding{mk("a-1", "custom", "k", "medium", "報告済み", nil)}
	r.Info = []schema.Finding{mk("i-1", "custom", "k", "info", "情報", nil), mk("i-2", "custom", "k2", "info", "情報 2", nil)}
	return marshal(t, r)
}

func TestThreadBlocksSplit(t *testing.T) {
	s := &threadSender{}
	dir := inputDir(t, manyReport(t, 3), "")
	res := runThread(t, dir, s, withBlocks)
	if res.Exit != ExitOK || len(s.got) != 2 {
		t.Fatalf("exit %d sent %d", res.Exit, len(s.got))
	}
	parent, reply := s.got[0].msg, s.got[1].msg
	checkLimits(t, parent)
	checkLimits(t, reply)
	if parent.ThreadTS != "" || reply.ThreadTS != "1700000000.000001" || s.got[1].route != s.got[0].route || s.got[0].route != RouteUrgent {
		t.Fatalf("parent ts %q reply ts %q routes %s %s", parent.ThreadTS, reply.ThreadTS, s.got[0].route, s.got[1].route)
	}
	p, r := allText(parent), allText(reply)
	for _, want := range []string{
		"<!channel>", "取れていないもの", "*まず対応*", "ルートユーザーが使われた* `id: r-1`", "GuardDuty: インスタンスの認証情報が AWS の外で使われた* `id: g-1`",
		"*確認推奨*", "🟠 *MFA の無いコンソールユーザー* 5 人", "🟡 *指摘 000*", "詳細はスレッド",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("parent lacks %q\n%s", want, p)
		}
	}
	// 確認推奨の主体・id・「→」は返信に回す。情報・報告済みの件数も返信
	for _, bad := range []string{"`alice`", "m-0", "x-000", "情報 2 件", "本日報告済み"} {
		if strings.Contains(p, bad) {
			t.Errorf("parent must not have %q\n%s", bad, p)
		}
	}
	for _, want := range []string{
		"*確認推奨*", "`alice` `bob` `carol` `dave` `erin`", "id: `m-0`", "*指摘 000* `id: x-000`", "情報 2 件", "本日報告済み 1 件", "`arata review`", "report.md",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("reply lacks %q\n%s", want, r)
		}
	}
	// メンションは 1 通目だけ
	if strings.Contains(r, "<!channel>") || strings.Contains(r, "r-1") {
		t.Errorf("reply must not repeat the mention or the urgent items\n%s", r)
	}
	checkGolden(t, "thread_blocks.txt", strings.ReplaceAll(PlainText(parent)+"\n=== スレッドへの返信 ===\n"+PlainText(reply), dir, "<dir>"))
}

// 返信に入れるものが無ければ (確認推奨が 0 件で、まず対応も 1 通目に入りきった)、返信せず inline と同じ 1 通を送る。
func TestThreadNoReplyWhenNothingToAdd(t *testing.T) {
	r := goldenRun(t)
	var top []schema.Finding
	for _, f := range r.Findings.New {
		if severityRank[f.Severity] >= severityRank["high"] {
			top = append(top, f)
		}
	}
	if len(top) == 0 {
		t.Fatal("golden has no high finding")
	}
	r.Findings.New, r.Findings.Changed, r.Findings.Recurred = top, nil, nil
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred = len(top), 0, 0
	body := marshal(t, r)
	for _, format := range []string{FormatBlocks, FormatText} {
		s := &threadSender{}
		runThread(t, inputDir(t, body, ""), s, func(o *Options) { o.Format = format })
		inline := &fakeSender{}
		run(t, inputDir(t, body, ""), inline, func(o *Options) { o.Format = format })
		if len(s.got) != 1 || len(inline.got) != 1 {
			t.Fatalf("%s: sent %d", format, len(s.got))
		}
		a, b := PlainText(s.got[0].msg), PlainText(inline.got[0].msg)
		if strings.Contains(a, "詳細はスレッド") || stripDir(a) != stripDir(b) {
			t.Fatalf("%s: must equal the inline message\n%s\n---\n%s", format, a, b)
		}
	}
}

// stripDir は一時ディレクトリのパスを除く (2 つの実行で入力のディレクトリが違うため)。
func stripDir(s string) string {
	return regexp.MustCompile(`/[^ \n]*/report\.md`).ReplaceAllString(s, "<dir>/report.md")
}

// mustKey は入力ディレクトリの報告の識別子。
func mustKey(t *testing.T, dir string) string {
	t.Helper()
	in, err := ReadInput(dir, now, rules.MaxAge)
	if err != nil {
		t.Fatal(err)
	}
	return in.Key()
}

// 件数が多い日: 返信は 3 通まで。1 通ずつ上限を守り、入らないものは「ほか N 件」に縮める。件数は落とさない。
func TestThreadBlocksManyRepliesAreCapped(t *testing.T) {
	s := &threadSender{}
	runThread(t, inputDir(t, manyReport(t, 400), ""), s, withBlocks)
	if len(s.got) != 1+MaxThreadReplies {
		t.Fatalf("sent %d", len(s.got))
	}
	shown, rest := 0, 0
	for i, g := range s.got {
		checkLimits(t, g.msg)
		if i > 0 && g.msg.ThreadTS != "1700000000.000001" {
			t.Fatalf("reply %d ts %q", i, g.msg.ThreadTS)
		}
		txt := allText(g.msg)
		if i > 0 {
			shown += strings.Count(txt, "*指摘 ")
		}
		for _, l := range strings.Split(txt, "\n") {
			var n int
			if _, err := fmt.Sscanf(l, "ほか %d 件は `arata review`", &n); err == nil {
				rest += n
			}
		}
	}
	if rest == 0 || shown+rest != 400 {
		t.Fatalf("shown %d + rest %d != 400", shown, rest)
	}
	last := allText(s.got[len(s.got)-1].msg)
	if !strings.Contains(last, "情報 2 件") || !strings.Contains(last, "report.md") {
		t.Fatalf("the last reply must carry the counts and the guide\n%s", last)
	}
}

// 1 通目に入りきらない「まず対応」は、返信の先頭に「まず対応 (続き)」として送る。
func TestThreadBlocksUrgentOverflow(t *testing.T) {
	r := goldenRun(t)
	var fs []schema.Finding
	for i := range 60 {
		fs = append(fs, schema.Finding{ID: fmt.Sprintf("h-%03d", i), Check: fmt.Sprintf("custom_%03d", i), Key: "k", Severity: "high", Summary: fmt.Sprintf("急ぎ %03d", i)})
	}
	r.Findings.New, r.Findings.Changed, r.Findings.Recurred = fs, nil, nil
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.MaxSeverity = len(fs), 0, 0, "high"
	s := &threadSender{}
	runThread(t, inputDir(t, marshal(t, r), ""), s, withBlocks)
	if len(s.got) < 2 {
		t.Fatalf("sent %d", len(s.got))
	}
	p, rp := allText(s.got[0].msg), allText(s.got[1].msg)
	if !strings.Contains(p, "急ぎ 000") || !strings.Contains(rp, "*まず対応 (続き)*") {
		t.Fatalf("parent\n%s\nreply\n%s", p, rp)
	}
	total := 0
	for _, g := range s.got {
		total += strings.Count(allText(g.msg), "*急ぎ ")
	}
	if total != 60 {
		t.Fatalf("urgent items shown %d", total)
	}
}

// text でも同じ規則で分ける。1 通ずつ 3,800 字まで。LLM の headline は 1 通目の要約に使う。
func TestThreadText(t *testing.T) {
	s := &threadSender{}
	dir := inputDir(t, manyReport(t, 3), "")
	runThread(t, dir, s)
	if len(s.got) != 2 || s.got[0].msg.Blocks != nil {
		t.Fatalf("sent %d", len(s.got))
	}
	p, r := s.got[0].text, s.got[1].text
	for _, want := range []string{"<!channel>", "*まず対応*", "`id: r-1`", "*確認推奨*", "*MFA の無いコンソールユーザー* 5 人", "取れなかったソース", "詳細はスレッド"} {
		if !strings.Contains(p, want) {
			t.Errorf("parent lacks %q\n%s", want, p)
		}
	}
	for _, bad := range []string{"`alice`", "m-0", "x-000", "<!channel>"} {
		if strings.Contains(r, "<!channel>") || (bad != "<!channel>" && strings.Contains(p, bad)) {
			t.Errorf("misplaced %q\nparent\n%s\nreply\n%s", bad, p, r)
		}
	}
	for _, want := range []string{"*確認推奨*", "`id: m-0`", "`id: x-000`", "*情報 (2)*", "*本日報告済み (1)*", "全文: "} {
		if !strings.Contains(r, want) {
			t.Errorf("reply lacks %q\n%s", want, r)
		}
	}
	checkGolden(t, "thread_text.txt", strings.ReplaceAll(p+"\n=== スレッドへの返信 ===\n"+r, dir, "<dir>"))

	s = &threadSender{}
	runThread(t, inputDir(t, manyReport(t, 400), ""), s)
	if len(s.got) != 1+MaxThreadReplies {
		t.Fatalf("sent %d", len(s.got))
	}
	for i, g := range s.got {
		if n := utf8.RuneCountInString(g.text); n > MaxTextRunes {
			t.Fatalf("message %d: %d runes", i, n)
		}
	}
	if !strings.Contains(s.got[len(s.got)-1].text, "`arata review`") {
		t.Fatal("cut notice must point to arata review")
	}
}

func TestThreadTextLLMHeadline(t *testing.T) {
	s := &threadSender{}
	llm := &fakeLLM{responses: []string{`{"headline":"ルートユーザーの利用を最優先で確認してください","items":[]}`}}
	runThread(t, inputDir(t, manyReport(t, 3), ""), s, withLLM(llm))
	if len(s.got) != 2 || !strings.Contains(s.got[0].text, "ルートユーザーの利用を最優先で確認してください") || !strings.Contains(s.got[0].text, LLMNotice) {
		t.Fatalf("%+v", s.got)
	}
}

// 返信に失敗したら終了コード 5。1 通目は送れているので .aratam-notified は書く (1 通目を二重に送らない)。返信だけの送り直しはしない。
func TestThreadReplyFailure(t *testing.T) {
	dir := inputDir(t, manyReport(t, 3), "")
	s := &threadSender{failAt: 2}
	if res := runThread(t, dir, s, withBlocks); res.Exit != ExitSend || !res.Sent {
		t.Fatalf("%+v", res)
	}
	if !Notified(dir, mustKey(t, dir)) {
		t.Fatal("must mark notified after the parent was sent")
	}
	s2 := &threadSender{}
	if res := runThread(t, dir, s2, withBlocks); res.Exit != ExitOK || len(s2.got) != 0 {
		t.Fatalf("second run must not resend: %+v %d", res, len(s2.got))
	}
}

// 1 通目の応答に ts が無い (形が合わない) ときは、返信せず失敗にする。1 通目は送れているので印は書く。
func TestThreadParentWithoutTS(t *testing.T) {
	dir := inputDir(t, manyReport(t, 3), "")
	s := &threadSender{tsOf: func(int) string { return "" }}
	if res := runThread(t, dir, s, withBlocks); res.Exit != ExitSend || len(s.got) != 1 {
		t.Fatalf("%+v sent %d", res, len(s.got))
	}
	if !Notified(dir, mustKey(t, dir)) {
		t.Fatal("must mark notified")
	}
	// ts は notify の側でも形を確かめる (送る側の実装に頼らない)
	dir = inputDir(t, manyReport(t, 3), "")
	s = &threadSender{tsOf: func(int) string { return "<!channel>" }}
	if res := runThread(t, dir, s, withBlocks); res.Exit != ExitSend || len(s.got) != 1 {
		t.Fatalf("%+v sent %d", res, len(s.got))
	}
}

// 1 通目の送信に失敗したら、今と同じ (返信は送らない。印も書かない)。
func TestThreadParentFailure(t *testing.T) {
	dir := inputDir(t, manyReport(t, 3), "")
	s := &threadSender{failAt: 1}
	if res := runThread(t, dir, s, withBlocks); res.Exit != ExitSend || len(s.got) != 0 || Notified(dir, mustKey(t, dir)) {
		t.Fatalf("%+v sent %d", res, len(s.got))
	}
}

// 縮退 (原文の送信・入力の問題・静かな 1 行) は返信しない。blocks の LLM の失敗 (規則だけの Block Kit) は thread の分け方を使う。
func TestThreadDegradedNotices(t *testing.T) {
	failing := withLLM(&fakeLLM{responses: []string{"error"}})
	s := &threadSender{}
	if res := runThread(t, inputDir(t, manyReport(t, 3), ""), s, failing); res.Exit != ExitFallback || len(s.got) != 1 || !strings.Contains(s.got[0].text, FallbackNotice) {
		t.Fatalf("text fallback must be one message: %+v %d", res, len(s.got))
	}
	s = &threadSender{}
	if res := runThread(t, inputDir(t, manyReport(t, 3), ""), s, withBlocks, failing); res.Exit != ExitFallback || len(s.got) != 2 || !strings.Contains(allText(s.got[0].msg), BlocksFallbackNotice) {
		t.Fatalf("blocks fallback uses the thread split: %+v %d", res, len(s.got))
	}
	s = &threadSender{}
	if res := runThread(t, t.TempDir(), s, withBlocks); res.Exit != ExitInput || len(s.got) != 1 {
		t.Fatalf("input problem: %+v %d", res, len(s.got))
	}
	r := goldenRun(t)
	r.Findings.New, r.Findings.Changed, r.Findings.Recurred = nil, nil, nil
	r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.MaxSeverity = 0, 0, 0, ""
	r.Coverage.SourcesFailed = nil
	s = &threadSender{}
	if res := runThread(t, inputDir(t, marshal(t, r), ""), s, withBlocks); res.Exit != ExitOK || len(s.got) != 1 {
		t.Fatalf("quiet: %+v %d", res, len(s.got))
	}
}
