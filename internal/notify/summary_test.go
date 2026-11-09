package notify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeLLM は LLM の応答の固定値を返す。responses を順に返し、尽きたら最後のものを繰り返す。
type fakeLLM struct {
	mu        sync.Mutex
	responses []string // "block" は ctx が終わるまで待つ (時間切れ)、"error" はエラーを返す
	calls     int
	system    string
	report    []byte
	systems   []string // 呼び出しごとの system と入力 (要約と提案の書き起こしで別の呼び出しになる)
	inputs    [][]byte
}

func (f *fakeLLM) Summarize(ctx context.Context, system string, report []byte) ([]byte, error) {
	f.mu.Lock()
	i := min(f.calls, len(f.responses)-1)
	f.calls++
	f.system, f.report = system, report
	f.systems, f.inputs = append(f.systems, system), append(f.inputs, report)
	resp := f.responses[i]
	f.mu.Unlock()
	switch resp {
	case "block":
		<-ctx.Done()
		return nil, ctx.Err()
	case "error":
		return nil, errors.New("llm: service unavailable")
	}
	return []byte(resp), nil
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "llm", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func withLLM(l *fakeLLM) func(*Options) {
	return func(o *Options) {
		o.Summarizer = l
		o.LLMTimeout = 200 * time.Millisecond
	}
}

// 正常: LLM の分類と説明を決まった書式で組み立てる。重大度・概要・主要キーは report.json の値。LLM に渡すのは report.json だけ。
func TestSummaryNormal(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	l := &fakeLLM{responses: []string{fixture(t, "ok.json")}}
	s := &fakeSender{}
	res, _ := run(t, dir, s, withLLM(l))
	if res != (Result{Exit: ExitOK, Route: RouteUrgent, Sent: true}) || l.calls != 1 {
		t.Fatalf("%+v calls %d", res, l.calls)
	}
	if string(l.report) != string(golden(t, "report.json")) {
		t.Fatal("the LLM must receive report.json as is")
	}
	if !strings.Contains(l.system, "# report.json の読み方と要約の手順") || !strings.Contains(l.system, `"approve_suggestions"`) {
		t.Fatalf("system must embed docs/ai/report.md and the output contract")
	}
	checkGolden(t, "summary_report.txt", strings.ReplaceAll(s.got[0].text, dir, "<dir>"))
	if strings.Contains(s.got[0].text, "要約に含まれていなかった指摘") {
		t.Fatal("nothing is missing")
	}
}

// 欠落あり: 漏れた new / changed / recurred は規則で末尾に足す。知らない ID・知らない class・重複は捨てる。LLM の文字列もエスケープする。
func TestSummaryMissingFindingsAreAppended(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), "")
	s := &fakeSender{}
	res, _ := run(t, dir, s, withLLM(&fakeLLM{responses: []string{fixture(t, "missing.json")}}))
	if res.Exit != ExitOK {
		t.Fatalf("%+v", res)
	}
	text := s.got[0].text
	checkGolden(t, "summary_missing.txt", strings.ReplaceAll(text, dir, "<dir>"))
	if strings.Count(text, "<!channel>") != 1 || !strings.Contains(text, "root の利用が 1 件 &lt;!channel&gt;") {
		t.Errorf("only the configured mention may be live:\n%s", text)
	}
	for _, bad := range []string{"f-999", "f-998", "f-997", "LLM が作った ID", "重複"} {
		if strings.Contains(text, bad) {
			t.Errorf("%q must not appear", bad)
		}
	}
	_, missing, _ := strings.Cut(text, "*要約に含まれていなかった指摘* (規則で追加)\n")
	for _, id := range []string{"f-010", "f-001", "f-003", "f-009"} {
		if !strings.Contains(missing, "`id: "+id+"`") {
			t.Errorf("%s must be appended:\n%s", id, missing)
		}
	}
	if strings.Contains(missing, "`id: f-002`") || strings.Contains(missing, "`id: f-005`") {
		t.Errorf("classified findings must not be appended:\n%s", missing)
	}
}

// 形が不正・時間切れ・エラー: 1 回だけ再試行し、だめなら原文を送って終了コード 3。
func TestSummaryFallback(t *testing.T) {
	cases := []struct {
		name      string
		responses []string
		calls     int
		want      string
	}{
		{"形が不正", []string{fixture(t, "malformed.txt")}, 2, "not the expected JSON"},
		{"headline が無い", []string{fixture(t, "no_headline.json")}, 2, "no headline"},
		{"時間切れ", []string{"block"}, 2, "timed out after 200ms"},
		{"エラー", []string{"error"}, 2, "service unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := inputDir(t, golden(t, "report.json"), "")
			l := &fakeLLM{responses: tc.responses}
			s := &fakeSender{}
			res, logs := run(t, dir, s, withLLM(l))
			if res != (Result{Exit: ExitFallback, Route: RouteUrgent, Sent: true}) || l.calls != tc.calls {
				t.Fatalf("%+v calls %d", res, l.calls)
			}
			if !strings.Contains(logs.String(), CodeLLMRetry) || !strings.Contains(logs.String(), CodeLLMFailed) || !strings.Contains(logs.String(), tc.want) {
				t.Fatalf("logs: %s", logs)
			}
			text := s.got[0].text
			if !strings.HasPrefix(text, "<!channel>\n"+FallbackNotice+"\n*arata daily (acme)*") || !strings.Contains(text, "*新規 (3)*") {
				t.Fatalf("fallback text:\n%s", text)
			}
			if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
				t.Fatal("fallback was sent, so it must be marked")
			}
		})
	}
	// 1 回目が失敗しても 2 回目が正しければ要約を送る
	l := &fakeLLM{responses: []string{"error", fixture(t, "ok.json")}}
	s := &fakeSender{}
	if res, _ := run(t, inputDir(t, golden(t, "report.json"), ""), s, withLLM(l)); res.Exit != ExitOK || l.calls != 2 || strings.Contains(s.got[0].text, FallbackNotice) {
		t.Fatalf("retry: %+v calls %d", res, l.calls)
	}
}

// 静かなとき・入力の問題では LLM を呼ばない。
func TestSummaryNotCalledWhenNotNeeded(t *testing.T) {
	l := &fakeLLM{responses: []string{fixture(t, "ok.json")}}
	run(t, inputDir(t, quietReport(t), ""), &fakeSender{}, withLLM(l))
	run(t, t.TempDir(), &fakeSender{}, withLLM(l))
	if l.calls != 0 {
		t.Fatalf("calls %d", l.calls)
	}
}

func TestParseSummaryAcceptsFencedJSON(t *testing.T) {
	in, err := ReadInput(inputDir(t, golden(t, "report.json"), ""), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSummary([]byte(fixture(t, "fenced.txt")), in, "high")
	if err != nil || s.Headline != "コードフェンス付き" {
		t.Fatalf("%+v %v", s, err)
	}
}

// 期間レポートも同じ流れで要約する (system は期間レポートの入力であることを伝える)。
func TestSummaryPeriod(t *testing.T) {
	dir := inputDir(t, golden(t, "period.json"), string(golden(t, "period.md")))
	l := &fakeLLM{responses: []string{`{"headline": "10 月は root の利用が 1 件", "items": [], "incidents": [], "approve_suggestions": []}`}}
	s := &fakeSender{}
	res, _ := run(t, dir, s, withLLM(l), func(o *Options) { o.Now = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) })
	if res.Exit != ExitOK || !strings.Contains(l.system, `"kind": "period"`) {
		t.Fatalf("%+v", res)
	}
	checkGolden(t, "summary_period.txt", strings.ReplaceAll(s.got[0].text, dir, "<dir>"))
}

// 長い LLM 応答: 理由文は上限で切り、切り詰めは優先度で行う (情報 → 確認依頼の理由文の順に削る)。
// 見出し・要対処・インシデント候補・承認の提案は残す。
func TestSummaryLongResponseKeepsPriorities(t *testing.T) {
	long := strings.Repeat("severity high。data.count=1 の根拠があり、", 20) // 400 字超
	r := goldenRun(t)
	for i := 0; i < 40; i++ { // 情報に分類される未対応を増やす
		f := r.Findings.StillOpen[0]
		f.ID = fmt.Sprintf("f-%03d", 100+i)
		r.Findings.StillOpen = append(r.Findings.StillOpen, f)
	}
	items := []map[string]string{
		{"finding_id": "f-002", "class": "action", "reason": long},
		{"finding_id": "f-009", "class": "action", "reason": long},
		{"finding_id": "f-003", "class": "action", "reason": long},
		{"finding_id": "f-001", "class": "confirm", "reason": long},
		{"finding_id": "f-010", "class": "confirm", "reason": long},
	}
	for i := 0; i < 40; i++ {
		items = append(items, map[string]string{"finding_id": fmt.Sprintf("f-%03d", 100+i), "class": "info", "reason": long})
	}
	resp := marshal(t, map[string]any{
		"headline":            "見出し",
		"items":               items,
		"incidents":           []map[string]any{{"finding_ids": []string{"f-002", "f-001"}, "summary": long}},
		"approve_suggestions": []map[string]string{{"finding_id": "f-001", "reason": long}},
	})
	s := &fakeSender{}
	res, _ := run(t, inputDir(t, marshal(t, r), ""), s, withLLM(&fakeLLM{responses: []string{string(resp)}}))
	text := s.got[0].text
	if res.Exit != ExitOK || utf8.RuneCountInString(text) > MaxTextRunes {
		t.Fatalf("%+v len %d", res, utf8.RuneCountInString(text))
	}
	for _, want := range []string{"見出し", "*要対処*", "`id: f-009`", "*インシデント候補*", "*approve の提案*", "`arata approve f-001 --note \"...\"`", "*取れなかったソース*", "全文: "} {
		if !strings.Contains(text, want) {
			t.Errorf("%q must remain:\n%s", want, text)
		}
	}
	// 理由文は 200 字で切る
	for _, l := range strings.Split(text, "\n") {
		if r := utf8.RuneCountInString(l); r > 260 {
			t.Errorf("line too long (%d): %s", r, l)
		}
	}
	// 情報は件数だけになり、個々の行は出ない
	if strings.Contains(text, "`id: f-120`") || !strings.Contains(text, "*情報* 40 件 (長いため省略)") {
		t.Errorf("info must be collapsed:\n%s", text)
	}
	if strings.Contains(text, "…(長いため省略)") {
		t.Errorf("priority trimming should be enough here:\n%s", text)
	}
}

// 優先度で削っても収まらないときも、承認の提案は必ず残す (要対処の行を末尾から切る)。
func TestSummaryApproveSuggestionsAlwaysRemain(t *testing.T) {
	r := goldenRun(t)
	var items []map[string]string
	for i := 0; i < 80; i++ {
		f := r.Findings.New[0]
		f.ID = fmt.Sprintf("f-%03d", 200+i)
		r.Findings.New = append(r.Findings.New, f)
		items = append(items, map[string]string{"finding_id": f.ID, "class": "action", "reason": "root の利用"})
	}
	resp := marshal(t, map[string]any{"headline": "多い", "items": items, "incidents": []any{},
		"approve_suggestions": []map[string]string{{"finding_id": "f-001", "reason": "デプロイ用の可能性"}}})
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s, withLLM(&fakeLLM{responses: []string{string(resp)}}))
	text := s.got[0].text
	if utf8.RuneCountInString(text) > MaxTextRunes || !strings.Contains(text, "`arata approve f-001 --note \"...\"`") || !strings.Contains(text, "…(長いため省略)") {
		t.Fatalf("len %d:\n%s", utf8.RuneCountInString(text), text)
	}
}

// 切り詰め (reason / approve / incidents / 全体) はすべて文字 (rune) 単位で、マルチバイト文字を途中で切らない。
func TestTruncationKeepsValidUTF8(t *testing.T) {
	r := goldenRun(t)
	for i := 0; i < 60; i++ {
		f := r.Findings.New[0]
		f.ID = fmt.Sprintf("f-%03d", 300+i)
		f.Summary = strings.Repeat("呼び出し元が不明🔑", 8)
		r.Findings.New = append(r.Findings.New, f)
	}
	for shift := 0; shift < 4; shift++ { // 先頭をずらし、上限の位置がマルチバイト文字のどの位置にも来るようにする
		long := strings.Repeat("a", shift) + strings.Repeat("同じ主体からの呼び出しが続いている🔑", 30)
		items := []map[string]string{}
		for i := 0; i < 60; i++ {
			items = append(items, map[string]string{"finding_id": fmt.Sprintf("f-%03d", 300+i), "class": "action", "reason": long})
		}
		resp := marshal(t, map[string]any{"headline": long, "items": items,
			"incidents":           []map[string]any{{"finding_ids": []string{"f-300"}, "summary": long}},
			"approve_suggestions": []map[string]string{{"finding_id": "f-001", "reason": long}}})
		s := &fakeSender{}
		run(t, inputDir(t, marshal(t, r), ""), s, withLLM(&fakeLLM{responses: []string{string(resp)}}))
		text := s.got[0].text
		if !utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) {
			t.Fatalf("shift %d: invalid UTF-8 in the message", shift)
		}
		if n := utf8.RuneCountInString(text); n > MaxTextRunes {
			t.Fatalf("shift %d: %d runes", shift, n)
		}
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, "• f-300: ") && !strings.HasSuffix(l, "…") {
				t.Fatalf("incident summary must be clipped: %s", l)
			}
		}
	}
	// ReportText (原文) の切り詰めも同じ
	dir := inputDir(t, marshal(t, r), "")
	s := &fakeSender{}
	run(t, dir, s)
	if !utf8.ValidString(s.got[0].text) || utf8.RuneCountInString(s.got[0].text) > MaxTextRunes {
		t.Fatal("report text must be valid UTF-8 within the limit")
	}
}
