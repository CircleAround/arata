package notify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLLM は LLM の応答の固定値を返す。responses を順に返し、尽きたら最後のものを繰り返す。
type fakeLLM struct {
	mu        sync.Mutex
	responses []string // "block" は ctx が終わるまで待つ (時間切れ)、"error" はエラーを返す
	calls     int
	system    string
	report    []byte
}

func (f *fakeLLM) Summarize(ctx context.Context, system string, report []byte) ([]byte, error) {
	f.mu.Lock()
	i := min(f.calls, len(f.responses)-1)
	f.calls++
	f.system, f.report = system, report
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
		if !strings.Contains(missing, "id "+id+" ") {
			t.Errorf("%s must be appended:\n%s", id, missing)
		}
	}
	if strings.Contains(missing, "id f-002 ") || strings.Contains(missing, "id f-005 ") {
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
	s, err := ParseSummary([]byte(fixture(t, "fenced.txt")), in)
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
