package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dryRunReport(t *testing.T) []byte {
	t.Helper()
	r := goldenRun(t)
	r.DryRun = true
	b, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// arata の試しの実行 (dry_run: true) の報告は送らない。誤って定時の経路に流しても通知が飛ばない (ADR 0049)。
// 通知済みの印も付けず、--force でも送らない。緊急用の重大度 (critical) があっても同じ。
func TestDryRunReportIsNotSent(t *testing.T) {
	for _, force := range []bool{false, true} {
		for _, format := range []string{"", FormatBlocks} {
			dir := inputDir(t, dryRunReport(t), "")
			s := &fakeSender{}
			res, logs := run(t, dir, s, func(o *Options) { o.Force, o.Format = force, format })
			if res.Sent || len(s.got) != 0 {
				t.Fatalf("force=%v format=%q: a dry-run report was sent: %+v", force, format, s.got)
			}
			if res.Exit != ExitOK {
				t.Fatalf("exit %d", res.Exit)
			}
			if !strings.Contains(logs.String(), CodeDryRunReport) {
				t.Fatalf("the reason must be logged with %s:\n%s", CodeDryRunReport, logs)
			}
			if _, err := os.Stat(filepath.Join(dir, NotifiedFile)); !os.IsNotExist(err) {
				t.Fatalf("a dry-run report must not be marked as notified: %v", err)
			}
		}
	}
}

// LLM も呼ばない (送らない報告の中身を外へ出さない)。
func TestDryRunReportDoesNotCallLLM(t *testing.T) {
	dir := inputDir(t, dryRunReport(t), "")
	llm := &fakeLLM{responses: []string{"error"}}
	res, _ := run(t, dir, &fakeSender{}, func(o *Options) { o.Summarizer = llm })
	if llm.calls != 0 || res.Sent {
		t.Fatalf("LLM calls=%d sent=%v", llm.calls, res.Sent)
	}
}

// aratam notify --dry-run (送らずに標準出力に出す) では文面を見られる。冒頭に試しの実行の報告であることを書く。
func TestDryRunReportIsShownByNotifyDryRun(t *testing.T) {
	for _, format := range []string{"", FormatBlocks} {
		dir := inputDir(t, dryRunReport(t), "")
		s := &fakeSender{}
		res, _ := run(t, dir, s, func(o *Options) { o.DryRun, o.Format = true, format })
		if !res.Sent || len(s.got) != 1 {
			t.Fatalf("format=%q: notify --dry-run must show the message: %+v", format, res)
		}
		shown := s.got[0].text + string(marshal(t, s.got[0].msg))
		if !strings.Contains(shown, "試しの実行") {
			t.Fatalf("format=%q: the message must say it is a dry-run report:\n%s", format, shown)
		}
		if _, err := os.Stat(filepath.Join(dir, NotifiedFile)); !os.IsNotExist(err) {
			t.Fatalf("must not be marked as notified: %v", err)
		}
	}
}

// 定時の実行の報告 (dry_run が無い) は今までどおり送る。
func TestScheduledReportIsStillSent(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), "")
	s := &fakeSender{}
	if res, _ := run(t, dir, s); !res.Sent {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(s.got[0].text, "試しの実行") {
		t.Fatal("a scheduled report must not be labelled as a dry run")
	}
}
