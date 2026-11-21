package notify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 重大度の下限 (min_severity) を書いたプロファイルの報告の送り方 (ADR 0082 の 7 節)。判定はせず、送り方だけを変える。
func TestDecideMinSeverity(t *testing.T) {
	base := goldenRun(t)
	failed := []schema.SourceFailure{{Source: "s", Code: "ACCESS_DENIED"}}
	cases := []struct {
		name string
		mod  func(r *schema.Report)
		want Decision
	}{
		{"取れなかったソースだけでは静か (緊急にしない)", func(r *schema.Report) {
			r.Summary = schema.Summary{}
			r.Coverage.SourcesFailed = failed
		}, Decision{Route: RouteNormal, Quiet: true}},
		{"high の指摘は重大度で緊急", func(r *schema.Report) {
			r.Summary = schema.Summary{New: 1, MaxSeverity: "high"}
			r.Coverage.SourcesFailed = failed
		}, Decision{Route: RouteUrgent}},
		{"取れなかったソースがあっても送り先は重大度だけ", func(r *schema.Report) {
			r.Summary = schema.Summary{New: 1, MaxSeverity: "medium"}
			r.Coverage.SourcesFailed = failed
		}, Decision{Route: RouteNormal}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := *base
			tc.mod(&r)
			r.MinSeverity = "high"
			if got := Decide(&Input{Kind: KindRun, Run: &r}, Rules{UrgentSeverity: "high"}); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestRunMinSeverityQuietIsSilent(t *testing.T) {
	r := goldenRun(t)
	r.Summary = schema.Summary{StillOpen: 1, CollectErrors: []schema.CollectError{}}
	r.Findings.New, r.Findings.Changed, r.Findings.Recurred = nil, nil, nil
	r.Coverage.SourcesFailed = []schema.SourceFailure{{Source: "s", Code: "ACCESS_DENIED"}}
	r.MinSeverity = "high"
	dir := inputDir(t, marshal(t, r), "")
	s := &fakeSender{}
	// on_quiet: short でも、取れなかったソースがあっても送らない (毎時の「新規なし」と「取れなかった」を作らない)
	res, _ := run(t, dir, s)
	if res.Exit != ExitOK || res.Sent || len(s.got) != 0 {
		t.Fatalf("must not send: %+v %v", res, s.got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
		t.Fatalf("must mark: %q", b)
	}
}

func TestRunMinSeveritySaysTheScope(t *testing.T) {
	for _, format := range []string{FormatText, FormatBlocks} {
		r := goldenRun(t)
		r.MinSeverity = "high"
		dir := inputDir(t, marshal(t, r), "")
		s := &fakeSender{}
		res, _ := run(t, dir, s, func(o *Options) { o.Format = format })
		if !res.Sent || len(s.got) != 1 {
			t.Fatalf("%s: %+v", format, res)
		}
		body := s.got[0].text
		if format == FormatBlocks {
			body = string(marshal(t, s.got[0].msg.Blocks))
		}
		if !strings.Contains(body, ScopeNotice("high")) {
			t.Fatalf("%s: the scope line is missing:\n%s", format, body)
		}
	}
	// 下限の無い報告には出さない
	dir := inputDir(t, golden(t, "report.json"), "")
	s := &fakeSender{}
	if run(t, dir, s); len(s.got) != 1 || strings.Contains(s.got[0].text, "だけを見ています") {
		t.Fatalf("%v", s.got)
	}
}

// report.json の値は信用しない (ADR 0037)。語彙に無い下限は文面に載せない。
func TestScopeNoticeVocabulary(t *testing.T) {
	for _, v := range []string{"high", "critical", "medium", "low"} {
		if !strings.Contains(ScopeNotice(v), v+" 以上") {
			t.Errorf("%s: %s", v, ScopeNotice(v))
		}
	}
	for _, v := range []string{"", "info", "<!channel>", "high\n*偽*", "HIGH"} {
		if got := ScopeNotice(v); (v != "" && strings.Contains(got, v)) || !strings.Contains(got, "下限より上だけ") {
			t.Errorf("%q: %s", v, got)
		}
	}
}
