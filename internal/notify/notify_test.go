package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/report/schema"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

// arata の report.json / report.md のゴールデン (internal/report が固定しているもの) をそのまま入力にする。
// 形が変われば aratam のテストも落ちる (arata と aratam の契約)。
const goldenDir = "../report/testdata"

// generated_at (2026-10-21T09:00:00Z) の 1 時間後。
var now = time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

var rules = Rules{Name: "acme", MaxAge: 26 * time.Hour, UrgentSeverity: "high", OnQuiet: "short", UrgentMention: "<!channel>"}

type sent struct {
	route Route
	text  string
	msg   Message
}

type fakeSender struct {
	got []sent
	err error
}

func (f *fakeSender) Send(_ context.Context, r Route, m Message) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, sent{r, m.Text, m})
	return nil
}

// inputDir は report.json (と report.md) を一時ディレクトリに置く。md が空なら report.md を置かない。
func inputDir(t *testing.T, reportJSON []byte, md string) string {
	t.Helper()
	dir := t.TempDir()
	if reportJSON != nil {
		if err := os.WriteFile(filepath.Join(dir, ReportJSON), reportJSON, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if md != "" {
		if err := os.WriteFile(filepath.Join(dir, ReportMD), []byte(md), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenRun(t *testing.T) *schema.Report {
	t.Helper()
	r, err := schema.Parse(golden(t, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func run(t *testing.T, dir string, s *fakeSender, mod ...func(*Options)) (Result, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	o := Options{Dir: dir, Now: now, Rules: rules, Sender: s, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	for _, m := range mod {
		m(&o)
	}
	return Run(context.Background(), o), &logs
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if got != string(want) {
		t.Fatalf("%s differs (run with -update to refresh)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestDecide(t *testing.T) {
	base := goldenRun(t)
	cases := []struct {
		name   string
		mod    func(r *schema.Report)
		urgent string
		want   Decision
	}{
		{"critical と取得失敗 → 緊急", func(*schema.Report) {}, "high", Decision{Route: RouteUrgent}},
		{"medium は high 未満 → 通常", func(r *schema.Report) { r.Summary.MaxSeverity = "medium"; r.Coverage.SourcesFailed = nil }, "high", Decision{Route: RouteNormal}},
		{"medium でも下限が medium なら緊急", func(r *schema.Report) { r.Summary.MaxSeverity = "medium"; r.Coverage.SourcesFailed = nil }, "medium", Decision{Route: RouteUrgent}},
		{"取得失敗だけでも緊急", func(r *schema.Report) {
			r.Summary.MaxSeverity = "low"
			r.Coverage.SourcesFailed = []schema.SourceFailure{{Source: "s", Code: "ACCESS_DENIED", Partial: true}}
		}, "high", Decision{Route: RouteUrgent}},
		{"0 件で取得失敗なし → 静か", func(r *schema.Report) {
			r.Summary = schema.Summary{StillOpen: 2}
			r.Coverage.SourcesFailed = nil
		}, "high", Decision{Route: RouteNormal, Quiet: true}},
		{"0 件でも取得失敗があれば静かでない (緊急)", func(r *schema.Report) {
			r.Summary = schema.Summary{}
		}, "high", Decision{Route: RouteUrgent}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := *base
			tc.mod(&r)
			got := Decide(&Input{Kind: KindRun, Run: &r}, Rules{UrgentSeverity: tc.urgent})
			if got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
	// 期間レポートは常に通常用で、0 件でも静かとみなさない
	if got := Decide(&Input{Kind: KindPeriod, Period: &schema.PeriodReport{}}, rules); got != (Decision{Route: RouteNormal}) {
		t.Fatalf("period: %+v", got)
	}
}

// provider: none の通知 (report.md を整形して送る) のゴールデン。送ったら .aratam-notified に run_id を書き、同じ run は二度送らない。
func TestRunNoneSendsReportAndPreventsDuplicates(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	s := &fakeSender{}
	res, _ := run(t, dir, s)
	if res != (Result{Exit: ExitOK, Route: RouteUrgent, Sent: true}) || len(s.got) != 1 || s.got[0].route != RouteUrgent {
		t.Fatalf("result %+v sent %+v", res, s.got)
	}
	checkGolden(t, "none_report.txt", strings.ReplaceAll(s.got[0].text, dir, "<dir>"))
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
		t.Fatalf(".aratam-notified: %q", b)
	}

	res, logs := run(t, dir, s)
	if res != (Result{Exit: ExitOK}) || len(s.got) != 1 || !strings.Contains(logs.String(), CodeAlreadyNotified) {
		t.Fatalf("second run must not send: %+v %d %s", res, len(s.got), logs)
	}
	res, _ = run(t, dir, s, func(o *Options) { o.Force = true })
	if !res.Sent || len(s.got) != 2 {
		t.Fatalf("--force must resend: %+v", res)
	}
}

func TestRunDryRunDoesNotMark(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), "")
	s := &fakeSender{}
	res, _ := run(t, dir, s, func(o *Options) { o.DryRun = true })
	if !res.Sent || len(s.got) != 1 {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, NotifiedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run must not write %s: %v", NotifiedFile, err)
	}
	// report.md が無ければ report.json から arata と同じ書式で作る
	if !strings.Contains(s.got[0].text, "*新規 (3)*") {
		t.Fatalf("the text must be rendered from report.json:\n%s", s.got[0].text)
	}
}

func TestRunPeriodReport(t *testing.T) {
	dir := inputDir(t, golden(t, "period.json"), string(golden(t, "period.md")))
	s := &fakeSender{}
	res, _ := run(t, dir, s, func(o *Options) { o.Now = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) })
	if res.Exit != ExitOK || len(s.got) != 1 || s.got[0].route != RouteNormal || !strings.HasPrefix(s.got[0].text, "*arata 期間レポート (acme)*") || strings.Contains(s.got[0].text, "(0)*") {
		t.Fatalf("%+v %+v", res, s.got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "period:2026-10-01/2026-10-31@2026-10-31T23:00:00Z\n" {
		t.Fatalf(".aratam-notified: %q", b)
	}
}

func quietReport(t *testing.T) []byte {
	r := goldenRun(t)
	r.Summary = schema.Summary{StillOpen: 4, MaxSeverity: "", CollectErrors: []schema.CollectError{}}
	r.Findings.New, r.Findings.Changed, r.Findings.Recurred = nil, nil, nil
	r.Coverage.SourcesFailed = []schema.SourceFailure{}
	return marshal(t, r)
}

func TestRunQuiet(t *testing.T) {
	dir := inputDir(t, quietReport(t), "")
	s := &fakeSender{}
	if res, _ := run(t, dir, s); res.Exit != ExitOK || len(s.got) != 1 || s.got[0].route != RouteNormal ||
		s.got[0].text != "*arata daily (acme)* 2026-10-20T09:00:00Z 〜 2026-10-21T09:00:00Z: 新規なし (変化・再発なし、取得の失敗なし。未対応 4 件)" {
		t.Fatalf("short: %+v %v", res, s.got)
	}

	dir = inputDir(t, quietReport(t), "")
	s = &fakeSender{}
	res, _ := run(t, dir, s, func(o *Options) { o.Rules.OnQuiet = "silent" })
	if res.Exit != ExitOK || res.Sent || len(s.got) != 0 {
		t.Fatalf("silent must not send: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, NotifiedFile)); string(b) != "run-1\n" {
		t.Fatalf("silent must still mark: %q", b)
	}
}

// report.json が無い・読めない・古い → 緊急用に直接送って終了コード 4。
func TestRunInputProblems(t *testing.T) {
	stale := goldenRun(t)
	stale.GeneratedAt = "2026-10-19T00:00:00Z"
	noTime := goldenRun(t)
	noTime.GeneratedAt = ""
	cases := []struct {
		name, code string
		body       []byte
	}{
		{"無い", CodeInputMissing, nil},
		{"JSON でない", CodeInputInvalid, []byte("{not json")},
		{"generated_at が無い", CodeInputInvalid, marshal(t, noTime)},
		{"知らない kind", CodeInputInvalid, []byte(`{"kind":"weekly-digest","generated_at":"2026-10-21T09:00:00Z"}`)},
		{"古い", CodeInputStale, marshal(t, stale)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := inputDir(t, tc.body, "")
			s := &fakeSender{}
			res, logs := run(t, dir, s)
			if res != (Result{Exit: ExitInput, Route: RouteUrgent, Sent: true}) || len(s.got) != 1 || s.got[0].route != RouteUrgent {
				t.Fatalf("%+v %+v", res, s.got)
			}
			text := s.got[0].text
			if !strings.HasPrefix(text, "<!channel>\n*arata の出力が無いか古いため") || !strings.Contains(text, "`"+tc.code+"`") || !strings.Contains(text, dir) ||
				!strings.Contains(logs.String(), tc.code) {
				t.Fatalf("text:\n%s\nlogs: %s", text, logs)
			}
			if _, err := os.Stat(filepath.Join(dir, NotifiedFile)); err == nil {
				t.Fatal("input problems must not mark")
			}
		})
	}
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, stale), ""), s)
	if !strings.Contains(s.got[0].text, "max_age 26h0m0s より古い") {
		t.Fatalf("stale reason: %s", s.got[0].text)
	}
}

func TestRunSendFailure(t *testing.T) {
	s := &fakeSender{err: errors.New("slack: webhook returned 500: oops")}
	dir := inputDir(t, golden(t, "report.json"), "")
	res, logs := run(t, dir, s)
	if res.Exit != ExitSend || !strings.Contains(logs.String(), CodeSendFailed) || !strings.Contains(logs.String(), "oops") {
		t.Fatalf("%+v %s", res, logs)
	}
	if _, err := os.Stat(filepath.Join(dir, NotifiedFile)); err == nil {
		t.Fatal("failed send must not mark")
	}
	// 入力の問題を送れなかったときも 5
	if res, _ := run(t, t.TempDir(), s); res.Exit != ExitSend {
		t.Fatalf("input problem + send failure: %+v", res)
	}
}

func TestRunNameMismatchWarns(t *testing.T) {
	s := &fakeSender{}
	res, logs := run(t, inputDir(t, golden(t, "report.json"), ""), s, func(o *Options) { o.Rules.Name = "other" })
	if !res.Sent || !strings.Contains(logs.String(), CodeNameMismatch) ||
		!strings.Contains(s.got[0].text, ":warning: 設定の name (other) と report.json の name (acme) が違います") {
		t.Fatalf("%+v %s\n%s", res, logs, s.got[0].text)
	}
}

// 緊急用の Webhook があるとき (UrgentMention が空) はメンションを付けない。通常用ではメンションを付けない。
func TestMention(t *testing.T) {
	s := &fakeSender{}
	run(t, inputDir(t, golden(t, "report.json"), ""), s, func(o *Options) { o.Rules.UrgentMention = "" })
	if strings.Contains(s.got[0].text, "<!channel>") {
		t.Fatalf("no mention expected:\n%s", s.got[0].text)
	}
	r := goldenRun(t)
	r.Summary.MaxSeverity = "low"
	r.Coverage.SourcesFailed = nil
	s = &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s)
	if s.got[0].route != RouteNormal || strings.HasPrefix(s.got[0].text, "<!channel>") {
		t.Fatalf("normal route must not mention:\n%s", s.got[0].text)
	}
}

// ログ由来の値がメンションやリンクとして働かないよう、report の文字列は & < > をエスケープする。
func TestReportValuesAreEscaped(t *testing.T) {
	r := goldenRun(t)
	r.Findings.New[0].Summary = "UA <!channel> <https://evil.example|click> & more"
	r.Findings.New[0].Data = map[string]any{"count": 1, "ips": []string{"<!here>"}}
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s, func(o *Options) { o.Rules.UrgentMention = "" })
	text := s.got[0].text
	if strings.Contains(text, "<!channel>") || strings.Contains(text, "<!here>") || strings.Contains(text, "<https://") ||
		!strings.Contains(text, "• *[critical]* UA &lt;!channel&gt; &lt;https://evil.example|click&gt; &amp; more `root_usage`\n    count 1 · ips &lt;!here&gt; · 初出 2026-10-21T09:00:00Z · `id: f-002`") {
		t.Fatalf("not escaped:\n%s", text)
	}
}

func TestLongReportIsTruncated(t *testing.T) {
	r := goldenRun(t)
	for i := 0; i < 200; i++ {
		f := r.Findings.New[2]
		f.ID = fmt.Sprintf("f-%03d", 100+i)
		r.Findings.StillOpen = append(r.Findings.StillOpen, f)
	}
	dir := inputDir(t, marshal(t, r), "")
	s := &fakeSender{}
	run(t, dir, s)
	text := s.got[0].text
	if n := utf8.RuneCountInString(text); n > MaxTextRunes {
		t.Fatalf("too long: %d", n)
	}
	if !strings.HasPrefix(text, "<!channel>\n*arata daily (acme)*") ||
		!strings.HasSuffix(text, "…(長いため省略)\n全文: "+filepath.Join(dir, ReportMD)) {
		t.Fatalf("truncated text:\n%s", text[len(text)-300:])
	}
}

// 件数 0 の区分は出さない (run は report.json から作り、期間レポートは report.md の節を除く)。
func TestEmptySectionsAreOmitted(t *testing.T) {
	r := goldenRun(t)
	r.Findings.Changed, r.Findings.Recurred, r.Info = nil, nil, nil
	s := &fakeSender{}
	run(t, inputDir(t, marshal(t, r), ""), s)
	for _, h := range []string{"*変化", "*再発", "*情報", "ありません"} {
		if strings.Contains(s.got[0].text, h) {
			t.Errorf("%s must be omitted:\n%s", h, s.got[0].text)
		}
	}
	md := "# t\n\n- x\n\n## 新規 (1)\n\n- a\n\n## 再発 (0)\n\nありません。\n\n## 新規の主体 (0)\n\n期間内に初めて観測した主体はありません。\n\n## 実行の状況\n\n- y\n"
	if got := dropEmptySections(md); got != "# t\n\n- x\n\n## 新規 (1)\n\n- a\n\n## 実行の状況\n\n- y\n" {
		t.Fatalf("%q", got)
	}
}

// finding はチェックごとの主要キーだけを 1 行に出し、summary に既に入っている値は繰り返さない。
func TestDetailShowsKeyFieldsOnly(t *testing.T) {
	cases := []struct {
		f    schema.Finding
		want string
	}{
		{schema.Finding{ID: "f-1", Check: "unknown_assume_role", Summary: "既知リストに無い arn:aws:iam::111111111111:user/ci が arn:aws:iam::111111111111:role/admin を 2 回引き受け", FirstSeen: "2026-10-20T08:00:00Z",
			Data: map[string]any{"caller": "arn:aws:iam::111111111111:user/ci", "caller_kind": "IAMUser", "count": 2.0, "ips": []any{"203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8"}, "last_time": "2026-10-21T01:00:00Z", "event_names": []any{"AssumeRole"}}},
			"ips 203.0.113.5, 203.0.113.6, 203.0.113.7 他 1 · last_time 2026-10-21T01:00:00Z · 初出 2026-10-20T08:00:00Z · `id: f-1`"},
		{schema.Finding{ID: "f-2", Check: "login_bruteforce", Summary: "ログイン失敗が平常帯を超過: 198.51.100.7 から 52 件", FirstSeen: "2026-10-21T09:00:00Z",
			Data: map[string]any{"ip": "198.51.100.7", "count": 52.0, "date": "2026-10-20", "reason": "above_baseline", "threshold": 20.0, "baseline_median": 3.0, "baseline_days_with_data": 14.0}},
			"date 2026-10-20 (UTC) · reason above_baseline · threshold 20 · 初出 2026-10-21T09:00:00Z · `id: f-2`"},
		{schema.Finding{ID: "f-4", Check: "access_denied", Summary: "拒否された API 呼び出し: arn:aws:iam::123456789012:role/example が 6 種類 (7 件) で拒否 (列挙の兆候)", FirstSeen: "2026-10-21T09:00:00Z",
			Data: map[string]any{"principal": "arn:aws:iam::123456789012:role/example", "count": 7.0, "distinct_apis": 6.0, "allowlist_status": "approved", "threshold": "breadth",
				"apis": []any{"iam:ListUsers × 2", "s3:ListBuckets × 1", "ec2:DescribeInstances × 1", "iam:CreateUser × 1"}, "ips": []any{"198.51.100.1"}, "error_codes": []any{"AccessDenied"}}},
			"apis iam:ListUsers × 2, s3:ListBuckets × 1, ec2:DescribeInstances × 1 他 1 · ips 198.51.100.1 · allowlist_status approved · 初出 2026-10-21T09:00:00Z · `id: f-4`"},
		{schema.Finding{ID: "f-3", Check: "some_future_check", Summary: "何か", FirstSeen: "2026-10-21T09:00:00Z",
			Data: map[string]any{"count": 3.0, "ips": []any{"192.0.2.1"}, "other": "x"}},
			"count 3 · ips 192.0.2.1 · 初出 2026-10-21T09:00:00Z · `id: f-3`"},
	}
	for _, tc := range cases {
		if got := detail(tc.f); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.f.Check, got, tc.want)
		}
	}
}

func TestMarkNotifiedFailureKeepsExit(t *testing.T) {
	dir := inputDir(t, golden(t, "report.json"), "")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600) == nil {
		t.Skip("directory is writable (running as root?)")
	}
	s := &fakeSender{}
	res, logs := run(t, dir, s)
	if res.Exit != ExitOK || !res.Sent || !strings.Contains(logs.String(), CodeMarkFailed) {
		t.Fatalf("%+v %s", res, logs)
	}
}

// arata が report.json に足した節 (proposals) や、この aratam が知らない節があっても止まらず、本文の通知は変わらない (ADR 0018・0023)。
// proposals は 2 通目として通常用に送る (ADR 0024。proposals_test.go)。
func TestUnknownSectionsAreIgnored(t *testing.T) {
	base := inputDir(t, golden(t, "report.json"), string(golden(t, "report.md")))
	s0 := &fakeSender{}
	run(t, base, s0)

	var m map[string]any
	if err := json.Unmarshal(golden(t, "report.json"), &m); err != nil {
		t.Fatal(err)
	}
	m["proposals"] = []any{map[string]any{"kind": "probe_allowed", "stage": "count_first", "web_acl": "prod-waf", "summary": "探索が許可された", "evidence": map[string]any{"count": 12}},
		map[string]any{"kind": "observation", "about": "false_positive", "reason": "undetermined", "stage": "none", "web_acl": "prod-waf", "summary": "s", "evidence": map[string]any{}}}
	m["future_section"] = map[string]any{"x": 1}
	dir := inputDir(t, marshal(t, m), string(golden(t, "report.md")))
	s := &fakeSender{}
	res, _ := run(t, dir, s)
	if res.Exit != ExitOK || !res.Sent || len(s.got) != 2 {
		t.Fatalf("%+v %+v", res, s.got)
	}
	if got, want := strings.ReplaceAll(s.got[0].text, dir, "<dir>"), strings.ReplaceAll(s0.got[0].text, base, "<dir>"); got != want {
		t.Fatalf("notification changed:\n%s\nwant:\n%s", got, want)
	}
	r, err := schema.Parse(marshal(t, m))
	if err != nil || len(r.Proposals) != 2 || r.Proposals[1].Reason != "undetermined" {
		t.Fatalf("%v %+v", err, r)
	}
}

// ack 中の finding の重大度が上がったとき、arata は新しい class を足さず changed に印を付けて出す (ADR 0022)。
// aratam は max_severity で緊急用に振り分け、変化として本文に出す (aratam 側の変更なしで届くことを固定する)。
func TestEscalatedChangedGoesUrgent(t *testing.T) {
	r := goldenRun(t)
	f := schema.Finding{ID: "f-ad", Check: "access_denied", Key: "arn:aws:iam::123456789012:role/ai-investigation-readonly", Severity: "high", Status: "open",
		Summary:   "(確認済み (ack) だったが重大度が medium → high に上昇) 拒否された API 呼び出し: arn:aws:iam::123456789012:role/ai-investigation-readonly が 22 種類 (22 件) で拒否 (列挙の兆候)",
		FirstSeen: "2026-10-18T09:00:00Z", LastSeen: "2026-10-21T09:00:00Z", LastChanged: "2026-10-21T09:00:00Z",
		Data: map[string]any{"escalated_from_suppressed": true, "suppressed_status": "acked", "suppressed_severity": "medium", "distinct_apis": 22}}
	r.Summary = schema.Summary{Changed: 1, MaxSeverity: "high", CollectErrors: []schema.CollectError{}}
	r.Findings = schema.Findings{New: []schema.Finding{}, Changed: []schema.Finding{f}, Recurred: []schema.Finding{}, Resolved: []schema.Finding{}, StillOpen: []schema.Finding{}}
	r.AlreadyReported, r.Info = []schema.Finding{}, []schema.Finding{}
	r.Coverage.SourcesFailed = []schema.SourceFailure{}
	s := &fakeSender{}
	res, _ := run(t, inputDir(t, marshal(t, r), ""), s)
	if res.Route != RouteUrgent || !res.Sent || len(s.got) != 1 || s.got[0].route != RouteUrgent {
		t.Fatalf("escalated high must go urgent: %+v %+v", res, s.got)
	}
	if !strings.Contains(s.got[0].text, "medium → high に上昇") {
		t.Fatalf("text must show the escalation:\n%s", s.got[0].text)
	}
}
