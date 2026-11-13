package schema

import (
	"strings"
	"testing"
)

// ログ由来の値の改行で report.md に偽の見出しを作らせない (期間レポートの通知は report.md から作る)。
func TestMarkdownKeepsLogValuesOnOneLine(t *testing.T) {
	const hostile = "/x\n## 新規 (0)\r\n- 偽の行"
	r := &Report{Name: "n", Profile: "daily"}
	r.Findings.New = []Finding{{ID: "f", Check: "probe_paths", Severity: "low", Summary: hostile, Data: map[string]any{"path": hostile}}}
	r.Proposals = []Proposal{
		{Kind: "false_positive", Stage: "count_first", Summary: hostile, Evidence: map[string]any{"path": hostile}},
		{Kind: "observation", About: "a", Reason: "b", Summary: hostile},
	}
	for _, l := range strings.Split(r.Markdown(), "\n") {
		if l == "## 新規 (0)" || strings.HasPrefix(l, "- 偽の行") {
			t.Errorf("ログの改行で行が作られた: %q", l)
		}
	}
}

// 主体がアカウントしか分からない finding (data.external_account) は、report.md で ARN (`...:root`) を「外部アカウント NNN (呼び出した主体は記録に無い)」と書く。
// report.md は LLM が使えないときの通知の本文にもなる。ルートユーザーが使われたと読ませない。
func TestMarkdownAccountOnlyCaller(t *testing.T) {
	const root = "arn:aws:iam::111122223333:root"
	r := &Report{Name: "n", Profile: "hourly"}
	r.Findings.New = []Finding{
		{ID: "f1", Check: "unknown_assume_role", Key: root + "->arn:aws:iam::123456789012:role/Admin", Severity: "high",
			Summary: "既知リストに無い外部アカウント 111122223333 (呼び出した主体は記録に無い) が自アカウントのロール Admin を 1 回引き受け (内向き、MFA 不明)",
			Data:    map[string]any{"caller": root, "caller_kind": "unknown", "caller_identity": "account_only", "external_account": "111122223333", "role_arn": "arn:aws:iam::123456789012:role/Admin"}},
		// 以前の版の arata が作った finding (caller_identity が無い) も external_account で分かる
		{ID: "f2", Check: "access_denied", Key: root, Severity: "medium", Summary: "s", Data: map[string]any{"principal": root, "external_account": "111122223333"}},
		// 本物のルートユーザー (external_account が無い) はそのまま
		{ID: "f3", Check: "root_usage", Key: "arn:aws:iam::123456789012:root|203.0.113.1", Severity: "critical", Summary: "s", Data: map[string]any{"principal": "arn:aws:iam::123456789012:root"}},
		// external_account と違うアカウントの ARN、形の違う値は置き換えない
		{ID: "f4", Check: "new_principal", Key: "k", Severity: "medium", Summary: "s", Data: map[string]any{"principal": "arn:aws:iam::444455556666:root", "external_account": "111122223333", "note": root + "x"}},
	}
	md := r.Markdown()
	for _, want := range []string{
		"  - caller: 外部アカウント 111122223333 (呼び出した主体は記録に無い)\n",
		"  - caller_identity: account_only\n",
		"  - principal: 外部アカウント 111122223333 (呼び出した主体は記録に無い)\n",
		"  - principal: arn:aws:iam::123456789012:root\n",
		"  - principal: arn:aws:iam::444455556666:root\n",
		"  - note: " + root + "x\n",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report.md に %q が無い:\n%s", want, md)
		}
	}
	if strings.Contains(md, ": "+root+"\n") {
		t.Errorf("アカウントしか分からない主体の ARN が root のまま出た:\n%s", md)
	}
}

func TestFindingAccountOnly(t *testing.T) {
	for _, c := range []struct {
		data map[string]any
		want string
	}{
		{map[string]any{"external_account": "111122223333"}, "111122223333"},
		{map[string]any{"external_account": "111122223333\n"}, ""},
		{map[string]any{"external_account": "１１１１２２２２３３３３"}, ""},
		{map[string]any{"external_account": 111122223333.0}, ""},
		{map[string]any{"caller_identity": "account_only"}, ""}, // アカウント ID が無ければ置き換える先が無い
		{nil, ""},
	} {
		got, ok := Finding{Data: c.data}.AccountOnly()
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%v: %q %v", c.data, got, ok)
		}
	}
}

// 試しの実行 (ADR 0049) の report.md は冒頭にその旨を書き、カバレッジに注記を出す。定時の実行の report.md は変わらない。
func TestMarkdownDryRun(t *testing.T) {
	r := &Report{Name: "acme", Profile: "daily"}
	plain := r.Markdown()
	if strings.Contains(plain, "試しの実行") || strings.Contains(plain, "注意") {
		t.Fatalf("a scheduled report must not mention a dry run:\n%s", plain)
	}
	r.DryRun, r.Coverage.Notes = true, []string{"見た範囲は A から B まで\n## 偽の見出し"}
	md := r.Markdown()
	head, cov, _ := strings.Cut(md, "## カバレッジ")
	if !strings.Contains(head, "試しの実行 (--dry-run)") {
		t.Fatalf("the head must say it is a dry run:\n%s", md)
	}
	if !strings.Contains(cov, "- **注意**: 見た範囲は A から B まで ## 偽の見出し\n") {
		t.Fatalf("the note must be one line under coverage:\n%s", md)
	}
	if got, want := strings.Count(md, "\n"), strings.Count(plain, "\n")+2; got != want {
		t.Fatalf("lines: got %d want %d", got, want)
	}
}
