package ai

import (
	"regexp"
	"strings"
	"testing"
)

// TestSections は各トピックの見出しを固定する。見出しを変えたら help ai を読む側 (組み込みの LLM プロンプト) も見直すこと。
func TestSections(t *testing.T) {
	want := map[string][]string{
		"ai":        {"概要", "概念", "コマンド", "終了コード", "標準エラーのログと code", "allowlist.yaml の形式", "認証の注意", "次に読むもの"},
		"ai report": {"report.json の構造", "読む順序", "要約の手順", "相関付け", "分類の基準", "書いてはいけないこと", "追加の裏取り (任意)", "WAF の修正提案の候補 (proposals)", "期間レポート (report --month / --from --to)", "approve について"},
		"ai approve": {"原則", "allowlist.yaml を PR で直す運用", "承認してよい主体の目安", "SaaS 連携は account で承認する", "行き先を既知にする (assume_destinations)", "監査する側のアカウント (audit_account)", "外部アカウント root の見方", "arn_pattern の使いどころ",
			"期限付き承認の使いどころ", "tags の語彙", "access_denied が鳴ったとき", "principal_new_source・secret_access が鳴ったとき", "approve ではなく ack / snooze / resolve にするもの"},
		"ai runtime":  {"使い方", "リポジトリと fork", "ワークフローのトリガー", "OIDC の信頼", "main の保護と書き込み権限", "secrets", "Actions の設定", "ワークフローの形", "監査対象の前提 (context_file) の下書き", "報告の書き方"},
		"ai playbook": {"使い方", "一覧"},
	}
	for _, tp := range Topics {
		d := tp.Parse()
		var got []string
		for _, s := range d.Sections {
			got = append(got, s.Title)
			if s.Body == "" {
				t.Errorf("%s: section %q is empty", tp.Name, s.Title)
			}
		}
		if strings.Join(got, "|") != strings.Join(want[tp.Name], "|") {
			t.Errorf("%s sections:\n got %v\nwant %v", tp.Name, got, want[tp.Name])
		}
		if d.Title == "" {
			t.Errorf("%s: no title", tp.Name)
		}
		if n := strings.Count(tp.Markdown(), "\n"); n > 150 {
			t.Errorf("%s: %d lines (keep it within about 150)", tp.Name, n)
		}
	}
}

func TestLookup(t *testing.T) {
	for _, sub := range []string{"", "report", "approve", "runtime", "playbook", "playbook root_usage"} {
		if _, err := Lookup(sub); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Lookup("nope"); err == nil || !strings.Contains(err.Error(), "arata help ai report") || !strings.Contains(err.Error(), "arata help ai playbook") {
		t.Fatalf("%v", err)
	}
	if _, err := Lookup("playbook nope"); err == nil || !strings.Contains(err.Error(), "root_usage") {
		t.Fatalf("unknown playbook must list the checks: %v", err)
	}
}

// TestCodesDocumented は help ai に固定語彙の code が全部書かれていることを確かめる。
func TestCodesDocumented(t *testing.T) {
	idx, _ := Lookup("")
	for _, code := range []string{"ACCESS_DENIED", "LOG_GROUP_MISSING", "FORMAT_MISMATCH", "FORMAT_DRIFT", "QUERY_LIMIT", "QUERY_INVALID", "STORE_LOCKED", "STORE_CORRUPT", "RUN_MISSED", "COLLECT_FAILED", "CONFIG_INVALID"} {
		if !strings.Contains(idx.Markdown(), "`"+code+"`") {
			t.Errorf("code %s is not documented", code)
		}
	}
}

// TestPlaybooks は playbook の書式を固定する。見出しは aratam が LLM の system に埋め込むときの約束でもある。
func TestPlaybooks(t *testing.T) {
	names := PlaybookNames()
	if len(names) == 0 {
		t.Fatal("no playbooks")
	}
	acct := regexp.MustCompile(`\b\d{12}\b`)
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	for _, name := range names {
		body, ok := Playbook(name)
		if !ok || body == "" {
			t.Fatalf("%s: Playbook() is empty", name)
		}
		tp, err := Lookup("playbook " + name)
		if err != nil {
			t.Fatal(err)
		}
		if tp.Markdown() != body {
			t.Fatalf("%s: help ai playbook differs from Playbook()", name)
		}
		d := tp.Parse()
		if !strings.HasPrefix(d.Title, name+": ") {
			t.Errorf("%s: title %q must start with %q", name, d.Title, name+": ")
		}
		var got []string
		for _, s := range d.Sections {
			got = append(got, s.Title)
			if s.Body == "" {
				t.Errorf("%s: section %q is empty", name, s.Title)
			}
		}
		if strings.Join(got, "|") != strings.Join(PlaybookSections, "|") {
			t.Errorf("%s sections:\n got %v\nwant %v", name, got, PlaybookSections)
		}
		sec := map[string]string{}
		for _, s := range d.Sections {
			sec[s.Title] = s.Body
		}
		if !strings.Contains(sec["まず確かめること"], "\n2. ") && !strings.HasPrefix(sec["まず確かめること"], "1. ") {
			t.Errorf("%s: まず確かめること must be a numbered list", name)
		}
		if !strings.Contains(sec["まず確かめること"], "arata ") {
			t.Errorf("%s: まず確かめること must name an arata command", name)
		}
		// 封じ込めや状態の変更は人が判断する (approve と同じ方針)
		if !strings.Contains(sec["対処の選択肢"], "人が") {
			t.Errorf("%s: 対処の選択肢 must say that a person decides", name)
		}
		// 顧客の情報を書かない: アカウント ID は架空の値だけ、メールアドレスは書かない
		for _, id := range acct.FindAllString(body, -1) {
			if id != "123456789012" && id != "111122223333" {
				t.Errorf("%s: account id %s (use 123456789012 / 111122223333)", name, id)
			}
		}
		if m := email.FindString(body); m != "" {
			t.Errorf("%s: email address %q", name, m)
		}
		if n := strings.Count(body, "\n"); n > 120 {
			t.Errorf("%s: %d lines (keep it within about 120)", name, n)
		}
	}
	if _, ok := Playbook("nope"); ok {
		t.Fatal("unknown check must not have a playbook")
	}
	idx, _ := Lookup("playbook")
	for _, name := range names {
		if !strings.Contains(idx.Markdown(), "`arata help ai playbook "+name+"`") {
			t.Errorf("playbook index lacks %s", name)
		}
	}
}

// TestRuntimeChecklist は実行環境 (GitHub Actions) のチェックリストが、確かめる設定の名前と守る規則を持つことを固定する。
func TestRuntimeChecklist(t *testing.T) {
	tp, err := Lookup("runtime")
	if err != nil {
		t.Fatal(err)
	}
	body := tp.Markdown()
	for _, want := range []string{
		// 確かめる設定 (GitHub の API の項目名とエンドポイント)
		"allow_forking", "members_can_fork_private_repositories", "fork-pr-workflows-private-repos",
		"pull_request_target", "actions/oidc/customization/sub", "use_immutable_subject", "rules/branches/main",
		"default_workflow_permissions", "sha_pinning_required", "selected-actions", "persist-credentials: false",
		"aws-actions/configure-aws-credentials@*", "deployment_branch_policy",
		// sub の形 (ID 入り、1 つのブランチ)
		"repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("help ai runtime lacks %q", want)
		}
	}
	sec := map[string]string{}
	for _, s := range tp.Parse().Sections {
		sec[s.Title] = s.Body
	}
	// 設定を変えるのは人 (LLM は読むだけ。approve と同じ方針)
	if !strings.Contains(sec["使い方"], "人が") || !strings.Contains(sec["使い方"], "読み取り") {
		t.Errorf("使い方 must say that the LLM only reads and a person changes the settings")
	}
	// 環境を作るときは context_file の下書きまで行う。マージは人、前提は承認の代わりにならない
	for _, want := range []string{"llm.context_file", "下書き", "人が", "allowlist", "未確認"} {
		if !strings.Contains(sec["監査対象の前提 (context_file) の下書き"], want) {
			t.Errorf("the context_file section lacks %q", want)
		}
	}
	// 読み取りの例だけを書く: 設定を書き換える gh api の呼び出し (-X / --method / -f / -F) を載せない
	if m := regexp.MustCompile(`gh api[^\n]*\s(-X|--method|-f|-F|--field|--raw-field|--input)\s`).FindString(body); m != "" {
		t.Errorf("help ai runtime must show read-only gh api calls only: %q", m)
	}
	// 顧客の情報を書かない: アカウント ID は架空の値だけ、メールアドレスは書かない
	for _, id := range regexp.MustCompile(`\b\d{12}\b`).FindAllString(body, -1) {
		if id != "123456789012" && id != "111122223333" {
			t.Errorf("account id %s (use 123456789012 / 111122223333)", id)
		}
	}
	// 入口から案内している
	idx, _ := Lookup("")
	if !strings.Contains(idx.Markdown(), "arata help ai runtime") {
		t.Errorf("help ai must point to arata help ai runtime")
	}
}

// TestPlaybookMentioned は help ai と help ai report から playbook へ案内していることを確かめる。
func TestPlaybookMentioned(t *testing.T) {
	for _, sub := range []string{"", "report"} {
		tp, _ := Lookup(sub)
		if !strings.Contains(tp.Markdown(), "arata help ai playbook") {
			t.Errorf("help %s must point to arata help ai playbook", tp.Name)
		}
	}
}
