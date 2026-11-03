package ai

import (
	"strings"
	"testing"
)

// TestSections は各トピックの見出しを固定する。見出しを変えたら help ai を読む側 (組み込みの LLM プロンプト) も見直すこと。
func TestSections(t *testing.T) {
	want := map[string][]string{
		"ai":        {"概要", "概念", "コマンド", "終了コード", "標準エラーのログと code", "allowlist.yaml の形式", "認証の注意", "次に読むもの"},
		"ai report": {"report.json の構造", "読む順序", "要約の手順", "相関付け", "分類の基準", "書いてはいけないこと", "追加の裏取り (任意)", "WAF の修正提案の候補 (proposals)", "期間レポート (report --month / --from --to)", "approve について"},
		"ai approve": {"原則", "承認してよい主体の目安", "SaaS 連携は account で承認する", "外部アカウント root の見方", "arn_pattern の使いどころ",
			"期限付き承認の使いどころ", "tags の語彙", "approve ではなく ack / snooze / resolve にするもの"},
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
	for _, sub := range []string{"", "report", "approve"} {
		if _, err := Lookup(sub); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Lookup("nope"); err == nil || !strings.Contains(err.Error(), "arata help ai report") {
		t.Fatalf("%v", err)
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
