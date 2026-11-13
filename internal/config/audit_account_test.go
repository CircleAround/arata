package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAuditAccount(t *testing.T) {
	for _, tc := range []struct {
		in   string
		id   string
		none bool
		ok   bool
	}{
		{"111122223333", "111122223333", false, true},
		{"999999999999", "999999999999", false, true},
		{"none", "", true, true},
		{"", "", false, false},
		{"None", "", false, false},
		{"NONE", "", false, false},
		{" none", "", false, false},
		{"11112222333", "", false, false},
		{"1111222233334", "", false, false},
		{"1111-2222-3333", "", false, false},
		{"111122223333\n", "", false, false},
		{"１１１１２２２２３３３３", "", false, false}, // 全角の数字は受け付けない
		{"arn:aws:iam::111122223333:root", "", false, false},
	} {
		id, none, err := ParseAuditAccount(tc.in)
		if (err == nil) != tc.ok || id != tc.id || none != tc.none {
			t.Errorf("ParseAuditAccount(%q) = %q, %v, %v; want %q, %v, ok=%v", tc.in, id, none, err, tc.id, tc.none, tc.ok)
		}
	}
	// エラー文は 2 つの選択肢を示す
	_, _, err := ParseAuditAccount("self")
	if err == nil || !strings.Contains(err.Error(), "12-digit") || !strings.Contains(err.Error(), "none") {
		t.Fatalf("error must name both choices: %v", err)
	}
}

// TestLoadAuditAccount は設定の audit_account の読み込みを確かめる。
// 決定 (ADR 0045): 書いていない設定 (この項目より前の版で作ったもの) は読み込める。書いてあれば 12 桁の ID か none だけ。
func TestLoadAuditAccount(t *testing.T) {
	base := "name: acme\nstore: dir:///tmp/arata-test\nsources: [{id: trail, kind: cloudtrail-lookup}]\nprofiles: {daily: {window: 24h, checks: [root_usage]}}\n"
	for _, tc := range []struct {
		line string
		want string
		ok   bool
	}{
		{"", "", true},
		{"audit_account: none\n", "none", true},
		{"audit_account: \"111122223333\"\n", "111122223333", true},
		{"audit_account: 111122223333\n", "111122223333", true}, // 引用符が無くても同じ
		{"audit_account: self\n", "", false},
		{"audit_account: 1111\n", "", false},
		{"audit_account: [\"111122223333\"]\n", "", false},
	} {
		p := filepath.Join(t.TempDir(), "arata.yaml")
		if err := os.WriteFile(p, []byte(base+tc.line), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if (err == nil) != tc.ok {
			t.Errorf("%q: err = %v, want ok=%v", tc.line, err, tc.ok)
			continue
		}
		if err == nil && cfg.AuditAccount != tc.want {
			t.Errorf("%q: AuditAccount = %q, want %q", tc.line, cfg.AuditAccount, tc.want)
		}
		// 型の誤り (列) は YAML の読み込みが行番号つきで止める
		if err != nil && !strings.Contains(tc.line, "[") && !strings.Contains(err.Error(), "audit_account") {
			t.Errorf("%q: error must name the key: %v", tc.line, err)
		}
	}
}
