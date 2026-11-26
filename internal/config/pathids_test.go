package config

import (
	"strings"
	"testing"
)

// path_ids (パスの型の規則。ADR 0071 の 2 節・0087 の 5・6 節)。値はすべて架空。

const pathIDsBlock = `    path_ids:
      segments:
        - '[0-9]{1,20}'
        - '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
      templates:
        - '/users/:id/profile'
        - '/billing/charges/:id/:any'
      formats: [json, csv]
      max_segments: 8
`

func TestPathIDs(t *testing.T) {
	cfg, err := Load(write(t, logsSource(railsRequest+pathIDsBlock)))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Sources[len(cfg.Sources)-1]
	c := s.PathRules()
	if c == nil {
		t.Fatal("PathRules is nil")
	}
	if tpl, ids := c.Normalize("/billing/charges/42/202611.json"); tpl != "/billing/charges/:id/:any" || len(ids) != 1 || ids[0] != "42" {
		t.Fatalf("Normalize = %q %q", tpl, ids)
	}
	// 書かなければ規則なし (パスの型の要るチェックは skip。暗黙の既定は持たない)
	cfg, err = Load(write(t, logsSource(railsRequest)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources[len(cfg.Sources)-1].PathRules() != nil {
		t.Fatal("PathRules without path_ids")
	}
	// 1 行のログの形式 (http_access) にも書ける
	if _, err := Load(write(t, logsSource("    format: nginx_access\n"+pathIDsBlock))); err != nil {
		t.Fatal(err)
	}
}

func TestPathIDsInvalid(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"wafv2", "    format: wafv2\n" + pathIDsBlock, "path_ids"},
		{"text", "    format: text\n" + pathIDsBlock, "path_ids"},
		{"max_segments が無い", railsRequest + "    path_ids:\n      segments: ['[0-9]+']\n", "max_segments"},
		{"規則が無い", railsRequest + "    path_ids:\n      max_segments: 8\n", "segments or templates"},
		{"正規表現", railsRequest + "    path_ids:\n      segments: ['[0-9']\n      max_segments: 8\n", "segments"},
		{"型", railsRequest + "    path_ids:\n      templates: ['/:any/:id']\n      max_segments: 8\n", "fixed"},
		{"拡張子", railsRequest + "    path_ids:\n      segments: ['[0-9]+']\n      formats: [JSON]\n      max_segments: 8\n", "formats"},
	} {
		_, err := Load(write(t, logsSource(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "source web") {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
	// 知らないキー (綴りの誤り) は読み込みで止まる
	if _, err := Load(write(t, logsSource(railsRequest+"    path_ids:\n      segment: ['[0-9]+']\n      max_segments: 8\n"))); err == nil || !strings.Contains(err.Error(), "segment") {
		t.Errorf("unknown key: %v", err)
	}
}
