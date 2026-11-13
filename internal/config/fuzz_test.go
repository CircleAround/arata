package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ファズテスト (ADR 0041)。設定は利用者が書くファイル。壊れた値でもパニックせず、受け入れた値は書いたとおりの意味になる。

func FuzzParseDuration(f *testing.F) {
	for _, s := range []string{"26h", "30d", "1d", "90m", "0d", "0", "-1d", "1.5h", "1h30m", "d", "", "106751d", "106752d", "213504d", "9223372036854775807d", "1e3d", " 1d", "+1d", "1dd"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDuration(s)
		if err != nil {
			if d != 0 {
				t.Fatalf("ParseDuration(%q) がエラーなのに %v を返した", s, d)
			}
		} else {
			if d <= 0 {
				t.Fatalf("ParseDuration(%q) = %v: 正でない", s, d)
			}
			// 日数は桁あふれで別の長さにならない
			if n, ok := strings.CutSuffix(s, "d"); ok {
				if days, err := strconv.Atoi(n); err != nil || d/(24*time.Hour) != time.Duration(days) || d%(24*time.Hour) != 0 {
					t.Fatalf("ParseDuration(%q) = %v: 書いた日数と違う", s, d)
				}
			}
		}
		if d2, err := parseDelay(s); err == nil && d2 < 0 {
			t.Fatalf("parseDelay(%q) = %v: 負", s, d2)
		}
	})
}

func FuzzParseStore(f *testing.F) {
	for _, s := range []string{"dir:///var/lib/arata/acme", "dir://", "s3://example-bucket/arata/acme", "s3://example-bucket", "s3://example-bucket/", "s3:///x", "s3://b//x", "s3://b/a//c/",
		"s3://b/../x", "file:///x", "", "S3://b/x", "s3://b/a/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, u string) {
		st, err := parseStore(u)
		if err != nil {
			if st != (Store{}) {
				t.Fatalf("parseStore(%q) がエラーなのに %+v を返した", u, st)
			}
			return
		}
		switch st.Scheme {
		case "dir":
			if st.Dir == "" || u != "dir://"+st.Dir || st.Bucket != "" || st.Prefix != "" {
				t.Fatalf("parseStore(%q) = %+v", u, st)
			}
		case "s3":
			if st.Bucket == "" || strings.Contains(st.Bucket, "/") || st.Dir != "" {
				t.Fatalf("parseStore(%q) = %+v: バケット名が不正", u, st)
			}
			// 接頭辞はキーの先頭になる。空の区間があると、同じ場所を別のキーとして読み書きする
			if strings.HasPrefix(st.Prefix, "/") || strings.HasSuffix(st.Prefix, "/") || strings.Contains(st.Prefix, "//") {
				t.Fatalf("parseStore(%q) = %+v: 接頭辞に空の区間", u, st)
			}
			if rest := strings.TrimPrefix(u, "s3://"+st.Bucket); strings.Trim(rest, "/") != st.Prefix && strings.TrimSuffix(strings.TrimPrefix(rest, "/"), "/") != st.Prefix {
				t.Fatalf("parseStore(%q) = %+v: 接頭辞が書いたものと違う", u, st)
			}
		default:
			t.Fatalf("parseStore(%q) = %+v: 知らない scheme", u, st)
		}
	})
}

// 設定ファイル全体。読めたら検証済みの値が入っている。読めなければエラー (パニックしない)。
func FuzzLoad(f *testing.F) {
	b, err := os.ReadFile("../../examples/arata.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	for _, s := range []string{
		"name: acme\nstore: dir:///tmp/x\n", "name: acme\nstore: s3://example-bucket/p\nsources: [{id: a, kind: cloudtrail-lookup}]\nprofiles: {daily: {checks: [default-daily]}}\n",
		"sources: [{id: web, kind: cloudwatch-logs, log_group: prod-nginx-access, format: nginx_access, yields: http_access, ingest_delay: 0d}]\n",
		"sources: [null]\nprofiles: {x: null}\nchecks: null\n", "profiles: {a: {window: 9223372036854775807d}}\n", "name: [1]\n", "- x\n", "a: &a [*a]\n", "",
	} {
		f.Add([]byte(s))
	}
	dir, err := os.MkdirTemp("", "arata-fuzz-*")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "arata.yaml")
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(path)
		if err != nil {
			if cfg != nil {
				t.Fatal("エラーなのに設定を返した")
			}
			return
		}
		if cfg.Store.Scheme != "dir" && cfg.Store.Scheme != "s3" {
			t.Fatalf("store を検証せずに受け入れた: %+v", cfg.Store)
		}
		ids := map[string]bool{}
		for _, s := range cfg.Sources {
			if s.ID == "" || ids[s.ID] || !SupportedKinds[s.Kind] || s.IngestDelay < 0 {
				t.Fatalf("source を検証せずに受け入れた: %+v", s)
			}
			// id はストアのパスに使う (ADR 0037)
			if strings.ContainsAny(s.ID, `/\`) || strings.Contains(s.ID, "..") {
				t.Fatalf("パスの区切りを含む source の id を受け入れた: %q", s.ID)
			}
			ids[s.ID] = true
		}
		for name := range cfg.Profiles {
			if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
				t.Fatalf("パスの区切りを含む profile 名を受け入れた: %q", name)
			}
		}
		cfg.MaxIngestDelay()
		cfg.AuditLogGroups()
	})
}

// FuzzParseAuditAccount は --audit-account / audit_account の値 (利用者の入力) の解釈を確かめる。
// 守る規則: 受け付けるのは「ASCII の数字ちょうど 12 桁」か「none」だけ。受け付けた ID は入力そのもので、none と同時には成り立たない。
// 受け付けた値は allowlist の account: と設定の YAML に引用符付きでそのまま書くので、数字以外 (改行・引用符・空白) を 1 文字も通さない。
func FuzzParseAuditAccount(f *testing.F) {
	for _, s := range []string{"111122223333", "999999999999", "none", "", "None", " none", "none\n", "11112222333", "1111222233334", "111122223333\n", "１１１１２２２２３３３３",
		"1111 2222 3333", "0x1111222233", "1e11", "-11122223333", "+11122223333", "111122223333\"\nprincipals: []", "\x00", "nonenone"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, none, err := ParseAuditAccount(s)
		if err != nil {
			if id != "" || none {
				t.Fatalf("ParseAuditAccount(%q) がエラーなのに %q, %v を返した", s, id, none)
			}
			if s == AuditAccountNone {
				t.Fatalf("none を拒否した: %v", err)
			}
			return
		}
		if none {
			if s != AuditAccountNone || id != "" {
				t.Fatalf("ParseAuditAccount(%q) = %q, none", s, id)
			}
			return
		}
		if id != s || len(id) != 12 {
			t.Fatalf("ParseAuditAccount(%q) = %q: 入力そのものの 12 桁でない", s, id)
		}
		for i := 0; i < len(id); i++ {
			if id[i] < '0' || id[i] > '9' {
				t.Fatalf("ParseAuditAccount(%q) が数字以外を通した", s)
			}
		}
	})
}
