package account_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/account/accounttest"
)

// ファズテスト (ADR 0040)。認証情報レポートは IAM が返す CSV だが、ユーザー名は利用者 (と侵入者) が決められる。
// 壊れた CSV でもパニックせず、読めた行は決まった形 (日時は RFC 3339 の UTC か空、キーは 2 本まで) になる。
func FuzzParseCredentialReport(f *testing.F) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f.Add(accounttest.CredentialReport(
		accounttest.CredentialRow{User: "<root_account>", ARN: "arn:aws:iam::123456789012:root", PasswordNotSupported: true, MFA: true, Key1Active: true, Key1Rotated: t0},
		accounttest.CredentialRow{User: "alice", ARN: "arn:aws:iam::123456789012:user/alice", Password: true, PasswordLastUsed: t0, Key1Active: true, Key1LastUsed: t0, Key2Active: true},
	))
	for _, s := range []string{"user,arn\nalice\n", "user,user\na,b\n", "user,access_key_1_active,access_key_1_last_rotated\n\"a\nb\",true,2026-10-01T00:00:00+09:00\n",
		"user,arn\n\"alice,arn\n", "a,b\n1,2,3\n", "\xff,\xfe\n1,2\n", "user\n", "\n\n", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		rows, err := account.ParseCredentialReport(content)
		if err != nil {
			if rows != nil {
				t.Fatal("エラーなのに行を返した")
			}
			return
		}
		if _, err := json.Marshal(rows); err != nil {
			t.Fatalf("行を JSON にできない: %v", err)
		}
		checkTime := func(name string, v any) {
			s, ok := v.(string)
			if !ok {
				t.Fatalf("%s が文字列でない: %T", name, v)
			}
			if s == "" {
				return
			}
			if tm, err := time.Parse(time.RFC3339, s); err != nil || tm.Location() != time.UTC {
				t.Fatalf("%s = %q: RFC 3339 の UTC でない", name, s)
			}
		}
		for _, d := range rows {
			for _, k := range []string{"user", "arn"} {
				if _, ok := d[k].(string); !ok {
					t.Fatalf("%s が文字列でない: %T", k, d[k])
				}
			}
			for _, k := range []string{"password_enabled", "mfa_active"} {
				if _, ok := d[k].(bool); !ok {
					t.Fatalf("%s が真偽値でない: %T", k, d[k])
				}
			}
			checkTime("password_last_used", d["password_last_used"])
			keys, _ := d["access_keys"].([]any)
			if len(keys) > 2 {
				t.Fatalf("アクセスキーが %d 本", len(keys))
			}
			for _, k := range keys {
				m := k.(map[string]any)
				if _, ok := m["active"].(bool); !ok || (m["key"] != "1" && m["key"] != "2") {
					t.Fatalf("アクセスキーの形が不正: %v", m)
				}
				checkTime("last_rotated", m["last_rotated"])
				checkTime("last_used", m["last_used"])
			}
		}
	})
}
