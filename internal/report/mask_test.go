package report

import (
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/store"
)

// メール形式の IAM ユーザー名は、ストアには残してもレポートには出さない。
func TestReportHidesEmails(t *testing.T) {
	const mail = "alice@example.com"
	now := time.Now()
	f := store.Finding{ID: "f", Check: "credential_hygiene", Key: "no_mfa|" + mail, Severity: "medium", Summary: "MFA が無い: " + mail, FirstSeen: now,
		Data: map[string]any{"user": mail, "list": []any{"x", mail}, "nested": map[string]any{"u": mail}, "n": 1.0}}
	r := Build(Input{Results: []checks.Result{{Class: checks.ClassNew, Finding: f}}, Now: now})
	j, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j), mail) || strings.Contains(r.Markdown(), mail) {
		t.Fatalf("メールアドレスが残った:\n%s", j)
	}
	if f.Data["user"] != mail {
		t.Fatal("ストアの値を書き換えた")
	}
}
