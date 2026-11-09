package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/store"
)

// ファズテスト (ADR 0040)。レポートと通知に個人を特定できる値 (メールアドレス、assumed-role のセッション名) を出さない (ADR 0037)。
// finding の key・summary・data のどの深さに置いても、report.json に元の形で残らないことを確かめる。
func FuzzFindingMasksIdentity(f *testing.F) {
	for _, s := range [][3]string{{"", "", `{}`}, {"user ", " からのログイン", `{"ips":["203.0.113.1"],"n":1}`}, {"a@b.", ".c", `[{"k":["x"]}]`}, {"assumed-role/r/", ",x", `"s"`}, {"\xff", "\n", `null`}} {
		f.Add(s[0], s[1], s[2])
	}
	const (
		email   = "alice@example.com"
		session = "alice-session"
		arn     = "arn:aws:sts::123456789012:assumed-role/audit-role/" + session
	)
	f.Fuzz(func(t *testing.T, pre, post, extra string) {
		var v any
		_ = json.Unmarshal([]byte(extra), &v)
		a, b := pre+email+post, pre+arn+post
		got := toFinding(store.Finding{ID: "f1", Check: "new_principal", Key: b + "|" + a, Summary: a + " " + b, Data: map[string]any{
			"user": a, "principal": b, "list": []string{a, b}, "any": []any{a, map[string]any{"deep": []any{b, a}}, 1, nil, true}, "extra": v,
		}})
		// キー (項目名) は arata のチェックが決める値で、ログ由来ではない。値だけを見る
		out, err := json.Marshal([]any{got.Key, got.Summary, got.Data["user"], got.Data["principal"], got.Data["list"], got.Data["any"]})
		if err != nil {
			t.Fatalf("finding を JSON にできない: %v", err)
		}
		if strings.Contains(string(out), email) || strings.Contains(string(out), "/audit-role/"+session) {
			t.Fatalf("個人を特定できる値が残った: %s", out)
		}
		if _, err := json.Marshal(got); err != nil {
			t.Fatalf("finding を JSON にできない: %v", err)
		}
	})
}
