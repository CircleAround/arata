// Package codestest は、コマンドが実際に出したログの行を確かめる、テストの共通部分 (ADR 0054)。テストからだけ使う。
package codestest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

// Check は、標準エラー stderr の JSON の行を 1 行ずつ確かめる (JSON でない行は見ない)。
//
//   - log スキーマに合う (time・level・msg があり、level は決まった値、code は決まった形)
//   - code があれば、そのコマンド (tool) の一覧にある
//   - ERROR の行には code がある
func Check(t testing.TB, tool, stderr string) {
	t.Helper()
	for _, line := range strings.Split(stderr, "\n") {
		var m map[string]any
		if strings.TrimSpace(line) == "" || json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		schematest.Matches(t, codes.LogSchema, []byte(line))
		code, has := m["code"].(string)
		if has && !codes.Known(tool, code) {
			t.Fatalf("log code %q is not in the list of %s (internal/codes): %s", code, tool, line)
		}
		if m["level"] == "ERROR" && !has {
			t.Fatalf("an ERROR line needs a code: %s", line)
		}
	}
}
