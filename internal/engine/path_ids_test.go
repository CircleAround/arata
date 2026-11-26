package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
)

// doctor の path_ids の行 (ADR 0071 の 2 節)。値はすべて架空。実 AWS には接続しない。

const pathIDsSource = requestLinesSource + `      user_id:
        from: app_line
        regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})$'
    path_ids:
      segments: ['[0-9]{1,20}']
      templates: ['/users/:id/orders/:id']
      formats: [json]
      max_segments: 8
`

func pathDoctor(t *testing.T, rows []map[string]string) *DoctorRow {
	t.Helper()
	h := newHarnessWith(t, pathIDsSource, "")
	h.logs.LogGroups = []string{"prod-app"}
	h.logs.On("sort @timestamp desc", doctorSample(95, 5))
	h.logs.On("as path_requests", cwlogstest.Response{Rows: rows})
	res := Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour)
	for i, r := range res.Rows {
		if r.Source == "web" && r.Item == "path_ids" {
			return &res.Rows[i]
		}
	}
	t.Fatalf("path_ids の行が無い: %+v", res.Rows)
	return nil
}

func TestDoctorPathIDs(t *testing.T) {
	// Insights の結果の型は印 (?id) のまま返る。Sanitize してから数える
	row := pathDoctor(t, []map[string]string{
		{"day": "2026-10-21 00:00:00.000", "tpl": "/orders/?id", "path_requests": "120", "path_users": "30"},
		{"day": "2026-10-21 00:00:00.000", "tpl": "/users/?id/orders", "path_requests": "40", "path_users": "12"},
		{"day": "2026-10-21 00:00:00.000", "tpl": "/users/taro/orders", "path_requests": "9", "path_users": "1"},
		{"day": "2026-10-21 00:00:00.000", "tpl": "/users/hanako/orders", "path_requests": "3", "path_users": "1"},
		{"day": "2026-10-21 00:00:00.000", "tpl": "/u/alice@example.com", "path_requests": "2", "path_users": "1"},
		// ログイン名の区間は、ほかの人も触る位置 (bob も alice のフォロワーを見る)。2 人が触った型の値でも、例には出さない
		{"day": "2026-10-21 00:00:00.000", "tpl": "/alice/followers", "path_requests": "5", "path_users": "2"},
		{"day": "2026-10-21 00:00:00.000", "tpl": "/alice/settings", "path_requests": "4", "path_users": "1"},
	})
	if row.Status != DoctorOK {
		t.Fatalf("status: %+v", row)
	}
	for _, want := range []string{"型 7 (ID を含む 2)", "1 日に 1 人の利用者しか触らなかった型 4", "/users/<4>/orders", "/users/<6>/orders", "/<5>/<8>", "/<1>/:x", "templates"} {
		if !strings.Contains(row.Detail, want) {
			t.Errorf("detail に %q が無い: %s", want, row.Detail)
		}
	}
	// 名前の区間とメールアドレスは出さない。設定の templates の固定の区間 (users) と印のほかは長さだけ
	for _, bad := range []string{"taro", "hanako", "alice", "example.com", "followers", "settings"} {
		if strings.Contains(row.Detail, bad) {
			t.Errorf("detail に %q が出た: %s", bad, row.Detail)
		}
	}
	// 型が 1 つも無い → warn
	if row := pathDoctor(t, nil); row.Status != DoctorWarn {
		t.Fatalf("型なし: %+v", row)
	}
}
