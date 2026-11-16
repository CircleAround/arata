package store

import (
	"context"
	"reflect"
	"testing"
)

// 怪しい IP の一覧 (ADR 0069 の 2 節): 日ごとの行を (date, source) で丸ごと置き換える (作り直しで二重に数えない)。
// keepFrom より前の日の行は、書くときに全部のソースについて消す (保持の期間 M)。
func TestIPListDays(t *testing.T) {
	st, _ := open(t)
	ctx := context.Background()
	r := func(date, src, reason, ip string, n float64) IPListRow {
		return IPListRow{Date: date, Source: src, Reason: reason, IP: ip, Count: n}
	}
	put := func(src, date string, keep string, rows ...IPListRow) {
		t.Helper()
		if err := st.ReplaceIPListDay(ctx, src, date, rows, keep); err != nil {
			t.Fatal(err)
		}
	}
	put("web", "2026-10-20", "", r("2026-10-20", "web", "probe", "198.51.100.7", 3))
	put("waf", "2026-10-20", "", r("2026-10-20", "waf", "waf_block", "198.51.100.7", 9))
	put("web", "2026-10-21", "", r("2026-10-21", "web", "sign_in_failure", "2001:db8::1", 25), r("2026-10-21", "web", "probe", "198.51.100.7", 4))
	// 同じ日の作り直しは置き換え (足し込まない)。ほかのソースの同じ日はそのまま
	put("web", "2026-10-21", "", r("2026-10-21", "web", "probe", "198.51.100.7", 5))

	got, err := st.IPListDays(ctx, "2026-10-20", "2026-10-21")
	if err != nil {
		t.Fatal(err)
	}
	want := []IPListRow{
		r("2026-10-20", "waf", "waf_block", "198.51.100.7", 9),
		r("2026-10-20", "web", "probe", "198.51.100.7", 3),
		r("2026-10-21", "web", "probe", "198.51.100.7", 5),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows =\n%v\nwant\n%v", got, want)
	}
	if got, _ := st.IPListDays(ctx, "2026-10-21", "2026-10-21"); len(got) != 1 {
		t.Errorf("one day = %v", got)
	}
	// 行の無い日の置き換えは、その日の行を消す
	put("web", "2026-10-21", "")
	if got, _ := st.IPListDays(ctx, "2026-10-21", "2026-10-21"); len(got) != 0 {
		t.Errorf("emptied day = %v", got)
	}
	// keepFrom より前の日は、どのソースの行も消える
	put("web", "2026-10-22", "2026-10-21", r("2026-10-22", "web", "probe", "203.0.113.10", 3))
	if got, _ := st.IPListDays(ctx, "", ""); len(got) != 1 || got[0].Date != "2026-10-22" {
		t.Errorf("after prune = %v", got)
	}
}

// schema 8 のストア (ip_list_days が無い) は、開くと表が足され、schema 9 になる。
func TestMigrateAddsIPListDays(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DROP TABLE ip_list_days`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE schema_version SET version=8`); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var v int
	if err := st.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil || v != schemaVersion || schemaVersion < 9 {
		t.Fatalf("version %d (%v)", v, err)
	}
	if rows, err := st.IPListDays(context.Background(), "", ""); err != nil || len(rows) != 0 {
		t.Fatalf("rows %v (%v)", rows, err)
	}
}
