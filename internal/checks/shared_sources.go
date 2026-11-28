package checks

import (
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/record"
)

// sharedSourceOn は ip が日 date (YYYY-MM-DD、UTC) に人の多い送信元 (allowlist の shared_sources。ADR 0094 の 1 節) かを返す。
// 期限はその日の始まりで見る (expires の日はその日の終わりまで有効なので、expires の日までが shared)。source_ips の IP は当たらない。
func sharedSourceOn(al *allowlist.List, ip, date string) (*allowlist.SharedSourceEntry, bool) {
	if al == nil || !al.HasSharedSources() {
		return nil, false
	}
	at, err := time.Parse(record.DateLayout, date)
	if err != nil {
		return nil, false
	}
	return al.SharedSource(ip, at)
}

// addShared は finding の data に人の多い送信元の印 (shared: true と、項目の note) を足す。shared でない IP の data には何も足さない。
func addShared(data map[string]any, e *allowlist.SharedSourceEntry) {
	data["shared"] = true
	data["shared_note"] = e.Note
}
