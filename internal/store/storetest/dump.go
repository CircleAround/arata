// Package storetest はストアのテスト用の補助。rebuild したストアと run を重ねたストアの中身を比べるのに使う。
package storetest

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// Dump は <dir>/audit.sqlite の全テーブル (sqlite_ で始まる内部のものを除く) を、テーブル名 → 行 (列を | でつないだ文字列、並べ替え済み) で返す。
func Dump(dir string) (map[string][]string, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "audit.sqlite")+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, n)
	}
	rows.Close()
	out := map[string][]string{}
	for _, t := range tables {
		lines, err := dumpTable(db, t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t, err)
		}
		out[t] = lines
	}
	return out, nil
}

func dumpTable(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(`SELECT * FROM "` + table + `"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	lines := []string{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		parts := make([]string, len(cols))
		for i, v := range vals {
			switch x := v.(type) {
			case nil:
				parts[i] = cols[i] + "=NULL"
			case []byte:
				parts[i] = cols[i] + "=" + string(x)
			default:
				parts[i] = fmt.Sprintf("%s=%v", cols[i], x)
			}
		}
		lines = append(lines, strings.Join(parts, "|"))
	}
	sort.Strings(lines)
	return lines, rows.Err()
}
