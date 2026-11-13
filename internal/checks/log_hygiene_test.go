package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

func hygieneCheck() LogHygiene {
	return LogHygiene{Config: config.LogHygiene{Sources: []string{"app_prod", "web"}, Kinds: config.LogHygieneKinds(), ParamFields: []string{"name", "address", "tel"}}}
}

// hygieneItem は collector (cwlogs) が出す形の項目。
func hygieneItem(kind string, count int, kv ...any) record.SnapshotItem {
	it := snap(record.KindLogHygiene, kind, append([]any{"log_group", "prod-app", "kind", kind, "count", count, "retention", "never", "window_hours", 168}, kv...)...)
	return it
}

func hygieneSnapshot(t *testing.T, st *store.Dir, source string, items ...record.SnapshotItem) {
	t.Helper()
	if err := st.ReplaceSnapshot(context.Background(), record.KindLogHygiene, source, items, now); err != nil {
		t.Fatal(err)
	}
}

func TestLogHygiene(t *testing.T) {
	c := hygieneCheck()
	if c.Name() != "log_hygiene" || c.Cadence() != Weekly || c.Mode() != ModeState || len(c.Needs()) != 1 || c.Needs()[0] != record.KindLogHygiene {
		t.Fatalf("%s %s %s %v", c.Name(), c.Cadence(), c.Mode(), c.Needs())
	}
	st := newStore(t)
	hygieneSnapshot(t, st, "app_prod",
		hygieneItem(config.HygieneSecretAWSAccessKey, 2),
		hygieneItem(config.HygieneSecretSlackToken, 0),
		hygieneItem(config.HygieneSecretPrivateKey, 1),
		hygieneItem(config.HygienePresignedLongTerm, 3),
		hygieneItem(config.HygienePresignedURL, 40),
		hygieneItem(config.HygieneUnfilteredParam, 12, "fields", map[string]any{"tel": 5, "name": 9}),
		hygieneItem(config.HygieneDebugSQL, 1500),
	)
	hygieneSnapshot(t, st, "web",
		hygieneItem(config.HygienePresignedURL, 7, "log_group", "prod-nginx-access", "retention", "set", "retention_days", 30),
		hygieneItem(config.HygieneDebugSQL, 0, "log_group", "prod-nginx-access", "retention", "set", "retention_days", 30),
	)
	obs, err := c.Evaluate(context.Background(), st, weekly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// ロググループ × 種類で 1 件。0 行は出さない。行数の下限は無い (1 行でも出す)
	if got := keys(obs); got != "app_prod|secret_aws_access_key;app_prod|secret_private_key;app_prod|presigned_url_long_term_key;app_prod|presigned_url;app_prod|unfiltered_param;app_prod|debug_sql;web|presigned_url" {
		t.Fatalf("keys: %s", got)
	}
	m := byKeyObs(obs)
	for key, sev := range map[string]Severity{"app_prod|secret_aws_access_key": High, "app_prod|secret_private_key": High, "app_prod|presigned_url_long_term_key": Medium,
		"app_prod|presigned_url": Medium, "app_prod|unfiltered_param": Medium, "app_prod|debug_sql": Low, "web|presigned_url": Medium} {
		if m[key].Severity != sev || m[key].Check != "log_hygiene" {
			t.Errorf("%s: severity %s, want %s", key, m[key].Severity, sev)
		}
	}
	up := m["app_prod|unfiltered_param"]
	if up.Summary != "ロググループ prod-app のログに、隠されていない送信項目 (name, tel) が 12 行 (直近 7 日。保持期間は無期限)" {
		t.Fatalf("summary: %s", up.Summary)
	}
	b, _ := json.Marshal(up.Data)
	if string(b) != `{"count":12,"fields":{"name":9,"tel":5},"kind":"unfiltered_param","log_group":"prod-app","retention":"never","window_hours":168}` {
		t.Fatalf("data: %s", b)
	}
	web := m["web|presigned_url"]
	if web.Summary != "ロググループ prod-nginx-access のログに、署名付き URL が 7 行 (直近 7 日。保持期間は 30 日)" || web.Data["retention"] != "set" || web.Data["retention_days"] != 30 {
		t.Fatalf("web: %s %+v", web.Summary, web.Data)
	}
	if s := m["app_prod|secret_aws_access_key"].Summary; s != "ロググループ prod-app のログに、AWS の長期のアクセスキーの ID の形 が 2 行 (直近 7 日。保持期間は無期限)" {
		t.Fatalf("summary: %s", s)
	}
	if _, ok := m["app_prod|debug_sql"].Data["fields"]; ok {
		t.Fatal("fields is only for unfiltered_param")
	}

	// Fingerprint: 行数と保持期間が変わっても同じ (毎週 changed にしない)。当たった項目の集合が変われば変わる
	hygieneSnapshot(t, st, "app_prod",
		hygieneItem(config.HygieneUnfilteredParam, 300, "fields", map[string]any{"name": 200, "tel": 100}, "retention", "set", "retention_days", 90, "window_hours", 200),
		hygieneItem(config.HygieneDebugSQL, 1, "retention", "unknown"))
	obs2, _ := c.Evaluate(context.Background(), st, weekly(), nil)
	m2 := byKeyObs(obs2)
	if m2["app_prod|unfiltered_param"].Fingerprint != up.Fingerprint || m2["app_prod|debug_sql"].Fingerprint != m["app_prod|debug_sql"].Fingerprint {
		t.Fatalf("fingerprint must not depend on counts / retention: %q vs %q", m2["app_prod|unfiltered_param"].Fingerprint, up.Fingerprint)
	}
	if s := m2["app_prod|debug_sql"].Summary; s != "ロググループ prod-app のログに、debug の SQL の出力 が 1 行 (直近 7 日。保持期間は不明)" {
		t.Fatalf("summary: %s", s)
	}
	if s := m2["app_prod|unfiltered_param"].Summary; !strings.Contains(s, "(直近 200 時間。保持期間は 90 日)") {
		t.Fatalf("summary: %s", s)
	}
	hygieneSnapshot(t, st, "app_prod", hygieneItem(config.HygieneUnfilteredParam, 12, "fields", map[string]any{"name": 9, "tel": 5, "address": 1}))
	obs3, _ := c.Evaluate(context.Background(), st, weekly(), nil)
	if fp := byKeyObs(obs3)["app_prod|unfiltered_param"].Fingerprint; fp == up.Fingerprint || !strings.Contains(fp, "address,name,tel") {
		t.Fatalf("fingerprint must change with the set of fields: %q", fp)
	}
	if len(obs3) != 2 {
		t.Fatalf("other kinds of app_prod are resolved (0 rows): %s", keys(obs3))
	}
}

// 設定から外したソース・種類・項目名は、前のスナップショットが残っていても報告しない。
func TestLogHygieneFollowsConfig(t *testing.T) {
	st := newStore(t)
	hygieneSnapshot(t, st, "app_prod",
		hygieneItem(config.HygieneDebugSQL, 5),
		hygieneItem(config.HygieneUnfilteredParam, 12, "fields", map[string]any{"name": 9, "tel": 5}))
	hygieneSnapshot(t, st, "old", hygieneItem(config.HygieneDebugSQL, 5))
	c := LogHygiene{Config: config.LogHygiene{Sources: []string{"app_prod"}, Kinds: []string{config.HygieneUnfilteredParam}, ParamFields: []string{"tel"}}}
	obs, err := c.Evaluate(context.Background(), st, weekly(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys(obs) != "app_prod|unfiltered_param" || !strings.Contains(obs[0].Summary, "(tel)") || strings.Contains(obs[0].Summary, "name") {
		t.Fatalf("%s: %+v", keys(obs), obs)
	}
	// 設定が空なら何も出さず、理由を返す (engine が skip にする)
	for _, cfg := range []config.LogHygiene{{}, {Sources: []string{"app_prod"}}, {Kinds: []string{config.HygieneDebugSQL}}} {
		c := LogHygiene{Config: cfg}
		if c.Disabled() == "" {
			t.Fatalf("%+v must be disabled", cfg)
		}
		if obs, _ := c.Evaluate(context.Background(), st, weekly(), nil); len(obs) != 0 {
			t.Fatalf("%+v: %s", cfg, keys(obs))
		}
	}
	if hygieneCheck().Disabled() != "" {
		t.Fatal("configured check must not be disabled")
	}
}

// スナップショットの項目 (ストアの中身) が何であっても、finding に載る文字列は設定の値と決まった語だけ。
// 守る規則:
//   - Key は `<設定のソース id>|<設定の種類>`、重大度は種類で決まる
//   - 行数は 1 以上の整数。読めない行数の項目は出さない
//   - retention は set / never / unknown のどれか。retention_days は set のときだけ
//   - fields の名前は設定の param_fields にあるものだけ
//   - 見出しと Data に、項目の中の任意の文字列が残らない (ロググループの名前は名前の形のときだけ)
func FuzzLogHygieneSnapshot(f *testing.F) {
	f.Add("unfiltered_param", "prod-app", "never", "name", 12.0, 9.0, 30.0)
	f.Add("debug_sql", "prod-app\n| x", "forever", "password", -1.0, 0.5, -3.0)
	f.Add("secret_private_key", "", "set", "tel", 1e300, 1.0, 0.0)
	f.Add("x|y", "a b", "set", "", 3.0, 3.0, 7.0)
	const marker = "s3cr3t value from log" // ロググループの名前の形でもない文字列
	f.Fuzz(func(t *testing.T, kind, group, retention, field string, count, fcount, days float64) {
		items := []record.SnapshotItem{
			snap(record.KindLogHygiene, kind, "log_group", group, "kind", kind+marker, "count", count, "retention", retention, "retention_days", days,
				"fields", map[string]any{field: fcount, "name": marker, marker: 3}, "window_hours", days, "note", marker),
			snap(record.KindLogHygiene, config.HygieneUnfilteredParam, "log_group", group+marker, "count", count, "retention", retention+marker, "fields", map[string]any{field + marker: fcount, "tel": fcount}),
			snap(record.KindLogHygiene, config.HygieneDebugSQL, "log_group", marker, "count", marker, "fields", marker),
		}
		for i := range items {
			items[i].Source = "app_prod"
		}
		c := hygieneCheck()
		obs, err := c.Evaluate(context.Background(), snapshotQuery{items: items}, weekly(), nil)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		seen := map[string]bool{}
		for _, o := range obs {
			src, k, ok := strings.Cut(o.Key, "|")
			if !ok || src != "app_prod" || !c.Config.HasKind(k) || seen[o.Key] || o.Severity != hygieneSeverity[k] || o.Data["kind"] != k {
				t.Fatalf("key / severity: %+v", o)
			}
			seen[o.Key] = true
			n, isInt := o.Data["count"].(int64)
			if !isInt || n < 1 {
				t.Fatalf("count: %+v", o)
			}
			switch o.Data["retention"] {
			case "set":
				if d, ok := o.Data["retention_days"].(int); !ok || d < 1 {
					t.Fatalf("retention_days: %+v", o)
				}
			case "never", "unknown":
				if _, ok := o.Data["retention_days"]; ok {
					t.Fatalf("retention_days without set: %+v", o)
				}
			default:
				t.Fatalf("retention: %+v", o)
			}
			if fs, ok := o.Data["fields"].(map[string]int64); ok {
				for name, v := range fs {
					if !contains(c.Config.ParamFields, name) || v < 1 || k != config.HygieneUnfilteredParam {
						t.Fatalf("fields: %+v", o)
					}
				}
			} else if _, has := o.Data["fields"]; has {
				t.Fatalf("fields の型: %+v", o)
			}
			b, err := json.Marshal(o)
			if err != nil {
				t.Fatalf("JSON にできない: %v", err)
			}
			if strings.Contains(string(b), marker) {
				t.Fatalf("finding に項目の文字列が残った: %s", b)
			}
			if lg, ok := o.Data["log_group"].(string); ok && (lg != group || !logGroupName.MatchString(lg)) {
				t.Fatalf("log_group: %+v", o)
			}
			if strings.ContainsAny(o.Summary, "\n\r") {
				t.Fatalf("見出しに改行: %q", o.Summary)
			}
		}
	})
}

// snapshotQuery はスナップショットだけを返す Query (ファズ用。ストアを作らない)。
type snapshotQuery struct {
	store.Query
	items []record.SnapshotItem
}

func (q snapshotQuery) Snapshot(context.Context, record.Kind) ([]record.SnapshotItem, error) {
	return q.items, nil
}
