package schema

import (
	"encoding/json"
	"flag"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

var update = flag.Bool("update", false, "スキーマのゴールデン (schemas/*.schema.json) を更新する")

// report.json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
// 型を変えるとここが落ちる。項目を足すのは互換。消す・名前や型や意味を変えるなら、版 (ReportSchemaVersion) を上げて Release の本文に書く。
func TestReportSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, ReportSchema, ReportSchemaVersion,
		"プロファイル実行の報告 (arata run / evaluate / report の report.json と、標準出力の --format json)。読み方は arata help ai report",
		Report{}, true, *update)
	schematest.Golden(t, PeriodReportSchema, PeriodReportSchemaVersion,
		"期間レポート (arata report --from --to / --month の report.json。kind: period)",
		PeriodReport{}, true, *update)
}

// 出す報告は、いつも今の名前と版を持つ。保存済みの古い報告 (項目が無い) を読み直して出すときも同じ。
func TestJSONStampsTheSchema(t *testing.T) {
	old, err := Parse([]byte(`{"profile":"daily","findings":{"new":[],"changed":[],"recurred":[],"resolved":[],"still_open":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if old.Schema != "" || old.SchemaVersion != 0 {
		t.Fatalf("a report without the fields must parse as is: %+v", old)
	}
	for name, r := range map[string]interface{ JSON() ([]byte, error) }{ReportSchema: old, PeriodReportSchema: &PeriodReport{Kind: "period"}} {
		b, err := r.JSON()
		if err != nil {
			t.Fatal(err)
		}
		var head struct {
			Schema  string `json:"schema"`
			Version int    `json:"schema_version"`
		}
		if err := json.Unmarshal(b, &head); err != nil {
			t.Fatal(err)
		}
		if head.Schema != name || head.Version != 1 {
			t.Errorf("%s: got %q version %d", name, head.Schema, head.Version)
		}
	}
	// JSON は受け取った値を書き換えない
	if old.Schema != "" {
		t.Fatal("JSON must not change the report")
	}
}
