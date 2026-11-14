package engine

import (
	"flag"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

var updateSchemas = flag.Bool("update-schemas", false, "スキーマのゴールデン (schemas/*.schema.json) を更新する")

// doctor / profiles の --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
// 項目を足すのは互換。消す・名前や型や意味を変えるなら、版を上げて Release の本文に書く。
func TestOutputSchemasAreFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: DoctorSchema, Version: DoctorSchemaVersion, Versioned: true, Type: DoctorResult{},
		Description: "arata doctor --format json の出力。権限・ロググループ・解釈率などの検査の行と、必要な IAM action。読み方は arata help ai logs"}, *updateSchemas)
	schematest.Golden(t, schematest.Spec{Name: ProfilesSchema, Version: ProfilesSchemaVersion, Versioned: true, Type: ProfilesView{},
		Description: "arata profiles --format json の出力。プロファイルごとに実際に走るチェックとパラメータ (由来つき)、どのプロファイルにも入っていないチェック"}, *updateSchemas)
	// 最上位が配列の出力は、今の形を版 1 として固定する (schema / schema_version の項目は持てない)
	schematest.Golden(t, schematest.Spec{Name: ReviewSchema, Version: ReviewSchemaVersion, Type: []ReviewItem{},
		Description: "arata review --format json の出力。未対応の finding の配列 (最上位が配列。schema の項目は無い)。data の中身はチェックごとで、このスキーマでは縛らない"}, *updateSchemas)
}
