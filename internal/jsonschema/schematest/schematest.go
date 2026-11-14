// Package schematest は、機械が読む出力をスキーマで固定するテストの共通部分 (ADR 0054)。
//
//   - Golden: 型から作ったスキーマが schemas/<名前>.schema.json と一致する (-update で書き直す)
//   - Conforms: コマンドが実際に出した出力が、そのスキーマに合い、型に無い項目を持たない
//
// テストからだけ使う。
package schematest

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema"
	"github.com/CircleAround/arata/schemas"
)

// path は schemas/<名前>.schema.json の場所 (テストのカレントディレクトリから go.mod を探す)。
func path(t testing.TB, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "schemas", name+".schema.json")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// Golden は v の型から作ったスキーマを、置いてあるファイルと比べる。update なら先に書き直す。
// 最上位がオブジェクトの出力は、schema (名前) と schema_version (版) の項目を const で持つことも確かめる。
// 最上位が配列の出力 (版 1 の review・config-diff) は項目を持てないので、versioned を false にする。
func Golden(t *testing.T, name string, version int, description string, v any, versioned, update bool) {
	t.Helper()
	got, err := jsonschema.Generate(v, jsonschema.Options{ID: schemas.ID(name, version), Title: name, Description: description})
	if err != nil {
		t.Fatal(err)
	}
	p := path(t, name)
	if update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run the test with -update to create it)", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("schemas/%s.schema.json differs from the schema of %T.\n"+
			"Adding a field is compatible. Removing, renaming or retyping one needs a new schema_version and a note in the release (ADR 0054).\n"+
			"Review the change, then run this test with -update.\n--- generated ---\n%s", name, v, got)
	}
	if !versioned {
		return
	}
	var head struct {
		Properties struct {
			Schema struct {
				Const string `json:"const"`
			} `json:"schema"`
			Version struct {
				Const int `json:"const"`
			} `json:"schema_version"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(got, &head); err != nil {
		t.Fatal(err)
	}
	if head.Properties.Schema.Const != name || head.Properties.Version.Const != version {
		t.Fatalf("%T must carry schema (const %q) and schema_version (const %d): got %q and %d",
			v, name, version, head.Properties.Schema.Const, head.Properties.Version.Const)
	}
	required := map[string]bool{}
	for _, r := range head.Required {
		required[r] = true
	}
	if !required["schema"] || !required["schema_version"] {
		t.Fatalf("%T: schema and schema_version must be required (no omitempty)", v)
	}
}

// Conforms は、コマンドの実際の出力 out を確かめる。
//
//   - スキーマに合う: 必須の項目があり、null を出してよい項目のほかは null でなく、enum / const の値である
//   - 型に無い項目を出していない: DisallowUnknownFields で into (出力の型へのポインタ) に読める
func Conforms(t *testing.T, name string, out []byte, into any) {
	t.Helper()
	schema, ok := schemas.Lookup(name)
	if !ok {
		t.Fatalf("no embedded schema %q", name)
	}
	if err := jsonschema.Verify(schema, out); err != nil {
		t.Fatalf("the output does not match schemas/%s.schema.json: %v\n%s", name, err, out)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("the output has a field the type %T lacks (every field must come from the type): %v\n%s", into, err, out)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("the output must be one JSON value:\n%s", out)
	}
}
