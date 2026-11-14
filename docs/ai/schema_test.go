package ai

import (
	"encoding/json"
	"flag"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

var update = flag.Bool("update", false, "スキーマのゴールデン (schemas/help-ai.schema.json) を更新する")

// arata help ai --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestDocSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: DocSchema, Version: DocSchemaVersion, Versioned: true, Type: Doc{},
		Description: "arata help ai [topic] --format json の出力。LLM 向けの文書を節ごとに分けたもの。本文 (body) の文言は固定しない"}, *update)
}

// どの文書も、節に分けた形がスキーマに合い、型に無い項目を持たない。
func TestEveryDocConforms(t *testing.T) {
	topics := append([]Topic(nil), Topics...)
	for _, name := range PlaybookNames() {
		tp, err := Lookup("playbook " + name)
		if err != nil {
			t.Fatal(err)
		}
		topics = append(topics, tp)
	}
	for _, id := range ThreatNames() {
		tp, err := Lookup("threats " + id)
		if err != nil {
			t.Fatal(err)
		}
		topics = append(topics, tp)
	}
	for _, tp := range topics {
		b, err := json.Marshal(tp.Parse())
		if err != nil {
			t.Fatal(err)
		}
		schematest.Conforms(t, DocSchema, b, &Doc{})
	}
}
