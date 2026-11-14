package main

import (
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
	"github.com/CircleAround/arata/schemas"
)

// rebuild --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestRebuildSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: rebuildSchema, Version: rebuildSchemaVersion, Versioned: true, Type: rebuildOutput{},
		Description: "arata rebuild --format json の出力。raw から作り直した表ごとの件数と、引き継いだもの・読み飛ばしたもの"}, *update)
}

// arata schema [名前] と arata help schema [名前] は、埋め込んだスキーマのファイルそのものを出す (ADR 0054)。
// 引数なしなら名前の一覧。AWS にもストアにも繋がず、設定ファイルも要らない。
func TestSchemaCommand(t *testing.T) {
	c := newCLI(t)
	list := strings.Join(schemas.Names(), "\n") + "\n"
	for _, args := range [][]string{{"schema"}, {"help", "schema"}} {
		if code := c.run(args...); code != 0 || c.stdout.String() != list {
			t.Fatalf("%v: exit %d\n%s%s", args, code, c.stdout, c.stderr)
		}
	}
	if len(schemas.Names()) == 0 {
		t.Fatal("no schemas are embedded")
	}
	for _, name := range schemas.Names() {
		want, _ := schemas.Lookup(name)
		for _, args := range [][]string{{"schema", name}, {"help", "schema", name}} {
			if code := c.run(args...); code != 0 || c.stdout.String() != string(want) {
				t.Fatalf("%v: exit %d\n%s%s", args, code, c.stdout, c.stderr)
			}
		}
	}
	for _, args := range [][]string{{"schema", "none"}, {"help", "schema", "none"}, {"schema", "report", "extra"}, {"help", "schema", "report", "extra"}} {
		if code := c.run(args...); code != 2 || c.stdout.Len() != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, c.stdout, c.stderr)
		}
	}
	// 一覧に出る (ルートのヘルプ) ことと、読む側の決まりがヘルプにあること
	if c.run(); !strings.Contains(c.stdout.String(), "\n  schema ") {
		t.Fatalf("root help lacks schema:\n%s", c.stdout)
	}
	if c.run("schema", "--help"); !strings.Contains(c.stdout.String(), "schema_version が自分の知る版より大きければ止める") {
		t.Fatalf("schema help:\n%s", c.stdout)
	}
}
