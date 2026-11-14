package jsonschema

import (
	"strings"
	"testing"
	"time"
)

type inner struct {
	ID    string   `json:"id"`
	Rate  *float64 `json:"rate"`
	Extra *float64 `json:"extra,omitempty"`
}

type embedded struct {
	Shared string `json:"shared"`
}

type sample struct {
	Schema  string `json:"schema" jsonschema:"const=sample"`
	Version int    `json:"schema_version" jsonschema:"const=1"`
	embedded
	Method  string           `json:"method" jsonschema:"enum=bot|webhook" desc:"送り方"`
	OK      bool             `json:"ok"`
	Count   int64            `json:"count"`
	Ratio   float64          `json:"ratio"`
	Items   []inner          `json:"items"`
	Names   []string         `json:"names,omitempty"`
	Counts  map[string]int64 `json:"counts"`
	Data    map[string]any   `json:"data"`
	Any     any              `json:"any,omitempty"`
	One     *inner           `json:"one,omitempty"`
	Null    *inner           `json:"null"`
	At      time.Time        `json:"at"`
	Skipped string           `json:"-"`
	hidden  string
	NoTag   string
	Anon    struct {
		A string `json:"a"`
	} `json:"anon"`
}

const sampleSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:arata:schema:sample:1",
  "title": "sample",
  "description": "見本",
  "type": "object",
  "properties": {
    "schema": {
      "type": "string",
      "const": "sample"
    },
    "schema_version": {
      "type": "integer",
      "const": 1
    },
    "shared": {
      "type": "string"
    },
    "method": {
      "description": "送り方",
      "type": "string",
      "enum": [
        "bot",
        "webhook"
      ]
    },
    "ok": {
      "type": "boolean"
    },
    "count": {
      "type": "integer"
    },
    "ratio": {
      "type": "number"
    },
    "items": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/inner"
      }
    },
    "names": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "counts": {
      "type": "object",
      "additionalProperties": {
        "type": "integer"
      }
    },
    "data": {
      "type": "object"
    },
    "any": {},
    "one": {
      "$ref": "#/$defs/inner"
    },
    "null": {
      "anyOf": [
        {
          "$ref": "#/$defs/inner"
        },
        {
          "type": "null"
        }
      ]
    },
    "at": {
      "type": "string",
      "format": "date-time"
    },
    "NoTag": {
      "type": "string"
    },
    "anon": {
      "type": "object",
      "properties": {
        "a": {
          "type": "string"
        }
      },
      "required": [
        "a"
      ]
    }
  },
  "required": [
    "schema",
    "schema_version",
    "shared",
    "method",
    "ok",
    "count",
    "ratio",
    "items",
    "counts",
    "data",
    "null",
    "at",
    "NoTag",
    "anon"
  ],
  "$defs": {
    "inner": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "rate": {
          "type": [
            "number",
            "null"
          ]
        },
        "extra": {
          "type": "number"
        }
      },
      "required": [
        "id",
        "rate"
      ]
    }
  }
}
`

func TestGenerate(t *testing.T) {
	// 公開していない項目 (hidden) と json:"-" の項目は、スキーマに出ない
	_ = sample{hidden: "x", Skipped: "x"}
	got, err := Generate(sample{}, Options{ID: "urn:arata:schema:sample:1", Title: "sample", Description: "見本"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sampleSchema {
		t.Fatalf("got:\n%s", got)
	}
	// ポインタを渡しても同じ
	again, err := Generate(&sample{}, Options{ID: "urn:arata:schema:sample:1", Title: "sample", Description: "見本"})
	if err != nil || string(again) != string(got) {
		t.Fatalf("pointer: %v\n%s", err, again)
	}
}

func TestGenerateTopLevelArray(t *testing.T) {
	got, err := Generate([]inner{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"type": "array"`, `"$ref": "#/$defs/inner"`, `"$defs"`} {
		if !strings.Contains(string(got), w) {
			t.Errorf("lacks %s:\n%s", w, got)
		}
	}
}

type recursive struct {
	Name     string      `json:"name"`
	Children []recursive `json:"children,omitempty"`
}

func TestGenerateRecursiveType(t *testing.T) {
	got, err := Generate(struct {
		Root recursive `json:"root"`
	}{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(got), `"$ref": "#/$defs/recursive"`); n != 2 {
		t.Fatalf("want 2 refs, got %d:\n%s", n, got)
	}
}

type marshaler struct{}

func (marshaler) MarshalJSON() ([]byte, error) { return []byte(`1`), nil }

// 扱えない形は黙って落とさず、エラーにする (スキーマに無い項目が出力に出るのを防ぐ)。
func TestGenerateRejectsUnsupported(t *testing.T) {
	cases := map[string]any{
		"channel":        struct{ C chan int }{},
		"func":           struct{ F func() }{},
		"interface":      struct{ E error }{},
		"non-string key": struct{ M map[int]string }{},
		"bytes":          struct{ B []byte }{},
		"marshaler":      struct{ M marshaler }{},
		"string option": struct {
			N int `json:"n,string"`
		}{},
		"enum on a number": struct {
			N int `json:"n" jsonschema:"enum=1|2"`
		}{},
		"unknown tag key": struct {
			S string `json:"s" jsonschema:"pattern=x"`
		}{},
		"bad const": struct {
			N int `json:"n" jsonschema:"const=x"`
		}{},
		"array (fixed len)": struct{ A [2]int }{},
	}
	for name, v := range cases {
		if out, err := Generate(v, Options{}); err == nil {
			t.Errorf("%s: want an error, got\n%s", name, out)
		}
	}
}

func TestVerify(t *testing.T) {
	ok := `{"schema":"sample","schema_version":1,"shared":"s","method":"bot","ok":true,"count":2,"ratio":0.5,
		"items":[{"id":"a","rate":null},{"id":"b","rate":1.5,"extra":2}],"counts":{"x":1},"data":{"k":[1,"a",null]},
		"null":null,"at":"2026-01-02T03:04:05Z","NoTag":"","anon":{"a":""},"added_later":1}`
	if err := Verify([]byte(sampleSchema), []byte(ok)); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	bad := map[string][2]string{
		"missing required":       {`"shared":"s",`, ``},
		"null array":             {`"items":[{"id":"a","rate":null},{"id":"b","rate":1.5,"extra":2}]`, `"items":null`},
		"null object":            {`"data":{"k":[1,"a",null]}`, `"data":null`},
		"enum":                   {`"method":"bot"`, `"method":"email"`},
		"const":                  {`"schema_version":1`, `"schema_version":2`},
		"const string":           {`"schema":"sample"`, `"schema":"other"`},
		"type":                   {`"ok":true`, `"ok":"true"`},
		"integer":                {`"count":2`, `"count":2.5`},
		"nested required":        {`{"id":"a","rate":null}`, `{"id":"a"}`},
		"nested type":            {`"extra":2`, `"extra":"2"`},
		"additional properties":  {`"counts":{"x":1}`, `"counts":{"x":"1"}`},
		"anyOf":                  {`"null":null`, `"null":3`},
		"null where not allowed": {`"NoTag":""`, `"NoTag":null`},
	}
	for name, r := range bad {
		if !strings.Contains(ok, r[0]) {
			t.Fatalf("%s: the valid document lacks %s", name, r[0])
		}
		doc := strings.Replace(ok, r[0], r[1], 1)
		if err := Verify([]byte(sampleSchema), []byte(doc)); err == nil {
			t.Errorf("%s: want an error for %s", name, doc)
		}
	}
	if err := Verify([]byte(sampleSchema), []byte(ok+" {}")); err == nil {
		t.Error("trailing data must be rejected")
	}
	// 知らないキーワードは「検証した」ことにしない
	if err := Verify([]byte(`{"type":"string","pattern":"^a"}`), []byte(`"b"`)); err == nil {
		t.Error("unknown keyword must be an error")
	}
	if err := Verify([]byte(`{"$ref":"#/$defs/none"}`), []byte(`1`)); err == nil {
		t.Error("unresolved $ref must be an error")
	}
}
