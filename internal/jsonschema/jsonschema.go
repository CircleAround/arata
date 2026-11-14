// Package jsonschema は、機械が読む出力の Go の型から JSON Schema (draft 2020-12) を作る。
//
// 決定 (ADR 0054): 依存を足さず、標準ライブラリ (reflect) で作る。扱うのは出力に使っている形だけで、
// 扱えない形はエラーにする (スキーマに無い項目が、黙って出力に出るのを防ぐ)。
// 作ったスキーマは schemas/<名前>.schema.json にゴールデンとして置く (schematest)。実行時には使わない。
//
// 型とスキーマの対応:
//
//   - 構造体: object。項目は定義の順。omitempty / omitzero の無い項目は required。名前のある構造体は $defs に置いて $ref で指す
//   - 文字列・真偽値・整数・小数: string / boolean / integer / number
//   - スライス: array。map[string]T: object と additionalProperties。any と map[string]any: 中身を縛らない
//   - ポインタ: omitempty があれば省略できる項目、無ければ null を許す項目
//   - time.Time: string (format: date-time)
//
// タグ: `jsonschema:"enum=a|b"` (閉じた語彙。文字列だけ)、`jsonschema:"const=値"` (文字列か整数)、`desc:"説明"`、
// `jsonschema:"open=名前"` (開いた語彙。既知の値は Options.Open から取り、anyOf で「既知の値」か「形に合う文字列」と書く。
// 既知の値を機械で引けて、値を足しても古いスキーマで落ちない)。
// スキーマは開いた形にする (additionalProperties: false を書かない)。読む側が古いスキーマで新しい出力を確かめても、足した項目で落ちない。
package jsonschema

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Draft はスキーマの方言。
const Draft = "https://json-schema.org/draft/2020-12/schema"

// Options はスキーマの見出しと、開いた語彙。
type Options struct {
	ID          string
	Title       string
	Description string
	// Open は `jsonschema:"open=名前"` の語彙 (名前ごと)。
	Open map[string]Vocabulary
}

// Vocabulary は開いた語彙。Values は今の既知の値、Pattern は値の形 (これから足される値も合う正規表現)。
type Vocabulary struct {
	Values  []string
	Pattern string
}

// schema は出すキーワード。Verify が読むのもこのキーワードだけ。
type schema struct {
	Schema               string             `json:"$schema,omitempty"`
	ID                   string             `json:"$id,omitempty"`
	Title                string             `json:"title,omitempty"`
	Description          string             `json:"description,omitempty"`
	Ref                  string             `json:"$ref,omitempty"`
	Type                 any                `json:"type,omitempty"` // 文字列か、null を許すときは 2 つの並び
	Const                any                `json:"const,omitempty"`
	Enum                 []string           `json:"enum,omitempty"`
	Format               string             `json:"format,omitempty"`
	Pattern              string             `json:"pattern,omitempty"`
	Properties           properties         `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Items                *schema            `json:"items,omitempty"`
	AdditionalProperties *schema            `json:"additionalProperties,omitempty"`
	AnyOf                []*schema          `json:"anyOf,omitempty"`
	Defs                 map[string]*schema `json:"$defs,omitempty"`
}

type property struct {
	name string
	s    *schema
}

// properties は定義の順を保つ (map にすると名前の順になり、型の並びと合わなくなる)。
type properties []property

func (p properties) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(e.name)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(e.s)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

var (
	timeType          = reflect.TypeOf(time.Time{})
	marshalerType     = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

type generator struct {
	defs  map[string]*schema
	types map[string]reflect.Type
	open  map[string]Vocabulary
}

// Generate は v の型のスキーマを、整形した JSON (末尾に改行) で返す。v の値は使わない。
func Generate(v any, o Options) ([]byte, error) {
	t := reflect.TypeOf(v)
	if t == nil {
		return nil, fmt.Errorf("jsonschema: nil has no type")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	g := &generator{defs: map[string]*schema{}, types: map[string]reflect.Type{}, open: o.Open}
	var root *schema
	var err error
	if t.Kind() == reflect.Struct && t != timeType {
		// 最上位の構造体は $defs に置かず、その場に書く
		if err = unsupported(t); err == nil {
			root, err = g.object(t)
		}
	} else {
		root, err = g.of(t)
	}
	if err != nil {
		return nil, fmt.Errorf("jsonschema: %s: %w", t, err)
	}
	root.Schema, root.ID, root.Title, root.Description = Draft, o.ID, o.Title, o.Description
	if len(g.defs) > 0 {
		root.Defs = g.defs
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// unsupported は、encoding/json が型の形と違う出し方をする型 (自前の MarshalJSON など) を断る。
func unsupported(t reflect.Type) error {
	if t == timeType {
		return nil
	}
	for _, m := range []reflect.Type{marshalerType, textMarshalerType} {
		if t.Implements(m) || reflect.PointerTo(t).Implements(m) {
			return fmt.Errorf("%s marshals itself; its JSON form is not known from the type", t)
		}
	}
	return nil
}

func (g *generator) of(t reflect.Type) (*schema, error) {
	if err := unsupported(t); err != nil {
		return nil, err
	}
	switch t.Kind() {
	case reflect.String:
		return &schema{Type: "string"}, nil
	case reflect.Bool:
		return &schema{Type: "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &schema{Type: "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return &schema{Type: "number"}, nil
	case reflect.Interface:
		if t.NumMethod() != 0 {
			return nil, fmt.Errorf("%s: only the empty interface (any) is supported", t)
		}
		return &schema{}, nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil, fmt.Errorf("%s: byte slices are not supported (they marshal as base64)", t)
		}
		items, err := g.of(t.Elem())
		if err != nil {
			return nil, err
		}
		return &schema{Type: "array", Items: items}, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String || unsupported(t.Key()) != nil {
			return nil, fmt.Errorf("%s: map keys must be plain strings", t)
		}
		s := &schema{Type: "object"}
		if e := t.Elem(); e.Kind() != reflect.Interface || e.NumMethod() != 0 {
			values, err := g.of(e)
			if err != nil {
				return nil, err
			}
			s.AdditionalProperties = values
		}
		return s, nil
	case reflect.Pointer:
		return g.of(t.Elem())
	case reflect.Struct:
		if t == timeType {
			return &schema{Type: "string", Format: "date-time"}, nil
		}
		if t.Name() == "" {
			return g.object(t)
		}
		name := t.Name()
		if seen, ok := g.types[name]; ok {
			if seen != t {
				return nil, fmt.Errorf("two types are named %s (%s and %s)", name, seen, t)
			}
			return &schema{Ref: "#/$defs/" + name}, nil
		}
		// 先に登録する (自分を含む型で止まらない)
		g.types[name] = t
		s, err := g.object(t)
		if err != nil {
			return nil, err
		}
		g.defs[name] = s
		return &schema{Ref: "#/$defs/" + name}, nil
	}
	return nil, fmt.Errorf("%s (%s) is not supported", t, t.Kind())
}

func (g *generator) object(t reflect.Type) (*schema, error) {
	s := &schema{Type: "object"}
	if err := g.fields(t, s, map[string]bool{}); err != nil {
		return nil, err
	}
	return s, nil
}

func (g *generator) fields(t reflect.Type, s *schema, seen map[string]bool) error {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, tagged := f.Tag.Lookup("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			// 埋め込みの構造体は、encoding/json と同じく項目を親に並べる
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() != reflect.Struct || unsupported(et) != nil {
				return fmt.Errorf("%s.%s: only plain structs can be embedded", t, f.Name)
			}
			if err := g.fields(et, s, seen); err != nil {
				return err
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		if !tagged || name == "" {
			name = f.Name
		}
		optional := false
		for _, o := range strings.Split(opts, ",") {
			switch o {
			case "":
			case "omitempty", "omitzero":
				optional = true
			default:
				return fmt.Errorf("%s.%s: json option %q is not supported", t, f.Name, o)
			}
		}
		if seen[name] {
			return fmt.Errorf("%s.%s: the name %q is used twice", t, f.Name, name)
		}
		seen[name] = true
		ps, err := g.of(f.Type)
		if err != nil {
			return fmt.Errorf("%s.%s: %w", t, f.Name, err)
		}
		if f.Type.Kind() == reflect.Pointer && !optional {
			ps = nullable(ps)
		}
		if ps, err = g.annotate(ps, f); err != nil {
			return fmt.Errorf("%s.%s: %w", t, f.Name, err)
		}
		s.Properties = append(s.Properties, property{name, ps})
		if !optional {
			s.Required = append(s.Required, name)
		}
	}
	return nil
}

// nullable は null を許す形にする (omitempty の無いポインタ)。
func nullable(s *schema) *schema {
	if t, ok := s.Type.(string); ok && s.Ref == "" {
		c := *s
		c.Type = []string{t, "null"}
		return &c
	}
	return &schema{AnyOf: []*schema{s, {Type: "null"}}}
}

// annotate はタグの enum / const / 開いた語彙 / 説明を足したスキーマを返す。
func (g *generator) annotate(s *schema, f reflect.StructField) (*schema, error) {
	s.Description = f.Tag.Get("desc")
	tag := f.Tag.Get("jsonschema")
	if tag == "" {
		return s, nil
	}
	for _, part := range strings.Split(tag, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || value == "" {
			return nil, fmt.Errorf("jsonschema tag %q: want key=value", part)
		}
		switch {
		case key == "open" && s.Type == "string":
			v, ok := g.open[value]
			if !ok || len(v.Values) == 0 {
				return nil, fmt.Errorf("jsonschema tag %q: Options.Open has no values for %q", part, value)
			}
			if _, err := regexp.Compile(v.Pattern); err != nil || v.Pattern == "" {
				return nil, fmt.Errorf("jsonschema tag %q: the pattern of %q is not a regular expression", part, value)
			}
			s = &schema{Description: s.Description, AnyOf: []*schema{{Enum: append([]string(nil), v.Values...)}, {Type: "string", Pattern: v.Pattern}}}
		case key == "enum" && s.Type == "string":
			s.Enum = strings.Split(value, "|")
		case key == "const" && s.Type == "string":
			s.Const = value
		case key == "const" && s.Type == "integer":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("jsonschema tag %q: %w", part, err)
			}
			s.Const = n
		default:
			return nil, fmt.Errorf("jsonschema tag %q is not supported on this type", part)
		}
	}
	return s, nil
}
