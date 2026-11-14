package jsonschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Verify は、Generate が作ったスキーマに doc (JSON) が合うかを確かめる。テスト用 (実行時には使わない。ADR 0054)。
//
// JSON Schema の検証器ではない。読むのは Generate が出すキーワードだけで、知らないキーワードがあればエラーにする
// (読めないキーワードを黙って飛ばして「確かめた」ことにしない)。format は確かめない。
// 確かめるのは、型 (null を出してよい項目か)・必須の項目・enum・const。スキーマに無い項目があることは問わない (スキーマは開いた形)。
func Verify(schemaJSON, doc []byte) error {
	var root map[string]any
	if err := decodeOne(schemaJSON, &root); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	var v any
	if err := decodeOne(doc, &v); err != nil {
		return fmt.Errorf("document: %w", err)
	}
	defs, _ := root["$defs"].(map[string]any)
	return (&verifier{defs: defs}).check(root, v, "$")
}

func decodeOne(b []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after the JSON value")
	}
	return nil
}

type verifier struct {
	defs map[string]any
}

func (c *verifier) check(s map[string]any, v any, at string) error {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kw := s[k]
		var err error
		switch k {
		case "$schema", "$id", "title", "description", "format", "$defs", "required", "additionalProperties":
			// 見出しと、下の properties / type と一緒に見るもの
		case "$ref":
			name, ok := strings.CutPrefix(fmt.Sprint(kw), "#/$defs/")
			def, found := c.defs[name].(map[string]any)
			if !ok || !found {
				return fmt.Errorf("%s: unresolved $ref %v", at, kw)
			}
			err = c.check(def, v, at)
		case "type":
			err = checkType(kw, v, at)
		case "const":
			if !equal(kw, v) {
				err = fmt.Errorf("%s: want %v, got %v", at, kw, v)
			}
		case "enum":
			list, _ := kw.([]any)
			found := false
			for _, e := range list {
				found = found || equal(e, v)
			}
			if !found {
				err = fmt.Errorf("%s: %v is not one of %v", at, v, list)
			}
		case "properties":
			err = c.properties(s, v, at)
		case "items":
			items, ok := kw.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: items must be a schema", at)
			}
			if arr, isArr := v.([]any); isArr {
				for i, e := range arr {
					if err := c.check(items, e, fmt.Sprintf("%s[%d]", at, i)); err != nil {
						return err
					}
				}
			}
		case "anyOf":
			list, _ := kw.([]any)
			var first error
			matched := false
			for _, e := range list {
				sub, ok := e.(map[string]any)
				if !ok {
					return fmt.Errorf("%s: anyOf must list schemas", at)
				}
				if e := c.check(sub, v, at); e == nil {
					matched = true
				} else if first == nil {
					first = e
				}
			}
			if !matched {
				err = fmt.Errorf("%s: matches none of anyOf (%v)", at, first)
			}
		default:
			return fmt.Errorf("%s: schema keyword %q is not supported by Verify", at, k)
		}
		if err != nil {
			return err
		}
	}
	// properties の無い object (map[string]T) の値
	if _, has := s["properties"]; !has {
		if err := c.additional(s, v, at, nil); err != nil {
			return err
		}
	}
	if _, has := s["properties"]; !has && s["required"] != nil {
		return fmt.Errorf("%s: required without properties", at)
	}
	return nil
}

func (c *verifier) properties(s map[string]any, v any, at string) error {
	props, ok := s["properties"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s: properties must be an object", at)
	}
	obj, isObj := v.(map[string]any)
	if !isObj {
		return nil // 型の違いは type が報せる
	}
	if req, ok := s["required"].([]any); ok {
		for _, r := range req {
			if _, has := obj[fmt.Sprint(r)]; !has {
				return fmt.Errorf("%s: required %q is missing", at, r)
			}
		}
	}
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sub, ok := props[n].(map[string]any)
		if !ok {
			return fmt.Errorf("%s.%s: property must be a schema", at, n)
		}
		if pv, has := obj[n]; has {
			if err := c.check(sub, pv, at+"."+n); err != nil {
				return err
			}
		}
	}
	return c.additional(s, v, at, props)
}

// additional は additionalProperties のスキーマを、properties に無い項目の値に当てる。
func (c *verifier) additional(s map[string]any, v any, at string, props map[string]any) error {
	kw, has := s["additionalProperties"]
	if !has {
		return nil
	}
	sub, ok := kw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: additionalProperties must be a schema", at)
	}
	obj, _ := v.(map[string]any)
	names := make([]string, 0, len(obj))
	for n := range obj {
		if _, known := props[n]; !known {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if err := c.check(sub, obj[n], at+"."+n); err != nil {
			return err
		}
	}
	return nil
}

func checkType(kw, v any, at string) error {
	var want []string
	switch t := kw.(type) {
	case string:
		want = []string{t}
	case []any:
		for _, e := range t {
			want = append(want, fmt.Sprint(e))
		}
	}
	if len(want) == 0 {
		return fmt.Errorf("%s: type must be a name or a list of names", at)
	}
	for _, w := range want {
		ok := false
		switch w {
		case "string":
			_, ok = v.(string)
		case "boolean":
			_, ok = v.(bool)
		case "number":
			_, ok = v.(json.Number)
		case "integer":
			if n, isNum := v.(json.Number); isNum {
				_, err := n.Int64()
				ok = err == nil
			}
		case "array":
			_, ok = v.([]any)
		case "object":
			_, ok = v.(map[string]any)
		case "null":
			ok = v == nil
		default:
			return fmt.Errorf("%s: unknown type %q", at, w)
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("%s: want %s, got %s", at, strings.Join(want, " or "), describe(v))
}

func describe(v any) string {
	if v == nil {
		return "null"
	}
	b, _ := json.Marshal(v)
	if len(b) > 60 {
		b = append(b[:60], "…"...)
	}
	return string(b)
}

// equal は const / enum の比較 (文字列と数だけ)。
func equal(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok || bok {
		return aok && bok && an.String() == bn.String()
	}
	as, aok := a.(string)
	bs, bok := b.(string)
	return aok && bok && as == bs
}
