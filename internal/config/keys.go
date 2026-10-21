package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// UnknownKeys は設定の YAML のうち、arata が知らないキーのパス (例: `profiles.daily.overide`) を出現順に返す。
// Load は未知のキーで失敗するので、`config init --diff` は Load の前にこれで未知のキーを列挙する。
func UnknownKeys(b []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	var out []string
	unknownKeys(doc.Content[0], reflect.TypeOf(Config{}), "", &out)
	return out, nil
}

func unknownKeys(n *yaml.Node, t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case n.Kind == yaml.MappingNode && t.Kind() == reflect.Struct:
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			ft, ok := fields[k]
			if !ok {
				*out = append(*out, join(path, k))
				continue
			}
			unknownKeys(n.Content[i+1], ft, join(path, k), out)
		}
	case n.Kind == yaml.MappingNode && t.Kind() == reflect.Map:
		for i := 0; i+1 < len(n.Content); i += 2 {
			unknownKeys(n.Content[i+1], t.Elem(), join(path, n.Content[i].Value), out)
		}
	case n.Kind == yaml.SequenceNode && t.Kind() == reflect.Slice:
		for i, c := range n.Content {
			unknownKeys(c, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// yamlFields は struct の yaml キー → 型 (inline は展開、`-` は除く)。
func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if !f.IsExported() || tag == "-" {
			continue
		}
		if strings.Contains(tag, "inline") {
			for k, v := range yamlFields(f.Type) {
				out[k] = v
			}
			continue
		}
		name := yamlName(f)
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = f.Type
	}
	return out
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}
