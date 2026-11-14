package schemas

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 版 1 で持つスキーマ。足したらここにも足す (ファイルを置き忘れた・消したことに気づく)。
var want = []string{"arata-config-check", "aratam-config-check", "aratam-doctor", "aratam-dry-run", "config-diff", "doctor", "help-ai", "log", "profiles", "rebuild", "repo-diff", "report", "report-period", "review"}

func TestNames(t *testing.T) {
	got := Names()
	if !sort.StringsAreSorted(got) || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names: %v, want %v", got, want)
	}
}

// どのスキーマも、決めた見出しを持ち、開いた形である (ADR 0054)。
func TestEverySchemaHasTheAgreedHeader(t *testing.T) {
	id := regexp.MustCompile(`^urn:arata:schema:([a-z][a-z0-9-]*):([1-9][0-9]*)$`)
	for _, name := range Names() {
		b, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s: not found", name)
		}
		var head struct {
			Schema string `json:"$schema"`
			ID     string `json:"$id"`
			Title  string `json:"title"`
		}
		if err := json.Unmarshal(b, &head); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if head.Schema != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s: $schema %q", name, head.Schema)
		}
		if m := id.FindStringSubmatch(head.ID); m == nil || m[1] != name {
			t.Errorf("%s: $id %q", name, head.ID)
		}
		if head.Title != name {
			t.Errorf("%s: title %q", name, head.Title)
		}
		// 開いた形: 足した項目で、古いスキーマの検証が落ちないようにする
		if bytes.Contains(b, []byte(`"additionalProperties": false`)) || bytes.Contains(b, []byte(`"unevaluatedProperties"`)) {
			t.Errorf("%s: schemas must stay open", name)
		}
		if !bytes.HasSuffix(b, []byte("}\n")) {
			t.Errorf("%s: must end with a newline", name)
		}
	}
}

func TestWrite(t *testing.T) {
	var list bytes.Buffer
	if err := Write(&list, ""); err != nil {
		t.Fatal(err)
	}
	if list.String() != strings.Join(want, "\n")+"\n" {
		t.Fatalf("list:\n%s", list.String())
	}
	var one bytes.Buffer
	if err := Write(&one, "report"); err != nil {
		t.Fatal(err)
	}
	file, _ := Lookup("report")
	if !bytes.Equal(one.Bytes(), file) || len(file) == 0 {
		t.Fatal("the output must be the embedded file itself")
	}
	for _, bad := range []string{"none", "../schemas", "report.schema.json", "report/"} {
		err := Write(&bytes.Buffer{}, bad)
		if err == nil || !strings.Contains(err.Error(), "arata-config-check, aratam-config-check, aratam-doctor") {
			t.Errorf("%q: want an error that lists the names, got %v", bad, err)
		}
	}
	if ID("report", 1) != "urn:arata:schema:report:1" {
		t.Fatal(ID("report", 1))
	}
}
