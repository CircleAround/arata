// Package ai は AI (LLM) 向けの使い方の文書 (docs/ai/*.md) をバイナリに埋め込む。`arata help ai` が表示する。
//
// 決定 (ADR 0012): skill ファイルを別に配らず、バイナリと同じ版の文書を同梱する (版のずれを無くし、顧客環境で完結させる)。
package ai

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed index.md report.md approve.md
var files embed.FS

// Topic は文書 1 つ。
type Topic struct {
	Name string // "ai" / "ai report" / "ai approve"
	File string
}

// Topics は `arata help ai [topic]` の一覧。
var Topics = []Topic{
	{Name: "ai", File: "index.md"},
	{Name: "ai report", File: "report.md"},
	{Name: "ai approve", File: "approve.md"},
}

// Section は見出し (##) 1 つ分。
type Section struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Doc は `--format json` の形。
type Doc struct {
	Topic    string    `json:"topic"`
	Title    string    `json:"title"`
	Sections []Section `json:"sections"`
}

// Lookup は sub ("" / "report" / "approve") の文書を返す。
func Lookup(sub string) (Topic, error) {
	name := strings.TrimSpace("ai " + sub)
	for _, t := range Topics {
		if t.Name == name {
			return t, nil
		}
	}
	names := make([]string, 0, len(Topics))
	for _, t := range Topics {
		names = append(names, "arata help "+t.Name)
	}
	return Topic{}, fmt.Errorf("unknown topic %q (%s)", sub, strings.Join(names, ", "))
}

// Markdown は文書の本文。
func (t Topic) Markdown() string {
	b, err := files.ReadFile(t.File)
	if err != nil {
		panic(err) // embed しているので起きない
	}
	return string(b)
}

// Parse は本文を # 見出しと ## セクションに分ける。コードブロック内の # は見出しとみなさない。
func (t Topic) Parse() Doc {
	d := Doc{Topic: t.Name, Sections: []Section{}}
	var cur *Section
	var body []string
	flush := func() {
		if cur != nil {
			cur.Body = strings.TrimSpace(strings.Join(body, "\n"))
			d.Sections = append(d.Sections, *cur)
		}
		body = nil
	}
	fence := false
	for _, line := range strings.Split(t.Markdown(), "\n") {
		if strings.HasPrefix(line, "```") {
			fence = !fence
		}
		switch {
		case !fence && strings.HasPrefix(line, "# ") && d.Title == "":
			d.Title = strings.TrimPrefix(line, "# ")
		case !fence && strings.HasPrefix(line, "## "):
			flush()
			cur = &Section{Title: strings.TrimPrefix(line, "## ")}
		default:
			body = append(body, line)
		}
	}
	flush()
	return d
}
