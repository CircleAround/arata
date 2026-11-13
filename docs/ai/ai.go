// Package ai は AI (LLM) 向けの使い方の文書 (docs/ai/*.md) をバイナリに埋め込む。`arata help ai` が表示する。
//
// 決定 (ADR 0012): skill ファイルを別に配らず、バイナリと同じ版の文書を同梱する (版のずれを無くし、顧客環境で完結させる)。
package ai

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed index.md report.md approve.md runtime.md onboarding.md playbooks/*.md
var files embed.FS

// Topic は文書 1 つ。
type Topic struct {
	Name string // "ai" / "ai report" / "ai approve" / "ai runtime" / "ai onboarding" / "ai playbook" / "ai playbook <check>"
	File string // 空なら playbook の一覧 (埋め込んだ playbook から作る)
}

// Topics は `arata help ai [topic]` の一覧 (個々の playbook は含まない。`ai playbook <check>` で引く)。
var Topics = []Topic{
	{Name: "ai", File: "index.md"},
	{Name: "ai report", File: "report.md"},
	{Name: "ai approve", File: "approve.md"},
	{Name: "ai runtime", File: "runtime.md"},
	{Name: "ai onboarding", File: "onboarding.md"},
	{Name: "ai playbook"},
}

const playbookDir = "playbooks"

// PlaybookSections は playbook の見出し (## ) で、この順に必ず持つ。
// aratam などが LLM の system に埋め込むときの約束でもあるので、変えるときは読む側も見直す。
var PlaybookSections = []string{"この指摘の意味", "まず確かめること", "判断の分かれ目", "対処の選択肢", "やってはいけないこと"}

// PlaybookNames は playbook のあるチェック名 (名前順)。
func PlaybookNames() []string {
	ents, err := fs.ReadDir(files, playbookDir)
	if err != nil {
		panic(err) // embed しているので起きない
	}
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".md"); ok && !e.IsDir() {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// Playbook はチェック名 (finding の check) の対処手順 (Markdown の本文) を返す。無ければ false。
// 決定: aratam が「その run に出たチェックの playbook」を LLM の system に入れられるよう、標準ライブラリだけで引ける形にする
// (aratam の依存の許可リストに docs/ai は入っている)。
func Playbook(check string) (string, bool) {
	if check == "" || strings.ContainsAny(check, "/\\.") {
		return "", false
	}
	b, err := files.ReadFile(path.Join(playbookDir, check+".md"))
	if err != nil {
		return "", false
	}
	return string(b), true
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

// Lookup は sub ("" / "report" / "approve" / "runtime" / "onboarding" / "playbook" / "playbook <check>") の文書を返す。
func Lookup(sub string) (Topic, error) {
	if check, ok := strings.CutPrefix(strings.TrimSpace(sub), "playbook "); ok {
		check = strings.TrimSpace(check)
		if _, ok := Playbook(check); !ok {
			return Topic{}, fmt.Errorf("no playbook for check %q (%s)", check, strings.Join(PlaybookNames(), ", "))
		}
		return Topic{Name: "ai playbook " + check, File: path.Join(playbookDir, check+".md")}, nil
	}
	name := strings.TrimSpace("ai " + sub)
	for _, t := range Topics {
		if t.Name == name {
			return t, nil
		}
	}
	names := make([]string, 0, len(Topics)+1)
	for _, t := range Topics {
		names = append(names, "arata help "+t.Name)
	}
	names = append(names, "arata help ai playbook <check>")
	return Topic{}, fmt.Errorf("unknown topic %q (%s)", sub, strings.Join(names, ", "))
}

// Markdown は文書の本文。
func (t Topic) Markdown() string {
	if t.File == "" {
		return playbookIndex()
	}
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

// playbookIndex は `arata help ai playbook` の本文 (使い方と一覧)。一覧は埋め込んだ playbook の題から作る。
func playbookIndex() string {
	var b strings.Builder
	b.WriteString(`# チェックごとの対処手順 (playbook)

## 使い方

finding の ` + "`check`" + ` ごとに、確かめる順番・判断の分かれ目・対処の選択肢を決めた手順。
LLM はこの手順に沿って、根拠 (finding の ` + "`data`" + `) と利用者の事情を踏まえた助言を書く。

- 本文は ` + "`arata help ai playbook <check>`" + ` (` + "`--format json`" + ` で節ごと)。その run に出たチェックの分だけ読めばよい
- 見出しは固定: ` + strings.Join(PlaybookSections, " / ") + `
- 手順は汎用。アプリの構成・正規の送信元・運用の事情は組み込み側が渡す文書 (aratam の context_file など) で補う。食い違うときは利用者の事情を優先し、そう書き添える
- 封じ込め (認証情報の無効化・セッションの失効・公開の取り消しなど) は**人が判断して実行する**。LLM は提案まで (approve と同じ方針)
- arata は読み取り専用。手順の中の AWS の操作も、LLM が自分で行ってよいのは読み取り (` + "`describe` / `get` / `list` / `lookup`" + `) だけ。` + "`approve` / `ack` / `snooze` / `resolve`" + ` は人が行う
- aratam の要約のように手を動かせない LLM は、「まず確かめること」を人への確認事項として書く (自分で確かめたことにしない)
- 重大度は規則が決める。playbook を理由に critical / high を軽く扱わない

## 一覧

| チェック | 内容 | 本文 |
|---|---|---|
`)
	for _, n := range PlaybookNames() {
		t := Topic{Name: "ai playbook " + n, File: path.Join(playbookDir, n+".md")}
		title := strings.TrimPrefix(t.Parse().Title, n+": ")
		fmt.Fprintf(&b, "| %s | %s | `arata help ai playbook %s` |\n", n, title, n)
	}
	return b.String()
}
