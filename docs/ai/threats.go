package ai

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// 実際に起きた攻撃と、arata のどのチェックで何が見えるかの対応表 (docs/ai/threats/<id>.md。ADR 0057)。
//
// 決定:
//   - 事例 1 つが 1 ファイル。見出しは固定 (ThreatSections)。一覧とチェックごとの表は、事例の本文から作る (二重に持つとずれる)。
//   - 出典が「観測した」と書くことと、「スクリプトにその機能がある」とだけ書くことを、段階ごとに分ける (ThreatBasis)。
//   - チェックの名前を書けるのは「攻撃の段階と arata で見えるもの」の表の 3 列目だけで、実在するチェックに限る (テストで固定)。
//     これから作るチェックは「予定している改善」に、予定と分かるように書く。
//   - 事例の本文も、playbook の「関連する事例」の節も、aratam の LLM の system には入れない (PlaybookProcedure)。

const threatDir = "threats"

// ThreatSections は事例の見出し (## ) で、この順に必ず持つ。
var ThreatSections = []string{"概要", "出典", "攻撃の段階と arata で見えるもの", "arata では見えないもの", "予定している改善"}

// ThreatBasis は段階ごとの「出典の書き方」の語彙。
//
//	観測: 出典が、被害の環境や公開の記録で実際に見たと書いている
//	機能: 出典が、スクリプトや道具にその機能があるとだけ書いている (被害の環境で起きたとは書いていない)
//	推定: 出典が、推定・評価として書いている
//	記述: 出典が攻撃者の手口として書いているが、観測か機能かを明示していない
//	想定: 出典には無い。前の段階の結果として起こり得ることを、arata の側で想定したもの
var ThreatBasis = []string{"観測", "機能", "推定", "記述", "想定"}

// NoThreatYet は、対応する事例が無いチェックに書く決まった文言。
const NoThreatYet = "対応する公開の事例はまだ無い"

// ThreatStage は「攻撃の段階と arata で見えるもの」の表の 1 行。
type ThreatStage struct {
	Stage  string   // 攻撃の段階
	Basis  string   // 出典の書き方 (ThreatBasis)
	Checks []string // arata のチェック (無ければ空 = 見えない)
	Record string   // 元になる記録 (CloudTrail の event 名など)
	Output string   // 出るもの (重大度と条件)。見えない段階はその理由
}

// ThreatNames は事例の ID (公開日の新しい順。同じ日なら名前順)。
func ThreatNames() []string {
	ents, err := fs.ReadDir(files, threatDir)
	if err != nil {
		panic(err) // embed しているので起きない
	}
	var ids []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".md"); ok && !e.IsDir() {
			ids = append(ids, n)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := ThreatPublished(ids[i]), ThreatPublished(ids[j])
		if a != b {
			return a > b
		}
		return ids[i] < ids[j]
	})
	return ids
}

// Threat は事例の本文 (Markdown) を返す。無ければ false。
func Threat(id string) (string, bool) {
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return "", false
	}
	b, err := files.ReadFile(path.Join(threatDir, id+".md"))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func threatSection(id, title string) string {
	if _, ok := Threat(id); !ok {
		return ""
	}
	for _, s := range (Topic{File: path.Join(threatDir, id+".md")}).Parse().Sections {
		if s.Title == title {
			return s.Body
		}
	}
	return ""
}

var threatPublishedRe = regexp.MustCompile(`^- 公開日: (\d{4}-\d{2}-\d{2})`)

// ThreatPublished は事例の公開日 (概要の先頭の行 `- 公開日: YYYY-MM-DD`)。無ければ空。
func ThreatPublished(id string) string {
	if m := threatPublishedRe.FindStringSubmatch(threatSection(id, ThreatSections[0])); m != nil {
		return m[1]
	}
	return ""
}

var threatCheckRe = regexp.MustCompile("`([a-z_]+)`")

// ThreatStages は事例の段階の表を返す (見出しと区切りの行は除く)。列が 5 つでない行は、空の行として返す (テストが落とす)。
func ThreatStages(id string) []ThreatStage {
	var out []ThreatStage
	rows := 0
	for _, line := range strings.Split(threatSection(id, ThreatSections[2]), "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		if rows++; rows <= 2 { // 見出しと区切り
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) != 5 {
			out = append(out, ThreatStage{})
			continue
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		st := ThreatStage{Stage: cells[0], Basis: cells[1], Record: cells[3], Output: cells[4]}
		for _, m := range threatCheckRe.FindAllStringSubmatch(cells[2], -1) {
			st.Checks = append(st.Checks, m[1])
		}
		out = append(out, st)
	}
	return out
}

// ThreatChecks は事例の表に出てくるチェックの名前 (名前順、重複なし)。
func ThreatChecks(id string) []string {
	seen := map[string]bool{}
	var out []string
	for _, st := range ThreatStages(id) {
		for _, c := range st.Checks {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

func threatTitle(id string) string {
	return strings.TrimPrefix((Topic{File: path.Join(threatDir, id+".md")}).Parse().Title, id+": ")
}

// ThreatTable は事例の一覧の表 (事例の本文から作る)。
func ThreatTable() string {
	var b strings.Builder
	b.WriteString("| 事例 | 公開日 | 内容 | 見えるチェック | 本文 |\n|---|---|---|---|---|\n")
	for _, id := range ThreatNames() {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | `arata help ai threats %s` |\n", id, ThreatPublished(id), threatTitle(id), strings.Join(ThreatChecks(id), ", "), id)
	}
	return b.String()
}

// ThreatCheckTable はチェックごとの事例の表。事例の無いチェックには NoThreatYet を書く。
func ThreatCheckTable() string {
	by := map[string][]string{}
	for _, id := range ThreatNames() {
		for _, c := range ThreatChecks(id) {
			by[c] = append(by[c], id)
		}
	}
	var b strings.Builder
	b.WriteString("| チェック | 事例 |\n|---|---|\n")
	for _, n := range PlaybookNames() {
		v := NoThreatYet
		if len(by[n]) > 0 {
			v = strings.Join(by[n], ", ")
		}
		fmt.Fprintf(&b, "| %s | %s |\n", n, v)
	}
	return b.String()
}

// threatIndex は `arata help ai threats` の本文。表は事例の本文から作る。
func threatIndex() string {
	return `# 実際に起きた攻撃と、arata で見えるもの (事例の対応表)

## 使い方

公開された攻撃の事例ごとに、攻撃の段階と、その段階で arata のどのチェックが、どの記録から、何を出すかを並べた表。
「なぜこのチェックを入れるか」と「入れても何が見えないか」を判断する材料にする。

- 本文は ` + "`arata help ai threats <id>`" + ` (` + "`--format json`" + ` で節ごと)。見出しは固定: ` + strings.Join(ThreatSections, " / ") + `
- 根拠は公開の出典だけ (URL と日付を必ず書く)。出典の文は写さず、要約する
- 段階ごとに「出典の書き方」を分けている。**観測**: 出典が、被害の環境や公開の記録で実際に見たと書いている / **機能**: スクリプトや道具にその機能があるとだけ書いている /
  **推定**: 出典が推定として書いている / **記述**: 手口として書いているが、観測か機能かを明示していない / **想定**: 出典には無く、前の段階の結果として起こり得ることを arata の側で想定した
- 「見えるチェック」は、そのチェックを profiles に入れ、要る記録を集めているときの話 (` + "`arata profiles`" + `、` + "`arata help ai logs`" + `)。重大度と条件は各事例の表に書いてある
- **表に載っていることは、検知できるという保証ではない。** 条件 (既知リストの状態、平常帯、周期) で出ないことがあり、事例ごとに「arata では見えないもの」を必ず読む
- 指摘が出たときに、それがこの表の攻撃だと断定しない。重大度は規則が決め、判断は人が行う (` + "`arata help ai playbook <check>`" + `)

## 事例の一覧

` + ThreatTable() + `
## チェックごとの事例

` + ThreatCheckTable() + `
## 保守の決まり

- 新しいチェックを足す PR では、そのチェックで見える公開の事例を足すか、playbook の「関連する事例」に「` + NoThreatYet + `」と書く
- 事例には、公開日と、日付の付いた出典の URL (一次情報か、調査した会社の記事) が必ずある。出典を自分で読んで確かめられないものは入れない
- 表に書くチェックの名前は、実在するチェックだけ。これから作るものは「予定している改善」に、予定と分かるように書き、実装した PR で表へ移す
- チェックの重大度や条件を変えたら、そのチェックが出てくる事例の表も直す
- 利用者の環境で見た事実は書かない (公開の出典だけ)。攻撃の基盤の値 (IP など) は書き写さず、出典へ案内する
- どれもテストが確かめる (` + "`docs/ai/threats_test.go`" + `)
`
}
