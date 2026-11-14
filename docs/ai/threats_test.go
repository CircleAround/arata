package ai

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	threatIDRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-\d{4}-\d{2}$`)
	threatDateRe = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	threatURLRe  = regexp.MustCompile(`https://[^\s)>]+`)
	threatRefRe  = regexp.MustCompile("`arata help ai threats ([a-z0-9-]+)`")
)

// TestThreats は事例 (docs/ai/threats/<id>.md) の書式と保守の決まりを固定する (ADR 0057)。
//   - 見出しは固定。各事例に公開日と、日付の付いた出典の URL が必ずある
//   - 段階の表に出てくるチェックは実在する (playbook がある = 登録済み。internal/checks のテストが登録と playbook の一致を固定している)
//   - 出典の書き方 (観測 / 機能 / 推定 / 記述 / 想定) を必ず分ける
//   - arata では見えないものと、予定している改善 (無ければ「無し」) を必ず書く
func TestThreats(t *testing.T) {
	ids := ThreatNames()
	if len(ids) < 2 {
		t.Fatalf("threats: %v", ids)
	}
	known := map[string]bool{}
	for _, n := range PlaybookNames() {
		known[n] = true
	}
	basis := map[string]bool{}
	for _, b := range ThreatBasis {
		basis[b] = true
	}
	acct := regexp.MustCompile(`\b\d{12}\b`)
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	ip := regexp.MustCompile(`\b\d{1,3}(\[?\.\]?\d{1,3}){3}\b`)
	for _, id := range ids {
		if !threatIDRe.MatchString(id) {
			t.Errorf("%s: id must look like <name>-YYYY-MM", id)
		}
		body, ok := Threat(id)
		if !ok || body == "" {
			t.Fatalf("%s: Threat() is empty", id)
		}
		tp, err := Lookup("threats " + id)
		if err != nil {
			t.Fatal(err)
		}
		if tp.Markdown() != body {
			t.Fatalf("%s: help ai threats differs from Threat()", id)
		}
		d := tp.Parse()
		if !strings.HasPrefix(d.Title, id+": ") {
			t.Errorf("%s: title %q must start with %q", id, d.Title, id+": ")
		}
		var got []string
		sec := map[string]string{}
		for _, s := range d.Sections {
			got = append(got, s.Title)
			sec[s.Title] = s.Body
			if s.Body == "" {
				t.Errorf("%s: section %q is empty", id, s.Title)
			}
		}
		if strings.Join(got, "|") != strings.Join(ThreatSections, "|") {
			t.Errorf("%s sections:\n got %v\nwant %v", id, got, ThreatSections)
		}
		// 公開日: 概要の先頭の行。id の年月と合う
		pub := ThreatPublished(id)
		if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(pub) {
			t.Errorf("%s: 概要 must start with `- 公開日: YYYY-MM-DD` (got %q)", id, pub)
		}
		// 出典: 箇条書きの 1 行ごとに https の URL と日付
		n := 0
		for _, line := range strings.Split(sec["出典"], "\n") {
			if !strings.HasPrefix(line, "- ") {
				continue
			}
			n++
			if !threatURLRe.MatchString(line) || !threatDateRe.MatchString(line) {
				t.Errorf("%s: source line needs an https URL and a date (YYYY-MM-DD): %q", id, line)
			}
		}
		if n == 0 {
			t.Errorf("%s: 出典 has no source", id)
		}
		if !strings.Contains(sec["出典"], pub) {
			t.Errorf("%s: 公開日 %s is not the date of any source", id, pub)
		}
		// 段階の表
		stages := ThreatStages(id)
		if len(stages) < 3 {
			t.Errorf("%s: stage table has %d rows", id, len(stages))
		}
		visible := 0
		for _, st := range stages {
			if st.Stage == "" || st.Record == "" || st.Output == "" {
				t.Errorf("%s: stage row has an empty cell: %+v", id, st)
			}
			if !basis[st.Basis] {
				t.Errorf("%s: stage %q: 出典の書き方 %q must be one of %v", id, st.Stage, st.Basis, ThreatBasis)
			}
			for _, c := range st.Checks {
				if !known[c] {
					t.Errorf("%s: stage %q names check %q, which does not exist", id, st.Stage, c)
				}
			}
			if len(st.Checks) > 0 {
				visible++
				if !regexp.MustCompile(`critical|high|medium|low|info`).MatchString(st.Output) {
					t.Errorf("%s: stage %q must state the severity", id, st.Stage)
				}
			}
		}
		if visible == 0 || visible == len(stages) {
			t.Errorf("%s: the table must have both visible and invisible stages (visible %d of %d)", id, visible, len(stages))
		}
		// 表の外の `…` に、実在しないチェックの名前を「今あるもの」として書かない: 予定のチェックは「予定している改善」にだけ書く
		if !strings.Contains(sec["予定している改善"], "予定") && !strings.HasPrefix(sec["予定している改善"], "無し") {
			t.Errorf("%s: 予定している改善 must say 予定 or start with 無し", id)
		}
		if !strings.Contains(sec["arata では見えないもの"], "- ") {
			t.Errorf("%s: arata では見えないもの must be a list", id)
		}
		// 顧客の情報を書かない・攻撃の基盤の値 (IP) を書き写さない
		for _, a := range acct.FindAllString(body, -1) {
			if a != "123456789012" && a != "111122223333" {
				t.Errorf("%s: account id %s", id, a)
			}
		}
		if m := email.FindString(body); m != "" {
			t.Errorf("%s: email address %q", id, m)
		}
		if m := ip.FindString(body); m != "" {
			t.Errorf("%s: IP address %q (do not copy indicators; link to the source)", id, m)
		}
		if n := strings.Count(body, "\n"); n > 120 {
			t.Errorf("%s: %d lines (keep it within about 120)", id, n)
		}
	}
	if _, ok := Threat("nope"); ok {
		t.Fatal("unknown id must not have a threat")
	}
	if _, err := Lookup("threats nope"); err == nil || !strings.Contains(err.Error(), ids[0]) {
		t.Fatalf("unknown threat must list the ids: %v", err)
	}
}

// TestPlaybookThreats は、どのチェックの playbook も「関連する事例」に、事例か「対応する公開の事例はまだ無い」を書いていて、
// 事例の表と食い違わないことを固定する。新しいチェックを足す PR は、どちらかを書かないと落ちる。
func TestPlaybookThreats(t *testing.T) {
	want := map[string][]string{}
	for _, id := range ThreatNames() {
		for _, c := range ThreatChecks(id) {
			want[c] = append(want[c], id)
		}
	}
	for _, name := range PlaybookNames() {
		sort.Strings(want[name])
		tp, _ := Lookup("playbook " + name)
		body := ""
		for _, s := range tp.Parse().Sections {
			if s.Title == "関連する事例" {
				body = s.Body
			}
		}
		var got []string
		for _, m := range threatRefRe.FindAllStringSubmatch(body, -1) {
			got = append(got, m[1])
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want[name], ",") {
			t.Errorf("%s: 関連する事例 names %v, but the threat tables name this check in %v", name, got, want[name])
		}
		if none := strings.Contains(body, NoThreatYet); none != (len(want[name]) == 0) {
			t.Errorf("%s: 関連する事例 must say %q exactly when no threat names the check", name, NoThreatYet)
		}
		if !strings.Contains(body, "`arata help ai threats`") {
			t.Errorf("%s: 関連する事例 must point to `arata help ai threats`", name)
		}
	}
}

// TestThreatIndex は対応表 (arata help ai threats) が事例とチェックをすべて持ち、人向けの docs/threats.md の表と一字一句同じことを固定する。
func TestThreatIndex(t *testing.T) {
	tp, err := Lookup("threats")
	if err != nil {
		t.Fatal(err)
	}
	idx := tp.Markdown()
	human, err := os.ReadFile("../threats.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ThreatNames() {
		if !strings.Contains(idx, "`arata help ai threats "+id+"`") {
			t.Errorf("index lacks %s", id)
		}
		if !strings.Contains(string(human), "(ai/threats/"+id+".md)") {
			t.Errorf("docs/threats.md must link to ai/threats/%s.md", id)
		}
	}
	for _, name := range PlaybookNames() {
		if !strings.Contains(idx, "\n| "+name+" | ") {
			t.Errorf("index lacks check %s", name)
		}
	}
	if !strings.Contains(idx, NoThreatYet) {
		t.Errorf("index must say %q for checks without a threat", NoThreatYet)
	}
	for _, table := range []string{ThreatTable(), ThreatCheckTable()} {
		if !strings.Contains(idx, table) {
			t.Errorf("index lacks the generated table")
		}
		if !strings.Contains(string(human), table) {
			t.Errorf("docs/threats.md must contain this table verbatim (generated from docs/ai/threats/*.md):\n%s", table)
		}
	}
	// 入口から案内している
	for _, sub := range []string{"", "playbook"} {
		tp, _ := Lookup(sub)
		if !strings.Contains(tp.Markdown(), "arata help ai threats") {
			t.Errorf("help %s must point to arata help ai threats", tp.Name)
		}
	}
	for _, f := range []string{"../../README.md", "../../CLAUDE.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "docs/threats.md") {
			t.Errorf("%s must point to docs/threats.md", f)
		}
	}
}
