package scaffold

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
)

// 差分の種類。
const (
	DiffUnusedCheck    = "unused_check"    // どのプロファイルにも入っていないチェック
	DiffUnknownCheck   = "unknown_check"   // プロファイルに書かれているが、この版に無いチェック
	DiffParamChanged   = "param_changed"   // checks: に書いた値がこの版の既定値と違う
	DiffUnknownKey     = "unknown_key"     // arata が知らないキー (綴りの誤り、廃止されたキー)
	DiffMissingProfile = "missing_profile" // 雛形にあって設定に無いプロファイル
	DiffMissingKey     = "missing_key"     // 雛形が必ず書くのに設定に無いキー (audit_account。ADR 0045)
)

// DiffItem は差分 1 件。
// config init --diff --format json のスキーマの名前と版 (ADR 0054)。名前は `arata schema <名前>` の名前。
// 決定 (ADR 0054): 出力の最上位は DiffItem の配列のまま、版 1 として固定する (review と同じ理由)。
const (
	DiffSchema        = "config-diff"
	DiffSchemaVersion = 1
)

type DiffItem struct {
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Current  string `json:"current,omitempty"`
	Template string `json:"template,omitempty"`
	Detail   string `json:"detail"`
}

// rawConfig は差分を取るために緩く読む設定 (未知のキーがあっても読める)。
type rawConfig struct {
	Profiles map[string]struct {
		Checks []string `yaml:"checks"`
	} `yaml:"profiles"`
	Checks       map[string]map[string]any `yaml:"checks"`
	AuditAccount yaml.Node                 `yaml:"audit_account"`
}

// Diff は現在の設定 (YAML) とこの版の雛形の差分を返す。設定が Load で失敗する状態 (未知のキーなど) でも動く。
// 決定: checks: に書いていないパラメータは実行時にこの版の既定値が効くので差分にしない。書いた値が既定値と違うものだけを出す
// (監査対象ごとに意図して変えた値か、古い版の既定値を写したままかは人が判断する)。overrides は意図した上書きなので比べない。
func Diff(current []byte, reg *checks.Registry) ([]DiffItem, error) {
	var cur rawConfig
	if err := yaml.Unmarshal(current, &cur); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	out := []DiffItem{}

	used := map[string][]string{}
	pnames := make([]string, 0, len(cur.Profiles))
	for n := range cur.Profiles {
		pnames = append(pnames, n)
	}
	sort.Strings(pnames)
	for _, pn := range pnames {
		p := config.Profile{Checks: cur.Profiles[pn].Checks}
		for _, c := range p.ExpandChecks(reg.Defaults()) {
			if _, ok := reg.Get(c); !ok {
				out = append(out, DiffItem{Kind: DiffUnknownCheck, Path: "profiles." + pn + ".checks", Current: c, Detail: "この版に無いチェック (run / evaluate は CONFIG_INVALID で止まる)"})
				continue
			}
			used[c] = append(used[c], pn)
		}
	}
	for _, n := range reg.Names() {
		if len(used[n]) > 0 {
			continue
		}
		var in []string
		for _, p := range Profiles {
			for _, c := range ProfileChecks(reg, p) {
				if c == n {
					in = append(in, p.Name)
				}
			}
		}
		out = append(out, DiffItem{Kind: DiffUnusedCheck, Path: n, Template: strings.Join(in, ", "), Detail: "どのプロファイルにも入っていない (実行されない)。" + Descriptions[n]})
	}
	for _, p := range Profiles {
		if _, ok := cur.Profiles[p.Name]; !ok && len(ProfileChecks(reg, p)) > 0 {
			out = append(out, DiffItem{Kind: DiffMissingProfile, Path: "profiles." + p.Name, Template: strings.Join(ProfileChecks(reg, p), ", "), Detail: p.Comment})
		}
	}
	for _, p := range config.DefaultChecks().Params() {
		v, ok := cur.Checks[p.Check][p.Key]
		if !ok {
			continue
		}
		if c, t := flow(v), flow(p.Value); c != t {
			out = append(out, DiffItem{Kind: DiffParamChanged, Path: "checks." + p.Check + "." + p.Key, Current: c, Template: t, Detail: "この版の既定値と違う"})
		}
	}
	// 決定 (ADR 0045): audit_account は雛形が必ず書く (config init が選ばせる)。この項目より前の版で作った設定には無いので、
	// 無いことを差分に出して選ばせる。run は止めない。値の誤りはここでは見ない (Load / config check が止める)
	if cur.AuditAccount.Kind == 0 || cur.AuditAccount.Tag == "!!null" {
		out = append(out, DiffItem{Kind: DiffMissingKey, Path: "audit_account", Template: `"<12 桁のアカウント ID>" か none`,
			Detail: "監査する側のアカウントを選んでいない。別のアカウントのロールが読み取り専用ロールを引き受けて監査するなら audit_account: \"<そのアカウントの ID>\" を書き、" +
				"allowlist の principals に account: \"<同じ ID>\" を足す (無いと unknown_assume_role が監査そのものを high で報告する)。" +
				"同じアカウントの中・手元から直接なら audit_account: none を書く"})
	}
	unknown, err := config.UnknownKeys(current)
	if err != nil {
		return nil, err
	}
	for _, k := range unknown {
		out = append(out, DiffItem{Kind: DiffUnknownKey, Path: k, Detail: "arata が知らないキー (綴りの誤りか、この版で無くなったキー。設定の読み込みは失敗する)"})
	}
	return out, nil
}

// WriteDiff は人向けに差分を書く。
func WriteDiff(w io.Writer, items []DiffItem) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "この版の雛形との差分はありません。")
		return err
	}
	fmt.Fprintf(w, "この版の雛形との差分: %d 件\n", len(items))
	for _, it := range items {
		line := fmt.Sprintf("  [%s] %s", it.Kind, it.Path)
		switch {
		case it.Current != "" && it.Template != "":
			line += fmt.Sprintf(": 設定 %s / 雛形 %s", it.Current, it.Template)
		case it.Current != "":
			line += ": " + it.Current
		case it.Template != "":
			line += fmt.Sprintf(" (雛形では %s)", it.Template)
		}
		if _, err := fmt.Fprintf(w, "%s — %s\n", line, it.Detail); err != nil {
			return err
		}
	}
	return nil
}
