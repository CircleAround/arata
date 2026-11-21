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
	DiffMissingParam   = "missing_param"   // 雛形が書くのに、設定のそのチェックの節に無いパラメータ (この版の既定値が効いている)
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
		Checks      []string `yaml:"checks"`
		Silenced    *bool    `yaml:"silenced"`
		MinSeverity *string  `yaml:"min_severity"`
	} `yaml:"profiles"`
	Checks       map[string]map[string]any `yaml:"checks"`
	AuditAccount yaml.Node                 `yaml:"audit_account"`
	IPList       map[string]any            `yaml:"ip_list"`
}

// Diff は現在の設定 (YAML) とこの版の雛形の差分を返す。設定が Load で失敗する状態 (未知のキーなど) でも動く。
// 決定: checks: に書いた値が既定値と違うものを param_changed で出す (監査対象ごとに意図して変えた値か、古い版の既定値を写したままかは人が判断する)。
// overrides は意図した上書きなので比べない。
// 決定 (設計書 2 章。以前の「書いていないパラメータは差分にしない」を置き換え): 設定にそのチェックの節があるのに、雛形が書くパラメータが無ければ
// missing_param で出す (版を上げて増えた既定値が、見えないまま効くのを防ぐ。ADR 0014)。出すのはどれかのプロファイルで動くチェックだけ。
// 節ごと書いていないチェックは全部を既定値に任せているので出さない (手書きの短い設定で全パラメータが並ぶのを避ける)。
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
	// 決定 (ADR 0068): 雛形が silenced: true を書くプロファイルで、設定に silenced が無ければ足し方を出す (書いた値は比べない)
	for _, p := range Profiles {
		if cp, ok := cur.Profiles[p.Name]; ok && p.Silenced && cp.Silenced == nil {
			out = append(out, DiffItem{Kind: DiffMissingKey, Path: "profiles." + p.Name + ".silenced", Template: "true",
				Detail: "雛形は silenced: true を書く。" + silencedComment + "。出したくなければ silenced: false を書く"})
		}
	}
	// 決定 (ADR 0082): 雛形が min_severity を書くプロファイルで、設定に min_severity が無ければ足す行を出す (書いた値は比べない)
	for _, p := range Profiles {
		if cp, ok := cur.Profiles[p.Name]; ok && p.MinSeverity != "" && cp.MinSeverity == nil {
			out = append(out, DiffItem{Kind: DiffMissingKey, Path: "profiles." + p.Name + ".min_severity", Template: p.MinSeverity,
				Detail: "雛形は min_severity: " + p.MinSeverity + " を書く。" + minSeverityComment + "。書かなければ下限なし (medium 以下もこの run で記録・報告し、daily では本日報告済みに回る)"})
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
	for _, p := range config.DefaultChecks().Params() {
		sec, ok := cur.Checks[p.Check]
		if !ok || len(used[p.Check]) == 0 {
			continue
		}
		if _, ok := sec[p.Key]; ok {
			continue
		}
		t := flow(p.Value)
		detail := "設定のこのチェックの節に無い (雛形の値が、この版の既定値として黙って効いている)。値を確かめて書く"
		if c := paramComments[p.Check+"."+p.Key]; c != "" {
			detail += "。" + c
		}
		out = append(out, DiffItem{Kind: DiffMissingParam, Path: "checks." + p.Check + "." + p.Key, Template: t, Detail: detail})
	}
	// 決定 (ADR 0045): audit_account は雛形が必ず書く (config init が選ばせる)。この項目より前の版で作った設定には無いので、
	// 無いことを差分に出して選ばせる。run は止めない。値の誤りはここでは見ない (Load / config check が止める)
	if cur.AuditAccount.Kind == 0 || cur.AuditAccount.Tag == "!!null" {
		out = append(out, DiffItem{Kind: DiffMissingKey, Path: "audit_account", Template: `"<12 桁のアカウント ID>" か none`,
			Detail: "監査する側のアカウントを選んでいない。別のアカウントのロールが読み取り専用ロールを引き受けて監査するなら audit_account: \"<そのアカウントの ID>\" を書き、" +
				"allowlist の principals に account: \"<同じ ID>\" を足す (無いと unknown_assume_role が監査そのものを high で報告する)。" +
				"同じアカウントの中・手元から直接なら audit_account: none を書く"})
	}
	out = append(out, diffIPList(current, cur.IPList)...)
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

// diffIPList は ip_list: の差分 (ADR 0069)。無ければ missing_key (一覧を作らない)、書いた値が既定値と違えば param_changed。
// 書いていない項目は既定値が効くので差分にしない (checks: と同じ)。
func diffIPList(current []byte, l map[string]any) []DiffItem {
	var top map[string]any
	if err := yaml.Unmarshal(current, &top); err != nil {
		return nil
	}
	if _, ok := top["ip_list"]; !ok {
		return []DiffItem{{Kind: DiffMissingKey, Path: "ip_list", Template: "active: " + config.DefaultIPListActive + ", reasons: waf_block / probe / sign_in_failure",
			Detail: "怪しい IP の一覧を作らない (ADR 0069)。作るなら雛形の ip_list: を写す (書いた理由だけが効く)"}}
	}
	var out []DiffItem
	for _, p := range config.DefaultIPListParams() {
		var v any = l
		for _, k := range strings.Split(p.Path, ".") {
			m, ok := v.(map[string]any)
			if !ok {
				v = nil
				break
			}
			v = m[k]
		}
		if v == nil {
			continue
		}
		if c, t := flow(v), flow(p.Value); c != t {
			out = append(out, DiffItem{Kind: DiffParamChanged, Path: "ip_list." + p.Path, Current: c, Template: t, Detail: "この版の既定値と違う"})
		}
	}
	return out
}
