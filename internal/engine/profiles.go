package engine

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
)

// ProfileCheck は profile で実際に走るチェック 1 つ。
type ProfileCheck struct {
	Name    string `json:"name"`
	Cadence string `json:"cadence"`
	Mode    string `json:"mode"`
	// Via は設定での書き方。explicit (名前を書いた) か default-<cadence> (省略記法から展開した)。
	Via string `json:"via"`
}

// ProfileView は profile で実際に効いているチェックとパラメータ (`arata profiles`)。
type ProfileView struct {
	Name       string         `json:"name"`
	Window     string         `json:"window"`
	MaxCatchup string         `json:"max_catchup"`
	Checks     []ProfileCheck `json:"checks"`
	// Params はこの profile のチェックのパラメータ (overrides を重ねた値) と由来 (overrides / checks / default)。
	Params []config.Param `json:"params"`
}

// ProfilesView は全 profile の表示と、どの profile にも入っていないチェック。
type ProfilesView struct {
	Profiles []ProfileView `json:"profiles"`
	Unused   []string      `json:"unused_checks"`
}

// Profiles は設定で実際に効いているプロファイルの中身を返す。省略記法 (default-*) は展開済み。
func Profiles(cfg *config.Config, reg *checks.Registry) ProfilesView {
	out := ProfilesView{Profiles: []ProfileView{}, Unused: UnusedChecks(cfg, reg)}
	if out.Unused == nil {
		out.Unused = []string{}
	}
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		explicit := map[string]bool{}
		for _, n := range p.Checks {
			explicit[n] = true
		}
		v := ProfileView{Name: name, Window: p.WindowRaw, MaxCatchup: p.MaxCatchupRaw, Checks: []ProfileCheck{}, Params: []config.Param{}}
		if v.MaxCatchup == "" {
			v.MaxCatchup = "7d"
		}
		in := map[string]bool{}
		for _, n := range p.ExpandChecks(reg.Defaults()) {
			pc := ProfileCheck{Name: n, Cadence: "?", Mode: "?", Via: "explicit"}
			if c, ok := reg.Get(n); ok {
				pc.Cadence, pc.Mode = string(c.Cadence()), string(c.Mode())
				if !explicit[n] {
					pc.Via = "default-" + pc.Cadence
				}
			}
			v.Checks = append(v.Checks, pc)
			in[n] = true
		}
		for _, prm := range cfg.ParamsFor(name) {
			if in[prm.Check] {
				v.Params = append(v.Params, prm)
			}
		}
		out.Profiles = append(out.Profiles, v)
	}
	return out
}

// originLabel は人向けの由来の表記。
var originLabel = map[string]string{config.OriginOverride: "overrides", config.OriginConfig: "checks:", config.OriginDefault: "既定値"}

// WriteTable は人向けの表を書く。
func (v ProfilesView) WriteTable(w io.Writer) error {
	for i, p := range v.Profiles {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "profile %s (window %s, max_catchup %s)\n", p.Name, p.Window, p.MaxCatchup)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  CHECK\tCADENCE\tMODE\tVIA")
		for _, c := range p.Checks {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", c.Name, c.Cadence, c.Mode, c.Via)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if len(p.Params) == 0 {
			continue
		}
		// tabwriter は文字数で揃えるので、全角の「既定値」がずれる。表示幅で揃える
		pw, ow := len("PARAM"), len("ORIGIN")
		for _, prm := range p.Params {
			pw, ow = max(pw, len(prm.Check)+1+len(prm.Key)), max(ow, displayWidth(originLabel[prm.Origin]))
		}
		fmt.Fprintf(w, "  %s  %s  VALUE\n", pad("PARAM", pw), pad("ORIGIN", ow))
		for _, prm := range p.Params {
			fmt.Fprintf(w, "  %s  %s  %s\n", pad(prm.Check+"."+prm.Key, pw), pad(originLabel[prm.Origin], ow), formatValue(prm.Value))
		}
	}
	if len(v.Unused) > 0 {
		fmt.Fprintf(w, "\n%s: どのプロファイルにも入っていない (実行されない): %s\n", CodeCheckUnused, strings.Join(v.Unused, ", "))
	}
	return nil
}

// displayWidth は端末での表示幅 (全角を 2 と数える)。
func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x1100 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func pad(s string, w int) string {
	return s + strings.Repeat(" ", max(0, w-displayWidth(s)))
}

func formatValue(v any) string {
	switch x := v.(type) {
	case []string:
		return "[" + strings.Join(x, ", ") + "]"
	case []int:
		s := make([]string, len(x))
		for i, n := range x {
			s[i] = fmt.Sprint(n)
		}
		return "[" + strings.Join(s, ", ") + "]"
	}
	return fmt.Sprint(v)
}
