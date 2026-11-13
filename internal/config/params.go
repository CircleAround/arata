package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// チェックのパラメータの由来 (`arata profiles` が表示する)。
const (
	OriginDefault  = "default"   // チェックの既定値 (設定に書いていない)
	OriginConfig   = "checks"    // 全体の checks: に書いた値
	OriginOverride = "overrides" // profiles.<name>.overrides に書いた値
)

// CollectionParams は収集 (Logs Insights の集計クエリ、CloudTrail の注目イベント) の条件に使うパラメータ。
// 決定: metrics は (date, source, metric, key) で全プロファイル共有・置き換え保存なので、プロファイルごとに集計条件を変えると
// プロファイルが交互に別条件の値で上書きし平常帯が壊れる。overrides では変えられず、全体の checks: でだけ変える。
// access_denied.error_codes も同じ (events に残す拒否の条件。保存はプロファイルに依らない)。
// waf_review の top_paths / rate_path_groups / trusted_cidrs も wafv2 の日次集計の条件 (ADR 0023)。
var CollectionParams = map[string]bool{"paths": true, "methods": true, "failure_statuses": true, "statuses": true, "exclude_paths": true, "error_codes": true,
	"top_paths": true, "rate_path_groups": true, "trusted_cidrs": true,
	// endpoint_abuse の画面・時間幅・連鎖も日次集計の条件 (ADR 0030)
	"endpoints": true, "window": true, "follow_ups": true,
	// cost_anomaly の GetAnomalies の範囲と下限も問い合わせの条件 (スナップショットは全プロファイル共有。ADR 0032)
	"lookback_days": true, "min_impact_usd": true,
	// log_hygiene の見るソース・種類・項目名も問い合わせの条件 (スナップショットは全プロファイル共有。ADR 0050)
	"sources": true, "kinds": true, "param_fields": true}

// Param はチェックのパラメータ 1 つ (checks.<Check>.<Key>)。
type Param struct {
	Check  string `json:"check"`
	Key    string `json:"key"`
	Value  any    `json:"value"`
	Origin string `json:"origin,omitempty"`
}

// paramField は Checks の葉のフィールド 1 つ。
type paramField struct {
	check, key string
	v          reflect.Value
}

// paramFields は Checks の葉のフィールドを yaml のキーで列挙する (宣言順。inline の Baseline は展開する)。
func paramFields(c *Checks) []paramField {
	var out []paramField
	cv := reflect.ValueOf(c).Elem()
	for i := 0; i < cv.NumField(); i++ {
		check := yamlName(cv.Type().Field(i))
		var walk func(v reflect.Value)
		walk = func(v reflect.Value) {
			for j := 0; j < v.NumField(); j++ {
				f := v.Type().Field(j)
				if strings.Contains(f.Tag.Get("yaml"), "inline") {
					walk(v.Field(j))
					continue
				}
				out = append(out, paramField{check: check, key: yamlName(f), v: v.Field(j)})
			}
		}
		walk(cv.Field(i))
	}
	return out
}

func yamlName(f reflect.StructField) string {
	return strings.Split(f.Tag.Get("yaml"), ",")[0]
}

// ParamChecks はパラメータを持つチェック名 (checks: のキー、宣言順)。
func ParamChecks() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range paramFields(&Checks{}) {
		if !seen[f.check] {
			seen[f.check] = true
			out = append(out, f.check)
		}
	}
	return out
}

// Params は c のパラメータを宣言順に返す (Origin は空)。
func (c Checks) Params() []Param {
	var out []Param
	for _, f := range paramFields(&c) {
		out = append(out, Param{Check: f.check, Key: f.key, Value: f.v.Interface()})
	}
	return out
}

// overlay は o の非ゼロの葉を c に上書きする。
func (c *Checks) overlay(o Checks) {
	dst, src := paramFields(c), paramFields(&o)
	for i := range dst {
		if !src[i].v.IsZero() {
			dst[i].v.Set(src[i].v)
		}
	}
}

// validateOverrides は overrides に集計条件のパラメータが書かれていないかを確かめる。
func validateOverrides(o Checks) error {
	var bad []string
	for _, f := range paramFields(&o) {
		if CollectionParams[f.key] && !f.v.IsZero() {
			bad = append(bad, f.check+"."+f.key)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("overrides cannot change collection conditions (%s): they shape the shared daily metrics; set them in checks: instead", strings.Join(bad, ", "))
	}
	return nil
}

// ChecksFor はプロファイルで効くチェックのパラメータ (全体の checks: に overrides を重ねたもの) を返す。未定義のプロファイルなら全体の値。
func (c *Config) ChecksFor(profile string) Checks {
	out := c.Checks
	if p, ok := c.Profiles[profile]; ok {
		out.overlay(p.Overrides)
	}
	return out
}

// ParamsFor はプロファイルで効くパラメータとその由来を返す。
func (c *Config) ParamsFor(profile string) []Param {
	eff := c.ChecksFor(profile)
	p := c.Profiles[profile]
	raw, ov := paramFields(&c.checksRaw), paramFields(&p.Overrides)
	out := eff.Params()
	for i := range out {
		switch {
		case !ov[i].v.IsZero():
			out[i].Origin = OriginOverride
		case !raw[i].v.IsZero():
			out[i].Origin = OriginConfig
		default:
			out[i].Origin = OriginDefault
		}
	}
	return out
}

// ProfileNames はプロファイル名 (ソート済み)。
func (c *Config) ProfileNames() []string {
	out := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
