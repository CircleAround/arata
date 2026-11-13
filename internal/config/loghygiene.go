package config

import (
	"fmt"
	"strings"
)

// log_hygiene が数える種類 (checks.log_hygiene.kinds に書く名前。ADR 0050)。
const (
	HygieneSecretAWSAccessKey = "secret_aws_access_key" // #nosec G101 -- 種類の名前で、秘密の値ではない
	HygieneSecretSlackToken   = "secret_slack_token"    // #nosec G101 -- 種類の名前で、秘密の値ではない
	HygieneSecretPrivateKey   = "secret_private_key"    // #nosec G101 -- 種類の名前で、秘密の値ではない
	HygienePresignedLongTerm  = "presigned_url_long_term_key"
	HygienePresignedURL       = "presigned_url"
	HygieneUnfilteredParam    = "unfiltered_param"
	HygieneDebugSQL           = "debug_sql"
)

// hygieneKinds は種類の決まった順 (クエリの条件と finding の並び)。
var hygieneKinds = []string{HygieneSecretAWSAccessKey, HygieneSecretSlackToken, HygieneSecretPrivateKey, HygienePresignedLongTerm, HygienePresignedURL,
	HygieneUnfilteredParam, HygieneDebugSQL}

// LogHygieneKinds は log_hygiene の種類の名前 (決まった順)。
func LogHygieneKinds() []string { return append([]string(nil), hygieneKinds...) }

// 項目名の上限 (ADR 0050)。
const (
	MaxHygieneParamFields   = 32
	MaxHygieneParamFieldLen = 64
)

// LogHygiene は log_hygiene の設定 (ADR 0050)。
//
// 決定 (ADR 0014): 既定は 3 つとも空。見るロググループ・種類・項目名は利用者が書いたものだけで、空なら何も読まない。
// 3 つとも収集の条件 (スナップショットは全プロファイルで共有) なので、overrides では変えられない (CollectionParams)。
type LogHygiene struct {
	// Sources は見る cloudwatch-logs のソースの id。
	Sources []string `yaml:"sources"`
	// Kinds は数える種類 (LogHygieneKinds の名前)。
	Kinds []string `yaml:"kinds"`
	// ParamFields は unfiltered_param が見る送信項目の名前 (1〜64 字の英数字・`_`・`-`、32 個まで)。
	ParamFields []string `yaml:"param_fields"`
}

// Covers はソース id を log_hygiene が読むか (sources にあり、kinds が空でない)。
func (h LogHygiene) Covers(id string) bool {
	return len(h.Kinds) > 0 && contains(h.Sources, id)
}

// HasKind は種類 kind を数えるか。
func (h LogHygiene) HasKind(kind string) bool { return contains(h.Kinds, kind) }

// ValidHygieneParamField は項目名が形の規則 (1〜64 字の英数字・`_`・`-`) どおりか。
// 決定 (ADR 0050): 項目名は Insights の正規表現に入る。形をここで絞り、クエリの組み立てでも文字どおりにする (二重の守り)。
func ValidHygieneParamField(s string) bool {
	if len(s) < 1 || len(s) > MaxHygieneParamFieldLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validate は種類と項目名を確かめる (ソースの id は Config.validateLogHygiene)。
//
// 決定: `unfiltered_param` を書いて param_fields が空、またはその逆は CONFIG_INVALID にする。前者は何も数えないのに「0 件」に見え、
// 後者は書いた項目名が見られていないのに見ているように読める。
func (h LogHygiene) validate() error {
	if d := duplicate(h.Kinds); d != "" {
		return fmt.Errorf("kinds: duplicate %q", d)
	}
	for _, k := range h.Kinds {
		if !contains(hygieneKinds, k) {
			return fmt.Errorf("kinds: unknown kind %q (want %s)", k, strings.Join(hygieneKinds, ", "))
		}
	}
	if len(h.ParamFields) > MaxHygieneParamFields {
		return fmt.Errorf("param_fields: %d names; at most %d", len(h.ParamFields), MaxHygieneParamFields)
	}
	for _, f := range h.ParamFields {
		if !ValidHygieneParamField(f) {
			return fmt.Errorf("param_fields: %q must be 1-%d characters of letters, digits, _ and -", f, MaxHygieneParamFieldLen)
		}
	}
	if d := duplicate(h.ParamFields); d != "" {
		return fmt.Errorf("param_fields: duplicate %q", d)
	}
	switch has := h.HasKind(HygieneUnfilteredParam); {
	case has && len(h.ParamFields) == 0:
		return fmt.Errorf("kinds has %s but param_fields is empty (it would count nothing)", HygieneUnfilteredParam)
	case !has && len(h.ParamFields) > 0:
		return fmt.Errorf("param_fields is set but kinds does not have %s (the names would not be looked at)", HygieneUnfilteredParam)
	}
	return nil
}

// validateLogHygiene は log_hygiene.sources が cloudwatch-logs のソースの id かを確かめる。形式は問わない
// (text のほか、既存の形式のソースも書ける。ADR 0050)。
func (c *Config) validateLogHygiene() error {
	h := c.Checks.LogHygiene
	if d := duplicate(h.Sources); d != "" {
		return fmt.Errorf("sources: duplicate %q", d)
	}
	byID := map[string]Source{}
	for _, s := range c.Sources {
		byID[s.ID] = s
	}
	for _, id := range h.Sources {
		if s, ok := byID[id]; !ok || s.Kind != KindCloudWatchLogs {
			return fmt.Errorf("sources: %q must be the id of a %s source", id, KindCloudWatchLogs)
		}
	}
	return nil
}

// duplicate は l の中で 2 度出る最初の値 (無ければ "")。
func duplicate(l []string) string {
	seen := map[string]bool{}
	for _, s := range l {
		if seen[s] {
			return s
		}
		seen[s] = true
	}
	return ""
}
