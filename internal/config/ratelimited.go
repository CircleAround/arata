package config

import (
	"fmt"
	"strings"
)

// RateLimitedIP は rate_limited_ip (429 の集まった IP。ADR 0094 の 2 節) の設定。
// statuses・paths・user_sources・ip_users_store_* は集計の条件 (日の値の形を決め、全プロファイルで共有する) なので、overrides では変えられない (CollectionParams)。
// min_count・suggest_min_users は判定の閾値 (仮の値。実データで見直す) で、overrides で変えられる。
//
// 決定 (ADR 0094 の 2 節の実装):
//   - 429 は http_access の http_hits のクエリ (sign_in_failures・probe_hits と同じ 1 本) の 3 つ目の選択肢として数える (rate_limited。ADR 0031)
//   - 同じ IP からログインできた利用者の数 (ip_users) は、user_sources に書いたソースだけで数える (書かなければ数えず、材料に添えない。ADR 0014)
//   - shared_sources (ADR 0094 の 1 節) はまだ無い。入れるときは shared_min_count をここに足し、下限の切り替えはチェックの側 (checks.RateLimitedIP.minCount) で行う
type RateLimitedIP struct {
	// Statuses は数えるステータス (アプリの回数の制限が返すもの)。
	Statuses []int `yaml:"statuses"`
	// Paths は数えるパスの接頭辞。空なら全パス。
	Paths []string `yaml:"paths"`
	// UserSources は ip_users を数える cloudwatch-logs のソース (request_lines で request.user_id と ip のあるもの)。空なら数えない。
	UserSources []string `yaml:"user_sources"`
	// IPUsersStoreMin はストアに残す ip_users の日の値の下限。IPUsersStoreTop は日ごとに残す IP の数 (値の大きい順)。
	IPUsersStoreMin int `yaml:"ip_users_store_min"`
	IPUsersStoreTop int `yaml:"ip_users_store_top"`
	// MinCount は報告する 1 日の件数の下限。
	MinCount float64 `yaml:"min_count"`
	// SuggestMinUsers は、ip_users がこれ以上なら suggest_shared、未満なら few_users を付ける人数。
	SuggestMinUsers float64 `yaml:"suggest_min_users"`
}

// DefaultRateLimitedStatuses は rate_limited_ip.statuses の既定。
var DefaultRateLimitedStatuses = []int{429}

// CountsUsers はソース id で ip_users を数えるか。
func (r RateLimitedIP) CountsUsers(id string) bool { return containsString(r.UserSources, id) }

func (r *RateLimitedIP) applyDefaults() {
	if r.Statuses == nil {
		r.Statuses = DefaultRateLimitedStatuses
	}
	setInt(&r.IPUsersStoreMin, 3)
	setInt(&r.IPUsersStoreTop, 200)
	setFloat(&r.MinCount, 20)
	setFloat(&r.SuggestMinUsers, 10)
}

func (r RateLimitedIP) validate() error {
	if err := validateStatuses(r.Statuses, func(s int) bool { return s >= 400 && s <= 599 }); err != nil {
		return fmt.Errorf("statuses: %w (400-599)", err)
	}
	for _, p := range r.Paths {
		if len(p) == 0 || p[0] != '/' {
			return fmt.Errorf("paths: %q must start with /", p)
		}
	}
	if r.MinCount < 1 {
		return fmt.Errorf("min_count >= 1")
	}
	if r.SuggestMinUsers < 1 {
		return fmt.Errorf("suggest_min_users >= 1")
	}
	if r.IPUsersStoreMin < 1 || r.IPUsersStoreTop < 1 || r.IPUsersStoreTop > MaxUserStoreTop {
		return fmt.Errorf("ip_users_store_min >= 1, 1 <= ip_users_store_top <= %d", MaxUserStoreTop)
	}
	return nil
}

// validateRateLimitedSources は user_sources が、ユーザー ID と ip を読む request_lines の cloudwatch-logs のソースかを確かめる。
func (c *Config) validateRateLimitedSources() error {
	byID := map[string]Source{}
	for _, s := range c.Sources {
		byID[s.ID] = s
	}
	seen := map[string]bool{}
	for _, id := range c.Checks.RateLimitedIP.UserSources {
		if seen[id] {
			return fmt.Errorf("rate_limited_ip: user_sources: %q is listed twice", id)
		}
		seen[id] = true
		s, ok := byID[id]
		if !ok {
			return fmt.Errorf("rate_limited_ip: user_sources: source %q is not defined", id)
		}
		if s.Kind != KindCloudWatchLogs || s.UserIDFrom() == UserIDFromNone {
			return fmt.Errorf("rate_limited_ip: user_sources: source %q must be a cloudwatch-logs request_lines source with request.user_id (from: %s)",
				id, strings.Join([]string{UserIDFromAppLine, UserIDFromDebugSQL}, " or "))
		}
		if !s.extractsField("ip") {
			return fmt.Errorf("rate_limited_ip: user_sources: source %q does not extract the client IP: add (?P<ip>...) to the first line of its request.lines", id)
		}
	}
	return nil
}
