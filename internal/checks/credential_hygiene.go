package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// CredentialHygiene は IAM 認証情報レポートから衛生上の問題を報告する (週次、state)。
//   - `unused_key|<user>|<n>`: 有効なアクセスキーが unused_days (既定 90) 日超使われていない (使われていなければ作成・ローテーションから) — medium
//   - `no_mfa|<user>`: コンソールにログインできる (パスワード有効) のに MFA が無い — medium
//   - `root_access_key|<n>`: ルートユーザーにアクセスキーがある — high
//
// 問題が無くなれば resolved (state)。経過日数は Data に残し Fingerprint に入れない (毎週変わるため)。
type CredentialHygiene struct {
	Config config.CredentialHygiene
}

func (CredentialHygiene) Name() string         { return "credential_hygiene" }
func (CredentialHygiene) Cadence() Cadence     { return Weekly }
func (CredentialHygiene) Mode() Mode           { return ModeState }
func (CredentialHygiene) Needs() []record.Kind { return []record.Kind{record.KindCredentialReport} }

func (c CredentialHygiene) Evaluate(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, error) {
	items, err := q.Snapshot(ctx, record.KindCredentialReport)
	if err != nil {
		return nil, err
	}
	var obs []Observation
	for _, it := range items {
		user, arn := it.Key, it.String("arn")
		base := map[string]any{"user": user, "arn": arn, "report_generated_at": it.String("report_generated_at")}
		keys, _ := it.Data["access_keys"].([]any)
		for _, k := range keys {
			km, _ := k.(map[string]any)
			if active, _ := km["active"].(bool); !active {
				continue
			}
			n, _ := km["key"].(string)
			if user == account.RootUser {
				obs = append(obs, Observation{Check: c.Name(), Key: "root_access_key|" + n, Severity: High,
					Summary: fmt.Sprintf("ルートユーザーに有効なアクセスキー (key %s) がある", n), Fingerprint: fingerprint(High, nil, "root", n),
					Data: with(base, "key", n, "last_used", km["last_used"], "last_rotated", km["last_rotated"])})
				continue
			}
			last, _ := km["last_used"].(string)
			basis := "最終使用"
			if last == "" {
				last, _ = km["last_rotated"].(string)
				basis = "使われておらず、作成・ローテーション"
			}
			t, err := time.Parse(time.RFC3339, last)
			if err != nil {
				continue
			}
			days := int(w.To.Sub(t).Hours() / 24)
			if days <= c.Config.UnusedDays {
				continue
			}
			obs = append(obs, Observation{Check: c.Name(), Key: "unused_key|" + user + "|" + n, Severity: Medium,
				Summary:     fmt.Sprintf("アクセスキーが %d 日使われていない: %s の key %s (%s から %d 日、閾値 %d 日)", days, user, n, basis, days, c.Config.UnusedDays),
				Fingerprint: fingerprint(Medium, nil, user, n),
				Data:        with(base, "key", n, "last_used", km["last_used"], "last_rotated", km["last_rotated"], "days_unused", days, "unused_days", c.Config.UnusedDays)})
		}
		if user != account.RootUser && it.Bool("password_enabled") && !it.Bool("mfa_active") {
			obs = append(obs, Observation{Check: c.Name(), Key: "no_mfa|" + user, Severity: Medium,
				Summary: fmt.Sprintf("コンソールにログインできるユーザーに MFA が無い: %s", user), Fingerprint: fingerprint(Medium, nil, user),
				Data: with(base, "password_last_used", it.String("password_last_used"))})
		}
	}
	return obs, nil
}

// with は m の写しに kv を足す。
func with(m map[string]any, kv ...any) map[string]any {
	out := make(map[string]any, len(m)+len(kv)/2)
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}
