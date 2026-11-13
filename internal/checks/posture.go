package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// posture の finding の Key。
const (
	PostureKeyTrailLogging    = "cloudtrail_logging"
	PostureKeyTrailValidation = "cloudtrail_log_validation"
	PostureKeyGuardDuty       = "guardduty_enabled" // + "|<region>"
	PostureKeyRootMFA         = "root_mfa"
	PostureKeyS3PublicAccess  = "s3_public_access_block"
	PostureKeyPasswordPolicy  = "password_policy"
	PostureKeyALBWAF          = "alb_waf" // + "|<region>|<ALB の名前>"
)

// Posture はアカウントの姿勢を項目ごとに 1 finding で報告する (週次、state)。問題が直れば resolved。
//   - cloudtrail_logging: 記録中のマルチリージョン証跡が無い (high)
//   - cloudtrail_log_validation: 記録中の証跡にログファイル検証が無効のものがある (medium)
//   - guardduty_enabled|<region>: GuardDuty が有効でない (high)
//   - root_mfa: ルートユーザーに MFA が無い (high)
//   - s3_public_access_block: アカウント単位の S3 Public Access Block が未設定、または 4 項目のどれかが無効 (high)
//   - password_policy: IAM パスワードポリシーが未設定、または最小文字数が min_password_length (既定 14) 未満 (medium)
//   - alb_waf|<region>|<ALB>: インターネット向けの ALB に WAFv2 の WebACL が付いていない (medium。ADR 0048)
//
// 決定 (ADR 0015): 権限不足などで取れなかった項目 (unknown) は、前回の finding (open / acked / snoozed) をそのまま観測し直して維持する
// (resolved にしない)。権限を外されたことを「直った」と誤認しないため。
type Posture struct {
	Config config.Posture
}

func (Posture) Name() string         { return "posture" }
func (Posture) Cadence() Cadence     { return Weekly }
func (Posture) Mode() Mode           { return ModeState }
func (Posture) Needs() []record.Kind { return []record.Kind{record.KindPostureItem} }

func (c Posture) Evaluate(ctx context.Context, q store.Query, _ collect.Window, _ *allowlist.List) ([]Observation, error) {
	items, err := q.Snapshot(ctx, record.KindPostureItem)
	if err != nil {
		return nil, err
	}
	prev, err := q.Findings(ctx, c.Name(), []string{store.FindingOpen, store.FindingAcked, store.FindingSnoozed})
	if err != nil {
		return nil, err
	}
	prevByKey := map[string]store.Finding{}
	for _, f := range prev {
		prevByKey[f.Key] = f
	}
	var obs []Observation
	ng := func(key string, sev Severity, summary string, data map[string]any, parts ...any) {
		obs = append(obs, Observation{Check: c.Name(), Key: key, Severity: sev, Summary: summary, Fingerprint: fingerprint(sev, nil, parts...), Data: data})
	}
	for _, it := range items {
		if account.IsUnknown(it) {
			if region, ok := strings.CutPrefix(it.Key, account.PostureALBWAF+"|"); ok {
				// ALB ごとの finding なので、そのリージョンの前回の finding を全部維持する
				for _, f := range prev {
					if strings.HasPrefix(f.Key, PostureKeyALBWAF+"|"+region+"|") {
						obs = append(obs, Observation{Check: c.Name(), Key: f.Key, Severity: Severity(f.Severity), Summary: f.Summary, Fingerprint: f.Fingerprint, Data: f.Data})
					}
				}
				continue
			}
			for _, key := range postureKeys(it.Key) {
				if f, ok := prevByKey[key]; ok {
					obs = append(obs, Observation{Check: c.Name(), Key: key, Severity: Severity(f.Severity), Summary: f.Summary, Fingerprint: f.Fingerprint, Data: f.Data})
				}
			}
			continue
		}
		switch {
		case it.Key == account.PostureCloudTrail:
			logging := strs(it.Data["logging"])
			if !it.Bool("multi_region_logging") {
				ng(PostureKeyTrailLogging, High, fmt.Sprintf("記録中のマルチリージョン CloudTrail 証跡が無い (証跡 %d、記録中 %d)", int(it.Number("trails")), len(logging)),
					map[string]any{"trails": int(it.Number("trails")), "logging": logging}, len(logging))
			}
			if bad := strs(it.Data["without_validation"]); len(bad) > 0 {
				ng(PostureKeyTrailValidation, Medium, "CloudTrail のログファイル検証が無効な証跡がある: "+strings.Join(bad, ", "),
					map[string]any{"trails": bad}, strings.Join(bad, ","))
			}
		case strings.HasPrefix(it.Key, account.PostureGuardDuty+"|"):
			region := strings.TrimPrefix(it.Key, account.PostureGuardDuty+"|")
			if !it.Bool("enabled") {
				ng(PostureKeyGuardDuty+"|"+region, High, "GuardDuty が有効でない ("+region+")", map[string]any{"region": region})
			}
		case it.Key == account.PostureRootMFA:
			if !it.Bool("mfa_enabled") {
				ng(PostureKeyRootMFA, High, "ルートユーザーに MFA が無い", map[string]any{"root_access_keys": it.Bool("root_access_keys")})
			}
		case it.Key == account.PostureS3PublicAccess:
			var off []string
			for _, k := range []string{"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"} {
				if !it.Bool(k) {
					off = append(off, k)
				}
			}
			switch {
			case !it.Bool("configured"):
				ng(PostureKeyS3PublicAccess, High, "S3 のアカウント単位の Public Access Block が未設定", map[string]any{"configured": false}, "unset")
			case len(off) > 0:
				ng(PostureKeyS3PublicAccess, High, "S3 のアカウント単位の Public Access Block に無効な項目がある: "+strings.Join(off, ", "),
					map[string]any{"configured": true, "disabled": off}, strings.Join(off, ","))
			}
		case strings.HasPrefix(it.Key, account.PostureALBWAF+"|"):
			region := strings.TrimPrefix(it.Key, account.PostureALBWAF+"|")
			for _, alb := range albsWithoutWAF(it.Data["without_waf"]) {
				ng(PostureKeyALBWAF+"|"+region+"|"+alb.name, Medium, "インターネット向けの ALB に WAF (WAFv2 の WebACL) が付いていない: "+alb.name+" ("+region+")",
					map[string]any{"region": region, "name": alb.name, "arn": alb.arn})
			}
		case it.Key == account.PosturePasswordPolicy:
			min := int(it.Number("minimum_length"))
			switch {
			case !it.Bool("configured"):
				ng(PostureKeyPasswordPolicy, Medium, "IAM パスワードポリシーが未設定", map[string]any{"configured": false}, "unset")
			case min < c.Config.MinPasswordLength:
				ng(PostureKeyPasswordPolicy, Medium, fmt.Sprintf("IAM パスワードポリシーの最小文字数が %d (推奨 %d 以上)", min, c.Config.MinPasswordLength),
					map[string]any{"configured": true, "minimum_length": min, "min_password_length": c.Config.MinPasswordLength}, min)
			}
		}
	}
	return obs, nil
}

// postureKeys は posture_item の Key から出し得る finding の Key。
func postureKeys(item string) []string {
	switch {
	case item == account.PostureCloudTrail:
		return []string{PostureKeyTrailLogging, PostureKeyTrailValidation}
	case strings.HasPrefix(item, account.PostureGuardDuty+"|"):
		return []string{PostureKeyGuardDuty + "|" + strings.TrimPrefix(item, account.PostureGuardDuty+"|")}
	}
	return []string{item} // root_mfa / s3_public_access_block / password_policy は同じ名前
}

type albRef struct{ name, arn string }

// albsWithoutWAF は posture_item の without_waf (名前と ARN の一覧) を読む。名前が空か、key の区切り (|) を含むものは捨てる
// (ALB の名前は英数字とハイフンだけ。key を壊さないための守り)。
func albsWithoutWAF(v any) []albRef {
	var list []any
	switch x := v.(type) {
	case []any:
		list = x
	case []map[string]any:
		for _, m := range x {
			list = append(list, m)
		}
	}
	var out []albRef
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		arn, _ := m["arn"].(string)
		if name == "" || strings.Contains(name, "|") {
			continue
		}
		out = append(out, albRef{name, arn})
	}
	return out
}

// strs は []string か JSON から戻した []any を []string にする。
func strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
