package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// DefenseEvasion は監査・検知の仕組み (CloudTrail・GuardDuty・Access Analyzer・ログ・Config・Security Hub・WAF のログ) を
// 止める・弱める操作を報告する (ADR 0026)。
//
// 決定:
//   - 成功したもの (errorCode なし) だけ。失敗は access_denied が扱う
//   - 「弱める」かは要求の内容 (collector が requestParameters から取り出した値) だけで判断する。CloudTrail には前の値が残らないので、
//     弱めたか分からない変更 (UpdateTrail の SNS の変更、データイベントの追加など) は報告しない
//   - allowlist で `tags: [deploy]` の承認済みの主体なら 1 段下げる (critical → high、high → medium)。info にはしない (IaC でも監査の無効化は人が見るべき)
//   - 監査対象のロググループ (arata の cloudwatch-logs のソース) への削除・保持期間の短縮は critical
type DefenseEvasion struct {
	Config config.DefenseEvasion
	// AuditLogGroups は arata が監査に使うロググループ (config.Config.AuditLogGroups)。
	AuditLogGroups []string
	// LogBaselineDays はログから作る平常帯の日数 (login_bruteforce / probe_paths の baseline_days の大きい方)。
	// 監査対象のロググループの保持期間がこれより短いと、init で平常帯を作り直せない。
	LogBaselineDays int
}

func (DefenseEvasion) Name() string         { return "defense_evasion" }
func (DefenseEvasion) Cadence() Cadence     { return Daily }
func (DefenseEvasion) Mode() Mode           { return ModeEvent }
func (DefenseEvasion) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

const (
	srcCloudTrail     = "cloudtrail.amazonaws.com"
	srcGuardDuty      = "guardduty.amazonaws.com"
	srcAccessAnalyzer = "access-analyzer.amazonaws.com"
	srcLogs           = "logs.amazonaws.com"
	srcEC2            = "ec2.amazonaws.com"
	srcConfig         = "config.amazonaws.com"
	srcSecurityHub    = "securityhub.amazonaws.com"
	srcWAFv2          = "wafv2.amazonaws.com"
	srcS3             = "s3.amazonaws.com"
	srcRDS            = "rds.amazonaws.com"
	srcLambda         = "lambda.amazonaws.com"
)

var defenseEvasionAPIs = concatAPIs(
	apisOf(srcCloudTrail, "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "PutInsightSelectors"),
	apisOf(srcGuardDuty, "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount", "DisassociateFromAdministratorAccount",
		"CreateFilter", "UpdateFilter", "DeletePublishingDestination"),
	apisOf(srcAccessAnalyzer, "DeleteAnalyzer", "CreateArchiveRule"),
	apisOf(srcLogs, "DeleteLogGroup", "DeleteLogStream", "PutRetentionPolicy", "DeleteSubscriptionFilter"),
	apisOf(srcEC2, "DeleteFlowLogs"),
	apisOf(srcConfig, "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteServiceLinkedConfigurationRecorder", "DeleteDeliveryChannel"),
	apisOf(srcSecurityHub, "DisableSecurityHub", "DisableSecurityHubV2", "BatchDisableStandards"),
	apisOf(srcWAFv2, "DeleteLoggingConfiguration", "PutLoggingConfiguration"),
	apisOf(srcS3, "DeleteBucketPolicy", "PutBucketLifecycle"),
)

// DefenseEvasionAPIs は defense_evasion が見る操作 (CreateTrail は証跡の宛先を覚えるためにだけ読む)。
func DefenseEvasionAPIs() []API {
	return append(append([]API(nil), defenseEvasionAPIs...), API{Source: srcCloudTrail, Name: "CreateTrail"})
}

func concatAPIs(ls ...[]API) []API {
	var out []API
	for _, l := range ls {
		out = append(out, l...)
	}
	return out
}

func (c DefenseEvasion) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{EventSources: apiSources(defenseEvasionAPIs), WriteOnly: true})
	if err != nil {
		return nil, err
	}
	trailBuckets, err := c.trailBuckets(ctx, q, w)
	if err != nil {
		return nil, err
	}
	audit := map[string]bool{}
	for _, g := range c.AuditLogGroups {
		audit[g] = true
	}
	aggs := map[string]*eventAgg{}
	sev := map[string]Severity{}
	reasons := map[string]string{}
	for _, e := range evs {
		if e.ErrorCode != "" {
			continue
		}
		api, ok := findAPI(defenseEvasionAPIs, e)
		if !ok {
			continue
		}
		j := c.judge(api, e, audit, trailBuckets)
		if j.sev == "" {
			continue
		}
		label := apiLabel(api)
		k := label + "|" + e.PrincipalARN + "|" + j.target
		a, ok := aggs[k]
		if !ok {
			a = newEventAgg()
			a.extra["api"] = label
			a.extra["principal"] = e.PrincipalARN
			a.extra["principal_kind"] = string(e.PrincipalKind)
			a.extra["target"] = j.target
			s := j.sev
			if knownDeploy(al, e.PrincipalARN, w.To) {
				s = lowerOne(s)
				a.extra["known_deploy_principal"] = true
			}
			sev[k] = s
			aggs[k] = a
		}
		for dk, dv := range j.data {
			a.extra[dk] = dv
		}
		if j.reason != "" {
			reasons[k] = j.reason
		}
		a.add(e.Time, e.Name, e.IP)
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		target := a.extra["target"].(string)
		shown := target
		if shown == "" {
			shown = "(アカウント)"
		}
		summary := fmt.Sprintf("監査・検知の無効化 %s: %s → %s (%d 件)", a.extra["api"], record.PrincipalLabel(a.extra["principal"].(string), record.PrincipalKind(a.extra["principal_kind"].(string))), shown, a.count)
		if r := reasons[k]; r != "" {
			summary += "。" + r
			a.extra["reason"] = r
		}
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: sev[k], Summary: summary, Data: a.data(),
			Fingerprint: fingerprint(sev[k], a.ips, target, reasons[k])}
	}
	return sortedObs(obs), nil
}

type judgement struct {
	sev    Severity
	target string
	reason string
	data   map[string]any
}

// judge は 1 件の操作の重大度・対象・理由を決める。sev が空なら報告しない。
func (c DefenseEvasion) judge(api API, e record.TrailEvent, audit, trailBuckets map[string]bool) judgement {
	d := e.Data
	j := judgement{data: map[string]any{}}
	switch api.Source {
	case srcCloudTrail:
		j.target = dataStr(d, "name")
		if j.target == "" {
			j.target = dataStr(d, "trail")
		}
		switch api.Name {
		case "StopLogging", "DeleteTrail":
			j.sev = Critical
		case "UpdateTrail":
			var changes []string
			if v, ok := dataBool(d, "multi_region"); ok && !v {
				changes = append(changes, "multi_region=false")
			}
			if v, ok := dataBool(d, "log_validation"); ok && !v {
				changes = append(changes, "log_validation=false")
			}
			if b := dataStr(d, "s3_bucket"); b != "" {
				changes = append(changes, "s3_bucket="+b)
			}
			if len(changes) > 0 {
				j.sev, j.data["changes"] = High, changes
			}
		case "PutEventSelectors":
			if r := dataStrings(d, "selectors_reduced"); len(r) > 0 {
				j.sev, j.data["changes"] = High, r
			}
		case "PutInsightSelectors":
			if v, _ := dataBool(d, "insights_cleared"); v {
				j.sev, j.data["changes"] = High, []string{"insights_cleared"}
			}
		}
	case srcGuardDuty:
		j.target = dataStr(d, "detector_id")
		switch api.Name {
		case "UpdateDetector":
			var changes []string
			if v, ok := dataBool(d, "enable"); ok && !v {
				changes = append(changes, "enable=false")
			}
			for _, f := range dataStrings(d, "features_disabled") {
				changes = append(changes, f+"=DISABLED")
			}
			if len(changes) > 0 {
				j.sev, j.data["changes"] = High, changes
			}
		case "CreateFilter", "UpdateFilter":
			j.target = dataStr(d, "name")
			if dataStr(d, "filter_action") == "ARCHIVE" {
				j.sev, j.reason = High, "findings を自動でアーカイブするフィルタ"
			}
		default:
			j.sev = High
		}
	case srcAccessAnalyzer:
		j.target = dataStr(d, "analyzer")
		if r := dataStr(d, "rule"); r != "" {
			j.target += "/" + r
		}
		j.sev = High
	case srcLogs:
		g := dataStr(d, "log_group")
		j.target = g
		base := High
		if audit[g] {
			base = Critical
			j.data["audit_log_group"] = true
		}
		switch api.Name {
		case "DeleteLogStream":
			if !audit[g] {
				return judgement{}
			}
			j.sev = Critical
		case "PutRetentionPolicy":
			days, ok := dataInt(d, "retention_days")
			if !ok || days >= c.Config.MinLogRetentionDays {
				return judgement{}
			}
			j.sev = base
			j.data["retention_days"] = days
			j.data["min_log_retention_days"] = c.Config.MinLogRetentionDays
			j.reason = fmt.Sprintf("保持期間 %d 日 (下限 %d 日)", days, c.Config.MinLogRetentionDays)
			if audit[g] && c.LogBaselineDays > 0 && days < c.LogBaselineDays {
				j.data["shorter_than_baseline_days"] = true
				j.reason += fmt.Sprintf("。arata の平常帯の日数 (%d 日) より短い", c.LogBaselineDays)
			}
		default:
			j.sev = base
		}
		if audit[g] && j.reason == "" {
			j.reason = "arata の監査対象のロググループ"
		}
	case srcEC2:
		j.target = strings.Join(dataStrings(d, "flow_log_ids"), ",")
		j.sev = High
	case srcConfig:
		j.target = dataStr(d, "recorder")
		if j.target == "" {
			j.target = dataStr(d, "delivery_channel")
		}
		j.sev = High
	case srcSecurityHub:
		j.target = strings.Join(dataStrings(d, "standards"), ",")
		j.sev = High
	case srcWAFv2:
		j.target = dataStr(d, "resource_arn")
		switch api.Name {
		case "DeleteLoggingConfiguration":
			j.sev = High
		case "PutLoggingConfiguration":
			if v, _ := dataBool(d, "logging_filter"); v {
				j.sev, j.reason = High, "ログのフィルタ (記録を減らせる) を設定"
			}
		}
	case srcS3:
		b := dataStr(d, "bucket")
		j.target = b
		if !trailBuckets[b] {
			return judgement{}
		}
		j.sev = High
		j.reason = "CloudTrail の証跡の宛先バケット"
		if days, ok := dataInt(d, "lifecycle_expiration_days"); ok {
			j.data["lifecycle_expiration_days"] = days
			j.reason += fmt.Sprintf("。最短 %d 日で消える", days)
		}
	}
	if ch, ok := j.data["changes"].([]string); ok && j.reason == "" {
		j.reason = "変更: " + strings.Join(ch, ", ")
	}
	return j
}

// trailBuckets は証跡の宛先のバケット: 設定の trail_buckets と、保存済みの CreateTrail / UpdateTrail の s3BucketName (成功したもの)。
func (c DefenseEvasion) trailBuckets(ctx context.Context, q store.Query, w collect.Window) (map[string]bool, error) {
	out := map[string]bool{}
	for _, b := range c.Config.TrailBuckets {
		out[b] = true
	}
	evs, err := q.Events(ctx, time.Time{}, w.To, store.EventFilter{EventSources: []string{srcCloudTrail}, Names: []string{"CreateTrail", "UpdateTrail"}})
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		if b := dataStr(e.Data, "s3_bucket"); b != "" && e.ErrorCode == "" {
			out[b] = true
		}
	}
	return out, nil
}
