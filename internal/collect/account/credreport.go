package account

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// RootUser は認証情報レポートのルートユーザーの行の user 列。
const RootUser = "<root_account>"

// credentialReportPolls はレポート生成を待つ回数 (2 秒間隔)。
const credentialReportPolls = 15

// CredentialReport は IAM 認証情報レポートを取り、ユーザーごとに 1 項目を出す collector (iam_credential_report)。
//
// 決定: GenerateCredentialReport は書き込み系 (レポートの生成のみ) で、読み取り専用ロールでは拒否されることが多い。
// 拒否されても GetCredentialReport で既存のレポート (生成から 4 時間以内) が取れればそれを使い、生成時刻を Data の report_generated_at に残す。
// 既存のレポートも無ければ ACCESS_DENIED (action は iam:GenerateCredentialReport)。
type CredentialReport struct{ base }

var _ collect.Collector = (*CredentialReport)(nil)

// NewCredentialReport は collector を作る。IAM はグローバルなので clients の先頭だけを使う。
func NewCredentialReport(id string, clients ...Clients) *CredentialReport {
	return &CredentialReport{newBase(id, clients)}
}

func (c *CredentialReport) Yields() []record.Kind { return []record.Kind{record.KindCredentialReport} }

func (c *CredentialReport) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	api := c.clients[0].IAM
	denied := false
	if _, err := api.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		if ce := c.fail(ActionGenerateCredentialReport, err); ce.Code == collect.CodeAccessDenied {
			denied = true
			c.Logger.Warn("credential report generation was denied; using the existing report if any", "code", collect.CodeAccessDenied, "source", c.id, "action", ActionGenerateCredentialReport)
		} else {
			return ce
		}
	}
	var out *iam.GetCredentialReportOutput
	for i := 0; ; i++ {
		var err error
		out, err = api.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			break
		}
		code := collect.APICode(err)
		waiting := code == "ReportInProgress" || (code == "ReportNotPresent" && !denied)
		if waiting && i < credentialReportPolls {
			if err := c.Sleep(ctx, 2*time.Second); err != nil {
				return err
			}
			continue
		}
		if denied && (code == "ReportNotPresent" || code == "ReportExpired") {
			return &collect.Error{Code: collect.CodeAccessDenied, Source: c.id, Action: ActionGenerateCredentialReport,
				Err: fmt.Errorf("no credential report generated within 4 hours, and generating one was denied: %w", err)}
		}
		return c.fail(ActionGetCredentialReport, err)
	}
	rows, err := ParseCredentialReport(out.Content)
	if err != nil {
		return c.fail("", err)
	}
	generated := ""
	if out.GeneratedTime != nil {
		generated = out.GeneratedTime.UTC().Format(time.RFC3339)
	}
	at := snapshotTime(w)
	for _, r := range rows {
		r["report_generated_at"] = generated
		user, _ := r["user"].(string)
		if err := sink.Emit(ctx, item(record.KindCredentialReport, at, c.id, user, r)); err != nil {
			return err
		}
	}
	return nil
}

// Probe は GetCredentialReport だけを試す (Generate は書き込み系なので doctor では呼ばない)。レポートがまだ無いのは権限の問題ではない。
func (c *CredentialReport) Probe(ctx context.Context) []collect.ProbeResult {
	_, err := c.clients[0].IAM.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if code := collect.APICode(err); code == "ReportNotPresent" || code == "ReportExpired" || code == "ReportInProgress" {
		err = nil
	}
	return []collect.ProbeResult{
		probe(ActionGetCredentialReport, err),
		{Action: ActionGenerateCredentialReport, Detail: "書き込み系 (レポートの生成のみ) なので doctor では試さない。拒否されても 4 時間以内に生成済みのレポートがあれば使う"},
	}
}

// ParseCredentialReport は認証情報レポートの CSV を行ごとの Data にする。
// 日時は RFC3339 (UTC) の文字列、無い値 (N/A / no_information / not_supported) は ""。真偽値は bool。
func ParseCredentialReport(content []byte) ([]map[string]any, error) {
	recs, err := csv.NewReader(bytes.NewReader(content)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("credential report: %w", err)
	}
	if len(recs) == 0 {
		return nil, nil
	}
	header := recs[0]
	var out []map[string]any
	for _, rec := range recs[1:] {
		raw := map[string]string{}
		for i, h := range header {
			if i < len(rec) {
				raw[h] = rec[i]
			}
		}
		d := map[string]any{
			"user":               raw["user"],
			"arn":                raw["arn"],
			"password_enabled":   raw["password_enabled"] == "true",
			"password_last_used": reportTime(raw["password_last_used"]),
			"mfa_active":         raw["mfa_active"] == "true",
		}
		var keys []any
		for _, n := range []string{"1", "2"} {
			p := "access_key_" + n + "_"
			if _, ok := raw[p+"active"]; !ok {
				continue
			}
			keys = append(keys, map[string]any{
				"key":          n,
				"active":       raw[p+"active"] == "true",
				"last_rotated": reportTime(raw[p+"last_rotated"]),
				"last_used":    reportTime(raw[p+"last_used_date"]),
			})
		}
		d["access_keys"] = keys
		out = append(out, d)
	}
	return out, nil
}

func reportTime(s string) string {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
