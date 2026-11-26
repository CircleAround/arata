package cloudtrail

import (
	"math"

	"github.com/CircleAround/arata/internal/record"
)

// maxSigninDuration は max_signin_session_duration に残す秒の上限 (これより大きい値は形が違うとみなす。十分に大きい 100 年)。
const maxSigninDuration = 100 * 365 * 24 * 3600

// signinDetail は aws login のログインのセッションの値を data に足す (ADR 0092 の 1 節・3 節)。
//
// 決定:
//   - signin_session: CreateOAuth2Token は additionalEventData.signInSessionArn (無ければ sessionContext.signInSessionArn)、
//     ほかの記録は sessionContext.signInSessionArn。形 (record.ValidSigninSession) に合うときだけ。項目を足すだけなので互換 (ADR 0054)
//   - CreateOAuth2Token (signin.amazonaws.com) にだけ: grant_type (authorization_code・refresh_token・other)、signin_client (cross-device・same-device・other)、
//     signin_success・signin_extended ("true" / "false" の文字列のときだけ)、cli_version (User-Agent の先頭が AWS CLI の版の形のときだけ。判定には使わない)。
//     grant_type・signin_client は、キーが無ければ入れない
//   - UpdateLoginProfile (iam.amazonaws.com) の maxSigninSessionDuration: 0 以上の整数 (秒) なら max_signin_session_duration。
//     キーがあれば (形に依らず) signin_duration_changed: true (iam_changes が報告する。形が違っても変更の試みは見落とさない)
func signinDetail(r rawEvent, d map[string]any) {
	ctx, _ := r.UserIdentity.SessionContext.SignInSessionArn.(string)
	if r.EventSource == "iam.amazonaws.com" && r.EventName == "UpdateLoginProfile" {
		if v, ok := r.RequestParameters["maxSigninSessionDuration"]; ok {
			d["signin_duration_changed"] = true
			if n, ok := v.(float64); ok && n >= 0 && n <= maxSigninDuration && n == math.Trunc(n) {
				d["max_signin_session_duration"] = int(n)
			}
		}
	}
	if r.EventSource != "signin.amazonaws.com" || r.EventName != "CreateOAuth2Token" {
		if record.ValidSigninSession(ctx) {
			d["signin_session"] = ctx
		}
		return
	}
	ad := r.AdditionalEventData
	if s, _ := ad["signInSessionArn"].(string); record.ValidSigninSession(s) {
		d["signin_session"] = s
	} else if record.ValidSigninSession(ctx) {
		d["signin_session"] = ctx
	}
	if v, ok := ad["grant_type"]; ok {
		d["grant_type"] = record.SigninGrant(v)
	}
	if v, ok := r.RequestParameters["client_id"]; ok {
		d["signin_client"] = record.SigninClient(v)
	}
	if v, ok := record.SigninFlag(ad["success"]); ok {
		d["signin_success"] = v
	}
	if v, ok := record.SigninFlag(ad["SignInSessionExtended"]); ok {
		d["signin_extended"] = v
	}
	if v, ok := record.CLIVersion(r.UserAgent); ok {
		d["cli_version"] = v
	}
}
