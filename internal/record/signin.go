package record

import "regexp"

// aws login のログインのセッション (ADR 0092)。
//
// 決定 (ADR 0092 の 1 節・ADR 0037): ログ由来の値は、決まった形に合うときだけ使う。形に合わない値は入れない。

// signinSessionRe はログインのセッションの ARN の形 (arn:aws:signin:<リージョン>:<12 桁>:session/<UUID>)。`$` は末尾の改行にも合うので \z。
var signinSessionRe = regexp.MustCompile(`^arn:aws:signin:[a-z0-9-]{1,32}:[0-9]{12}:session/([0-9a-f-]{36})\z`)

// SigninSessionUUID はログインのセッションの ARN の UUID の部分を返す。形に合わなければ false。
func SigninSessionUUID(arn string) (string, bool) {
	m := signinSessionRe.FindStringSubmatch(arn)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ValidSigninSession はログインのセッションの ARN の形か。
func ValidSigninSession(arn string) bool {
	_, ok := SigninSessionUUID(arn)
	return ok
}

// 出し直しの種類 (CreateOAuth2Token の additionalEventData.grant_type) と、出し直した道具 (requestParameters.client_id) の値。
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	SigninOther            = "other"
	SigninCrossDevice      = "cross-device"
	SigninSameDevice       = "same-device"
)

// SigninGrant は grant_type の値を決まった値にする (知らない値・文字列でない値は other)。
func SigninGrant(v any) string {
	switch s, _ := v.(string); s {
	case GrantAuthorizationCode, GrantRefreshToken:
		return s
	}
	return SigninOther
}

// SigninClient は client_id の値を決まった値にする (知らない値・文字列でない値は other)。
func SigninClient(v any) string {
	switch s, _ := v.(string); s {
	case "arn:aws:signin:::devtools/cross-device":
		return SigninCrossDevice
	case "arn:aws:signin:::devtools/same-device":
		return SigninSameDevice
	}
	return SigninOther
}

// SigninFlag は "true" / "false" の文字列を真偽にする。ほかの値 (文字列でない true を含む) は false を返す (ok も false)。
func SigninFlag(v any) (value, ok bool) {
	switch s, _ := v.(string); s {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// cliVersionRe は AWS CLI の User-Agent の先頭の版 (aws-cli/<数字>.<数字>.<数字>)。
var cliVersionRe = regexp.MustCompile(`^aws-cli/[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[ ]|\z)`)

// CLIVersion は User-Agent の先頭が AWS CLI の版の形なら、その部分 (aws-cli/2.31.4) を返す。偽れる値なので判定には使わない (ADR 0092 の 2 節)。
func CLIVersion(ua string) (string, bool) {
	m := cliVersionRe.FindString(ua)
	if m == "" {
		return "", false
	}
	if m[len(m)-1] == ' ' {
		m = m[:len(m)-1]
	}
	return m, true
}
