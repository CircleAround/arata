package cloudtrail

import "regexp"

// deniedAssumeRe は、断られた sts:AssumeRole の errorMessage の決まった形。末尾は「ロールの ARN」(名前は IAM が許す文字で 128 文字まで)。
// 後ろに理由 (because ... / with an explicit deny ...) が続く文・改行を含む文は合わない (`$` は末尾の改行にも合うので \z)。
var deniedAssumeRe = regexp.MustCompile(`^User: (\S+) is not authorized to perform: sts:AssumeRole on resource: (arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128})\z`)

// maxDeniedMessage は読む errorMessage の長さの上限 (呼び出し元の ARN と、ロールの ARN の上限を足しても届かない長さ)。
const maxDeniedMessage = 2048

// deniedAssumeTarget は、断られた AssumeRole の errorMessage から引き受け先のロールの ARN を取る。
//
// 決定 (設計書 6 章): 断られた AssumeRole の記録は requestParameters が null で resources も無く、引き受け先は errorMessage の文にしか無い。
// errorMessage は呼び出した側の入力 (要求したロールの ARN) を含む信用しない値なので (ADR 0037・0041)、
// 文全体が決まった形で、文の呼び出し元が userIdentity.arn (caller) と 1 字も違わないときだけ取る。形に合わなければ何も取らない。
// 文そのものは残さない (呼び出し元のセッション名 = 利用者名が入る)。
func deniedAssumeTarget(msg, caller string) (string, bool) {
	if caller == "" || len(msg) > maxDeniedMessage {
		return "", false
	}
	m := deniedAssumeRe.FindStringSubmatch(msg)
	if m == nil || m[1] != caller {
		return "", false
	}
	return m[2], true
}
