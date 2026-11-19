package record

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
)

// sessionKeyRe は一時的な認証情報 (STS が発行したもの) のアクセスキー ID の形。
var sessionKeyRe = regexp.MustCompile(`^ASIA[A-Z0-9]{16}$`)

// SessionKeyHash は一時的な認証情報のアクセスキー ID (ASIA + 英大文字・数字 16 桁) の SHA-256 の先頭 32 桁 (16 進)。形に合わなければ空と false。
//
// 決定 (ADR 0076 の 4 節): bulk: exempt の読み取りを、ECS が AssumeRole で発行した認証情報と突き合わせるのに使う。突き合わせには一致だけが要るので、
// キーそのものは残さない (ストアや report に認証情報の形の文字列を持ち込まず、秘密の検査の誤検知とも混ざらないため)。
func SessionKeyHash(key string) (string, bool) {
	if !sessionKeyRe.MatchString(key) {
		return "", false
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16]), true
}
