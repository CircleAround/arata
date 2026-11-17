package record

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ECS Exec (ExecuteCommand) の記録から取り出す値の形 (ADR 0072)。
// 決定 (ADR 0037・0041): ログ由来の値なので、Key と見出しに使う名前は決まった形だけを受け入れる。collector が取り出すときと、
// チェックがストアから読み戻したときの両方で同じ関数を通す。

// ecsNameRe はクラスター名・コンテナ名・タスク ID の形 (ECS の名前は英数字・`-`・`_`、255 文字まで。`.` は余裕として許す)。
var ecsNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}\z`)

// ecsSessionIDRe は ECS Exec のセッション ID の形。
// 決定: SSM のセッション ID は利用者名 (SSO ならメールアドレス) から作られることがあるので、ECS Exec の接頭辞のものだけを残す。
var ecsSessionIDRe = regexp.MustCompile(`^ecs-execute-command-[A-Za-z0-9]{1,80}\z`)

// MaxECSCommandRunes は残すコマンドの長さの上限 (rune)。
const MaxECSCommandRunes = 256

// ECSName は s がクラスター名・コンテナ名・タスク ID の形なら s を返す。
func ECSName(s string) (string, bool) {
	if ecsNameRe.MatchString(s) {
		return s, true
	}
	return "", false
}

// ECSNameOf は名前か ARN (`arn:aws:ecs:<リージョン>:<アカウント>:cluster/<名前>`・`task/<クラスター>/<ID>`) から、最後の部分を ECSName の形で返す。
func ECSNameOf(v string) (string, bool) {
	if rest, ok := strings.CutPrefix(v, "arn:"); ok {
		parts := strings.SplitN(rest, ":", 5)
		if len(parts) != 5 || parts[1] != "ecs" {
			return "", false
		}
		res := parts[4]
		i := strings.LastIndexByte(res, '/')
		if i < 0 {
			return "", false
		}
		v = res[i+1:]
	}
	return ECSName(v)
}

// ECSSessionID は s が ECS Exec のセッション ID の形なら s を返す。
func ECSSessionID(s string) (string, bool) {
	if ecsSessionIDRe.MatchString(s) {
		return s, true
	}
	return "", false
}

// CleanECSCommand はコマンドを 1 行にし (制御文字は空白に、書式の文字 (Unicode の Cf) は除く)、前後の空白を除いて、
// MaxECSCommandRunes で切る。truncated は切ったか。
func CleanECSCommand(s string) (out string, truncated bool) {
	var b strings.Builder
	n := 0
	// 壊れた UTF-8 は空白 1 つにする (正しく符号化された U+FFFD はそのまま。整えた結果を整え直しても変わらないように)
	for _, r := range strings.ToValidUTF8(s, " ") {
		switch {
		case unicode.Is(unicode.Cc, r):
			r = ' '
		case unicode.Is(unicode.Cf, r):
			continue
		}
		if n == MaxECSCommandRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		n++
	}
	out = strings.TrimSpace(b.String())
	return out, truncated
}

// CleanECSCommandOK は CleanECSCommand の結果の形か (空でなく、上限以下、制御文字・書式の文字を含まない、前後に空白が無い)。
func CleanECSCommandOK(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > MaxECSCommandRunes || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
