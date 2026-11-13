package notify

import (
	"regexp"
	"strings"

	"github.com/CircleAround/arata/internal/report/schema"
)

// 主体がアカウントしか分からない finding (CloudTrail に呼び出し元のアカウント ID しか残らない記録。ロール側から見たクロスアカウントの AssumeRole など) の扱い。
// arata はその主体を `arn:aws:iam::NNN:root` と書く (Key と data。既存の ack・既知リストとの一致のため変えない)。
// これはアカウントそのものを指す ARN で、ルートユーザーが使われたことを表さないが、LLM が「NNN の root から引き受けられた」と要約したことがある。
//
// 決定 (aratam 設計書 2 章、ADR 0037 の「守りは規則に置く」):
//   - system に規則 (accountOnlyRule) を書く。ただしプロンプトは守られない前提で、出力を規則で直す・捨てる
//   - LLM の文の中の、その主体の ARN は「外部アカウント NNN (呼び出した主体は記録に無い)」に置き換える
//   - 置き換えた後、そのアカウント ID の近く (同じ文の maxRootDistance 文字以内) に root・ルートの語があれば捨てる
//   - その finding に付く文 (理由・「→」・approve の提案・インシデント候補) は、root・ルートの語があれば捨てる (finding は規則の行に戻る)
//   - 全体の文 (headline・blocks の summary) は「ルートユーザー」「root アカウント」などの言い方があれば形の不正にする (再試行し、だめなら規則で組み立てる)。
//     語だけでは捨てない (`root_causes`・ルートテーブルなどの別の話で要約の全部を失わないため)
//   - 本物のルートの指摘 (root_usage、posture の root_mfa など。チェック名・key・見出しに root・ルートの語がある、アカウントしか分からない主体ではない finding) が
//     同じ範囲にあるときは、語と言い方では捨てない (アカウント ID の近くだけを見る)
//   - 見分けるのは data の `external_account` (schema.Finding.AccountOnly)。以前の版の arata の report.json でも効く

// accountOnlyRule は system に足す規則。
const accountOnlyRule = "- data に `caller_identity: account_only` か `principal_identity: account_only` (または `external_account`) がある finding の主体 `arn:aws:iam::NNN:root` は、" +
	"アカウント NNN のどれかの主体を表す (どの主体かは記録に無い)。ルートユーザーが使われたのではない。「外部アカウント NNN」と書き、「root」「ルートユーザー」と書かない (通知の側で検査して、その項目を捨てる)。"

// rejectAccountOnlyRoot は検査で捨てた理由 (ログに出す固定の文)。
const rejectAccountOnlyRoot = "calls an account-only principal the root user"

// maxRootDistance は、アカウント ID と root・ルートの語がこの文字数以内なら「そのアカウントの root」と読める、とみなす距離。
const maxRootDistance = "16"

var (
	rootWord = regexp.MustCompile(`(?i)root|ルート`)
	// rootUserPhrase はルートユーザーの利用を指す言い方 (全体の文で見る)。
	rootUserPhrase = regexp.MustCompile(`(?i)(?:root|ルート)\s*(?:user|account|ユーザ|アカウント)`)
	// accountOnlyKey は、主体のチェックの key が「アカウントそのもの」の ARN で始まる形 (unknown_assume_role は `<ARN>-><ロール>`、ほかは ARN だけ)。
	accountOnlyKey = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):root(?:->.*)?\z`)
)

// accountOnlyChecks は、key が主体の ARN で、ルートユーザーを対象にしないチェック (期間レポートの events は data を持たないので、key の形で見分ける)。
var accountOnlyChecks = map[string]bool{"unknown_assume_role": true, "new_principal": true, "access_denied": true, "secret_access": true, "principal_new_source": true}

// accountOnlyOf は、finding の主体がアカウントしか分からないなら、そのアカウント ID を返す。
func accountOnlyOf(f findingRef) (string, bool) {
	if f.finding != nil {
		return f.finding.AccountOnly()
	}
	if !accountOnlyChecks[f.check] {
		return "", false
	}
	if m := accountOnlyKey.FindStringSubmatch(f.key); m != nil {
		return m[1], true
	}
	return "", false
}

// rootGuard は LLM の文 1 つに掛ける検査の材料。
type rootGuard struct {
	accounts map[string]bool // アカウントしか分からない主体のアカウント ID
	genuine  bool            // 同じ範囲に本物のルートの指摘がある
}

// newRootGuard は、文が指す finding (全体の文なら報告の全部) から検査の材料を作る。
func newRootGuard(fs ...findingRef) rootGuard {
	g := rootGuard{accounts: map[string]bool{}}
	for _, f := range fs {
		if a, ok := accountOnlyOf(f); ok {
			g.accounts[a] = true
		} else if rootWord.MatchString(f.check) || rootWord.MatchString(f.key) || rootWord.MatchString(f.summary) {
			g.genuine = true
		}
	}
	return g
}

// apply は LLM の文を直し、捨てる理由を返す (捨てないなら空)。scoped は finding に付く文 (false は全体の文)。
// 対象のアカウントが無ければ何もしない。
func (g rootGuard) apply(s string, scoped bool) (string, string) {
	if len(g.accounts) == 0 {
		return s, ""
	}
	s = oneLine(s) // 目に見えない文字で語を割らせない (rejectLLMText と同じ)
	s = schema.AccountRootARNRe.ReplaceAllStringFunc(s, func(arn string) string {
		if m := schema.AccountRootARNRe.FindStringSubmatch(arn); g.accounts[m[1]] {
			return schema.AccountOnlyLabel(m[1])
		}
		return arn
	})
	plain := s
	for a := range g.accounts {
		plain = strings.ReplaceAll(plain, schema.AccountOnlyLabel(a), a) // 置き換えた表記の括弧の分を距離に数えない
	}
	for a := range g.accounts {
		near := regexp.MustCompile(`(?i)` + a + `[^。]{0,` + maxRootDistance + `}(?:root|ルート)|(?:root|ルート)[^。]{0,` + maxRootDistance + `}` + a)
		if near.MatchString(plain) {
			return "", rejectAccountOnlyRoot
		}
	}
	switch {
	case g.genuine:
	case scoped && rootWord.MatchString(plain), !scoped && rootUserPhrase.MatchString(plain):
		return "", rejectAccountOnlyRoot
	}
	return s, ""
}
