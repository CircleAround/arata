package schema

import "regexp"

// IdentityAccountOnly は finding の data (`caller_identity`・`principal_identity`) の値。主体がアカウントしか分からないことを表す
// (CloudTrail に呼び出し元のアカウント ID しか残らない記録。ロール側から見たクロスアカウントの AssumeRole など)。
// record.IdentityAccountOnly と同じ値 (このパッケージは標準ライブラリだけに依存するので、こちらにも置く)。
const IdentityAccountOnly = "account_only"

var (
	accountIDRe = regexp.MustCompile(`^[0-9]{12}\z`)
	// AccountRootARNRe は「アカウントそのもの」を指す ARN (`arn:aws:iam::NNN:root`)。文の中から探すときに使う (1 つ目の括弧がアカウント ID)。
	AccountRootARNRe = regexp.MustCompile(`arn:aws[a-z-]*:iam::([0-9]{12}):root`)
)

// AccountOnlyLabel は、アカウントしか分からない主体の表記。root・ルートの語を含めない。record.AccountOnlyLabel と同じ文。
func AccountOnlyLabel(account string) string {
	return "外部アカウント " + account + " (呼び出した主体は記録に無い)"
}

// AccountOnly は、finding の主体がアカウントしか分からないなら、そのアカウント ID (12 桁の数字) を返す。
//
// 決定 (設計書 6 章): 見分けるのは data の `external_account`。arata はこの項目を、主体が `arn:aws:iam::NNN:root` で
// ルートユーザーではないときにだけ書く。`caller_identity`・`principal_identity` を足す前の版が作った finding
// (still_open は data を書き換えないので残る) にもあるので、こちらで見る。
func (f Finding) AccountOnly() (string, bool) {
	a, ok := f.Data["external_account"].(string)
	if !ok || !accountIDRe.MatchString(a) {
		return "", false
	}
	return a, true
}

// AccountOnlyText は data の値 v が、この finding の「アカウントしか分からない主体」そのものを指す ARN なら AccountOnlyLabel の表記にする。それ以外はそのまま。
// 決定: report.md は人が読み、LLM が使えないときの通知の本文にもなる。`...:root` のままだとルートユーザーの利用と読めるので置き換える。
// report.json の data と Key は ARN のまま (approve・ack・既知リストの一致に使う)。
func (f Finding) AccountOnlyText(v string) string {
	account, ok := f.AccountOnly()
	if !ok {
		return v
	}
	if m := AccountRootARNRe.FindStringSubmatch(v); m != nil && m[0] == v && m[1] == account {
		return AccountOnlyLabel(account)
	}
	return v
}
