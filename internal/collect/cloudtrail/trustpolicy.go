package cloudtrail

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// 信頼ポリシーの読み取り (ADR 0056)。iam_changes が、UpdateAssumeRolePolicy / CreateRole の信頼ポリシーに
// `*` や、そのアカウントの外の主体があるかを判定するための値だけを取り出す。文書そのものは残さない。
//
// 文書は API を呼んだ側が書いた値 (ログ由来)。決定:
//   - 見るのは Effect: Allow の Statement の Principal だけ (Statement は 1 つでも配列でも読む)。Deny は見ない
//   - `"Principal": "*"`・`"AWS": "*"` (配列の中も) は `*`。Allow + NotPrincipal は「挙げた主体以外の全員」なので `*` として扱う
//     (バケットポリシーの publicStatements と同じ。ADR 0037。ADR 0056 の本文は「読めない」と書いたが、重い側に寄せる)
//   - AWS の値が 12 桁のアカウント ID か IAM / STS の ARN なら、そのアカウントを取り出す。Federated の値が
//     oidc-provider / saml-provider の ARN ならそのアカウント、ホスト名の形 (cognito-identity.amazonaws.com など) なら名前を取り出す
//   - Service (AWS のサービス) は数えない
//   - それ以外の値 (消えた主体の ID、知らない種類の主体、文字列でない値)、JSON として読めない文書、大きすぎる文書は「読めない」(OK が false)。
//     読めないものを「`*` も外の主体も無い」と扱わない。読めない文書でも、見つけた `*` は落とさない
//   - Condition は判定しない (絞っているかを規則で決められない)。有無だけを残す
type trustSummary struct {
	OK           bool     // 全部読めた
	Wildcard     bool     // 誰でも (`*`) を許す Statement がある
	Accounts     []string // AWS / Federated の主体のアカウント (12 桁。重複なし、昇順)
	Federated    []string // ARN でない Federated の値 (ホスト名の形)
	HasCondition bool     // Allow の Statement に Condition がある
}

// maxTrustPolicyBytes は読む文書の大きさの上限 (IAM の信頼ポリシーの上限は 4096 文字まで引き上げられる。URL エンコードの分の余裕を見る)。
const maxTrustPolicyBytes = 32 << 10

var (
	trustAccountRe   = regexp.MustCompile(`^[0-9]{12}\z`)
	trustAWSARNRe    = regexp.MustCompile(`^arn:aws[a-z-]*:(?:iam|sts)::([0-9]{12}):[A-Za-z0-9+=,.@_/-]+\z`)
	trustProviderRe  = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):(?:oidc-provider|saml-provider)/[A-Za-z0-9+=,.@_/:-]+\z`)
	trustFederatedRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?\z`)
)

// parseTrustPolicy は信頼ポリシー (JSON の文字列。URL エンコードされた形と、オブジェクトのままの形も読む) から trustSummary を作る。
func parseTrustPolicy(doc any) trustSummary {
	var pol map[string]any
	switch x := doc.(type) {
	case map[string]any:
		pol = x
	case string:
		if len(x) > maxTrustPolicyBytes {
			return trustSummary{}
		}
		s := strings.TrimSpace(x)
		if strings.HasPrefix(s, "%") {
			u, err := url.QueryUnescape(s)
			if err != nil {
				return trustSummary{}
			}
			s = u
		}
		if json.Unmarshal([]byte(s), &pol) != nil {
			return trustSummary{}
		}
	}
	if pol == nil {
		return trustSummary{}
	}
	var sts []any
	switch x := pol["Statement"].(type) {
	case map[string]any:
		sts = []any{x}
	case []any:
		sts = x
	}
	if len(sts) == 0 {
		return trustSummary{}
	}
	out := trustSummary{OK: true}
	accounts, federated := map[string]bool{}, map[string]bool{}
	for _, v := range sts {
		st, ok := v.(map[string]any)
		if !ok {
			out.OK = false
			continue
		}
		switch e, _ := st["Effect"].(string); e {
		case "Deny":
			continue
		case "Allow":
		default:
			out.OK = false
			continue
		}
		if c, ok := st["Condition"].(map[string]any); ok && len(c) > 0 {
			out.HasCondition = true
		}
		if st["NotPrincipal"] != nil {
			out.Wildcard = true
			continue
		}
		switch p := st["Principal"].(type) {
		case string:
			if p == "*" {
				out.Wildcard = true
			} else {
				out.OK = false
			}
		case map[string]any:
			if len(p) == 0 {
				out.OK = false
			}
			for kind, val := range p {
				vals, ok := trustValues(val)
				if !ok {
					out.OK = false
					continue
				}
				for _, s := range vals {
					switch kind {
					case "AWS":
						if s == "*" {
							out.Wildcard = true
						} else if trustAccountRe.MatchString(s) {
							accounts[s] = true
						} else if m := trustAWSARNRe.FindStringSubmatch(s); m != nil {
							accounts[m[1]] = true
						} else {
							out.OK = false
						}
					case "Federated":
						if m := trustProviderRe.FindStringSubmatch(s); m != nil {
							accounts[m[1]] = true
						} else if trustFederatedRe.MatchString(s) {
							federated[s] = true
						} else {
							out.OK = false
						}
					case "Service":
					default:
						out.OK = false
					}
				}
			}
		default:
			out.OK = false
		}
	}
	// 一覧が上限を超える文書は「読めない」(切り詰めた一覧で「外の主体は無い」と読ませない)
	if len(accounts) > maxDetailItems || len(federated) > maxDetailItems {
		out.OK = false
	}
	if !out.OK {
		return trustSummary{Wildcard: out.Wildcard}
	}
	out.Accounts, out.Federated = trustSorted(accounts), trustSorted(federated)
	return out
}

// trustValues は主体の値 (文字列か、文字列の配列) を列にする。文字列でない値・空の配列があれば ok が false。
func trustValues(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, len(out) > 0
	}
	return nil, false
}

func trustSorted(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// trustPolicyParams は、信頼ポリシーを要求に持つ IAM の操作と、その requestParameters のキー。
var trustPolicyParams = map[string]string{"UpdateAssumeRolePolicy": "policyDocument", "CreateRole": "assumeRolePolicyDocument"}

// trustDetail は UpdateAssumeRolePolicy / CreateRole の記録に、信頼ポリシーから読んだ値を足す (ADR 0056)。
// trust_policy は必ず付ける (ok / unreadable。無いのは以前の版で集めた記録、と見分けるため)。
// 拒否された呼び出しは requestParameters が記録されないので unreadable になる。
func trustDetail(source, name string, rp map[string]any, d map[string]any) {
	key, ok := trustPolicyParams[name]
	if !ok || source != "iam.amazonaws.com" {
		return
	}
	s := parseTrustPolicy(rp[key])
	d["trust_policy"] = "unreadable"
	if s.OK {
		d["trust_policy"] = "ok"
	}
	if s.Wildcard {
		d["trust_wildcard"] = true
	}
	if s.HasCondition {
		d["trust_has_condition"] = true
	}
	putList(d, "trust_accounts", s.Accounts)
	putList(d, "trust_federated", s.Federated)
}
