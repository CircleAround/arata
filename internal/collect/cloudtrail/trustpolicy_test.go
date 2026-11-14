package cloudtrail

import (
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseTrustPolicy(t *testing.T) {
	const own = "123456789012"
	for _, tc := range []struct {
		name string
		doc  any
		want trustSummary
	}{
		{"自アカウントのロールだけ", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app"},"Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true, Accounts: []string{own}}},
		{"サービスだけ", `{"Statement":{"Effect":"Allow","Principal":{"Service":["ecs-tasks.amazonaws.com","lambda.amazonaws.com"]},"Action":"sts:AssumeRole"}}`,
			trustSummary{OK: true}},
		{"AWS の *", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true, Wildcard: true}},
		{"Principal が *", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true, Wildcard: true}},
		{"配列の中の *", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root","*"]},"Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true, Wildcard: true, Accounts: []string{own}}},
		{"条件つきの *", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example"}}}]}`,
			trustSummary{OK: true, Wildcard: true, HasCondition: true}},
		{"NotPrincipal は挙げた主体以外の全員", `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true, Wildcard: true}},
		{"外のアカウント (ID と ARN)", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","arn:aws:iam::123456789012:root","arn:aws:sts::444455556666:assumed-role/x/y"]},"Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true, Accounts: []string{"111122223333", own, "444455556666"}}},
		{"自アカウントの OIDC プロバイダ", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:example-org/example-repo:ref:refs/heads/main"}}}]}`,
			trustSummary{OK: true, Accounts: []string{own}, HasCondition: true}},
		{"ARN でない Federated", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`,
			trustSummary{OK: true, Federated: []string{"cognito-identity.amazonaws.com"}}},
		{"Deny は見ない", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			trustSummary{OK: true}},
		{"URL エンコードされた文書", `%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22%2A%22%7D%7D%5D%7D`,
			trustSummary{OK: true, Wildcard: true}},
		{"オブジェクトのまま", map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "*"}}}},
			trustSummary{OK: true, Wildcard: true}},
		// 読めない
		{"無い", nil, trustSummary{}},
		{"空", ``, trustSummary{}},
		{"JSON でない", `{"Statement":`, trustSummary{}},
		{"Statement が無い", `{"Version":"2012-10-17"}`, trustSummary{}},
		{"Statement が空", `{"Statement":[]}`, trustSummary{}},
		{"Statement の要素がオブジェクトでない", `{"Statement":["x"]}`, trustSummary{}},
		{"知らない Effect", `{"Statement":[{"Effect":"allow","Principal":{"AWS":"*"}}]}`, trustSummary{}},
		{"Principal が無い", `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`, trustSummary{}},
		{"消えた主体の ID", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"AROAEXAMPLEID"}}]}`, trustSummary{}},
		{"知らない種類の主体", `{"Statement":[{"Effect":"Allow","Principal":{"CanonicalUser":"abc"}}]}`, trustSummary{}},
		{"主体が文字列でない", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":[1]}}]}`, trustSummary{}},
		{"* でない文字列の Principal", `{"Statement":[{"Effect":"Allow","Principal":"x"}]}`, trustSummary{}},
		{"大きすぎる", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Sid":"` + strings.Repeat("a", maxTrustPolicyBytes) + `"}]}`, trustSummary{}},
		// 読めない部分が 1 つでもあれば、読めた * も「読めた」とは言わないが、* は落とさない
		{"* と読めない主体", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*","AROAEXAMPLEID"]}}]}`, trustSummary{Wildcard: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseTrustPolicy(tc.doc); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// 収集のときに残すのは判定に使う値だけ (文書そのものは残さない)。
func TestNormalizeTrustPolicy(t *testing.T) {
	c := New("trail")
	body := func(name, key, doc string) string {
		return `{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/gha-deploy/s","accountId":"123456789012","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::123456789012:role/gha-deploy"}}},
		 "eventSource":"iam.amazonaws.com","eventName":"` + name + `","recipientAccountId":"123456789012","requestParameters":{"roleName":"app",` + key + `:` + doc + `}}`
	}
	const star = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"*\",\"111122223333\"]},\"Condition\":{\"Bool\":{\"aws:MultiFactorAuthPresent\":\"true\"}}}]}"`
	for _, tc := range []struct{ name, key string }{{"UpdateAssumeRolePolicy", `"policyDocument"`}, {"CreateRole", `"assumeRolePolicyDocument"`}} {
		e, ok := c.normalize(ev("e-1", fuzzEventTime, body(tc.name, tc.key, star)))
		if !ok {
			t.Fatal("not normalized")
		}
		d := e.Data
		if d["trust_policy"] != "ok" || d["trust_wildcard"] != true || d["trust_has_condition"] != true || !reflect.DeepEqual(d["trust_accounts"], []string{"111122223333"}) || d["role_name"] != "app" {
			t.Fatalf("%s: %+v", tc.name, d)
		}
		for k, v := range d {
			if s, _ := v.(string); strings.Contains(s, "Statement") {
				t.Fatalf("%s: 文書そのものを残した: %s=%q", tc.name, k, s)
			}
		}
	}
	// 読めない・無いときは unreadable (拒否された呼び出しは requestParameters が無い)
	for _, b := range []string{body("UpdateAssumeRolePolicy", `"policyDocument"`, `"x"`),
		`{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/alice"},"eventSource":"iam.amazonaws.com","eventName":"CreateRole","errorCode":"AccessDenied"}`} {
		e, _ := c.normalize(ev("e-2", fuzzEventTime, b))
		if e.Data["trust_policy"] != "unreadable" || e.Data["trust_wildcard"] != nil || e.Data["trust_accounts"] != nil {
			t.Fatalf("%+v", e.Data)
		}
	}
	// ほかの操作には付けない
	e, _ := c.normalize(ev("e-3", fuzzEventTime, body("PutRolePolicy", `"policyDocument"`, star)))
	for k := range e.Data {
		if strings.HasPrefix(k, "trust_") {
			t.Fatalf("PutRolePolicy に %s", k)
		}
	}
}

// ファズテスト (ADR 0041・0056)。信頼ポリシーは API を呼んだ側が書いた値。守る規則:
//   - パニックしない。同じ入力で同じ結果
//   - 取り出すアカウントは 12 桁の数字だけ、Federated の名前は決まった形だけ、どちらも上限まで・昇順・重複なし
//   - 読めない文書 (OK が false) は、`*` 以外の値を持たない
//   - Allow の Statement の AWS の主体に `*` を足した文書を、「読めて `*` なし」と読まない (extra がどんな値でも)
func FuzzParseTrustPolicy(f *testing.F) {
	for _, s := range []string{
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`,
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":["111122223333","arn:aws:iam::123456789012:role/app"],"Service":"ec2.amazonaws.com","Federated":"cognito-identity.amazonaws.com"},"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`,
		`{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"111122223333"}},{"Effect":"Deny","Principal":"*"}]}`,
		`%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%22%2A%22%7D%5D%7D`,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"123456789012\n"}}]}`, `{"Statement":[null,1,"x"]}`, `%zz`, `[]`, `null`, ``,
	} {
		f.Add(s, "arn:aws:iam::111122223333:root")
	}
	f.Fuzz(func(t *testing.T, doc, extra string) {
		got := parseTrustPolicy(doc)
		if again := parseTrustPolicy(doc); !reflect.DeepEqual(got, again) {
			t.Fatalf("結果が揃わない: %+v / %+v", got, again)
		}
		checkTrustSummary(t, got)
		b, err := json.Marshal(map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": []any{extra, "*"}}}}})
		if err != nil {
			return
		}
		for _, d := range []string{string(b), url.QueryEscape(string(b))} {
			s := parseTrustPolicy(d)
			checkTrustSummary(t, s)
			if !s.Wildcard {
				t.Fatalf("`*` を落とした: %q → %+v", d, s)
			}
		}
	})
}

func checkTrustSummary(t *testing.T, s trustSummary) {
	t.Helper()
	if !s.OK && (len(s.Accounts) > 0 || len(s.Federated) > 0 || s.HasCondition) {
		t.Fatalf("読めない文書に値がある: %+v", s)
	}
	for _, l := range [][]string{s.Accounts, s.Federated} {
		if len(l) > maxDetailItems || !sort.StringsAreSorted(l) {
			t.Fatalf("一覧が規則に合わない: %q", l)
		}
		for i := 1; i < len(l); i++ {
			if l[i] == l[i-1] {
				t.Fatalf("重複: %q", l)
			}
		}
	}
	for _, a := range s.Accounts {
		if len(a) != 12 || strings.Trim(a, "0123456789") != "" {
			t.Fatalf("アカウントが 12 桁の数字でない: %q", a)
		}
	}
	for _, n := range s.Federated {
		if n == "" || len(n) > 128 || strings.Trim(n, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
			t.Fatalf("Federated の名前が決まった形でない: %q", n)
		}
	}
}
