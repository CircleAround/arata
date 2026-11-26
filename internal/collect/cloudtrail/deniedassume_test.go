package cloudtrail

import (
	"regexp"
	"strings"
	"testing"
)

// deniedAssume は、断られた AssumeRole の記録の形 (値は架空)。requestParameters は null で resources も無く、引き受け先は errorMessage の文にしか無い。
func deniedAssume(caller, msg string) string {
	return `{"userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:alice-session","arn":"` + caller + `","accountId":"123456789012",
	  "sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/AdminRole"},"attributes":{"mfaAuthenticated":"false"}}},
	  "eventTime":"2026-10-21T01:00:00Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","sourceIPAddress":"203.0.113.2",
	  "errorCode":"AccessDenied","errorMessage":` + msg + `,"requestParameters":null,"responseElements":null,"recipientAccountId":"123456789012","eventID":"e"}`
}

const deniedCaller = "arn:aws:sts::123456789012:assumed-role/AdminRole/alice-session"

func deniedMsg(caller, resource string) string {
	return `"User: ` + caller + ` is not authorized to perform: sts:AssumeRole on resource: ` + resource + `"`
}

// 決定 (設計書 6 章): 断られた AssumeRole は、errorMessage が決まった形で、呼び出し元が userIdentity.arn と一致し、
// 末尾がロールの ARN の形のときだけ、引き受け先を denied_role_arn に残す。文そのものは残さない。
func TestNormalizeDeniedAssumeRoleTarget(t *testing.T) {
	cases := []struct {
		name, json string
		want       any
	}{
		{"決まった形", deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:role/none")), "arn:aws:iam::111122223333:role/none"},
		{"パス付きのロール", deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:role/ops/partner-admin")), "arn:aws:iam::111122223333:role/ops/partner-admin"},
		{"後ろに理由が続く (形に合わない)", deniedAssume(deniedCaller, `"User: `+deniedCaller+` is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/none because no identity-based policy allows the sts:AssumeRole action"`), nil},
		{"呼び出し元が userIdentity.arn と違う", deniedAssume(deniedCaller, deniedMsg("arn:aws:sts::123456789012:assumed-role/AdminRole/bob", "arn:aws:iam::111122223333:role/none")), nil},
		{"リソースがロールでない", deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:user/none")), nil},
		{"リソースが *", deniedAssume(deniedCaller, deniedMsg(deniedCaller, "*")), nil},
		{"末尾に改行", deniedAssume(deniedCaller, `"User: `+deniedCaller+` is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/none\n"`), nil},
		{"アカウントが 12 桁でない", deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::1111:role/none")), nil},
		{"ロール名が長すぎる", deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:role/"+strings.Repeat("a", 129))), nil},
		{"別の操作", deniedAssume(deniedCaller, `"User: `+deniedCaller+` is not authorized to perform: sts:TagSession on resource: arn:aws:iam::111122223333:role/none"`), nil},
		{"文字列でない errorMessage", deniedAssume(deniedCaller, `["x"]`), nil},
	}
	c := New("trail")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := c.normalize(ev("e1", fuzzEventTime, tc.json))
			if !ok {
				t.Fatal("normalize failed (errorMessage の形で記録ごと捨てない)")
			}
			if got := e.Data["denied_role_arn"]; got != tc.want {
				t.Fatalf("denied_role_arn = %v, want %v", got, tc.want)
			}
			// 文そのものと、セッション名を含む呼び出し元の ARN は残さない
			for k, v := range e.Data {
				if s, _ := v.(string); strings.Contains(s, "not authorized") || strings.Contains(s, "alice-session") {
					t.Fatalf("data.%s に errorMessage の文かセッション名を残した: %q", k, s)
				}
			}
		})
	}
	// 成功した記録・requestParameters.roleArn がある記録・AssumeRole 以外には付けない
	for name, body := range map[string]string{
		"errorCode が無い": strings.Replace(deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:role/none")), `"errorCode":"AccessDenied",`, ``, 1),
		"roleArn がある":   strings.Replace(deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:role/none")), `"requestParameters":null`, `"requestParameters":{"roleArn":"arn:aws:iam::111122223333:role/other"}`, 1),
		"AssumeRole 以外": strings.Replace(deniedAssume(deniedCaller, deniedMsg(deniedCaller, "arn:aws:iam::111122223333:role/none")), `"eventName":"AssumeRole"`, `"eventName":"AssumeRoleWithSAML"`, 1),
	} {
		e, _ := c.normalize(ev("e2", fuzzEventTime, body))
		if v, has := e.Data["denied_role_arn"]; has {
			t.Fatalf("%s: denied_role_arn を付けた: %v", name, v)
		}
	}
}

// deniedRoleShape は、取り出した値が満たす形 (ロールの ARN。名前は 128 文字まで)。実装の正規表現とは別に書く。
var deniedRoleShape = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}\z`)

// ファズテスト (ADR 0041)。errorMessage は呼び出した側の入力 (要求したロールの ARN) を含む、信用しない値。
// 性質: 形に合わない文からは何も取らない (取ったなら、文は決まった形を呼び出し元と取った ARN で組み立てたものと 1 字も違わない)。
// 取った ARN は必ずロールの ARN の形。
func FuzzDeniedAssumeTarget(f *testing.F) {
	for _, s := range [][2]string{
		{"User: " + deniedCaller + " is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/none", deniedCaller},
		{"User: " + deniedCaller + " is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/a b", deniedCaller},
		{"User: arn:aws:iam::123456789012:user/alice is not authorized to perform: sts:AssumeRole on resource: arn:aws-cn:iam::111122223333:role/x/y", "arn:aws:iam::123456789012:user/alice"},
		{"User: x is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/none\n", "x"},
		{"User:  is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/", ""},
		{"", ""},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, msg, caller string) {
		role, ok := deniedAssumeTarget(msg, caller)
		if !ok {
			if role != "" {
				t.Fatalf("取れなかったのに値を返した: %q", role)
			}
			return
		}
		if !deniedRoleShape.MatchString(role) {
			t.Fatalf("ロールの ARN の形でない値を取った: %q (%q)", role, msg)
		}
		if caller == "" || msg != "User: "+caller+" is not authorized to perform: sts:AssumeRole on resource: "+role {
			t.Fatalf("決まった形でない文から取った: %q (caller %q) → %q", msg, caller, role)
		}
	})
}
