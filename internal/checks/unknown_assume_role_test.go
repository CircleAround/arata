package checks

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

const (
	ownAcct   = "123456789012"
	otherAcct = "111122223333"
	ownUser   = "arn:aws:iam::123456789012:user/alice"
	ownRole   = "arn:aws:iam::123456789012:role/Admin"
	otherRole = "arn:aws:iam::111122223333:role/partner-admin"
	otherRoot = "arn:aws:iam::111122223333:root"
	ownRole2  = "arn:aws:iam::123456789012:role/Deploy2"
)

// 向きは規則で決める。決められないときは書かない (推測しない。設計書 6 章)。
func TestAssumeDirection(t *testing.T) {
	cases := []struct {
		name      string
		caller    string
		kind      record.PrincipalKind
		role      string
		recipient string
		want      string
	}{
		{"外向き: 自アカウントのユーザーが外部のロール", ownUser, record.PrincipalUser, otherRole, ownAcct, dirOutbound},
		{"外向き: 受け取ったアカウントの記録が無くても、IAM ユーザーの ARN は呼び出し側の記録にしか載らない", ownUser, record.PrincipalUser, otherRole, "", dirOutbound},
		{"外向き: 自アカウントのロールが外部のロール", "arn:aws:iam::123456789012:role/Deploy", record.PrincipalAssumedRole, otherRole, ownAcct, dirOutbound},
		{"内向き: 外部アカウント (AWSAccount) が自アカウントのロール", otherRoot, record.PrincipalUnknown, ownRole, ownAcct, dirInbound},
		{"内向き: 受け取ったアカウントの記録が無くても、AWSAccount の形はロール側の記録にしか載らない", otherRoot, record.PrincipalUnknown, ownRole, "", dirInbound},
		{"内向き: 外部アカウントのロールが自アカウントのロール", "arn:aws:iam::111122223333:role/ci", record.PrincipalAssumedRole, ownRole, ownAcct, dirInbound},
		{"内部: どちらも自アカウント", ownUser, record.PrincipalUser, ownRole, ownAcct, dirInternal},
		{"内部: 同じアカウントどうしは、そのアカウントにしか記録されない", ownUser, record.PrincipalUser, ownRole, "", dirInternal},
		{"不明: ロールの呼び出し元で、受け取ったアカウントが分からない", "arn:aws:iam::123456789012:role/Deploy", record.PrincipalAssumedRole, otherRole, "", ""},
		{"不明: 受け取ったアカウントがどちらでもない", ownUser, record.PrincipalUser, otherRole, "999999999999", ""},
		{"不明: IAM ユーザーの ARN なのに、受け取ったアカウントがロール側 (食い違い)", ownUser, record.PrincipalUser, otherRole, otherAcct, ""},
		{"不明: AWSAccount の形なのに、受け取ったアカウントが呼び出し側 (食い違い)", otherRoot, record.PrincipalUnknown, ownRole, otherAcct, ""},
		{"不明: 同じアカウントどうしなのに、受け取ったアカウントが別", ownUser, record.PrincipalUser, ownRole, otherAcct, ""},
		{"不明: 受け取ったアカウントが 12 桁でない", "arn:aws:iam::123456789012:role/Deploy", record.PrincipalAssumedRole, otherRole, "12345", ""},
		{"不明: ロールの ARN が読めない", ownUser, record.PrincipalUser, "partner-admin", ownAcct, ""},
		{"不明: ロールの ARN がロールでない", ownUser, record.PrincipalUser, "arn:aws:iam::111122223333:user/x", ownAcct, ""},
		{"不明: 呼び出し元のアカウントが 12 桁でない", "arn:aws:iam::1:user/alice", record.PrincipalUser, otherRole, ownAcct, ""},
		{"不明: 呼び出し元に記法の文字", "arn:aws:iam::123456789012:user/<!here>", record.PrincipalUser, otherRole, ownAcct, ""},
		{"不明: ロール名に改行", ownUser, record.PrincipalUser, "arn:aws:iam::111122223333:role/a\nb", ownAcct, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := newAssumeParties(c.caller, c.kind, c.role, c.recipient).direction; got != c.want {
				t.Fatalf("direction = %q, want %q", got, c.want)
			}
		})
	}
}

// MFA は記録に証拠があるときだけ「あり / なし」と書く。項目が無いのは「不明」(「なし」と書かない)。
func TestAssumeMFA(t *testing.T) {
	cases := []struct {
		name string
		data map[string]any
		want string
	}{
		{"requestParameters.serialNumber があった", map[string]any{"mfa_serial": true}, mfaYes},
		{"セッションが MFA で認証済み", map[string]any{"session_mfa": "true"}, mfaYes},
		{"セッションは MFA なしだが、呼び出しに serialNumber", map[string]any{"session_mfa": "false", "mfa_serial": true}, mfaYes},
		{"セッションが MFA なし", map[string]any{"session_mfa": "false"}, mfaNo},
		{"どちらの項目も無い", map[string]any{"role_arn": otherRole}, mfaUnknown},
		{"data が無い", nil, mfaUnknown},
		{"知らない値", map[string]any{"session_mfa": "TRUE\n<!here>"}, mfaUnknown},
		{"型が違う", map[string]any{"session_mfa": true, "mfa_serial": "yes"}, mfaUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := assumeMFA(c.data); got != c.want {
				t.Fatalf("mfa = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUnknownAssumeRoleDirectionAndMFA(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	at := now.Add(-time.Hour)
	ev := func(id, caller string, kind record.PrincipalKind, ip string, data map[string]any) record.TrailEvent {
		return record.TrailEvent{EventID: id, Time: at, Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: caller, PrincipalKind: kind, IP: ip, Data: data, ReadOnly: true}
	}
	for _, e := range []record.TrailEvent{
		// 外向き。コンソールのスイッチロール: 送信元がサービス名で IP が無く、セッションは MFA 済み
		ev("o1", ownUser, record.PrincipalUser, "", map[string]any{"role_arn": otherRole, "recipient_account": ownAcct, "session_mfa": "true", "invoked_by": "AWS Internal"}),
		// 内向き。外部アカウントから。MFA の項目は無い
		ev("i1", otherRoot, record.PrincipalUnknown, "198.51.100.7", map[string]any{"role_arn": ownRole, "recipient_account": ownAcct}),
		// 内部。MFA ありとなしが混ざる
		ev("n1", ownUser, record.PrincipalUser, "198.51.100.8", map[string]any{"role_arn": ownRole, "recipient_account": ownAcct, "mfa_serial": true}),
		ev("n2", ownUser, record.PrincipalUser, "198.51.100.8", map[string]any{"role_arn": ownRole, "recipient_account": ownAcct, "session_mfa": "false"}),
		// 向きが決まらない (ロールの呼び出し元で、受け取ったアカウントの記録が無い。以前の版で集めたイベント)
		ev("u1", "arn:aws:iam::123456789012:role/Deploy", record.PrincipalAssumedRole, "198.51.100.9", map[string]any{"role_arn": otherRole, "session_mfa": "false"}),
		// 向きが決まらない (受け取ったアカウントが食い違う) うえ、呼び出し元はアカウントしか分からない
		ev("u2", otherRoot, record.PrincipalUnknown, "198.51.100.10", map[string]any{"role_arn": ownRole2, "recipient_account": otherAcct}),
	} {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	obs, err := UnknownAssumeRole{}.Evaluate(ctx, st, w, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Observation{}
	for _, o := range obs {
		by[o.Key] = o
		if o.Severity != High {
			t.Fatalf("重大度は high のまま: %+v", o)
		}
	}
	if len(by) != 5 {
		t.Fatalf("keys: %s", keys(obs))
	}
	check := func(key, summary string, data map[string]any, absent ...string) {
		t.Helper()
		o, ok := by[key]
		if !ok {
			t.Fatalf("Key が変わった: %q が無い (%s)", key, keys(obs))
		}
		if o.Summary != summary {
			t.Fatalf("summary\n got: %s\nwant: %s", o.Summary, summary)
		}
		for k, want := range data {
			got := o.Data[k]
			if l, ok := got.([]string); ok {
				got = strings.Join(l, ",")
			}
			if got != want {
				t.Fatalf("%s: data.%s = %v, want %v", key, k, o.Data[k], want)
			}
		}
		for _, k := range absent {
			if _, has := o.Data[k]; has {
				t.Fatalf("%s: data.%s は出さない: %v", key, k, o.Data[k])
			}
		}
	}
	check(ownUser+"->"+otherRole,
		"既知リストに無い自アカウントの user/alice が外部アカウント 111122223333 のロール partner-admin を 1 回引き受け (外向き、MFA あり)",
		map[string]any{"direction": "outbound", "mfa": "true", "caller_account": ownAcct, "role_account": otherAcct, "invoked_by": "AWS Internal", "caller": ownUser, "role_arn": otherRole},
		"ips", "external_account", "caller_identity")
	// 呼び出し元がアカウントしか分からない (ロール側の記録)。Key と caller は ARN のまま (既存の ack・既知リスト・approve との一致を保つ) だが、
	// 見出しは root と読めない文にし、data に caller_identity: account_only を持たせる。caller_kind は主体の種類の語彙 (unknown) のまま
	check(otherRoot+"->"+ownRole,
		"既知リストに無い外部アカウント 111122223333 (呼び出した主体は記録に無い) が自アカウントのロール Admin を 1 回引き受け (内向き、MFA 不明)",
		map[string]any{"direction": "inbound", "mfa": "unknown", "external_account": otherAcct, "ips": "198.51.100.7",
			"caller": otherRoot, "caller_kind": "unknown", "caller_identity": "account_only"}, "invoked_by")
	check(ownUser+"->"+ownRole,
		"既知リストに無い自アカウントの user/alice が自アカウントのロール Admin を 2 回引き受け (内部、MFA の有無が混在)",
		map[string]any{"direction": "internal", "mfa": "mixed", "ips": "198.51.100.8"}, "caller_identity")
	check("arn:aws:iam::123456789012:role/Deploy->"+otherRole,
		"既知リストに無い arn:aws:iam::123456789012:role/Deploy が arn:aws:iam::111122223333:role/partner-admin を 1 回引き受け (MFA なし)",
		map[string]any{"mfa": "false"}, "direction", "caller_identity")
	check(otherRoot+"->"+ownRole2,
		"既知リストに無い 外部アカウント 111122223333 (呼び出した主体は記録に無い) が arn:aws:iam::123456789012:role/Deploy2 を 1 回引き受け (MFA 不明)",
		map[string]any{"mfa": "unknown", "external_account": otherAcct, "caller_identity": "account_only"}, "direction")
	// 見出しに root・ルートの語を出さない (アカウントしか分からない呼び出し元をルートユーザーと読ませない)
	for _, k := range []string{otherRoot + "->" + ownRole, otherRoot + "->" + ownRole2} {
		if s := by[k].Summary; strings.Contains(s, "root") || strings.Contains(s, "ルート") {
			t.Fatalf("見出しに root の語がある: %s", s)
		}
	}
	// Fingerprint は変えない (重大度 + IP 集合 + allowlist 状態)。既存の finding を changed にしない
	if fp := by[ownUser+"->"+ownRole].Fingerprint; fp != "high|198.51.100.8|unknown" {
		t.Fatalf("fingerprint: %q", fp)
	}
}

// 呼び出し元もロールも自アカウントで、呼び出し元がアカウントしか分からない記録 (種類の無い記録など) は「外部」とも root とも書かない。
func TestAssumeSummaryAccountOnlyInternal(t *testing.T) {
	const ownRoot = "arn:aws:iam::123456789012:root"
	p := newAssumeParties(ownRoot, record.PrincipalUnknown, ownRole, ownAcct)
	if p.direction != dirInternal {
		t.Fatalf("direction: %q", p.direction)
	}
	got := assumeSummary(p, true, "", ownRole, 2, mfaUnknown)
	if want := "既知リストに無い自アカウント (呼び出した主体は記録に無い) が自アカウントのロール Admin を 2 回引き受け (内部、MFA 不明)"; got != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}

var headlineUnsafe = regexp.MustCompile("[\\s<>()\\[\\]|*`]")

// CloudTrail の主体の ARN・requestParameters.roleArn・recipientAccountId はログ由来の信用できない値 (ADR 0041)。守る規則:
//   - 向きは outbound / inbound / internal か、空 (不明) だけ
//   - 向きを書くのは、呼び出し元とロールのアカウントがどちらも 12 桁の数字として読めたときだけ。
//     internal は両者が同じ、outbound / inbound は違う。受け取ったアカウントがあれば、outbound は呼び出し元、inbound はロールのアカウントと一致する
//   - 向きを書いたときに見出しへ出す表記 (呼び出し元・ロール) は、空白・改行・Markdown や Slack の記法の文字を含まない
//   - 向きが不明なら表記は空 (見出しは従来の形のまま)
func FuzzAssumeDirection(f *testing.F) {
	kinds := []record.PrincipalKind{record.PrincipalUser, record.PrincipalRole, record.PrincipalAssumedRole, record.PrincipalRoot, record.PrincipalService, record.PrincipalUnknown}
	for _, s := range [][3]string{
		{ownUser, otherRole, ownAcct}, {otherRoot, ownRole, ownAcct}, {ownUser, ownRole, ""}, {ownUser, otherRole, otherAcct},
		{"arn:aws:iam::123456789012:user/<!here>", otherRole, ownAcct}, {ownUser, "arn:aws:iam::111122223333:role/a\nb", ""},
		{"arn:aws:iam::１２３４５６７８９０１２:user/x", otherRole, ""}, {"arn:aws:iam::123456789012:user/alice\x00", ownRole, "123456789012\n"},
		{"arn:aws:sts::123456789012:assumed-role/Admin/s", "arn:aws:iam::111122223333:role/path/to/r", "111122223333"}, {"", "", ""},
		{"arn:aws:iam::123456789012:root", "arn:aws-cn:iam::111122223333:role/r", "123456789012"},
	} {
		for i := range kinds {
			f.Add(s[0], uint8(i), s[1], s[2])
		}
	}
	acct := regexp.MustCompile(`^\d{12}$`)
	f.Fuzz(func(t *testing.T, caller string, k uint8, role, recipient string) {
		kind := kinds[int(k)%len(kinds)]
		p := newAssumeParties(caller, kind, role, recipient)
		switch p.direction {
		case "":
			if p.callerLabel != "" || p.roleLabel != "" {
				t.Fatalf("向きが不明なのに表記がある: %+v", p)
			}
			return
		case dirOutbound, dirInbound, dirInternal:
		default:
			t.Fatalf("知らない向き: %q", p.direction)
		}
		if !acct.MatchString(p.callerAccount) || !acct.MatchString(p.roleAccount) {
			t.Fatalf("アカウントが 12 桁でないのに向きを書いた: %+v", p)
		}
		if !strings.Contains(caller, ":"+p.callerAccount+":") || !strings.Contains(role, ":"+p.roleAccount+":") {
			t.Fatalf("アカウントが入力の ARN に無い: %+v", p)
		}
		if (p.direction == dirInternal) != (p.callerAccount == p.roleAccount) {
			t.Fatalf("向きとアカウントが合わない: %+v", p)
		}
		if recipient != "" {
			if want := map[string]string{dirOutbound: p.callerAccount, dirInbound: p.roleAccount, dirInternal: p.callerAccount}[p.direction]; recipient != want {
				t.Fatalf("受け取ったアカウント %q と向きが合わない: %+v", recipient, p)
			}
		}
		for _, l := range []string{p.callerLabel, p.roleLabel} {
			if l == "" || len(l) > maxAssumeLabel || headlineUnsafe.MatchString(l) {
				t.Fatalf("見出しに出せない表記: %q", l)
			}
		}
		// 呼び出し元がアカウントしか分からないなら、見出しの呼び出し元に root の語を出さない (ロールの名前に含まれる分は別)
		if acct, accountOnly := record.ExternalAccount(caller, kind); accountOnly {
			sum := assumeSummary(p, true, record.AccountOnlyLabel(acct), role, 1, mfaUnknown)
			if rest := strings.Replace(sum, p.roleLabel, "", 1); strings.Contains(rest, "root") || !strings.Contains(sum, "呼び出した主体は記録に無い") {
				t.Fatalf("アカウントしか分からない呼び出し元を root と読める見出し: %q", sum)
			}
		}
	})
}
