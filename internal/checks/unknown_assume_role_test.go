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
	got := assumeSummary(p, true, "", ownRole, 2, mfaUnknown, allowlist.StatusUnknown)
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
			sum := assumeSummary(p, true, record.AccountOnlyLabel(acct), role, 1, mfaUnknown, allowlist.StatusUnknown)
			if rest := strings.Replace(sum, p.roleLabel, "", 1); strings.Contains(rest, "root") || !strings.Contains(sum, "呼び出した主体は記録に無い") {
				t.Fatalf("アカウントしか分からない呼び出し元を root と読める見出し: %q", sum)
			}
		}
	})
}

const (
	unknownAcct    = "444455556666"
	scopedAcct     = "111111111111"
	expiredAcct    = "999999999999"
	ownUser2       = "arn:aws:iam::123456789012:user/bob"
	otherRole2     = "arn:aws:iam::111122223333:role/ops/ReadOnly"
	knownDestsYAML = `
assume_destinations:
  - account: "111122223333"
    note: 運用を受託しているアカウント
    approved_by: alice
  - account: "111111111111"
    roles: ["ReadOnly"]
    note: 読み取りのロールだけ
  - account: "999999999999"
    note: 契約が終わった
    expires: 2026-01-31
`
)

func knownDests(t *testing.T) *allowlist.List {
	t.Helper()
	al, err := allowlist.Parse([]byte(knownDestsYAML))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

// 外向きで、行き先が既知リストの assume_destinations に期限内で載っていて、MFA ありの引き受けだけを報告しない (ADR 0047)。
// それ以外 (知らない行き先、MFA なし・不明・混在、内向き、内部、向きが決まらない、期限切れ、絞ったロールの外) は今までどおり high。
func TestUnknownAssumeRoleKnownDestination(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	at := now.Add(-time.Hour)
	n := 0
	ev := func(caller string, kind record.PrincipalKind, role string, data map[string]any) {
		t.Helper()
		n++
		d := map[string]any{"role_arn": role, "recipient_account": ownAcct}
		for k, v := range data {
			if v == nil {
				delete(d, k)
			} else {
				d[k] = v
			}
		}
		e := record.TrailEvent{EventID: "e" + strings.Repeat("x", n), Time: at.Add(time.Duration(n) * time.Minute), Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com",
			PrincipalARN: caller, PrincipalKind: kind, IP: "198.51.100.8", Data: d, ReadOnly: true}
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	mfa := map[string]any{"session_mfa": "true"}
	role := func(acct, name string) string { return "arn:aws:iam::" + acct + ":role/" + name }
	// 報告しない: 既知の行き先 + MFA あり (alice が 2 つのロールに 3 回、bob が 1 回)
	ev(ownUser, record.PrincipalUser, otherRole, mfa)
	ev(ownUser, record.PrincipalUser, otherRole, map[string]any{"mfa_serial": true})
	ev(ownUser, record.PrincipalUser, otherRole2, mfa)
	ev(ownUser2, record.PrincipalUser, otherRole, mfa)
	// 報告しない: ロールを絞った行き先の、そのロール
	ev(ownUser, record.PrincipalUser, role(scopedAcct, "ReadOnly"), mfa)
	// high: 知らない行き先 (MFA あり)
	ev(ownUser, record.PrincipalUser, role(unknownAcct, "Admin"), mfa)
	// high: 既知の行き先だが MFA 不明 / なし / 混在
	ev(ownUser, record.PrincipalUser, role(otherAcct, "mfa-unknown"), nil)
	ev(ownUser, record.PrincipalUser, role(otherAcct, "mfa-none"), map[string]any{"session_mfa": "false"})
	ev(ownUser, record.PrincipalUser, role(otherAcct, "mfa-mixed"), mfa)
	ev(ownUser, record.PrincipalUser, role(otherAcct, "mfa-mixed"), nil)
	// high: 絞ったロールの外
	ev(ownUser, record.PrincipalUser, role(scopedAcct, "Admin"), mfa)
	// high: 行き先の期限切れ
	ev(ownUser, record.PrincipalUser, role(expiredAcct, "Admin"), mfa)
	// high: 内向き (行き先として既知のアカウントから、自アカウントのロールへ)。行き先の既知は呼び出し元を承認しない
	ev(otherRoot, record.PrincipalUnknown, ownRole, mfa)
	// high: 内部
	ev(ownUser, record.PrincipalUser, ownRole, mfa)
	// high: 向きが決まらない (ロールの呼び出し元で、受け取ったアカウントの記録が無い)
	ev("arn:aws:iam::123456789012:role/Deploy", record.PrincipalAssumedRole, otherRole, map[string]any{"session_mfa": "true", "recipient_account": nil})

	obs, err := UnknownAssumeRole{}.Evaluate(ctx, st, w, knownDests(t))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Observation{}
	for _, o := range obs {
		by[o.Key] = o
	}
	for _, k := range []string{ownUser + "->" + otherRole, ownUser + "->" + otherRole2, ownUser2 + "->" + otherRole, ownUser + "->" + role(scopedAcct, "ReadOnly")} {
		if o, ok := by[k]; ok {
			t.Fatalf("既知の行き先 + MFA ありを報告した: %+v", o)
		}
	}
	high := map[string][2]string{ // Key → 見出しの括弧、data.destination_status
		ownUser + "->" + role(unknownAcct, "Admin"):           {"(外向き、MFA あり)", ""},
		ownUser + "->" + role(otherAcct, "mfa-unknown"):       {"(外向き、MFA 不明。行き先は既知だが、MFA ありと確かめられないので報告)", "approved"},
		ownUser + "->" + role(otherAcct, "mfa-none"):          {"(外向き、MFA なし。行き先は既知だが、MFA ありと確かめられないので報告)", "approved"},
		ownUser + "->" + role(otherAcct, "mfa-mixed"):         {"(外向き、MFA の有無が混在。行き先は既知だが、MFA ありと確かめられないので報告)", "approved"},
		ownUser + "->" + role(scopedAcct, "Admin"):            {"(外向き、MFA あり)", ""},
		ownUser + "->" + role(expiredAcct, "Admin"):           {"(外向き、MFA あり。行き先の承認は期限切れ)", "expired"},
		otherRoot + "->" + ownRole:                            {"(内向き、MFA あり)", ""},
		ownUser + "->" + ownRole:                              {"(内部、MFA あり)", ""},
		"arn:aws:iam::123456789012:role/Deploy->" + otherRole: {"(MFA あり)", ""},
	}
	for k, want := range high {
		o, ok := by[k]
		if !ok {
			t.Fatalf("報告されない: %s (%s)", k, keys(obs))
		}
		if o.Severity != High || !strings.HasSuffix(o.Summary, want[0]) {
			t.Fatalf("%s: %s %s, want high …%s", k, o.Severity, o.Summary, want[0])
		}
		if got, _ := o.Data["destination_status"].(string); got != want[1] {
			t.Fatalf("%s: destination_status = %q, want %q", k, got, want[1])
		}
		// Fingerprint は変えない (既存の ack 済みの finding を changed にしない)
		if o.Fingerprint != "high|198.51.100.8|unknown" {
			t.Fatalf("%s: fingerprint %q", k, o.Fingerprint)
		}
	}
	// 報告しなかった分は、行き先のアカウントごとに info で 1 行残す (黙って消さない)
	info, ok := by["known-destination:"+otherAcct]
	if !ok {
		t.Fatalf("info の行が無い: %s", keys(obs))
	}
	if want := "既知の行き先 (外部アカウント 111122223333) への MFA ありの引き受け 4 回は報告していない (呼び出し元 2、ロール 2)"; info.Severity != Info || info.Summary != want {
		t.Fatalf("info: %s %s\nwant: %s", info.Severity, info.Summary, want)
	}
	for k, want := range map[string]any{"known_destination": true, "role_account": otherAcct, "direction": "outbound", "mfa": "true", "count": 4,
		"callers": ownUser + "," + ownUser2, "callers_total": 2, "roles": otherRole2 + "," + otherRole, "roles_total": 2, "ips": "198.51.100.8",
		"allowlist_subjects": "assume_destination:111122223333"} {
		got := info.Data[k]
		if l, ok := got.([]string); ok {
			got = strings.Join(l, ",")
		}
		if got != want {
			t.Fatalf("info: data.%s = %v, want %v", k, info.Data[k], want)
		}
	}
	// approve が主体として読む項目は info の行に持たせない (行き先の行を主体の承認にしない)
	for _, k := range []string{"caller", "caller_kind", "role_arn", "allowlist_status"} {
		if _, has := info.Data[k]; has {
			t.Fatalf("info: data.%s は出さない", k)
		}
	}
	// 呼び出し元やロールが増えても changed にしない (毎時の窓で顔ぶれが変わる)
	if info.Fingerprint != "info||known-destination" {
		t.Fatalf("info: fingerprint %q", info.Fingerprint)
	}
	if o, ok := by["known-destination:"+scopedAcct]; !ok || o.Data["count"] != 1 || strings.Join(o.Data["allowlist_subjects"].([]string), ",") != "assume_destination:111111111111 roles:ReadOnly" {
		t.Fatalf("ロールを絞った行き先の info: %+v", o)
	}
	if len(by) != len(high)+2 {
		t.Fatalf("keys: %s", keys(obs))
	}
}

// 既知リストに行き先が無ければ、何も変わらない (見出し・data・info の行)。
func TestUnknownAssumeRoleWithoutDestinations(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	if err := st.InsertEvent(ctx, record.TrailEvent{EventID: "o1", Time: now.Add(-time.Hour), Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com",
		PrincipalARN: ownUser, PrincipalKind: record.PrincipalUser, Data: map[string]any{"role_arn": otherRole, "recipient_account": ownAcct, "session_mfa": "true"}, ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	obs, err := UnknownAssumeRole{}.Evaluate(ctx, st, collect.Window{From: now.Add(-24 * time.Hour), To: now}, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Severity != High || !strings.HasSuffix(obs[0].Summary, "(外向き、MFA あり)") {
		t.Fatalf("%+v", obs)
	}
	if _, has := obs[0].Data["destination_status"]; has {
		t.Fatalf("destination_status は行き先が既知リストにあるときだけ: %+v", obs[0].Data)
	}
}

// finding の data (ストアから読み戻した値) で、報告しない条件を満たすかを決める (approve と、既知リストを直した後の解消が使う)。
func TestKnownDestinationOf(t *testing.T) {
	al := knownDests(t)
	base := func(over map[string]any) map[string]any {
		d := map[string]any{"direction": "outbound", "mfa": "true", "role_arn": otherRole, "role_account": otherAcct, "caller": ownUser}
		for k, v := range over {
			d[k] = v
		}
		return d
	}
	cases := []struct {
		name string
		data map[string]any
		want string
	}{
		{"外向き + 既知 + MFA あり", base(nil), "assume_destination:111122223333"},
		{"MFA 不明", base(map[string]any{"mfa": "unknown"}), ""},
		{"MFA なし", base(map[string]any{"mfa": "false"}), ""},
		{"MFA 混在", base(map[string]any{"mfa": "mixed"}), ""},
		{"MFA の項目が無い (以前の版の finding)", base(map[string]any{"mfa": nil}), ""},
		{"MFA の型が違う", base(map[string]any{"mfa": true}), ""},
		{"内向き", base(map[string]any{"direction": "inbound"}), ""},
		{"内部", base(map[string]any{"direction": "internal"}), ""},
		{"向きが無い", base(map[string]any{"direction": nil}), ""},
		{"知らない行き先", base(map[string]any{"role_arn": "arn:aws:iam::444455556666:role/x", "role_account": unknownAcct}), ""},
		{"role_account が role_arn と食い違う", base(map[string]any{"role_account": unknownAcct}), ""},
		{"role_arn がロールの ARN でない", base(map[string]any{"role_arn": "arn:aws:iam::111122223333:user/x"}), ""},
		{"期限切れ", base(map[string]any{"role_arn": "arn:aws:iam::999999999999:role/x", "role_account": expiredAcct}), ""},
		{"絞ったロール", base(map[string]any{"role_arn": "arn:aws:iam::111111111111:role/ReadOnly", "role_account": scopedAcct}), "assume_destination:111111111111 roles:ReadOnly"},
		{"絞ったロールの外", base(map[string]any{"role_arn": "arn:aws:iam::111111111111:role/Admin", "role_account": scopedAcct}), ""},
		{"data が無い", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.data != nil {
				for k, v := range c.data {
					if v == nil {
						delete(c.data, k)
					}
				}
			}
			e, ok := KnownDestinationOf(al, c.data, now)
			if ok != (c.want != "") || (ok && e.Subject() != c.want) {
				t.Fatalf("got %v %+v, want %q", ok, e, c.want)
			}
		})
	}
}

// 報告しない条件は、ログ由来の値 (呼び出し元・ロールの ARN・受け取ったアカウント・MFA の項目) で決まる (ADR 0041・0047)。守る規則:
//   - 行き先が既知になるのは、向きが外向きで、ロールの ARN のアカウントが既知リストに書いた 12 桁と文字どおり同じときだけ
//     (呼び出し元のアカウントが行き先と同じ・内向き・内部・向きが決まらない引き受けは、どんな値でも既知にならない)
//   - finding の data から決める側 (KnownDestinationOf) は、それに加えて mfa が文字どおり true のときだけ満たす。
//     data の role_account が role_arn と食い違えば満たさない
func FuzzKnownDestination(f *testing.F) {
	kinds := []record.PrincipalKind{record.PrincipalUser, record.PrincipalRole, record.PrincipalAssumedRole, record.PrincipalRoot, record.PrincipalService, record.PrincipalUnknown}
	for _, s := range [][4]string{
		{ownUser, otherRole, ownAcct, "true"}, {ownUser, otherRole, ownAcct, "unknown"}, {ownUser, otherRole, ownAcct, "false"}, {ownUser, otherRole, "", "mixed"},
		{ownUser, "arn:aws:iam::444455556666:role/x", ownAcct, "true"}, {otherRoot, ownRole, ownAcct, "true"}, {ownUser, ownRole, "", "true"},
		{ownUser, "arn:aws:iam::111122223333:role/a\nb", ownAcct, "true"}, {ownUser, "arn:aws:iam::1111222233334:role/x", "", "true"},
		{ownUser, "arn:aws:iam::１１１１２２２２３３３３:role/x", "", "true"}, {ownUser, otherRole + "->" + otherRole, ownAcct, "TRUE"},
		{"arn:aws:iam::111122223333:user/x", otherRole, otherAcct, "true"}, {ownUser, "arn:aws:iam::111122223333:role/ReadOnly", ownAcct, "true\n"}, {"", "", "", ""},
	} {
		for i := range kinds {
			f.Add(s[0], uint8(i), s[1], s[2], s[3])
		}
	}
	al, err := allowlist.Parse([]byte("assume_destinations:\n  - account: \"111122223333\"\n    roles: [\"partner-*\", ReadOnly]\n    note: 受託\n  - account: \"111111111111\"\n    note: 受託\n"))
	if err != nil {
		f.Fatal(err)
	}
	listed := map[string]bool{"111122223333": true, "111111111111": true}
	f.Fuzz(func(t *testing.T, caller string, k uint8, role, recipient, mfa string) {
		p := newAssumeParties(caller, kinds[int(k)%len(kinds)], role, recipient)
		e, st := destinationOf(al, p, now)
		if (e == nil) != (st == allowlist.StatusUnknown) || st == allowlist.StatusExpired {
			t.Fatalf("状態と項目が合わない: %s %+v", st, e)
		}
		if st == allowlist.StatusApproved {
			if p.direction != dirOutbound || !listed[p.roleAccount] || e.Account != p.roleAccount || p.callerAccount == p.roleAccount {
				t.Fatalf("外向きでない・書いていないアカウントを既知にした: caller %q role %q recipient %q → %+v", caller, role, recipient, p)
			}
			if !strings.Contains(role, ":iam::"+p.roleAccount+":role/") {
				t.Fatalf("ロールの ARN のアカウントと合わない: %q %+v", role, p)
			}
			if p.roleAccount == "111122223333" && p.roleLabel != "ReadOnly" && !strings.HasPrefix(p.roleLabel, "partner-") {
				t.Fatalf("絞ったロールの外を既知にした: %q", p.roleLabel)
			}
		}
		data := map[string]any{"direction": p.direction, "mfa": mfa, "role_arn": role, "role_account": p.roleAccount}
		de, ok := KnownDestinationOf(al, data, now)
		if ok != (st == allowlist.StatusApproved && mfa == "true") || (ok && de != e) {
			t.Fatalf("data からの判定が合わない: ok %v (行き先 %s、mfa %q)", ok, st, mfa)
		}
		// data の role_account が食い違う・向きが外向きでないなら、満たさない
		data["role_account"] = "999999999999"
		if _, ok := KnownDestinationOf(al, data, now); ok {
			t.Fatal("role_account が role_arn と食い違うのに満たした")
		}
		data["role_account"], data["direction"] = p.roleAccount, dirInbound
		if _, ok := KnownDestinationOf(al, data, now); ok {
			t.Fatal("内向きなのに満たした")
		}
	})
}
