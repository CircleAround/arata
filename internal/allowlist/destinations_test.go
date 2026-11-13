package allowlist

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// 外向きの引き受けの「行き先として既知のアカウント」(assume_destinations。ADR 0047)。
const destSample = `
principals:
  - account: "123456789012"
    note: 呼び出し元として既知 (行き先ではない)
assume_destinations:
  - account: "111122223333"
    note: 運用を受託しているアカウント
    approved_by: alice
    approved_at: 2026-11-13
  - account: "444455556666"
    note: 期限付きの受託
    expires: 2026-12-31
  - account: "999999999999"
    roles: ["ops-*", "support/ReadOnly"]
    note: 決まったロールだけ
  - account: "111111111111"
    note: 以前はアカウント全体
    expires: 2026-10-31
  - account: "111111111111"
    roles: ["ReadOnly"]
    note: 今は読み取りだけ
`

func TestAssumeDestination(t *testing.T) {
	l := load(t, destSample)
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name          string
		account, role string
		at            time.Time
		want          Status
		subject       string
	}{
		{"既知の行き先", "111122223333", "partner-admin", at, StatusApproved, "assume_destination:111122223333"},
		{"期限の日の終わりまで有効", "444455556666", "x", time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC), StatusApproved, "assume_destination:444455556666"},
		{"期限を過ぎた", "444455556666", "x", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), StatusExpired, "assume_destination:444455556666"},
		{"ロールを絞った項目: glob に一致", "999999999999", "ops-deploy", at, StatusApproved, "assume_destination:999999999999 roles:ops-*,support/ReadOnly"},
		{"ロールを絞った項目: パス付きの名前に一致", "999999999999", "support/ReadOnly", at, StatusApproved, "assume_destination:999999999999 roles:ops-*,support/ReadOnly"},
		{"ロールを絞った項目: 一致しないロールは既知でない", "999999999999", "Admin", at, StatusUnknown, ""},
		{"ロールを絞った項目: 前方一致では通さない (先頭から末尾まで)", "999999999999", "xops-deploy", at, StatusUnknown, ""},
		{"期限切れの項目と有効な項目: 有効な項目に一致するロール", "111111111111", "ReadOnly", at, StatusApproved, "assume_destination:111111111111 roles:ReadOnly"},
		{"期限切れの項目と有効な項目: ほかのロールは期限切れ", "111111111111", "Admin", at, StatusExpired, "assume_destination:111111111111"},
		// principals の account: は呼び出し元の承認。行き先を既知にしない (混同しない)。書いていないアカウントも同じ
		{"principals の account: は行き先にならない", "123456789012", "x", at, StatusUnknown, ""},
		{"アカウントが空", "", "x", at, StatusUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, st := l.AssumeDestination(c.account, c.role, c.at)
			if st != c.want {
				t.Fatalf("status = %s, want %s", st, c.want)
			}
			if (e == nil) != (c.want == StatusUnknown) {
				t.Fatalf("entry = %+v (status %s)", e, st)
			}
			if e != nil && e.Subject() != c.subject {
				t.Fatalf("subject = %q, want %q", e.Subject(), c.subject)
			}
		})
	}
	// 逆も同じ: 行き先として既知でも、そのアカウントの主体 (呼び出し元) は承認されない
	if _, st := l.Principal("arn:aws:iam::111122223333:root", at); st != StatusUnknown {
		t.Fatalf("assume_destinations が呼び出し元を承認した: %s", st)
	}
	if st := l.Account("111122223333", at); st != StatusUnknown {
		t.Fatalf("assume_destinations が account: の承認になった: %s", st)
	}
}

func TestAssumeDestinationOnEmptyList(t *testing.T) {
	var zero List
	if e, st := zero.AssumeDestination("111122223333", "x", time.Now()); e != nil || st != StatusUnknown {
		t.Fatalf("空の List: %+v %s", e, st)
	}
}

func TestAssumeDestinationsValidation(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"account が無い", "assume_destinations:\n  - note: n\n", `assume_destinations[0]: account "": want a 12-digit account ID`},
		{"11 桁", "assume_destinations:\n  - account: \"11112222333\"\n    note: n\n", "want a 12-digit account ID"},
		{"ARN", "assume_destinations:\n  - account: arn:aws:iam::111122223333:root\n    note: n\n", "want a 12-digit account ID"},
		{"全角の数字", "assume_destinations:\n  - account: \"１１１１２２２２３３３３\"\n    note: n\n", "want a 12-digit account ID"},
		{"note が無い", "assume_destinations:\n  - account: \"111122223333\"\n", "assume_destinations[0]: note is required"},
		{"note が空白", "assume_destinations:\n  - account: \"111122223333\"\n    note: \"  \"\n", "note is required"},
		{"expires の形", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    expires: 2026/12/31\n", `expires "2026/12/31": want YYYY-MM-DD`},
		{"roles が空", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    roles: []\n", "roles is empty"},
		{"roles に ARN", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    roles: [\"arn:aws:iam::111122223333:role/ops\"]\n", "roles[0]"},
		{"roles に role/ を付けた", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    roles: [\"ops\", \"role/ops\"]\n", "roles[1]"},
		{"roles に空白", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    roles: [\"ops admin\"]\n", "roles[0]"},
		{"roles に空の文字列", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    roles: [\"\"]\n", "roles[0]"},
		{"2 つ目の項目", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n  - account: \"1\"\n    note: n\n", "assume_destinations[1]: account"},
		// principals の書き方 (arn / arn_pattern / tags) は使えない。知らないキーは読み込みで止める
		{"arn_pattern は書けない", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    arn_pattern: arn:aws:iam::111122223333:role/*\n", "field arn_pattern not found"},
		{"tags は書けない", "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    tags: [deploy]\n", "field tags not found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, err := Parse([]byte(c.body))
			if err == nil || l != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestCheckAssumeDestinations(t *testing.T) {
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name, body string
		want       []Problem
	}{
		{name: "ok", body: "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    expires: 2026-11-13\n"},
		{name: "項目のエラーには行を添える",
			body: "principals: []\nassume_destinations:\n  - account: \"111122223333\"\n    note: n\n  - account: \"111122223333\"\n",
			want: []Problem{{Line: 5, Msg: "assume_destinations[1]: note is required"}}},
		{name: "同じアカウントの重複は警告",
			body: "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n  - account: \"444455556666\"\n    note: n\n  - account: \"111122223333\"\n    note: m\n",
			want: []Problem{{Line: 6, Warn: true, Msg: "assume_destinations[2]: duplicate of assume_destinations[0] (line 2): account 111122223333"}}},
		{name: "アカウント全体の項目があるのにロールを絞った項目 (絞れていない) は警告",
			body: "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n  - account: \"111122223333\"\n    roles: [ReadOnly]\n    note: m\n",
			want: []Problem{{Line: 4, Warn: true, Msg: "assume_destinations[1]: duplicate of assume_destinations[0] (line 2): account 111122223333"}}},
		{name: "違うロールに絞った項目どうしは重複でない",
			body: "assume_destinations:\n  - account: \"111122223333\"\n    roles: [ReadOnly]\n    note: n\n  - account: \"111122223333\"\n    roles: [Support]\n    note: m\n"},
		{name: "同じロールに絞った項目どうしは重複",
			body: "assume_destinations:\n  - account: \"111122223333\"\n    roles: [ReadOnly]\n    note: n\n  - account: \"111122223333\"\n    roles: [ReadOnly]\n    note: m\n",
			want: []Problem{{Line: 5, Warn: true, Msg: "assume_destinations[1]: duplicate of assume_destinations[0]"}}},
		{name: "期限切れは警告 (run は止めない。次の run から high で報告される)",
			body: "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n    expires: 2026-11-12\n",
			want: []Problem{{Line: 2, Warn: true, Msg: "assume_destinations[0]: expired on 2026-11-12: account 111122223333"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, got := Check([]byte(tc.body), at)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			errs := 0
			for i, w := range tc.want {
				if got[i].Line != w.Line || got[i].Warn != w.Warn || !strings.Contains(got[i].Msg, w.Msg) {
					t.Errorf("[%d] got %+v, want %+v", i, got[i], w)
				}
				if !w.Warn {
					errs++
				}
			}
			if (l == nil) != (errs > 0) {
				t.Fatalf("エラーがあるときだけ List は nil: %+v", got)
			}
		})
	}
}

var dest = NewDestination{Account: "111122223333", Note: "運用を受託: 契約 #2", ApprovedBy: "alice", ApprovedAt: "2026-11-13", Expires: "2027-03-31"}

const destRendered = `  - account: "111122223333"
    note: '運用を受託: 契約 #2'
    approved_by: alice
    approved_at: 2026-11-13
    expires: 2027-03-31
`

func TestAppendDestination(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"節が無ければ末尾に足す",
			"# 既知リスト\nprincipals:\n  - arn: arn:aws:iam::123456789012:role/Deploy   # コメント\n\nsource_ips:\n  - cidr: 203.0.113.0/24\n",
			"# 既知リスト\nprincipals:\n  - arn: arn:aws:iam::123456789012:role/Deploy   # コメント\n\nsource_ips:\n  - cidr: 203.0.113.0/24\n\nassume_destinations:\n" + destRendered},
		{"空のファイル", "", "assume_destinations:\n" + destRendered},
		{"節の末尾に足す (principals もほかの行も変えない)",
			"assume_destinations:\n    # 受託先\n    - account: \"444455556666\"\n      note: n   # 行末\n\n# 主体\nprincipals:\n  - account: \"111122223333\"\n",
			"assume_destinations:\n    # 受託先\n    - account: \"444455556666\"\n      note: n   # 行末\n" +
				"    - account: \"111122223333\"\n      note: '運用を受託: 契約 #2'\n      approved_by: alice\n      approved_at: 2026-11-13\n      expires: 2027-03-31\n" +
				"\n# 主体\nprincipals:\n  - account: \"111122223333\"\n"},
		{"空の列", "principals: []\nassume_destinations: []   # まだ無い\n", "principals: []\nassume_destinations: # まだ無い\n" + destRendered},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, added, err := AppendDestinationBytes([]byte(c.src), dest)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != c.want {
				t.Fatalf("got:\n%s\nwant:\n%s", out, c.want)
			}
			if !strings.Contains(string(out), added) || !strings.Contains(added, `account: "111122223333"`) {
				t.Fatalf("added = %q", added)
			}
			l, err := Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			if _, st := l.AssumeDestination("111122223333", "any", time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)); st != StatusApproved {
				t.Fatalf("足した行き先が既知にならない: %s", st)
			}
		})
	}
}

func TestAppendDestinationRoles(t *testing.T) {
	d := NewDestination{Account: "111122223333", Roles: []string{"ops-*", "support/ReadOnly"}, Note: "受託", ApprovedAt: "2026-11-13"}
	out, added, err := AppendDestinationBytes(nil, d)
	if err != nil {
		t.Fatal(err)
	}
	want := "  - account: \"111122223333\"\n    roles: [\"ops-*\", \"support/ReadOnly\"]\n    note: 受託\n    approved_at: 2026-11-13\n"
	if added != want {
		t.Fatalf("added:\n%s\nwant:\n%s", added, want)
	}
	l, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	if _, st := l.AssumeDestination("111122223333", "ops-x", at); st != StatusApproved {
		t.Fatal(st)
	}
	if _, st := l.AssumeDestination("111122223333", "Admin", at); st != StatusUnknown {
		t.Fatal(st)
	}
}

func TestAppendDestinationRejects(t *testing.T) {
	listed := "assume_destinations:\n  - account: \"111122223333\"\n    note: n\n"
	scoped := "assume_destinations:\n  - account: \"111122223333\"\n    roles: [ReadOnly]\n    note: n\n"
	cases := []struct {
		name string
		src  string
		d    NewDestination
		want string
		is   error
	}{
		{"同じアカウントが既にある", listed, dest, "already listed", ErrAlreadyListed},
		{"アカウント全体の項目があるのにロールを足す (既に含まれる)", listed, NewDestination{Account: "111122223333", Roles: []string{"ops"}, Note: "n"}, "already listed", ErrAlreadyListed},
		{"ロールを絞った項目があるのにアカウント全体を足す (広げるのは人が項目を直す)", scoped, NewDestination{Account: "111122223333", Note: "n"}, "already listed", ErrAlreadyListed},
		{"同じロールの項目が既にある", scoped, NewDestination{Account: "111122223333", Roles: []string{"ReadOnly"}, Note: "n"}, "already listed", ErrAlreadyListed},
		{"account が 12 桁でない", "", NewDestination{Account: "1111", Note: "n"}, "12-digit", nil},
		{"account に YAML の記法", "", NewDestination{Account: "111122223333\"\n  - account: \"999999999999", Note: "n"}, "12-digit", nil},
		{"note が無い", "", NewDestination{Account: "111122223333"}, "note is required", nil},
		{"roles の形", "", NewDestination{Account: "111122223333", Roles: []string{"a b"}, Note: "n"}, "roles[0]", nil},
		{"フロー形式の列は書き換えない", "assume_destinations: [{account: \"444455556666\", note: n}]\n", dest, "flow style", nil},
		{"今のファイルが読めない", "assume_destinations:\n  - account: x\n", dest, "current file is invalid", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, err := AppendDestinationBytes([]byte(c.src), c.d)
			if err == nil || out != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v (out %q), want %q", err, out, c.want)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Fatalf("err = %v, want %v", err, c.is)
			}
		})
	}
	// ロールを絞った項目があるアカウントに、別のロールは足せる
	if _, _, err := AppendDestinationBytes([]byte(scoped), NewDestination{Account: "111122223333", Roles: []string{"Support"}, Note: "n"}); err != nil {
		t.Fatal(err)
	}
}
