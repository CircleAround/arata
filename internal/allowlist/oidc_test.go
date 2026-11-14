package allowlist

import (
	"strings"
	"testing"
	"time"
)

const oidcYAML = `
oidc_subjects:
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-deploy
    repo: example-org/example-repo
    refs: ["refs/heads/main", "refs/tags/v*"]
    environments: ["production"]
    note: 本番のデプロイ
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-nightly
    repo: example-org/example-repo
    refs: ["refs/heads/main"]
    hours: ["18:00-19:00", "23:30-00:30"]
    source_ips: ["203.0.113.0/24"]
    note: 夜間の定期実行
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-ci
    repo: example-org/example-repo
    pull_request: true
    note: PR の検査
    expires: 2026-10-31
  - provider: oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789
    role: arn:aws:iam::123456789012:role/app-irsa
    note: クラスタのサービスアカウント
`

func TestOIDCSubjects(t *testing.T) {
	l, err := Parse([]byte(oidcYAML))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	const gh = "token.actions.githubusercontent.com"
	const deploy = "arn:aws:iam::123456789012:role/gha-deploy"
	for _, tc := range []struct {
		name string
		a    OIDCAssume
		want Status
	}{
		{"ブランチ", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}, StatusApproved},
		{"タグの glob", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/tags/v1.2.3"}, StatusApproved},
		{"environment", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "environment", Environment: "production"}, StatusApproved},
		{"リポジトリの大文字小文字は区別しない", OIDCAssume{Provider: gh, Role: deploy, Repo: "Example-Org/Example-Repo", Kind: "ref", Ref: "refs/heads/main"}, StatusApproved},
		{"知らないブランチ", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/feature"}, StatusUnknown},
		{"ref の glob は先頭から末尾まで", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main2"}, StatusUnknown},
		{"知らない environment", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "environment", Environment: "staging"}, StatusUnknown},
		{"environment の名前は ref に一致しない", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "environment", Environment: "refs/heads/main"}, StatusUnknown},
		{"pull_request は書いた項目だけ", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "pull_request"}, StatusUnknown},
		{"知らないリポジトリ", OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/other-repo", Kind: "ref", Ref: "refs/heads/main"}, StatusUnknown},
		{"読めない sub", OIDCAssume{Provider: gh, Role: deploy}, StatusUnknown},
		{"別のロール", OIDCAssume{Provider: gh, Role: "arn:aws:iam::123456789012:role/admin", Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}, StatusUnknown},
		{"期限切れ", OIDCAssume{Provider: gh, Role: "arn:aws:iam::123456789012:role/gha-ci", Repo: "example-org/example-repo", Kind: "pull_request"}, StatusExpired},
		{"GitHub 以外", OIDCAssume{Provider: "oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789", Role: "arn:aws:iam::123456789012:role/app-irsa"}, StatusApproved},
		{"GitHub 以外の項目は GitHub の引き受けを既知にしない", OIDCAssume{Provider: gh, Role: "arn:aws:iam::123456789012:role/app-irsa", Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}, StatusUnknown},
		{"別のプロバイダ", OIDCAssume{Provider: "cognito-identity.amazonaws.com", Role: deploy}, StatusUnknown},
	} {
		if _, st := l.OIDCSubject(tc.a, at); st != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, st, tc.want)
		}
	}
	// ロールが既知か (期限内の項目にあるか)
	for role, want := range map[string]bool{deploy: true, "arn:aws:iam::123456789012:role/app-irsa": true, "arn:aws:iam::123456789012:role/gha-ci": false, "arn:aws:iam::123456789012:role/admin": false, "": false} {
		if got := l.OIDCRoleKnown(role, at); got != want {
			t.Errorf("OIDCRoleKnown(%q) = %v", role, got)
		}
	}
	// 時間帯 (UTC。日をまたぐ書き方も可) と送信元
	es, st := l.OIDCSubject(OIDCAssume{Provider: gh, Role: "arn:aws:iam::123456789012:role/gha-nightly", Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}, at)
	if st != StatusApproved || len(es) != 1 {
		t.Fatal(st, es)
	}
	day := func(h, m int) time.Time { return time.Date(2026, 11, 13, h, m, 0, 0, time.UTC) }
	for _, tc := range []struct {
		at           time.Time
		ip           string
		hours, srcOK bool
	}{
		{day(18, 0), "203.0.113.9", true, true},
		{day(18, 59), "203.0.113.9", true, true},
		{day(19, 0), "203.0.113.9", false, true},
		{day(23, 45), "198.51.100.1", true, false},
		{day(0, 29), "", true, false},
		{day(0, 30), "x", false, false},
		{day(3, 0).In(time.FixedZone("JST", 9*3600)), "203.0.113.9", false, true},
	} {
		if h, s := es[0].InHours(tc.at), es[0].SourceAllowed(tc.ip); h != tc.hours || s != tc.srcOK {
			t.Errorf("%s %q: hours %v source %v", tc.at.Format("15:04"), tc.ip, h, s)
		}
	}
	// 書かなければ見ない
	es, _ = l.OIDCSubject(OIDCAssume{Provider: gh, Role: deploy, Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}, at)
	if !es[0].InHours(day(3, 0)) || !es[0].SourceAllowed("198.51.100.1") || !es[0].SourceAllowed("") {
		t.Error("hours / source_ips を書いていない項目が外と判定した")
	}
	if got := es[0].Subject(); got != "oidc_subject:token.actions.githubusercontent.com example-org/example-repo -> "+deploy {
		t.Errorf("Subject: %q", got)
	}
}

func TestOIDCSubjectsInvalid(t *testing.T) {
	const head = "oidc_subjects:\n  - provider: token.actions.githubusercontent.com\n    role: arn:aws:iam::123456789012:role/gha-deploy\n"
	for _, tc := range []struct{ name, yaml, want string }{
		{"provider なし", "oidc_subjects:\n  - role: arn:aws:iam::123456789012:role/x\n    note: n\n", "provider"},
		{"provider が ARN", "oidc_subjects:\n  - provider: arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\n    role: arn:aws:iam::123456789012:role/x\n    note: n\n", "provider"},
		{"role が ARN でない", "oidc_subjects:\n  - provider: token.actions.githubusercontent.com\n    role: gha-deploy\n    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n", "role"},
		{"role に glob", "oidc_subjects:\n  - provider: token.actions.githubusercontent.com\n    role: arn:aws:iam::123456789012:role/*\n    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n", "role"},
		{"GitHub で repo なし", head + "    refs: [\"refs/heads/main\"]\n    note: n\n", "repo"},
		{"repo に glob", head + "    repo: example-org/*\n    refs: [\"refs/heads/main\"]\n    note: n\n", "repo"},
		{"入り口なし", head + "    repo: example-org/example-repo\n    note: n\n", "refs, environments"},
		{"pull_request: false だけ", head + "    repo: example-org/example-repo\n    pull_request: false\n    note: n\n", "refs, environments"},
		{"空の refs", head + "    repo: example-org/example-repo\n    refs: []\n    pull_request: true\n    note: n\n", "refs is empty"},
		{"refs が refs/ で始まらない", head + "    repo: example-org/example-repo\n    refs: [\"main\"]\n    note: n\n", "refs[0]"},
		{"refs に空白", head + "    repo: example-org/example-repo\n    refs: [\"refs/heads/a b\"]\n    note: n\n", "refs[0]"},
		{"environment に glob", head + "    repo: example-org/example-repo\n    environments: [\"prod*\"]\n    note: n\n", "environments[0]"},
		{"note なし", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n", "note"},
		{"expires の形", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n    expires: 2026/12/31\n", "expires"},
		{"hours の形", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n    hours: [\"9-10\"]\n", "hours[0]"},
		{"hours の範囲", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n    hours: [\"24:00-25:00\"]\n", "hours[0]"},
		{"hours の始まりと終わりが同じ", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n    hours: [\"09:00-09:00\"]\n", "hours[0]"},
		{"source_ips の形", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n    source_ips: [\"203.0.113.1\"]\n", "source_ips[0]"},
		{"GitHub 以外に repo", "oidc_subjects:\n  - provider: cognito-identity.amazonaws.com\n    role: arn:aws:iam::123456789012:role/x\n    repo: example-org/example-repo\n    note: n\n", "only for token.actions.githubusercontent.com"},
		{"知らないキー", head + "    repo: example-org/example-repo\n    refs: [\"*\"]\n    note: n\n    workflow: x\n", "workflow"},
	} {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", tc.name, err, tc.want)
		}
	}
}

func TestCheckOIDCSubjects(t *testing.T) {
	at := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	dup := oidcYAML + "  - provider: token.actions.githubusercontent.com\n    role: arn:aws:iam::123456789012:role/gha-deploy\n    repo: Example-Org/example-repo\n    environments: [\"production\"]\n    refs: [\"refs/tags/v*\", \"refs/heads/main\"]\n    note: 重複\n"
	l, ps := Check([]byte(dup), at)
	if l == nil || len(ps) != 2 {
		t.Fatalf("%+v", ps)
	}
	if !ps[0].Warn || ps[0].Line != 16 || !strings.Contains(ps[0].Msg, "oidc_subjects[2]: expired on 2026-10-31") {
		t.Errorf("%+v", ps[0])
	}
	if !ps[1].Warn || !strings.Contains(ps[1].Msg, "oidc_subjects[4]: duplicate of oidc_subjects[0] (line 3)") {
		t.Errorf("%+v", ps[1])
	}
	_, ps = Check([]byte("oidc_subjects:\n  - provider: x\n"), at)
	if len(ps) != 1 || ps[0].Warn || ps[0].Line != 2 {
		t.Errorf("%+v", ps)
	}
}
