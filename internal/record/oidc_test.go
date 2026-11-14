package record

import (
	"strings"
	"testing"
)

func TestOIDCProvider(t *testing.T) {
	for _, tc := range []struct{ in, name, account string }{
		{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", GitHubOIDCProvider, "123456789012"},
		{"arn:aws:iam::123456789012:oidc-provider/oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789", "oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789", "123456789012"},
		{"cognito-identity.amazonaws.com", "cognito-identity.amazonaws.com", ""},
		{"accounts.google.com", "accounts.google.com", ""},
		{"", OIDCProviderUnparsed, ""},
		{"unparsed", OIDCProviderUnparsed, ""},
		{"arn:aws:iam::123456789012:oidc-provider/x y.example.com", OIDCProviderUnparsed, ""},
		{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\n", OIDCProviderUnparsed, ""},
		{"<!here>.example.com", OIDCProviderUnparsed, ""},
	} {
		if name, account := OIDCProvider(tc.in); name != tc.name || account != tc.account {
			t.Errorf("%q: got %q %q", tc.in, name, account)
		}
	}
}

func TestGitHubRunID(t *testing.T) {
	for _, tc := range []struct {
		ua, id string
		ok     bool
	}{
		{"aws-sdk-js/3.0 exec-env/GitHubActions md/run_id#19283746501 m/E", "19283746501", true},
		{"exec-env/GitHubActions md/run_id#1", "1", true},
		{"md/run_id#1", "", false},
		{"exec-env/GitHubActions md/run_id#abc", "", false},
		{"exec-env/GitHubActions xmd/run_id#1", "", false},
		{"exec-env/GitHubActions md/run_id#" + strings.Repeat("1", 21), "", false},
	} {
		if id, ok := GitHubRunID(tc.ua); id != tc.id || ok != tc.ok {
			t.Errorf("%q: got %q %v", tc.ua, id, ok)
		}
	}
}

// ファズテスト (ADR 0041・0055)。sub・プロバイダ・userAgent はログ由来の値。守る規則:
//   - パニックしない。読めなかったら値を返さない
//   - 読めた各部分は決まった形 (リポジトリ・ref・environment・数字の ID) で、空白の始まりと終わり・改行・制御文字・`<` `>` を含まない
//   - 正規化した形 (Normalized) は元の sub から ID だけを外したもので、読み直すと同じ組になる (ID 入りと ID なしが同じ組になる)
//   - プロバイダの名前は決まった形か unparsed、アカウントは 12 桁の数字か空。run_id は数字だけ
func FuzzParseGitHubSub(f *testing.F) {
	for _, s := range []string{
		"repo:example-org/example-repo:ref:refs/heads/main", "repo:example-org@1234567/example-repo@7654321:ref:refs/heads/main",
		"repo:example-org/example-repo:environment:Production East", "repo:example-org/example-repo:pull_request",
		"repo:example-org/example-repo:ref:refs/heads/main\n", "repo:a/b:environment:x:ref:refs/heads/main", "repo:a@/b:pull_request", "",
		"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", "exec-env/GitHubActions md/run_id#19283746501",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sub, ok := ParseGitHubSub(s)
		if !ok {
			if sub != (GitHubSub{}) {
				t.Fatalf("読めないのに値がある: %+v", sub)
			}
		} else {
			if !ValidGitHubRepo(sub.Repo) || len(s) > MaxOIDCSub {
				t.Fatalf("リポジトリが決まった形でない: %+v", sub)
			}
			for _, id := range []string{sub.OwnerID, sub.RepoID} {
				if strings.Trim(id, "0123456789") != "" {
					t.Fatalf("ID が数字でない: %+v", sub)
				}
			}
			switch sub.Kind {
			case OIDCKindRef:
				if !ValidGitRef(sub.Ref) || sub.Environment != "" {
					t.Fatalf("%+v", sub)
				}
			case OIDCKindEnvironment:
				if !ValidGitHubEnvironment(sub.Environment) || sub.Ref != "" || strings.TrimSpace(sub.Environment) != sub.Environment {
					t.Fatalf("%+v", sub)
				}
			case OIDCKindPullRequest:
				if sub.Ref != "" || sub.Environment != "" {
					t.Fatalf("%+v", sub)
				}
			default:
				t.Fatalf("知らない種類: %+v", sub)
			}
			n := sub.Normalized()
			if strings.ContainsAny(n, "\n\r\t<>@") && sub.Kind != OIDCKindRef || strings.ContainsAny(n, "\n\r\t<>") {
				t.Fatalf("正規化した sub に出してはいけない文字: %q", n)
			}
			again, ok := ParseGitHubSub(n)
			want := sub
			want.OwnerID, want.RepoID = "", ""
			if !ok || again != want {
				t.Fatalf("正規化した形を読み直すと違う組になる: %q → %+v (元 %+v)", n, again, sub)
			}
			// ID を外した形と元の sub は、ID の部分だけが違う
			if sub.OwnerID == "" && sub.RepoID == "" && n != s {
				t.Fatalf("ID の無い sub が正規化で変わった: %q → %q", s, n)
			}
		}
		name, account := OIDCProvider(s)
		if name != OIDCProviderUnparsed && !ValidOIDCProvider(name) || strings.ContainsAny(name, " \n\r\t<>") {
			t.Fatalf("プロバイダの名前が決まった形でない: %q", name)
		}
		if account != "" && (len(account) != 12 || strings.Trim(account, "0123456789") != "" || name == OIDCProviderUnparsed) {
			t.Fatalf("プロバイダのアカウントが規則に合わない: %q (%q)", account, name)
		}
		if id, ok := GitHubRunID(s); ok != (id != "") || strings.Trim(id, "0123456789") != "" || len(id) > 20 {
			t.Fatalf("run_id が数字でない: %q", id)
		}
	})
}
