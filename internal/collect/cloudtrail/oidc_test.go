package cloudtrail

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/record"
)

func TestParseGitHubSub(t *testing.T) {
	for _, tc := range []struct {
		sub  string
		want record.GitHubSub
		ok   bool
	}{
		{"repo:example-org/example-repo:ref:refs/heads/main", record.GitHubSub{Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/heads/main"}, true},
		{"repo:example-org@1234567/example-repo@7654321:ref:refs/heads/main", record.GitHubSub{Repo: "example-org/example-repo", OwnerID: "1234567", RepoID: "7654321", Kind: "ref", Ref: "refs/heads/main"}, true},
		{"repo:example-org/example-repo:ref:refs/tags/v1.2.3", record.GitHubSub{Repo: "example-org/example-repo", Kind: "ref", Ref: "refs/tags/v1.2.3"}, true},
		{"repo:example-org/example.repo_1:environment:production", record.GitHubSub{Repo: "example-org/example.repo_1", Kind: "environment", Environment: "production"}, true},
		{"repo:example-org@1/example-repo@2:environment:Production East", record.GitHubSub{Repo: "example-org/example-repo", OwnerID: "1", RepoID: "2", Kind: "environment", Environment: "Production East"}, true},
		{"repo:example-org/example-repo:pull_request", record.GitHubSub{Repo: "example-org/example-repo", Kind: "pull_request"}, true},
		// 読めない形
		{"", record.GitHubSub{}, false},
		{"repo:example-org/example-repo", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:ref:main", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:ref:refs/heads/a b", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:ref:refs/heads/<!here>", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:ref:refs/heads/main\n", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:environment: production", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:environment:a:b", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:pull_request:x", record.GitHubSub{}, false},
		{"repo:example-org@x/example-repo:ref:refs/heads/main", record.GitHubSub{}, false},
		{"repo:-org/example-repo:ref:refs/heads/main", record.GitHubSub{}, false},
		{"repo:example-org/a/b:ref:refs/heads/main", record.GitHubSub{}, false},
		{"repository_owner:example-org:job_workflow_ref:example-org/example-repo/.github/workflows/x.yml@refs/heads/main", record.GitHubSub{}, false},
		{"repo:example-org/example-repo:ref:refs/heads/" + strings.Repeat("a", record.MaxOIDCSub), record.GitHubSub{}, false},
	} {
		got, ok := record.ParseGitHubSub(tc.sub)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %+v %v, want %+v %v", tc.sub, got, ok, tc.want, tc.ok)
		}
	}
}

func oidcBody(provider, sub, role, agent string) string {
	b, _ := json.Marshal(map[string]any{
		"userIdentity":       map[string]any{"type": "WebIdentityUser", "principalId": provider + ":sts.amazonaws.com:" + sub, "userName": sub, "identityProvider": provider},
		"eventSource":        "sts.amazonaws.com",
		"eventName":          "AssumeRoleWithWebIdentity",
		"sourceIPAddress":    "203.0.113.9",
		"userAgent":          agent,
		"recipientAccountId": "123456789012",
		"requestParameters":  map[string]any{"roleArn": role, "roleSessionName": "GitHubActions"},
		"readOnly":           true,
	})
	return string(b)
}

const (
	ghProvider = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
	ghAgent    = "aws-sdk-js/3.0 ua/2.1 os/linux lang/js md/nodejs#24 api/sts exec-env/GitHubActions md/run_id#19283746501 m/E"
)

func TestNormalizeOIDCAssume(t *testing.T) {
	c := New("trail")
	const role = "arn:aws:iam::123456789012:role/gha-deploy"
	for _, tc := range []struct {
		name string
		body string
		want map[string]any
		none []string
	}{
		{"GitHub", oidcBody(ghProvider, "repo:example-org@1234567/example-repo@7654321:ref:refs/heads/main", role, ghAgent),
			map[string]any{"oidc_provider": "token.actions.githubusercontent.com", "oidc_provider_account": "123456789012", "oidc_sub_form": "github",
				"oidc_repo": "example-org/example-repo", "oidc_owner_id": "1234567", "oidc_repo_id": "7654321", "oidc_sub_kind": "ref", "oidc_ref": "refs/heads/main",
				"role_arn": role, "gha_run_id": "19283746501"},
			[]string{"oidc_environment"}},
		{"environment", oidcBody(ghProvider, "repo:example-org/example-repo:environment:production", role, "curl/8"),
			map[string]any{"oidc_sub_form": "github", "oidc_sub_kind": "environment", "oidc_environment": "production"},
			[]string{"oidc_ref", "gha_run_id", "oidc_owner_id"}},
		{"読めない sub は値を残さない", oidcBody(ghProvider, "repository_owner:example-org:x <!here>", role, "exec-env/GitHubActions md/run_id#abc"),
			map[string]any{"oidc_provider": "token.actions.githubusercontent.com", "oidc_sub_form": "unparsed"},
			[]string{"oidc_repo", "oidc_sub_kind", "gha_run_id"}},
		// run_id は GitHub Actions の実行と名乗る userAgent のときだけ
		{"run_id だけ", oidcBody(ghProvider, "repo:example-org/example-repo:pull_request", role, "md/run_id#123"),
			map[string]any{"oidc_sub_kind": "pull_request"}, []string{"gha_run_id"}},
		{"GitHub 以外は sub を読まない", oidcBody("arn:aws:iam::123456789012:oidc-provider/oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789", "system:serviceaccount:default:app", role, ghAgent),
			map[string]any{"oidc_provider": "oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789", "oidc_provider_account": "123456789012", "oidc_sub_form": "not_read"},
			[]string{"oidc_repo", "oidc_sub_kind", "gha_run_id"}},
		{"ARN でないプロバイダ", oidcBody("cognito-identity.amazonaws.com", "ap-northeast-1:00000000-0000-0000-0000-000000000000", role, ""),
			map[string]any{"oidc_provider": "cognito-identity.amazonaws.com", "oidc_sub_form": "not_read"}, []string{"oidc_provider_account"}},
		{"読めないプロバイダ", oidcBody("x <!here>", "repo:example-org/example-repo:pull_request", role, ""),
			map[string]any{"oidc_provider": "unparsed", "oidc_sub_form": "not_read"}, []string{"oidc_repo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := c.normalize(ev("e-1", fuzzEventTime, tc.body))
			if !ok {
				t.Fatal("not normalized")
			}
			// 主体は空のまま (sub を主体にしない。ADR 0055)
			if e.PrincipalARN != "" || e.PrincipalKind != record.PrincipalAssumedRole || e.IP != "203.0.113.9" {
				t.Fatalf("%+v", e)
			}
			for k, v := range tc.want {
				if e.Data[k] != v {
					t.Errorf("data.%s = %v, want %v", k, e.Data[k], v)
				}
			}
			for _, k := range tc.none {
				if _, has := e.Data[k]; has {
					t.Errorf("data.%s があってはいけない: %v", k, e.Data[k])
				}
			}
			// sub そのもの・セッション名は残さない
			for k, v := range e.Data {
				if s, _ := v.(string); strings.HasPrefix(s, "repo:") || strings.Contains(s, "serviceaccount") || s == "GitHubActions" || strings.Contains(s, "here") {
					t.Errorf("data.%s に生の値: %q", k, s)
				}
			}
		})
	}
	// 信頼ポリシーが止めた引き受けの記録 (実際の形): requestParameters が null で roleArn が無い。sub とプロバイダは読める
	denied := `{"userIdentity":{"type":"WebIdentityUser","principalId":"` + ghProvider + `:sts.amazonaws.com:repo:example-org@1234567/example-repo@7654321:ref:refs/heads/work",
	  "userName":"repo:example-org@1234567/example-repo@7654321:ref:refs/heads/work","identityProvider":"` + ghProvider + `"},
	  "eventSource":"sts.amazonaws.com","eventName":"AssumeRoleWithWebIdentity","sourceIPAddress":"203.0.113.30","userAgent":"` + ghAgent + `",
	  "errorCode":"AccessDenied","errorMessage":"Not authorized to perform sts:AssumeRoleWithWebIdentity","requestParameters":null,"responseElements":null,"recipientAccountId":"123456789012","readOnly":true}`
	d, ok := c.normalize(ev("e-denied", fuzzEventTime, denied))
	if !ok || d.ErrorCode != "AccessDenied" || d.PrincipalARN != "" || d.Data["oidc_sub_form"] != "github" || d.Data["oidc_repo"] != "example-org/example-repo" ||
		d.Data["oidc_ref"] != "refs/heads/work" || d.Data["oidc_owner_id"] != "1234567" || d.Data["gha_run_id"] != "19283746501" || d.Data["oidc_provider_account"] != "123456789012" {
		t.Fatalf("%+v", d)
	}
	if _, has := d.Data["role_arn"]; has {
		t.Fatalf("role_arn: %v", d.Data["role_arn"])
	}
	// ほかの AssumeRole には付けない
	e, _ := c.normalize(ev("e-2", fuzzEventTime, assumeRole))
	for k := range e.Data {
		if strings.HasPrefix(k, "oidc_") || k == "gha_run_id" {
			t.Fatalf("AssumeRole に %s", k)
		}
	}
}
