package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/CircleAround/arata/internal/config"
)

// fakeSTS は AssumeRole に固定の認証情報を返し、署名に使われたアクセスキーを記録する (実 AWS に接続しない)。
func fakeSTS(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var signedBy []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		signedBy = append(signedBy, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/arata-readonly/s</Arn><AssumedRoleId>AROAEXAMPLE:s</AssumedRoleId></AssumedRoleUser>
<Credentials><AccessKeyId>AKIAAUDIT</AccessKeyId><SecretAccessKey>audit-secret</SecretAccessKey><SessionToken>audit-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
</AssumeRoleResult></AssumeRoleResponse>`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), signedBy...)
	}
}

// actionsEnv は configure-aws-credentials が実行用ロールの認証情報を環境変数に置き、
// arata repo init が書き出す arata-audit.yml (見本は examples/audit-repo) が AWS_CONFIG_FILE を書いた状態を再現する。
func actionsEnv(t *testing.T, stsURL string) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "aws-config")
	body := `[profile arata-audit]
role_arn = arn:aws:iam::123456789012:role/arata-readonly
credential_source = Environment

[profile arata-store]
role_arn = arn:aws:iam::123456789012:role/arata-store
credential_source = Environment
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIARUNNER")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "runner-secret")
	t.Setenv("AWS_SESSION_TOKEN", "runner-token")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ENDPOINT_URL_STS", stsURL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// 見本のワークフローの前提: aws.profile は環境変数の認証情報 (実行用ロール) から監査ロールを引き受ける。
func TestAuditProfileAssumesRoleFromEnvironmentCredentials(t *testing.T) {
	srv, signedBy := fakeSTS(t)
	actionsEnv(t, srv.URL)
	cfg := &config.Config{}
	cfg.AWS.Profile = "arata-audit"

	ac, err := loadAWSConfig(context.Background(), cfg, "ap-northeast-1")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := ac.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "AKIAAUDIT" {
		t.Fatalf("audit calls must use the assumed role, got %s", creds.AccessKeyID)
	}
	got := signedBy()
	if len(got) != 1 || !strings.Contains(got[0], "Credential=AKIARUNNER/") {
		t.Fatalf("AssumeRole must be signed by the runner role: %v", got)
	}
}

// 見本のワークフローの前提: store_profile を省略すると、監査ロールを経由せず実行用ロールのままバケットへ書く。
func TestStoreWithoutProfileUsesEnvironmentCredentials(t *testing.T) {
	srv, signedBy := fakeSTS(t)
	actionsEnv(t, srv.URL)
	cfg := &config.Config{StoreRegion: "ap-northeast-1"}
	cfg.AWS.Profile = "arata-audit"

	api, err := NewS3StoreClient(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := api.(*s3.Client).Options().Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "AKIARUNNER" {
		t.Fatalf("the store must use the runner role, got %s", creds.AccessKeyID)
	}
	if got := signedBy(); len(got) != 0 {
		t.Fatalf("the store must not assume the audit role: %v", got)
	}
}

// 見本の README の別案: バケットが別のロールなら store_profile で、実行用ロールから引き受ける (credential_source は role_arn が要る)。
func TestStoreProfileAssumesSeparateRoleFromEnvironmentCredentials(t *testing.T) {
	srv, signedBy := fakeSTS(t)
	actionsEnv(t, srv.URL)
	cfg := &config.Config{StoreProfile: "arata-store", StoreRegion: "ap-northeast-1"}

	api, err := NewS3StoreClient(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.(*s3.Client).Options().Credentials.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := signedBy()
	if len(got) != 1 || !strings.Contains(got[0], "Credential=AKIARUNNER/") {
		t.Fatalf("AssumeRole must be signed by the runner role: %v", got)
	}
}
