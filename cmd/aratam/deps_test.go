package main

import (
	"os/exec"
	"strings"
	"testing"
)

// aratam のバイナリに入る (標準ライブラリ以外の) パッケージを許可リストで固定する。
// 決定 (ADR 0018): aratam は arata のストア・AWS の監査ロール・チェックを知らない。
// SQLite や監査用の AWS SDK のサービスが import の連鎖で紛れ込まないよう、go list -deps で確かめる。
var allowedDeps = []string{
	"github.com/CircleAround/arata/cmd/aratam",
	"github.com/CircleAround/arata/internal/notify",
	"github.com/CircleAround/arata/internal/slack",
	"github.com/CircleAround/arata/internal/subcmd",
	"github.com/CircleAround/arata/internal/report/schema",
	"github.com/CircleAround/arata/internal/llm",
	"github.com/CircleAround/arata/docs/ai", // LLM の system に埋め込む文書 (標準ライブラリだけに依存)
	"github.com/CircleAround/arata/schemas", // 機械が読む出力の JSON Schema のファイル (標準ライブラリだけに依存。ADR 0054)
	"gopkg.in/yaml.v3",
	// bedrock プロバイダ (aratam 設計書 1 章で AWS SDK を使ってよいとしたもの)。Converse と、標準の認証チェーンが使う STS / SSO だけ
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime",
	"github.com/aws/aws-sdk-go-v2/config",
	"github.com/aws/aws-sdk-go-v2/credentials",
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds",
	"github.com/aws/aws-sdk-go-v2/aws",
	"github.com/aws/aws-sdk-go-v2/internal",
	"github.com/aws/aws-sdk-go-v2/service/internal",
	"github.com/aws/aws-sdk-go-v2/service/sts",
	"github.com/aws/aws-sdk-go-v2/service/sso",
	"github.com/aws/aws-sdk-go-v2/service/ssooidc",
	"github.com/aws/aws-sdk-go-v2/service/signin",
	"github.com/aws/smithy-go",
}

// 許可リストとは別に、名指しで入れてはならないもの (許可リストを広げるときの歯止め)。
var forbiddenDeps = []string{
	"modernc.org/sqlite",
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail",
	"github.com/aws/aws-sdk-go-v2/service/iam",
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs",
	"github.com/aws/aws-sdk-go-v2/service/guardduty",
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer",
	"github.com/aws/aws-sdk-go-v2/service/s3control",
	"github.com/CircleAround/arata/internal/store",
	"github.com/CircleAround/arata/internal/checks",
	"github.com/CircleAround/arata/internal/collect",
	"github.com/CircleAround/arata/internal/engine",
	"github.com/CircleAround/arata/internal/config",
}

func TestDependenciesStaySeparateFromArata(t *testing.T) {
	// go test は子プロセスの PATH の先頭に GOROOT/bin を足すので、テストと同じ版の go が見つかる
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Skipf("go list is not available: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, f := range forbiddenDeps {
			if p == f || strings.HasPrefix(p, f+"/") {
				t.Errorf("aratam must not depend on %s", p)
			}
		}
		ok := false
		for _, a := range allowedDeps {
			if p == a || strings.HasPrefix(p, a+"/") {
				ok = true
			}
		}
		if !ok {
			t.Errorf("unexpected dependency %s (add it to allowedDeps only if aratam really needs it)", p)
		}
	}
}
