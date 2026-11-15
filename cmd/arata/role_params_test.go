package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

// config role-params --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestRoleParamsSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: roleParamsSchema, Version: roleParamsSchemaVersion, Versioned: true, Type: roleParamsOutput{},
		Description: "arata config role-params --format json の出力。設定から作った、読み取り専用ロール (deploy/iam/readonly-role.yaml) に渡すパラメータ。AWS にもストアにも繋がずに出す"}, *update)
}

// logSources は cloudwatch-logs のソースを並べた設定を書く。
func (c *cli) logSources(sources string) {
	c.writeConfig(fmt.Sprintf(`
name: acme
store: dir://%s/store
aws:
  region: ap-northeast-1
sources:
  - id: trail
    kind: cloudtrail-lookup
%s
profiles:
  daily:
    window: 24h
    checks: [root_usage]
audit_account: none
`, c.dir, sources))
}

func (c *cli) roleParamsJSON(wantExit int) roleParamsOutput {
	c.t.Helper()
	if code := c.run("config", "role-params", "--format", "json", "-c", c.cfg); code != wantExit {
		c.t.Fatalf("exit %d, want %d\n%s%s", code, wantExit, c.stdout, c.stderr)
	}
	var out roleParamsOutput
	if wantExit == 0 {
		schematest.Conforms(c.t, roleParamsSchema, c.stdout.Bytes(), &out)
	}
	return out
}

// 決定 (ADR 0062): AllowedLogGroupNames は、cloudwatch-logs のソースの log_group を、重複を除いて設定の順に並べたもの。
// 同じロググループを別のリージョン・別のソースで読んでも 1 つ (ロールの ARN はリージョンを * にする)。
func TestRoleParamsFromSources(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.logSources(`  - id: web
    kind: cloudwatch-logs
    log_group: prod-nginx-access
    format: nginx_access
  - id: api
    kind: cloudwatch-logs
    log_group: /app/prod/api
    format: json
    fields: { ip: remote_ip, path: path, status: status }
  - id: web-us
    kind: cloudwatch-logs
    log_group: prod-nginx-access
    format: nginx_access
    regions: [us-east-1]`)
	out := c.roleParamsJSON(0)
	if out.Schema != "arata-role-params" || out.SchemaVersion != 1 {
		t.Fatalf("header: %+v", out)
	}
	if out.Parameters.AllowedLogGroupNames != "prod-nginx-access,/app/prod/api" {
		t.Fatalf("AllowedLogGroupNames = %q", out.Parameters.AllowedLogGroupNames)
	}
	if strings.Join(out.LogGroups, " ") != "prod-nginx-access /app/prod/api" {
		t.Fatalf("log_groups = %q", out.LogGroups)
	}

	// 人向けの出力は、そのまま打てる --parameter-overrides の引数を含む (文言は固定しない。機械は json を読む)
	if code := c.run("config", "role-params", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "AllowedLogGroupNames=prod-nginx-access,/app/prod/api") {
		t.Fatalf("text:\n%s", c.stdout)
	}
}

// 決定 (ADR 0062): ロググループのソースが無ければ none (どのロググループの中身も読ませない) を出す。error にしない
// (arata repo init が書き出す設定は、ロググループのソースがコメントだけ)。text には、なぜ none なのかを添える。
func TestRoleParamsWithoutLogSources(t *testing.T) {
	c := newCLI(t)
	c.offline()
	out := c.roleParamsJSON(0)
	if out.Parameters.AllowedLogGroupNames != "none" || out.LogGroups == nil || len(out.LogGroups) != 0 {
		t.Fatalf("%+v\n%s", out, c.stdout)
	}
	if code := c.run("config", "role-params", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	for _, want := range []string{"AllowedLogGroupNames=none", "cloudwatch-logs のソースが無いので、どのロググループも読ませない"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Fatalf("text に %q が無い:\n%s", want, c.stdout)
		}
	}
}

// ロールのパラメータの AllowedPattern に合わない名前 (使えない文字) は、スタックの更新で弾かれる前に CONFIG_INVALID にする。
func TestRoleParamsRejectsNamesTheRoleCannotTake(t *testing.T) {
	// none は予約語 (どのロググループも読ませない) と区別できないので、その名前のロググループは読ませられない
	for _, name := range []string{"prod nginx", "prod:nginx", "prod-*", "none"} {
		t.Run(name, func(t *testing.T) {
			c := newCLI(t)
			c.offline()
			c.logSources(fmt.Sprintf(`  - id: web
    kind: cloudwatch-logs
    log_group: %q
    format: nginx_access`, name))
			c.roleParamsJSON(2)
			if strings.Join(c.codes(), ",") != "CONFIG_INVALID" || !strings.Contains(c.stderr.String(), name) {
				t.Fatalf("codes %v\n%s", c.codes(), c.stderr)
			}
		})
	}
}

// 値が CloudFormation のパラメータの上限 (4,096 バイト) を超えるなら、出さずに CONFIG_INVALID。
// ロールのインラインポリシーの上限 (10,240 文字) に近いなら、出したうえで警告する (Deny の分は設定から分からない)。
func TestRoleParamsSizeLimits(t *testing.T) {
	sources := func(n, length int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "  - id: s%d\n    kind: cloudwatch-logs\n    log_group: %s%04d\n    format: nginx_access\n", i, strings.Repeat("a", length-4), i)
		}
		return b.String()
	}

	c := newCLI(t)
	c.offline()
	c.logSources(sources(40, 100)) // 値は 40×101-1 = 4,039 バイト。ARN は 40×(2×100+60) ≒ 10,400 文字
	out := c.roleParamsJSON(0)
	if len(out.Parameters.AllowedLogGroupNames) > 4096 || !strings.Contains(c.stderr.String(), "10,240") {
		t.Fatalf("len %d\n%s", len(out.Parameters.AllowedLogGroupNames), c.stderr)
	}

	c = newCLI(t)
	c.offline()
	c.logSources(sources(41, 100)) // 41×101-1 = 4,140 バイト
	c.roleParamsJSON(2)
	if strings.Join(c.codes(), ",") != "CONFIG_INVALID" || !strings.Contains(c.stderr.String(), "4,096") {
		t.Fatalf("codes %v\n%s", c.codes(), c.stderr)
	}
}

// 決定 (ADR 0063): cloudtrail-s3 のソースがあれば、バケットの名前と接頭辞 (前後の / を外す) も出す。無ければ空。
func TestRoleParamsCloudTrailS3(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.writeConfig(fmt.Sprintf(`
name: acme
store: dir://%s/store
aws:
  region: ap-northeast-1
sources:
  - id: trail
    kind: cloudtrail-s3
    bucket: example-trail-logs
    prefix: logs/org-1/
    account_id: "123456789012"
    regions: [ap-northeast-1, us-east-1]
profiles:
  daily:
    window: 24h
    checks: [root_usage]
audit_account: none
`, c.dir))
	out := c.roleParamsJSON(0)
	if out.Parameters.CloudTrailBucketName != "example-trail-logs" || out.Parameters.CloudTrailBucketPrefix != "logs/org-1" || out.Parameters.AllowedLogGroupNames != "none" {
		t.Fatalf("parameters = %+v", out.Parameters)
	}
	if code := c.run("config", "role-params", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d\n%s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "--parameter-overrides AllowedLogGroupNames=none CloudTrailBucketName=example-trail-logs CloudTrailBucketPrefix=logs/org-1") {
		t.Fatalf("text: %s", c.stdout)
	}

	c.logSources("")
	if out := c.roleParamsJSON(0); out.Parameters.CloudTrailBucketName != "" || out.Parameters.CloudTrailBucketPrefix != "" {
		t.Fatalf("without cloudtrail-s3: %+v", out.Parameters)
	}
}
