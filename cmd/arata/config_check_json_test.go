package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

// config check --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestConfigCheckSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: configCheckSchema, Version: configCheckSchemaVersion, Versioned: true, Type: configCheckOutput{},
		Description: "arata config check --format json の出力。設定と allowlist.yaml の形の検査の結果。AWS にもストアにも繋がずに出す"}, *update)
}

// checkJSON は config check --format json を流し、出力がスキーマと型に合うことを確かめて返す。
func (c *cli) checkJSON(wantExit int, args ...string) configCheckOutput {
	c.t.Helper()
	if len(args) == 0 {
		args = []string{"-c", c.cfg}
	}
	if code := c.run(append([]string{"config", "check", "--format", "json"}, args...)...); code != wantExit {
		c.t.Fatalf("exit %d, want %d\n%s%s", code, wantExit, c.stdout, c.stderr)
	}
	var out configCheckOutput
	schematest.Conforms(c.t, configCheckSchema, c.stdout.Bytes(), &out)
	return out
}

// warn だけなら ok: true で終了コード 0。行は text と同じ内容で、ファイルと行は path / line に分かれる。
func TestConfigCheckJSON(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.writeAllowlist(`principals:
  - arn: arn:aws:iam::123456789012:role/Deploy
    note: デプロイ
    tags: [deploy]
  - account: "111122223333"
    note: 監視 SaaS
  - arn: arn:aws:iam::123456789012:role/Deploy
    note: デプロイ (期限つき)
    expires: 2027-03-31
source_ips:
  - cidr: 203.0.113.0/24
`)
	out := c.checkJSON(0)
	compareGolden(t, "config_check.json", c.checkOut())
	if !out.OK || len(out.Rows) != 3 || strings.Contains(c.stderr.String(), "CONFIG_INVALID") {
		t.Fatalf("%+v\n%s", out, c.stderr)
	}
	al := filepath.Join(c.dir, "allowlist.yaml")
	if r := out.Rows[1]; r.Status != "warn" || r.Item != "allowlist" || r.Path != al || r.Line != 7 {
		t.Fatalf("warn row: %+v", r)
	}
	if r := out.Rows[0]; r.Status != "ok" || r.Item != "config" || r.Path != c.cfg || r.Line != 0 {
		t.Fatalf("config row: %+v", r)
	}
}

// ng があれば ok: false で終了コード 2 (text と同じ)。標準エラーの code も同じ。
func TestConfigCheckJSONProblems(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.writeAllowlist(`principals:
  - arn: arn:aws:iam::123456789012:role/Deploy
    note: デプロイ

  - arn: arn:aws:iam::123456789012:role/Ops
    account: "111122223333"
`)
	out := c.checkJSON(2)
	if out.OK || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("%+v %v", out, c.codes())
	}
	var ng []configCheckRow
	for _, r := range out.Rows {
		if r.Status == "ng" {
			ng = append(ng, r)
		}
	}
	if len(ng) != 1 || ng[0].Item != "allowlist" || ng[0].Line != 5 || !strings.HasSuffix(ng[0].Path, "allowlist.yaml") {
		t.Fatalf("ng rows: %+v", ng)
	}
}

// 設定を読めないときは、設定の ng の行と、allowlist を検査していない (skip) 行。skip の行はファイルを指さない。
func TestConfigCheckJSONNoConfig(t *testing.T) {
	c := newCLI(t)
	c.offline()
	none := filepath.Join(c.dir, "none.yaml")
	out := c.checkJSON(2, "-c", none)
	if out.OK || len(out.Rows) != 2 {
		t.Fatalf("%+v", out)
	}
	if r := out.Rows[0]; r.Status != "ng" || r.Item != "config" || r.Path != none {
		t.Fatalf("%+v", r)
	}
	if r := out.Rows[1]; r.Status != "skip" || r.Item != "allowlist" || r.Path != "" || r.Line != 0 {
		t.Fatalf("%+v", r)
	}
	// text は今までと同じ行
	if code := c.run("config", "check", "-c", none); code != 2 || !strings.Contains(c.stdout.String(), "\nskip  allowlist: 設定を読めないので検査していません") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
}

func TestConfigCheckRejectsUnknownFormat(t *testing.T) {
	c := newCLI(t)
	c.offline()
	if code := c.run("config", "check", "-c", c.cfg, "--format", "table"); code != 2 || c.stdout.Len() != 0 || !strings.Contains(c.stderr.String(), "text|json") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
}
