package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkOut は config check の標準出力から一時ディレクトリを伏せたもの (ゴールデン用)。
func (c *cli) checkOut() []byte {
	return []byte(strings.ReplaceAll(c.stdout.String(), c.dir, "<dir>"))
}

func (c *cli) writeAllowlist(body string) {
	if err := os.WriteFile(filepath.Join(c.dir, "allowlist.yaml"), []byte(body), 0o600); err != nil {
		c.t.Fatal(err)
	}
}

// offline は AWS とストアに触れたら失敗するようにする (config check はどちらにも繋がない)。
func (c *cli) offline() {
	c.onCollect = func() { c.t.Fatal("config check must not reach AWS") }
	c.t.Cleanup(func() {
		if _, err := os.Stat(filepath.Join(c.dir, "store")); err == nil {
			c.t.Fatal("config check must not create the store")
		}
	})
}

func TestConfigCheckOK(t *testing.T) {
	c := newCLI(t)
	c.offline()
	// 同じ主体の重複は警告 (run は受け付けるので終了コードは 0)
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
	if code := c.run("config", "check", "-c", c.cfg); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	compareGolden(t, "config_check.txt", c.checkOut())
	if strings.Contains(c.stderr.String(), "CONFIG_INVALID") {
		t.Fatalf("warnings must not be logged as errors: %s", c.stderr)
	}
}

func TestConfigCheckProblems(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.writeAllowlist(`principals:
  - arn: arn:aws:iam::123456789012:role/Deploy
    note: デプロイ

  - arn: arn:aws:iam::123456789012:role/Ops
    account: "111122223333"
`)
	if code := c.run("config", "check", "-c", c.cfg); code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" {
		t.Fatalf("exit %d %v\n%s%s", code, c.codes(), c.stdout, c.stderr)
	}
	compareGolden(t, "config_check_ng.txt", c.checkOut())
}

func TestConfigCheckRules(t *testing.T) {
	base := func(t *testing.T) *cli { c := newCLI(t); c.offline(); return c }
	cfgOf := func(c *cli) string {
		b, err := os.ReadFile(c.cfg)
		if err != nil {
			c.t.Fatal(err)
		}
		return string(b)
	}
	cases := []struct {
		name  string
		setup func(c *cli)
		exit  int
		want  []string
	}{
		{"unknown key with line", func(c *cli) { c.writeConfig(cfgOf(c) + "retension:\n  events: 30d\n") }, 2,
			[]string{"ng    " + "<dir>/config.yaml", "field retension not found", "line 20"}},
		{"type", func(c *cli) {
			c.writeConfig(strings.Replace(cfgOf(c), "checks: [root_usage, unknown_assume_role, oidc_assume_role]", "checks: root_usage", 1))
		}, 2,
			[]string{"line 12", "cannot unmarshal"}},
		{"required", func(c *cli) { c.writeConfig(strings.Replace(cfgOf(c), "name: acme\n", "", 1)) }, 2,
			[]string{"config: name is required"}},
		{"unknown check name (the rule of doctor and run)", func(c *cli) {
			c.writeConfig(strings.Replace(cfgOf(c), "checks: [root_usage, unknown_assume_role, oidc_assume_role]", "checks: [root_usage, root_usege]", 1))
		}, 2, []string{`profile hourly: unknown check "root_usege"`}},
		// 設定が読めなければ allowlist の場所が決まらないので、allowlist は見ない
		{"allowlist is skipped when the config is broken", func(c *cli) {
			c.writeConfig("name: [\n")
			c.writeAllowlist("principals: 1\n")
		}, 2, []string{"ng    <dir>/config.yaml", "skip  allowlist"}},
		{"allowlist expires", func(c *cli) {
			c.writeAllowlist("principals:\n  - account: \"111122223333\"\n    expires: 2027/03/31\n")
		}, 2, []string{"ng    <dir>/allowlist.yaml:2: principals[0]: expires \"2027/03/31\": want YYYY-MM-DD"}},
		{"allowlist unknown key", func(c *cli) {
			c.writeAllowlist("principals:\n  - account: \"111122223333\"\n    expire: 2027-03-31\n")
		}, 2, []string{"ng    <dir>/allowlist.yaml: ", "line 3: field expire not found"}},
		// run は allowlist が無ければ空として動く (init の直後)。check は警告にとどめる
		{"missing allowlist is a warning", func(c *cli) {
			if err := os.Remove(filepath.Join(c.dir, "allowlist.yaml")); err != nil {
				c.t.Fatal(err)
			}
		}, 0, []string{"ok    <dir>/config.yaml", "warn  <dir>/allowlist.yaml: file not found"}},
		{"allowlist: key", func(c *cli) {
			c.writeConfig(cfgOf(c) + "allowlist: lists/known.yaml\n")
			if err := os.MkdirAll(filepath.Join(c.dir, "lists"), 0o750); err != nil {
				c.t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(c.dir, "lists", "known.yaml"), []byte("admin_users: [alice]\n"), 0o600); err != nil {
				c.t.Fatal(err)
			}
		}, 0, []string{"ok    <dir>/lists/known.yaml: principals 0, source_ips 0, admin_users 1, secrets_access 0"}},
		// s3:// のストアでも繋がない (テストの S3 は nil で、届けば失敗する)
		{"s3 store is not opened", func(c *cli) {
			c.writeConfig(strings.Replace(cfgOf(c), "store: dir://"+c.dir+"/store", "store: s3://example-arata-store/acme", 1))
		}, 0, []string{"ok    <dir>/config.yaml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base(t)
			tc.setup(c)
			code := c.run("config", "check", "-c", c.cfg)
			out := string(c.checkOut())
			if code != tc.exit {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.exit, out, c.stderr)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Fatalf("output lacks %q:\n%s", w, out)
				}
			}
			if (code == 2) != strings.Contains(c.stderr.String(), "CONFIG_INVALID") {
				t.Fatalf("exit %d but stderr: %s", code, c.stderr)
			}
		})
	}
}

// 設定の見本は config check を通る (見本の誤りを CI で止める)。
func TestConfigCheckExamples(t *testing.T) {
	c := newCLI(t)
	c.offline()
	if code := c.run("config", "check", "-c", filepath.Join("..", "..", "examples", "arata.yaml")); code != 0 || strings.Contains(c.stdout.String(), "warn") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
}

// 設定ファイルが無いときは、他のコマンドと同じく探した場所を示して終了コード 2。
func TestConfigCheckNoFile(t *testing.T) {
	c := newCLI(t)
	if code := c.run("config", "check", "-c", filepath.Join(c.dir, "none.yaml")); code != 2 || !strings.Contains(string(c.checkOut()), "ng    <dir>/none.yaml: ") {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
}

// カレントディレクトリの下のファイルは相対パスで出す (CI のログで「aws/prod/allowlist.yaml:2」と読める)。
func TestConfigCheckShowsRelativePaths(t *testing.T) {
	c := newCLI(t)
	c.offline()
	c.writeAllowlist("principals:\n  - account: \"111122223333\"\n    expires: 2027/03/31\n")
	t.Chdir(c.dir)
	if code := c.run("config", "check", "-c", "config.yaml"); code != 2 {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	want := "ok    config.yaml: name acme, sources 1, profiles 3\nng    allowlist.yaml:2: principals[0]: expires \"2027/03/31\": want YYYY-MM-DD\n"
	if c.stdout.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", c.stdout, want)
	}
}
