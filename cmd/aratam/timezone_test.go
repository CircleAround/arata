package main

import (
	"os/exec"
	"strings"
	"testing"
)

// timezone を書くと、通知の時刻がそのゾーンになる (コマンドレベル)。日付だけの値は UTC の日のまま。
func TestNotifyTimezone(t *testing.T) {
	c := newCLI(t)
	c.editConfig("timezone: UTC", "timezone: Asia/Tokyo")
	if code := c.run("notify", "--in", c.inputDir(), "-c", c.cfg, "--dry-run"); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	out := c.stdout.String()
	for _, want := range []string{"2026-10-20T18:00:00+09:00 〜 2026-10-21T18:00:00+09:00", "初出 2026-10-21T18:00:00+09:00", "date 2026-10-20 (UTC)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}

	c = newCLI(t)
	c.editConfig("timezone: UTC", "timezone: Asia/Tokyo")
	c.editConfig("format: text", "format: blocks")
	if code := c.run("notify", "--in", c.inputDir(), "-c", c.cfg, "--dry-run"); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, c.stdout, c.stderr)
	}
	if out := c.stdout.String(); !strings.Contains(out, "*期間* 10/20 18:00 〜 10/21 18:00 (JST)") {
		t.Errorf("blocks:\n%s", out)
	}
}

// 不正な名前は読み込みで設定エラー (notify・doctor・config check のどれでも送る前に止まる)。
func TestTimezoneInvalidIsConfigError(t *testing.T) {
	for _, args := range [][]string{{"notify", "--in", "x", "--dry-run"}, {"doctor"}, {"config", "check"}} {
		c := newCLI(t)
		c.editConfig("timezone: UTC", "timezone: JST")
		code := c.run(append(args, "-c", c.cfg)...)
		if code != 2 || strings.Join(c.codes(), ",") != "CONFIG_INVALID" || !strings.Contains(c.stdout.String()+c.stderr.String(), "IANA time zone name such as Asia/Tokyo") {
			t.Errorf("%v: exit %d %v\n%s%s", args, code, c.codes(), c.stdout, c.stderr)
		}
	}
}

// doctor と config check は、使うタイムゾーンを表示する (timezone の無い設定で UTC になることも見える)。
func TestDoctorAndCheckShowTimezone(t *testing.T) {
	for _, tc := range []struct{ from, to, want string }{
		{"timezone: UTC", "timezone: Asia/Tokyo", "timezone Asia/Tokyo"},
		{"timezone: UTC", "", "timezone UTC"},
	} {
		c := newCLI(t)
		c.editConfig(tc.from, tc.to)
		if code := c.run("doctor", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), tc.want) {
			t.Errorf("doctor: exit %d\n%s%s", code, c.stdout, c.stderr)
		}
		if code := c.run("config", "check", "-c", c.cfg); code != 0 || !strings.Contains(c.stdout.String(), tc.want) {
			t.Errorf("config check: exit %d\n%s%s", code, c.stdout, c.stderr)
		}
	}
}

// 決定 (aratam 設計書 4-3 章): タイムゾーンのデータ (標準ライブラリの time/tzdata) をバイナリに埋め込む。
// tzdata の無い実行環境 (最小構成のコンテナ) でも timezone が使える。外部の依存は足さない。
func TestTimezoneDataIsEmbedded(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list is not available: %v", err)
	}
	if !strings.Contains("\n"+string(out), "\ntime/tzdata\n") {
		t.Fatal("aratam must embed time/tzdata")
	}
}
