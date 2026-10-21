package subcmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// testTree は cli.go の解釈を確かめる小さなコマンド木。
func testTree(out *bytes.Buffer) (*Command, *string, map[string]any) {
	got := map[string]any{}
	var cfg string
	root := &Command{Use: "app", Short: "テスト用", Version: "1.2.3", Stdout: out}
	root.PersistentStringVarP(&cfg, "config", "c", "", "設定ファイル")
	var note, profile string
	var tags, statuses []string
	var force bool
	leaf := &Command{Use: "approve <id>", Short: "承認する", Args: ExactArgs(1), Run: func(_ context.Context, args []string) error {
		got["args"], got["note"], got["tags"], got["force"] = args, note, tags, force
		return nil
	}}
	leaf.StringVar(&note, "note", "", "理由")
	leaf.StringArrayVar(&tags, "tag", "タグ")
	leaf.BoolVar(&force, "force", false, "上書き")
	run := &Command{Use: "run", Short: "実行する", Args: NoArgs, Run: func(_ context.Context, args []string) error {
		got["profile"], got["status"] = profile, statuses
		return nil
	}}
	run.StringVar(&profile, "profile", "daily", "プロファイル")
	run.StringSliceVar(&statuses, "status", "状態")
	var until string
	snooze := &Command{Use: "snooze", Short: "沈黙", Run: func(context.Context, []string) error { got["until"] = until; return nil }}
	snooze.StringVar(&until, "until", "", "期日")
	snooze.MarkFlagRequired("until")
	group := &Command{Use: "config", Short: "設定"}
	group.AddCommand(&Command{Use: "init", Short: "雛形", Args: NoArgs, Run: func(context.Context, []string) error { got["config init"] = true; return nil }})
	root.AddCommand(leaf, run, snooze, group)
	return root, &cfg, got
}

func TestCLIFlagsAndArgs(t *testing.T) {
	var out bytes.Buffer
	root, cfg, got := testTree(&out)
	// 位置引数とフラグが混ざってよい・短縮形・繰り返し・ルートより前の global flag
	if err := root.Execute(context.Background(), []string{"-c", "a.yaml", "approve", "F1", "--note", "x y", "--tag", "deploy", "--tag=ai", "--force"}); err != nil {
		t.Fatal(err)
	}
	if *cfg != "a.yaml" || strings.Join(got["args"].([]string), ",") != "F1" || got["note"] != "x y" || strings.Join(got["tags"].([]string), "|") != "deploy|ai" || got["force"] != true {
		t.Fatalf("got %v cfg %q", got, *cfg)
	}
	if err := root.Execute(context.Background(), []string{"run", "--config=b.yaml", "--status", "open,acked", "--status", "snoozed"}); err != nil {
		t.Fatal(err)
	}
	if *cfg != "b.yaml" || got["profile"] != "daily" || strings.Join(got["status"].([]string), ",") != "open,acked,snoozed" {
		t.Fatalf("got %v cfg %q", got, *cfg)
	}
	if err := root.Execute(context.Background(), []string{"config", "init", "-c", "c.yaml"}); err != nil || got["config init"] != true || *cfg != "c.yaml" {
		t.Fatalf("nested: %v %v", err, got)
	}
}

func TestCLIErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"bogus"}, `unknown command "bogus" for "app"`},
		{[]string{"config", "bogus"}, `unknown command "bogus" for "app config"`},
		{[]string{"run", "--bogus"}, "unknown flag: --bogus"},
		{[]string{"run", "-b"}, "unknown shorthand flag: 'b' in -b"},
		{[]string{"run", "extra"}, `unknown command "extra" for "app run"`},
		{[]string{"approve", "a", "--force=x"}, `invalid argument "x" for "--force" flag: strconv.ParseBool: parsing "x": invalid syntax`},
		{[]string{"approve"}, "accepts 1 arg(s), received 0"},
		{[]string{"approve", "a", "b"}, "accepts 1 arg(s), received 2"},
		{[]string{"snooze"}, `required flag(s) "until" not set`},
		{[]string{"run", "--profile"}, "flag needs an argument: --profile"},
		{[]string{"run", "-c"}, "flag needs an argument: 'c' in -c"},
		{[]string{"run", "-v"}, "unknown shorthand flag: 'v' in -v"},
	} {
		var out bytes.Buffer
		root, _, _ := testTree(&out)
		err := root.Execute(context.Background(), tc.args)
		if err == nil || err.Error() != tc.want {
			t.Errorf("%v: got %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	var out bytes.Buffer
	root, _, got := testTree(&out)
	for _, args := range [][]string{{}, {"--help"}, {"-h"}} {
		out.Reset()
		if err := root.Execute(context.Background(), args); err != nil {
			t.Fatal(err)
		}
		want := `テスト用

Usage:
  app [command]

Available Commands:
  approve     承認する
  config      設定
  run         実行する
  snooze      沈黙

Flags:
  -c, --config string   設定ファイル
  -h, --help            help for app
  -v, --version         version for app

Use "app [command] --help" for more information about a command.
`
		if out.String() != want {
			t.Fatalf("%v:\n%s", args, out.String())
		}
	}
	// -h は必須フラグや引数の検査より先
	out.Reset()
	if err := root.Execute(context.Background(), []string{"snooze", "-h"}); err != nil || got["until"] != nil {
		t.Fatalf("help must not run: %v %v", err, got)
	}
	if !strings.Contains(out.String(), "Usage:\n  app snooze [flags]\n\nFlags:\n  -h, --help           help for snooze\n      --until string   期日\n\nGlobal Flags:\n  -c, --config string   設定ファイル\n") {
		t.Fatalf("leaf help:\n%s", out.String())
	}
	out.Reset()
	_ = root.Execute(context.Background(), []string{"run", "--help"})
	if !strings.Contains(out.String(), `      --profile string   プロファイル (default "daily")`) || !strings.Contains(out.String(), "      --status strings") {
		t.Fatalf("defaults and types:\n%s", out.String())
	}
	out.Reset()
	if err := root.Execute(context.Background(), []string{"config"}); err != nil || !strings.Contains(out.String(), "Usage:\n  app config [command]") {
		t.Fatalf("group without subcommand prints help: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := root.Execute(context.Background(), []string{"--version"}); err != nil || out.String() != "app version 1.2.3\n" {
		t.Fatalf("version: %v %q", err, out.String())
	}
}
