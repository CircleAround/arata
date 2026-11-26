package scanscripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 偽の gitleaks。呼ばれた引数と、stdin モードで受け取った内容を $FAKE_LOG に残す。
// FAKE_FAIL=git|stdin でそのモードを「検出あり」にする。標準入力は毎回読み切る (呼び出し側の入力を食わないことを確かめる)。
const fakeGitleaks = `#!/bin/sh
echo "ARGS $*" >>"$FAKE_LOG"
if [ "$1" = stdin ]; then sed 's/^/STDIN /' >>"$FAKE_LOG"; else cat >/dev/null; fi
[ "$FAKE_FAIL" != "$1" ]
`

const zeros = "0000000000000000000000000000000000000000"

type repo struct {
	t               *testing.T
	dir, log, fake  string
	env             []string
	base, tip, side string // base は origin/main、tip は作業の枝、side は無関係の枝
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// cleanEnv は利用者の git の設定と、フックから起動されたときの GIT_* を持ち込まない。
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "GITLEAKS") && !strings.HasPrefix(kv, "FAKE_") {
			env = append(env, kv)
		}
	}
	return append(env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=dev", "GIT_AUTHOR_EMAIL=dev@example.com",
		"GIT_COMMITTER_NAME=dev", "GIT_COMMITTER_EMAIL=dev@example.com")
}

func newRepo(t *testing.T) *repo {
	t.Helper()
	tmp := t.TempDir()
	r := &repo{t: t, dir: filepath.Join(tmp, "r"), log: filepath.Join(tmp, "log"), fake: filepath.Join(tmp, "gitleaks")}
	if err := os.WriteFile(r.fake, []byte(fakeGitleaks), 0o700); err != nil { // #nosec G306 -- テストが起動する偽の実行ファイル
		t.Fatal(err)
	}
	r.env = append(cleanEnv(), "GITLEAKS="+r.fake, "FAKE_LOG="+r.log)
	if err := os.Mkdir(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.git("init", "-q", "-b", "main")
	r.base = r.commit("msg-base")
	r.git("update-ref", "refs/remotes/origin/main", r.base)
	r.git("checkout", "-q", "-b", "side")
	r.side = r.commit("msg-side")
	r.git("checkout", "-q", "-b", "work", "main")
	r.tip = r.commit("msg-work")
	return r
}

func (r *repo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 -- テストが組み立てた引数
	cmd.Dir, cmd.Env = r.dir, r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *repo) commit(msg string) string {
	r.t.Helper()
	r.git("commit", "-q", "--allow-empty", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

// scan は tools/scan-commits.sh を一時リポジトリで動かし、偽の gitleaks の記録を返す。
func (r *repo) scan(stdin string, extraEnv []string, args ...string) (log string, err error) {
	r.t.Helper()
	_ = os.Remove(r.log)
	cmd := exec.Command(filepath.Join(repoRoot(r.t), "tools", "scan-commits.sh"), args...) // #nosec G204 -- テストが組み立てた引数
	cmd.Dir, cmd.Stdin = r.dir, strings.NewReader(stdin)
	cmd.Env = append(append([]string{}, r.env...), extraEnv...)
	out, err := cmd.CombinedOutput()
	r.t.Logf("scan-commits.sh %v: %s", args, out)
	b, _ := os.ReadFile(r.log)
	return string(b), err
}

func assertScanned(t *testing.T, log, logOpts string, messages, absent []string) {
	t.Helper()
	if want := "ARGS git --no-banner --redact -c .gitleaks.toml --log-opts=" + logOpts + " .\n"; !strings.Contains(log, want) {
		t.Errorf("差分の検査の引数が違う: want %q\n%s", want, log)
	}
	if !strings.Contains(log, "ARGS stdin --no-banner --redact -c .gitleaks.toml\n") {
		t.Errorf("コミットメッセージを検査していない:\n%s", log)
	}
	for _, m := range messages {
		if !strings.Contains(log, "STDIN "+m+"\n") {
			t.Errorf("%s を読んでいない:\n%s", m, log)
		}
	}
	for _, m := range absent {
		if strings.Contains(log, "STDIN "+m+"\n") {
			t.Errorf("範囲の外の %s を読んだ:\n%s", m, log)
		}
	}
}

func TestRangeReadsOnlyThatRange(t *testing.T) {
	r := newRepo(t)
	rng := r.base + ".." + r.tip
	log, err := r.scan("", nil, rng)
	if err != nil {
		t.Fatal(err)
	}
	assertScanned(t, log, rng, []string{"msg-work"}, []string{"msg-base", "msg-side"})
}

func TestAllReadsEveryBranch(t *testing.T) {
	r := newRepo(t)
	log, err := r.scan("", nil, "--all")
	if err != nil {
		t.Fatal(err)
	}
	assertScanned(t, log, "--all", []string{"msg-base", "msg-side", "msg-work"}, nil)
}

// gitleaks は範囲が壊れていても「0 件」で成功するので、渡す前に落とす。
func TestBadRangeFailsBeforeGitleaks(t *testing.T) {
	r := newRepo(t)
	for _, args := range [][]string{{"nosuch..HEAD"}, {zeros + ".." + r.tip}, {""}, {}} {
		log, err := r.scan("", nil, args...)
		if err == nil || log != "" {
			t.Errorf("%q: err=%v log=%q", args, err, log)
		}
	}
}

func TestFindingFails(t *testing.T) {
	r := newRepo(t)
	for _, mode := range []string{"git", "stdin"} {
		if _, err := r.scan("", []string{"FAKE_FAIL=" + mode}, "--all"); err == nil {
			t.Errorf("%s の検出を成功にした", mode)
		}
	}
}

func TestMissingGitleaksFails(t *testing.T) {
	r := newRepo(t)
	if _, err := r.scan("", []string{"GITLEAKS=" + filepath.Join(r.dir, "nosuch")}, "--all"); err == nil {
		t.Error("gitleaks が無いのに成功した")
	}
}

func TestUnpushedWithoutUpstreamStartsAtOriginMain(t *testing.T) {
	r := newRepo(t)
	log, err := r.scan("", nil, "--unpushed")
	if err != nil {
		t.Fatal(err)
	}
	assertScanned(t, log, "origin/main..HEAD", []string{"msg-work"}, []string{"msg-base", "msg-side"})
}

func TestUnpushedWithUpstreamStartsAtUpstream(t *testing.T) {
	r := newRepo(t)
	r.git("config", "remote.origin.url", "unused")
	r.git("config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
	r.git("update-ref", "refs/remotes/origin/work", r.tip)
	r.git("branch", "-q", "--set-upstream-to=origin/work")
	r.commit("msg-new")
	log, err := r.scan("", nil, "--unpushed")
	if err != nil {
		t.Fatal(err)
	}
	assertScanned(t, log, "@{upstream}..HEAD", []string{"msg-new"}, []string{"msg-base", "msg-work"})
}

func TestPrePush(t *testing.T) {
	r := newRepo(t)
	line := func(localSHA, remoteSHA string) string {
		return "refs/heads/x " + localSHA + " refs/heads/x " + remoteSHA + "\n"
	}
	opts := func(sha string) string { return sha + " --not --remotes=origin" }

	t.Run("送るコミットだけを読む", func(t *testing.T) {
		log, err := r.scan(line(r.tip, zeros), nil, "--pre-push", "origin")
		if err != nil {
			t.Fatal(err)
		}
		assertScanned(t, log, opts(r.tip), []string{"msg-work"}, []string{"msg-base", "msg-side"})
	})
	t.Run("複数の参照を全部読む", func(t *testing.T) {
		log, err := r.scan(line(r.tip, zeros)+line(r.side, r.base), nil, "--pre-push", "origin")
		if err != nil {
			t.Fatal(err)
		}
		assertScanned(t, log, opts(r.tip), []string{"msg-work", "msg-side"}, []string{"msg-base"})
		assertScanned(t, log, opts(r.side), nil, nil)
	})
	t.Run("枝の削除は読まない", func(t *testing.T) {
		log, err := r.scan("(delete) "+zeros+" refs/heads/x "+r.tip+"\n", nil, "--pre-push", "origin")
		if err != nil || log != "" {
			t.Errorf("err=%v log=%q", err, log)
		}
	})
	t.Run("検出があれば push を止める", func(t *testing.T) {
		if _, err := r.scan(line(r.tip, zeros)+line(r.side, zeros), []string{"FAKE_FAIL=git"}, "--pre-push", "origin"); err == nil {
			t.Error("成功した")
		}
	})
}
