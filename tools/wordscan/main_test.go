package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 試験用の語。実際の禁止語の一覧とは無関係の架空の値。
const word = "zzforbiddenword"

func patterns(t *testing.T, lines ...string) []*pattern {
	t.Helper()
	ps, err := parsePatterns(strings.Join(lines, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=alice", "GIT_AUTHOR_EMAIL=alice@example.com",
		"GIT_COMMITTER_NAME=alice", "GIT_COMMITTER_EMAIL=alice@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "clean.txt", "nothing here\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "clean")
	return dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// run は CLI の入口を通し、終了コードと全出力を返す。
func run(t *testing.T, env string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := realMain(args, env, &out)
	return code, out.String()
}

func TestParsePatterns(t *testing.T) {
	ps := patterns(t, "# comment", "", "  ", `foo\.bar`, "Baz")
	if len(ps) != 2 {
		t.Fatalf("got %d patterns, want 2", len(ps))
	}
	if !ps[1].re.MatchString("xbAZx") {
		t.Error("patterns must be case-insensitive")
	}
	if ps[0].re.MatchString("fooxbar") {
		t.Error("patterns must be regexps")
	}
}

func TestInvalidPatternDoesNotEchoIt(t *testing.T) {
	_, err := parsePatterns("ok\n" + word + "(")
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), word) {
		t.Errorf("error leaks the pattern: %v", err)
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error should name the line: %v", err)
	}
}

func TestNoPatternsFailsClosed(t *testing.T) {
	dir := newRepo(t)
	for _, env := range []string{"", "\n# only comment\n"} {
		code, out := run(t, env, "-mode", "tree", "-repo", dir)
		if code != exitError {
			t.Errorf("env %q: code %d, want %d\n%s", env, code, exitError, out)
		}
	}
}

func TestUnknownModeIsError(t *testing.T) {
	if code, _ := run(t, word, "-mode", "nope"); code != exitError {
		t.Errorf("code %d", code)
	}
}

func TestPatternsFromFile(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "a.txt", word+"\n")
	pf := filepath.Join(t.TempDir(), "p.txt")
	write(t, filepath.Dir(pf), "p.txt", word+"\n")
	if code, out := run(t, "", "-mode", "tree", "-repo", dir, "-patterns", pf); code != exitHit {
		t.Errorf("code %d\n%s", code, out)
	}
	if code, _ := run(t, "", "-mode", "tree", "-repo", dir, "-patterns", pf+".missing"); code != exitError {
		t.Errorf("missing file: code %d", code)
	}
}

func TestTreeReportsFileAndLineOnly(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "docs/a.md", "one\ntwo "+strings.ToUpper(word)+" two\n")
	code, out := run(t, word, "-mode", "tree", "-repo", dir)
	if code != exitHit {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out, "docs/a.md:2") {
		t.Errorf("missing location:\n%s", out)
	}
	assertNoLeak(t, out)
}

func TestTreeCleanAndIgnoredFiles(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, ".gitignore", ".env\n")
	write(t, dir, ".env", word+"\n") // git の管理外は読まない
	if code, out := run(t, word, "-mode", "tree", "-repo", dir); code != exitOK {
		t.Errorf("code %d\n%s", code, out)
	}
	write(t, dir, "new-untracked.txt", word+"\n") // 未追跡でも .gitignore に無いものは読む
	if code, out := run(t, word, "-mode", "tree", "-repo", dir); code != exitHit {
		t.Errorf("code %d\n%s", code, out)
	}
}

func TestMatchingFileNameIsMasked(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "x-"+word+".txt", "body\n")
	code, out := run(t, word, "-mode", "tree", "-repo", dir)
	if code != exitHit {
		t.Fatalf("code %d\n%s", code, out)
	}
	assertNoLeak(t, out)
}

func TestMatchingFileNameAndBodyIsMasked(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "x-"+word+".txt", word+"\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "add")
	for _, mode := range []string{"tree", "history"} {
		code, out := run(t, word, "-mode", mode, "-repo", dir)
		if code != exitHit {
			t.Fatalf("%s: code %d\n%s", mode, code, out)
		}
		assertNoLeak(t, out)
	}
}

func TestHistoryFindsDeletedFile(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "gone.txt", "a\n"+word+"\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "add")
	git(t, dir, "rm", "-q", "gone.txt")
	git(t, dir, "commit", "-q", "-m", "remove")
	if code, _ := run(t, word, "-mode", "tree", "-repo", dir); code != exitOK {
		t.Errorf("tree: code %d", code)
	}
	code, out := run(t, word, "-mode", "history", "-repo", dir)
	if code != exitHit {
		t.Fatalf("history: code %d\n%s", code, out)
	}
	if !strings.Contains(out, "gone.txt:2") {
		t.Errorf("missing location:\n%s", out)
	}
	assertNoLeak(t, out)
}

func TestHistoryFindsCommitMessageTagAndRef(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string){
		"message": func(t *testing.T, dir string) {
			git(t, dir, "commit", "-q", "--allow-empty", "-m", "subject", "-m", "see "+word)
		},
		"annotated tag": func(t *testing.T, dir string) {
			git(t, dir, "tag", "-a", "v1", "-m", word)
		},
		"branch name": func(t *testing.T, dir string) {
			git(t, dir, "branch", "feat/"+word)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := newRepo(t)
			setup(t, dir)
			code, out := run(t, word, "-mode", "history", "-repo", dir)
			if code != exitHit {
				t.Fatalf("code %d\n%s", code, out)
			}
			assertNoLeak(t, out)
		})
	}
}

// コミットの作者欄は公開前提で、検査の対象外 (ADR 0036)。
func TestHistoryIgnoresAuthorAndCommitter(t *testing.T) {
	dir := newRepo(t)
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "x", "--author", word+" <"+word+"@example.com>")
	if code, out := run(t, word, "-mode", "history", "-repo", dir); code != exitOK {
		t.Errorf("code %d\n%s", code, out)
	}

	var hits []int
	commit := "tree abc\nauthor fumu <a@example.com> 1 +0000\ncommitter fumu <a@example.com> 1 +0000\n\nauthor fumu in message\n"
	scanLines([]byte(commit), patterns(t, "fumu"), true, func(n int) { hits = append(hits, n) })
	if len(hits) != 1 || hits[0] != 5 {
		t.Errorf("hits %v, want only the message line 5", hits)
	}
}

func TestHistoryClean(t *testing.T) {
	dir := newRepo(t)
	if code, out := run(t, word, "-mode", "history", "-repo", dir); code != exitOK {
		t.Errorf("code %d\n%s", code, out)
	}
}

// 短い語は、ロックファイルのハッシュや署名の base64 に偶然現れる。ここで誤検知すると検査が信用されなくなる。
func TestHashesAndSignaturesAreNotScanned(t *testing.T) {
	ps := patterns(t, "fumu")
	for _, line := range []string{
		"    resolution: {integrity: sha512-abcdefghFuMuabcdefghijklmnopqrstuvwxyz0123456789+/==}",
		"github.com/example/mod v1.2.3 h1:abcdefghFuMuabcdefghijklmnopqrstuvwxyz0123=",
	} {
		if matchLine(ps, []byte(line)) {
			t.Errorf("false positive: %s", line)
		}
	}
	if !matchLine(ps, []byte("sha512-short fumu")) {
		t.Error("text beside a hash must still be scanned")
	}

	commit := "tree abc\nauthor a\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n FuMuAbC\n -----END PGP SIGNATURE-----\n\nfumu in message\n"
	var hits []int
	scanLines([]byte(commit), ps, true, func(n int) { hits = append(hits, n) })
	if len(hits) != 1 || hits[0] != 8 {
		t.Errorf("hits %v, want only the message line 8", hits)
	}
}

func TestDirMode(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pr-1.txt", "title\nhand written "+word+"\n")
	write(t, dir, "pr-2.txt", "clean\n")
	code, out := run(t, word, "-mode", "dir", "-dir", dir)
	if code != exitHit {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out, "pr-1.txt:2") || strings.Contains(out, "pr-2.txt") {
		t.Errorf("out:\n%s", out)
	}
	assertNoLeak(t, out)
}

// GitHub の自動生成のノートの @login は作者の表示で隠せないので除く。手で書いた本文は検出する (ADR 0036)。
func TestGitHubNotes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "release-v1.txt", strings.Join([]string{
		"* [AI] something by @" + word + " in https://github.com/example/repo/pull/1",
		"* @" + word + " made their first contribution in https://github.com/example/repo/pull/1",
	}, "\n")+"\n")
	if code, out := run(t, word, "-mode", "dir", "-dir", dir, "-github-notes"); code != exitOK {
		t.Errorf("auto lines: code %d\n%s", code, out)
	}
	if code, _ := run(t, word, "-mode", "dir", "-dir", dir); code != exitHit {
		t.Errorf("without the flag the login must match: code %d", code)
	}

	for _, line := range []string{
		"contact @" + word + " for details",
		"* " + word + " fix by @alice in https://github.com/example/repo/pull/1",
		"thanks to " + word,
	} {
		d := t.TempDir()
		write(t, d, "pr-1.txt", line+"\n")
		if code, out := run(t, word, "-mode", "dir", "-dir", d, "-github-notes"); code != exitHit {
			t.Errorf("%q: code %d\n%s", line, code, out)
		}
	}
}

func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(strings.ToLower(out), word) {
		t.Errorf("output leaks the word:\n%s", out)
	}
}
