// wordscan は公開できない語 (顧客名など) がリポジトリに入っていないかを確かめる小さなツール。
// 語の一覧はリポジトリに置けないので、環境変数 SENSITIVE_PATTERNS か -patterns のファイルから読む (ADR 0036)。
//
//	SENSITIVE_PATTERNS="$(cat list.txt)" go run ./tools/wordscan -mode history
//	go run ./tools/wordscan -patterns list.txt -mode tree
//
// コミットの作者欄は公開前提で、検査の対象外 (ADR 0036)。
// 一覧は 1 行 1 つの正規表現 (大文字小文字を区別しない)。空行と # で始まる行は読み飛ばす。
//
// モード:
//
//	tree     作業ツリーの、git の管理下と未追跡のファイル (.gitignore のものは読まない)
//	history  全参照から届く全オブジェクト (削除されたファイル、コミットメッセージ、タグ) と参照の名前
//	dir      -dir の下のファイル。GitHub の本文を書き出したものに使う
//
// 出力は場所だけ。CI のログは公開されるので、語・一致した行・語を含むファイル名を出さない。
// 終了コード: 0 = 一致なし、1 = 一致あり、2 = 入力のエラー (語の一覧が空のときを含む。判定できないものは通さない)。
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	exitOK    = 0
	exitHit   = 1
	exitError = 2
)

type pattern struct {
	re *regexp.Regexp
}

// ロックファイルの整合性ハッシュ。base64 に短い語が偶然現れるので、照合の前に除く。
var hashRe = regexp.MustCompile(`(?:sha1-|sha256-|sha512-|h1:)[A-Za-z0-9+/=]{20,}`)

// GitHub の自動生成のリリースノートの @login。PR の作者の表示として公開時に必ず見えるので除く (ADR 0036)。
var (
	noteByRe    = regexp.MustCompile(`^(\* .* by )@[A-Za-z0-9-]+( in https://github\.com/\S+/pull/[0-9]+\s*)$`)
	noteFirstRe = regexp.MustCompile(`^(\* )@[A-Za-z0-9-]+( made their first contribution in https://github\.com/)`)
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Getenv("SENSITIVE_PATTERNS"), os.Stdout))
}

func realMain(args []string, env string, out io.Writer) int {
	flags := flag.NewFlagSet("wordscan", flag.ContinueOnError)
	flags.SetOutput(out)
	mode := flags.String("mode", "tree", "tree | history | dir")
	repo := flags.String("repo", ".", "git リポジトリ (tree / history)")
	dir := flags.String("dir", "", "読むディレクトリ (dir)")
	patternsFile := flags.String("patterns", "", "語の一覧のファイル。無ければ環境変数 SENSITIVE_PATTERNS")
	notes := flags.Bool("github-notes", false, "GitHub の自動生成のノートの @login を除いて照合する")
	if err := flags.Parse(args); err != nil {
		return exitError
	}

	text := env
	if *patternsFile != "" {
		b, err := os.ReadFile(*patternsFile)
		if err != nil {
			fmt.Fprintln(out, "wordscan: 語の一覧のファイルを読めません")
			return exitError
		}
		text = string(b)
	}
	ps, err := parsePatterns(text)
	if err != nil {
		fmt.Fprintln(out, "wordscan:", err)
		return exitError
	}
	if len(ps) == 0 {
		fmt.Fprintln(out, "wordscan: 語の一覧が空です (SENSITIVE_PATTERNS か -patterns)")
		return exitError
	}

	s := &scanner{ps: ps, notes: *notes, out: out}
	switch *mode {
	case "tree":
		err = s.tree(*repo)
	case "history":
		err = s.history(*repo)
	case "dir":
		err = s.dir(*dir)
	default:
		err = errors.New("-mode は tree / history / dir のどれかです")
	}
	if err != nil {
		fmt.Fprintln(out, "wordscan:", err)
		return exitError
	}
	if s.hits > 0 {
		fmt.Fprintf(out, "wordscan: %d 件の一致 (語は出力しません。docs/sensitive-scan.md)\n", s.hits)
		return exitHit
	}
	fmt.Fprintln(out, "wordscan: 一致なし")
	return exitOK
}

// parsePatterns は一覧を読む。regexp のエラーはパターンを含むので、行番号だけを返す。
func parsePatterns(text string) ([]*pattern, error) {
	var ps []*pattern
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile("(?i)" + line)
		if err != nil {
			return nil, fmt.Errorf("語の一覧の %d 行目は正規表現として読めません", i+1)
		}
		ps = append(ps, &pattern{re: re})
	}
	return ps, nil
}

func matchLine(ps []*pattern, line []byte) bool {
	line = hashRe.ReplaceAll(line, nil)
	for _, p := range ps {
		if p.re.Match(line) {
			return true
		}
	}
	return false
}

// scanLines は一致した行の番号 (1 始まり) を hit に渡す。commit が真ならヘッダの署名 (base64) と作者欄を読み飛ばす。
func scanLines(content []byte, ps []*pattern, commit bool, hit func(line int)) {
	inHeader, inSig := commit, false
	for i, line := range bytes.Split(content, []byte("\n")) {
		if inHeader {
			if len(line) == 0 {
				inHeader = false
			}
			if bytes.HasPrefix(line, []byte("gpgsig")) {
				inSig = true
				continue
			}
			if inSig && bytes.HasPrefix(line, []byte(" ")) {
				continue
			}
			inSig = false
			if bytes.HasPrefix(line, []byte("author ")) || bytes.HasPrefix(line, []byte("committer ")) {
				continue
			}
		}
		if matchLine(ps, line) {
			hit(i + 1)
		}
	}
}

type scanner struct {
	ps    []*pattern
	notes bool
	out   io.Writer
	hits  int
}

func (s *scanner) report(format string, args ...any) {
	s.hits++
	fmt.Fprintf(s.out, format+"\n", args...)
}

func (s *scanner) nameMatches(name string) bool {
	return matchLine(s.ps, []byte(name))
}

// file は 1 つのファイルを照合する。名前が一致するときは名前を出さず、一覧の中の順番で示す。
func (s *scanner) file(name string, index int, content []byte) {
	label := name
	if s.nameMatches(name) {
		label = "file#" + strconv.Itoa(index)
		s.report("%s: ファイル名が一致", label)
	}
	if s.notes {
		content = stripNotes(content)
	}
	scanLines(content, s.ps, false, func(line int) { s.report("%s:%d", label, line) })
}

func stripNotes(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		line = noteByRe.ReplaceAll(line, []byte("$1$2"))
		lines[i] = noteFirstRe.ReplaceAll(line, []byte("$1$2"))
	}
	return bytes.Join(lines, []byte("\n"))
}

func (s *scanner) tree(repo string) error {
	out, err := gitOutput(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	names := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	sort.Strings(names)
	for i, name := range names {
		if name == "" {
			continue
		}
		path := filepath.Join(repo, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue // 削除したばかりのファイルと、シンボリックリンク・サブモジュール
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("file#%d を読めません", i+1)
		}
		s.file(name, i+1, content)
	}
	return nil
}

func (s *scanner) dir(root string) error {
	if root == "" {
		return errors.New("-dir を指定してください")
	}
	index := 0
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		index++
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		s.file(name, index, content)
		return nil
	})
}

func (s *scanner) history(repo string) error {
	refs, err := gitOutput(repo, "for-each-ref", "--format=%(refname)")
	if err != nil {
		return err
	}
	for i, ref := range strings.Split(strings.TrimSpace(string(refs)), "\n") {
		if s.nameMatches(ref) {
			s.report("ref#%d: 参照の名前が一致", i+1)
		}
	}

	objects, err := gitOutput(repo, "rev-list", "--objects", "--all")
	if err != nil {
		return err
	}
	paths := map[string]string{}
	var oids []string
	for _, line := range strings.Split(strings.TrimSpace(string(objects)), "\n") {
		oid, path, _ := strings.Cut(line, " ")
		if oid == "" {
			continue
		}
		oids = append(oids, oid)
		paths[oid] = path
	}
	return catFile(repo, oids, func(oid, kind string, content []byte) {
		switch kind {
		case "blob":
			label := paths[oid]
			if s.nameMatches(label) {
				label = "(名前を伏せたファイル)"
			}
			scanLines(content, s.ps, false, func(line int) { s.report("blob %s %s:%d", oid[:12], label, line) })
		case "commit":
			scanLines(content, s.ps, true, func(line int) { s.report("commit %s:%d", oid[:12], line) })
		case "tag":
			scanLines(content, s.ps, false, func(line int) { s.report("tag %s:%d", oid[:12], line) })
		case "tree":
			// ファイル名は tree に入っている。削除されたファイルの名前もここで見つかる
			found := false
			scanLines(content, s.ps, false, func(int) { found = true })
			if found {
				s.report("tree %s: ファイル名が一致", oid[:12])
			}
		}
	})
}

func gitOutput(repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s に失敗しました: %w", args[0], err)
	}
	return out, nil
}

// catFile は git cat-file --batch でオブジェクトを 1 つのプロセスから読む。
func catFile(repo string, oids []string, fn func(oid, kind string, content []byte)) error {
	cmd := exec.Command("git", "-C", repo, "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(strings.Join(oids, "\n") + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	r := bufio.NewReader(stdout)
	for range oids {
		header, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("git cat-file の出力を読めません: %w", err)
		}
		fields := strings.Fields(header)
		if len(fields) != 3 {
			return errors.New("git cat-file の出力の形が想定外です")
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			return err
		}
		content := make([]byte, size+1) // 末尾の改行まで読む
		if _, err := io.ReadFull(r, content); err != nil {
			return err
		}
		fn(fields[0], fields[1], content[:size])
	}
	return cmd.Wait()
}
