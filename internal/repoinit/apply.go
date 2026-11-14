package repoinit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Action は Apply が 1 つのファイルにしたこと。
type Action string

const (
	Created     Action = "created"     // 無かったので作った
	Unchanged   Action = "unchanged"   // 生成物が同じ中身で既にある
	Differs     Action = "differs"     // 生成物が違う中身で既にある (書いていない。--force で書き直す)
	Overwritten Action = "overwritten" // 生成物を --force で書き直した
	Kept        Action = "kept"        // 利用者が育てるファイルが既にある (どの指定でも書き直さない)
)

// Result は Apply の 1 つのファイルの結果。
type Result struct {
	Path   string
	Kind   Kind
	Action Action
}

// maxExisting は、比べるために読む既存のファイルの大きさの上限。超えるものは「違う」として扱い、中身は読まない。
const maxExisting = 1 << 20

// Apply は一式を dir に書く。既定では 1 つも上書きしない (無いファイルだけを作る)。
// force なら生成物だけを書き直す。利用者が育てるファイル (Seed) は、どの指定でも書き直さない。
//
// 書く先を先に全部確かめ、1 つでもふつうのファイルでない (シンボリックリンク、ディレクトリなど)・途中がシンボリックリンクなら、
// 何も書かずにエラーにする (リンクをたどって dir の外に書かない)。
func Apply(dir string, files []File, force bool) ([]Result, error) {
	results := make([]Result, len(files))
	write := make([]bool, len(files))
	var missing []string
	for i, f := range files {
		cur, exists, err := readTarget(dir, f.Path)
		if err != nil {
			return nil, err
		}
		r := Result{Path: f.Path, Kind: f.Kind}
		switch {
		case !exists:
			r.Action, write[i] = Created, true
			missing = append(missing, f.Missing...)
		case f.Kind == Seed:
			r.Action = Kept
		case cur != nil && bytes.Equal(cur, f.Body):
			r.Action = Unchanged
		case force:
			r.Action, write[i] = Overwritten, true
		default:
			r.Action = Differs
		}
		results[i] = r
	}
	if len(missing) > 0 {
		// 新しく作る aratam.yaml のチャンネル ID が足りない。空の値で書き出さない (ADR 0060)。1 つも書かない
		return nil, &MissingArgsError{Args: missing}
	}
	for i, f := range files {
		if !write[i] {
			continue
		}
		if err := writeFile(filepath.Join(dir, filepath.FromSlash(f.Path)), f.Body, f.Mode); err != nil {
			return nil, err
		}
	}
	return results, nil
}

// readTarget は dir の下の rel を読む。無ければ exists=false。大きすぎれば中身は nil (exists=true)。
// rel の途中のディレクトリと rel そのものが、シンボリックリンクなどでないことを確かめる。
func readTarget(dir, rel string) (body []byte, exists bool, err error) {
	parts := strings.Split(rel, "/")
	p := dir
	for i, part := range parts {
		p = filepath.Join(p, part)
		st, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		last := i == len(parts)-1
		switch {
		case !last && !st.IsDir():
			return nil, false, fmt.Errorf("%s: not a directory (symbolic links are not followed)", p)
		case last && !st.Mode().IsRegular():
			return nil, false, fmt.Errorf("%s: not a regular file (symbolic links are not followed)", p)
		case last && st.Size() > maxExisting:
			return nil, true, nil
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	body, err = io.ReadAll(io.LimitReader(f, maxExisting+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxExisting {
		return nil, true, nil
	}
	return body, true, nil
}

// writeFile は一時ファイルに書いてから置き換える (書きかけを残さない。置き換えはリンクをたどらない)。
func writeFile(path string, body []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- git で管理するリポジトリの作業ツリー。秘密は書かない
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".arata-repo-init-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// MissingArgsError は、新しく作るファイルに要る引数が足りないこと。
type MissingArgsError struct{ Args []string }

func (e *MissingArgsError) Error() string {
	return "missing arguments for the files to create: " + strings.Join(e.Args, " ") + " (there are no defaults; nothing was written)"
}

// NewAccounts は、aws/<アカウント>/aratam.yaml がまだ無いアカウント (新しく作るので、チャンネル ID が要る) を、accounts の順で返す。
func NewAccounts(dir string, accounts []string) ([]string, error) {
	var out []string
	for _, a := range accounts {
		if !accountRE.MatchString(a) {
			continue // 形の誤りは Validate が出す
		}
		_, exists, err := readTarget(dir, "aws/"+a+"/aratam.yaml")
		if err != nil {
			return nil, err
		}
		if !exists {
			out = append(out, a)
		}
	}
	return out, nil
}
