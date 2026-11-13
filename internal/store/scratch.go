package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Scratch は dir:// のストアを一時ディレクトリへ複製したもの (試しの実行 `arata run --dry-run`。ADR 0049)。
// 読み書きは複製に対して Dir がそのまま担い、Close で複製を消す。元のディレクトリには何も書かない。
//
// 決定: 重ね合わせの層 (メモリ上の差分を SQL の結果に重ねる) を作らず、複製の上でふだんと同じコードを動かす。
// 判定の規則を 2 か所に持たないので、試しの実行と定時の実行の結果がずれない。S3 のストアは元から同じ作りで、Commit しなければ何も送らない。
type Scratch struct {
	*Dir
	work string
}

var _ Store = (*Scratch)(nil)

// OpenScratch は dir の SQLite を一時ディレクトリへ複製して開く。dir にストアがまだ無ければ空の複製で始める (dir は作らない)。
//
// 決定: ロックは複製する間だけ取り、取れなければ ErrLocked (書き込み中の実行の途中の状態を読まない)。複製が済んだら放すので、
// 試しの収集の間に定時の実行を止めない。ロックのファイルは作らない (無ければ、まだ誰も書いていないストアとしてそのまま読む)。
// 決定: SQLite を元の場所で開かない。WAL モードは読むだけでも -wal / -shm を作り、チェックポイントで本体を書き換え得る。
// 本体と、異常終了で残った -wal をバイトのまま写し、複製の側で開く (-wal の内容は複製の側で取り込まれる)。raw は写さない (run は読まない)。
func OpenScratch(dir string) (*Scratch, error) {
	work, err := os.MkdirTemp("", "arata-dry-run-")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s, err := openScratch(dir, work)
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	return s, nil
}

func openScratch(dir, work string) (*Scratch, error) {
	dst := filepath.Join(work, "store")
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := copyDatabase(dir, dst); err != nil {
		return nil, err
	}
	d, err := Open(dst)
	if err != nil {
		return nil, err
	}
	return &Scratch{Dir: d, work: work}, nil
}

// copyDatabase はロックを持った状態で dir の SQLite (と残っていれば -wal) を dst へ写す。
func copyDatabase(dir, dst string) error {
	lock, err := os.Open(filepath.Join(dir, "audit.lock"))
	switch {
	case err == nil:
		defer lock.Close()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return ErrLocked
			}
			return fmt.Errorf("store: lock: %w", err)
		}
		defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("store: %w", err)
	}
	for _, name := range []string{dbFile, dbFile + "-wal"} {
		if err := copyFile(filepath.Join(dir, name), filepath.Join(dst, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Commit は何もしない (複製は捨てる)。
func (s *Scratch) Commit(context.Context) error { return nil }

// Close は複製を閉じて消す。
func (s *Scratch) Close() error {
	err := s.Dir.Close()
	if rerr := os.RemoveAll(s.work); rerr != nil && err == nil {
		err = fmt.Errorf("store: %w", rerr)
	}
	return err
}

// OpenS3Scratch は S3 のストアの SQLite だけを一時ディレクトリへ取得して開く (試しの実行。ADR 0049)。
// 決定: S3 のストアにロックは無く (排他は Commit の条件付きの書き込み。ADR 0034)、読むだけの実行は 1 回の取得で整合した SQLite を得るので、何も取らない。
// Commit は何も送らず、raw への追記の前の取得もしない (追記は複製の中だけで、捨てる)。reports/ も取得しない。
func OpenS3Scratch(ctx context.Context, api S3API, loc S3Location) (*S3, error) {
	work, err := os.MkdirTemp("", "arata-dry-run-")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s, err := openS3(ctx, api, loc, work, true)
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	return s, nil
}
