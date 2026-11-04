package store

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// ErrConflict は開始してから別の実行が S3 のストアを書いたとき (code: STORE_CONFLICT)。上書きせずに失敗させる。
var ErrConflict = errors.New("store: another run updated the S3 store first; nothing was overwritten, run it again")

// ErrS3Unavailable は S3 に問い合わせられなかったとき (権限・通信。code: STORE_UNAVAILABLE)。ストアの破損とは区別する。
var ErrS3Unavailable = errors.New("store: S3 store is unavailable")

// ErrDatabaseTooLarge は S3 の SQLite を展開すると maxDatabaseBytes を超えるとき。バケットの中身の破損か改ざんを疑う。
var ErrDatabaseTooLarge = errors.New("store: the S3 database is larger than the limit when decompressed")

// maxDatabaseBytes は S3 の SQLite を展開するときの上限。
// 決定 (ADR 0037): 圧縮率の高いオブジェクトで実行環境のディスクを埋めさせない。設計書の見積もりは年に数百 MB までなので、十分に余裕を見た固定値にする (設定は足さない)。
const maxDatabaseBytes int64 = 8 << 30

// ErrObjectTooLarge は S3 のオブジェクトが maxObjectBytes を超えるとき。
var ErrObjectTooLarge = errors.New("store: an S3 object is larger than the limit")

// maxObjectBytes は S3 から取得する 1 オブジェクトの上限 (変数なのはテストのため)。決定の理由は maxDatabaseBytes と同じ。
var maxObjectBytes int64 = 8 << 30

// S3API はストアと doctor が使う S3 の操作。*s3.Client が満たす。
type S3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetBucketVersioning(ctx context.Context, in *s3.GetBucketVersioningInput, opts ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// S3DatabaseObject は S3 の SQLite のオブジェクト名 (prefix の下)。
const S3DatabaseObject = dbFile + ".gz"

// S3Location はストアの置き場所。
type S3Location struct {
	Bucket string
	Prefix string // 末尾の / は持たない。空ならバケットの直下
}

// Key は prefix の下の相対パスのオブジェクトキー。
func (l S3Location) Key(rel string) string {
	if l.Prefix == "" {
		return rel
	}
	return l.Prefix + "/" + rel
}

// URL は相対パスの s3:// の表記 (ログと出力用)。
func (l S3Location) URL(rel string) string { return "s3://" + l.Bucket + "/" + l.Key(rel) }

// s3Object は開始時に見たオブジェクト。etag が空なら S3 に無かった。
type s3Object struct {
	etag string
	sum  [sha256.Size]byte
}

// S3 は s3:// バックエンド。実行のたびに一時ディレクトリへ出し入れする作業用の複製で、読み書きは Dir がそのまま担う (ADR 0034)。
//
// 決定: 確定は明示の Commit だけが行う。呼ばずに Close すれば (失敗・中断・パニック・読むだけのコマンド) S3 は開始前のまま。
// 決定: raw は日のファイルに初めて追記するときに取得する。ファイルの日は run の窓ではなくレコードの時刻で決まるので、
// 窓から予測すると外れた日のファイルを丸ごと置き換えて S3 の行を消し得る。転送も追記した日だけになる。
type S3 struct {
	*Dir
	api  S3API
	loc  S3Location
	work string

	mu      sync.Mutex
	objects map[string]s3Object // 取得した raw と reports (ストアのディレクトリからの相対パス)
	dbETag  string
	done    bool
	// rawOrphaned は S3 に SQLite が無いのに raw があった。
	rawOrphaned bool
}

var _ Store = (*S3)(nil)

// OpenS3 は SQLite と reports/ を一時ディレクトリへ取得して開く。S3 に SQLite が無ければ空のストアで始める (Commit で初めて作る)。
// 権限・通信の失敗は ErrS3Unavailable で、「無い」とは扱わない (空のストアで始めると全部が new として報告されるため)。
func OpenS3(ctx context.Context, api S3API, loc S3Location) (*S3, error) {
	work, err := os.MkdirTemp("", "arata-store-")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s, err := openS3(ctx, api, loc, work)
	if err != nil {
		os.RemoveAll(work)
		return nil, err
	}
	return s, nil
}

func openS3(ctx context.Context, api S3API, loc S3Location, work string) (*S3, error) {
	dir := filepath.Join(work, "store")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	gz := filepath.Join(work, S3DatabaseObject)
	obj, err := download(ctx, api, loc, S3DatabaseObject, gz)
	if err != nil {
		return nil, err
	}
	if obj.etag != "" {
		if err := gunzipFile(gz, filepath.Join(dir, dbFile), maxDatabaseBytes); err != nil {
			return nil, fmt.Errorf("store: %s: %w", loc.URL(S3DatabaseObject), err)
		}
	}
	s := &S3{api: api, loc: loc, work: work, objects: map[string]s3Object{}, dbETag: obj.etag}
	reports, err := listObjects(ctx, api, loc, "reports/")
	if err != nil {
		return nil, err
	}
	for _, rel := range reports {
		o, err := download(ctx, api, loc, rel, filepath.Join(dir, rel))
		if err != nil {
			return nil, err
		}
		s.objects[rel] = o
	}
	if s.Dir, err = Open(dir); err != nil {
		return nil, err
	}
	s.Dir.beforeAppend = s.fetchRaw
	if obj.etag == "" {
		prefix := loc.Key("raw/")
		out, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &loc.Bucket, Prefix: &prefix, MaxKeys: aws.Int32(1)})
		if err != nil {
			s.Dir.Close()
			return nil, unavailable(ctx, "list", prefix, err)
		}
		s.rawOrphaned = len(out.Contents) > 0
	}
	return s, nil
}

// RawWithoutDatabase は開始時に S3 に SQLite が無く raw があったか (SQLite が失われた疑い。初回は raw も無い)。
// 呼び出し側は書き込みを進めないこと (Commit すると空の SQLite が状態を上書きする)。
func (s *S3) RawWithoutDatabase() bool { return s.rawOrphaned }

// fetchRaw は raw のファイルに初めて追記する前に、S3 の今の内容を取得する。
func (s *S3) fetchRaw(ctx context.Context, rel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[rel]; ok {
		return nil
	}
	o, err := download(ctx, s.api, s.loc, rel, filepath.Join(s.Dir.dir, rel))
	if err != nil {
		return err
	}
	s.objects[rel] = o
	return nil
}

// Commit は変わったファイルを S3 へ書き戻す。呼べるのは 1 回で、以後このストアは読み書きできない (Close だけ)。
//
// 決定: 順序は SQLite の事前の確かめ → raw・reports (変わったものだけ) → SQLite。すべて条件付きで、SQLite が書けたら確定。
// raw も条件付きにするのは、S3 が追記できず日のファイルを丸ごと置き換えるため (無条件だと先に終わった実行の行を消す)。
// SQLite の前で失敗すると raw だけが先に進むが、次の run は古い SQLite から同じ窓を引き直すので SQLite では二重に数えない (ADR 0034)。
func (s *S3) Commit(ctx context.Context) error {
	if s.done {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.done = true
	if _, err := s.Dir.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return wrap(err)
	}
	if err := s.Dir.Close(); err != nil {
		return err
	}
	gz := filepath.Join(s.work, S3DatabaseObject)
	if err := gzipFile(filepath.Join(s.Dir.dir, dbFile), gz); err != nil {
		return err
	}
	if err := s.checkUnchanged(ctx); err != nil {
		return err
	}
	changed, err := s.changedFiles()
	if err != nil {
		return err
	}
	for _, rel := range changed {
		if err := upload(ctx, s.api, s.loc, rel, filepath.Join(s.Dir.dir, rel), s.objects[rel].etag); err != nil {
			return err
		}
	}
	return upload(ctx, s.api, s.loc, S3DatabaseObject, gz, s.dbETag)
}

// checkUnchanged は SQLite が開始時のままか確かめる。負けが確かな実行が raw を進めないための早めの判定で、排他そのものは条件付きの書き込みが担う。
func (s *S3) checkUnchanged(ctx context.Context) error {
	key := s.loc.Key(S3DatabaseObject)
	out, err := s.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.loc.Bucket, Key: &key})
	etag := ""
	switch {
	case err == nil:
		etag = aws.ToString(out.ETag)
	case HTTPStatus(err) != http.StatusNotFound:
		return unavailable(ctx, "head", key, err)
	}
	if etag != s.dbETag {
		return fmt.Errorf("%w (%s)", ErrConflict, key)
	}
	return nil
}

// changedFiles は取得したものから内容が変わったファイルと、新しくできた reports/ を返す。
func (s *S3) changedFiles() ([]string, error) {
	out := []string{}
	for rel, o := range s.objects {
		sum, err := fileSum(filepath.Join(s.Dir.dir, rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		if sum != o.sum {
			out = append(out, rel)
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.Dir.dir, "reports"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("store: %w", err)
	}
	for _, e := range entries {
		rel := "reports/" + e.Name()
		if _, ok := s.objects[rel]; !ok && e.Type().IsRegular() {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Close は開いていれば閉じ、一時ディレクトリを消す。Commit していなければ何も送らない。
func (s *S3) Close() error {
	err := s.Dir.Close()
	if rerr := os.RemoveAll(s.work); rerr != nil && err == nil {
		err = fmt.Errorf("store: %w", rerr)
	}
	return err
}

// RebuildS3 は raw を全部取得して SQLite を作り直し、SQLite だけを条件付きで置き換える (ADR 0033・0034)。
// 決定: 元の SQLite の .bak は残さない (S3 のバージョニングが世代を持つ)。--from-scratch は壊れたオブジェクトを読まないが、ETag は条件に使う。
func RebuildS3(ctx context.Context, api S3API, loc S3Location, o RebuildOptions) (*RebuildResult, error) {
	work, err := os.MkdirTemp("", "arata-store-")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer os.RemoveAll(work)
	dir := filepath.Join(work, "store")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	gz := filepath.Join(work, S3DatabaseObject)
	db, err := download(ctx, api, loc, S3DatabaseObject, gz)
	if err != nil {
		return nil, err
	}
	if db.etag != "" && !o.FromScratch {
		if err := gunzipFile(gz, filepath.Join(dir, dbFile), maxDatabaseBytes); err != nil {
			return nil, fmt.Errorf("store: %s: %w", loc.URL(S3DatabaseObject), err)
		}
	}
	raw, err := listObjects(ctx, api, loc, "raw/")
	if err != nil {
		return nil, err
	}
	for _, rel := range raw {
		if _, err := download(ctx, api, loc, rel, filepath.Join(dir, rel)); err != nil {
			return nil, err
		}
	}
	res, err := Rebuild(ctx, dir, o)
	if err != nil {
		return nil, err
	}
	if err := gzipFile(filepath.Join(dir, dbFile), gz); err != nil {
		return nil, err
	}
	if err := upload(ctx, api, loc, S3DatabaseObject, gz, db.etag); err != nil {
		return nil, err
	}
	res.Dir, res.Database, res.Backup = loc.URL(""), loc.URL(S3DatabaseObject), ""
	return res, nil
}

// download はオブジェクトを path に取得する。無ければ空の s3Object を返す (path は作らない)。
func download(ctx context.Context, api S3API, loc S3Location, rel, path string) (s3Object, error) {
	key := loc.Key(rel)
	out, err := api.GetObject(ctx, &s3.GetObjectInput{Bucket: &loc.Bucket, Key: &key})
	if err != nil {
		if HTTPStatus(err) == http.StatusNotFound {
			return s3Object{}, nil
		}
		return s3Object{}, unavailable(ctx, "get", key, err)
	}
	defer out.Body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return s3Object{}, fmt.Errorf("store: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return s3Object{}, fmt.Errorf("store: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(out.Body, maxObjectBytes+1))
	if err != nil {
		os.Remove(path)
		return s3Object{}, unavailable(ctx, "get", key, err)
	}
	if n > maxObjectBytes {
		os.Remove(path)
		return s3Object{}, fmt.Errorf("%w: %s", ErrObjectTooLarge, key)
	}
	o := s3Object{etag: aws.ToString(out.ETag)}
	copy(o.sum[:], h.Sum(nil))
	return o, nil
}

// upload は path を置く。etag が空なら「まだ無いこと」を、あれば「開始時のままであること」を条件にする。
func upload(ctx context.Context, api S3API, loc S3Location, rel, path, etag string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer f.Close()
	key := loc.Key(rel)
	in := &s3.PutObjectInput{Bucket: &loc.Bucket, Key: &key, Body: f}
	if etag == "" {
		in.IfNoneMatch = aws.String("*")
	} else {
		in.IfMatch = aws.String(etag)
	}
	if _, err := api.PutObject(ctx, in); err != nil {
		switch HTTPStatus(err) {
		// 412 は条件の不一致、409 は同時の条件付き書き込みの衝突、404 は If-Match の対象が消された
		case http.StatusPreconditionFailed, http.StatusConflict, http.StatusNotFound:
			return fmt.Errorf("%w (%s)", ErrConflict, key)
		}
		return unavailable(ctx, "put", key, err)
	}
	return nil
}

// listObjects は prefix の下のオブジェクトを、ストアからの相対パスで返す。
func listObjects(ctx context.Context, api S3API, loc S3Location, sub string) ([]string, error) {
	prefix := loc.Key(sub)
	in := &s3.ListObjectsV2Input{Bucket: &loc.Bucket, Prefix: &prefix}
	out := []string{}
	for {
		page, err := api.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, unavailable(ctx, "list", prefix, err)
		}
		for _, o := range page.Contents {
			if rel, ok := relativeKey(loc, sub, aws.ToString(o.Key)); ok {
				out = append(out, rel)
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			return out, nil
		}
		in.ContinuationToken = page.NextContinuationToken
	}
}

// relativeKey はキーをストアからの相対パスにする。sub の下の、正規化しても同じパスだけを受ける。
// 決定 (ADR 0037): キーは信用しない。`reports/../audit.sqlite` のように、一時ディレクトリの外や sub の外のファイルを置き換えるキーは取得しない。
func relativeKey(loc S3Location, sub, key string) (string, bool) {
	rel, ok := strings.CutPrefix(key, loc.Key(""))
	if !ok || !strings.HasPrefix(rel, sub) || path.Clean(rel) != rel || !filepath.IsLocal(rel) {
		return "", false
	}
	return rel, true
}

// HTTPStatus は S3 の応答の状態 (応答が無ければ 0)。
func HTTPStatus(err error) int {
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

func unavailable(ctx context.Context, op, key string, err error) error {
	if c := ctx.Err(); c != nil {
		return fmt.Errorf("store: %s %s: %w", op, key, c)
	}
	return fmt.Errorf("%w: %s %s: %v", ErrS3Unavailable, op, key, err)
}

func fileSum(path string) (sum [sha256.Size]byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer out.Close()
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return out.Close()
}

// gunzipFile は src を dst に展開する。limit バイトを超えたら ErrDatabaseTooLarge で止め、dst を消す。
func gunzipFile(src, dst string, limit int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(zr, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		out.Close()
		os.Remove(dst)
		return ErrDatabaseTooLarge
	}
	return out.Close()
}
