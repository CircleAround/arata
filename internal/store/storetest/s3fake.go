package storetest

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Request は FakeS3 が受けた要求 1 件。
type S3Request struct {
	Method, Key, IfMatch, IfNoneMatch string
	Status                            int
}

// FakeS3 は S3 の HTTP API の最小限の偽物 (path-style)。PutObject / GetObject / HeadObject / ListObjectsV2 と、
// doctor が読むバケットの設定に答える。If-Match / If-None-Match と ETag は S3 と同じに振る舞う
// (条件の不一致は 412 PreconditionFailed、If-Match の対象が無ければ 404 NoSuchKey、ETag は内容の MD5 を引用符で囲んだもの)。
type FakeS3 struct {
	Bucket string
	// PageSize は ListObjectsV2 の 1 ページの最大件数 (続きの取得を試すため。0 なら 1000)。
	PageSize int
	// Versioning は GetBucketVersioning の Status。Encrypted / PublicBlocked はバケットの設定。
	Versioning    string
	Encrypted     bool
	PublicBlocked bool
	// Denied に入れた操作 (GET・PUT・HEAD・LIST・VERSIONING・ENCRYPTION・PUBLIC_ACCESS_BLOCK) は 403 AccessDenied を返す。
	Denied map[string]bool
	// BeforePut は PutObject の条件を見る前に呼ばれる。0 以外を返すとその状態で失敗させる。別の実行が割り込む再現にも使う (ロックは取っていない)。
	BeforePut func(key string) int

	mu       sync.Mutex
	objects  map[string][]byte
	requests []S3Request
}

// NewFakeS3 は偽の S3 を立て、それにつないだ本物の SDK のクライアントを返す。実 AWS には接続しない。
func NewFakeS3(t testing.TB, bucket string) (*FakeS3, *s3.Client) {
	t.Helper()
	f := &FakeS3{Bucket: bucket, objects: map[string][]byte{}, Denied: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "example-secret", ""),
		HTTPClient:   srv.Client(),
		// 失敗の注入をそのまま見る (再試行の待ちも入らない)
		RetryMaxAttempts: 1,
	})
}

// ETagOf は内容の ETag (S3 と同じく引用符つき)。
func ETagOf(b []byte) string {
	h := md5.Sum(b)
	return `"` + hex.EncodeToString(h[:]) + `"`
}

// Put はテストの準備として直接オブジェクトを置く。
func (f *FakeS3) Put(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), body...)
}

// Delete はオブジェクトを消す。
func (f *FakeS3) Delete(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
}

// Get はオブジェクトの中身。無ければ nil。
func (f *FakeS3) Get(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects[key]
}

// Snapshot は全オブジェクトの key → ETag。
func (f *FakeS3) Snapshot() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.objects))
	for k, v := range f.objects {
		out[k] = ETagOf(v)
	}
	return out
}

// Requests はこれまでの要求 (method が空でなければその method だけ)。
func (f *FakeS3) Requests(method string) []S3Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []S3Request
	for _, r := range f.requests {
		if method == "" || r.Method == method {
			out = append(out, r)
		}
	}
	return out
}

// ResetRequests は要求の記録を消す。
func (f *FakeS3) ResetRequests() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
}

func (f *FakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	if bucket != f.Bucket {
		s3Error(w, http.StatusNotFound, "NoSuchBucket", r.Method != http.MethodHead)
		return
	}
	q := r.URL.Query()
	rec := S3Request{Method: r.Method, Key: key, IfMatch: r.Header.Get("If-Match"), IfNoneMatch: r.Header.Get("If-None-Match")}
	status := http.StatusOK
	switch {
	case key == "" && q.Has("versioning"):
		status = f.bucketConfig(w, "VERSIONING", func() string {
			return `<VersioningConfiguration><Status>` + f.Versioning + `</Status></VersioningConfiguration>`
		})
	case key == "" && q.Has("encryption"):
		if !f.Encrypted && !f.Denied["ENCRYPTION"] {
			status = http.StatusNotFound
			s3Error(w, status, "ServerSideEncryptionConfigurationNotFoundError", true)
			break
		}
		status = f.bucketConfig(w, "ENCRYPTION", func() string {
			return `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
		})
	case key == "" && q.Has("publicAccessBlock"):
		if !f.PublicBlocked && !f.Denied["PUBLIC_ACCESS_BLOCK"] {
			status = http.StatusNotFound
			s3Error(w, status, "NoSuchPublicAccessBlockConfiguration", true)
			break
		}
		status = f.bucketConfig(w, "PUBLIC_ACCESS_BLOCK", func() string {
			return `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
		})
	case key == "" && r.Method == http.MethodGet:
		status = f.list(w, r)
	case r.Method == http.MethodPut:
		status = f.put(w, r, key)
	case r.Method == http.MethodGet, r.Method == http.MethodHead:
		status = f.get(w, r, key)
	default:
		status = http.StatusMethodNotAllowed
		w.WriteHeader(status)
	}
	rec.Status = status
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	f.mu.Unlock()
}

func (f *FakeS3) bucketConfig(w http.ResponseWriter, op string, body func() string) int {
	if f.Denied[op] {
		s3Error(w, http.StatusForbidden, "AccessDenied", true)
		return http.StatusForbidden
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, body())
	return http.StatusOK
}

func (f *FakeS3) get(w http.ResponseWriter, r *http.Request, key string) int {
	body := r.Method != http.MethodHead
	op := "GET"
	if !body {
		op = "HEAD"
	}
	if f.Denied[op] {
		s3Error(w, http.StatusForbidden, "AccessDenied", body)
		return http.StatusForbidden
	}
	f.mu.Lock()
	b, ok := f.objects[key]
	f.mu.Unlock()
	if !ok {
		s3Error(w, http.StatusNotFound, "NoSuchKey", body)
		return http.StatusNotFound
	}
	w.Header().Set("ETag", ETagOf(b))
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	if body {
		_, _ = w.Write(b)
	}
	return http.StatusOK
}

func (f *FakeS3) put(w http.ResponseWriter, r *http.Request, key string) int {
	if f.Denied["PUT"] {
		s3Error(w, http.StatusForbidden, "AccessDenied", true)
		return http.StatusForbidden
	}
	b, err := readS3Body(r)
	if err != nil {
		s3Error(w, http.StatusBadRequest, "IncompleteBody", true)
		return http.StatusBadRequest
	}
	if f.BeforePut != nil {
		if st := f.BeforePut(key); st != 0 {
			s3Error(w, st, "InternalError", true)
			return st
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, exists := f.objects[key]
	ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
	switch {
	case ifMatch != "" && !exists:
		s3Error(w, http.StatusNotFound, "NoSuchKey", true)
		return http.StatusNotFound
	case ifMatch != "" && ifMatch != ETagOf(cur):
		s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed", true)
		return http.StatusPreconditionFailed
	case ifNone == "*" && exists:
		s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed", true)
		return http.StatusPreconditionFailed
	}
	f.objects[key] = b
	w.Header().Set("ETag", ETagOf(b))
	return http.StatusOK
}

// readS3Body は PutObject の本文を読む。SDK が aws-chunked で送ってきたらほどく。
func readS3Body(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(r.Body)
	if err != nil || !strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
		return b, err
	}
	var out []byte
	for {
		line, rest, ok := strings.Cut(string(b), "\r\n")
		if !ok {
			return nil, fmt.Errorf("aws-chunked: no chunk size")
		}
		size, _, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(size, 16, 64)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, rest[:n]...)
		b = []byte(strings.TrimPrefix(rest[n:], "\r\n"))
	}
}

func (f *FakeS3) list(w http.ResponseWriter, r *http.Request) int {
	if f.Denied["LIST"] {
		s3Error(w, http.StatusForbidden, "AccessDenied", true)
		return http.StatusForbidden
	}
	q := r.URL.Query()
	page := f.PageSize
	if page == 0 {
		page = 1000
	}
	if m, err := strconv.Atoi(q.Get("max-keys")); err == nil && m > 0 && m < page {
		page = m
	}
	f.mu.Lock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, q.Get("prefix")) && k > q.Get("continuation-token") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	type content struct {
		Key  string
		ETag string
		Size int
	}
	res := struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		IsTruncated           bool
		NextContinuationToken string `xml:",omitempty"`
		KeyCount              int
		Contents              []content
	}{}
	if len(keys) > page {
		keys = keys[:page]
		res.IsTruncated = true
		res.NextContinuationToken = keys[page-1]
	}
	for _, k := range keys {
		res.Contents = append(res.Contents, content{Key: k, ETag: ETagOf(f.objects[k]), Size: len(f.objects[k])})
	}
	f.mu.Unlock()
	res.KeyCount = len(res.Contents)
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(res)
	return http.StatusOK
}

func s3Error(w http.ResponseWriter, status int, code string, body bool) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if body {
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
	}
}
