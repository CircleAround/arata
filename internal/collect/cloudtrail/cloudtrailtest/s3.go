package cloudtrailtest

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3 は trail の配信先のバケットの偽物 (ListObjectsV2 と GetObject だけ)。キーは辞書順に返す (汎用バケットと同じ)。
type S3 struct {
	mu      sync.Mutex
	Objects map[string][]byte
	// PageSize は ListObjectsV2 の 1 ページのキーの数 (0 なら 1000)。
	PageSize int
	// ListErr / GetErr が非 nil なら、その操作を失敗させる。GetErrFor はキーごとの失敗。
	ListErr   error
	GetErr    error
	GetErrFor map[string]error
	Lists     []*s3.ListObjectsV2Input
	Gets      []string
}

// Put はオブジェクトを置く。
func (f *S3) Put(key string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Objects == nil {
		f.Objects = map[string][]byte{}
	}
	f.Objects[key] = body
}

func (f *S3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Lists = append(f.Lists, in)
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	var keys []string
	for k := range f.Objects {
		if strings.HasPrefix(k, aws.ToString(in.Prefix)) && k > aws.ToString(in.StartAfter) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	start := 0
	if in.ContinuationToken != nil {
		start, _ = strconv.Atoi(*in.ContinuationToken)
	}
	size := f.PageSize
	if size <= 0 {
		size = 1000
	}
	end := min(start+size, len(keys))
	out := &s3.ListObjectsV2Output{IsTruncated: aws.Bool(end < len(keys))}
	for _, k := range keys[start:end] {
		out.Contents = append(out.Contents, s3types.Object{Key: aws.String(k), Size: aws.Int64(int64(len(f.Objects[k])))})
	}
	if end < len(keys) {
		out.NextContinuationToken = aws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *S3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := aws.ToString(in.Key)
	f.Gets = append(f.Gets, key)
	if f.GetErr != nil {
		return nil, f.GetErr
	}
	if err := f.GetErrFor[key]; err != nil {
		return nil, err
	}
	b, ok := f.Objects[key]
	if !ok {
		return nil, APIError{Code: "NoSuchKey"}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b)), ContentLength: aws.Int64(int64(len(b)))}, nil
}

// TrailKey は trail の配信のキー (<prefix>/AWSLogs/[<org>/]<account>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_<時刻>_<suffix>.json.gz)。
func TrailKey(prefix, org, account, region string, delivered time.Time, suffix string) string {
	var b strings.Builder
	if prefix != "" {
		b.WriteString(strings.Trim(prefix, "/") + "/")
	}
	b.WriteString("AWSLogs/")
	if org != "" {
		b.WriteString(org + "/")
	}
	d := delivered.UTC()
	fmt.Fprintf(&b, "%s/CloudTrail/%s/%s/%s_CloudTrail_%s_%s_%s.json.gz", account, region, d.Format("2006/01/02"), account, region, d.Format("20060102T1504Z"), suffix)
	return b.String()
}

// TrailFile は記録 (LookupEvents の偽物と同じ types.Event の CloudTrailEvent) を、trail の配信のファイル (gzip の {"Records":[...]}) にする。
// category が空でなければ各記録に eventCategory を付ける。
func TrailFile(category string, evs ...types.Event) []byte {
	recs := make([]json.RawMessage, 0, len(evs))
	for _, e := range evs {
		raw := []byte(aws.ToString(e.CloudTrailEvent))
		if category != "" {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			m["eventCategory"] = category
			raw, _ = json.Marshal(m)
		}
		recs = append(recs, raw)
	}
	doc, _ := json.Marshal(map[string]any{"Records": recs})
	return Gzip(doc)
}

// Gzip は b を gzip で圧縮する。
func Gzip(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}
