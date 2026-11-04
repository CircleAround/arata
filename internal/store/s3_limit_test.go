package store

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type bigObject struct {
	S3API
	size int
}

func (b bigObject) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", b.size))), ETag: aws.String(`"e"`)}, nil
}

// 大きすぎるオブジェクトで実行環境のディスクを埋めない。途中のファイルも残さない。
func TestDownloadStopsAtLimit(t *testing.T) {
	defer func(n int64) { maxObjectBytes = n }(maxObjectBytes)
	maxObjectBytes = 1024
	path := filepath.Join(t.TempDir(), "o")
	loc := S3Location{Bucket: "b"}
	if _, err := download(context.Background(), bigObject{size: 2048}, loc, "o", path); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("途中のファイルが残った: %v", err)
	}
	if _, err := download(context.Background(), bigObject{size: 1024}, loc, "o", path); err != nil {
		t.Fatal(err)
	}
}
