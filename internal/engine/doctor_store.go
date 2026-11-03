package engine

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/store"
)

// StoreActions は s3:// のストアのバケットに要る IAM action。If-Match の書き込みにも s3:GetObject が要る。
var StoreActions = []string{"s3:GetObject", "s3:ListBucket", "s3:PutObject"}

// store は s3:// のストアのバケットを検査する (ADR 0034)。
//
// 決定: 読めるかだけを確かめ、書き込みは試さない (doctor は何も変えない)。
// 決定: 推奨 (バージョニング・暗号化・パブリックアクセスブロック) を満たさなければ warn。確かめる権限が無ければ飛ばす
// (ストアに必須の権限ではない)。バケットの設定を読むのは読み取りだけ。
func (d *doctor) store(ctx context.Context) {
	if d.cfg.Store.Scheme != "s3" {
		return
	}
	src := config.Source{ID: "store", Kind: "s3"}
	d.res.StoreActions = StoreActions
	d.add(src, "store_scope", DoctorOK, "", "読み取り専用は監査対象のアカウントへの約束で、ストアのバケットは別。arata はこのバケットに書く (書き込みは試さない)")
	api, err := d.deps.S3Store(ctx, d.cfg)
	if err != nil {
		d.add(src, "store_read", DoctorNG, CodeStoreUnavailable, "S3 のクライアントを作れない: "+err.Error())
		return
	}
	d.storeRead(ctx, api, src)
	bucket := &d.cfg.Store.Bucket

	d.storeRecommendation(src, "store_versioning", "s3:GetBucketVersioning", func() (string, error) {
		out, err := api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket})
		if err == nil && out.Status != s3types.BucketVersioningStatusEnabled {
			return "バージョニングが有効でない (誤った上書きから戻せない)", nil
		}
		return "", err
	}, "バージョニングが有効")
	d.storeRecommendation(src, "store_encryption", "s3:GetEncryptionConfiguration", func() (string, error) {
		_, err := api.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket})
		if store.HTTPStatus(err) == http.StatusNotFound {
			return "既定の暗号化の設定が無い (SSE-S3 か SSE-KMS を推奨)", nil
		}
		return "", err
	}, "既定の暗号化が有効")
	d.storeRecommendation(src, "store_public_access", "s3:GetBucketPublicAccessBlock", func() (string, error) {
		out, err := api.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket})
		if store.HTTPStatus(err) == http.StatusNotFound {
			return "パブリックアクセスブロックの設定が無い", nil
		}
		if err != nil {
			return "", err
		}
		c := out.PublicAccessBlockConfiguration
		if c == nil || !aws.ToBool(c.BlockPublicAcls) || !aws.ToBool(c.IgnorePublicAcls) || !aws.ToBool(c.BlockPublicPolicy) || !aws.ToBool(c.RestrictPublicBuckets) {
			return "パブリックアクセスブロックの 4 項目のどれかが無効", nil
		}
		return "", nil
	}, "パブリックアクセスブロックが有効")
}

// storeRead はバケットと SQLite のオブジェクトを読めるか確かめる。まだ無いのは問題ではない (初回の run が作る)。
func (d *doctor) storeRead(ctx context.Context, api store.S3API, src config.Source) {
	loc := s3Location(d.cfg)
	prefix := loc.Key("")
	if _, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &loc.Bucket, Prefix: &prefix, MaxKeys: aws.Int32(1)}); err != nil {
		d.storeReadFailed(src, "s3:ListBucket", err)
		return
	}
	key := loc.Key(store.S3DatabaseObject)
	_, err := api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &loc.Bucket, Key: &key})
	switch {
	case err == nil:
		d.add(src, "store_read", DoctorOK, "", d.cfg.Store.String()+" を読める")
	case store.HTTPStatus(err) == http.StatusNotFound:
		raw := loc.Key("raw/")
		out, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &loc.Bucket, Prefix: &raw, MaxKeys: aws.Int32(1)})
		switch {
		case err != nil:
			d.storeReadFailed(src, "s3:ListBucket", err)
		case len(out.Contents) > 0:
			d.add(src, "store_read", DoctorNG, CodeStoreCorrupt, d.cfg.Store.String()+" に raw があるのに SQLite が無い (書き込み系のコマンドは止まる)。"+lostDatabaseAction)
		default:
			d.add(src, "store_read", DoctorOK, "", d.cfg.Store.String()+" を読める (SQLite はまだ無い。最初の init / run が作る)")
		}
	default:
		d.storeReadFailed(src, "s3:GetObject", err)
	}
}

func (d *doctor) storeReadFailed(src config.Source, action string, err error) {
	if store.HTTPStatus(err) == http.StatusForbidden {
		d.add(src, "store_read", DoctorNG, collect.CodeAccessDenied, fmt.Sprintf("%s が拒否された (%s): %v", action, d.cfg.Store.String(), err))
		return
	}
	d.add(src, "store_read", DoctorNG, CodeStoreUnavailable, fmt.Sprintf("%s を読めない: %v", d.cfg.Store.String(), err))
}

// storeRecommendation は check が返した問題を warn に、権限が無ければ飛ばしたことを ok に、その他の失敗を warn にする。
func (d *doctor) storeRecommendation(src config.Source, item, action string, check func() (string, error), okDetail string) {
	problem, err := check()
	switch {
	case store.HTTPStatus(err) == http.StatusForbidden:
		d.add(src, item, DoctorOK, "", "skip: "+action+" が無いので確かめない")
	case err != nil:
		d.add(src, item, DoctorWarn, "", "確かめられない: "+err.Error())
	case problem != "":
		d.add(src, item, DoctorWarn, "", problem)
	default:
		d.add(src, item, DoctorOK, "", okDetail)
	}
}
