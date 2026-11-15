package cloudtrail

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// trail の S3 への配信から読む collector (cloudtrail-s3。ADR 0063)。
//
// 決定:
//   - キーは <prefix>/AWSLogs/[<o-id>/]<account-id>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_YYYYMMDDTHHmmZ_<16 文字>.json.gz。
//     日のプレフィックスとファイル名の時刻は**配信した時刻**で、中の記録はそれより前の任意の時点のもの (公式文書)
//   - 配信時刻が [窓の始まり (再走査を含む) の分, 窓の終わり + 配信の余裕) のファイルを読み、記録の eventTime が [窓の始まり, 窓の終わり) のものだけを使う
//   - CloudTrail-Insight・CloudTrail-Digest などの段は引かない。CloudTrail の段に混ざる data event・ネットワークアクティビティは捨てる
//     (eventCategory が Management か、項目の無い古い記録だけを使う)
//   - ファイルは信用できない入力 (ADR 0037)。gzip を解いた大きさに上限を置き、読めないファイルは TRAIL_FILE_INVALID の WARN で飛ばして他を読み続ける

// S3API は S3 のクライアントのうち使う部分。テストでは偽の実装を注入する。
type S3API interface {
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// IAM action (doctor が列挙し、ACCESS_DENIED に添える)。
const (
	ActionS3ListBucket = "s3:ListBucket"
	ActionS3GetObject  = "s3:GetObject"
)

// MaxTrailFileBytes は gzip を解いた 1 ファイルの大きさの上限。公式の上限 (圧縮前 50 MB) に余裕を足した値。
const MaxTrailFileBytes = 64 << 20

// TrailLocation は trail の配信先 (どのバケットの、どのアカウントの記録を読むか)。
type TrailLocation struct {
	Bucket string
	// Prefix は trail の S3 キーの接頭辞 (無ければ空。末尾の / は有っても無くてもよい)。
	Prefix string
	// OrganizationID は組織の trail のときの o-xxxxxxxxxx (キーに入る)。
	OrganizationID string
	AccountID      string
	Regions        []string
}

// RegionPrefix はリージョンの、日のプレフィックスの手前まで (…/CloudTrail/<region>/)。
func (l TrailLocation) RegionPrefix(region string) string {
	var b strings.Builder
	if p := strings.Trim(l.Prefix, "/"); p != "" {
		b.WriteString(p + "/")
	}
	b.WriteString("AWSLogs/")
	if l.OrganizationID != "" {
		b.WriteString(l.OrganizationID + "/")
	}
	b.WriteString(l.AccountID + "/CloudTrail/" + region + "/")
	return b.String()
}

// S3Collector は 1 ソース分の、trail の S3 を読む collector。
type S3Collector struct {
	id      string
	loc     TrailLocation
	api     S3API
	Notable func(record.TrailEvent) bool
	// Delay は配信の余裕 (ingest_delay)。窓の終わりからこの分あとに配信されたファイルまで読む。
	Delay    time.Duration
	MaxBytes int64
	Logger   *slog.Logger
}

var _ collect.Collector = (*S3Collector)(nil)

// NewS3 は collector を作る。
func NewS3(id string, loc TrailLocation, api S3API) *S3Collector {
	return &S3Collector{id: id, loc: loc, api: api, Notable: DefaultNotable, MaxBytes: MaxTrailFileBytes,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (c *S3Collector) ID() string { return c.id }

func (c *S3Collector) Yields() []record.Kind {
	return []record.Kind{record.KindTrailEvent, record.KindPrincipalSeen}
}

// s3Stats は 1 リージョンで読んだ量 (INFO に残す)。
type s3Stats struct {
	files, invalid, records, skipped, events int
	bytes                                    int64
}

// Collect は窓の分のファイルを読み、LookupEvents の collector と同じレコードを出す。
func (c *S3Collector) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	agg := newTrailAgg(c.id, c.Notable)
	var firstErr error
	for _, region := range c.loc.Regions {
		if err := c.collectRegion(ctx, region, w, sink, agg); err != nil {
			firstErr = err
			break
		}
	}
	// 失敗しても取れた分の principal_seen と活動の集計は捨てない
	if err := agg.flush(ctx, sink); err != nil {
		return err
	}
	return firstErr
}

func (c *S3Collector) collectRegion(ctx context.Context, region string, w collect.Window, sink collect.RecordSink, agg *trailAgg) error {
	from := w.Start().UTC().Truncate(time.Minute)
	until := w.To.UTC().Add(c.Delay)
	var st s3Stats
	keys, err := c.list(ctx, region, from, until)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := c.readFile(ctx, key, w, sink, agg, &st); err != nil {
			ce := collect.Classify(c.id, ActionS3GetObject, err)
			ce.Err = fmt.Errorf("region %s (after %d files): %w", region, st.files, ce.Err)
			return ce
		}
	}
	c.Logger.Info("collect region done", "source", c.id, "region", region, "files", st.files, "bytes", st.bytes, "records", st.records,
		"skipped_records", st.skipped, "events", st.events, "invalid_files", st.invalid)
	return nil
}

// list は配信時刻が [from, until) のファイルのキーを、古い順に返す。
func (c *S3Collector) list(ctx context.Context, region string, from, until time.Time) ([]string, error) {
	base := c.loc.RegionPrefix(region)
	name := c.loc.AccountID + "_CloudTrail_" + region + "_"
	var out []string
	for day := dayStart(from); day.Before(until); day = day.AddDate(0, 0, 1) {
		prefix := base + day.Format("2006/01/02") + "/"
		in := &s3.ListObjectsV2Input{Bucket: aws.String(c.loc.Bucket), Prefix: aws.String(prefix)}
		if day.Equal(dayStart(from)) {
			// ファイル名は時刻の順に並ぶので、始まりの分の手前から引く (同じ分のファイルは "…T1504Z_" で、"…T1504" より後ろ)
			in.StartAfter = aws.String(prefix + name + from.Format("20060102T1504"))
		}
		for {
			res, err := c.api.ListObjectsV2(ctx, in)
			if err != nil {
				ce := collect.Classify(c.id, ActionS3ListBucket, err)
				ce.Err = fmt.Errorf("region %s: list %s: %w", region, prefix, ce.Err)
				return nil, ce
			}
			done := false
			for _, o := range res.Contents {
				key := aws.ToString(o.Key)
				t, ok := deliveredAt(key, name)
				if !ok || t.Before(from) {
					continue
				}
				if !t.Before(until) {
					done = true
					break
				}
				out = append(out, key)
			}
			if done || !aws.ToBool(res.IsTruncated) || res.NextContinuationToken == nil {
				break
			}
			in.ContinuationToken = res.NextContinuationToken
		}
	}
	return out, nil
}

// deliveredAt はファイル名の配信時刻を読む。形に合わない名前 (ダイジェストや別のアカウント・リージョンのもの) は false。
func deliveredAt(key, name string) (time.Time, bool) {
	file := key[strings.LastIndex(key, "/")+1:]
	rest, ok := strings.CutPrefix(file, name)
	if !ok || !strings.HasSuffix(rest, ".json.gz") || len(rest) < len("20060102T1504Z") {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102T1504Z", rest[:len("20060102T1504Z")])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func dayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// readFile は 1 ファイルを読み、窓の中の管理イベントを数える。返す err は S3 の失敗だけ (ファイルの中身の誤りは WARN で飛ばす)。
func (c *S3Collector) readFile(ctx context.Context, key string, w collect.Window, sink collect.RecordSink, agg *trailAgg, st *s3Stats) error {
	res, err := c.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.loc.Bucket), Key: aws.String(key)})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	st.files++
	recs, n, err := ReadTrailFile(res.Body, c.MaxBytes)
	st.bytes += n
	if err != nil {
		if !errors.Is(err, ErrInvalidTrailFile) {
			return err // 読んでいる途中の通信の失敗など。次の run が同じファイルを読み直す
		}
		st.invalid++
		c.Logger.Warn("skipped an unreadable trail file", "code", codes.TrailFileInvalid, "source", c.id, "key", key, "error", err.Error())
		return nil
	}
	for _, r := range recs {
		st.records++
		if !managementEvent(r) {
			st.skipped++
			continue
		}
		e, ok := normalizeRaw(c.id, r, "", nil)
		if !ok || e.Time.Before(w.Start()) || !e.Time.Before(w.To) {
			continue
		}
		added, err := agg.add(ctx, e, w, sink)
		if err != nil {
			return err
		}
		if added {
			st.events++
		}
	}
	return nil
}

// ErrInvalidTrailFile はファイルの中身の誤り (gzip・JSON の形、大きさの上限)。読み直しても同じなので飛ばす。
// これ以外の誤り (通信の途中切れなど) はソースの失敗にする (黙って記録を落とさない)。
var ErrInvalidTrailFile = errors.New("invalid trail file")

func invalidFile(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTrailFile, fmt.Sprintf(format, a...))
}

// managementEvent は管理イベントか (eventCategory が Management、または項目の無い古い記録)。
func managementEvent(r rawEvent) bool {
	return r.EventCategory == "" || r.EventCategory == "Management"
}

// isGzipContentError は gzip の形の誤りか (ヘッダー・チェックサム・圧縮の中身)。途中で切れた (io.ErrUnexpectedEOF) のは通信の失敗と区別できないので含めない。
func isGzipContentError(err error) bool {
	var ce flate.CorruptInputError
	return errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) || errors.As(err, &ce)
}

// ReadTrailFile は trail の S3 のファイル (gzip の JSON の {"Records":[...]}) を読む。n は gzip を解いた後に読んだバイト数。
// 決定: 解いた大きさが max を超えたら読むのをやめて誤りにする (信用できない入力。ADR 0037)。Records の要素で形の合わないものは
// 全体を誤りにせず捨てる (1 件の誤りで他の記録を失わない)。
func ReadTrailFile(r io.Reader, max int64) (recs []rawEvent, n int64, err error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		// 0 バイトのファイルは io.EOF (中身の誤り。ファズで見つけた)
		if isGzipContentError(err) || errors.Is(err, io.EOF) {
			return nil, 0, invalidFile("gzip: %v", err)
		}
		return nil, 0, err
	}
	defer gz.Close()
	var buf bytes.Buffer
	n, err = io.Copy(&buf, io.LimitReader(gz, max+1))
	if err != nil {
		if isGzipContentError(err) {
			return nil, n, invalidFile("gzip: %v", err)
		}
		return nil, n, err
	}
	if n > max {
		return nil, n, invalidFile("file is larger than %d bytes after decompression", max)
	}
	var doc struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		return nil, n, invalidFile("json: %v", err)
	}
	if doc.Records == nil {
		return nil, n, invalidFile(`json: no "Records" array`)
	}
	for _, raw := range doc.Records {
		var e rawEvent
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		recs = append(recs, e)
	}
	return recs, n, nil
}

// TrailInfoAPI は doctor が trail の設定を読むのに使う部分 (読み取りだけ。ADR 0063)。
type TrailInfoAPI interface {
	DescribeTrails(ctx context.Context, in *ct.DescribeTrailsInput, opts ...func(*ct.Options)) (*ct.DescribeTrailsOutput, error)
	GetEventSelectors(ctx context.Context, in *ct.GetEventSelectorsInput, opts ...func(*ct.Options)) (*ct.GetEventSelectorsOutput, error)
}

// ActionGetEventSelectors は doctor が trail の記録の範囲を確かめる action。
const ActionGetEventSelectors = "cloudtrail:GetEventSelectors"
