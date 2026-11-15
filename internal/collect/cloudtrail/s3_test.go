package cloudtrail

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/CircleAround/arata/internal/codes"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/record"
)

const testAccount = "123456789012"

var s3Base = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

func testLocation(regions ...string) TrailLocation {
	return TrailLocation{Bucket: "example-trail-logs", AccountID: testAccount, Regions: regions}
}

// s3Events は窓 [01:00, 02:00) を中心にした記録の組。
func s3Events() []types.Event {
	alice := cloudtrailtest.User(testAccount, "alice")
	role := cloudtrailtest.AssumedRole(testAccount, "app", "i-0abc")
	return []types.Event{
		cloudtrailtest.Event("e1", s3Base.Add(time.Hour+5*time.Minute), alice, "iam.amazonaws.com", "CreateAccessKey", "us-east-1", "198.51.100.7", false, map[string]any{"userName": "bob"}),
		cloudtrailtest.Event("e2", s3Base.Add(time.Hour+10*time.Minute), role, "secretsmanager.amazonaws.com", "GetSecretValue", "ap-northeast-1", "203.0.113.5", true, map[string]any{"secretId": "prod/db"}),
		cloudtrailtest.WithError(cloudtrailtest.Event("e3", s3Base.Add(time.Hour+20*time.Minute), role, "s3.amazonaws.com", "ListBuckets", "ap-northeast-1", "203.0.113.5", true, nil), "AccessDenied"),
		cloudtrailtest.Event("e4", s3Base.Add(time.Hour+30*time.Minute), alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "198.51.100.7", true, nil),
	}
}

func s3Collector(f *cloudtrailtest.S3, loc TrailLocation) *S3Collector {
	c := NewS3("trail", loc, f)
	c.Delay = 15 * time.Minute
	return c
}

func put(f *cloudtrailtest.S3, region string, delivered time.Time, suffix, category string, evs ...types.Event) string {
	k := cloudtrailtest.TrailKey("", "", testAccount, region, delivered, suffix)
	f.Put(k, cloudtrailtest.TrailFile(category, evs...))
	return k
}

func sortedCaptured(c *captured) *captured {
	sort.Slice(c.events, func(i, j int) bool { return c.events[i].EventID < c.events[j].EventID })
	sort.Slice(c.principals, func(i, j int) bool {
		return c.principals[i].ARN+c.principals[i].IP < c.principals[j].ARN+c.principals[j].IP
	})
	sort.Slice(c.metrics, func(i, j int) bool {
		return c.metrics[i].Metric+c.metrics[i].Key < c.metrics[j].Metric+c.metrics[j].Key
	})
	return c
}

// 同じ記録を LookupEvents と trail の S3 から読むと、同じレコードが出る (ADR 0063。正規化と集計を共有する)。
func TestS3CollectSameAsLookup(t *testing.T) {
	evs := s3Events()
	w := collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour), ScanFrom: s3Base.Add(time.Hour - 15*time.Minute)}

	byRegion := map[string][]types.Event{}
	for _, e := range evs {
		r := regionOf(t, e)
		byRegion[r] = append(byRegion[r], e)
	}
	var clients []RegionClient
	f := &cloudtrailtest.S3{}
	for _, region := range []string{"ap-northeast-1", "us-east-1"} {
		clients = append(clients, RegionClient{Region: region, API: &Fake{Pages: [][]types.Event{byRegion[region]}}})
		// 記録の 5 分後に配信 (1 ファイルにまとめる)
		put(f, region, s3Base.Add(time.Hour+35*time.Minute), "AAAAAAAAAAAAAAAA", "Management", byRegion[region]...)
	}
	lookup, _, _ := testCollector("trail", clients...)
	want := &captured{}
	if err := lookup.Collect(context.Background(), w, want); err != nil {
		t.Fatal(err)
	}
	got := &captured{}
	if err := s3Collector(f, testLocation("ap-northeast-1", "us-east-1")).Collect(context.Background(), w, got); err != nil {
		t.Fatal(err)
	}
	if len(want.events) == 0 || len(want.principals) == 0 || len(want.metrics) == 0 {
		t.Fatalf("test data should produce every kind of record: %+v", want)
	}
	if !reflect.DeepEqual(sortedCaptured(got), sortedCaptured(want)) {
		t.Errorf("S3 records differ from LookupEvents\n got: %+v\nwant: %+v", got, want)
	}
}

func regionOf(t *testing.T, e types.Event) string {
	t.Helper()
	recs, _, err := ReadTrailFile(bytes.NewReader(cloudtrailtest.TrailFile("", e)), MaxTrailFileBytes)
	if err != nil || len(recs) != 1 {
		t.Fatalf("regionOf: %v %d", err, len(recs))
	}
	return recs[0].AWSRegion
}

// 配信時刻で読むファイルを絞り、記録の時刻で窓に入れる。窓の終わりの後に配信されたファイルも、余裕 (ingest_delay) の分は読む。
func TestS3CollectDeliveryAndEventWindows(t *testing.T) {
	alice := cloudtrailtest.User(testAccount, "alice")
	at := func(id string, m time.Duration) types.Event {
		return cloudtrailtest.Event(id, s3Base.Add(m), alice, "ec2.amazonaws.com", "DescribeInstances", "ap-northeast-1", "198.51.100.7", true, nil)
	}
	f := &cloudtrailtest.S3{}
	// 窓 [01:00, 02:00)、再走査の始まり 00:45、余裕 15 分 → 配信時刻 [00:45, 02:15) のファイルを読む
	put(f, "ap-northeast-1", s3Base.Add(40*time.Minute), "A000000000000000", "Management", at("old-file", 38*time.Minute))
	put(f, "ap-northeast-1", s3Base.Add(45*time.Minute), "B000000000000000", "Management", at("before-scan", 30*time.Minute), at("rescan", 50*time.Minute))
	put(f, "ap-northeast-1", s3Base.Add(2*time.Hour+10*time.Minute), "C000000000000000", "Management", at("late", 119*time.Minute), at("after", 125*time.Minute))
	put(f, "ap-northeast-1", s3Base.Add(2*time.Hour+15*time.Minute), "D000000000000000", "Management", at("too-late-file", 110*time.Minute))
	w := collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour), ScanFrom: s3Base.Add(45 * time.Minute)}
	got := &captured{}
	c := s3Collector(f, testLocation("ap-northeast-1"))
	c.Notable = func(record.TrailEvent) bool { return true }
	if err := c.Collect(context.Background(), w, got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range got.events {
		ids = append(ids, e.EventID)
	}
	sort.Strings(ids)
	if want := []string{"late", "rescan"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("events = %v, want %v", ids, want)
	}
	// 読んだファイルは B と C だけ (A は配信が早い、D は余裕を過ぎた)
	if len(f.Gets) != 2 || !strings.Contains(f.Gets[0], "B000") || !strings.Contains(f.Gets[1], "C000") {
		t.Errorf("gets = %v", f.Gets)
	}
	// 再走査の区間の記録は Count ではなく RescanCount に数える (ADR 0013)
	if len(got.principals) != 1 || got.principals[0].Count != 1 || got.principals[0].RescanCount != 1 {
		t.Errorf("principals = %+v", got.principals)
	}
}

// 日をまたぐ窓は、配信時刻の日ごとのプレフィックスを引く。始まりの日だけ StartAfter で手前を飛ばす。ページ分けも辿る。
func TestS3CollectListsDayPrefixes(t *testing.T) {
	alice := cloudtrailtest.User(testAccount, "alice")
	f := &cloudtrailtest.S3{PageSize: 2}
	var want []string
	for i := 0; i < 5; i++ {
		ts := s3Base.Add(-30*time.Minute + time.Duration(i)*20*time.Minute) // 23:30 〜 00:50
		id := "e" + string(rune('a'+i))
		put(f, "ap-northeast-1", ts.Add(5*time.Minute), strings.Repeat(string(rune('A'+i)), 16), "",
			cloudtrailtest.Event(id, ts, alice, "ec2.amazonaws.com", "RunInstances", "ap-northeast-1", "198.51.100.7", false, nil))
		want = append(want, id)
	}
	w := collect.Window{From: s3Base.Add(-40 * time.Minute), To: s3Base.Add(time.Hour)}
	got := &captured{}
	c := s3Collector(f, testLocation("ap-northeast-1"))
	c.Notable = func(record.TrailEvent) bool { return true }
	if err := c.Collect(context.Background(), w, got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range got.events {
		ids = append(ids, e.EventID)
	}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("events = %v, want %v (files in order across the day boundary)", ids, want)
	}
	var prefixes []string
	for _, in := range f.Lists {
		prefixes = append(prefixes, *in.Prefix)
	}
	if !strings.HasSuffix(prefixes[0], "/2026/11/14/") || !strings.HasSuffix(prefixes[len(prefixes)-1], "/2026/11/15/") {
		t.Errorf("prefixes = %v", prefixes)
	}
	if f.Lists[0].StartAfter == nil || !strings.HasSuffix(*f.Lists[0].StartAfter, "_20261114T2320") {
		t.Errorf("first list should start after the window's minute: %v", f.Lists[0].StartAfter)
	}
}

// data event・ネットワークアクティビティは trail_event・principal_seen・活動の集計にしない。管理イベントと、eventCategory の無い古い記録は使う。
func TestS3CollectSkipsNonManagement(t *testing.T) {
	role := cloudtrailtest.AssumedRole(testAccount, "app", "i-0abc")
	ev := func(id string) types.Event {
		return cloudtrailtest.Event(id, s3Base.Add(time.Hour+time.Minute), role, "s3.amazonaws.com", "GetObject", "ap-northeast-1", "203.0.113.9", true, nil)
	}
	f := &cloudtrailtest.S3{}
	put(f, "ap-northeast-1", s3Base.Add(time.Hour+5*time.Minute), "A000000000000000", "Data", ev("data"))
	put(f, "ap-northeast-1", s3Base.Add(time.Hour+5*time.Minute), "B000000000000000", "NetworkActivity", ev("net"))
	put(f, "ap-northeast-1", s3Base.Add(time.Hour+5*time.Minute), "C000000000000000", "Management", ev("mgmt"))
	put(f, "ap-northeast-1", s3Base.Add(time.Hour+5*time.Minute), "D000000000000000", "", ev("legacy"))
	got := &captured{}
	c := s3Collector(f, testLocation("ap-northeast-1"))
	c.Notable = func(record.TrailEvent) bool { return true }
	if err := c.Collect(context.Background(), collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour)}, got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range got.events {
		ids = append(ids, e.EventID)
	}
	sort.Strings(ids)
	if !reflect.DeepEqual(ids, []string{"legacy", "mgmt"}) {
		t.Errorf("events = %v", ids)
	}
	if len(got.principals) != 1 || got.principals[0].Count != 2 {
		t.Errorf("principal_seen should count only management events: %+v", got.principals)
	}
}

// 重複して配信された同じ eventID は 1 回だけ数える。
func TestS3CollectDedupesRedelivery(t *testing.T) {
	alice := cloudtrailtest.User(testAccount, "alice")
	e := cloudtrailtest.Event("dup", s3Base.Add(time.Hour+time.Minute), alice, "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.7", false, nil)
	f := &cloudtrailtest.S3{}
	put(f, "us-east-1", s3Base.Add(time.Hour+5*time.Minute), "A000000000000000", "Management", e)
	put(f, "us-east-1", s3Base.Add(time.Hour+10*time.Minute), "B000000000000000", "Management", e)
	got := &captured{}
	if err := s3Collector(f, testLocation("us-east-1")).Collect(context.Background(), collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour)}, got); err != nil {
		t.Fatal(err)
	}
	if len(got.events) != 1 || len(got.principals) != 1 || got.principals[0].Count != 1 {
		t.Errorf("events = %d, principals = %+v", len(got.events), got.principals)
	}
}

// 組織の trail と接頭辞はキーに入る。別のアカウントの記録 (同じバケット) は読まない。
func TestS3CollectOrganizationPrefix(t *testing.T) {
	alice := cloudtrailtest.User(testAccount, "alice")
	e := cloudtrailtest.Event("org", s3Base.Add(time.Hour+time.Minute), alice, "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.7", false, nil)
	other := cloudtrailtest.Event("other", s3Base.Add(time.Hour+time.Minute), cloudtrailtest.User("111122223333", "x"), "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.8", false, nil)
	f := &cloudtrailtest.S3{}
	d := s3Base.Add(time.Hour + 5*time.Minute)
	f.Put(cloudtrailtest.TrailKey("logs/", "o-exampleorg1", testAccount, "us-east-1", d, "A000000000000000"), cloudtrailtest.TrailFile("Management", e))
	f.Put(cloudtrailtest.TrailKey("logs/", "o-exampleorg1", "111122223333", "us-east-1", d, "B000000000000000"), cloudtrailtest.TrailFile("Management", other))
	loc := testLocation("us-east-1")
	loc.Prefix, loc.OrganizationID = "logs/", "o-exampleorg1"
	got := &captured{}
	if err := s3Collector(f, loc).Collect(context.Background(), collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour)}, got); err != nil {
		t.Fatal(err)
	}
	if len(got.events) != 1 || got.events[0].EventID != "org" {
		t.Errorf("events = %+v", got.events)
	}
	if want := "logs/AWSLogs/o-exampleorg1/123456789012/CloudTrail/us-east-1/2026/11/15/"; *f.Lists[0].Prefix != want {
		t.Errorf("prefix = %s, want %s", *f.Lists[0].Prefix, want)
	}
}

// 中身の壊れたファイルは TRAIL_FILE_INVALID の WARN で飛ばし、他のファイルは読み続ける。
func TestS3CollectSkipsInvalidFile(t *testing.T) {
	alice := cloudtrailtest.User(testAccount, "alice")
	f := &cloudtrailtest.S3{}
	bad := cloudtrailtest.TrailKey("", "", testAccount, "us-east-1", s3Base.Add(time.Hour+5*time.Minute), "A000000000000000")
	f.Put(bad, []byte("this file is plain text, not gzip"))
	put(f, "us-east-1", s3Base.Add(time.Hour+6*time.Minute), "B000000000000000", "Management",
		cloudtrailtest.Event("ok", s3Base.Add(time.Hour+time.Minute), alice, "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.7", false, nil))
	var logs bytes.Buffer
	c := s3Collector(f, testLocation("us-east-1"))
	c.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	got := &captured{}
	if err := c.Collect(context.Background(), collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour)}, got); err != nil {
		t.Fatal(err)
	}
	if len(got.events) != 1 {
		t.Errorf("events = %+v", got.events)
	}
	if !strings.Contains(logs.String(), codes.TrailFileInvalid) || !strings.Contains(logs.String(), bad) {
		t.Errorf("want a %s warning with the key: %s", codes.TrailFileInvalid, logs.String())
	}
}

// S3 の拒否は ACCESS_DENIED と action。途中まで読めた分の principal_seen は捨てない。
func TestS3CollectErrors(t *testing.T) {
	alice := cloudtrailtest.User(testAccount, "alice")
	w := collect.Window{From: s3Base.Add(time.Hour), To: s3Base.Add(2 * time.Hour)}
	t.Run("list denied", func(t *testing.T) {
		f := &cloudtrailtest.S3{ListErr: cloudtrailtest.APIError{Code: "AccessDenied"}}
		err := s3Collector(f, testLocation("us-east-1")).Collect(context.Background(), w, &captured{})
		var ce *collect.Error
		if !errors.As(err, &ce) || ce.Code != collect.CodeAccessDenied || ce.Action != ActionS3ListBucket {
			t.Errorf("err = %#v", err)
		}
	})
	t.Run("get denied (KMS)", func(t *testing.T) {
		f := &cloudtrailtest.S3{}
		put(f, "us-east-1", s3Base.Add(time.Hour+5*time.Minute), "A000000000000000", "Management",
			cloudtrailtest.Event("a", s3Base.Add(time.Hour+time.Minute), alice, "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.7", false, nil))
		k := put(f, "us-east-1", s3Base.Add(time.Hour+10*time.Minute), "B000000000000000", "Management")
		f.GetErrFor = map[string]error{k: cloudtrailtest.APIError{Code: "AccessDenied"}}
		got := &captured{}
		err := s3Collector(f, testLocation("us-east-1")).Collect(context.Background(), w, got)
		var ce *collect.Error
		if !errors.As(err, &ce) || ce.Code != collect.CodeAccessDenied || ce.Action != ActionS3GetObject {
			t.Errorf("err = %#v", err)
		}
		if len(got.principals) != 1 {
			t.Errorf("principal_seen read before the failure should be kept: %+v", got.principals)
		}
	})
	t.Run("truncated body is a failure, not skipped", func(t *testing.T) {
		f := &cloudtrailtest.S3{}
		k := put(f, "us-east-1", s3Base.Add(time.Hour+5*time.Minute), "A000000000000000", "Management",
			cloudtrailtest.Event("a", s3Base.Add(time.Hour+time.Minute), alice, "iam.amazonaws.com", "CreateUser", "us-east-1", "198.51.100.7", false, nil))
		f.Objects[k] = f.Objects[k][:len(f.Objects[k])/2]
		if err := s3Collector(f, testLocation("us-east-1")).Collect(context.Background(), w, &captured{}); err == nil {
			t.Error("want an error so that the next run reads the file again")
		}
	})
}

func TestReadTrailFileLimits(t *testing.T) {
	big := cloudtrailtest.Gzip([]byte(`{"Records":[` + strings.Repeat(`{"eventID":"x"},`, 100) + `{"eventID":"y"}]}`))
	if _, _, err := ReadTrailFile(bytes.NewReader(big), 64); !errors.Is(err, ErrInvalidTrailFile) {
		t.Errorf("over the limit: err = %v", err)
	}
	for name, body := range map[string][]byte{
		"not gzip":   []byte("this file is plain text, not gzip"),
		"not json":   cloudtrailtest.Gzip([]byte("{")),
		"no Records": cloudtrailtest.Gzip([]byte(`{"events":[]}`)),
	} {
		if _, _, err := ReadTrailFile(bytes.NewReader(body), MaxTrailFileBytes); !errors.Is(err, ErrInvalidTrailFile) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// 形の合わない要素だけを捨てる
	recs, _, err := ReadTrailFile(bytes.NewReader(cloudtrailtest.Gzip([]byte(`{"Records":[1,{"eventID":"ok"}]}`))), MaxTrailFileBytes)
	if err != nil || len(recs) != 1 || recs[0].EventID != "ok" {
		t.Errorf("recs = %+v, err = %v", recs, err)
	}
	// 通信の失敗は中身の誤りにしない
	if _, _, err := ReadTrailFile(io.MultiReader(bytes.NewReader(big[:10]), errReader{}), MaxTrailFileBytes); err == nil || errors.Is(err, ErrInvalidTrailFile) {
		t.Errorf("read error: err = %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestDeliveredAt(t *testing.T) {
	name := testAccount + "_CloudTrail_us-east-1_"
	ok := "AWSLogs/123456789012/CloudTrail/us-east-1/2026/11/15/123456789012_CloudTrail_us-east-1_20261115T0105Z_Mu0KsOhtH1ar15ZZ.json.gz"
	if got, valid := deliveredAt(ok, name); !valid || !got.Equal(time.Date(2026, 11, 15, 1, 5, 0, 0, time.UTC)) {
		t.Errorf("got %v %v", got, valid)
	}
	for _, k := range []string{
		"AWSLogs/123456789012/CloudTrail/us-east-1/2026/11/15/123456789012_CloudTrail-Digest_us-east-1_t_us-east-1_20261115T010501Z.json.gz",
		"AWSLogs/123456789012/CloudTrail/us-east-1/2026/11/15/111122223333_CloudTrail_us-east-1_20261115T0105Z_x.json.gz",
		"AWSLogs/123456789012/CloudTrail/us-east-1/2026/11/15/123456789012_CloudTrail_us-east-1_2026111XT0105Z_x.json.gz",
		"AWSLogs/123456789012/CloudTrail/us-east-1/2026/11/15/123456789012_CloudTrail_us-east-1_20261115T0105Z_x.json",
	} {
		if _, valid := deliveredAt(k, name); valid {
			t.Errorf("%s should not be a trail file of this account and region", k)
		}
	}
}
