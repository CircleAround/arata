package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cloudtrail/cloudtrailtest"
	"github.com/CircleAround/arata/internal/store/storetest"
)

const (
	s3Bucket = "example-arata-store"
	s3DB     = "acme/audit.sqlite.gz"
)

// newS3CLI は設定のストアを偽の S3 に向けた CLI を返す (実 AWS には接続しない)。
func newS3CLI(t *testing.T) (*cli, *storetest.FakeS3) {
	t.Helper()
	c := newCLI(t)
	b, err := os.ReadFile(c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.writeConfig(strings.Replace(string(b), "store: dir://"+c.dir+"/store", "store: s3://"+s3Bucket+"/acme", 1))
	f, api := storetest.NewFakeS3(t, s3Bucket)
	c.s3 = api
	return c, f
}

func (c *cli) rootLogin(id string) {
	c.fake.Add(cloudtrailtest.Event(id, c.now.Add(-time.Hour), cloudtrailtest.Root(acct), "signin.amazonaws.com", "ConsoleLogin", "us-east-1", "198.51.100.8", false, nil))
}

func (c *cli) firstFinding() string {
	c.t.Helper()
	if code := c.run("review", "--config", c.cfg, "--format", "json"); code != 0 {
		c.t.Fatalf("review: exit %d\n%s", code, c.stderr)
	}
	var items []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(c.stdout.Bytes(), &items); err != nil || len(items) == 0 {
		c.t.Fatalf("review: %v\n%s", err, c.stdout)
	}
	return items[0].ID
}

func TestS3StoreCommands(t *testing.T) {
	c, f := newS3CLI(t)
	c.rootLogin("r1")
	if code := c.run("run", "--config", c.cfg, "--profile", "daily", "--format", "md"); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, c.stderr)
	}
	if f.Get(s3DB) == nil || f.Get("acme/reports/daily.json") == nil {
		t.Fatalf("objects: %v", f.Snapshot())
	}

	// 読むだけのコマンドは何も送らない
	f.ResetRequests()
	before := f.Snapshot()
	id := c.firstFinding()
	if code := c.run("report", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("report: exit %d\n%s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "root_usage") {
		t.Fatalf("report from S3: %s", c.stdout)
	}
	if code := c.run("report", "--config", c.cfg, "--month", "2026-10"); code != 0 {
		t.Fatalf("period report: exit %d\n%s", code, c.stderr)
	}
	if len(f.Requests("PUT")) != 0 || !reflect.DeepEqual(f.Snapshot(), before) {
		t.Fatalf("read-only commands must not write: %+v", f.Requests("PUT"))
	}

	// 失敗した書き込み系のコマンドも送らない
	if code := c.run("ack", "--config", c.cfg, "no-such-finding"); code == 0 {
		t.Fatalf("ack of an unknown finding must fail")
	}
	if len(f.Requests("PUT")) != 0 {
		t.Fatalf("a failed command must not write: %+v", f.Requests("PUT"))
	}

	// ack は SQLite を書き、次の実行に残る
	if code := c.run("ack", "--config", c.cfg, id); code != 0 {
		t.Fatalf("ack: exit %d\n%s", code, c.stderr)
	}
	if puts := f.Requests("PUT"); len(puts) != 1 || puts[0].Key != s3DB || puts[0].IfMatch != before[s3DB] {
		t.Fatalf("ack writes the database only: %+v", puts)
	}
	if code := c.run("review", "--config", c.cfg, "--status", "acked", "--format", "json"); code != 0 || !strings.Contains(c.stdout.String(), id) {
		t.Fatalf("acked finding must be kept: exit %d\n%s", code, c.stdout)
	}

	if code := c.run("rebuild", "--config", c.cfg); code != 0 {
		t.Fatalf("rebuild: exit %d\n%s", code, c.stderr)
	}
	if !strings.Contains(c.stdout.String(), "rebuilt s3://"+s3Bucket+"/"+s3DB) {
		t.Fatalf("rebuild output: %s", c.stdout)
	}
	c.assertCodesInVocabulary()
}

// 衝突したら report を出さない (--out のファイルを作らない)。確定していない結果を aratam が通知しないように。
func TestS3StoreConflictEmitsNoReport(t *testing.T) {
	c, f := newS3CLI(t)
	if code := c.run("run", "--config", c.cfg, "--profile", "daily"); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, c.stderr)
	}
	c.now = c.now.Add(24 * time.Hour)
	c.rootLogin("r1")
	f.BeforePut = func(key string) int {
		f.BeforePut = nil
		f.Put(s3DB, []byte("written by another run"))
		return 0
	}
	out := filepath.Join(c.dir, "out")
	code := c.run("run", "--config", c.cfg, "--profile", "daily", "--out", out)
	if code != 2 || !strings.Contains(strings.Join(c.codes(), ","), "STORE_CONFLICT") {
		t.Fatalf("exit %d codes %v\n%s", code, c.codes(), c.stderr)
	}
	if _, err := os.Stat(filepath.Join(out, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("no report on a conflict: %v", err)
	}
	if string(f.Get(s3DB)) != "written by another run" {
		t.Fatalf("the other run's database must survive")
	}
	c.assertCodesInVocabulary()
}

// 途中で止まった init もここまでの分を確定し、--resume で続けられる。
func TestS3StoreInitPartialIsCommitted(t *testing.T) {
	c, f := newS3CLI(t)
	c.fake.Err = errors.New("lookup failed")
	code := c.run("init", "--config", c.cfg, "--window", "2d")
	if code != 3 {
		t.Fatalf("init: exit %d\n%s", code, c.stderr)
	}
	if f.Get(s3DB) == nil {
		t.Fatalf("a partial init must be saved")
	}
	c.fake.Err = nil
	if code := c.run("init", "--config", c.cfg, "--resume"); code != 0 {
		t.Fatalf("resume: exit %d\n%s%s", code, c.stdout, c.stderr)
	}
}

// init の確定に失敗したら、収集が失われたことと再実行の案内を出す。
func TestS3StoreInitCommitFailure(t *testing.T) {
	c, f := newS3CLI(t)
	f.BeforePut = func(key string) int {
		f.BeforePut = nil
		f.Put(s3DB, []byte("written by another run"))
		return 0
	}
	code := c.run("init", "--config", c.cfg, "--window", "2d")
	if code != 2 || !strings.Contains(strings.Join(c.codes(), ","), "STORE_CONFLICT") {
		t.Fatalf("exit %d codes %v\n%s", code, c.codes(), c.stderr)
	}
	for _, want := range []string{"失われました", "arata init --resume"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Fatalf("stdout must contain %q: %s", want, c.stdout)
		}
	}
}

func TestS3StoreDoctor(t *testing.T) {
	c, f := newS3CLI(t)
	f.Versioning, f.Encrypted, f.PublicBlocked = "Enabled", true, true
	c.run("doctor", "--config", c.cfg)
	for _, want := range []string{"store_scope", "s3:PutObject"} {
		if !strings.Contains(c.stdout.String(), want) {
			t.Fatalf("doctor must show %q:\n%s", want, c.stdout)
		}
	}
	if len(f.Requests("PUT")) != 0 {
		t.Fatalf("doctor must not write")
	}
}
