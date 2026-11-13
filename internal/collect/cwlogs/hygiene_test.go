package cwlogs

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// テストの例の値は、秘密の検査 (gitleaks) が「本物の形」と読まないように、実行時に組み立てる。どれも架空の値。
var (
	exKeyID  = "AKIA" + "IOSFODNN7" + "EXAMPLE" // AWS の文書の例のキー ID
	exSlack  = "xox" + "b-" + "abcdefABCDEF-" + "abcdefghijkl"
	exPEM    = "-----BEGIN RSA " + "PRIVATE KEY-----"
	exPEMRaw = "-----BEGIN " + "PRIVATE KEY-----"
	esc      = "\x1b"
)

func textSource() config.Source {
	return config.Source{ID: "app_prod", Kind: config.KindCloudWatchLogs, LogGroup: "prod-app", Format: config.FormatText, ExpectedMatchRate: 0.8, MaxScanGB: 5}
}

func hygieneCfg() config.LogHygiene {
	return config.LogHygiene{Sources: []string{"app_prod"}, Kinds: config.LogHygieneKinds(), ParamFields: []string{"name", "address", "tel"}}
}

func hygieneChecks() config.Checks {
	c := checksCfg()
	c.LogHygiene = hygieneCfg()
	return c
}

// goMatch は条件を Go の regexp で評価する (Insights の `like` / `not like` と同じ意味: 部分一致)。
func goMatch(t testing.TB, c HygieneCond, line string) bool {
	t.Helper()
	ok := regexp.MustCompile(c.Like).MatchString(line)
	if c.NotLike != "" && regexp.MustCompile(c.NotLike).MatchString(line) {
		return false
	}
	return ok
}

// matched は line に当たる一時フィールドの名前 (ソート済み)。
func matched(t testing.TB, conds []HygieneCond, line string) string {
	t.Helper()
	var out []string
	for _, c := range conds {
		if goMatch(t, c, line) {
			out = append(out, c.Field)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// 正規表現の意味を Go の regexp で固定する (ADR 0050 の表と「形の揺れ」)。Insights の方言の確認は sandbox で別に行う。
func TestHygieneConditions(t *testing.T) {
	_, conds, err := HygieneQuery(textSource(), hygieneCfg())
	if err != nil {
		t.Fatal(err)
	}
	const (
		key    = "f_secret_aws_access_key"
		slack  = "f_secret_slack_token"
		pem    = "f_secret_private_key"
		longT  = "f_presigned_url_long_term_key"
		signed = "f_presigned_url"
		param  = "f_unfiltered_param"
		sql    = "f_debug_sql"
	)
	url := "https://example-bucket.s3.ap-northeast-1.amazonaws.com/a.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="
	for _, tc := range []struct{ line, want string }{
		// 何にも当たらない
		{`Started GET "/items/1" for 203.0.113.7 at 2026-10-21 09:00:00 +0000`, ""},
		{`Completed 200 OK in 12ms (Views: 3.0ms | ActiveRecord: 1.2ms)`, ""},

		// 長期のアクセスキーの ID
		{"AWS_ACCESS_KEY_ID=" + exKeyID, key},
		{`{"aws_access_key_id": "` + exKeyID + `"}`, key},
		{"key " + exKeyID + " rotated", key},
		{exKeyID, key},
		{"credential=" + exKeyID, key},
		{"Credential=" + exKeyID, key},
		{"Amz-Credential=" + exKeyID, key},
		{"AKIA" + "SHORT", ""},
		{"ASIA" + "IOSFODNN7" + "EXAMPLE", ""},                   // 一時的な認証情報のキー ID は対象外
		{exKeyID + "MOREUPPERCASELETTERS", ""},                   // 20 字より長い英大文字の並び
		{"akia" + "iosfodnn7" + "example", ""},                   // 小文字
		{url + exKeyID + "%2F20261021", longT},                   // 署名付き URL の中のキー ID は secret に数えない
		{url + exKeyID + "/x key=" + exKeyID, key + "," + longT}, // 同じ行に URL の外のキー ID もあれば両方
		{"X-Amz-Credential=" + exKeyID, longT},

		// Slack のトークン
		{"SLACK_BOT_TOKEN=" + exSlack, slack},
		{"token: " + "xox" + "p-" + "1111111111-2222222222-abcdefABCDEF", slack},
		{"xapp" + "-1-A000000000-0000000000000-abcdef0123456789", slack},
		{"xoxb" + "-short", ""},
		{"the xoxo-gossip-girl-quote", ""},

		// PEM の秘密鍵
		{exPEM, pem},
		{exPEMRaw, pem},
		{"-----BEGIN EC " + "PRIVATE KEY-----", pem},
		{"-----BEGIN OPENSSH " + "PRIVATE KEY-----", pem},
		{"-----BEGIN ENCRYPTED " + "PRIVATE KEY-----", pem},
		{"-----BEGIN PGP " + "PRIVATE KEY BLOCK-----", pem},
		{"-----BEGIN PUBLIC KEY-----", ""},
		{"-----BEGIN CERTIFICATE-----", ""},

		// 署名付き URL (一時的な認証情報で署名したもの)
		{url + "ASIA" + "EXAMPLEEXAMPLE00" + "%2F20261021&X-Amz-Signature=0123abcd", signed},
		{"GET /a.pdf?X-Amz-Signature=0123abcd HTTP/1.1", signed},
		{url + exKeyID + "%2F20261021&X-Amz-Signature=0123abcd", longT}, // 長期のキーの行は presigned_url に数えない
		{"X-Amz-Signature", ""},

		// 隠されていない送信項目: => と : の前後の空白は任意 (Ruby 3.4 の Hash#inspect、JSON の両方の書き方)
		{`  Parameters: {"user"=>{"name"=>"alice", "email"=>"[FILTERED]"}}`, param + ",f_param_0"},
		{`  Parameters: {"user" => {"name" => "alice", "email" => "[FILTERED]"}}`, param + ",f_param_0"},
		{`{"params":{"name":"alice"}}`, param + ",f_param_0"},
		{`{"params": {"name": "alice"}}`, param + ",f_param_0"},
		{`{"name" : "alice"}`, param + ",f_param_0"},
		{`  Parameters: {"name"=>"alice", "tel"=>"000-0000-0000"}`, param + ",f_param_0,f_param_2"},
		{`  Parameters: {"address"=>"1 Example St"}`, param + ",f_param_1"},
		// 隠されている・空・別の鍵・文字列でない値
		{`  Parameters: {"name"=>"[FILTERED]", "tel"=>"[FILTERED]"}`, ""},
		{`  Parameters: {"name" => "[FILTERED]"}`, ""},
		{`{"name": "[FILTERED]"}`, ""},
		{`  Parameters: {"name"=>""}`, ""},
		{`{"name": ""}`, ""},
		{`  Parameters: {"file_name"=>"a.pdf", "username"=>"alice", "name_kana"=>"x"}`, ""},
		{`  Parameters: {"name"=>nil, "tel"=>123}`, ""},
		{`  Parameters: {"name"=>{"first"=>"x"}}`, ""},
		{`name=alice`, ""},

		// debug の SQL: 色付きでも色なしでも
		{`  User Load (0.5ms)  SELECT "users".* FROM "users" WHERE "users"."id" = 1 LIMIT 1`, sql},
		{"  " + esc + "[1m" + esc + "[36mUser Load (0.5ms)" + esc + "[0m  " + esc + "[1m" + esc + "[34mSELECT \"users\".* FROM \"users\"" + esc + "[0m", sql},
		{"  " + esc + "[1m" + esc + "[35mSQL (1.2ms)" + esc + "[0m  " + esc + "[1m" + esc + "[32mINSERT INTO \"orders\" (\"note\") VALUES ('x')" + esc + "[0m", sql},
		{`  Order Update (12ms)  UPDATE "orders" SET "note" = 'x' WHERE "orders"."id" = 1`, sql},
		{`  (0.3ms)  DELETE FROM "sessions" WHERE "sessions"."id" = 1`, sql},
		{`(0.000435s) SELECT * FROM items`, sql},
		{`Completed 200 OK in 12ms (Views: 3.0ms | ActiveRecord: 1.2ms)  SELECT`, ""},
		{`SELECT is a keyword (see docs)`, ""},
		{`  Rendered items/index.html.erb (Duration: 1.2ms | Allocations: 300)`, ""},
		{`  TRANSACTION (0.1ms)  BEGIN`, ""},
		{`(0.5ms) SELECTED 3 rows`, ""},
	} {
		want := strings.Split(tc.want, ",")
		sort.Strings(want)
		if got := matched(t, conds, tc.line); got != strings.Join(want, ",") {
			t.Errorf("%q:\n got  %q\n want %q", strings.ReplaceAll(tc.line, esc, "ESC"), got, tc.want)
		}
	}
}

func TestHygieneQuery(t *testing.T) {
	q, conds, err := HygieneQuery(textSource(), hygieneCfg())
	if err != nil {
		t.Fatal(err)
	}
	stages := strings.Split(q, "\n| ")
	if len(stages) != 2 || !strings.HasPrefix(stages[0], "fields (") || !strings.HasPrefix(stages[1], "stats count(*) as n_lines, sum(f_secret_aws_access_key) as n_secret_aws_access_key, ") {
		t.Fatalf("query must be `fields` then `stats`:\n%s", q)
	}
	// 値を返す段・関数を使わない
	for _, bad := range []string{"display", "sort", "limit", "parse", " by ", "@message as", "earliest", "latest", "min(", "max(", "pct(", "@ptr"} {
		if strings.Contains(q, bad) {
			t.Fatalf("query must not use %q:\n%s", bad, q)
		}
	}
	// 種類 7 つ + 項目 3 つ。名前は種類と番号から作り、設定の値を含まない
	var fields []string
	for _, c := range conds {
		fields = append(fields, c.Field)
	}
	if got := strings.Join(fields, ","); got != "f_secret_aws_access_key,f_secret_slack_token,f_secret_private_key,f_presigned_url_long_term_key,f_presigned_url,f_unfiltered_param,f_param_0,f_param_1,f_param_2,f_debug_sql" {
		t.Fatalf("fields: %s", got)
	}
	if !strings.Contains(q, `(@message like /"name"\s*(=>|:)\s*"[^"\[]/) as f_param_0`) || !strings.Contains(q, `(@message like /"(name|address|tel)"\s*(=>|:)\s*"[^"\[]/) as f_unfiltered_param`) {
		t.Fatalf("param conditions:\n%s", q)
	}
	if !strings.Contains(q, `(@message like /X-Amz-Signature=/ and @message not like /X-Amz-Credential=AKIA/) as f_presigned_url,`) {
		t.Fatalf("presigned_url must exclude long-term keys:\n%s", q)
	}

	// 書いた種類だけ。unfiltered_param が無ければ項目の条件も無い
	q, conds, err = HygieneQuery(textSource(), config.LogHygiene{Sources: []string{"app_prod"}, Kinds: []string{config.HygieneDebugSQL, config.HygieneSecretPrivateKey}})
	if err != nil || len(conds) != 2 || conds[0].Kind != config.HygieneSecretPrivateKey || strings.Contains(q, "f_param") || strings.Contains(q, "AKIA") {
		t.Fatalf("kinds subset: %v %+v\n%s", err, conds, q)
	}

	// stream_prefix のソースは、そのストリームだけを数える (同じロググループの 2 つのソースは別に数える)
	src := textSource()
	src.StreamPrefix = "web/"
	q, _, err = HygieneQuery(src, hygieneCfg())
	if err != nil || !strings.HasPrefix(q, `filter @logStream like /^web\//`+"\n| fields (") || len(strings.Split(q, "\n| ")) != 3 {
		t.Fatalf("stream prefix: %v\n%s", err, q)
	}

	// 種類が空なら組み立てない。検査を通らない項目名はクエリに入れずにエラーにする (設定の検査との二重の守り)
	if _, _, err := HygieneQuery(textSource(), config.LogHygiene{Sources: []string{"app_prod"}}); err == nil {
		t.Fatal("empty kinds must be an error")
	}
	for _, bad := range []string{`na"me`, "a/b", "a b", "a\n| display @message", ""} {
		h := hygieneCfg()
		h.ParamFields = []string{"name", bad}
		if _, _, err := HygieneQuery(textSource(), h); err == nil {
			t.Fatalf("field %q must be rejected", bad)
		}
	}
}

func hygieneRow(kv ...string) cwlogstest.Response {
	all := map[string]string{"n_lines": "1000"}
	for _, c := range mustConds(hygieneCfg()) {
		all[c.Sum] = "0"
	}
	for i := 0; i+1 < len(kv); i += 2 {
		all[kv[i]] = kv[i+1]
	}
	return cwlogstest.Response{Rows: []map[string]string{all}, BytesScanned: 1e9}
}

func mustConds(h config.LogHygiene) []HygieneCond {
	_, conds, err := HygieneQuery(textSource(), h)
	if err != nil {
		panic(err)
	}
	return conds
}

func newHygiene(t testing.TB, src config.Source, fake *cwlogstest.Fake) *Collector {
	t.Helper()
	c, err := New(src, hygieneChecks(), fake)
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.Now = func() time.Time { return now }
	c.Select(map[record.Kind]bool{record.KindLogHygiene: true})
	return c
}

func snapshotItems(recs []record.Record) map[string]record.SnapshotItem {
	out := map[string]record.SnapshotItem{}
	for _, r := range recs {
		if it, ok := r.(record.SnapshotItem); ok {
			out[it.Key] = it
		}
	}
	return out
}

func TestCollectHygiene(t *testing.T) {
	fake := &cwlogstest.Fake{Groups: map[string]cwlogstest.Group{"prod-app": {Created: now.AddDate(0, -6, 0)}}, Now: func() time.Time { return now }}
	fake.On("as f_secret_aws_access_key", hygieneRow("n_unfiltered_param", "12", "n_param_0", "9", "n_param_2", "5.0", "n_debug_sql", "1.2E3"))
	c := newHygiene(t, textSource(), fake)
	if got := c.Yields(); len(got) != 1 || got[0] != record.KindLogHygiene {
		t.Fatalf("yields: %v", got)
	}
	sink := &sinkRecorder{}
	w := collect.Window{From: now.Add(-7 * 24 * time.Hour), To: now, ScanFrom: now.Add(-8 * 24 * time.Hour), CollectedAt: now}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	// 1 本だけ。範囲は窓 (再走査の分は足さない)。解釈率の集計は流さない
	if len(fake.Started) != 1 || aws.ToInt64(fake.Started[0].StartTime) != w.From.Unix() || aws.ToInt64(fake.Started[0].EndTime) != w.To.Unix()-1 {
		t.Fatalf("queries: %v", fake.Queries())
	}
	if c.FormatStats() != nil {
		t.Fatalf("a text source has no match rate: %+v", c.FormatStats())
	}
	items := snapshotItems(sink.recs)
	if len(items) != 7 || len(sink.recs) != 7 {
		t.Fatalf("one item per kind: %+v", sink.recs)
	}
	up := items[config.HygieneUnfilteredParam]
	fields, _ := up.Data["fields"].(map[string]any)
	if up.Kind != record.KindLogHygiene || up.Source != "app_prod" || !up.Time.Equal(now) || up.Number("count") != 12 || up.String("log_group") != "prod-app" ||
		up.String("retention") != RetentionNever || up.Data["retention_days"] != nil || up.Number("window_hours") != 168 ||
		len(fields) != 2 || fields["name"] != int64(9) || fields["tel"] != int64(5) {
		t.Fatalf("unfiltered_param: %+v", up)
	}
	if it := items[config.HygieneDebugSQL]; it.Number("count") != 1200 || it.Data["fields"] != nil {
		t.Fatalf("debug_sql: %+v", it)
	}
	if it := items[config.HygieneSecretAWSAccessKey]; it.Number("count") != 0 {
		t.Fatalf("zero counts are recorded as 0: %+v", it)
	}

	// 保持期間: 設定されていれば日数、DescribeLogGroups が失敗すれば unknown (止めない)
	fake = &cwlogstest.Fake{Groups: map[string]cwlogstest.Group{"prod-app": {Created: now.AddDate(0, -6, 0), RetentionDays: 30}}, Now: func() time.Time { return now }}
	fake.On("as f_secret_aws_access_key", hygieneRow("n_secret_private_key", "1"))
	sink = &sinkRecorder{}
	if err := newHygiene(t, textSource(), fake).Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if it := snapshotItems(sink.recs)[config.HygieneSecretPrivateKey]; it.String("retention") != RetentionSet || it.Number("retention_days") != 30 || it.Number("count") != 1 {
		t.Fatalf("retention set: %+v", it)
	}
	fake = &cwlogstest.Fake{DescribeErr: cwlogstest.APIError{Code: "AccessDeniedException"}}
	fake.On("as f_secret_aws_access_key", hygieneRow("n_secret_private_key", "1"))
	sink = &sinkRecorder{}
	if err := newHygiene(t, textSource(), fake).Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if it := snapshotItems(sink.recs)[config.HygieneSecretPrivateKey]; it.String("retention") != RetentionUnknown || it.Data["retention_days"] != nil {
		t.Fatalf("retention unknown: %+v", it)
	}
}

func TestCollectHygieneNoData(t *testing.T) {
	w := collect.Window{From: now.Add(-7 * 24 * time.Hour), To: now, CollectedAt: now}
	// 行が 1 つも無い (stats が行を返さない): 0 件
	fake := &cwlogstest.Fake{}
	fake.On("as f_secret_aws_access_key", cwlogstest.Response{})
	sink := &sinkRecorder{}
	if err := newHygiene(t, textSource(), fake).Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	for k, it := range snapshotItems(sink.recs) {
		if it.Number("count") != 0 {
			t.Fatalf("%s: %+v", k, it)
		}
	}
	if len(sink.recs) != 7 {
		t.Fatalf("items: %d", len(sink.recs))
	}
	// 範囲がロググループの作成前: 問い合わせず「データなし」(0 件)
	fake = &cwlogstest.Fake{Groups: map[string]cwlogstest.Group{"prod-app": {Created: now.Add(time.Hour)}}, Now: func() time.Time { return now }}
	sink = &sinkRecorder{}
	if err := newHygiene(t, textSource(), fake).Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if len(fake.Started) != 0 || len(sink.recs) != 7 {
		t.Fatalf("out of range: %d queries, %d items", len(fake.Started), len(sink.recs))
	}
}

// 読めない結果・失敗は収集の失敗にする (0 件として解消に倒さない)。何も出さない。
func TestCollectHygieneFailures(t *testing.T) {
	w := collect.Window{From: now.Add(-7 * 24 * time.Hour), To: now, CollectedAt: now}
	two := hygieneRow()
	two.Rows = append(two.Rows, two.Rows[0])
	missing := hygieneRow()
	delete(missing.Rows[0], "n_debug_sql")
	for name, tc := range map[string]struct {
		resp cwlogstest.Response
		code string
	}{
		"not a number":   {hygieneRow("n_debug_sql", "many"), collect.CodeCollectFailed},
		"empty":          {hygieneRow("n_debug_sql", ""), collect.CodeCollectFailed},
		"negative":       {hygieneRow("n_debug_sql", "-1"), collect.CodeCollectFailed},
		"fraction":       {hygieneRow("n_debug_sql", "1.5"), collect.CodeCollectFailed},
		"NaN":            {hygieneRow("n_debug_sql", "NaN"), collect.CodeCollectFailed},
		"Inf":            {hygieneRow("n_param_1", "Inf"), collect.CodeCollectFailed},
		"huge":           {hygieneRow("n_debug_sql", "1e300"), collect.CodeCollectFailed},
		"hex":            {hygieneRow("n_debug_sql", "0x10"), collect.CodeCollectFailed},
		"spaces":         {hygieneRow("n_debug_sql", " 3"), collect.CodeCollectFailed},
		"bad line count": {hygieneRow("n_lines", "x"), collect.CodeCollectFailed},
		"missing column": {missing, collect.CodeCollectFailed},
		"two rows":       {two, collect.CodeCollectFailed},
		"access denied":  {cwlogstest.Response{StartErr: cwlogstest.APIError{Code: "AccessDeniedException"}}, collect.CodeAccessDenied},
		"malformed":      {cwlogstest.Response{StartErr: cwlogstest.APIError{Code: "MalformedQueryException"}}, collect.CodeQueryInvalid},
		"timeout":        {cwlogstest.Response{Status: "Timeout"}, collect.CodeQueryLimit},
		"max_scan_gb":    {cwlogstest.Response{Rows: hygieneRow().Rows, BytesScanned: 6e9}, collect.CodeQueryLimit},
	} {
		fake := &cwlogstest.Fake{}
		fake.On("as f_secret_aws_access_key", tc.resp)
		sink := &sinkRecorder{}
		err := newHygiene(t, textSource(), fake).Collect(context.Background(), w, sink)
		var ce *collect.Error
		if !errors.As(err, &ce) || ce.Code != tc.code || ce.Source != "app_prod" {
			t.Errorf("%s: want %s, got %v", name, tc.code, err)
		}
		if len(sink.recs) != 0 {
			t.Errorf("%s: a failed collection must emit nothing: %+v", name, sink.recs)
		}
	}
}

// 既存の形式のソースも log_hygiene で読める。必要な種類だけを流す: weekly は衛生のクエリだけ、daily は今までどおりの集計だけ。
func TestSelectKinds(t *testing.T) {
	checks := hygieneChecks()
	checks.LogHygiene.Sources = []string{"web"}
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now, CollectedAt: now}
	build := func(needs map[record.Kind]bool) (*Collector, *cwlogstest.Fake) {
		fake := &cwlogstest.Fake{}
		fake.On("as lines_total", linesResp("2026-10-21", "1000", "950"))
		fake.On("as f_secret_aws_access_key", hygieneRow("n_presigned_url", "4"))
		c, err := New(nginxSource(), checks, fake)
		if err != nil {
			t.Fatal(err)
		}
		c.Sleep = func(context.Context, time.Duration) error { return nil }
		if needs != nil {
			c.Select(needs)
		}
		return c, fake
	}
	kindsOf := func(c *Collector) string {
		var out []string
		for _, k := range c.Yields() {
			out = append(out, string(k))
		}
		return strings.Join(out, ",")
	}

	// 既定 (Select しない。collect / init) と daily: 今までどおり。衛生のクエリは流さない
	for _, needs := range []map[record.Kind]bool{nil, {record.KindHTTPAccess: true, record.KindTrailEvent: true}} {
		c, fake := build(needs)
		sink := &sinkRecorder{}
		if err := c.Collect(context.Background(), w, sink); err != nil {
			t.Fatal(err)
		}
		if kindsOf(c) != "http_access" || len(snapshotItems(sink.recs)) != 0 || strings.Contains(strings.Join(fake.Queries(), "\n"), "f_secret") || c.FormatStats() == nil {
			t.Fatalf("needs %v: yields %s, queries %v", needs, kindsOf(c), fake.Queries())
		}
	}
	// weekly: 衛生のクエリ 1 本だけ
	c, fake := build(map[record.Kind]bool{record.KindLogHygiene: true, record.KindPostureItem: true})
	sink := &sinkRecorder{}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if kindsOf(c) != "log_hygiene" || len(fake.Started) != 1 || len(sink.recs) != 7 || c.FormatStats() != nil {
		t.Fatalf("weekly: yields %s, %d queries, %d records", kindsOf(c), len(fake.Started), len(sink.recs))
	}
	// 両方を必要とするプロファイル: 両方
	c, fake = build(map[record.Kind]bool{record.KindLogHygiene: true, record.KindHTTPAccess: true})
	sink = &sinkRecorder{}
	if err := c.Collect(context.Background(), w, sink); err != nil {
		t.Fatal(err)
	}
	if kindsOf(c) != "http_access,log_hygiene" || len(snapshotItems(sink.recs)) != 7 || c.FormatStats() == nil || c.FormatStats().BytesScanned != c.Scanned() {
		t.Fatalf("both: yields %s, %d queries", kindsOf(c), len(fake.Started))
	}
	// sources に無いソースは、必要とされても衛生のクエリを流さない
	checks.LogHygiene.Sources = []string{"other"}
	c, _ = build(map[record.Kind]bool{record.KindLogHygiene: true})
	if kindsOf(c) != "" {
		t.Fatalf("uncovered source: %s", kindsOf(c))
	}
	// doctor が構文検査するクエリ
	checks.LogHygiene.Sources = []string{"web"}
	c, _ = build(nil)
	if q := c.Queries(); !strings.Contains(q["log_hygiene"], "as f_debug_sql") || q[httpHits] == "" {
		t.Fatalf("queries: %v", q)
	}
	tc, err := New(textSource(), hygieneChecks(), &cwlogstest.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	if q := tc.Queries(); len(q) != 1 || q["log_hygiene"] == "" || tc.QueryCount() != 0 {
		t.Fatalf("text queries: %v", q)
	}
}

// ---- ファズテスト (ADR 0041・0050「クエリの組み立て」) ----

var (
	hygieneFieldName = regexp.MustCompile(`^f_[a-z0-9_]+$`)
	hygieneSumName   = regexp.MustCompile(`^n_[a-z0-9_]+$`)
)

// 設定の値 (項目名・stream_prefix) が何であっても、クエリの形が変わらない。
// 守る規則:
//   - 段は `fields` と `stats` だけ (stream_prefix があれば先頭に `filter @logStream` が 1 つ)。数と並びは設定の値に依らない
//   - `/.../` の中にエスケープされていない `/` が無い
//   - 一時フィールドの名前は全部異なり、決まった字だけ (設定の値が識別子に入らない)
//   - 正規表現は Go の regexp でも読め、4 つの書き方 (`=>` と `:`、空白の有無) に一致し、[FILTERED]・空の値・別の鍵に一致しない
//   - 設定の検査を通らない項目名はクエリに入らない (エラー)
func FuzzHygieneQuery(f *testing.F) {
	for _, s := range [][2]string{{"name", ""}, {"address", "web/"}, {"tel", "app/prod-"}, {"user-name_2", ""}, {`na"me`, ""}, {"a/b", "/"}, {"a\n| display @message", ""},
		{"x", "a\n| display @message"}, {"(a|b)", ""}, {`a\`, `\`}, {"", ""}, {"名前", "ストリーム/"}, {"a b", " "}, {strings.Repeat("a", 64), ""}, {strings.Repeat("a", 65), ""}, {"x", "\x00"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, field, prefix string) {
		src := textSource()
		src.StreamPrefix = prefix
		h := config.LogHygiene{Sources: []string{"app_prod"}, Kinds: config.LogHygieneKinds(), ParamFields: []string{"name", field, "tel"}}
		q, conds, err := HygieneQuery(src, h)
		valid := config.ValidHygieneParamField(field) && field != "name" && field != "tel"
		if err != nil {
			if q != "" || conds != nil {
				t.Fatalf("エラーなのにクエリを返した: %q", q)
			}
			if valid && !strings.ContainsFunc(prefix, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				t.Fatalf("正しい項目名 %q (stream_prefix %q) を拒否した: %v", field, prefix, err)
			}
			return
		}
		if !valid {
			t.Fatalf("検査を通らない項目名 %q がクエリに入った:\n%s", field, q)
		}
		stages := strings.Split(q, "\n")
		want := []string{"fields (", "| stats count(*) as n_lines, sum("}
		if prefix != "" {
			want = []string{"filter @logStream like /^", "| fields (", "| stats count(*) as n_lines, sum("}
		}
		if len(stages) != len(want) {
			t.Fatalf("段の数が変わった (%d):\n%s", len(stages), q)
		}
		for i, p := range want {
			if !strings.HasPrefix(stages[i], p) {
				t.Fatalf("段 %d が %q で始まらない:\n%s", i, p, q)
			}
		}
		if prefix != "" && unescapedSlash(regexLiteral(prefix)) {
			t.Fatalf("stream_prefix %q がリテラルを抜け出せる", prefix)
		}
		seen := map[string]bool{}
		for _, c := range conds {
			if !hygieneFieldName.MatchString(c.Field) || !hygieneSumName.MatchString(c.Sum) || seen[c.Field] || seen[c.Sum] {
				t.Fatalf("一時フィールドの名前が不正か重複: %+v", c)
			}
			seen[c.Field], seen[c.Sum] = true, true
			for _, re := range []string{c.Like, c.NotLike} {
				if unescapedSlash(re) {
					t.Fatalf("%s: エスケープされていない / がある: %q", c.Field, re)
				}
				if _, err := regexp.Compile(re); err != nil {
					t.Fatalf("%s: Go の regexp で読めない: %q: %v", c.Field, re, err)
				}
			}
			if !strings.Contains(q, "("+c.Expr()+") as "+c.Field) || !strings.Contains(q, "sum("+c.Field+") as "+c.Sum) {
				t.Fatalf("%s がクエリに無い:\n%s", c.Field, q)
			}
		}
		// 項目の条件は、書いた名前の鍵にだけ一致する (空白の有無で結果が変わらない)
		var pc *HygieneCond
		for i := range conds {
			if conds[i].Param == field {
				pc = &conds[i]
			}
		}
		if pc == nil || pc.Field != "f_param_1" {
			t.Fatalf("項目 %q の条件が無い: %+v", field, conds)
		}
		for _, line := range []string{`"` + field + `"=>"x"`, `"` + field + `" => "x"`, `"` + field + `":"x"`, `"` + field + `": "x"`, `{"a"=>1, "` + field + `"=>"山田"}`} {
			if !goMatch(t, *pc, line) || !strings.Contains(matched(t, conds, line), "f_unfiltered_param") {
				t.Fatalf("%q に一致しない (%s)", line, pc.Like)
			}
		}
		for _, line := range []string{`"` + field + `"=>"[FILTERED]"`, `"` + field + `" => "[FILTERED]"`, `"` + field + `":"[FILTERED]"`, `"` + field + `": "[FILTERED]"`,
			`"` + field + `"=>""`, `"` + field + `" => ""`, `"` + field + `": ""`, `"x` + field + `"=>"x"`, `"` + field + `x": "x"`, `"x` + field + `" => "x"`, field + `=>"x"`, `"` + field + `"=>nil`} {
			if goMatch(t, *pc, line) {
				t.Fatalf("%q に一致した (%s)", line, pc.Like)
			}
		}
	})
}

// fuzzSecret は結果に紛れ込んだ文字列の印。record にも、エラーの文にも残ってはいけない。
const fuzzSecret = "s3cr3t-value-from-log"

// Insights の結果 (偽の API が返す任意の文字列) を読む。
// 守る規則:
//   - 受け取るのは有限で負でない整数だけ。それ以外 (数でない・負・小数・NaN・無限大・大きすぎる) は収集の失敗で、0 件にしない。何も出さない
//   - 成功したら、出した件数は結果の値そのもの (別の数に化けない)
//   - record とエラーの文に、結果の文字列が残らない
func FuzzHygieneRows(f *testing.F) {
	for _, s := range [][3]string{{"12", "3", "1000"}, {"0", "0", "0"}, {"5.0", "1.2E3", "1e3"}, {"NaN", "1", "1"}, {"-1", "1", "1"}, {"Inf", "1", "1"}, {"1", "-Inf", "1"}, {"1e300", "1", "1"},
		{"1.5", "1", "1"}, {"", "1", "1"}, {"1", "1", ""}, {" 1", "1", "1"}, {"0x10", "1", "1"}, {"1_000", "1", "1"}, {"１２", "1", "1"}, {fuzzSecret, "1", "1"}, {"1", "1" + fuzzSecret, "1"},
		{"9007199254740993", "1", "1"}, {"+3", "1", "1"}, {"1e", "1", "1"}, {".", "1", "1"}, {"1\n2", "1", "1"}} {
		f.Add(s[0], s[1], s[2])
	}
	conds := mustConds(hygieneCfg())
	f.Fuzz(func(t *testing.T, v1, v2, lines string) {
		row := map[string]string{"n_lines": lines, "@message": fuzzSecret, "@logStream": fuzzSecret, "extra": v1 + fuzzSecret}
		for _, c := range conds {
			row[c.Sum] = "0"
		}
		row["n_unfiltered_param"], row["n_param_0"], row["n_secret_slack_token"] = v1, v1, v2
		fake := &cwlogstest.Fake{}
		fake.On("as f_secret_aws_access_key", cwlogstest.Response{Rows: []map[string]string{row}})
		c := newHygiene(t, textSource(), fake)
		sink := &sinkRecorder{}
		err := c.Collect(context.Background(), collect.Window{From: now.Add(-7 * 24 * time.Hour), To: now, CollectedAt: now}, sink)
		n1, ok1 := exactCount(v1)
		n2, ok2 := exactCount(v2)
		_, ok3 := exactCount(lines)
		if err != nil {
			var ce *collect.Error
			if !errors.As(err, &ce) || ce.Code != collect.CodeCollectFailed {
				t.Fatalf("読めない結果は COLLECT_FAILED: %v", err)
			}
			if ok1 && ok2 && ok3 {
				t.Fatalf("読める結果 (%q, %q, %q) を失敗にした: %v", v1, v2, lines, err)
			}
			if len(sink.recs) != 0 {
				t.Fatalf("失敗したのに record を出した: %+v", sink.recs)
			}
			if strings.Contains(err.Error(), fuzzSecret) || (len(v1) > 3 && !ok1 && strings.Contains(err.Error(), v1)) {
				t.Fatalf("エラーの文に結果の文字列が残った: %v", err)
			}
			return
		}
		if !ok1 || !ok2 || !ok3 {
			t.Fatalf("読めない結果 (%q, %q, %q) を受け取った: %+v", v1, v2, lines, sink.recs)
		}
		items := snapshotItems(sink.recs)
		if len(items) != len(config.LogHygieneKinds()) {
			t.Fatalf("種類ごとに 1 項目: %+v", sink.recs)
		}
		up := items[config.HygieneUnfilteredParam]
		fields, _ := up.Data["fields"].(map[string]any)
		if up.Data["count"] != n1 || items[config.HygieneSecretSlackToken].Data["count"] != n2 || (n1 > 0) != (fields["name"] == n1) {
			t.Fatalf("件数が結果と違う: (%q, %q) → %+v / %+v", v1, v2, up, items[config.HygieneSecretSlackToken])
		}
		for _, it := range items {
			b, err := json.Marshal(it)
			if err != nil {
				t.Fatalf("record を JSON にできない: %v", err)
			}
			if strings.Contains(string(b), fuzzSecret) {
				t.Fatalf("record に結果の文字列が残った: %s", b)
			}
			if n, ok := it.Data["count"].(int64); !ok || n < 0 || n > MaxHygieneCount {
				t.Fatalf("件数が有限で負でない整数でない: %+v", it)
			}
		}
	})
}

// countGrammar は受け取る数の書き方 (実装と同じ文法)。値は exactCount が別の方法で読む。
var countGrammar = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?([eE]\+?[0-9]{1,3})?$`)

// exactCount は s を、実装とは別の方法 (多倍長の有理数) で「負でない整数」として読む。
func exactCount(s string) (int64, bool) {
	if len(s) > 32 || !countGrammar.MatchString(s) {
		return 0, false
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || !r.IsInt() || r.Sign() < 0 || r.Num().Cmp(big.NewInt(MaxHygieneCount)) > 0 {
		return 0, false
	}
	return r.Num().Int64(), true
}

// 「直前が lit でない位置」の表現 (後方参照の否定を選択肢で書いたもの) が、素直な判定と同じ意味になる。
func FuzzNotPrecededBy(f *testing.F) {
	for _, s := range [][2]string{{"X-Amz-Credential=", "X-Amz-Credential=K"}, {"X-Amz-Credential=", "Amz-Credential=K"}, {"ab=", "ab=K ab=ab=K"}, {"ab=", "K"}, {"ab=", "b=K"}, {"a", "aK"},
		{"-", "-K"}, {"a.b", "axbK"}, {"]", "]K"}, {"^", "^K K"}, {`\`, `\K`}, {"ab=", "ab=ab=K\nK"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, lit, line string) {
		if lit == "" || len(lit) > 24 || strings.ContainsFunc(lit, func(r rune) bool { return r < 0x20 || r > 0x7e || r == 'K' }) || strings.Contains(line, "\n") {
			return
		}
		re, err := regexp.Compile(notPrecededBy(lit) + "K")
		if err != nil {
			t.Fatalf("notPrecededBy(%q) = %q: %v", lit, notPrecededBy(lit), err)
		}
		if unescapedSlash(notPrecededBy(lit)) {
			t.Fatalf("notPrecededBy(%q) = %q: エスケープされていない / がある", lit, notPrecededBy(lit))
		}
		want := false
		for i := 0; i < len(line); i++ {
			if line[i] == 'K' && !strings.HasSuffix(line[:i], lit) {
				want = true
			}
		}
		if got := re.MatchString(line); got != want {
			t.Fatalf("notPrecededBy(%q) が %q に %v (正しくは %v)", lit, line, got, want)
		}
	})
}
