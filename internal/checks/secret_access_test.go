package checks

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 窓は appWindow [10-20 09:00, 10-21 09:00)。「主体 × 秘匿値」の初出は窓の前 14 日 [10-06 09:00, 10-20 09:00) と比べ、
// 一括読み出しの平常帯は窓の始まりの日 (10-20) の前日から 14 日 (10-06〜10-19) の日ごとの異なり数。

type secretSeed struct {
	st *store.Dir
	t  *testing.T
	n  int
}

// read は主体 arn の秘匿値の読み取り 1 件を at に入れる。api は "secretsmanager:GetSecretValue" の形。
func (s *secretSeed) read(arn string, kind record.PrincipalKind, at time.Time, api, code string, data map[string]any) {
	s.t.Helper()
	svc, name, _ := strings.Cut(api, ":")
	s.n++
	e := record.TrailEvent{EventID: fmt.Sprintf("s%05d", s.n), Time: at, Source: "trail", Name: name, EventSource: svc + ".amazonaws.com",
		PrincipalARN: arn, PrincipalKind: kind, IP: "198.51.100.1", ErrorCode: code, ReadOnly: true, Data: data}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

func (s *secretSeed) secret(arn string, kind record.PrincipalKind, at time.Time, id string) {
	s.read(arn, kind, at, "secretsmanager:GetSecretValue", "", map[string]any{"secret_id": id})
}

// coverage は arata が CloudTrail を収集し終えた日を、10-19 から遡って days 日分の init の run として入れる (活動の有無とは別)。
func coverage(t *testing.T, st *store.Dir, days int) {
	t.Helper()
	collectedRun(t, st, "init", time.Date(2026, 10, 20-days, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), "ok", trailOK())
}

var runSeq int

// trailOK は CloudTrail の収集が成功した run の stats。
func trailOK() map[string]any { return map[string]any{TrailCollectedStat: true} }

// collectedRun は窓 [from, to) を収集した run を入れる。started_at は窓の終わり。
func collectedRun(t *testing.T, st *store.Dir, profile string, from, to time.Time, status string, stats map[string]any) {
	t.Helper()
	runSeq++
	id := fmt.Sprintf("run-%03d", runSeq)
	ctx := context.Background()
	if err := st.BeginRun(ctx, store.Run{ID: id, Profile: profile, WindowFrom: from, WindowTo: to, StartedAt: to, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishRun(ctx, id, status, stats); err != nil {
		t.Fatal(err)
	}
}

func secretCheck() SecretAccess { return SecretAccess{Config: config.DefaultChecks().SecretAccess} }

func obsByKey(obs []Observation) map[string]Observation {
	out := map[string]Observation{}
	for _, o := range obs {
		out[o.Key] = o
	}
	return out
}

const (
	secApp    = "arn:aws:iam::123456789012:role/example-app"
	secWorker = "arn:aws:iam::123456789012:role/example-worker"
	secBatch  = "arn:aws:iam::123456789012:role/example-batch"
	secBusy   = "arn:aws:iam::123456789012:role/example-busy"
	secAlice  = "arn:aws:iam::123456789012:user/alice"
)

func seedSecretHistory(s *secretSeed) {
	for d := 6; d <= 19; d++ {
		at := time.Date(2026, 10, d, 12, 0, 0, 0, time.UTC)
		s.secret(secApp, record.PrincipalAssumedRole, at, "prod/db")
		s.read(secBatch, record.PrincipalAssumedRole, at, "ssm:GetParametersByPath", "", map[string]any{"path": "/example/prod/", "recursive": true, "with_decryption": true})
		for i := 0; i < 20; i++ {
			s.secret(secBusy, record.PrincipalAssumedRole, at, fmt.Sprintf("busy/%02d", i))
		}
	}
	// 復号しない GetParameter も「その名前を読んだことがある」の履歴には数える。ただし「秘匿値を読んだことがある」には数えない
	s.read(secWorker, record.PrincipalAssumedRole, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), "ssm:GetParameter", "", map[string]any{"name": "/example/prod/region", "with_decryption": false})
}

func TestSecretAccess(t *testing.T) {
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	seedSecretHistory(s)
	coverage(t, st, 14)
	in := now.Add(-3 * time.Hour)
	// app: いつもの秘匿値 + 新しい秘匿値 1 つ → low
	s.secret(secApp, record.PrincipalAssumedRole, in, "prod/db")
	s.secret(secApp, record.PrincipalAssumedRole, in, "prod/api")
	// worker: 秘匿値を (復号して) 読むのが初めて → medium。復号しない読み取りは対象外。読んだことのある名前は初出にしない
	s.read(secWorker, record.PrincipalAssumedRole, in, "ssm:GetParameter", "", map[string]any{"name": "/example/prod/token", "with_decryption": true})
	s.read(secWorker, record.PrincipalAssumedRole, in, "ssm:GetParameter", "", map[string]any{"name": "/example/prod/plain"})
	s.read(secWorker, record.PrincipalAssumedRole, in, "ssm:GetParameter", "", map[string]any{"name": "/example/prod/region", "with_decryption": true})
	// batch: パス単位で 1 と数える。いつものパス → 報告しない
	s.read(secBatch, record.PrincipalAssumedRole, in, "ssm:GetParametersByPath", "", map[string]any{"path": "/example/prod/", "recursive": true, "with_decryption": true})
	// busy: ふだん 20 個。25 個 (5 個は新しい) は平常帯 (60) の内 → low
	for i := 0; i < 25; i++ {
		s.secret(secBusy, record.PrincipalAssumedRole, in, fmt.Sprintf("busy/%02d", i))
	}
	// alice: 一括読み出し (GetSecretValue 8 個 + BatchGetSecretValue 3 個 + GetParameters 2 個 = 13 > 10) → high
	for i := 0; i < 8; i++ {
		s.secret(secAlice, record.PrincipalUser, in, fmt.Sprintf("prod/s%02d", i))
	}
	s.read(secAlice, record.PrincipalUser, in, "secretsmanager:BatchGetSecretValue", "", map[string]any{"secret_ids": []any{"prod/b1", "prod/b2", "prod/s00"}})
	s.read(secAlice, record.PrincipalUser, in, "secretsmanager:BatchGetSecretValue", "", map[string]any{"secret_filters": true})
	s.read(secAlice, record.PrincipalUser, in, "ssm:GetParameters", "", map[string]any{"names": []any{"/example/prod/a", "/example/prod/b"}, "with_decryption": true})
	// 失敗した読み取り (access_denied が扱う)・サービス主体・root は数えない
	s.secret("arn:aws:iam::123456789012:role/example-denied", record.PrincipalAssumedRole, in, "prod/db")
	s.read("arn:aws:iam::123456789012:role/example-denied", record.PrincipalAssumedRole, in, "secretsmanager:GetSecretValue", "AccessDeniedException", map[string]any{"secret_id": "prod/x"})
	s.secret("ecs-tasks.amazonaws.com", record.PrincipalService, in, "prod/db")
	s.secret("arn:aws:iam::123456789012:root", record.PrincipalRoot, in, "prod/db")
	// 初出の履歴は日の区切りに依らず窓の直前まで: denied ロールは窓の直前 (10-20 08:00) に prod/db を読んでいるので初出ではない
	s.secret("arn:aws:iam::123456789012:role/example-denied", record.PrincipalAssumedRole, now.Add(-25*time.Hour), "prod/db")

	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	got := obsByKey(obs)
	want := map[string]Severity{secApp: Low, secWorker: Medium, secBusy: Low, secAlice: High}
	if fmt.Sprint(bySev(obs)) != fmt.Sprint(want) {
		t.Fatalf("severities: %v", bySev(obs))
	}
	app := got[secApp].Data
	if fmt.Sprint(app["new_secrets"]) != "[secretsmanager:prod/api]" || app["first_reader"] != false || app["distinct_secrets"] != 2 {
		t.Fatalf("app: %+v", app)
	}
	w := got[secWorker].Data
	if fmt.Sprint(w["new_secrets"]) != "[ssm:/example/prod/token]" || w["first_reader"] != true || !strings.Contains(got[secWorker].Summary, "初めて") {
		t.Fatalf("worker: %+v %s", w, got[secWorker].Summary)
	}
	a := got[secAlice]
	if a.Data["distinct_secrets"] != 13 || a.Data["bulk"] != true || a.Data["threshold"] != 10.0 || a.Data["first_reader"] != true || !strings.Contains(a.Summary, "一括") {
		t.Fatalf("alice: %+v %s", a.Data, a.Summary)
	}
	if !strings.Contains(fmt.Sprint(a.Data["secrets"]), "secretsmanager:(filters)") {
		t.Fatalf("batch with filters must be one secret: %v", a.Data["secrets"])
	}
	busy := got[secBusy].Data
	if busy["bulk"] != false || busy["threshold"] != 60.0 || len(busy["new_secrets"].([]string)) != 5 {
		t.Fatalf("busy: %+v", busy)
	}
	for _, o := range obs {
		for _, k := range []string{"value", "secret_value", "SecretString"} {
			if _, ok := o.Data[k]; ok {
				t.Fatalf("value must not be recorded: %+v", o.Data)
			}
		}
	}
}

// 以前の版で集めた events (with_decryption が無い) の ssm の読み取りは、秘匿値を読んだことがあるとみなす (初めての読み手にしない)。
func TestSecretAccessLegacyHistory(t *testing.T) {
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 14)
	s.read(secWorker, record.PrincipalAssumedRole, time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), "ssm:GetParameter", "", map[string]any{"name": "/example/prod/old"})
	s.read(secWorker, record.PrincipalAssumedRole, now.Add(-time.Hour), "ssm:GetParameter", "", map[string]any{"name": "/example/prod/token", "with_decryption": true})
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Severity != Low || obs[0].Data["first_reader"] != false {
		t.Fatalf("obs: %+v", obs)
	}
}

// allowlist の secrets_access に書いた秘匿値は「初めて読む秘匿値」に数えない (一括読み出しの数には数える)。
func TestSecretAccessAllowlisted(t *testing.T) {
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 14)
	in := now.Add(-time.Hour)
	s.secret(secApp, record.PrincipalAssumedRole, in, "prod/db/main")
	s.read(secApp, record.PrincipalAssumedRole, in, "ssm:GetParametersByPath", "", map[string]any{"path": "/example/prod/", "with_decryption": true})
	s.secret(secWorker, record.PrincipalAssumedRole, in, "prod/db/main")
	s.secret(secWorker, record.PrincipalAssumedRole, in, "prod/api")
	al, err := allowlist.Parse([]byte("secrets_access:\n  - principal: " + secApp + "\n    secrets: [\"prod/db/*\", \"/example/prod/\"]\n" +
		"  - principal: " + secWorker + "\n    secrets: [\"prod/db/*\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	// worker は承認済みの秘匿値しか読んでいないので「初めての読み手」でもなく low
	if len(obs) != 1 || obs[0].Key != secWorker || obs[0].Severity != Low || fmt.Sprint(obs[0].Data["new_secrets"]) != "[secretsmanager:prod/api]" ||
		obs[0].Data["distinct_secrets"] != 2 || obs[0].Data["secrets_access_matched"] != 1 {
		t.Fatalf("obs: %+v", obs)
	}
}

// パス単位の読み取りは 1 と数え、Data に recursive を残す。
func TestSecretAccessPath(t *testing.T) {
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 14)
	in := now.Add(-3 * time.Hour)
	s.read(secBatch, record.PrincipalAssumedRole, in, "ssm:GetParametersByPath", "", map[string]any{"path": "/example/", "recursive": true, "with_decryption": true})
	s.read(secBatch, record.PrincipalAssumedRole, in.Add(time.Minute), "ssm:GetParametersByPath", "", map[string]any{"path": "/example/", "recursive": true, "with_decryption": true})
	s.read(secBatch, record.PrincipalAssumedRole, in, "ssm:GetParametersByPath", "", map[string]any{"path": "/plain/", "recursive": true})
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Severity != Medium || obs[0].Data["distinct_secrets"] != 1 || fmt.Sprint(obs[0].Data["paths"]) != "[/example/ (recursive)]" {
		t.Fatalf("obs: %+v", obs)
	}
}

// 導入直後 (CloudTrail を収集し終えた過去日が min_baseline_days 未満) は初出を報告しない。一括読み出しは絶対の閾値で報告する。
func TestSecretAccessWarmup(t *testing.T) {
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 6)
	in := now.Add(-3 * time.Hour)
	s.secret(secApp, record.PrincipalAssumedRole, in, "prod/db")
	for i := 0; i < 11; i++ {
		s.secret(secAlice, record.PrincipalUser, in, fmt.Sprintf("prod/s%02d", i))
	}
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(bySev(obs)) != fmt.Sprint(map[string]Severity{secAlice: High}) {
		t.Fatalf("obs: %v", bySev(obs))
	}
	if _, ok := obs[0].Data["new_secrets"]; ok || obs[0].Data["baseline_days_with_data"] != 6 {
		t.Fatalf("warmup must not report first reads: %+v", obs[0].Data)
	}
}

// 再走査で遅れて届いた読み取り (窓の前の区間で、今回の収集で初めて保存したもの) は窓に入り、履歴には入らない (初出を隠さない。ADR 0013)。
func TestSecretAccessLateEvent(t *testing.T) {
	st := newStore(t)
	coverage(t, st, 14)
	collected := now.Add(time.Minute)
	e := record.TrailEvent{EventID: "late", Time: appWindow.From.Add(-10 * time.Minute), Source: "trail", Name: "GetSecretValue", EventSource: "secretsmanager.amazonaws.com",
		PrincipalARN: secApp, PrincipalKind: record.PrincipalAssumedRole, IP: "198.51.100.1", ReadOnly: true, Data: map[string]any{"secret_id": "prod/late"}, CollectedAt: collected}
	if err := st.InsertEvent(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	w := appWindow
	w.ScanFrom, w.CollectedAt = w.From.Add(-time.Hour), collected
	obs, err := secretCheck().Evaluate(context.Background(), st, w, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Severity != Medium || fmt.Sprint(obs[0].Data["new_secrets"]) != "[secretsmanager:prod/late]" {
		t.Fatalf("obs: %+v", obs)
	}
}

// serviceAssume は AWS のサービス (ECS のタスク) が role を引き受けた記録を at に入れる。
func (s *secretSeed) serviceAssume(role string, at time.Time) {
	s.t.Helper()
	s.n++
	e := record.TrailEvent{EventID: fmt.Sprintf("a%05d", s.n), Time: at, Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com",
		PrincipalARN: "ecs-tasks.amazonaws.com", PrincipalKind: record.PrincipalService, ReadOnly: true, Data: map[string]any{"role_arn": role}}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

// startupRead は起動時の読み取り (GetParameters の 1 回) を入れる。names は prefix の後ろに 00.. の番号を付けた n 個。
// key が空でなければ、その認証情報で読んだ印 (session_key_hash) を付ける (ADR 0076)。
func (s *secretSeed) startupRead(arn string, at time.Time, prefix string, from, n int, key ...string) {
	s.t.Helper()
	names := []any{}
	for i := from; i < from+n; i++ {
		names = append(names, fmt.Sprintf("%s%02d", prefix, i))
	}
	d := map[string]any{"names": names, "with_decryption": true}
	if len(key) > 0 {
		d["session_key_hash"] = keyHash(s.t, key[0])
	}
	s.read(arn, record.PrincipalAssumedRole, at, "ssm:GetParameters", "", d)
}

// issue は ECS (by が空なら ecs-tasks.amazonaws.com) が role を引き受け、key の認証情報を発行した記録を at に入れる (ADR 0076)。
func (s *secretSeed) issue(role string, at time.Time, key string, by ...string) {
	s.t.Helper()
	svc := "ecs-tasks.amazonaws.com"
	if len(by) > 0 {
		svc = by[0]
	}
	s.n++
	e := record.TrailEvent{EventID: fmt.Sprintf("i%05d", s.n), Time: at, Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com",
		PrincipalARN: svc, PrincipalKind: record.PrincipalService, ReadOnly: true, Data: map[string]any{"role_arn": role, "issued_key_hash": keyHash(s.t, key)}}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

func keyHash(t *testing.T, key string) string {
	t.Helper()
	h, ok := record.SessionKeyHash(key)
	if !ok {
		t.Fatalf("テストのキーの形が違う: %q", key)
	}
	return h
}

// testKey は架空の一時的な認証情報のキー (ASIA + 16 桁)。
func testKey(n int) string { return fmt.Sprintf("ASIAEXAMPLE%09d", n) }

// bulk: exempt (ADR 0073): 起動時に決まった組を読むサービスのロールは、その組を一括読み出しの数から外す。
// 外した結果、何も報告しない主体は info の行 (bulk-exempt:<主体>) に残す。組の外・サービスのロールでない主体は今どおり数える。
func TestSecretAccessBulkExempt(t *testing.T) {
	const (
		exec    = "arn:aws:iam::123456789012:role/example-app-task-execution"
		execMix = "arn:aws:iam::123456789012:role/example-mix-task-execution"
		execAvg = "arn:aws:iam::123456789012:role/example-daily-task-execution"
		human   = "arn:aws:iam::123456789012:role/example-human-operator"
		set     = "/example-app/prod/secrets/S"
	)
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 14)
	for _, r := range []string{exec, execMix, execAvg} {
		s.serviceAssume(r, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	}
	// execAvg は毎日、外す組 15 個とほかの 2 個を読む。平常帯から外す組を除くと中央値は 2 (除かなければ 17 で、閾値 51 に隠れる)
	for d := 6; d <= 19; d++ {
		at := time.Date(2026, 10, d, 12, 0, 0, 0, time.UTC)
		s.startupRead(execAvg, at, set, 0, 15)
		s.startupRead(execAvg, at, "/example-app/prod/other/O", 0, 2)
	}
	in := now.Add(-3 * time.Hour)
	// 起動の 1 秒前に、ECS が実行用のロールの認証情報を発行する (ADR 0076。外すのはその直後の読み取りだけ)
	for i, r := range []string{exec, execMix, execAvg} {
		s.issue(r, in.Add(-time.Second), testKey(i+1))
	}
	// exec: 外す組 17 個だけ (7 + 10 の 2 回) → finding は出さず、info の行
	s.startupRead(exec, in, set, 0, 7, testKey(1))
	s.startupRead(exec, in, set, 7, 10, testKey(1))
	// execMix: 外す組 17 個 + 組の外 11 個 → 外した後の 11 が閾値 10 を超えて high
	s.startupRead(execMix, in, set, 0, 17, testKey(2))
	s.startupRead(execMix, in, "/example-app/prod/other/O", 0, 11, testKey(2))
	// execAvg: 外す組 15 個 + 組の外 12 個 (うち 2 個はいつもの) → 12 > max(10, 2 × 3) で high
	s.startupRead(execAvg, in, set, 0, 15, testKey(3))
	s.startupRead(execAvg, in, "/example-app/prod/other/O", 0, 12, testKey(3))
	// human: bulk: exempt を書いたが、サービスに引き受けられたロールではない → 外さず high
	s.startupRead(human, in, set, 0, 17)

	var b strings.Builder
	b.WriteString("secrets_access:\n")
	for _, r := range []string{exec, execMix, execAvg, human} {
		b.WriteString("  - principal: " + r + "\n    secrets: [\"/example-app/prod/secrets/*\"]\n    bulk: exempt\n    note: 起動時に ECS が読む\n")
	}
	al, err := allowlist.Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	m := obsByKey(obs)
	if len(m) != 4 {
		t.Fatalf("obs: %+v", obs)
	}
	if _, ok := m[exec]; ok {
		t.Fatalf("外した組だけの主体を報告した: %+v", m[exec])
	}
	line := m[BulkExemptKeyPrefix+exec]
	if line.Severity != Info || line.Data["bulk_exempt"] != true || line.Data["bulk_exempted"] != 17 || line.Data["bulk_counted"] != 0 ||
		fmt.Sprint(line.Data["bulk_exempt_patterns"]) != "[/example-app/prod/secrets/*]" || line.Data["principal"] != exec ||
		line.Data["count"] != 2 || fmt.Sprint(line.Data["ips"]) != "[198.51.100.1]" || !strings.Contains(line.Summary, "17 個") ||
		line.Data["bulk_exempt_sessions"] != 1 || line.Data["bulk_exempt_max_delay_seconds"] != 1 {
		t.Fatalf("info の行: %+v", line)
	}
	if line.Fingerprint != fingerprint(Info, nil, "bulk-exempt") {
		t.Fatalf("info の行の Fingerprint は固定: %s", line.Fingerprint)
	}
	if o := m[execMix]; o.Severity != High || o.Data["bulk"] != true || o.Data["distinct_secrets"] != 28 || o.Data["bulk_counted"] != 11 ||
		o.Data["bulk_exempted"] != 17 || fmt.Sprint(o.Data["bulk_exempt_patterns"]) != "[/example-app/prod/secrets/*]" {
		t.Fatalf("execMix: %+v", o)
	}
	if o := m[execAvg]; o.Severity != High || o.Data["baseline_median_distinct"] != 2.0 || o.Data["threshold"] != 10.0 || o.Data["bulk_counted"] != 12 {
		t.Fatalf("execAvg (平常帯からも外す): %+v", o)
	}
	if o := m[human]; o.Severity != High || o.Data["bulk_counted"] != 17 || o.Data["bulk_exempt_ignored"] != "not_service_role" || o.Data["bulk_exempted"] != nil {
		t.Fatalf("human (サービスのロールでない): %+v", o)
	}

	// bulk: exempt の無い secrets_access は、今までどおり一括読み出しに数える (既定は変えない)
	plain, err := allowlist.Parse([]byte("secrets_access:\n  - principal: " + exec + "\n    secrets: [\"/example-app/prod/secrets/*\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err = secretCheck().Evaluate(context.Background(), st, appWindow, plain)
	if err != nil {
		t.Fatal(err)
	}
	if o := obsByKey(obs)[exec]; o.Severity != High || o.Data["bulk_counted"] != nil || o.Data["bulk_exempt_ignored"] != nil {
		t.Fatalf("bulk の無い項目: %+v", o)
	}
}

// bulk: exempt (ADR 0076): 外すのは、ECS が AssumeRole で発行した認証情報 (キーのハッシュが一致) が、発行から bulk_exempt_within の内に使われた読み取りだけ。
// 外せなかった読み取りが 1 つでもあれば medium (bulk-exempt-unmatched:<主体>)。一括読み出しの high のときは high の data に載せるだけ。
func TestSecretAccessBulkExemptSession(t *testing.T) {
	const set = "/example-app/prod/secrets/S"
	role := func(n string) string { return "arn:aws:iam::123456789012:role/example-" + n + "-task-execution" }
	var (
		ok       = role("ok")       // 発行から 11 秒後に読む → 外す (info)
		boundary = role("boundary") // 窓の始まりの前 (前日の終わり) に発行、窓の中で読む → 外す
		skew     = role("skew")     // 記録の時刻のずれで、発行の 3 秒前に見える → 外す
		noKey    = role("nokey")    // 読み取りにキーの印が無い (以前の版で集めた・長期のキー) → medium
		noIssue  = role("noissue")  // 発行の記録が無い → medium
		late     = role("late")     // 発行から 5 分後 (窓の外) → medium
		mix      = role("mix")      // 起動時に 17 個を読み、うち 1 個を外からも読む → その 1 個だけ数え、medium
		stolen   = role("stolen")   // 外から 12 個を読む → 数えて high (medium は重ねない)
		other    = role("other")    // 発行は別のロールのもの → medium
		ec2      = role("ec2")      // 発行したのが ECS でない → medium
	)
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 14)
	in := now.Add(-3 * time.Hour)
	all := []string{ok, boundary, skew, noKey, noIssue, late, mix, stolen, other, ec2}
	for _, r := range all {
		s.serviceAssume(r, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)) // どれもサービスに引き受けられたロール (0073 の 4 節)
	}
	s.issue(ok, in.Add(-11*time.Second), testKey(1))
	s.startupRead(ok, in, set, 0, 17, testKey(1))
	s.issue(boundary, appWindow.From.Add(-30*time.Second), testKey(2))
	s.startupRead(boundary, appWindow.From.Add(10*time.Second), set, 0, 17, testKey(2))
	s.issue(skew, in.Add(3*time.Second), testKey(3))
	s.startupRead(skew, in, set, 0, 17, testKey(3))
	s.issue(noKey, in.Add(-time.Second), testKey(4))
	s.startupRead(noKey, in, set, 0, 3)
	s.startupRead(noIssue, in, set, 0, 3, testKey(5))
	s.issue(late, in.Add(-5*time.Minute), testKey(6))
	s.startupRead(late, in, set, 0, 3, testKey(6))
	s.issue(mix, in.Add(-time.Second), testKey(7))
	s.startupRead(mix, in, set, 0, 17, testKey(7))
	s.startupRead(mix, in.Add(time.Hour), set, 4, 1, testKey(70))
	s.issue(stolen, in.Add(-time.Second), testKey(8))
	s.startupRead(stolen, in, set, 0, 17, testKey(8))
	s.startupRead(stolen, in.Add(2*time.Hour), set, 0, 12, testKey(8))
	s.issue(role("unrelated"), in.Add(-time.Second), testKey(9))
	s.startupRead(other, in, set, 0, 3, testKey(9))
	s.issue(ec2, in.Add(-time.Second), testKey(10), "ec2.amazonaws.com")
	s.startupRead(ec2, in, set, 0, 3, testKey(10))

	var b strings.Builder
	b.WriteString("secrets_access:\n")
	for _, r := range all {
		b.WriteString("  - principal: " + r + "\n    secrets: [\"/example-app/prod/secrets/*\"]\n    bulk: exempt\n    note: 起動時に ECS が読む\n")
	}
	al, err := allowlist.Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	m := obsByKey(obs)
	for _, r := range []string{ok, boundary, skew} {
		line, has := m[BulkExemptKeyPrefix+r]
		if !has || line.Severity != Info || line.Data["bulk_exempted"] != 17 || line.Data["bulk_exempt_sessions"] != 1 {
			t.Errorf("%s: 外して info の行: %+v", r, line)
		}
		if _, has := m[BulkExemptUnmatchedKeyPrefix+r]; has {
			t.Errorf("%s: 外せた読み取りを medium にした", r)
		}
	}
	if d := m[BulkExemptKeyPrefix+ok].Data["bulk_exempt_max_delay_seconds"]; d != 11 {
		t.Errorf("最大の遅れ: %v", d)
	}
	for r, want := range map[string]string{noKey: "map[no_key:1]", noIssue: "map[no_issuance:1]", late: "map[outside_window:1]", other: "map[no_issuance:1]", ec2: "map[no_issuance:1]"} {
		o, has := m[BulkExemptUnmatchedKeyPrefix+r]
		if !has || o.Severity != Medium || fmt.Sprint(o.Data["bulk_exempt_unmatched"]) != want || o.Data["unmatched_secrets"] != 3 ||
			o.Data["principal"] != r || fmt.Sprint(o.Data["ips"]) != "[198.51.100.1]" || fmt.Sprint(o.Data["bulk_exempt_patterns"]) != "[/example-app/prod/secrets/*]" {
			t.Errorf("%s: medium: %+v", r, o)
		}
		if _, has := m[BulkExemptKeyPrefix+r]; has {
			t.Errorf("%s: medium と info の行を両方出した", r)
		}
		if _, has := m[r]; has {
			t.Errorf("%s: 閾値を超えないのに一括読み出し・初出を出した: %+v", r, m[r])
		}
	}
	if o := m[BulkExemptUnmatchedKeyPrefix+noKey]; o.Fingerprint != fingerprint(Medium, nil, "bulk-exempt-unmatched", "no_key") {
		t.Errorf("medium の Fingerprint は重大度と理由の集合: %s", o.Fingerprint)
	}
	if o := m[BulkExemptUnmatchedKeyPrefix+late]; o.Data["bulk_exempt_max_delay_seconds"] != 300 {
		t.Errorf("窓の外の遅れ: %+v", o.Data)
	}
	if o := m[BulkExemptUnmatchedKeyPrefix+mix]; o.Severity != Medium || o.Data["unmatched_secrets"] != 1 || o.Data["bulk_exempted"] != 16 || o.Data["bulk_counted"] != 1 {
		t.Errorf("mix: %+v", o)
	}
	if _, has := m[BulkExemptUnmatchedKeyPrefix+stolen]; has {
		t.Errorf("stolen: high に重ねて medium を出した")
	}
	if o := m[stolen]; o.Severity != High || o.Data["bulk_counted"] != 12 || o.Data["bulk_exempted"] != 5 || o.Data["bulk_exempt_ignored"] != "session_unmatched" ||
		fmt.Sprint(o.Data["bulk_exempt_unmatched"]) != "map[outside_window:1]" || o.Data["unmatched_secrets"] != 12 {
		t.Errorf("stolen: high の data: %+v", o)
	}

	// 窓を延ばせば (設定)、5 分後の読み取りも外れる
	c := secretCheck()
	c.Config.BulkExemptWithin = "10m"
	obs, err = c.Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	if m := obsByKey(obs); m[BulkExemptKeyPrefix+late].Severity != Info || m[BulkExemptUnmatchedKeyPrefix+late].Key != "" {
		t.Errorf("bulk_exempt_within: 10m で外れない: %+v", m[BulkExemptUnmatchedKeyPrefix+late])
	}
}

// principal_pattern (ADR 0079): CDK でスタックを作り直して末尾の乱数が変わったロールも、同じ項目で外れる。
// 照合 (0073 の 4 節・0076 の発行の突き合わせ) は実際の主体の ARN ごと。一致した pattern と、同じ pattern に一致した主体の数を data に出す。
func TestSecretAccessPrincipalPattern(t *testing.T) {
	const (
		set     = "/example-app/prod/secrets/S"
		stack   = "arn:aws:iam::123456789012:role/example-app-prod-AppTaskDefExecutionRole1A2B3C4D-"
		pat     = stack + "*"
		solo    = "arn:aws:iam::123456789012:role/example-batch-prod-JobExecutionRole5E6F7A8B-"
		soloPat = solo + "*"
	)
	var (
		before = stack + "AbcDef123Ghi" // 作り直しの前
		after  = stack + "XyZ789uvWxyz" // 作り直しの後 (同じ日に両方が読んだ)
		cross  = stack + "Cross0000000" // 同じ pattern の別のロールに発行されたキーで読む → 外さない (medium)
		alone  = solo + "Alone1234567"  // 1 つだけ。組の外の秘匿値も 1 つ読む → 初出の low
	)
	st := newStore(t)
	s := &secretSeed{st: st, t: t}
	coverage(t, st, 14)
	in := now.Add(-3 * time.Hour)
	for _, r := range []string{before, after, cross, alone} {
		s.serviceAssume(r, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	}
	s.issue(before, in.Add(-time.Second), testKey(1))
	s.startupRead(before, in, set, 0, 17, testKey(1))
	s.issue(after, in.Add(time.Hour-time.Second), testKey(2))
	s.startupRead(after, in.Add(time.Hour), set, 0, 17, testKey(2))
	s.startupRead(cross, in, set, 0, 3, testKey(2))
	s.issue(alone, in.Add(-time.Second), testKey(3))
	s.startupRead(alone, in, set, 0, 17, testKey(3))
	s.secret(alone, record.PrincipalAssumedRole, in, "prod/unlisted/db")

	al, err := allowlist.Parse([]byte(`
secrets_access:
  - principal_pattern: ` + pat + `
    secrets: ["/example-app/prod/secrets/*"]
    bulk: exempt
    note: 起動時に ECS が読む。作り直すと末尾の乱数が変わる
  - principal_pattern: ` + soloPat + `
    secrets: ["/example-app/prod/secrets/*"]
    bulk: exempt
    note: 起動時に ECS が読む
`))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := secretCheck().Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	m := obsByKey(obs)
	for _, r := range []string{before, after} {
		line, has := m[BulkExemptKeyPrefix+r]
		if !has || line.Severity != Info || line.Data["bulk_exempted"] != 17 || line.Data["principal"] != r ||
			fmt.Sprint(line.Data["secrets_access_principal_patterns"]) != "["+pat+"]" || line.Data["principal_pattern_principals"] != 3 {
			t.Errorf("%s: 作り直しの前後のどちらも外れて info: %+v", r, line)
		}
		if line.Fingerprint != fingerprint(Info, nil, "bulk-exempt") {
			t.Errorf("%s: Fingerprint に pattern を入れた: %s", r, line.Fingerprint)
		}
	}
	// 発行の突き合わせは実際の ARN で行う (同じ pattern に一致する別のロールの発行とは組まない)
	if o := m[BulkExemptUnmatchedKeyPrefix+cross]; o.Severity != Medium || fmt.Sprint(o.Data["bulk_exempt_unmatched"]) != "map[no_issuance:1]" ||
		fmt.Sprint(o.Data["secrets_access_principal_patterns"]) != "["+pat+"]" || o.Data["principal_pattern_principals"] != 3 {
		t.Errorf("cross: %+v", o)
	}
	if o := m[alone]; o.Severity != Low || o.Data["new_secret_count"] != 1 || fmt.Sprint(o.Data["secrets_access_principal_patterns"]) != "["+soloPat+"]" {
		t.Errorf("alone: 組の外の初出: %+v", o)
	} else if _, has := o.Data["principal_pattern_principals"]; has {
		t.Errorf("alone: 1 つだけなのに principal_pattern_principals を書いた: %+v", o.Data)
	}

	// principal (完全一致) の項目だけなら、data に pattern の項目を書かない
	al, err = allowlist.Parse([]byte("secrets_access:\n  - principal: " + before + "\n    secrets: [\"/example-app/prod/secrets/*\"]\n    bulk: exempt\n    note: n\n"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err = secretCheck().Evaluate(context.Background(), st, appWindow, al)
	if err != nil {
		t.Fatal(err)
	}
	m = obsByKey(obs)
	if line := m[BulkExemptKeyPrefix+before]; line.Severity != Info || line.Data["secrets_access_principal_patterns"] != nil || line.Data["principal_pattern_principals"] != nil {
		t.Errorf("principal の項目: %+v", line)
	}
	// 作り直しの後のロールは、完全一致の項目では外れない (今までどおり)
	if _, has := m[BulkExemptKeyPrefix+after]; has {
		t.Errorf("完全一致の項目が作り直しの後のロールに効いた")
	}
}
