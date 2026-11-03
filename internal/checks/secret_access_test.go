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
