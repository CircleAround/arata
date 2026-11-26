package checks

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// signin_session (ADR 0092 の 2 節)。窓は appWindow [10-20 09:00, 10-21 09:00)、評価する日は 10-20 と 10-21。
// 平常帯は 10-20 の前日から 14 日 (10-06〜10-19)。session_lookback は 3 日 (窓の始まり 10-20 09:00 から 10-17 09:00 まで遡る)。

const (
	siAlice  = "arn:aws:iam::123456789012:user/alice"
	siBob    = "arn:aws:iam::123456789012:user/bob"
	siOffice = "203.0.113.0/24"
	siHome   = "198.51.100.0/24"
)

func siSession(id string) string {
	return "arn:aws:signin:ap-northeast-1:123456789012:session/" + id + "-2222-3333-4444-555555555555"
}

func siUUID(id string) string { return id + "-2222-3333-4444-555555555555" }

type signinSeed struct {
	t  *testing.T
	st *store.Dir
	n  int
}

// token は CreateOAuth2Token を 1 件入れる。success は "true" / "false" / "" (入れない)。
func (s *signinSeed) token(at time.Time, principal, session, grant, ip, success, code string) {
	s.t.Helper()
	s.n++
	d := map[string]any{"grant_type": grant, "signin_client": "same-device", "cli_version": "aws-cli/2.31.4"}
	if session != "" {
		d["signin_session"] = session
	}
	if success != "" {
		d["signin_success"] = success == "true"
	}
	kind := record.PrincipalUser
	if strings.Contains(principal, ":role/") {
		kind = record.PrincipalAssumedRole
	}
	e := record.TrailEvent{EventID: fmt.Sprintf("si-%03d", s.n), Time: at, Name: "CreateOAuth2Token", EventSource: "signin.amazonaws.com", Source: "trail",
		Region: "ap-northeast-1", ReadOnly: true, PrincipalARN: principal, PrincipalKind: kind, IP: ip, ErrorCode: code, Data: d}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

func (s *signinSeed) metric(date, metric, principal, v string, n float64) {
	s.t.Helper()
	if err := s.st.UpsertMetric(context.Background(), record.Metric{Date: date, Source: "trail", From: record.KindTrailEvent, Metric: metric,
		Key: record.ActivityKey(principal, v), Value: n}); err != nil {
		s.t.Fatal(err)
	}
}

// baseline は 10-19 から遡って days 日、principal が prefixes から使われ、セッションが sessions 個あったことを入れる。
func (s *signinSeed) baseline(principal string, days, sessions int, prefixes ...string) {
	for i := 0; i < days; i++ {
		d := time.Date(2026, 10, 19-i, 0, 0, 0, 0, time.UTC).Format(record.DateLayout)
		for _, p := range prefixes {
			s.metric(d, record.MetricPrincipalSource, principal, p, 10)
		}
		for j := 0; j < sessions; j++ {
			s.metric(d, record.MetricPrincipalSigninSession, principal, fmt.Sprintf("%08x-0000-0000-0000-000000000000", j), 5)
		}
	}
}

func signinCheck(lookback string) SigninSession {
	c := config.DefaultChecks().SigninSession
	c.SessionLookback = lookback
	return SigninSession{Config: c}
}

func at(day, hour int) time.Time { return time.Date(2026, 10, day, hour, 0, 0, 0, time.UTC) }

func seedSigninScenario(t *testing.T, collected int) *store.Dir {
	st := newStore(t)
	s := &signinSeed{t: t, st: st}
	s.baseline(siAlice, 14, 2, siOffice, siHome)
	s.baseline(siBob, 14, 3, siOffice)
	coverage(t, st, collected)

	// A: 窓の中でログインし、同じ /24 の出し直しのあと、知らない /24 (平常帯の外) から出し直した → high
	s.token(at(20, 10), siAlice, siSession("aaaaaaaa"), record.GrantAuthorizationCode, "203.0.113.10", "true", "")
	s.token(at(20, 12), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, "203.0.113.11", "true", "")
	s.token(at(20, 14), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, "192.0.2.5", "true", "")
	s.token(at(20, 15), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, "192.0.2.6", "true", "")
	// B: lookback の中の過去の記録 (会社) のあと、主体の平常帯にある /24 (自宅) から → low
	s.token(at(19, 8), siAlice, siSession("bbbbbbbb"), record.GrantAuthorizationCode, "203.0.113.10", "true", "")
	s.token(at(20, 11), siAlice, siSession("bbbbbbbb"), record.GrantRefreshToken, "198.51.100.7", "true", "")
	// C: 最初の記録が lookback の外で、窓の最初の出し直しが平常帯の外 → high (まだ見ていない /24 の判定はしない)
	s.token(at(15, 8), siAlice, siSession("cccccccc"), record.GrantAuthorizationCode, "192.0.2.77", "true", "") // lookback の外 (読まない)
	s.token(at(20, 13), siAlice, siSession("cccccccc"), record.GrantRefreshToken, "192.0.2.9", "true", "")
	// D: 最初の記録が lookback の外で、窓の最初の出し直しが平常帯の中 → 報告しない。続く出し直しが同じ /24 なら報告しない
	s.token(at(20, 13), siAlice, siSession("dddddddd"), record.GrantRefreshToken, "203.0.113.12", "true", "")
	s.token(at(20, 16), siAlice, siSession("dddddddd"), record.GrantRefreshToken, "203.0.113.13", "true", "")
	// E: 最初のログインが新しい /24 から来ても、このチェックでは報告しない (principal_new_source が見る)
	s.token(at(20, 17), siAlice, siSession("eeeeeeee"), record.GrantAuthorizationCode, "192.0.2.200", "true", "")
	// F: 失敗した出し直しは送信元の移動に数えない (失敗の形で数える)。送信元が IP でない記録は判定しない
	s.token(at(19, 9), siBob, siSession("ffffffff"), record.GrantAuthorizationCode, "203.0.113.20", "true", "")
	s.token(at(20, 18), siBob, siSession("ffffffff"), record.GrantRefreshToken, "192.0.2.50", "false", "")
	s.token(at(20, 19), siBob, siSession("ffffffff"), record.GrantRefreshToken, "", "true", "")
	// 失敗: bob は 10-20 に 3 件 (success false か errorCode。セッションの無い記録も数える) → low。alice は 2 件 → 報告しない
	s.token(at(20, 20), siBob, "", record.GrantRefreshToken, "192.0.2.51", "", "AccessDeniedException")
	s.token(at(20, 21), siBob, siSession("ffffffff"), record.GrantRefreshToken, "192.0.2.52", "false", "")
	s.token(at(20, 22), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, "192.0.2.53", "false", "")
	s.token(at(20, 23), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, "192.0.2.54", "false", "")
	// セッションの数: alice は 10-20 に 4 つ (平常帯の最大 2 より多く、min_sessions 3 以上) → low。bob は 3 つ (平常帯の最大 3) → 報告しない
	for _, id := range []string{"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"} {
		s.metric("2026-10-20", record.MetricPrincipalSigninSession, siAlice, siUUID(id), 3)
	}
	for _, id := range []string{"ffffffff", "00000000", "11111111"} {
		s.metric("2026-10-20", record.MetricPrincipalSigninSession, siBob, siUUID(id), 3)
	}
	return st
}

func TestSigninSession(t *testing.T) {
	st := seedSigninScenario(t, 14)
	obs, err := signinCheck("3d").Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	by := obsByKey(obs)
	keyA := siAlice + "|" + siUUID("aaaaaaaa") + "|" + signinFormNewPrefix
	keyB := siAlice + "|" + siUUID("bbbbbbbb") + "|" + signinFormNewPrefix
	keyC := siAlice + "|" + siUUID("cccccccc") + "|" + signinFormNewPrefix
	keyFail := siBob + "|2026-10-20|" + signinFormFailures
	keySess := siAlice + "|2026-10-20|" + signinFormSessions
	want := map[string]Severity{keyA: High, keyB: Low, keyC: High, keyFail: Low, keySess: Low}
	got := map[string]Severity{}
	for k, o := range by {
		got[k] = o.Severity
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observations:\n got  %v\n want %v", got, want)
	}

	a := by[keyA].Data
	for k, v := range map[string]any{
		"principal": siAlice, "signin_session": siSession("aaaaaaaa"), "signin_client": "same-device", "in_principal_baseline": false,
		"refreshes": 3, "first_seen": at(20, 10).Format(time.RFC3339), "form": signinFormNewPrefix, "baseline_short": false, "first_outside_lookback": false,
	} {
		if a[k] != v {
			t.Errorf("A data.%s = %#v, want %#v", k, a[k], v)
		}
	}
	if !reflect.DeepEqual(a["new_prefixes"], []string{"192.0.2.0/24"}) || !reflect.DeepEqual(a["known_prefixes"], []string{siOffice}) {
		t.Errorf("A prefixes: new %v known %v", a["new_prefixes"], a["known_prefixes"])
	}
	if !reflect.DeepEqual(a["cli_versions"], []string{"aws-cli/2.31.4"}) {
		t.Errorf("A cli_versions: %v", a["cli_versions"])
	}
	if !strings.Contains(by[keyA].Summary, "192.0.2.0/24") {
		t.Errorf("A summary: %q", by[keyA].Summary)
	}
	b := by[keyB].Data
	if b["in_principal_baseline"] != true || !reflect.DeepEqual(b["new_prefixes"], []string{siHome}) || !reflect.DeepEqual(b["known_prefixes"], []string{siOffice}) ||
		b["first_seen"] != at(19, 8).Format(time.RFC3339) || b["refreshes"] != 1 {
		t.Errorf("B data: %v", b)
	}
	if c := by[keyC].Data; c["first_outside_lookback"] != true || c["known_prefixes"] != nil && len(c["known_prefixes"].([]string)) > 0 {
		t.Errorf("C data: %v", c)
	}
	if f := by[keyFail].Data; f["failures"] != 3 || f["date"] != "2026-10-20" || !reflect.DeepEqual(f["error_codes"], []string{"AccessDeniedException"}) {
		t.Errorf("failures data: %v", f)
	}
	if s := by[keySess].Data; s["sessions"] != 4 || s["baseline_max"] != 2 || s["date"] != "2026-10-20" {
		t.Errorf("sessions data: %v", s)
	}
}

// 同じセッションに新しい /24 が増えれば Fingerprint が変わる (changed で出直す)
func TestSigninSessionFingerprintGrows(t *testing.T) {
	st := seedSigninScenario(t, 14)
	c := signinCheck("3d")
	key := siAlice + "|" + siUUID("bbbbbbbb") + "|" + signinFormNewPrefix
	before, err := c.Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	s := &signinSeed{t: t, st: st, n: 100}
	s.token(at(21, 1), siAlice, siSession("bbbbbbbb"), record.GrantRefreshToken, "192.0.2.99", "true", "")
	after, err := c.Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	b, a := obsByKey(before)[key], obsByKey(after)[key]
	if b.Fingerprint == a.Fingerprint || a.Severity != High {
		t.Fatalf("fingerprint %q → %q, severity %s", b.Fingerprint, a.Fingerprint, a.Severity)
	}
}

// 収集し終えた過去日が min_baseline_days 未満の間は、high を medium に下げ、baseline_short を出す。セッションの数は判定しない
func TestSigninSessionShortCollected(t *testing.T) {
	st := newStore(t)
	s := &signinSeed{t: t, st: st}
	coverage(t, st, 3) // 10-17〜10-19 だけ収集した。metric は 10-19 の 1 日だけ
	s.metric("2026-10-19", record.MetricPrincipalSource, siAlice, siOffice, 10)
	s.metric("2026-10-19", record.MetricPrincipalSigninSession, siAlice, siUUID("00000000"), 1)
	s.token(at(19, 8), siAlice, siSession("aaaaaaaa"), record.GrantAuthorizationCode, "203.0.113.10", "true", "")
	s.token(at(20, 11), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, "192.0.2.7", "true", "")
	for _, id := range []string{"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"} {
		s.metric("2026-10-20", record.MetricPrincipalSigninSession, siAlice, siUUID(id), 3)
	}
	obs, err := signinCheck("3d").Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	by := obsByKey(obs)
	key := siAlice + "|" + siUUID("aaaaaaaa") + "|" + signinFormNewPrefix
	if len(by) != 1 || by[key].Severity != Medium || by[key].Data["baseline_short"] != true || by[key].Data["baseline_days_collected"] != 3 {
		t.Fatalf("got %v", by)
	}
}

// session_lookback を書かなければ skip する (既定を持たない。ADR 0014)。理由に何を書けば動くかを出す
func TestSigninSessionDisabledWithoutLookback(t *testing.T) {
	if got := signinCheck("").Disabled(); !strings.Contains(got, "session_lookback") {
		t.Fatalf("Disabled() = %q", got)
	}
	if got := signinCheck("3d").Disabled(); got != "" {
		t.Fatalf("Disabled() = %q", got)
	}
}

// ログ由来の値はストアから読み戻した後も形を確かめる: 形に合わない signin_session の記録は判定しない
func TestSigninSessionIgnoresMalformedSession(t *testing.T) {
	st := newStore(t)
	s := &signinSeed{t: t, st: st}
	coverage(t, st, 14)
	s.baseline(siAlice, 14, 1, siOffice)
	s.token(at(20, 11), siAlice, "arn:aws:signin:ap-northeast-1:123456789012:session/<!here>", record.GrantRefreshToken, "192.0.2.7", "true", "")
	s.token(at(20, 12), "arn:aws:iam::123456789012:role/Admin", siSession("aaaaaaaa"), record.GrantRefreshToken, "192.0.2.7", "true", "")
	obs, err := signinCheck("3d").Evaluate(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 0 {
		t.Fatalf("got %v", obsByKey(obs))
	}
}

// FuzzSigninRecordOf はストアから読み戻した CreateOAuth2Token の値 (元はログ由来) の読み方 (ADR 0037・0041)。
// 規則: 対象は signin の CreateOAuth2Token の IAM ユーザーだけ。セッションは形の合う ARN か空で、UUID はその ARN の末尾。
// grant_type は決まった値。送信元は /24・/48 か空。失敗は signin_success: false か errorCode のときだけ
func FuzzSigninRecordOf(f *testing.F) {
	f.Add(siSession("aaaaaaaa"), "refresh_token", "203.0.113.10", "", true, true)
	f.Add("arn:aws:signin:x:123456789012:session/<!here>", "x", "ec2.amazonaws.com", "AccessDenied", false, true)
	f.Add(siSession("aaaaaaaa")+"\n", "", "2001:db8::1", "", true, false)
	f.Fuzz(func(t *testing.T, session, grant, ip, code string, success, hasSuccess bool) {
		d := map[string]any{"signin_session": session, "grant_type": grant}
		if hasSuccess {
			d["signin_success"] = success
		}
		for _, kind := range []record.PrincipalKind{record.PrincipalUser, record.PrincipalAssumedRole} {
			e := record.TrailEvent{EventID: "x", Name: signinEventName, EventSource: signinEventSource, PrincipalARN: siAlice, PrincipalKind: kind, IP: ip, ErrorCode: code, Data: d}
			r, ok := signinRecordOf(e)
			if ok != (kind == record.PrincipalUser) {
				t.Fatalf("kind %s: ok %v", kind, ok)
			}
			if !ok {
				continue
			}
			if r.session != "" && (!record.ValidSigninSession(r.session) || !strings.HasSuffix(r.session, "/"+r.uuid) || len(r.uuid) != 36) || r.session == "" && r.uuid != "" {
				t.Fatalf("session %q uuid %q", r.session, r.uuid)
			}
			switch r.grant {
			case record.GrantAuthorizationCode, record.GrantRefreshToken, record.SigninOther:
			default:
				t.Fatalf("grant %q", r.grant)
			}
			if p, ok := record.SourcePrefix(ip); r.prefix != "" && (!ok || p != r.prefix) || ok && r.prefix == "" {
				t.Fatalf("prefix %q for %q", r.prefix, ip)
			}
			if r.failed != (code != "" || hasSuccess && !success) {
				t.Fatalf("failed %v (code %q success %v/%v)", r.failed, code, success, hasSuccess)
			}
		}
		e := record.TrailEvent{Name: signinEventName, EventSource: "example.amazonaws.com", PrincipalARN: siAlice, PrincipalKind: record.PrincipalUser, Data: d}
		if _, ok := signinRecordOf(e); ok {
			t.Fatal("other event sources must not be read")
		}
	})
}

// そのセッションの最初の記録 (authorization_code) が窓の中にあり、続く refresh_token が別の /24 から来た形 (開発リードの指摘)。
// lookback の外の扱い (first_outside_lookback) にはならず、まだ見ていない /24 として new_prefix になる。平常帯の内なら low、外なら high
func TestSigninSessionLoginThenRefreshInWindow(t *testing.T) {
	for _, tc := range []struct {
		name, ip string
		sev      Severity
		inBase   bool
	}{
		{"平常帯の内の /24", "198.51.100.7", Low, true},
		{"平常帯の外の /24", "192.0.2.7", High, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			s := &signinSeed{t: t, st: st}
			coverage(t, st, 14)
			s.baseline(siAlice, 14, 1, siOffice, siHome)
			s.token(at(20, 10), siAlice, siSession("aaaaaaaa"), record.GrantAuthorizationCode, "203.0.113.10", "true", "")
			s.token(at(20, 11), siAlice, siSession("aaaaaaaa"), record.GrantRefreshToken, tc.ip, "true", "")
			obs, err := signinCheck("3d").Evaluate(context.Background(), st, appWindow, &allowlist.List{})
			if err != nil {
				t.Fatal(err)
			}
			by := obsByKey(obs)
			key := siAlice + "|" + siUUID("aaaaaaaa") + "|" + signinFormNewPrefix
			o, ok := by[key]
			if !ok || len(by) != 1 {
				t.Fatalf("got %v", by)
			}
			p, _ := record.SourcePrefix(tc.ip)
			if o.Severity != tc.sev || o.Data["first_outside_lookback"] != false || o.Data["in_principal_baseline"] != tc.inBase ||
				!reflect.DeepEqual(o.Data["new_prefixes"], []string{p}) || !reflect.DeepEqual(o.Data["known_prefixes"], []string{siOffice}) ||
				o.Data["refreshes"] != 1 || o.Data["first_seen"] != at(20, 10).Format(time.RFC3339) {
				t.Fatalf("%s: %+v", o.Severity, o.Data)
			}
		})
	}
}
