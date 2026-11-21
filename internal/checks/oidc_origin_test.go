package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ADR 0081 のテストの値 (架空)。
const (
	ghaRole    = "arn:aws:iam::123456789012:role/gha-deploy"
	cdkDeploy  = "arn:aws:iam::123456789012:role/cdk-deploy-role"
	cdkPublish = "arn:aws:iam::123456789012:role/cdk-file-publishing-role"
	ssoRole    = "arn:aws:iam::123456789012:role/AWSReservedSSO_Admin_0123456789abcdef"
	taskRole   = "arn:aws:iam::123456789012:role/example-app-task"
)

var originWindow = collect.Window{From: now.Add(-time.Hour), To: now}

type originSeed struct {
	t  *testing.T
	st *store.Dir
	n  int
}

func (s *originSeed) put(e record.TrailEvent) {
	s.t.Helper()
	s.n++
	e.EventID, e.Source = fmt.Sprintf("o%05d", s.n), "trail"
	if e.EventSource == "" {
		e.EventSource = "sts.amazonaws.com"
	}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

// webIdentity は GitHub の OIDC の 1 段目 (key の認証情報を発行した) を入れる。
func (s *originSeed) webIdentity(at time.Time, key, role, env, runID string) {
	d := map[string]any{"role_arn": role, "issued_key_hash": keyHash(s.t, key), "oidc_provider": record.GitHubOIDCProvider, "oidc_sub_form": record.OIDCSubGitHub,
		"oidc_repo": "example-org/example-repo", "oidc_sub_kind": record.OIDCKindEnvironment, "oidc_environment": env}
	if runID != "" {
		d["gha_run_id"] = runID
	}
	s.put(record.TrailEvent{Time: at, Name: OIDCAssumeEvent, PrincipalKind: record.PrincipalAssumedRole, ReadOnly: true, Data: d})
}

// assume は caller のセッション (callerKey) が role を引き受け、issued の認証情報を発行した記録を入れる (役割の連鎖)。callerKey が空なら印なし。
func (s *originSeed) assume(at time.Time, caller, callerKey, role, issued string) {
	d := map[string]any{"role_arn": role, "recipient_account": ownAcct}
	if callerKey != "" {
		d["session_key_hash"] = keyHash(s.t, callerKey)
	}
	if issued != "" {
		d["issued_key_hash"] = keyHash(s.t, issued)
	}
	s.put(record.TrailEvent{Time: at, Name: "AssumeRole", PrincipalARN: caller, PrincipalKind: record.PrincipalAssumedRole, IP: "203.0.113.10", ReadOnly: true, Data: d})
}

// iam は caller のセッション (key) の IAM の操作 (CreateAccessKey) を入れる。
func (s *originSeed) iam(at time.Time, caller, key, user string) {
	d := map[string]any{"user_name": user}
	if key != "" {
		d["session_key_hash"] = keyHash(s.t, key)
	}
	s.put(record.TrailEvent{Time: at, Name: "CreateAccessKey", EventSource: "iam.amazonaws.com", PrincipalARN: caller, PrincipalKind: record.PrincipalAssumedRole, IP: "203.0.113.10", Data: d})
}

// GitHub の OIDC → deploy-role (2 段目) → その先 (3 段目) と、そのセッションの IAM の操作に、1 段目の手がかりが付く。
// 人の SSO のセッション・ECS のタスクのロールの finding には何も付かない。一部だけたどれた・入り口のロールなのにたどれないときは理由を出す。
func TestOIDCOriginsOnChainedFindings(t *testing.T) {
	st := newStore(t)
	s := &originSeed{t: t, st: st}
	first := now.Add(-2 * time.Hour) // 1 段目は窓の前 (前の時間の run)
	s.webIdentity(first, testKey(1), ghaRole, "production", "1234567")
	s.assume(now.Add(-50*time.Minute), ghaRole, testKey(1), cdkDeploy, testKey(2))    // 2 段目 (chain_depth 1)
	s.assume(now.Add(-40*time.Minute), ghaRole, testKey(80), cdkDeploy, testKey(3))   // 同じ Key、1 段目の無いキー (外で使われた手がかり)
	s.assume(now.Add(-30*time.Minute), cdkDeploy, testKey(2), cdkPublish, testKey(4)) // 3 段目 (chain_depth 2)
	s.iam(now.Add(-20*time.Minute), cdkDeploy, testKey(2), "ci-user")                 // 2 段目のセッションの IAM の操作 (chain_depth 2)
	s.assume(now.Add(-10*time.Minute), ghaRole, testKey(81), ownRole2, "")            // 入り口のロールなのに 1 段目が無い
	s.iam(now.Add(-20*time.Minute), ssoRole, testKey(90), "ops-user")                 // 人の SSO のセッション (発行は残さない)
	// ECS のタスクのロールのセッションからの引き受け (鎖の根が OIDC でない)
	s.put(record.TrailEvent{Time: now.Add(-55 * time.Minute), Name: "AssumeRole", PrincipalARN: ecsTasksService, PrincipalKind: record.PrincipalService, ReadOnly: true,
		Data: map[string]any{"role_arn": taskRole, "issued_key_hash": keyHash(t, testKey(5))}})
	s.assume(now.Add(-15*time.Minute), taskRole, testKey(5), cdkPublish, testKey(6))

	obs, err := UnknownAssumeRole{}.Evaluate(context.Background(), st, originWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	m := obsByKey(obs)
	want1 := `[{"assumed_at":"2026-10-21T07:00:00Z","chain_depth":1,"environment":"production","provider":"token.actions.githubusercontent.com","repo":"example-org/example-repo","role_arn":"arn:aws:iam::123456789012:role/gha-deploy","run_id":"1234567","sub_kind":"environment"}]`
	o := m[ghaRole+"->"+cdkDeploy]
	if got := jsonOf(t, o.Data["oidc_origins"]); got != want1 || o.Data["oidc_origins_total"] != 1 {
		t.Errorf("2 段目: %s (%+v)", got, o.Data)
	}
	if fmt.Sprint(o.Data["oidc_origin_unmatched"]) != "map[no_issuance:1]" {
		t.Errorf("一部だけたどれた: %+v", o.Data["oidc_origin_unmatched"])
	}
	o = m[cdkDeploy+"->"+cdkPublish]
	if got := jsonOf(t, o.Data["oidc_origins"]); !strings.Contains(got, `"chain_depth":2`) || o.Data["oidc_origin_unmatched"] != nil {
		t.Errorf("3 段目: %s (%+v)", got, o.Data)
	}
	o = m[ghaRole+"->"+ownRole2]
	if o.Data["oidc_origins"] != nil || fmt.Sprint(o.Data["oidc_origin_unmatched"]) != "map[no_issuance:1]" {
		t.Errorf("入り口のロールなのにたどれない: %+v", o.Data)
	}
	o = m[taskRole+"->"+cdkPublish]
	if o.Data["oidc_origins"] != nil || o.Data["oidc_origin_unmatched"] != nil {
		t.Errorf("ECS のタスクのロール (OIDC に関わらない) には付けない: %+v", o.Data)
	}

	obs, err = IAMChanges{}.Evaluate(context.Background(), st, originWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		switch o.Data["principal"] {
		case cdkDeploy:
			if got := jsonOf(t, o.Data["oidc_origins"]); !strings.Contains(got, `"chain_depth":2`) || !strings.Contains(got, `"run_id":"1234567"`) {
				t.Errorf("iam_changes (2 段目のセッション): %s", got)
			}
		case ssoRole:
			if o.Data["oidc_origins"] != nil || o.Data["oidc_origin_unmatched"] != nil {
				t.Errorf("人の SSO のセッションには付けない: %+v", o.Data)
			}
		default:
			t.Errorf("想定外の finding: %+v", o)
		}
	}
}

// 付けた値は判定に使わない: 1 段目の有無・値で、Key・Fingerprint・重大度・見出しが変わらない (ADR 0081 の 3 節)。
func TestOIDCOriginsDoNotChangeJudgement(t *testing.T) {
	run := func(withFirst bool, env string) map[string]Observation {
		st := newStore(t)
		s := &originSeed{t: t, st: st}
		if withFirst {
			s.webIdentity(now.Add(-2*time.Hour), testKey(1), ghaRole, env, "1")
		}
		s.assume(now.Add(-50*time.Minute), ghaRole, testKey(1), cdkDeploy, testKey(2))
		s.iam(now.Add(-20*time.Minute), cdkDeploy, testKey(2), "ci-user")
		out := map[string]Observation{}
		for _, c := range []Check{UnknownAssumeRole{}, IAMChanges{}} {
			obs, err := c.Evaluate(context.Background(), st, originWindow, &allowlist.List{})
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range obs {
				out[c.Name()+"|"+o.Key] = o
			}
		}
		return out
	}
	base := run(false, "")
	for _, other := range []map[string]Observation{run(true, "production"), run(true, "staging")} {
		if len(other) != len(base) {
			t.Fatalf("finding の数が変わった: %d と %d", len(other), len(base))
		}
		for k, b := range base {
			o := other[k]
			if o.Fingerprint != b.Fingerprint || o.Severity != b.Severity || o.Summary != b.Summary {
				t.Errorf("%s: 判定が変わった: %+v / %+v", k, o, b)
			}
			if o.Data["oidc_origins"] == nil {
				t.Errorf("%s: 手がかりが付かない", k)
			}
		}
	}
}

// たどる関数の規則: 寿命と ±5 秒の内の発行だけ、最大 4 段まで。
func TestOriginTrace(t *testing.T) {
	h := func(n int) string { return keyHash(t, testKey(n)) }
	at := now
	web := func(key int, ago time.Duration) record.TrailEvent {
		return record.TrailEvent{Time: at.Add(-ago), Name: OIDCAssumeEvent, EventSource: "sts.amazonaws.com", Data: map[string]any{"issued_key_hash": h(key), "role_arn": ghaRole}}
	}
	chain := func(caller, issued int, ago time.Duration) record.TrailEvent {
		return record.TrailEvent{Time: at.Add(-ago), Name: "AssumeRole", EventSource: "sts.amazonaws.com", PrincipalARN: cdkDeploy, PrincipalKind: record.PrincipalAssumedRole,
			Data: map[string]any{"issued_key_hash": h(issued), "session_key_hash": h(caller)}}
	}
	cases := []struct {
		name   string
		evs    []record.TrailEvent
		use    int
		depth  int
		reason string
	}{
		{"1 段目のセッションの記録", []record.TrailEvent{web(1, 11*time.Hour)}, 1, 1, ""},
		{"1 段目の寿命 (12 時間) を過ぎた", []record.TrailEvent{web(1, 12*time.Hour+6*time.Second)}, 1, 0, originNoIssuance},
		{"発行が使用より 5 秒を超えて後", []record.TrailEvent{web(1, -6*time.Second)}, 1, 0, originNoIssuance},
		{"記録の時刻のずれ (発行が 3 秒後)", []record.TrailEvent{web(1, -3*time.Second)}, 1, 1, ""},
		{"連鎖の寿命 (1 時間) を過ぎた", []record.TrailEvent{web(1, 2*time.Hour), chain(1, 2, time.Hour+6*time.Second)}, 2, 0, originNoIssuance},
		{"3 段目", []record.TrailEvent{web(1, 90*time.Minute), chain(1, 2, 50*time.Minute), chain(2, 3, 20*time.Minute)}, 3, 3, ""},
		{"4 段目まで", []record.TrailEvent{web(1, 3*time.Hour), chain(1, 2, 150*time.Minute), chain(2, 3, 100*time.Minute), chain(3, 4, 50*time.Minute)}, 4, 4, ""},
		{"5 段目は too_deep", []record.TrailEvent{web(1, 4*time.Hour), chain(1, 2, 200*time.Minute), chain(2, 3, 150*time.Minute), chain(3, 4, 100*time.Minute), chain(4, 5, 50*time.Minute)}, 5, 0, originTooDeep},
		{"輪 (同じキー) は too_deep", []record.TrailEvent{chain(6, 6, time.Second)}, 6, 0, originTooDeep},
		{"失敗した発行は使わない", []record.TrailEvent{func() record.TrailEvent { e := web(1, time.Hour); e.ErrorCode = "AccessDenied"; return e }()}, 1, 0, originNoIssuance},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := newOriginIndex(c.evs)
			_, depth, reason, _ := ix.trace(originUse{hash: h(c.use), at: at, principal: ghaRole})
			if depth != c.depth || reason != c.reason {
				t.Fatalf("depth=%d reason=%q, want %d %q", depth, reason, c.depth, c.reason)
			}
		})
	}
	if _, _, reason, _ := newOriginIndex(nil).trace(originUse{at: at}); reason != originNoKey {
		t.Fatalf("キーの無い記録: %q", reason)
	}
}

// 1 段目の値は、形を確かめたものだけを付ける (ストアの値も信用しない)。
func TestOriginElementValidates(t *testing.T) {
	c := issuedCred{at: now, data: map[string]any{"role_arn": "arn:aws:iam::123456789012:role/x\n<!here>", "oidc_provider": "evil\n.example", "oidc_sub_form": record.OIDCSubGitHub,
		"oidc_repo": "<!here>/x", "oidc_sub_kind": record.OIDCKindRef, "oidc_ref": "refs/heads/main", "gha_run_id": "12a"}}
	el := originElement(c, 1)
	for _, k := range []string{"role_arn", "provider", "repo", "sub_kind", "ref", "run_id"} {
		if _, has := el[k]; has {
			t.Errorf("形の合わない %s を付けた: %+v", k, el)
		}
	}
}

// ファズ (ADR 0041): 任意の発行と記録の組でも、必ず止まり、段数は 1〜4、付くのは寿命の内の AssumeRoleWithWebIdentity の値だけ。
func FuzzOriginTrace(f *testing.F) {
	f.Add([]byte{0, 1, 2, 10, 1, 2, 3, 20, 2, 3, 4, 30}, uint8(4), int64(3600))
	f.Add([]byte{1, 1, 1, 0}, uint8(1), int64(0))
	f.Add([]byte{0, 0, 9, 255, 1, 9, 9, 1}, uint8(9), int64(-100))
	f.Fuzz(func(t *testing.T, spec []byte, use uint8, ago int64) {
		hash := func(b byte) string { return fmt.Sprintf("%032x", b%8) }
		var evs []record.TrailEvent
		for i := 0; i+3 < len(spec) && len(evs) < 32; i += 4 {
			e := record.TrailEvent{EventSource: "sts.amazonaws.com", Time: now.Add(-time.Duration(spec[i+3]) * 4 * time.Minute), Data: map[string]any{"issued_key_hash": hash(spec[i+2])}}
			switch spec[i] % 4 {
			case 0:
				e.Name = OIDCAssumeEvent
				e.Data["role_arn"] = ghaRole
				e.Data["gha_run_id"] = "1"
			case 1:
				e.Name, e.PrincipalARN, e.PrincipalKind = "AssumeRole", cdkDeploy, record.PrincipalAssumedRole
				e.Data["session_key_hash"] = hash(spec[i+1])
			case 2:
				e.Name, e.PrincipalARN, e.PrincipalKind = "AssumeRole", ecsTasksService, record.PrincipalService
			default:
				e.Name, e.ErrorCode = "AssumeRole", "AccessDenied"
				e.Data["session_key_hash"] = hash(spec[i+1])
			}
			evs = append(evs, e)
		}
		ix := newOriginIndex(evs)
		u := originUse{hash: hash(use), at: now.Add(-time.Duration(ago%86400) * time.Second), principal: ghaRole}
		c, depth, reason, roles := ix.trace(u)
		if len(roles) == 0 || len(roles) > maxOriginChainDepth+1 {
			t.Fatalf("鎖の上のロールの数: %d", len(roles))
		}
		if reason != "" {
			if depth != 0 || c.kind != 0 {
				t.Fatalf("たどれないのに 1 段目を返した: %+v %d %q", c, depth, reason)
			}
			return
		}
		if depth < 1 || depth > maxOriginChainDepth || c.kind != issueWebIdentity {
			t.Fatalf("段数・種類: %d %v", depth, c.kind)
		}
		if depth == 1 && (u.at.Sub(c.at) < -originSkew || u.at.Sub(c.at) > webIdentityLifetime+originSkew) {
			t.Fatalf("寿命の外の 1 段目: %v %v", u.at, c.at)
		}
		el := originElement(c, depth)
		if el["chain_depth"] != depth || el["role_arn"] != ghaRole {
			t.Fatalf("要素: %+v", el)
		}
		// 1 段目までの時刻の差は、寿命の和を超えない
		if u.at.Sub(c.at) > webIdentityLifetime+chainedLifetime*time.Duration(depth-1)+originSkew*time.Duration(depth) {
			t.Fatalf("時刻の差が寿命の和を超えた: %v", u.at.Sub(c.at))
		}
	})
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// defense_evasion・public_exposure にも、2 段目のセッションの操作なら 1 段目の手がかりが付く (ADR 0081 の 5 節)。
func TestOIDCOriginsOnDefenseAndExposure(t *testing.T) {
	st := newStore(t)
	s := &originSeed{t: t, st: st}
	s.webIdentity(now.Add(-2*time.Hour), testKey(1), ghaRole, "production", "1234567")
	s.assume(now.Add(-50*time.Minute), ghaRole, testKey(1), cdkDeploy, testKey(2))
	key := keyHash(t, testKey(2))
	s.put(record.TrailEvent{Time: now.Add(-20 * time.Minute), Name: "StopLogging", EventSource: "cloudtrail.amazonaws.com", PrincipalARN: cdkDeploy, PrincipalKind: record.PrincipalAssumedRole,
		IP: "203.0.113.10", Data: map[string]any{"name": "main", "session_key_hash": key}})
	s.put(record.TrailEvent{Time: now.Add(-20 * time.Minute), Name: "PutBucketAcl", EventSource: "s3.amazonaws.com", PrincipalARN: cdkDeploy, PrincipalKind: record.PrincipalAssumedRole,
		IP: "203.0.113.10", Data: map[string]any{"bucket": "b3", "acl_public_grants": []any{"AllUsers:READ"}, "session_key_hash": key}})
	for _, c := range []Check{defenseConfig(), PublicExposure{Config: config.DefaultChecks().PublicExposure}} {
		obs, err := c.Evaluate(context.Background(), st, originWindow, &allowlist.List{})
		if err != nil {
			t.Fatal(err)
		}
		if len(obs) != 1 {
			t.Fatalf("%s: %+v", c.Name(), obs)
		}
		if got := jsonOf(t, obs[0].Data["oidc_origins"]); !strings.Contains(got, `"chain_depth":2`) || !strings.Contains(got, `"environment":"production"`) {
			t.Errorf("%s: %s", c.Name(), got)
		}
	}
}
