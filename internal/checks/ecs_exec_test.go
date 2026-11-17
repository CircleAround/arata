package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ECS Exec (ADR 0072) のテストの値。架空の値。
const (
	execAlice   = "arn:aws:iam::123456789012:user/alice"
	execUnknown = "arn:aws:iam::123456789012:user/example-unknown"
	execRoot    = "arn:aws:iam::123456789012:root"
)

type execSeed struct {
	t  *testing.T
	st *store.Dir
}

// principal は主体をストアに状態付きで置く (init のベースライン収集・承認・未知)。
func (s execSeed) principal(arn string, kind record.PrincipalKind, status string) {
	s.t.Helper()
	if err := s.st.UpsertPrincipalSeen(context.Background(), record.PrincipalSeen{ARN: arn, Kind: kind, FirstTime: now.Add(-48 * time.Hour), Time: now.Add(-time.Hour), Count: 1}, status); err != nil {
		s.t.Fatal(err)
	}
}

// exec は ExecuteCommand の記録を 1 件置く。data は collector が取り出す値 (ecs_*)。
func (s execSeed) exec(id string, at time.Time, arn string, kind record.PrincipalKind, code string, data map[string]any) {
	s.t.Helper()
	e := record.TrailEvent{EventID: id, Time: at, Source: "trail", Name: "ExecuteCommand", EventSource: "ecs.amazonaws.com", Region: "ap-northeast-1",
		PrincipalARN: arn, PrincipalKind: kind, IP: "203.0.113.1", ErrorCode: code, Data: data}
	if err := s.st.InsertEvent(context.Background(), e); err != nil {
		s.t.Fatal(err)
	}
}

func execData(task, cmd, session string) map[string]any {
	d := map[string]any{"ecs_cluster": "prod-cluster", "ecs_container": "app", "ecs_interactive": true}
	if task != "" {
		d["ecs_task"] = task
	}
	if cmd != "" {
		d["ecs_command"] = cmd
	}
	if session != "" {
		d["ecs_session_id"] = session
	}
	return d
}

func execEval(t *testing.T, st *store.Dir, al *allowlist.List, w collect.Window) map[string]Observation {
	t.Helper()
	obs, err := ECSExec{}.Evaluate(context.Background(), st, w, al)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Observation{}
	for _, o := range obs {
		if o.Check != "ecs_exec" || o.Summary == "" || o.Fingerprint == "" {
			t.Fatalf("incomplete: %+v", o)
		}
		out[o.Key] = o
	}
	return out
}

var execWindow = collect.Window{From: now.Add(-24 * time.Hour), To: now}

func emptyAllowlist(t *testing.T) *allowlist.List {
	al, err := allowlist.Parse([]byte("principals: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	return al
}

const execKeyAlice = execAlice + "|ap-northeast-1/prod-cluster|app|2026-10-21"

func TestECSExecSeverity(t *testing.T) {
	cases := []struct {
		name     string
		arn      string
		kind     record.PrincipalKind
		status   string // ストアの主体の状態 (空なら置かない)
		yaml     string
		code     string
		want     Severity
		known    bool
		denied   bool
		titleHas string
	}{
		{name: "baseline principal", arn: execAlice, kind: record.PrincipalUser, status: store.PrincipalBaseline, want: Medium, known: true, titleHas: "ECS Exec"},
		{name: "approved in allowlist", arn: execAlice, kind: record.PrincipalUser, status: store.PrincipalUnknown, yaml: "principals:\n  - arn: " + execAlice + "\n", want: Medium, known: true},
		{name: "deploy tag is not lowered", arn: execAlice, kind: record.PrincipalUser, status: store.PrincipalUnknown,
			yaml: "principals:\n  - arn: " + execAlice + "\n    tags: [deploy]\n", want: Medium, known: true},
		{name: "unknown principal", arn: execUnknown, kind: record.PrincipalUser, status: store.PrincipalUnknown, want: High, titleHas: "知らない主体"},
		{name: "not in store", arn: execUnknown, kind: record.PrincipalUser, want: High},
		{name: "approval expired", arn: execAlice, kind: record.PrincipalUser, status: store.PrincipalBaseline,
			yaml: "principals:\n  - arn: " + execAlice + "\n    expires: 2026-10-01\n", want: High},
		{name: "root", arn: execRoot, kind: record.PrincipalRoot, status: store.PrincipalBaseline, want: High},
		{name: "known failed", arn: execAlice, kind: record.PrincipalUser, status: store.PrincipalBaseline, code: "TargetNotConnectedException", want: Low, known: true, denied: true, titleHas: "試行 (失敗)"},
		{name: "unknown failed", arn: execUnknown, kind: record.PrincipalUser, status: store.PrincipalUnknown, code: "AccessDeniedException", want: Medium, denied: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := execSeed{t: t, st: newStore(t)}
			if tc.status != "" {
				s.principal(tc.arn, tc.kind, tc.status)
			}
			s.exec("e1", now.Add(-2*time.Hour), tc.arn, tc.kind, tc.code, execData("t1", "/bin/sh", "ecs-execute-command-01"))
			al := emptyAllowlist(t)
			if tc.yaml != "" {
				var err error
				if al, err = allowlist.Parse([]byte(tc.yaml)); err != nil {
					t.Fatal(err)
				}
			}
			obs := execEval(t, s.st, al, execWindow)
			if len(obs) != 1 {
				t.Fatalf("%+v", obs)
			}
			for _, o := range obs {
				if o.Severity != tc.want || o.Data["known"] != tc.known {
					t.Fatalf("severity %s known %v, want %s %v: %+v", o.Severity, o.Data["known"], tc.want, tc.known, o)
				}
				if d, _ := o.Data["denied"].(bool); d != tc.denied {
					t.Fatalf("denied %v: %+v", d, o.Data)
				}
				if tc.titleHas != "" && !strings.Contains(o.Summary, tc.titleHas) {
					t.Fatalf("summary %q lacks %q", o.Summary, tc.titleHas)
				}
				if tc.denied && o.Data["error_codes"] == nil {
					t.Fatalf("error_codes missing: %+v", o.Data)
				}
			}
		})
	}
}

func TestECSExecAggregation(t *testing.T) {
	s := execSeed{t: t, st: newStore(t)}
	s.principal(execAlice, record.PrincipalUser, store.PrincipalBaseline)
	day := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	// 同じ日・同じクラスター・同じコンテナのセッションは 1 件。タスクが違っても (デプロイで変わる) まとめる
	s.exec("e1", day.Add(1*time.Hour), execAlice, record.PrincipalUser, "", execData("t1", "/bin/sh", "ecs-execute-command-01"))
	s.exec("e2", day.Add(2*time.Hour), execAlice, record.PrincipalUser, "", execData("t2", "sh -c 'cat /proc/1/environ'", "ecs-execute-command-02"))
	s.exec("e3", day.Add(3*time.Hour), execAlice, record.PrincipalUser, "TargetNotConnectedException", execData("t2", "/bin/sh", ""))
	// 前の日は別の finding (日付が Key に入る)
	s.exec("e4", day.Add(-2*time.Hour), execAlice, record.PrincipalUser, "", execData("t0", "/bin/sh", "ecs-execute-command-00"))
	// 別のコンテナは別の finding
	other := execData("t1", "/bin/sh", "")
	other["ecs_container"] = "worker"
	s.exec("e5", day.Add(4*time.Hour), execAlice, record.PrincipalUser, "", other)
	// クラスター・コンテナの取れない記録 (拒否された呼び出し) は `-`
	s.exec("e6", day.Add(5*time.Hour), execAlice, record.PrincipalUser, "AccessDeniedException", nil)
	// 別の操作は見ない
	if err := s.st.InsertEvent(context.Background(), record.TrailEvent{EventID: "x", Time: day.Add(time.Hour), Source: "trail", Name: "RunTask", EventSource: "ecs.amazonaws.com",
		PrincipalARN: execAlice, PrincipalKind: record.PrincipalUser}); err != nil {
		t.Fatal(err)
	}
	obs := execEval(t, s.st, emptyAllowlist(t), collect.Window{From: day.Add(-24 * time.Hour), To: day.Add(24 * time.Hour)})
	keys := []string{
		execAlice + "|ap-northeast-1/-|-|2026-10-21",
		execKeyAlice,
		execAlice + "|ap-northeast-1/prod-cluster|app|2026-10-20",
		execAlice + "|ap-northeast-1/prod-cluster|worker|2026-10-21",
	}
	if len(obs) != len(keys) {
		t.Fatalf("got %d: %v", len(obs), obs)
	}
	for _, k := range keys {
		if _, ok := obs[k]; !ok {
			t.Fatalf("missing key %q in %v", k, obs)
		}
	}
	o := obs[execKeyAlice]
	if o.Severity != Medium || o.Data["count"] != 3 || o.Data["sessions"] != 2 || o.Data["has_errors"] != true || o.Data["denied"] != nil {
		t.Fatalf("%+v", o)
	}
	if got := strings.Join(o.Data["commands"].([]string), " / "); got != "/bin/sh / sh -c 'cat /proc/1/environ'" {
		t.Fatalf("commands: %q", got)
	}
	if got := strings.Join(o.Data["command_kinds"].([]string), ","); got != "shell,shell_c" {
		t.Fatalf("command_kinds: %q", got)
	}
	if got := strings.Join(o.Data["tasks"].([]string), ","); got != "t1,t2" {
		t.Fatalf("tasks: %q", got)
	}
	if got := strings.Join(o.Data["session_ids"].([]string), ","); got != "ecs-execute-command-01,ecs-execute-command-02" {
		t.Fatalf("session_ids: %q", got)
	}
	for k, v := range map[string]any{"principal": execAlice, "region": "ap-northeast-1", "cluster": "prod-cluster", "container": "app", "date": "2026-10-21", "interactive": true, "principal_status": "baseline"} {
		if o.Data[k] != v {
			t.Fatalf("data.%s = %v, want %v", k, o.Data[k], v)
		}
	}
	// 見出しにコマンドの文字列を出さない (通知に流れるため。ADR 0072 の 5 節)
	if strings.Contains(o.Summary, "environ") || strings.Contains(o.Summary, "/bin/sh") {
		t.Fatalf("summary must not contain commands: %q", o.Summary)
	}
	if !strings.Contains(o.Summary, "prod-cluster") || !strings.Contains(o.Summary, "app") || !strings.Contains(o.Summary, execAlice) {
		t.Fatalf("summary: %q", o.Summary)
	}
	if d := obs[execAlice+"|ap-northeast-1/-|-|2026-10-21"]; d.Severity != Low || d.Data["denied"] != true {
		t.Fatalf("denied: %+v", d)
	}
}

// 同じ日に新しいセッションが加われば、指紋が変わり changed になる。同じ記録を引き直しても変わらない (ADR 0072 の 4 節)。
func TestECSExecFingerprint(t *testing.T) {
	s := execSeed{t: t, st: newStore(t)}
	s.principal(execAlice, record.PrincipalUser, store.PrincipalBaseline)
	s.exec("e1", now.Add(-3*time.Hour), execAlice, record.PrincipalUser, "", execData("t1", "/bin/sh", ""))
	al := emptyAllowlist(t)
	first := execEval(t, s.st, al, execWindow)[execKeyAlice].Fingerprint
	again := execEval(t, s.st, al, execWindow)[execKeyAlice].Fingerprint
	if first != again {
		t.Fatalf("fingerprint must be stable: %q / %q", first, again)
	}
	s.exec("e2", now.Add(-2*time.Hour), execAlice, record.PrincipalUser, "", execData("t1", "/bin/sh", ""))
	if next := execEval(t, s.st, al, execWindow)[execKeyAlice].Fingerprint; next == first {
		t.Fatal("a new session must change the fingerprint")
	}
	if strings.Contains(first, "2026-") {
		t.Fatalf("fingerprint must not contain dates: %q", first)
	}
}

func TestECSExecCaps(t *testing.T) {
	s := execSeed{t: t, st: newStore(t)}
	s.principal(execAlice, record.PrincipalUser, store.PrincipalBaseline)
	for i := 0; i < 15; i++ {
		id := string(rune('a' + i))
		s.exec("e"+id, now.Add(-time.Duration(i+1)*time.Minute), execAlice, record.PrincipalUser, "", execData("t"+id, "cmd-"+id, "ecs-execute-command-"+id))
	}
	o := execEval(t, s.st, emptyAllowlist(t), execWindow)[execKeyAlice]
	if n := len(o.Data["commands"].([]string)); n != maxECSExecItems || o.Data["commands_more"] != 5 {
		t.Fatalf("commands: %d more %v", n, o.Data["commands_more"])
	}
	if len(o.Data["tasks"].([]string)) != maxECSExecItems || len(o.Data["session_ids"].([]string)) != maxECSExecItems {
		t.Fatalf("%+v", o.Data)
	}
}

// ストアから読み戻した値が決まった形でなければ、Key に使わない (ログ由来の値。ADR 0037)。
func TestECSExecRejectsMalformedStoredValues(t *testing.T) {
	s := execSeed{t: t, st: newStore(t)}
	s.principal(execAlice, record.PrincipalUser, store.PrincipalBaseline)
	s.exec("e1", now.Add(-time.Hour), execAlice, record.PrincipalUser, "", map[string]any{"ecs_cluster": "a|b", "ecs_container": "x\ny", "ecs_command": "sh\u0007", "ecs_session_id": "alice@example.com"})
	obs := execEval(t, s.st, emptyAllowlist(t), execWindow)
	o, ok := obs[execAlice+"|ap-northeast-1/-|-|2026-10-21"]
	if !ok {
		t.Fatalf("%v", obs)
	}
	if o.Data["commands"].([]string)[0] != "sh" || o.Data["session_ids"] != nil {
		t.Fatalf("%+v", o.Data)
	}
}

func TestCommandKind(t *testing.T) {
	for cmd, want := range map[string]string{
		"/bin/sh": "shell", "bash": "shell", "/usr/bin/zsh -l": "shell", "ash": "shell", "dash": "shell",
		"sh -c 'id'": "shell_c", "/bin/bash -lc env": "shell_c", "bash -ec x": "shell_c",
		"ls -la": "other", "python3 manage.py shell": "other", "shx": "other", "": "other", "bash --login": "shell",
	} {
		if got := commandKind(cmd); got != want {
			t.Errorf("commandKind(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// FuzzCommandKind: コマンドの分類 (ログ由来の値の解釈。ADR 0041) は、どんな入力でも決まった 3 つのどれかで、
// 先頭の語がシェルの名前 (パスの最後) のときだけ shell / shell_c。
func FuzzCommandKind(f *testing.F) {
	for _, s := range []string{"/bin/sh", "sh -c id", "bash -lc x", "ls", "", " \t", "sh --c", "/x/y/zsh -ec 'a'", "\xff sh -c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k := commandKind(s)
		fields := strings.Fields(s)
		isShell := len(fields) > 0 && shellNames[pathBase(fields[0])]
		switch k {
		case CommandShell, CommandShellC:
			if !isShell {
				t.Fatalf("%q classified as %s", s, k)
			}
		case CommandOther:
			if isShell {
				t.Fatalf("%q is a shell", s)
			}
		default:
			t.Fatalf("unknown kind %q", k)
		}
	})
}

func pathBase(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}
