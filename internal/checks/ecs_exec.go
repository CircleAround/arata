package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ECSExec は本番のコンテナでシェルを開く操作 (ECS Exec の ExecuteCommand) を、誰が・どこに・何を・どこから、で毎回報告する (ADR 0072)。
//
// 決定:
//   - 重大度: 知らない主体 (root を含む) は high、既知の主体は medium。すべて失敗した試行は 1 段下げる (知らない主体は medium、既知の主体は low)。
//     既知は new_principal が報告しない主体と同じ判定 (allowlist で期限内に承認済み、またはストアの状態が baseline / approved)。deploy タグでも下げない
//   - Key は `<主体>|<リージョン>/<クラスター>|<コンテナ>|<UTC の日付>`。取れない部分は `-`。タスクは Key に入れない (デプロイで変わる)
//   - Fingerprint は 重大度 + 既知か + 全部失敗か + その Key に入った記録の event_id の集合の要約。同じ日に新しいセッションが加われば changed になる
//   - 見出しにコマンドの文字列を出さない (通知に流れる。作業者が打った秘匿値が入りうる)。コマンドは data の commands (report に出す) と
//     規則の分類 command_kinds だけ。aratam は commands を LLM に渡さない
type ECSExec struct{}

func (ECSExec) Name() string         { return "ecs_exec" }
func (ECSExec) Cadence() Cadence     { return Hourly }
func (ECSExec) Mode() Mode           { return ModeEvent }
func (ECSExec) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

// ECSExecAPIs は ecs_exec が見る操作 (cloudtrail collector のテストで、注目イベントに入ることを固定する)。
func ECSExecAPIs() []API { return apisOf("ecs.amazonaws.com", "ExecuteCommand") }

// maxECSExecItems は data の commands・tasks・session_ids の数の上限。
const maxECSExecItems = 10

// コマンドの分類 (data.command_kinds)。
const (
	CommandShell  = "shell"   // シェルを開いた (sh・bash など)
	CommandShellC = "shell_c" // シェルに -c で文字列を渡した
	CommandOther  = "other"
)

var shellNames = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true}

// commandKind はコマンドの先頭の語がシェルか、-c (-lc などの組み合わせを含む) が付くかで分ける。
func commandKind(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return CommandOther
	}
	// 先頭の語の、最後の `/` より後ろ (path.Base と違い、末尾の `/` を除かない。`sh/` はシェルではない)
	prog := f[0][strings.LastIndexByte(f[0], '/')+1:]
	if !shellNames[prog] {
		return CommandOther
	}
	for _, a := range f[1:] {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a, 'c') {
			return CommandShellC
		}
	}
	return CommandShell
}

type execAgg struct {
	*eventAgg
	ids, commands, tasks, sessions, kinds map[string]bool
	failed, succeeded                     int
	codes                                 map[string]bool
	interactive                           bool
}

func (c ECSExec) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{EventSources: []string{"ecs.amazonaws.com"}, Names: []string{"ExecuteCommand"}})
	if err != nil {
		return nil, err
	}
	if len(evs) == 0 {
		return nil, nil
	}
	ps, err := q.Principals(ctx, store.PrincipalFilter{})
	if err != nil {
		return nil, err
	}
	storeStatus := map[string]string{}
	for _, p := range ps {
		storeStatus[p.ARN] = p.Status
	}
	aggs := map[string]*execAgg{}
	for _, e := range evs {
		cluster, container := execName(e.Data, "ecs_cluster"), execName(e.Data, "ecs_container")
		date := e.Time.UTC().Format(record.DateLayout)
		k := e.PrincipalARN + "|" + e.Region + "/" + cluster + "|" + container + "|" + date
		a, ok := aggs[k]
		if !ok {
			a = &execAgg{eventAgg: newEventAgg(), ids: map[string]bool{}, commands: map[string]bool{}, tasks: map[string]bool{}, sessions: map[string]bool{},
				kinds: map[string]bool{}, codes: map[string]bool{}}
			a.extra["principal"] = e.PrincipalARN
			a.extra["principal_kind"] = string(e.PrincipalKind)
			a.extra["region"] = e.Region
			a.extra["cluster"] = cluster
			a.extra["container"] = container
			a.extra["date"] = date
			known, status := execKnown(al, storeStatus, e, w)
			a.extra["known"] = known
			a.extra["principal_status"] = status
			aggs[k] = a
		}
		a.add(e.Time, "", e.IP)
		a.ids[e.EventID] = true
		if e.ErrorCode != "" {
			a.failed++
			a.codes[e.ErrorCode] = true
		} else {
			a.succeeded++
		}
		if s, ok := e.Data["ecs_command"].(string); ok {
			if cmd, _ := record.CleanECSCommand(s); cmd != "" {
				a.commands[cmd] = true
				a.kinds[commandKind(cmd)] = true
			}
		}
		if s := dataStr(e.Data, "ecs_task"); s != "" {
			if t, ok := record.ECSName(s); ok {
				a.tasks[t] = true
			}
		}
		if s := dataStr(e.Data, "ecs_session_id"); s != "" {
			if id, ok := record.ECSSessionID(s); ok {
				a.sessions[id] = true
			}
		}
		if v, _ := dataBool(e.Data, "ecs_interactive"); v {
			a.interactive = true
		}
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		known := a.extra["known"].(bool)
		denied := a.succeeded == 0
		sev := High
		if known {
			sev = Medium
		}
		if denied {
			sev = lowerOne(sev)
			a.extra["denied"] = true
		} else if a.failed > 0 {
			a.extra["has_errors"] = true
		}
		if len(a.codes) > 0 {
			a.extra["error_codes"] = sortedKeys(a.codes)
		}
		a.extra["sessions"] = a.succeeded
		if a.interactive {
			a.extra["interactive"] = true
		}
		if cmds := sortedKeys(a.commands); len(cmds) > 0 {
			a.extra["commands"] = capList(cmds, maxECSExecItems)
			if n := len(cmds) - maxECSExecItems; n > 0 {
				a.extra["commands_more"] = n
			}
			a.extra["command_kinds"] = sortedKeys(a.kinds)
		}
		if l := sortedKeys(a.tasks); len(l) > 0 {
			a.extra["tasks"] = capList(l, maxECSExecItems)
		}
		if l := sortedKeys(a.sessions); len(l) > 0 {
			a.extra["session_ids"] = capList(l, maxECSExecItems)
		}
		obs[k] = Observation{
			Check:       c.Name(),
			Key:         k,
			Severity:    sev,
			Summary:     execSummary(a, known, denied),
			Fingerprint: fingerprint(sev, nil, known, denied, idsDigest(a.ids)),
			Data:        a.data(),
		}
	}
	return sortedObs(obs), nil
}

// execName はストアから読み戻した名前 (元はログ由来) を、決まった形なら返す。違えば `-`。
func execName(d map[string]any, k string) string {
	if n, ok := record.ECSName(dataStr(d, k)); ok {
		return n
	}
	return "-"
}

// execKnown は主体が既知か (new_principal が報告しない主体と同じ判定) と、data に出す状態。root は既知にしない (root_usage が別に扱う)。
func execKnown(al *allowlist.List, storeStatus map[string]string, e record.TrailEvent, w collect.Window) (bool, string) {
	if e.PrincipalKind == record.PrincipalRoot {
		return false, "root"
	}
	_, status := al.Principal(e.PrincipalARN, w.To)
	switch status {
	case allowlist.StatusApproved:
		return true, "approved"
	case allowlist.StatusExpired:
		return false, "expired"
	}
	s, ok := storeStatus[e.PrincipalARN]
	if !ok {
		return false, "unseen"
	}
	return s == store.PrincipalBaseline || s == store.PrincipalApproved, s
}

// idsDigest は event_id の集合の要約 (指紋を短く保つ)。
func idsDigest(ids map[string]bool) string {
	h := sha256.Sum256([]byte(strings.Join(sortedKeys(ids), "\n")))
	return hex.EncodeToString(h[:8])
}

func execSummary(a *execAgg, known, denied bool) string {
	label := "ECS Exec"
	if denied {
		label = "ECS Exec の試行 (失敗)"
	}
	who := fmt.Sprint(a.extra["principal"])
	if !known {
		who = "知らない主体 " + who
	}
	what := "コマンドの実行"
	if a.kinds[CommandShell] || a.kinds[CommandShellC] {
		what = "シェル"
	}
	where := fmt.Sprintf("%s/%s のコンテナ %s", a.extra["region"], a.extra["cluster"], a.extra["container"])
	ips := sortedKeys(a.ips)
	if denied {
		return fmt.Sprintf("%s: %s が %s で%sを試みた (%d 件。%s)", label, who, where, what, a.count, sourcePhrase(ips, nil))
	}
	return fmt.Sprintf("%s: %s が %s で%s (%d セッション。%s)", label, who, where, what, a.succeeded, sourcePhrase(ips, nil))
}
