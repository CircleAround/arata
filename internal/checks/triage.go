package checks

import (
	"sort"
	"strings"
)

// 片付けの表 (ADR 0068 の 4 節・6 節): チェック × 重大度 → 上がる余地・許す操作。
//
// 正は各 playbook (docs/ai/playbooks/<check>.md) の「片付け」の節の表。ここはその写しで、テストで突き合わせる。
// 決まり (テストが確かめる):
//   - ack を許すのは「上がる余地がある」(同じ Key のまま、より重い重大度で観測されうる) 行だけ。ack 中に出直すのは重大度が上がったときだけ
//     (ADR 0022) なので、上がる余地の無い行の ack は最後になる。余地があっても ack を許さない行はある (ecs_exec。ADR 0072 の 8 節)
//   - high・critical の行は ack を許さない (最も重い側。2 節)
//   - approve は arata approve が受け付けるチェック (ApproveChecks) だけ
//   - 余地のあり・なしは、同じ Key で軽い観測と重い観測を作れるか (triage_escalation_test.go)。一部の Key だけ上がるチェック
//     (iam_changes の信頼ポリシーの変更など) は、守りの側に倒して「なし」にする
//   - 決定 (ADR 0077): 一部の Key だけを守りの側に倒す行は、Key の接頭辞 (KeyPrefix) を持つ。接頭辞の行は上がる余地「なし」だけで、
//     その接頭辞の Key には接頭辞の行が先に当たる (無ければ接頭辞の無い行)。playbook では「medium (`<接頭辞>`)」と書く

// 片付けの操作の名前 (store.Action* と同じ値)。
const (
	TriageApprove = "approve"
	TriageAck     = "ack"
	TriageSnooze  = "snooze"
	TriageResolve = "resolve"
)

// ApproveChecks は arata approve が受け付けるチェック (主体・行き先の承認、access_denied の想定済みの拒否)。
// oidc_assume_role は allowlist.yaml の oidc_subjects を人が書く (approve は書かない)。
var ApproveChecks = map[string]bool{"new_principal": true, "unknown_assume_role": true, "iam_changes": true, "access_denied": true}

// TriageRow は片付けの表の 1 行。
type TriageRow struct {
	Severities []Severity
	// KeyPrefix が空でなければ、Key がこの接頭辞で始まる finding だけの行 (ADR 0077)。
	KeyPrefix string
	// Escalates は、同じ Key のまま、より重い重大度で観測されうるか。
	Escalates bool
	// Allowed は許す操作 (approve・ack・snooze・resolve の順)。
	Allowed []string
}

var (
	noAck   = []string{TriageSnooze, TriageResolve}
	withAck = []string{TriageAck, TriageSnooze, TriageResolve}
	apNoAck = []string{TriageApprove, TriageSnooze, TriageResolve}
	apAck   = []string{TriageApprove, TriageAck, TriageSnooze, TriageResolve}
)

func row(escalates bool, allowed []string, sevs ...Severity) TriageRow {
	return TriageRow{Severities: sevs, Escalates: escalates, Allowed: allowed}
}

// keyRow は Key の接頭辞の行 (上がる余地なし。ADR 0077)。
func keyRow(prefix string, allowed []string, sevs ...Severity) TriageRow {
	return TriageRow{Severities: sevs, KeyPrefix: prefix, Allowed: allowed}
}

var triageTable = map[string][]TriageRow{
	"root_usage":             {row(false, noAck, Critical)},
	"defense_evasion":        {row(false, noAck, Critical, High, Medium)},
	"ecs_exec":               {row(false, noAck, High), row(true, noAck, Medium, Low)},
	"unknown_assume_role":    {row(false, apNoAck, High, Info)},
	"oidc_assume_role":       {row(false, noAck, High, Medium), row(true, withAck, Low), row(false, noAck, Info)},
	"secret_access":          {row(false, noAck, High), keyRow(BulkExemptUnmatchedKeyPrefix, noAck, Medium), row(true, withAck, Medium, Low), row(false, noAck, Info)},
	"guardduty_findings":     {row(false, noAck, High, Medium, Low)},
	"iam_changes":            {row(false, apNoAck, High, Medium, Info)},
	"access_denied":          {row(false, apNoAck, High), row(true, apAck, Medium)},
	"new_principal":          {row(false, apNoAck, Medium)},
	"principal_new_source":   {row(false, noAck, High), row(true, withAck, Medium, Low)},
	"unused_region_activity": {row(false, noAck, Critical, High), row(true, withAck, Medium)},
	"cost_anomaly":           {row(false, noAck, High, Medium)},
	"public_exposure":        {row(false, noAck, High, Medium, Low)},
	"login_bruteforce":       {row(false, noAck, Medium)},
	"probe_paths":            {row(false, noAck, Low)},
	"endpoint_abuse":         {row(false, noAck, Medium), row(true, withAck, Low)},
	"waf_block_trend":        {row(false, noAck, Low)},
	"ai_path_usage":          {row(false, noAck, Info)},
	"credential_hygiene":     {row(false, noAck, High, Medium)},
	"access_analyzer":        {row(false, noAck, High, Medium)},
	"posture":                {row(false, noAck, High, Medium)},
	"waf_review":             {row(false, noAck, Low)},
	"log_hygiene":            {row(false, noAck, High, Medium, Low)},
}

// TriageChecks は表のあるチェック (名前順)。
func TriageChecks() []string {
	out := make([]string, 0, len(triageTable))
	for c := range triageTable {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// TriageRows はチェックの表の行 (無ければ nil)。
func TriageRows(check string) []TriageRow { return triageTable[check] }

// TriageRowOf はチェック・Key・重大度の行。Key の接頭辞の行が先に当たる。表に無い組なら false (その組の ack は許さない側に倒す)。
func TriageRowOf(check, key string, sev Severity) (TriageRow, bool) {
	for _, prefixed := range []bool{true, false} {
		for _, r := range triageTable[check] {
			if (r.KeyPrefix != "") != prefixed || prefixed && !strings.HasPrefix(key, r.KeyPrefix) {
				continue
			}
			for _, s := range r.Severities {
				if s == sev {
					return r, true
				}
			}
		}
	}
	return TriageRow{}, false
}

// TriageAllows は表がその操作を許すか。表に無い組は ack だけを許さない (snooze・resolve は止めない。approve の可否は approve が決める)。
func TriageAllows(check, key string, sev Severity, action string) bool {
	r, ok := TriageRowOf(check, key, sev)
	if !ok {
		return action != TriageAck
	}
	for _, a := range r.Allowed {
		if a == action {
			return true
		}
	}
	return false
}
