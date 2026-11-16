package checks

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/CircleAround/arata/docs/ai"
)

// 表は登録済みの全チェックにあり、決まり (ADR 0068 の 4 節・6 節) を守る。
func TestTriageTableRules(t *testing.T) {
	reg := NewRegistry()
	if got, want := strings.Join(TriageChecks(), ","), strings.Join(sortedNames(reg.Names()), ","); got != want {
		t.Fatalf("checks in the triage table:\n got %s\nwant %s", got, want)
	}
	for _, check := range TriageChecks() {
		seen := map[Severity]bool{}
		for _, r := range TriageRows(check) {
			if len(r.Severities) == 0 || len(r.Allowed) == 0 {
				t.Errorf("%s: empty row %+v", check, r)
			}
			has := map[string]bool{}
			for _, a := range r.Allowed {
				has[a] = true
			}
			for _, s := range r.Severities {
				if seen[s] {
					t.Errorf("%s: severity %s is in two rows", check, s)
				}
				seen[s] = true
				if s.Rank() >= High.Rank() && has[TriageAck] {
					t.Errorf("%s %s: high and critical must not allow ack", check, s)
				}
			}
			if r.Escalates != has[TriageAck] {
				t.Errorf("%s %v: ack is allowed exactly when the severity can rise for the same key (escalates %v, ack %v)", check, r.Severities, r.Escalates, has[TriageAck])
			}
			if has[TriageApprove] != ApproveChecks[check] {
				t.Errorf("%s: approve %v, but arata approve accepts it: %v", check, has[TriageApprove], ApproveChecks[check])
			}
			if !has[TriageSnooze] || !has[TriageResolve] {
				t.Errorf("%s %v: snooze and resolve are always allowed", check, r.Severities)
			}
		}
	}
	if TriageAllows("secret_access", High, TriageAck) || !TriageAllows("secret_access", Low, TriageAck) || TriageAllows("root_usage", Low, TriageAck) || !TriageAllows("root_usage", Low, TriageResolve) {
		t.Fatal("TriageAllows")
	}
}

func sortedNames(l []string) []string {
	out := append([]string(nil), l...)
	sort.Strings(out)
	return out
}

// 正は各 playbook の「片付け」の節の表。Go の表 (triageTable) と、行の順まで一致する。
func TestTriageTableMatchesPlaybooks(t *testing.T) {
	sevName := map[string]Severity{"critical": Critical, "high": High, "medium": Medium, "low": Low, "info": Info}
	for _, check := range TriageChecks() {
		body, ok := ai.Playbook(check)
		if !ok {
			t.Fatalf("%s: no playbook", check)
		}
		rows, err := parseTriageSection(body)
		if err != nil {
			t.Errorf("%s: %v", check, err)
			continue
		}
		var got []TriageRow
		for _, r := range rows {
			var sevs []Severity
			for _, s := range strings.Split(r[0], "・") {
				sev, ok := sevName[strings.TrimSpace(s)]
				if !ok {
					t.Errorf("%s: unknown severity %q", check, s)
				}
				sevs = append(sevs, sev)
			}
			esc := map[string]bool{"あり": true, "なし": false}
			e, ok := esc[r[1]]
			if !ok {
				t.Errorf("%s: 上がる余地 must be あり or なし: %q", check, r[1])
			}
			got = append(got, TriageRow{Severities: sevs, Escalates: e, Allowed: strings.Split(r[2], "・")})
		}
		if !reflect.DeepEqual(got, TriageRows(check)) {
			t.Errorf("%s: the playbook's 片付け table differs from checks.triageTable\nplaybook: %+v\n      go: %+v", check, got, TriageRows(check))
		}
	}
}

// parseTriageSection は「## 片付け」の節の最初の表 (| 重大度 | 上がる余地 | 許す操作 |) の行を返す。
func parseTriageSection(body string) ([][3]string, error) {
	i := strings.Index(body, "\n## 片付け\n")
	if i < 0 {
		return nil, errf("no 片付け section")
	}
	sec := body[i+len("\n## 片付け\n"):]
	if j := strings.Index(sec, "\n## "); j >= 0 {
		sec = sec[:j]
	}
	var out [][3]string
	header := false
	for _, line := range strings.Split(sec, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			if header && len(out) > 0 {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for k := range cells {
			cells[k] = strings.TrimSpace(cells[k])
		}
		if len(cells) != 3 {
			return nil, errf("the table must have 3 columns: %q", line)
		}
		switch {
		case !header:
			if cells[0] != "重大度" || cells[1] != "上がる余地" || cells[2] != "許す操作" {
				return nil, errf("header must be | 重大度 | 上がる余地 | 許す操作 |: %q", line)
			}
			header = true
		case strings.HasPrefix(cells[0], "---"):
		default:
			out = append(out, [3]string{cells[0], cells[1], cells[2]})
		}
	}
	if len(out) == 0 {
		return nil, errf("no rows in the 片付け table")
	}
	return out, nil
}

func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }
