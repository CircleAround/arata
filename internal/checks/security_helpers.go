package checks

import (
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/record"
)

// API は CloudTrail の操作 1 つ (eventSource と eventName)。Prefix なら eventName の接頭辞で一致させる
// (Lambda の eventName は AddPermission20150331v2 のように API の版が付くため)。
// 決定: defense_evasion / public_exposure が見る操作の一覧はここで公開し、cloudtrail collector のテストで
// 「すべて注目イベントとして残る」ことを固定する (一覧のずれを防ぐ。ADR 0026)。
type API struct {
	Source string
	Name   string
	Prefix bool
}

func (a API) match(e record.TrailEvent) bool {
	if e.EventSource != a.Source {
		return false
	}
	if a.Prefix {
		return strings.HasPrefix(e.Name, a.Name)
	}
	return e.Name == a.Name
}

func apisOf(source string, names ...string) []API {
	out := make([]API, len(names))
	for i, n := range names {
		out[i] = API{Source: source, Name: n}
	}
	return out
}

func findAPI(apis []API, e record.TrailEvent) (API, bool) {
	for _, a := range apis {
		if a.match(e) {
			return a, true
		}
	}
	return API{}, false
}

func apiSources(apis []API) []string {
	set := map[string]bool{}
	for _, a := range apis {
		set[a.Source] = true
	}
	return sortedKeys(set)
}

// apiLabel は "cloudtrail:StopLogging" の形 (版付きの名前は接頭辞に寄せる)。
func apiLabel(a API) string {
	return strings.TrimSuffix(a.Source, ".amazonaws.com") + ":" + a.Name
}

func dataStr(d map[string]any, k string) string {
	s, _ := d[k].(string)
	return s
}

// dataBool は値があれば (値, true)。
func dataBool(d map[string]any, k string) (bool, bool) {
	b, ok := d[k].(bool)
	return b, ok
}

func dataInt(d map[string]any, k string) (int, bool) {
	switch v := d[k].(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

func dataStrings(d map[string]any, k string) []string {
	switch v := d[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func dataMaps(d map[string]any, k string) []map[string]any {
	v, _ := d[k].([]any)
	out := make([]map[string]any, 0, len(v))
	for _, x := range v {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// lowerOne は重大度を 1 段下げる (critical → high → medium → low)。info にはしない。
func lowerOne(s Severity) Severity {
	switch s {
	case Critical:
		return High
	case High:
		return Medium
	}
	return Low
}

// knownDeploy は allowlist で承認済みかつ `tags: [deploy]` の主体か (iam_changes と同じ規則)。
func knownDeploy(al *allowlist.List, arn string, at time.Time) bool {
	entry, status := al.Principal(arn, at)
	return status == allowlist.StatusApproved && entry.HasTag("deploy")
}

func uniqSorted(ss []string) []string {
	set := map[string]bool{}
	for _, s := range ss {
		if s != "" {
			set[s] = true
		}
	}
	return sortedKeys(set)
}
