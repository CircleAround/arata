package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// windowEvents は窓 [From, To) のイベントに、再走査の区間 [ScanFrom, From) で今回の収集で初めて保存したもの (遅れて届いたもの) を加えて返す。
// 決定 (ADR 0013): 重なり区間の収集済みイベントは前回の run で評価済みなので含めない (件数の水増しと、resolve 済みの事象の再報告を防ぐ)。
func windowEvents(ctx context.Context, q store.Query, w collect.Window, f store.EventFilter) ([]record.TrailEvent, error) {
	f.LateFrom, f.CollectedSince = w.ScanFrom, w.CollectedAt
	return q.Events(ctx, w.From, w.To, f)
}

// eventAgg はイベント群を Key ごとに集計するための共通構造。
type eventAgg struct {
	count int
	first time.Time
	last  time.Time
	names map[string]bool
	ips   map[string]bool
	extra map[string]any
}

func newEventAgg() *eventAgg {
	return &eventAgg{names: map[string]bool{}, ips: map[string]bool{}, extra: map[string]any{}}
}

func (a *eventAgg) add(t time.Time, name, ip string) {
	a.count++
	if a.first.IsZero() || t.Before(a.first) {
		a.first = t
	}
	if t.After(a.last) {
		a.last = t
	}
	if name != "" {
		a.names[name] = true
	}
	if ip != "" {
		a.ips[ip] = true
	}
}

// merge は b の件数・時刻・イベント名・IP を a に足す (extra は足さない)。
func (a *eventAgg) merge(b *eventAgg) {
	a.count += b.count
	if a.first.IsZero() || (!b.first.IsZero() && b.first.Before(a.first)) {
		a.first = b.first
	}
	if b.last.After(a.last) {
		a.last = b.last
	}
	for n := range b.names {
		a.names[n] = true
	}
	for ip := range b.ips {
		a.ips[ip] = true
	}
}

func (a *eventAgg) data() map[string]any {
	d := map[string]any{
		"count":      a.count,
		"first_time": a.first.UTC().Format(time.RFC3339),
		"last_time":  a.last.UTC().Format(time.RFC3339),
	}
	if len(a.names) > 0 {
		d["event_names"] = sortedKeys(a.names)
	}
	if len(a.ips) > 0 {
		d["ips"] = sortedKeys(a.ips)
	}
	for k, v := range a.extra {
		d[k] = v
	}
	return d
}

// fingerprint は changed 判定用の安定した文字列を作る。count や時刻は含めない。
func fingerprint(sev Severity, ips map[string]bool, parts ...any) string {
	s := string(sev) + "|" + strings.Join(sortedKeys(ips), ",")
	for _, p := range parts {
		s += "|" + fmt.Sprint(p)
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedObs(m map[string]Observation) []Observation {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Observation, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// maxInvokedBy は data.invoked_by に出すサービス名の数の上限。
const maxInvokedBy = 10

// sourcePhrase は見出しの「どこから」の句。送信元の IP があれば「<IP,…> から」、無くて AWS のサービス経由と分かれば
// 「AWS のサービス (<名前, …>) 経由で」、どちらも無ければ「IP の記録の無い送信元から」。
// 決定: 送信元が空のときに「 から」と書かない (見出しが崩れ、読む人と LLM が送信元不明の操作と受け取る)。
// services は record.ServiceName を通した値だけを渡す (ログ由来の値をそのまま見出しに出さない)。
func sourcePhrase(ips, services []string) string {
	switch {
	case len(ips) > 0:
		return strings.Join(ips, ",") + " から"
	case len(services) > 0:
		return "AWS のサービス (" + strings.Join(services, ", ") + ") 経由で"
	}
	return "IP の記録の無い送信元から"
}
