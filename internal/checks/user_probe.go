package checks

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ログインした利用者の総当たり (ADR 0071・0087): user_denied・user_id_enumeration・user_path_breadth。
// 材料は cwlogs の U1・U2 の日の値 (userprobe.go。From は http_user)。Insights は流さず、ストアの日の値だけを読む。
//
// 判定 (ADR 0071 の 1〜5・10 節):
//   - 1 日: 値が下限 (min_*) 以上、その利用者の平常帯 (直近 baseline_days 日の日の値の中央値 × factor) を超え、
//     アプリの平常帯 (同じ日々のうちアプリの記録のある日の「その日いちばん多かった利用者の値」の中央値 × app_factor) を超える
//   - 窓 (user_denied・user_id_enumeration): 評価する日に値があり、その日を含む window 日の和が min_count_window 以上、値のあった日が min_days 以上で、
//     利用者の窓の平常帯 (窓の前の baseline_days 日の中央値 × 窓の日数 × factor) と、アプリの窓の平常帯
//     (窓の前の baseline_days 日の各日を終わりとする window 日の和の、いちばん多い利用者の値の中央値 × app_factor) を超える
//   - 本人の平常帯もアプリの平常帯も、平常帯の日々のうちアプリの記録のある日だけから作る (収集の抜けた日を 0 に数えない)
//   - 新しい利用者 (平常帯の日々に値の残った日が min_baseline_days 未満) は、本人の平常帯を使わない (reasons に new_user)。
//     下限 (store_min) 未満の日は残らないので、ふだん値の小さい利用者もここに入る (本人の帯は 0 に近く、使っても結果は同じ)
//   - アプリの記録のある日 (user_requests のある日) が平常帯の日々に min_baseline_days 未満なら、その日は判定せず、coverage.notes に残りの日数を出す
//
// 決定 (実装):
//   - アプリの記録のある日は、同じソースの user_requests (ログインした要求の数) があり、そのチェックの集計 (U1 か U2) を流した印 (user_probe_days) のある日。利用者の値が下限未満で残らなかった日も「記録のある日」として 0 で数える
//   - アプリの平常帯の「いちばん多かった利用者の値」は、user_denied・user_templates では残した key の最大、user_id_enumeration では型ごとの分布の行 (user_ids_dist の max)。
//     窓の平常帯は、残した key の日の値の和の最大 (上位だけを残すので、上限で落ちた利用者は数えない。いちばん多い利用者は残る)
//   - finding は利用者ごとに 1 つ。評価する日 (窓に重なる日) のうち値の大きい日 (同じなら新しい日) を出す。
//     user_id_enumeration は条件を満たした型を ids の多い順に 5 つまで添え、重大度はその中の最も重いもの
//   - related は、同じ利用者・同じ日に条件を満たした、ほかの 2 つのチェックの名前 (そのチェックの sources が空なら見ない)
//   - 複数のソースを sources に書けば、同じ利用者・型の値はソースをまたいで足す
const (
	reasonAboveUserBand     = "above_user_band"
	reasonAboveAppBand      = "above_app_band"
	reasonWindow            = "window"
	reasonNewUser           = "new_user"
	reasonSuccessAmidDenied = "success_amid_denied"
	reasonSuccessOnly       = "success_only"
	// maxProbeTemplates は user_id_enumeration の finding に添える型の数。
	maxProbeTemplates = 5
)

const (
	userDeniedName        = "user_denied"
	userIDEnumerationName = "user_id_enumeration"
	userPathBreadthName   = "user_path_breadth"
)

// userProbeBase は 3 つのチェックに共通の設定 (related のために 3 つ全部を持つ)。
type userProbeBase struct {
	All config.Checks
	// PathSources は path_ids のあるソースの ID (Registry.SetPathIDSources)。
	PathSources []string
}

// UserDenied は 1 人の利用者の拒否 (401・403) の急増 (medium)。
type UserDenied struct{ userProbeBase }

// UserIDEnumeration は 1 人の利用者が、ID を含む型で多くの異なる ID を開いたもの (medium。拒否に混ざる成功は high)。
type UserIDEnumeration struct{ userProbeBase }

// UserPathBreadth は 1 人の利用者が触った型の多さ (low)。
type UserPathBreadth struct{ userProbeBase }

func (UserDenied) Name() string        { return userDeniedName }
func (UserIDEnumeration) Name() string { return userIDEnumerationName }
func (UserPathBreadth) Name() string   { return userPathBreadthName }

func (UserDenied) Cadence() Cadence        { return Daily }
func (UserIDEnumeration) Cadence() Cadence { return Daily }
func (UserPathBreadth) Cadence() Cadence   { return Daily }
func (UserDenied) Mode() Mode              { return ModeEvent }
func (UserIDEnumeration) Mode() Mode       { return ModeEvent }
func (UserPathBreadth) Mode() Mode         { return ModeEvent }

func (UserDenied) Needs() []record.Kind        { return []record.Kind{record.KindHTTPUser} }
func (UserIDEnumeration) Needs() []record.Kind { return []record.Kind{record.KindHTTPUser} }
func (UserPathBreadth) Needs() []record.Kind   { return []record.Kind{record.KindHTTPUser} }

func disabledSources(name string) string {
	return "checks." + name + ".sources is empty (nothing to read; see `arata help ai playbook " + name + "`)"
}

// pathSources は sources のうち path_ids のあるもの。
func (b userProbeBase) pathSources(sources []string) []string {
	var out []string
	for _, s := range sources {
		if containsStr(b.PathSources, s) {
			out = append(out, s)
		}
	}
	return out
}

func (c UserDenied) Disabled() string {
	if len(c.All.UserDenied.Sources) == 0 {
		return disabledSources(c.Name())
	}
	return ""
}

func (c UserIDEnumeration) Disabled() string {
	switch {
	case len(c.All.UserIDEnumeration.Sources) == 0:
		return disabledSources(c.Name())
	case len(c.pathSources(c.All.UserIDEnumeration.Sources)) == 0:
		return "no path_ids: none of checks.user_id_enumeration.sources has path_ids (see `arata help ai user_id`)"
	}
	return ""
}

func (c UserPathBreadth) Disabled() string {
	switch {
	case len(c.All.UserPathBreadth.Sources) == 0:
		return disabledSources(c.Name())
	case len(c.pathSources(c.All.UserPathBreadth.Sources)) == 0:
		return "no path_ids: none of checks.user_path_breadth.sources has path_ids (see `arata help ai user_id`)"
	}
	return ""
}

func (c UserDenied) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	obs, _, err := c.EvaluateWithNotes(ctx, q, w, al)
	return obs, err
}

func (c UserIDEnumeration) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	obs, _, err := c.EvaluateWithNotes(ctx, q, w, al)
	return obs, err
}

func (c UserPathBreadth) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	obs, _, err := c.EvaluateWithNotes(ctx, q, w, al)
	return obs, err
}

// probeHit は利用者 (と型) の、ある日の判定の結果。
type probeHit struct {
	day      string
	value    float64
	reasons  []string
	userBand float64
	appBand  float64
	window   map[string]any
}

func (h probeHit) better(o probeHit) bool {
	return h.value > o.value || h.value == o.value && h.day > o.day
}

// probeSeries は日の値を読むための入れ物。
type probeSeries struct {
	ctx       context.Context
	q         store.Query
	sources   []string
	from, to  string
	collected map[string]bool
}

func newProbeSeries(ctx context.Context, q store.Query, sources []string, probe string, w collect.Window, b config.UserBands, windowDays int) (*probeSeries, []string, error) {
	dates := windowDates(w)
	if len(dates) == 0 {
		return nil, nil, nil
	}
	ps := &probeSeries{ctx: ctx, q: q, sources: sources, from: addDays(dates[0], -(b.BaselineDays + 2*windowDays + 1)), to: dates[len(dates)-1]}
	rows, err := ps.load(cwlogs.MetricUserRequests)
	if err != nil {
		return nil, nil, err
	}
	ran, err := ps.load(cwlogs.MetricUserProbeDays)
	if err != nil {
		return nil, nil, err
	}
	ps.collected = map[string]bool{}
	for d := range rows {
		if ran[d][probe] > 0 {
			ps.collected[d] = true
		}
	}
	return ps, dates, nil
}

func (ps *probeSeries) load(metric string) (series, error) {
	ms, err := ps.q.Metrics(ps.ctx, store.MetricFilter{Metric: metric, From: ps.from, To: ps.to, Sources: ps.sources})
	if err != nil {
		return nil, err
	}
	s := series{}
	for _, m := range ms {
		if s[m.Date] == nil {
			s[m.Date] = map[string]float64{}
		}
		s[m.Date][m.Key] += m.Value
	}
	return s, nil
}

// waiting は d の平常帯の日々のうちアプリの記録のある日が足りなければ、残りの日数を返す (足りていれば 0)。
func (ps *probeSeries) waiting(d string, b config.UserBands) int {
	n := 0
	for _, bd := range baseDates(d, b.BaselineDays) {
		if ps.collected[bd] {
			n++
		}
	}
	if n >= b.MinBaselineDays {
		return 0
	}
	return b.MinBaselineDays - n
}

// waitNote は平常帯の蓄積待ちの注記。
func waitNote(name string, days int) string {
	return fmt.Sprintf("%s: 利用者ごとのチェックは平常帯の蓄積待ち (あと %d 日。アプリの記録のある日が min_baseline_days に満たない)", name, days)
}

// appMax は、bd の日の「いちばん多かった利用者の値」(記録のある日で値が無ければ 0)。group が空でなければ、その型の key だけ。
type maxOf func(s series, day string) float64

func keyMax(match func(key string) bool) maxOf {
	return func(s series, day string) float64 {
		m := 0.0
		for k, v := range s[day] {
			if (match == nil || match(k)) && v > m {
				m = v
			}
		}
		return m
	}
}

// bands は日 d の key の判定 (1 日の条件)。
func (ps *probeSeries) daily(s series, key, d string, v, min float64, b config.UserBands, appMaxOf func(day string) float64) (probeHit, bool) {
	h := probeHit{day: d, value: v}
	if v < min {
		return h, false
	}
	var userVals, appVals []float64
	withData := 0
	for _, bd := range baseDates(d, b.BaselineDays) {
		if _, ok := s[bd][key]; ok {
			withData++
		}
		// 決定 (レビューの指摘): 本人の帯もアプリの記録のある日だけから作る。収集の抜けた日を 0 にすると帯が下がり、誤りの指摘が増える
		// (記録のある日に値が無いのは下限未満なので 0 で正しい)
		if ps.collected[bd] {
			userVals = append(userVals, s[bd][key])
			appVals = append(appVals, appMaxOf(bd))
		}
	}
	h.appBand = median(appVals) * b.AppFactor
	if v <= h.appBand {
		return h, false
	}
	h.reasons = []string{reasonAboveAppBand}
	if withData < b.MinBaselineDays {
		h.reasons = append(h.reasons, reasonNewUser)
		return h, true
	}
	h.userBand = median(userVals) * b.Factor
	if v <= h.userBand {
		return h, false
	}
	h.reasons = append(h.reasons, reasonAboveUserBand)
	return h, true
}

// windowed は日 d を終わりとする窓の判定。sumsOf(e) は e を終わりとする窓の、利用者 (同じ型) の和の最大。
func (ps *probeSeries) windowed(s series, key, d string, b config.UserBands, uw config.UserWindow, appSumMax func(end string, n int) float64) (map[string]any, bool) {
	n := uw.WindowDays()
	if n < 1 || s[d][key] <= 0 {
		return nil, false
	}
	sum, days := 0.0, 0
	for i := 0; i < n; i++ {
		if x := s[addDays(d, -i)][key]; x > 0 {
			sum += x
			days++
		}
	}
	if sum < uw.MinCountWindow || days < uw.MinDays {
		return nil, false
	}
	start := addDays(d, -(n - 1))
	var userVals, appVals []float64
	withData := 0
	for _, bd := range baseDates(start, b.BaselineDays) {
		if _, ok := s[bd][key]; ok {
			withData++
		}
		if ps.collected[bd] { // 本人の帯も記録のある日だけ (daily と同じ)
			userVals = append(userVals, s[bd][key])
			appVals = append(appVals, appSumMax(bd, n))
		}
	}
	win := map[string]any{"days": n, "sum": sum, "days_with_value": days, "app_band": median(appVals) * b.AppFactor}
	if sum <= win["app_band"].(float64) {
		return nil, false
	}
	if withData >= b.MinBaselineDays {
		ub := median(userVals) * float64(n) * b.Factor
		win["user_band"] = ub
		if sum <= ub {
			return nil, false
		}
	} else {
		win["new_user"] = true
	}
	return win, true
}

// sumMax は e を終わりとする n 日の和の、match に当たる key の最大。
func sumMax(s series, match func(string) bool) func(end string, n int) float64 {
	return func(end string, n int) float64 {
		sums := map[string]float64{}
		for i := 0; i < n; i++ {
			for k, v := range s[addDays(end, -i)] {
				if match == nil || match(k) {
					sums[k] += v
				}
			}
		}
		m := 0.0
		for _, v := range sums {
			if v > m {
				m = v
			}
		}
		return m
	}
}

// mergeWindow は 1 日の判定と窓の判定をまとめる (どちらかを満たせば 1 件)。
func mergeWindow(day probeHit, dayOK bool, win map[string]any, winOK bool) (probeHit, bool) {
	if !dayOK && !winOK {
		return day, false
	}
	h := day
	if !dayOK {
		h.reasons = nil
		if win["new_user"] == true {
			h.reasons = append(h.reasons, reasonNewUser)
		}
	}
	if winOK {
		h.reasons = append(h.reasons, reasonWindow)
		h.window = win
	}
	sort.Strings(h.reasons)
	return h, true
}

// userOf は key の先頭の `<kind>:<id>` を data の user にする。
func userOf(key string) map[string]string {
	u, _, _ := strings.Cut(key, "|")
	kind, id, _ := strings.Cut(u, ":")
	return map[string]string{"kind": kind, "id": id}
}

// deniedHits は user_denied の条件を満たした利用者 (key → 日の判定)。wait は平常帯の蓄積待ちの残りの日数 (待ちの日があれば最大)。
func (b userProbeBase) deniedHits(ctx context.Context, q store.Query, w collect.Window) (map[string]probeHit, int, error) {
	cfg := b.All.UserDenied
	ps, dates, err := newProbeSeries(ctx, q, cfg.Sources, cwlogs.UserProbeSummary, w, cfg.UserBands, cfg.WindowDays())
	if err != nil || ps == nil {
		return nil, 0, err
	}
	s, err := ps.load(cwlogs.MetricUserDenied)
	if err != nil {
		return nil, 0, err
	}
	return probeDays(ps, s, dates, cfg.MinCount, cfg.UserBands, &cfg.UserWindow, keyMax(nil), sumMax(s, nil))
}

// breadthHits は user_path_breadth の条件を満たした利用者。
func (b userProbeBase) breadthHits(ctx context.Context, q store.Query, w collect.Window) (map[string]probeHit, int, series, error) {
	cfg := b.All.UserPathBreadth
	ps, dates, err := newProbeSeries(ctx, q, b.pathSources(cfg.Sources), cwlogs.UserProbeSummary, w, cfg.UserBands, 0)
	if err != nil || ps == nil {
		return nil, 0, nil, err
	}
	s, err := ps.load(cwlogs.MetricUserTemplates)
	if err != nil {
		return nil, 0, nil, err
	}
	hits, wait, err := probeDays(ps, s, dates, cfg.MinTemplates, cfg.UserBands, nil, keyMax(nil), nil)
	if err != nil {
		return nil, 0, nil, err
	}
	extra := series{}
	for _, m := range []string{cwlogs.MetricUserTemplatesOK, cwlogs.MetricUserTemplatesDenied, cwlogs.MetricUserTemplatesNotFound} {
		x, err := ps.load(m)
		if err != nil {
			return nil, 0, nil, err
		}
		for d, row := range x {
			for k, v := range row {
				if extra[d] == nil {
					extra[d] = map[string]float64{}
				}
				extra[d][m+"|"+k] = v
			}
		}
	}
	return hits, wait, extra, nil
}

// probeDays は評価する日ごとに key を判定し、key ごとに最もよい日を返す。
func probeDays(ps *probeSeries, s series, dates []string, min float64, b config.UserBands, uw *config.UserWindow, appMax maxOf, appSum func(string, int) float64) (map[string]probeHit, int, error) {
	out := map[string]probeHit{}
	wait := 0
	for _, d := range dates {
		if n := ps.waiting(d, b); n > 0 {
			wait = max(wait, n)
			continue
		}
		for key, v := range s[d] {
			day, dayOK := ps.daily(s, key, d, v, min, b, func(day string) float64 { return appMax(s, day) })
			var win map[string]any
			winOK := false
			if uw != nil {
				win, winOK = ps.windowed(s, key, d, b, *uw, appSum)
			}
			h, ok := mergeWindow(day, dayOK, win, winOK)
			if !ok {
				continue
			}
			if cur, seen := out[key]; !seen || h.better(cur) {
				out[key] = h
			}
		}
	}
	return out, wait, nil
}

// enumHit は user_id_enumeration の (利用者, 型) 1 つ。
type enumHit struct {
	probeHit
	template              string
	ok, denied, redirects float64
	hasRedirects          bool
	methods               map[string]float64
	severity              Severity
}

// enumHits は user_id_enumeration の条件を満たした (利用者, 型) を利用者ごとにまとめる。
func (b userProbeBase) enumHits(ctx context.Context, q store.Query, w collect.Window) (map[string][]enumHit, int, error) {
	cfg := b.All.UserIDEnumeration
	ps, dates, err := newProbeSeries(ctx, q, b.pathSources(cfg.Sources), cwlogs.UserProbeIDs, w, cfg.UserBands, cfg.WindowDays())
	if err != nil || ps == nil {
		return nil, 0, err
	}
	load := func(m string) series {
		if err != nil {
			return nil
		}
		var s series
		s, err = ps.load(m)
		return s
	}
	ids, ok, denied, redirects, methods, dist := load(cwlogs.MetricUserIDs), load(cwlogs.MetricUserIDsOK), load(cwlogs.MetricUserIDsDenied),
		load(cwlogs.MetricUserDeniedRedirects), load(cwlogs.MetricUserIDsMethods), load(cwlogs.MetricUserIDsDist)
	if err != nil {
		return nil, 0, err
	}
	excluded := func(tpl string) bool {
		for _, g := range cfg.ExcludeTemplates {
			if m, _ := path.Match(g, tpl); m {
				return true
			}
		}
		return false
	}
	// 型ごとの判定 (key は <kind>:<id>|<型>)
	byKey := map[string]probeHit{}
	wait := 0
	for _, d := range dates {
		if n := ps.waiting(d, cfg.UserBands); n > 0 {
			wait = max(wait, n)
			continue
		}
		for key, v := range ids[d] {
			_, tpl, found := strings.Cut(key, "|")
			if !found || excluded(tpl) {
				continue
			}
			sameTpl := func(k string) bool { _, t, _ := strings.Cut(k, "|"); return t == tpl }
			day, dayOK := ps.daily(ids, key, d, v, cfg.MinDistinct, cfg.UserBands, func(day string) float64 { return dist[day][tpl+"|max"] })
			win, winOK := ps.windowed(ids, key, d, cfg.UserBands, cfg.UserWindow, sumMax(ids, sameTpl))
			h, hit := mergeWindow(day, dayOK, win, winOK)
			if !hit {
				continue
			}
			if cur, seen := byKey[key]; !seen || h.better(cur) {
				byKey[key] = h
			}
		}
	}
	out := map[string][]enumHit{}
	for key, h := range byKey {
		user, tpl, _ := strings.Cut(key, "|")
		e := enumHit{probeHit: h, template: tpl, ok: ok[h.day][key], denied: denied[h.day][key], methods: map[string]float64{}, severity: Medium}
		if x, has := redirects[h.day][key]; has {
			e.redirects, e.hasRedirects = x, true
		}
		for k, v := range methods[h.day] {
			if m, cut := strings.CutPrefix(k, key+"|"); cut && !strings.Contains(m, "|") {
				e.methods[m] = v
			}
		}
		switch {
		case e.denied >= cfg.HighMinDenied && e.ok >= 1:
			e.severity = High
			e.reasons = append(e.reasons, reasonSuccessAmidDenied)
		case e.ok >= 1:
			e.reasons = append(e.reasons, reasonSuccessOnly)
		}
		sort.Strings(e.reasons)
		out[user] = append(out[user], e)
	}
	for u := range out {
		sort.Slice(out[u], func(i, j int) bool {
			a, b := out[u][i], out[u][j]
			if a.value != b.value {
				return a.value > b.value
			}
			return a.template < b.template
		})
	}
	return out, wait, nil
}

// related は、同じ利用者・同じ日に条件を満たした、ほかのチェックの名前 (sources を書いたものだけ)。
func (b userProbeBase) related(ctx context.Context, q store.Query, w collect.Window, self, user, day string) ([]string, error) {
	var out []string
	if self != userDeniedName && len(b.All.UserDenied.Sources) > 0 {
		hits, _, err := b.deniedHits(ctx, q, w)
		if err != nil {
			return nil, err
		}
		if h, ok := hits[user]; ok && h.day == day {
			out = append(out, userDeniedName)
		}
	}
	if self != userIDEnumerationName && len(b.pathSources(b.All.UserIDEnumeration.Sources)) > 0 {
		hits, _, err := b.enumHits(ctx, q, w)
		if err != nil {
			return nil, err
		}
		for _, h := range hits[user] {
			if h.day == day {
				out = append(out, userIDEnumerationName)
				break
			}
		}
	}
	if self != userPathBreadthName && len(b.pathSources(b.All.UserPathBreadth.Sources)) > 0 {
		hits, _, _, err := b.breadthHits(ctx, q, w)
		if err != nil {
			return nil, err
		}
		if h, ok := hits[user]; ok && h.day == day {
			out = append(out, userPathBreadthName)
		}
	}
	return out, nil
}

func probeData(user string, h probeHit) map[string]any {
	d := map[string]any{"user": userOf(user), "day": h.day, "reasons": h.reasons, "value": h.value, "app_band": h.appBand}
	if h.userBand > 0 || containsStr(h.reasons, reasonAboveUserBand) {
		d["user_band"] = h.userBand
	}
	if h.window != nil {
		d["window"] = h.window
	}
	return d
}

func notesFor(name string, wait int) []string {
	if wait > 0 {
		return []string{waitNote(name, wait)}
	}
	return nil
}

func (c UserDenied) EvaluateWithNotes(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, []string, error) {
	hits, wait, err := c.deniedHits(ctx, q, w)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]Observation{}
	statuses := intList(c.All.UserDenied.Statuses)
	for user, h := range hits {
		data := probeData(user, h)
		rel, err := c.related(ctx, q, w, c.Name(), user, h.day)
		if err != nil {
			return nil, nil, err
		}
		if len(rel) > 0 {
			data["related"] = rel
		}
		summary := fmt.Sprintf("%s の拒否 (%s) が 1 日に %.0f 件 (%s UTC。ふだんの最多の利用者の %.0f 倍の帯 %.0f)", user, statuses, h.value, h.day, c.All.UserDenied.AppFactor, h.appBand)
		if h.window != nil && !containsStr(h.reasons, reasonAboveAppBand) {
			summary = fmt.Sprintf("%s の拒否 (%s) が直近 %d 日に %.0f 件 (%d 日に分けて。%s UTC まで)", user, statuses, h.window["days"], h.window["sum"], h.window["days_with_value"], h.day)
		}
		out[user] = Observation{Check: c.Name(), Key: user, Severity: Medium, Summary: summary, Fingerprint: fingerprint(Medium, nil, strings.Join(h.reasons, ",")), Data: data}
	}
	return sortedObs(out), notesFor(c.Name(), wait), nil
}

func (c UserIDEnumeration) EvaluateWithNotes(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, []string, error) {
	hits, wait, err := c.enumHits(ctx, q, w)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]Observation{}
	for user, hs := range hits {
		top := hs[0]
		sev := Medium
		reasons := map[string]bool{}
		var tpls []map[string]any
		for i, h := range hs {
			if h.severity.Rank() > sev.Rank() {
				sev = h.severity
			}
			for _, r := range h.reasons {
				reasons[r] = true
			}
			if i >= maxProbeTemplates {
				continue
			}
			t := map[string]any{"template": h.template, "day": h.day, "ids": h.value, "ids_ok": h.ok, "ids_denied": h.denied, "methods": h.methods,
				"reasons": h.reasons, "app_band": h.appBand}
			if h.userBand > 0 || containsStr(h.reasons, reasonAboveUserBand) {
				t["user_band"] = h.userBand
			}
			if h.hasRedirects {
				t["denied_redirects"] = h.redirects
			}
			if h.window != nil {
				t["window"] = h.window
			}
			tpls = append(tpls, t)
		}
		data := map[string]any{"user": userOf(user), "day": top.day, "reasons": sortedKeys(reasons), "templates": tpls, "templates_matched": len(hs)}
		rel, err := c.related(ctx, q, w, c.Name(), user, top.day)
		if err != nil {
			return nil, nil, err
		}
		if len(rel) > 0 {
			data["related"] = rel
		}
		summary := fmt.Sprintf("%s が %s で 1 日に %.0f の異なる ID を開き、%.0f が拒否・%.0f が成功 (%s UTC。ふだんの最多の利用者の帯 %.0f)",
			user, top.template, top.value, top.denied, top.ok, top.day, top.appBand)
		if top.window != nil && !containsStr(top.reasons, reasonAboveAppBand) {
			summary = fmt.Sprintf("%s が %s で直近 %d 日に延べ %.0f の異なる ID を開いた (%d 日に分けて。%s UTC まで)", user, top.template, top.window["days"], top.window["sum"], top.window["days_with_value"], top.day)
		}
		if len(hs) > 1 {
			summary += fmt.Sprintf("。ほかに %d の型", len(hs)-1)
		}
		var fp []string
		for _, h := range hs {
			fp = append(fp, h.template+":"+strings.Join(h.reasons, "+"))
		}
		sort.Strings(fp)
		out[user] = Observation{Check: c.Name(), Key: user, Severity: sev, Summary: summary, Fingerprint: fingerprint(sev, nil, strings.Join(fp, ",")), Data: data}
	}
	return sortedObs(out), notesFor(c.Name(), wait), nil
}

func (c UserPathBreadth) EvaluateWithNotes(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, []string, error) {
	hits, wait, extra, err := c.breadthHits(ctx, q, w)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]Observation{}
	for user, h := range hits {
		data := probeData(user, h)
		data["templates_ok"] = extra[h.day][cwlogs.MetricUserTemplatesOK+"|"+user]
		data["templates_denied"] = extra[h.day][cwlogs.MetricUserTemplatesDenied+"|"+user]
		data["templates_not_found"] = extra[h.day][cwlogs.MetricUserTemplatesNotFound+"|"+user]
		rel, err := c.related(ctx, q, w, c.Name(), user, h.day)
		if err != nil {
			return nil, nil, err
		}
		if len(rel) > 0 {
			data["related"] = rel
		}
		summary := fmt.Sprintf("%s が 1 日に %.0f の型のパスに触った (%s UTC。拒否 %.0f・404 %.0f の型。ふだんの最多の利用者の帯 %.0f)",
			user, h.value, h.day, data["templates_denied"], data["templates_not_found"], h.appBand)
		out[user] = Observation{Check: c.Name(), Key: user, Severity: Low, Summary: summary, Fingerprint: fingerprint(Low, nil, strings.Join(h.reasons, ",")), Data: data}
	}
	return sortedObs(out), notesFor(c.Name(), wait), nil
}

func intList(l []int) string {
	parts := make([]string, len(l))
	for i, v := range l {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, "・")
}

func containsStr(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
