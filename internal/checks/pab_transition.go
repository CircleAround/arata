package checks

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// Public Access Block の変更を、前の状態と比べて分ける (ADR 0086)。
//
// 決定:
//   - 比べる相手は、操作の時刻より前のうち最も新しい材料 1 つだけ。材料は weekly の posture の snapshot (アカウント単位だけ) と、
//     同じ対象への成功した前の Put / Delete の記録。最も新しい材料が読めなければ「分からない」にし、古い材料に戻らない
//   - 記録と snapshot が同じ時刻なら記録を使う。snapshot は取得した時刻が操作より前のときだけ使う
//   - ストアから読み戻した値は、4 項目の名前と真偽値だけに絞る (知らない名前は捨て、形が合わなければ「分からない」)
//   - posture の s3_public_access_block が複数 (複数のソース) あるときは、どれが同じアカウントか決められないので「読めない」にする
//     (安全な側。medium)

// 判定 (data.transition)。
const (
	pabOpened       = "opened"
	pabTightened    = "tightened"
	pabPriorUnknown = "prior_unknown"
)

// 前の状態の出どころ (data.prior_source)。
const (
	pabSourceSnapshot   = "snapshot"
	pabSourceEvent      = "event"
	pabSourceNone       = "none"
	pabSourceUnreadable = "unreadable"
)

// pabFields は Public Access Block の 4 項目 (この順で並べる。collector の pab_enabled / pab_disabled と同じ)。
var pabFields = []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}

// pabSnapshotKeys は posture の snapshot (account.Posture.publicAccessBlock) の、4 項目の data のキー。
var pabSnapshotKeys = map[string]string{
	"BlockPublicAcls": "block_public_acls", "IgnorePublicAcls": "ignore_public_acls",
	"BlockPublicPolicy": "block_public_policy", "RestrictPublicBuckets": "restrict_public_buckets",
}

var pabAPINames = []string{"PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock", "PutPublicAccessBlock", "DeletePublicAccessBlock",
	"PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock"}

func isPABAPI(name string) bool {
	for _, n := range pabAPINames {
		if n == name {
			return true
		}
	}
	return false
}

// pabTarget は S3 の操作の対象 (Key の資源)。アカウント単位の操作は account、ほかはバケットの名前。
func pabTarget(name string, d map[string]any) string {
	if strings.Contains(name, "Account") {
		return "account"
	}
	return dataStr(d, "bucket")
}

// pabMaterial は前の状態の材料 1 つ。known のとき configured と enabled が前の状態。
type pabMaterial struct {
	source     string // pabSource*
	time       time.Time
	api        string // source が event のとき
	known      bool
	configured bool
	enabled    map[string]bool
}

// pabRequestOf は Put*PublicAccessBlock の data から、4 項目の true / false を読む。読めなければ ok=false。
//   - pab_parsed が true: pab_enabled と pab_disabled が重ならず、合わせて 4 項目ちょうどのときだけ読める
//   - pab_parsed が無い (前の版で集めた記録): pab_disabled に 4 項目の名前があれば、残りを true とみなす。無ければ読めない
func pabRequestOf(d map[string]any) (map[string]bool, bool) {
	valid := func(l []string) []string {
		var out []string
		for _, n := range l {
			if _, ok := pabSnapshotKeys[n]; ok {
				out = append(out, n)
			}
		}
		return out
	}
	on := map[string]bool{}
	if p, _ := dataBool(d, "pab_parsed"); p {
		en, dis := dataStrings(d, "pab_enabled"), dataStrings(d, "pab_disabled")
		seen := map[string]bool{}
		for _, n := range en {
			if _, ok := pabSnapshotKeys[n]; !ok || seen[n] {
				return nil, false
			}
			seen[n], on[n] = true, true
		}
		for _, n := range dis {
			if _, ok := pabSnapshotKeys[n]; !ok || seen[n] {
				return nil, false
			}
			seen[n] = true
		}
		if len(seen) != len(pabFields) {
			return nil, false
		}
		return on, true
	}
	off := valid(dataStrings(d, "pab_disabled"))
	if len(off) == 0 {
		return nil, false
	}
	for _, n := range pabFields {
		on[n] = true
	}
	for _, n := range off {
		on[n] = false
	}
	for n, v := range on {
		if !v {
			delete(on, n)
		}
	}
	return on, true
}

// pabMaterialOfEvent は前の Put / Delete の記録から材料を作る。
func pabMaterialOfEvent(e record.TrailEvent) pabMaterial {
	m := pabMaterial{source: pabSourceEvent, time: e.Time, api: "s3:" + e.Name}
	if strings.HasPrefix(e.Name, "Delete") {
		m.known, m.enabled = true, map[string]bool{}
		return m
	}
	on, ok := pabRequestOf(e.Data)
	if !ok {
		m.source = pabSourceUnreadable
		return m
	}
	m.known, m.configured, m.enabled = true, true, on
	return m
}

// pabMaterialOfSnapshot は posture の s3_public_access_block から材料を作る。
func pabMaterialOfSnapshot(it record.SnapshotItem) pabMaterial {
	m := pabMaterial{source: pabSourceUnreadable, time: it.Time}
	if account.IsUnknown(it) {
		return m
	}
	conf, ok := dataBool(it.Data, "configured")
	if !ok {
		return m
	}
	on := map[string]bool{}
	if conf {
		for _, n := range pabFields {
			v, ok := dataBool(it.Data, pabSnapshotKeys[n])
			if !ok {
				return m
			}
			if v {
				on[n] = true
			}
		}
	}
	m.source, m.known, m.configured, m.enabled = pabSourceSnapshot, true, conf, on
	return m
}

// pabHistory はチェックの中で 1 回だけ引いた前の状態の材料。
type pabHistory struct {
	snap   *pabMaterial
	events map[string][]pabMaterial // 対象 → 時刻の順
}

// loadPABHistory は窓の Put / Delete の評価に使う材料を引く。窓に該当する操作が無ければ引かない。
// 前の記録を探す範囲は、すべての操作より前の snapshot があればその時刻から、無ければ保存済みのすべて (ADR 0086 の 1 節)。
func loadPABHistory(ctx context.Context, q store.Query, w collect.Window, evs []record.TrailEvent) (*pabHistory, error) {
	h := &pabHistory{events: map[string][]pabMaterial{}}
	var first time.Time
	for _, e := range evs {
		if e.EventSource == srcS3 && e.ErrorCode == "" && isPABAPI(e.Name) && (first.IsZero() || e.Time.Before(first)) {
			first = e.Time
		}
	}
	if first.IsZero() {
		return h, nil
	}
	items, err := q.Snapshot(ctx, record.KindPostureItem)
	if err != nil {
		return nil, err
	}
	var found []record.SnapshotItem
	for _, it := range items {
		if it.Key == account.PostureS3PublicAccess {
			found = append(found, it)
		}
	}
	switch len(found) {
	case 0:
	case 1:
		m := pabMaterialOfSnapshot(found[0])
		h.snap = &m
	default:
		m := pabMaterial{source: pabSourceUnreadable}
		for _, it := range found {
			if it.Time.After(m.time) {
				m.time = it.Time
			}
		}
		h.snap = &m
	}
	var from time.Time
	if h.snap != nil && h.snap.time.Before(first) {
		from = h.snap.time
	}
	past, err := q.Events(ctx, from, w.To, store.EventFilter{EventSources: []string{srcS3}, Names: pabAPINames})
	if err != nil {
		return nil, err
	}
	for _, e := range past {
		if e.ErrorCode != "" {
			continue
		}
		t := pabTarget(e.Name, e.Data)
		h.events[t] = append(h.events[t], pabMaterialOfEvent(e))
	}
	for _, l := range h.events {
		sort.SliceStable(l, func(i, j int) bool { return l[i].time.Before(l[j].time) })
	}
	return h, nil
}

// prior は target への、時刻 at より前で最も新しい材料。無ければ source が none。
func (h *pabHistory) prior(target string, at time.Time) pabMaterial {
	var ev *pabMaterial
	if h != nil {
		l := h.events[target]
		for i := len(l) - 1; i >= 0; i-- {
			if l[i].time.Before(at) {
				ev = &l[i]
				break
			}
		}
	}
	var snap *pabMaterial
	if h != nil && target == "account" && h.snap != nil && h.snap.time.Before(at) {
		snap = h.snap
	}
	switch {
	case ev != nil && (snap == nil || !ev.time.Before(snap.time)):
		return *ev
	case snap != nil:
		return *snap
	}
	return pabMaterial{source: pabSourceNone}
}

// pabResult は 1 回の操作の判定。sev が空なら報告しない。
type pabResult struct {
	transition    string
	sev           Severity
	deleted       bool
	disabled      []string // 今回 false の項目
	enabled       []string
	newlyEnabled  []string
	newlyDisabled []string
	stillDisabled []string
}

// pabJudge は前の状態 (prior) と今回の要求から判定する (ADR 0086 の 2 節の表)。設定なしは 4 項目すべて false と同じに扱う。
func pabJudge(prior pabMaterial, deleted bool, cur map[string]bool, readable bool) pabResult {
	if deleted {
		return pabResult{transition: pabOpened, sev: High, deleted: true}
	}
	if !readable {
		return pabResult{}
	}
	r := pabResult{}
	for _, n := range pabFields {
		if cur[n] {
			r.enabled = append(r.enabled, n)
		} else {
			r.disabled = append(r.disabled, n)
		}
	}
	if len(r.disabled) == 0 {
		return pabResult{}
	}
	if !prior.known {
		r.transition, r.sev = pabPriorUnknown, Medium
		return r
	}
	r.newlyEnabled, r.newlyDisabled, r.stillDisabled = []string{}, []string{}, []string{}
	for _, n := range pabFields {
		was := prior.configured && prior.enabled[n]
		switch {
		case was && !cur[n]:
			r.newlyDisabled = append(r.newlyDisabled, n)
		case !was && cur[n]:
			r.newlyEnabled = append(r.newlyEnabled, n)
		case !was && !cur[n]:
			r.stillDisabled = append(r.stillDisabled, n)
		}
	}
	switch {
	case len(r.newlyDisabled) > 0:
		r.transition, r.sev = pabOpened, High
	case len(r.newlyEnabled) > 0:
		r.transition, r.sev = pabTightened, Info
	default:
		return pabResult{}
	}
	return r
}

// exposure は Key の「開いた中身」(ADR 0086 の 5 節)。opened は今までと同じ形。
func (r pabResult) exposure() string {
	switch {
	case r.deleted:
		return "deleted"
	case r.transition == pabTightened:
		return pabTightened + ":" + strings.Join(withSuffix(r.newlyEnabled, "=true"), ",")
	case r.transition == pabPriorUnknown:
		return pabPriorUnknown + ":" + strings.Join(withSuffix(r.disabled, "=false"), ",")
	}
	return strings.Join(withSuffix(r.disabled, "=false"), ",")
}

// putData は data に判定と前の状態を書く (ADR 0086 の 4 節)。
func (r pabResult) putData(d map[string]any, prior pabMaterial) {
	d["transition"] = r.transition
	d["prior_source"] = prior.source
	if prior.source != pabSourceNone {
		d["prior_time"] = prior.time.UTC().Format(time.RFC3339)
	}
	if prior.api != "" {
		d["prior_api"] = prior.api
	}
	if prior.known {
		d["prior_configured"] = prior.configured
		pe := []string{}
		for _, n := range pabFields {
			if prior.configured && prior.enabled[n] {
				pe = append(pe, n)
			}
		}
		d["prior_enabled"] = pe
	}
	if r.deleted {
		return
	}
	d["enabled"] = nonNilStrings(r.enabled)
	if prior.known {
		d["newly_enabled"] = r.newlyEnabled
		d["newly_disabled"] = r.newlyDisabled
		d["still_disabled"] = r.stillDisabled
	}
}

func withSuffix(l []string, suffix string) []string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = s + suffix
	}
	return out
}

func nonNilStrings(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}
