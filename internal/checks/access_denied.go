package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// AccessDenied は拒否された API 呼び出しの急増 (権限の列挙の兆候) を主体ごとに報告する (ADR 0021)。
//
// 決定:
//   - 拒否は CloudTrail の errorCode が設定 error_codes に入るもの (完全一致)。cloudtrail collector が events に残す。
//   - 評価するのは窓のイベント (windowEvents。再走査で遅れて届いた分を含み、重なり区間の評価済み分は含めない)。
//     daily の窓は 24 時間なので UTC の丸 1 日と比べる。UTC の日で分けないのは、日をまたぐ列挙が割れて閾値を下回るのを防ぐため。
//   - 平常帯は窓の始まりの日の前日から baseline_days 日の、その主体自身の日ごとの件数・異なり数 (無い日は 0) の中央値 × factor。
//     拒否のある過去日が min_baseline_days 未満 (導入直後) は平常帯を 0 とみなし、絶対の閾値だけで判定する。
//   - 幅: 拒否された API (eventSource:eventName) の種類が min_distinct_apis 以上かつ平常帯を超える → medium。high_distinct_apis 以上なら high。
//   - 量: 件数が max(min_count, 中央値 × factor) を超える → medium。両方満たせば重い方を 1 件 (Data の threshold は breadth)。
//   - サービスリンクロール (ARN が :role/aws-service-role/ を含む) は窓にも平常帯にも数えない。AWS のサービスしか引き受けられず、
//     権限も利用者が変えられないので、拒否は仕様由来のノイズで列挙の兆候に当たらない。設定にせず固定の規則 (events の保存は変えない)。
//   - サービス主体と root (root_usage が扱う) は除く。allowlist で承認済みでも除かない (承認は「居ること」を認めるもので、権限を探ってよいではない)。
//   - 想定済みの拒否 (allowlist の expected_denied。窓の終わりの時点で期限内の項目) は数える前に除く。窓にも平常帯にも同じく適用する
//     (平常帯に残すと、ふだんの想定内の拒否で平常帯が膨らみ、想定外の拒否が吸収されるため)。窓で除いた件数は Data の
//     expected_denied_excluded に残す (ADR 0022)。
type AccessDenied struct {
	Config config.AccessDenied
}

func (AccessDenied) Name() string         { return "access_denied" }
func (AccessDenied) Cadence() Cadence     { return Daily }
func (AccessDenied) Mode() Mode           { return ModeEvent }
func (AccessDenied) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

const (
	deniedBreadth = "breadth"
	deniedVolume  = "volume"
	maxDeniedAPIs = 10
)

// deniedAPI は eventSource の .amazonaws.com を落とした「サービス:操作」。
func deniedAPI(e record.TrailEvent) string {
	return strings.TrimSuffix(e.EventSource, ".amazonaws.com") + ":" + e.Name
}

// isServiceLinkedRole はサービスリンクロール (IAM のパスが /aws-service-role/ のロール) の ARN か。
// assumed-role のセッションはロールの ARN にまとまっているので ARN だけで判る。
func isServiceLinkedRole(arn string) bool {
	return strings.Contains(arn, ":role/aws-service-role/")
}

func deniedTarget(e record.TrailEvent) bool {
	return e.PrincipalARN != "" && !isServiceLinkedRole(e.PrincipalARN) && e.PrincipalKind != record.PrincipalService && e.PrincipalKind != record.PrincipalRoot
}

func (c AccessDenied) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	f := store.EventFilter{ErrorCodes: c.Config.ErrorCodes}
	evs, err := windowEvents(ctx, q, w, f)
	if err != nil {
		return nil, err
	}
	type cur struct {
		agg   *eventAgg
		kind  record.PrincipalKind
		apis  map[string]int
		codes map[string]bool
	}
	expected := func(e record.TrailEvent) bool { return al.DeniedExpected(e.PrincipalARN, deniedAPI(e), w.To) }
	byP := map[string]*cur{}
	excluded := map[string]int{}
	for _, e := range evs {
		if !deniedTarget(e) {
			continue
		}
		if expected(e) {
			excluded[e.PrincipalARN]++
			continue
		}
		p, ok := byP[e.PrincipalARN]
		if !ok {
			p = &cur{agg: newEventAgg(), kind: e.PrincipalKind, apis: map[string]int{}, codes: map[string]bool{}}
			byP[e.PrincipalARN] = p
		}
		p.agg.add(e.Time, "", e.IP)
		p.apis[deniedAPI(e)]++
		p.codes[e.ErrorCode] = true
	}
	if len(byP) == 0 {
		return nil, nil
	}

	// 平常帯: 主体 → 日 → (件数, API の集合)
	b := c.Config.Baseline
	day0 := dayOf(w.From)
	past, err := q.Events(ctx, day0.AddDate(0, 0, -b.BaselineDays), day0, f)
	if err != nil {
		return nil, err
	}
	type daily struct {
		count int
		apis  map[string]bool
	}
	hist := map[string]map[string]*daily{}
	datesWithData := map[string]bool{}
	for _, e := range past {
		date := e.Time.UTC().Format(record.DateLayout)
		datesWithData[date] = true
		if !deniedTarget(e) || expected(e) {
			continue
		}
		if hist[e.PrincipalARN] == nil {
			hist[e.PrincipalARN] = map[string]*daily{}
		}
		dd := hist[e.PrincipalARN][date]
		if dd == nil {
			dd = &daily{apis: map[string]bool{}}
			hist[e.PrincipalARN][date] = dd
		}
		dd.count++
		dd.apis[deniedAPI(e)] = true
	}
	useBaseline := len(datesWithData) >= b.MinBaselineDays
	bds := baseDates(day0.Format(record.DateLayout), b.BaselineDays)

	obs := map[string]Observation{}
	for arn, p := range byP {
		var medCount, medDistinct float64
		if useBaseline {
			counts := make([]float64, 0, len(bds))
			distincts := make([]float64, 0, len(bds))
			for _, bd := range bds {
				if dd := hist[arn][bd]; dd != nil {
					counts = append(counts, float64(dd.count))
					distincts = append(distincts, float64(len(dd.apis)))
				} else {
					counts = append(counts, 0)
					distincts = append(distincts, 0)
				}
			}
			medCount, medDistinct = median(counts), median(distincts)
		}
		distinct := len(p.apis)
		breadthThr := medDistinct * b.Factor
		volumeThr := medCount * b.Factor
		if volumeThr < b.MinCount {
			volumeThr = b.MinCount
		}
		var sev Severity
		var reason string
		switch {
		case distinct >= c.Config.MinDistinctAPIs && float64(distinct) > breadthThr:
			sev, reason = Medium, deniedBreadth
			if distinct >= c.Config.HighDistinctAPIs {
				sev = High
			}
		case float64(p.agg.count) > volumeThr:
			sev, reason = Medium, deniedVolume
		default:
			continue
		}

		_, status := al.Principal(arn, w.To)
		a := p.agg
		a.extra["principal"] = arn
		a.extra["principal_kind"] = string(p.kind)
		a.extra["allowlist_status"] = string(status)
		a.extra["distinct_apis"] = distinct
		a.extra["expected_denied_excluded"] = excluded[arn]
		a.extra["apis"] = topAPIs(p.apis, maxDeniedAPIs)
		a.extra["error_codes"] = sortedKeys(p.codes)
		a.extra["baseline_median_count"] = medCount
		a.extra["baseline_median_distinct"] = medDistinct
		a.extra["baseline_days_with_data"] = len(datesWithData)
		a.extra["breadth_threshold"] = breadthThr
		a.extra["volume_threshold"] = volumeThr
		a.extra["threshold"] = reason
		if acct, ok := record.ExternalAccount(arn, p.kind); ok {
			a.extra["external_account"] = acct
		}
		label := record.PrincipalLabel(arn, p.kind)
		summary := fmt.Sprintf("拒否された API 呼び出し: %s が %d 種類 (%d 件) で拒否 (列挙の兆候)", label, distinct, a.count)
		if reason == deniedVolume {
			summary = fmt.Sprintf("拒否された API 呼び出し: %s が %d 件 (%d 種類) で拒否 (平常 %.1f 件、閾値 %.0f 件)", label, a.count, distinct, medCount, volumeThr)
		}
		obs[arn] = Observation{Check: c.Name(), Key: arn, Severity: sev, Summary: summary,
			Fingerprint: fingerprint(sev, a.ips), Data: a.data()}
	}
	return sortedObs(obs), nil
}

// topAPIs は件数の多い順 (同数は名前順) に最大 n 個を "iam:ListUsers × 3" の形で返す。
func topAPIs(m map[string]int, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = fmt.Sprintf("%s × %d", k, m[k])
	}
	return out
}
