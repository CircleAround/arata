package checks

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// PrincipalNewSource は既知の主体 (承認済み・ベースライン) が、初めての送信元・リージョンから使われたことを報告する (ADR 0027)。
// アクセスキーの漏洩の典型 (new_principal は主体の初出しか見ない)。
//
// 決定:
//   - 材料は cloudtrail collector の主体の活動の日次集計 (record.MetricPrincipalSource など)。評価する日は窓に重なる UTC の日、
//     過去は窓の始まりの日の前日から baseline_days 日。値は下限なので、判定は「その日に有ったか」と書き込みの件数 (下限) にだけ使う
//   - 送信元は /24 (IPv4) / /48 (IPv6) で比べる。送信元が IP でないもの (サービス名・"AWS Internal") は collector が数えない。
//     allowlist の source_ips の内の送信元は新しい送信元にしない
//   - リージョンは成功した書き込みのあったリージョン。その主体が過去に書き込みをしていないリージョンでの書き込みを新しいリージョンとする
//   - 対象は IAM ユーザーとロール (のセッション) のうち既知のもの。未承認・期限切れは new_principal が扱う。サービス主体と root は数えない。
//     過去 baseline_days に活動が無く、その間に初めて現れた主体は「すべてが初めて」なので報告しない (new_principal・承認の流れが扱う)。
//     それより前から居て、過去 baseline_days に活動の無かった主体 (休眠していたキー) は報告する (active_in_baseline: false)
//   - 重大度: 新しい送信元だけ → low。新しい送信元からの書き込みが min_writes 以上、または新しいリージョンでの書き込み → medium。
//     新しい送信元 + 同じ窓で access_denied の観測もある → high
//   - access_denied との相関は、同じ (store, 窓, allowlist) で AccessDenied の Evaluate を呼んで得る (チェックは互いの結果を見られないため)。
//     access_denied がプロファイルに入っていなくても相関の材料として呼ぶ。access_denied の finding は出さない (ここで返すのは観測だけ)
//   - allowlist の主体の dynamic_source: true (CI のランナーなど送信元が毎回変わる主体) は low を出さない (medium 以上は出す)。
//     AWS のサービスが引き受けるロール (保存済みの AssumeRole の呼び出し元がサービス主体。Lambda・ECS のタスク・EC2 のインスタンスプロファイル) も同じ扱い
//     (送信元が AWS の管理する NAT などで毎回変わるため。持ち出したセッションの悪用は、書き込み・新しいリージョン・拒否で medium 以上として拾う)
//   - CloudTrail を収集し終えた過去日 (collectedDays。活動の有無ではない) が min_baseline_days 未満の間 (導入直後) は報告しない。
//     収集済みで日次集計の無い日は「活動なし」(操作の少ないアカウントでも判定する)
//   - 国の判定はしない (未決)。new_sources の要素は map なので、将来 country を足せる
type PrincipalNewSource struct {
	Config       config.PrincipalNewSource
	AccessDenied config.AccessDenied
}

func (PrincipalNewSource) Name() string     { return "principal_new_source" }
func (PrincipalNewSource) Cadence() Cadence { return Daily }
func (PrincipalNewSource) Mode() Mode       { return ModeEvent }
func (PrincipalNewSource) Needs() []record.Kind {
	return []record.Kind{record.KindTrailEvent, record.KindPrincipalSeen}
}

const maxNewSourceIPs = 10

// 重大度の理由 (Data の reasons)。
const (
	reasonNewSource       = "new_source"
	reasonNewSourceWrites = "new_source_writes"
	reasonNewRegion       = "new_region"
	reasonAccessDenied    = "access_denied"
)

type newSource struct {
	events, writes float64
}

func (c PrincipalNewSource) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	dates := windowDates(w)
	if len(dates) == 0 {
		return nil, nil
	}
	b := c.Config
	day0 := dates[0]
	bds := baseDates(day0, b.BaselineDays)
	withData, err := collectedDays(ctx, q, bds)
	if err != nil {
		return nil, err
	}
	if withData < b.MinBaselineDays {
		return nil, nil
	}
	from, to := addDays(day0, -b.BaselineDays), dates[len(dates)-1]
	src, err := loadSeries(ctx, q, record.MetricPrincipalSource, from, to)
	if err != nil {
		return nil, err
	}
	srcW, err := loadSeries(ctx, q, record.MetricPrincipalSourceWrites, from, to)
	if err != nil {
		return nil, err
	}
	reg, err := loadSeries(ctx, q, record.MetricPrincipalWriteRegion, from, to)
	if err != nil {
		return nil, err
	}

	// 過去: 主体 → 送信元 / 書き込みのリージョン
	pastSrc, pastReg := map[string]map[string]bool{}, map[string]map[string]bool{}
	active := map[string]bool{}
	mark := func(m map[string]map[string]bool, key string) {
		arn, v, ok := record.SplitActivityKey(key)
		if !ok {
			return
		}
		if m[arn] == nil {
			m[arn] = map[string]bool{}
		}
		m[arn][v] = true
		active[arn] = true
	}
	for _, d := range bds {
		for k := range src[d] {
			mark(pastSrc, k)
		}
		for k := range reg[d] {
			mark(pastReg, k)
		}
	}
	// 窓: 主体 → 新しい送信元 / 新しいリージョン
	newSrc := map[string]map[string]*newSource{}
	newReg := map[string]map[string]float64{}
	for _, d := range dates {
		for k, v := range src[d] {
			arn, prefix, ok := record.SplitActivityKey(k)
			if !ok || pastSrc[arn][prefix] {
				continue
			}
			if newSrc[arn] == nil {
				newSrc[arn] = map[string]*newSource{}
			}
			ns := newSrc[arn][prefix]
			if ns == nil {
				ns = &newSource{}
				newSrc[arn][prefix] = ns
			}
			ns.events += v
			ns.writes += srcW[d][k]
		}
		for k, v := range reg[d] {
			arn, region, ok := record.SplitActivityKey(k)
			if !ok || pastReg[arn][region] {
				continue
			}
			if newReg[arn] == nil {
				newReg[arn] = map[string]float64{}
			}
			newReg[arn][region] += v
		}
	}
	if len(newSrc) == 0 && len(newReg) == 0 {
		return nil, nil
	}

	ps, err := q.Principals(ctx, store.PrincipalFilter{})
	if err != nil {
		return nil, err
	}
	byARN := map[string]store.Principal{}
	for _, p := range ps {
		byARN[p.ARN] = p
	}
	deniedObs, err := AccessDenied{Config: c.AccessDenied}.Evaluate(ctx, q, w, al)
	if err != nil {
		return nil, err
	}
	denied := map[string]bool{}
	for _, o := range deniedObs {
		denied[o.Key] = true
	}
	baseStart, _ := time.Parse(record.DateLayout, from)
	serviceRoles, err := serviceAssumedRoles(ctx, q, baseStart, w.To)
	if err != nil {
		return nil, err
	}

	arns := map[string]bool{}
	for arn := range newSrc {
		arns[arn] = true
	}
	for arn := range newReg {
		arns[arn] = true
	}
	obs := map[string]Observation{}
	for arn := range arns {
		p, ok := byARN[arn]
		if !ok {
			continue
		}
		switch p.Kind {
		case record.PrincipalUser, record.PrincipalAssumedRole, record.PrincipalRole:
		default:
			continue
		}
		entry, status := al.Principal(arn, w.To)
		known := status == allowlist.StatusApproved || (status == allowlist.StatusUnknown && (p.Status == store.PrincipalBaseline || p.Status == store.PrincipalApproved))
		if !known {
			continue
		}
		if !active[arn] && !p.FirstSeen.Before(baseStart) {
			continue
		}
		ips, err := q.PrincipalIPs(ctx, arn)
		if err != nil {
			return nil, err
		}
		recent := map[string][]string{} // 送信元 → 窓の日に観測した IP
		for _, ip := range ips {
			if ip.LastSeen.Before(dayOf(w.From)) {
				continue
			}
			if pf, ok := record.SourcePrefix(ip.IP); ok {
				recent[pf] = append(recent[pf], ip.IP)
			}
		}
		var sources []map[string]any
		var prefixes []string
		var writes float64
		for prefix, ns := range newSrc[arn] {
			if allowedSource(al, prefix, recent[prefix]) {
				continue
			}
			prefixes = append(prefixes, prefix)
			writes += ns.writes
		}
		sort.Strings(prefixes)
		for _, prefix := range prefixes {
			ns := newSrc[arn][prefix]
			m := map[string]any{"prefix": prefix, "events": ns.events, "writes": ns.writes}
			if l := recent[prefix]; len(l) > 0 {
				sort.Strings(l)
				m["ips"] = capList(l, maxNewSourceIPs)
			}
			sources = append(sources, m)
		}
		regions := make([]string, 0, len(newReg[arn]))
		for r := range newReg[arn] {
			regions = append(regions, r)
		}
		sort.Strings(regions)

		var reasons []string
		var sev Severity
		if len(prefixes) > 0 {
			sev = Low
			reasons = append(reasons, reasonNewSource)
			if writes >= float64(b.MinWrites) {
				sev = Medium
				reasons = append(reasons, reasonNewSourceWrites)
			}
		}
		if len(regions) > 0 {
			sev = maxSev(sev, Medium)
			reasons = append(reasons, reasonNewRegion)
		}
		if len(prefixes) > 0 && denied[arn] {
			sev = High
			reasons = append(reasons, reasonAccessDenied)
		}
		dynamic := entry != nil && status == allowlist.StatusApproved && entry.DynamicSource
		if sev == "" || (sev == Low && (dynamic || serviceRoles[arn])) {
			continue
		}

		data := map[string]any{
			"principal":               arn,
			"principal_kind":          string(p.Kind),
			"allowlist_status":        string(status),
			"reasons":                 reasons,
			"writes_from_new_sources": writes,
			"access_denied":           denied[arn],
			"active_in_baseline":      active[arn],
			"baseline_days":           b.BaselineDays,
			"baseline_days_with_data": withData,
			"min_writes":              b.MinWrites,
		}
		if dynamic {
			data["dynamic_source"] = true
		}
		if serviceRoles[arn] {
			data["service_assumed"] = true
		}
		if len(sources) > 0 {
			data["new_sources"] = sources
		}
		if len(regions) > 0 {
			rs := make([]map[string]any, len(regions))
			for i, r := range regions {
				rs[i] = map[string]any{"region": r, "writes": newReg[arn][r]}
			}
			data["new_regions"] = rs
		}
		markAccountOnly(data, "principal_identity", arn, p.Kind)
		var parts []string
		if len(prefixes) > 0 {
			parts = append(parts, fmt.Sprintf("初めての送信元 %s から使われた (書き込み %.0f 件)", strings.Join(prefixes, ", "), writes))
		}
		if len(regions) > 0 {
			parts = append(parts, fmt.Sprintf("初めてのリージョン %s で書き込み", strings.Join(regions, ", ")))
		}
		if !active[arn] {
			parts = append(parts, fmt.Sprintf("過去 %d 日は使われていなかった", b.BaselineDays))
		}
		if len(prefixes) > 0 && denied[arn] {
			parts = append(parts, "同じ窓で拒否された呼び出しの急増 (access_denied) も出ている")
		}
		summary := fmt.Sprintf("既知の主体の新しい送信元: %s が%s", record.PrincipalLabel(arn, p.Kind), strings.Join(parts, "。"))
		obs[arn] = Observation{Check: c.Name(), Key: arn, Severity: sev, Summary: summary, Data: data,
			Fingerprint: fingerprint(sev, nil, strings.Join(prefixes, ","), strings.Join(regions, ","))}
	}
	return sortedObs(obs), nil
}

// serviceAssumedRoles は [from, to) に AWS のサービス (Lambda・ECS・EC2 など) が AssumeRole で引き受けたロール (保存済みの注目イベントの role_arn)。
// これらのセッションの送信元は AWS が管理する NAT などで毎回変わるので、dynamic_source と同じく low を出さない。
func serviceAssumedRoles(ctx context.Context, q store.Query, from, to time.Time) (map[string]bool, error) {
	evs, err := q.Events(ctx, from, to, store.EventFilter{NamePrefixes: []string{"AssumeRole"}, PrincipalKinds: []record.PrincipalKind{record.PrincipalService}})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range evs {
		if r := dataStr(e.Data, "role_arn"); r != "" && e.ErrorCode == "" {
			out[r] = true
		}
	}
	return out, nil
}

// allowedSource は送信元が allowlist の source_ips の内か: 窓で観測した IP がすべて内か、IP が分からなければネットワークの先頭のアドレスが内か。
func allowedSource(al *allowlist.List, prefix string, ips []string) bool {
	if len(ips) == 0 {
		p, err := netip.ParsePrefix(prefix)
		return err == nil && al.SourceIPAllowed(p.Addr().String())
	}
	for _, ip := range ips {
		if !al.SourceIPAllowed(ip) {
			return false
		}
	}
	return true
}

func maxSev(a, b Severity) Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}
