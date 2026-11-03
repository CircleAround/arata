package checks

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

// 提案の段階 (schema.Proposal.Stage)。
const (
	StageCountFirst = "count_first" // まず COUNT で様子を見る
	StageReview     = "review"      // 人が見直す (変更は勧めない)
	StageNone       = "none"        // observation (提案なし)
)

// 候補の種類 (schema.Proposal.Kind)。
const (
	ProposalFalsePositive = "false_positive"
	ProposalProbeAllowed  = "probe_allowed"
	ProposalRateMissing   = "rate_limit_missing"
	ProposalRateLoose     = "rate_limit_loose"
	ProposalRateTight     = "rate_limit_tight"
	ProposalUnusedRule    = "unused_rule"
	ProposalObservation   = "observation"
	// ProposalChallengeOnAppPath は正規の画面らしいパスで、多数の IP に Challenge / CAPTCHA を出し、多くが解いている (人が巻き込まれている疑い) (ADR 0028)。
	ProposalChallengeOnAppPath = "challenge_on_app_path"
)

// observation で提案しなかった理由 (schema.Proposal.Reason)。
const (
	ReasonBelowThreshold   = "below_threshold"
	ReasonUndetermined     = "undetermined"
	ReasonExcludedByConfig = "excluded_by_config"
	ReasonExcludedByRule   = "excluded_by_rule"
	ReasonPositionLimit    = "position_limit"
	// ReasonInformational は提案の候補ではない情報 (COUNT のルールの状況)。
	ReasonInformational = "informational"
)

// AboutChallengeImpact は Challenge / CAPTCHA の状況 (observation の about)。出した数・解かれた割合を毎回載せる計画の材料 (ADR 0028)。
const AboutChallengeImpact = "challenge_impact"

// AboutCountRuleStatus は COUNT のルールの状況 (observation の about)。提案ではなく計画の材料。
const AboutCountRuleStatus = "count_rule_status"

var proposalOrder = map[string]int{ProposalFalsePositive: 0, ProposalChallengeOnAppPath: 1, ProposalProbeAllowed: 2, ProposalRateMissing: 3,
	ProposalRateLoose: 4, ProposalRateTight: 5, ProposalUnusedRule: 6, ProposalObservation: 7}

// Proposer は finding のほかに report.json の proposals を返すチェックが満たす (waf_review)。engine は Evaluate の代わりに呼ぶ。
type Proposer interface {
	Propose(ctx context.Context, q store.Query, w collect.Window) ([]schema.Proposal, []Observation, error)
}

// StoredNeeder は、収集はさせずに保存済みのデータ (metrics) だけを読むレコード種類を宣言するチェックが満たす。
// engine はその種類を出すソースが設定に無ければ skip する (run はそのソースを引かない。費用を抑えるため)。
type StoredNeeder interface {
	StoredNeeds() []record.Kind
}

// WAFReview は WAF の修正提案の候補を作る (週次。ADR 0023)。daily が貯めた wafv2 の日次集計 (metrics) と、waf-config の設定
// (snapshot) から、決まった規則で候補を作り、report.json の proposals に出す。候補は人が判断して適用する。
//
// 決定:
//   - COUNT → BLOCK の切り替えは勧めない (計画して行う作業)。COUNT のルールの状況を observation (count_rule_status) で載せる
//   - 候補は finding ではない (差分判定に乗せず、毎回その時点の候補を出す)。重大な候補 (正規の画面での多数の IP の BLOCK) だけ low の finding にもする
//   - 「迷ったら提案しない」: 設定と突き合わせられない (WebACL が見つからない・同じ名前が複数ある・ルールが設定に無い・scope-down を解釈できない) ときは提案しない。
//     ただし不審な観測は observation (提案なし) として、提案しなかった理由と根拠の数字を添えて残す (不審な事実は必ず伝える)
//   - 異なり IP 数は日ごとの値の最大 (日をまたいで足せないので下限の見積もり)
//   - 攻撃そのものの検知は waf_block_trend・probe_paths・login_bruteforce の finding が担う。ここは WAF の設定の観点に限る
type WAFReview struct {
	Config config.WAFReview
	// SignInPaths は誤検知の候補から外すパス (sign-in。多数の IP からの BLOCK はクレデンシャルスタッフィングかもしれない)。
	SignInPaths []string
	// ProbePaths は探索パスの接頭辞 (誤検知の候補から外す)。
	ProbePaths []string
}

func (WAFReview) Name() string               { return "waf_review" }
func (WAFReview) Cadence() Cadence           { return Weekly }
func (WAFReview) Mode() Mode                 { return ModeState }
func (WAFReview) Needs() []record.Kind       { return []record.Kind{record.KindWAFConfig} }
func (WAFReview) StoredNeeds() []record.Kind { return []record.Kind{record.KindWAFAction} }
func (c WAFReview) Evaluate(ctx context.Context, q store.Query, w collect.Window, _ *allowlist.List) ([]Observation, error) {
	_, obs, err := c.Propose(ctx, q, w)
	return obs, err
}

// wafACLConf は WebACL 1 つの設定。ambiguous なら同じ名前が複数あり、突き合わせない。
type wafACLConf struct {
	scope, region string
	ambiguous     bool
	rules         map[string]record.SnapshotItem
}

func loadWAFConfig(items []record.SnapshotItem) map[string]*wafACLConf {
	acls := map[string]*wafACLConf{}
	for _, it := range items {
		if it.String("item") != "web_acl" {
			continue
		}
		name := it.String("acl")
		if a, ok := acls[name]; ok {
			a.ambiguous = true
			continue
		}
		acls[name] = &wafACLConf{scope: it.String("scope"), region: it.String("region"), rules: map[string]record.SnapshotItem{}}
	}
	for _, it := range items {
		if it.String("item") != "rule" {
			continue
		}
		if a, ok := acls[it.String("acl")]; ok && !a.ambiguous && it.String("scope") == a.scope && it.String("region") == a.region {
			a.rules[it.String("rule")] = it
		}
	}
	return acls
}

// conf は突き合わせられる WebACL の設定 (無い・曖昧なら nil)。
func conf(acls map[string]*wafACLConf, acl string) *wafACLConf {
	if a := acls[acl]; a != nil && !a.ambiguous {
		return a
	}
	return nil
}

// groupID はルールグループのルールの、ログの ruleGroupId (マネージドは `Vendor#Name`、自分のグループは ARN)。
func groupID(rule record.SnapshotItem) string {
	switch rule.String("type") {
	case account.WAFRuleManagedGroup:
		return strings.Replace(rule.String("managed"), "/", "#", 1)
	case account.WAFRuleGroup:
		return rule.String("rule_group_arn")
	}
	return ""
}

type reviewer struct {
	c     WAFReview
	q     store.Query
	acls  map[string]*wafACLConf
	end   string
	props []schema.Proposal
	obs   []Observation
}

func (c WAFReview) Propose(ctx context.Context, q store.Query, w collect.Window) ([]schema.Proposal, []Observation, error) {
	dates := windowDates(w)
	if len(dates) == 0 {
		return nil, nil, nil
	}
	items, err := q.Snapshot(ctx, record.KindWAFConfig)
	if err != nil {
		return nil, nil, err
	}
	r := &reviewer{c: c, q: q, acls: loadWAFConfig(items), end: dates[len(dates)-1]}
	for _, f := range []func(context.Context) error{r.falsePositives, r.challenges, r.countRuleStatus, r.probeAllowed, r.rateLimits, r.unusedRules, r.positionLimits} {
		if err := f(ctx); err != nil {
			return nil, nil, err
		}
	}
	sort.SliceStable(r.props, func(i, j int) bool { return proposalOrder[r.props[i].Kind] < proposalOrder[r.props[j].Kind] })
	return r.props, sortedObs(obsMap(r.obs)), nil
}

func obsMap(l []Observation) map[string]Observation {
	m := map[string]Observation{}
	for _, o := range l {
		m[o.Key] = o
	}
	return m
}

func (r *reviewer) load(ctx context.Context, metric string, days int) (series, error) {
	return loadSeries(ctx, r.q, metric, addDays(r.end, -(days-1)), r.end)
}

func (r *reviewer) proposal(kind, stage, acl string) schema.Proposal {
	p := schema.Proposal{Kind: kind, Stage: stage, WebACL: acl, Evidence: map[string]any{}}
	if a := conf(r.acls, acl); a != nil {
		p.Scope, p.Region = a.scope, a.region
	}
	return p
}

func (r *reviewer) observation(about, reason, acl string) schema.Proposal {
	p := r.proposal(ProposalObservation, StageNone, acl)
	p.About, p.Reason = about, reason
	return p
}

// add は候補を種類ごとの上限まで足す (l は根拠の強い順)。
func (r *reviewer) add(l []schema.Proposal) {
	if len(l) > r.c.Config.MaxProposals {
		l = l[:r.c.Config.MaxProposals]
	}
	r.props = append(r.props, l...)
}

// keyAgg は key ごとの期間の合計と日ごとの最大。
type keyAgg struct {
	sum, max float64
	days     int
}

func aggregate(s series) map[string]*keyAgg {
	out := map[string]*keyAgg{}
	for _, byKey := range s {
		for k, v := range byKey {
			a := out[k]
			if a == nil {
				a = &keyAgg{}
				out[k] = a
			}
			a.sum += v
			a.max = math.Max(a.max, v)
			if v > 0 {
				a.days++
			}
		}
	}
	return out
}

func hasPrefixAny(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

// isIPSourceGroup は送信元で止めるマネージドグループ (IP 評判・匿名 IP)。多数の IP を止めるのが正常なので誤検知の候補にしない。
func isIPSourceGroup(rule record.SnapshotItem) bool {
	m := rule.String("managed")
	return strings.Contains(m, "IpReputation") || strings.Contains(m, "AnonymousIp")
}

// falsePositives は「誤検知の疑い」: 探索パスではない正規化パスで、ルールの BLOCK が多数の異なる IP から来ている。
func (r *reviewer) falsePositives(ctx context.Context) error {
	cfg := r.c.Config
	counts, err := r.load(ctx, cwlogs.MetricWAFBlockPath, cfg.Days)
	if err != nil {
		return err
	}
	ips, err := r.load(ctx, cwlogs.MetricWAFBlockPathIPs, cfg.Days)
	if err != nil {
		return err
	}
	ca, ia := aggregate(counts), aggregate(ips)
	keys := make([]string, 0, len(ca))
	for k := range ca {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := ia[keys[i]], ia[keys[j]]
		if a != nil && b != nil && a.max != b.max {
			return a.max > b.max
		}
		if ca[keys[i]].sum != ca[keys[j]].sum {
			return ca[keys[i]].sum > ca[keys[j]].sum
		}
		return keys[i] < keys[j]
	})
	var props, notes []schema.Proposal
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 4)
		if len(parts) != 4 {
			continue
		}
		acl, rule, method, path := parts[0], parts[1], parts[2], parts[3]
		group, inner, _ := strings.Cut(rule, "/")
		n, maxIPs := ca[k].sum, 0.0
		if ia[k] != nil {
			maxIPs = ia[k].max
		}
		if group == "Default_Action" {
			continue // 既定の action (BLOCK の WebACL) は特定のルールの誤検知ではない
		}
		p := r.proposal(ProposalFalsePositive, StageCountFirst, acl)
		p.Rule, p.RuleInGroup, p.Method, p.Path = group, inner, method, path
		p.Evidence = map[string]any{"count": n, "distinct_ips_max_per_day": maxIPs, "distinct_ips_is_lower_bound": true, "days": cfg.Days}
		label := group
		if inner != "" {
			label += " の " + inner
		}
		note := func(reason, why string) {
			if maxIPs < cfg.MinDistinctIPs {
				return // 異なり IP が少ないものは攻撃の検知 (waf_block_trend) の領分
			}
			o := r.observation(ProposalFalsePositive, reason, acl)
			o.Rule, o.RuleInGroup, o.Method, o.Path, o.Evidence = p.Rule, p.RuleInGroup, p.Method, p.Path, p.Evidence
			o.Summary = fmt.Sprintf("%s: %s が %s %s を %.0f 件 BLOCK (日ごとの異なり IP 最大 %.0f)。%s ため誤検知の提案はしない", acl, label, method, path, n, maxIPs, why)
			notes = append(notes, o)
		}
		a := conf(r.acls, acl)
		var rc record.SnapshotItem
		ok := false
		if a != nil {
			rc, ok = a.rules[group]
		}
		switch {
		case hasPrefixAny(path, r.c.ProbePaths):
			continue
		case a == nil:
			note(ReasonUndetermined, "WebACL の設定と突き合わせられない (waf-config に無いか、同じ名前が複数ある)")
		case !ok:
			note(ReasonUndetermined, "ルールが WebACL の設定に無い")
		case rc.String("type") == account.WAFRuleRateBased:
			note(ReasonExcludedByRule, "レートベースのルールの BLOCK は多数の IP からでも正常なことがある (レート制限の候補で扱う)")
		case isIPSourceGroup(rc):
			note(ReasonExcludedByRule, "送信元の評判で止めるグループは多数の IP を止めるのが正常")
		case contains(r.c.SignInPaths, path):
			note(ReasonExcludedByRule, "sign-in のパスへの多数の IP からの BLOCK はクレデンシャルスタッフィングかもしれない")
		case maxIPs < cfg.MinDistinctIPs:
			if maxIPs >= 2 && n >= cfg.MinCount {
				o := r.observation(ProposalFalsePositive, ReasonBelowThreshold, acl)
				o.Rule, o.RuleInGroup, o.Method, o.Path, o.Evidence = p.Rule, p.RuleInGroup, p.Method, p.Path, p.Evidence
				o.Evidence["min_distinct_ips"] = cfg.MinDistinctIPs
				o.Summary = fmt.Sprintf("%s: %s が %s %s を %.0f 件 BLOCK。異なり IP (日ごとの最大 %.0f) が min_distinct_ips %.0f 未満のため提案しない", acl, label, method, path, n, maxIPs, cfg.MinDistinctIPs)
				notes = append(notes, o)
			}
		default:
			how := "このパスだけ COUNT にする (scope-down でパスを外すか、ルールの除外)"
			if inner != "" {
				how = "グループ " + group + " の " + inner + " をこのパスだけ COUNT にする (RuleActionOverrides か scope-down)"
			}
			p.Summary = fmt.Sprintf("%s: %s が正規の画面らしい %s %s を直近 %d 日で %.0f 件 BLOCK (日ごとの異なり IP 最大 %.0f)。誤検知の疑い。%s → 様子を見て除外を確定する",
				acl, label, method, path, cfg.Days, n, maxIPs, how)
			if maxIPs >= cfg.FindingDistinctIPs {
				p.FindingKey = "false_positive|" + acl + "|" + rule + "|" + method + " " + path
				d := map[string]any{"web_acl": acl, "rule": group, "rule_in_group": inner, "method": method, "path": path}
				for k, v := range p.Evidence {
					d[k] = v
				}
				r.obs = append(r.obs, Observation{Check: r.c.Name(), Key: p.FindingKey, Severity: Low,
					Summary:     fmt.Sprintf("WAF の誤検知の疑い: %s の %s が %s %s を多数の IP (日ごとの最大 %.0f) から BLOCK", acl, label, method, path, maxIPs),
					Fingerprint: fingerprint(Low, nil, ProposalFalsePositive), Data: d})
			}
			props = append(props, p)
		}
	}
	r.add(props)
	r.add(notes)
	return nil
}

// challengeAgg は Challenge / CAPTCHA の key (またはルール) ごとの期間の集計。IP は日ごとの値を足した「IP・日」(日をまたいで同じ IP を数え得る)。
type challengeAgg struct {
	issued, ipsMax, ipsSum, solvedSum, nonGet float64
}

func (a challengeAgg) ratio() float64 {
	if a.ipsSum == 0 {
		return 0
	}
	return math.Round(a.solvedSum/a.ipsSum*1000) / 1000
}

// challenges は Challenge / CAPTCHA の影響を評価する (ADR 0028)。
//
// 決定:
//   - 解かれた割合 = 解いた IP / 出した IP (日ごとの値を期間で足して比べる)。解いた IP は出した IP のうち同じ日・同じパスで同じ種類のトークンが受理された IP
//   - 割合が高い (challenge_solve_ratio 以上) = 人が解いている = 正規の利用者が巻き込まれている疑い。探索パスではない GET の画面で、
//     出した IP (日ごとの最大) が challenge_min_distinct_ips 以上なら「対象の絞り込み (scope-down) を検討し様子を見る」を提案する (stage review)。
//     これは仮説で、検証方法と前提は ADR 0028
//   - GET 以外は提案しない。Challenge / CAPTCHA はブラウザが画面として受け取る GET でしか解けず、POST や XHR の割合が低いのは「人が居ない」ことを意味しない
//   - 割合が低いものは提案しない (ボットを止めているのか、解けない通信なのかを区別できない)。challenge_impact に数字だけを載せる
//   - challenge_impact は毎回、出した数の多い challenge_top_rules 個のルールについて事実だけを書く (解釈を書かない)
func (r *reviewer) challenges(ctx context.Context) error {
	cfg := r.c.Config
	issued, err := r.load(ctx, cwlogs.MetricWAFChallengeIssued, cfg.Days)
	if err != nil {
		return err
	}
	ips, err := r.load(ctx, cwlogs.MetricWAFChallengeIssuedIPs, cfg.Days)
	if err != nil {
		return err
	}
	solved, err := r.load(ctx, cwlogs.MetricWAFChallengeSolvedIPs, cfg.Days)
	if err != nil {
		return err
	}
	ia, pa, sa := aggregate(issued), aggregate(ips), aggregate(solved)
	byKey := map[string]*challengeAgg{}
	byRule := map[string]*challengeAgg{}
	for k, v := range ia {
		parts := strings.SplitN(k, "|", 5)
		if len(parts) != 5 {
			continue
		}
		a := &challengeAgg{issued: v.sum}
		if x := pa[k]; x != nil {
			a.ipsMax, a.ipsSum = x.max, x.sum
		}
		if x := sa[k]; x != nil {
			a.solvedSum = x.sum
		}
		byKey[k] = a
		rk := parts[0] + "|" + parts[1] + "|" + parts[2]
		ra := byRule[rk]
		if ra == nil {
			ra = &challengeAgg{}
			byRule[rk] = ra
		}
		ra.issued += a.issued
		ra.ipsSum += a.ipsSum
		ra.solvedSum += a.solvedSum
		ra.ipsMax = math.Max(ra.ipsMax, a.ipsMax)
		if parts[3] != "GET" {
			ra.nonGet += a.issued
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := byKey[keys[i]], byKey[keys[j]]
		if a.ipsMax != b.ipsMax {
			return a.ipsMax > b.ipsMax
		}
		if a.issued != b.issued {
			return a.issued > b.issued
		}
		return keys[i] < keys[j]
	})
	var props, notes []schema.Proposal
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 5)
		acl, kind, rule, method, path := parts[0], parts[1], parts[2], parts[3], parts[4]
		a := byKey[k]
		if method != "GET" || hasPrefixAny(path, r.c.ProbePaths) || a.ipsMax < cfg.ChallengeMinDistinctIPs || a.ratio() < cfg.ChallengeSolveRatio {
			continue
		}
		group, inner, _ := strings.Cut(rule, "/")
		label := group
		if inner != "" {
			label += " の " + inner
		}
		ev := map[string]any{"kind": kind, "issued": a.issued, "distinct_ips_max_per_day": a.ipsMax, "distinct_ips_is_lower_bound": true,
			"issued_ips_day_sum": a.ipsSum, "solved_ips_day_sum": a.solvedSum, "solve_ratio": a.ratio(), "min_solve_ratio": cfg.ChallengeSolveRatio, "days": cfg.Days}
		facts := fmt.Sprintf("%s: %s の %s が %s %s で直近 %d 日に %.0f 件出され、出した IP の %.0f%% (日ごとの合計 %.0f / %.0f) が解いた (出した IP は日ごとの最大 %.0f)",
			acl, label, kindLabel(kind), method, path, cfg.Days, a.issued, a.ratio()*100, a.solvedSum, a.ipsSum, a.ipsMax)
		note := func(reason, why string) {
			o := r.observation(ProposalChallengeOnAppPath, reason, acl)
			o.Rule, o.RuleInGroup, o.Method, o.Path, o.Evidence = group, inner, method, path, ev
			o.Summary = facts + "。" + why + "ため提案しない"
			notes = append(notes, o)
		}
		ac := conf(r.acls, acl)
		var rc record.SnapshotItem
		ok := false
		if ac != nil {
			rc, ok = ac.rules[group]
		}
		switch {
		case ac == nil:
			note(ReasonUndetermined, "WebACL の設定と突き合わせられない (waf-config に無いか、同じ名前が複数ある)")
		case !ok:
			note(ReasonUndetermined, "ルールが WebACL の設定に無い")
		case rc.String("type") == account.WAFRuleRateBased:
			note(ReasonExcludedByRule, "レートベースのルールの Challenge / CAPTCHA は、多い利用者に解かせるのが狙いのことがある (レート制限の候補で扱う)")
		case isIPSourceGroup(rc):
			note(ReasonExcludedByRule, "送信元の評判で出すグループは多数の IP に出すのが正常")
		case contains(r.c.SignInPaths, path):
			note(ReasonExcludedByRule, "sign-in のパスの Challenge / CAPTCHA は総当たりへの備えとして意図したものが多い")
		default:
			p := r.proposal(ProposalChallengeOnAppPath, StageReview, acl)
			p.Rule, p.RuleInGroup, p.Method, p.Path, p.Evidence = group, inner, method, path, ev
			p.Summary = facts + "。人が解いている = 正規の利用者が巻き込まれている疑い。このパスを対象から外す (scope-down) か、" +
				kindLabel(kind) + " を出す条件を絞ることを検討し、様子を見る"
			props = append(props, p)
		}
	}
	r.add(props)
	r.add(notes)

	// challenge_impact: 出した数の多いルールから challenge_top_rules 個
	rules := make([]string, 0, len(byRule))
	for k := range byRule {
		rules = append(rules, k)
	}
	sort.Slice(rules, func(i, j int) bool {
		if byRule[rules[i]].issued != byRule[rules[j]].issued {
			return byRule[rules[i]].issued > byRule[rules[j]].issued
		}
		return rules[i] < rules[j]
	})
	if len(rules) > cfg.ChallengeTopRules {
		rules = rules[:cfg.ChallengeTopRules]
	}
	var impact []schema.Proposal
	for _, rk := range rules {
		parts := strings.SplitN(rk, "|", 3)
		acl, kind, rule := parts[0], parts[1], parts[2]
		a := byRule[rk]
		group, inner, _ := strings.Cut(rule, "/")
		label := group
		if inner != "" {
			label += " の " + inner
		}
		// 主なパス (出した数の多い順に 5 個)
		var paths []string
		for _, k := range sortedChallengeKeys(byKey, acl+"|"+kind+"|"+rule+"|") {
			if len(paths) == 5 {
				break
			}
			x := byKey[k]
			mp := strings.SplitN(k, "|", 5)
			paths = append(paths, fmt.Sprintf("%s %s (%.0f 件、%.0f%%)", mp[3], mp[4], x.issued, x.ratio()*100))
		}
		o := r.observation(AboutChallengeImpact, ReasonInformational, acl)
		o.Rule, o.RuleInGroup = group, inner
		o.Evidence = map[string]any{"kind": kind, "issued": a.issued, "issued_ips_day_sum": a.ipsSum, "solved_ips_day_sum": a.solvedSum, "solve_ratio": a.ratio(),
			"distinct_ips_max_per_day": a.ipsMax, "issued_non_get": a.nonGet, "paths": paths, "days": cfg.Days}
		o.Summary = fmt.Sprintf("%s: %s の %s: 直近 %d 日で %.0f 件出し、解かれた割合 %.0f%% (解いた IP %.0f / 出した IP %.0f、日ごとの合計)。GET 以外 %.0f 件 (解けない)。主なパス: %s",
			acl, kindLabel(kind), label, cfg.Days, a.issued, a.ratio()*100, a.solvedSum, a.ipsSum, a.nonGet, strings.Join(paths, ", "))
		impact = append(impact, o)
	}
	r.add(impact)
	return nil
}

// sortedChallengeKeys は prefix で始まる key を出した数の多い順に返す。
func sortedChallengeKeys(m map[string]*challengeAgg, prefix string) []string {
	var keys []string
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]].issued != m[keys[j]].issued {
			return m[keys[i]].issued > m[keys[j]].issued
		}
		return keys[i] < keys[j]
	})
	return keys
}

func kindLabel(kind string) string {
	if kind == "captcha" {
		return "CAPTCHA"
	}
	return "Challenge"
}

// countRules は WebACL のうち COUNT で動いているルール (ログの識別子 → ルール名とグループの中のルール名)。
type countRule struct{ rule, inner string }

func countRules(a *wafACLConf) map[string]countRule {
	out := map[string]countRule{}
	for name, rc := range a.rules {
		if rc.String("action") == "COUNT" {
			out[name] = countRule{rule: name}
		}
		gid := groupID(rc)
		if gid == "" || rc.String("count_overrides") == "" {
			continue
		}
		for _, inner := range strings.Split(rc.String("count_overrides"), ",") {
			out[gid+"/"+inner] = countRule{rule: name, inner: inner}
		}
	}
	return out
}

// countRuleStatus は COUNT のルールの状況を、計画の材料として毎回 observation (about: count_rule_status、reason: informational) で載せる。
//
// 決定 (ADR 0023): COUNT → BLOCK の切り替えは運用で計画して行う作業 (COUNT で入れるときに期間を決めて様子を見る) で、アプリの事情も絡むので、
// ログの数字だけで BLOCK を勧めない (count_to_block の提案は廃止した)。事実 (一致件数・怪しい通信の割合・一致した日数) だけを書く。
// 一致 0 のルールも載せる (使われていないルールの候補からは COUNT のルールを外し、重ならないようにする)。
// 怪しい通信 = 探索パスか、同じ日にレートベース以外のルールで BLOCK された IP からの一致 (既定の action と sign-in のパスの BLOCK も除く)。
func (r *reviewer) countRuleStatus(ctx context.Context) error {
	cfg := r.c.Config
	total, err := r.load(ctx, cwlogs.MetricWAFCountMatch, cfg.Days)
	if err != nil {
		return err
	}
	suspect, err := r.load(ctx, cwlogs.MetricWAFCountMatchSuspect, cfg.Days)
	if err != nil {
		return err
	}
	ta, sa := aggregate(total), aggregate(suspect)
	var notes []schema.Proposal
	acls := make([]string, 0, len(r.acls))
	for n := range r.acls {
		acls = append(acls, n)
	}
	sort.Strings(acls)
	for _, acl := range acls {
		a := conf(r.acls, acl)
		if a == nil {
			continue
		}
		rules := countRules(a)
		ids := make([]string, 0, len(rules))
		for id := range rules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			cr := rules[id]
			n, s, matched := 0.0, 0.0, 0
			if t := ta[acl+"|"+id]; t != nil {
				n, matched = t.sum, t.days
			}
			if x := sa[acl+"|"+id]; x != nil {
				s = x.sum
			}
			label := cr.rule
			if cr.inner != "" {
				label += " の " + cr.inner
			}
			o := r.observation(AboutCountRuleStatus, ReasonInformational, acl)
			o.Rule, o.RuleInGroup = cr.rule, cr.inner
			o.Evidence = map[string]any{"matches": n, "suspect_matches": s, "matching_days": matched, "days": cfg.Days, "suspect_blocked_ip_excludes": cwlogs.SuspectBlockExcludes}
			if n == 0 {
				o.Summary = fmt.Sprintf("%s: COUNT の %s: 直近 %d 日で一致なし", acl, label, cfg.Days)
			} else {
				ratio := math.Round(s/n*1000) / 1000
				o.Evidence["suspect_ratio"] = ratio
				o.Summary = fmt.Sprintf("%s: COUNT の %s: 直近 %d 日で %.0f 件一致、うち怪しい通信 %.0f%%、一致した日 %d / %d 日", acl, label, cfg.Days, n, ratio*100, matched, cfg.Days)
			}
			notes = append(notes, o)
		}
	}
	r.add(notes)
	return nil
}

// probeAllowed は「すり抜けている探索」: 探索パスへのリクエストが WAF で ALLOW になった。
func (r *reviewer) probeAllowed(ctx context.Context) error {
	cfg := r.c.Config
	counts, err := r.load(ctx, cwlogs.MetricWAFAllowProbe, cfg.Days)
	if err != nil {
		return err
	}
	ips, err := r.load(ctx, cwlogs.MetricWAFAllowProbeIPs, cfg.Days)
	if err != nil {
		return err
	}
	ca, ia := aggregate(counts), aggregate(ips)
	byACL := map[string][]string{}
	for k := range ca {
		acl, _, _ := strings.Cut(k, "|")
		byACL[acl] = append(byACL[acl], k)
	}
	acls := make([]string, 0, len(byACL))
	for a := range byACL {
		acls = append(acls, a)
	}
	sort.Strings(acls)
	var props, notes []schema.Proposal
	for _, acl := range acls {
		keys := byACL[acl]
		sort.Slice(keys, func(i, j int) bool {
			if ca[keys[i]].sum != ca[keys[j]].sum {
				return ca[keys[i]].sum > ca[keys[j]].sum
			}
			return keys[i] < keys[j]
		})
		total, maxIPs := 0.0, 0.0
		var paths []string
		for i, k := range keys {
			total += ca[k].sum
			if ia[k] != nil {
				maxIPs = math.Max(maxIPs, ia[k].max)
			}
			if i < 10 {
				_, path, _ := strings.Cut(k, "|")
				paths = append(paths, fmt.Sprintf("%s (%.0f 件)", path, ca[k].sum))
			}
		}
		if total == 0 {
			continue
		}
		var countNames []string
		if a := conf(r.acls, acl); a != nil {
			for name, rc := range a.rules {
				if rc.String("action") == "COUNT" {
					countNames = append(countNames, name)
				}
			}
		}
		sort.Strings(countNames)
		ev := map[string]any{"count": total, "paths": paths, "distinct_ips_max_per_day": maxIPs, "distinct_ips_is_lower_bound": true, "days": cfg.Days, "count_rules": countNames}
		if total < cfg.MinCount {
			o := r.observation(ProposalProbeAllowed, ReasonBelowThreshold, acl)
			o.Evidence = ev
			o.Evidence["min_count"] = cfg.MinCount
			o.Summary = fmt.Sprintf("%s: 探索パスへのリクエストが WAF で許可された (直近 %d 日で %.0f 件: %s)。min_count %.0f 未満のため提案しない",
				acl, cfg.Days, total, strings.Join(paths, ", "), cfg.MinCount)
			notes = append(notes, o)
			continue
		}
		p := r.proposal(ProposalProbeAllowed, StageCountFirst, acl)
		p.Evidence = ev
		how := "マネージドルール (AWSManagedRulesKnownBadInputsRuleSet など) か、探索パスをブロックするルールを COUNT で追加して様子を見る"
		if len(countNames) > 0 {
			how += "。COUNT で動いているルール: " + strings.Join(countNames, ", ") + " (状況は count_rule_status)"
		}
		p.Summary = fmt.Sprintf("%s: 探索パスへのリクエストが WAF で許可された (直近 %d 日で %.0f 件: %s)。%s", acl, cfg.Days, total, strings.Join(paths, ", "), how)
		props = append(props, p)
	}
	r.add(props)
	r.add(notes)
	return nil
}

// rateCoverage はパスの群をレートベースのルールが受け持つか。
//   - full: 受け持つルールが 1 つで、範囲を解釈できた (limit を比べられる)
//   - unknown: 解釈できない scope-down・IP 以外の集約・群の一部だけを受け持つルールがある (判断できない)
type rateCoverage struct {
	full    []record.SnapshotItem
	unknown []string
}

func (r *reviewer) coverage(a *wafACLConf, grp string) rateCoverage {
	var out rateCoverage
	groups := r.c.Config.RatePathGroups
	names := make([]string, 0, len(a.rules))
	for n := range a.rules {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		rc := a.rules[name]
		if rc.String("type") != account.WAFRuleRateBased {
			continue
		}
		agg := rc.String("rate_aggregate")
		if !rc.Bool("rate_scope_parsed") || (agg != "IP" && agg != "FORWARDED_IP") {
			out.unknown = append(out.unknown, name)
			continue
		}
		conds := rc.String("rate_scope_paths")
		if conds == "" {
			out.full = append(out.full, rc) // scope-down が無い: 全部を受け持つ
			continue
		}
		if strings.Contains(conds, ",") {
			out.unknown = append(out.unknown, name) // 複数の条件の組み合わせは解釈しない
			continue
		}
		op, s, _ := strings.Cut(conds, ":")
		switch {
		case grp == cwlogs.RateGroupOther:
			// 「その他」の群: どの群にも入らない範囲を受け持つルールは一部だけを受け持つ
			if !hasPrefixAny(s, groups) {
				out.unknown = append(out.unknown, name)
			}
		case op == "STARTS_WITH" && strings.HasPrefix(grp, s):
			out.full = append(out.full, rc)
		case strings.HasPrefix(s, grp) || strings.HasPrefix(grp, s):
			out.unknown = append(out.unknown, name) // 群の一部 (/login/submit だけ、EXACTLY など)
		}
	}
	return out
}

// rateLimits は「レート制限の不足 / 余裕」。値は 5 分あたり (WAF の既定の評価窓) にそろえて比べる。
func (r *reviewer) rateLimits(ctx context.Context) error {
	cfg := r.c.Config
	p50s, err := r.load(ctx, cwlogs.MetricWAFIPRateP50, cfg.Days)
	if err != nil {
		return err
	}
	p99s, err := r.load(ctx, cwlogs.MetricWAFIPRateP99, cfg.Days)
	if err != nil {
		return err
	}
	maxs, err := r.load(ctx, cwlogs.MetricWAFIPRateMax, cfg.Days)
	if err != nil {
		return err
	}
	a50, a99, amax := aggregate(p50s), aggregate(p99s), aggregate(maxs)
	keys := make([]string, 0, len(amax))
	for k := range amax {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var props []schema.Proposal
	var notes []schema.Proposal
	for _, k := range keys {
		acl, grp, _ := strings.Cut(k, "|")
		p99, mx, p50 := 0.0, amax[k].max, 0.0
		if a99[k] != nil {
			p99 = a99[k].max
		}
		if a50[k] != nil {
			p50 = a50[k].max
		}
		proposed := math.Max(math.Ceil(p99*cfg.RateMargin), cfg.RateFloor)
		ev := map[string]any{"path_group": grp, "p50_per_5min": p50, "p99_per_5min": p99, "max_per_5min": mx, "days": cfg.Days, "proposed_limit": proposed, "evaluation_window_sec": 300}
		burst := mx > p99*cfg.RateFactor && mx > proposed
		note := func(reason, why string) {
			o := r.observation(ProposalRateMissing, reason, acl)
			o.Path, o.Evidence = grp, ev
			o.Summary = fmt.Sprintf("%s: パスの群 %s で 1 IP が 5 分に最大 %.0f 件 (p99 %.0f)。%s", acl, grp, mx, p99, why)
			notes = append(notes, o)
		}
		if grp != cwlogs.RateGroupOther && (hasPrefixAny(grp, cfg.ExpectedHighRatePaths) || anyHasPrefix(cfg.ExpectedHighRatePaths, grp)) {
			if burst {
				note(ReasonExcludedByConfig, "expected_high_rate_paths に一致するためレート制限の提案はしない")
			}
			continue
		}
		a := conf(r.acls, acl)
		if a == nil {
			if burst {
				note(ReasonUndetermined, "WebACL の設定と突き合わせられないため提案しない")
			}
			continue
		}
		cov := r.coverage(a, grp)
		switch {
		case len(cov.unknown) > 0:
			if burst {
				note(ReasonUndetermined, "レートベースのルール ("+strings.Join(cov.unknown, ", ")+") がこの群を受け持つか判断できない (scope-down を解釈できない) ため提案しない")
			}
		case len(cov.full) == 0:
			if !burst {
				continue
			}
			p := r.proposal(ProposalRateMissing, StageCountFirst, acl)
			p.Path, p.Evidence = grp, ev
			p.Summary = fmt.Sprintf("%s: パスの群 %s を受け持つレートベースのルールが無く、1 IP が 5 分に最大 %.0f 件 (p99 %.0f の %.0f 倍超え)。limit %.0f (5 分、IP 単位) のレートベースのルールを COUNT で足して様子を見る",
				acl, grp, mx, p99, cfg.RateFactor, proposed)
			props = append(props, p)
		case len(cov.full) == 1:
			rc := cov.full[0]
			window := rc.Number("rate_window_sec")
			if window <= 0 {
				window = 300
			}
			per5 := math.Round(rc.Number("rate_limit")*300/window*10) / 10
			ev["current_rule"], ev["current_limit"], ev["current_window_sec"], ev["current_limit_per_5min"] = rc.String("rule"), rc.Number("rate_limit"), window, per5
			switch {
			case per5 > mx*cfg.RateLooseFactor && proposed < per5:
				p := r.proposal(ProposalRateLoose, StageReview, acl)
				p.Rule, p.Path, p.Evidence = rc.String("rule"), grp, ev
				p.Summary = fmt.Sprintf("%s: %s の limit (5 分あたり %.0f) が、パスの群 %s の観測の最大 %.0f の %.0f 倍より高い。limit %.0f への見直しを検討する",
					acl, rc.String("rule"), per5, grp, mx, cfg.RateLooseFactor, proposed)
				props = append(props, p)
			case per5 < p99:
				p := r.proposal(ProposalRateTight, StageReview, acl)
				p.Rule, p.Path, p.Evidence = rc.String("rule"), grp, ev
				p.Summary = fmt.Sprintf("%s: %s の limit (5 分あたり %.0f) が、パスの群 %s の観測の p99 %.0f より低い (正規の利用者も止まり得る)。limit %.0f への見直しを検討する",
					acl, rc.String("rule"), per5, grp, p99, proposed)
				props = append(props, p)
			}
		default:
			if burst {
				names := []string{}
				for _, rc := range cov.full {
					names = append(names, rc.String("rule"))
				}
				note(ReasonUndetermined, "複数のレートベースのルール ("+strings.Join(names, ", ")+") が受け持つため値の比較はしない")
			}
		}
	}
	r.add(props)
	r.add(notes)
	return nil
}

func anyHasPrefix(prefixes []string, p string) bool {
	for _, x := range prefixes {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

// unusedRules は「使われていないルール」: unused_days 日、終了ルールにもカウントの一致にもならなかった (見直しの候補。削除は勧めない)。
// データのある日 (その WebACL の waf_rule_action がある日) が unused_days に満たなければ判定しない。
func (r *reviewer) unusedRules(ctx context.Context) error {
	cfg := r.c.Config
	actions, err := r.load(ctx, cwlogs.MetricWAFRuleAction, cfg.UnusedDays)
	if err != nil {
		return err
	}
	counts, err := r.load(ctx, cwlogs.MetricWAFCountMatch, cfg.UnusedDays)
	if err != nil {
		return err
	}
	dataDays, used := map[string]int{}, map[string]bool{}
	for _, byKey := range actions {
		seen := map[string]bool{}
		for k, v := range byKey {
			parts := strings.SplitN(k, "|", 3)
			if len(parts) != 3 || v <= 0 {
				continue
			}
			seen[parts[0]] = true
			used[parts[0]+"|"+parts[1]] = true
		}
		for acl := range seen {
			dataDays[acl]++
		}
	}
	for _, byKey := range counts {
		for k, v := range byKey {
			if v > 0 {
				used[k] = true
			}
		}
	}
	var props []schema.Proposal
	acls := make([]string, 0, len(r.acls))
	for n := range r.acls {
		acls = append(acls, n)
	}
	sort.Strings(acls)
	for _, acl := range acls {
		a := conf(r.acls, acl)
		if a == nil || dataDays[acl] < cfg.UnusedDays {
			continue
		}
		names := make([]string, 0, len(a.rules))
		for n := range a.rules {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			rc := a.rules[name]
			if used[acl+"|"+name] || rc.String("action") == "COUNT" {
				continue // COUNT のルールは count_rule_status が一致 0 も含めて載せる
			}
			if gid := groupID(rc); gid != "" && usedPrefix(used, acl+"|"+gid+"/") {
				continue
			}
			p := r.proposal(ProposalUnusedRule, StageReview, acl)
			p.Rule = name
			p.Evidence = map[string]any{"days_without_match": cfg.UnusedDays, "type": rc.String("type"), "action": rc.String("action")}
			p.Summary = fmt.Sprintf("%s: ルール %s (%s, %s) は直近 %d 日、一度も一致していない。見直しの候補 (守りとして残す価値があることも多い。削除は勧めない)",
				acl, name, rc.String("type"), rc.String("action"), cfg.UnusedDays)
			props = append(props, p)
		}
	}
	r.add(props)
	return nil
}

func usedPrefix(used map[string]bool, prefix string) bool {
	for k := range used {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// positionLimits は、カウントの一致や止めたグループを見る配列の位置の上限を超えた行があった (数え漏れの可能性) ことを observation にする。
func (r *reviewer) positionLimits(ctx context.Context) error {
	s, err := r.load(ctx, cwlogs.MetricWAFPositionLimit, r.c.Config.Days)
	if err != nil {
		return err
	}
	agg := aggregate(s)
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var notes []schema.Proposal
	for _, k := range keys {
		acl, field, _ := strings.Cut(k, "|")
		o := r.observation(AboutCountRuleStatus, ReasonPositionLimit, acl)
		o.Evidence = map[string]any{"field": field, "requests": agg[k].sum, "days": r.c.Config.Days}
		o.Summary = fmt.Sprintf("%s: %s の最後の位置まで埋まったリクエストが直近 %d 日で %.0f 件。それより後ろの一致は数えていない (カウントの一致・止めたグループの中のルールが少なめ)",
			acl, field, r.c.Config.Days, agg[k].sum)
		notes = append(notes, o)
	}
	r.add(notes)
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
