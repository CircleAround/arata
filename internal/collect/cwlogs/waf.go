package cwlogs

import (
	"context"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// wafv2 の日次集計のうち waf_review (WAF の修正提案の候補) が使うもの (ADR 0023)。key は `|` 区切り。
//
// 決定:
//   - 生ログ・ヘッダー・クエリ文字列・Cookie・User-Agent・本文は引かない。集計の結果 (件数・異なり IP 数・p50 など) だけを保存する
//   - パスはクエリ (`?` 以降) を落とし、数字だけ・UUID の区間を `:id` にしてから合算する (Insights に正規表現の置換が無いので Go 側で行う)。
//     そのため Insights では (パス, IP) で集計し、Go で正規化してから異なり IP を数える。生パスごとの異なり IP を足すと、
//     1 IP が /items/1..500 を列挙したときに 500 IP と数え、攻撃を「誤検知の疑い」と取り違えるため
//   - 1 回の結果は 10000 行まで。超えたら件数の多い組だけが残り (少なめに数える。候補は出にくい側に倒れる)、WARN と run の stats に残す
//   - 正規の送信元 (checks.waf_review.trusted_cidrs) は waf_rule_action 以外の集計から外す。waf_rule_action は「使われていないルール」の判定に使うので外さない
const (
	MetricWAFRuleAction        = "waf_rule_action"              // key = <WebACL>|<終了ルール>|<action>
	MetricWAFBlockPath         = "waf_block_path"               // key = <WebACL>|<ルール>|<method>|<正規化パス> (件数)
	MetricWAFBlockPathIPs      = "waf_block_path_ips"           // 同じ key の異なり IP 数
	MetricWAFAllowProbe        = "waf_allow_probe"              // key = <WebACL>|<正規化パス> (許可された探索の件数)
	MetricWAFAllowProbeIPs     = "waf_allow_probe_ips"          // 同じ key の異なり IP 数
	MetricWAFCountMatch        = "waf_rule_count_match"         // key = <WebACL>|<ルール> (カウントモードの一致)
	MetricWAFCountMatchSuspect = "waf_rule_count_match_suspect" // 同じ key のうち探索パスへの一致と、BLOCK されたリクエストでの一致 (ADR 0067。以前は「その日 BLOCK された IP」からの一致)
	MetricWAFIPRateP50         = "waf_ip_rate_p50"              // key = <WebACL>|<パスの群> (1 IP あたり 5 分間の件数)
	MetricWAFIPRateP99         = "waf_ip_rate_p99"
	MetricWAFIPRateMax         = "waf_ip_rate_max"
	// Challenge / CAPTCHA の影響 (ADR 0028)。key = <WebACL>|<challenge|captcha>|<ルール>[/<グループの中のルール>]|<method>|<正規化パス>
	MetricWAFChallengeIssued    = "waf_challenge_issued"     // 出した (トークンが無い・無効で止めた) 件数
	MetricWAFChallengeIssuedIPs = "waf_challenge_issued_ips" // 出した異なり IP 数
	// MetricWAFChallengeSolvedIPs は出した IP のうち、同じ日・同じ method とパスで同じ種類のトークンが受理された (解いた) 異なり IP 数。
	MetricWAFChallengeSolvedIPs = "waf_challenge_solved_ips"
	// MetricWAFPositionLimit は配列の位置の上限を超えた (それより後ろを数えていない) リクエストの数。key = <WebACL>|<配列の名前>
	MetricWAFPositionLimit = "waf_position_limit"
	// MetricWAFBlockIPSuspect は BLOCK の件数 (key = ip) のうち、suspect の「BLOCK された IP」と同じものを除いたもの
	// (レートベースのルール・既定の action・sign-in のパス・trusted_cidrs)。怪しい IP の一覧の waf_block の元 (ADR 0069)。
	// MetricWAFAllowProbeIP は許可された探索の件数 (key = ip。trusted_cidrs を除く)。一覧の probe の元。
	// どちらも ip_list: を書いたときだけ出す (IP を key に持つ行を、使わない利用者のストアに足さない)。
	MetricWAFBlockIPSuspect = "waf_block_ip_suspect"
	MetricWAFAllowProbeIP   = "waf_allow_probe_ip"
)

// suspectBlockIP は「BLOCK された IP」の集計の名前 (保存しない)。
const suspectBlockIP = "waf_suspect_block_ip"

// challengeSolved は「トークンが受理された行」の集計の名前 (保存しない。出した IP との積集合を waf_challenge_solved_ips にする)。
const challengeSolved = "waf_challenge_solved"

// ChallengeKinds は Challenge / CAPTCHA の種類 (key の 2 番目)。ログの action は大文字。
var ChallengeKinds = []string{"challenge", "captcha"}

// SuspectBlockExcludes は suspect の「BLOCK された IP」から除く BLOCK (evidence に残す)。
const SuspectBlockExcludes = "rate_based_rules,default_action,sign_in_paths"

// RateGroupOther は rate_path_groups のどれにも当たらないパスの群の名前。
const RateGroupOther = "*"

// 配列の位置の上限 (Insights は JSON の配列を `name.0.field` に平坦化する。2026-11 に sandbox の実ログで group by できることを確認)。
// 決定: トップレベルの nonTerminatingMatchingRules は先頭 3 個、ruleGroupList は先頭 8 グループ (各グループの中は先頭 1 個) を見る。
// ruleGroupList には一致しなかったグループも WebACL の順に全部入る。上限のすぐ後ろの位置 (番兵) も group by に入れ、
// 埋まっていれば上限を超えた (数え漏れの可能性) として waf_position_limit に数え、止めたグループの中のルール名は決めない。
const (
	countTopPositions = 3
	groupPositions    = 8
)

var (
	topSentinel   = "nonTerminatingMatchingRules." + strconv.Itoa(countTopPositions) + ".ruleId"
	groupSentinel = "ruleGroupList." + strconv.Itoa(groupPositions) + ".ruleGroupId"
)

// wafv2 のまとめた集計の名前 (保存しない。クエリの列名)。
// separateCountQuery は、trusted_cidrs が無くてもカウントの一致を別の 1 本にする (テストで、まとめた形と値が同じことを確かめるため)。
var separateCountQuery = false

const (
	wafActions = "waf_actions" // 止めた・出した系の行の件数の列の名前
	wafRate    = "waf_ip_rate"
	// クエリの名前 (部分の行の名前。ADR 0067 で組み替えたので、前の版の部分の行と混ざらない名前にした)
	wafLines      = "waf_lines"      // 1': 全行 (解釈率・waf_rule_action・waf_block・カウントの一致の合計)
	wafBlocks     = "waf_blocks"     // 2': BLOCK と許可された探索
	wafChallenges = "waf_challenges" // 3': Challenge / CAPTCHA (出した・受理)
)

// 決定 (ADR 0031): wafv2 のクエリは 4 本 (解釈率 + ルールごとの件数、止めた・出した系の細かい集計、カウントの一致、レート)。
//   - 解釈率と waf_rule_action は全行を (日, WebACL, ルール, action) で数える 1 本にまとめる (行は数十)
//   - waf_block_ip・waf_block_path・waf_allow_probe・「BLOCK された IP」・Challenge / CAPTCHA (出した・受理) は 1 本にまとめる。
//     filter は行の種類の和 (BLOCK、または正規の送信元以外の CHALLENGE / CAPTCHA・許可された探索・トークンの受理) だけにして、
//     group by はそれぞれの軸の和集合にする。trusted_cidrs・探索パス・sign-in のパス・レートベース / 既定の action の除外は Go で行う
//     (Insights の isIpInSubnet・接頭辞の like・完全一致の in と同じ意味)
//   - カウントの一致は別のまま (評価中のマネージドルールを COUNT にすると全行に一致し、path の軸に入れると行が爆発する)
//   - レートは 2 段の stats (pct) なので別のまま (UTC の 1 日ずつ)
//
// 決定 (ADR 0067。上の分け方を置き換える): 行の多い種類を BLOCK と同じクエリに置かない。1' 全行 (+ trusted_cidrs が無ければカウントの一致の合計)、
// 2' BLOCK と許可された探索、3' Challenge / CAPTCHA、(trusted_cidrs があれば) ip の軸の無いカウントの一致、レート。CAPTCHA の多い時に
// CAPTCHA の (path × ip) の行が止めた・出した系の上限を埋め、BLOCK の行を押し出していた (大きなアカウントの rows_by_action)
//
// WAFQueries は wafv2 ソースの集計クエリ (順番どおりに流す。先頭は解釈率を兼ねる)。前処理の後ろに WebACL 名の取り出しを付ける。
func WAFQueries(p Profile, c config.Checks) []MergedQuery {
	head := wafHead(p)
	trusted := trustedFilter(c.WAFReview.TrustedCIDRs)
	pp := c.ProbePaths
	// 決定: strip_path_prefix があれば、接頭辞を必須にして判定する (API Gateway の REST API は全部のパスにステージ名が付く。sandbox で確認)
	sp := regexLiteral(p.StripPrefix)
	probe := "path like /^" + sp + "(" + prefixAlternation(pp.Paths) + ")/"
	if len(pp.ExcludePaths) > 0 {
		probe = and(probe, "path not like /^"+sp+"("+prefixAlternation(pp.ExcludePaths)+")/")
	}
	tail := func(metric string) string {
		return "\n| sort " + metric + " desc\n| limit " + strconv.Itoa(MaxRows)
	}
	filter := func(conds ...string) string {
		if f := and(conds...); f != "" {
			return "\n| filter " + f
		}
		return ""
	}

	// カウントのルールの位置のフィールド (一致しない行では null) と、探索パスの印 (parse の捕獲。探索パスでない行では null)
	fields := countFields()
	var present []string
	for _, f := range fields {
		if strings.HasSuffix(f, ".ruleId") {
			present = append(present, "ispresent("+f+")")
		}
	}
	probeParse := "\n| parse path /^" + sp + "(?<probe>" + prefixAlternation(pp.Paths) + ")/"
	countAxes := strings.Join(fields, ", ") + ", " + topSentinel + ", " + groupSentinel + ", probe"
	if len(pp.ExcludePaths) > 0 {
		probeParse += "\n| parse path /^" + sp + "(?<probe_ex>" + prefixAlternation(pp.ExcludePaths) + ")/"
		countAxes += ", probe_ex"
	}
	// 止めたグループの中のルール名は ruleGroupList.N.terminatingRule.ruleId を位置で取る (blockInner)。
	// 決定: `parse @message` の正規表現で最初の terminatingRule を取る案は、前にある COUNT のグループの terminatingRule を取り違えるのでやめた (sandbox で確認)
	var terms []string
	for i := 0; i < groupPositions; i++ {
		terms = append(terms, "ruleGroupList."+strconv.Itoa(i)+".terminatingRule.ruleId")
	}
	// 決定 (ADR 0067): カウントの一致の合計は、正規の送信元 (trusted_cidrs) が無ければ全行のクエリに入れる (ip の軸を持たないので上限に当たらない)。
	// trusted_cidrs があれば、全行のクエリでは正規の送信元を除けない (確かめ済みの機能では行の印にできない) ので、ip の軸を持たない別の 1 本にする
	mergeCount := trusted == "" && !separateCountQuery
	var qs []MergedQuery
	if mergeCount {
		lines := head + probeParse + "\n| stats count(*) as " + MetricLinesTotal + ", count(" + p.MatchField + ") as " + MetricLinesMatched +
			" by bin(1d) as day, acl, rule, action, " + countAxes + tail(MetricLinesTotal)
		qs = append(qs, MergedQuery{Name: wafLines, Query: lines, Metrics: []string{MetricLinesTotal, MetricWAFRuleAction, MetricWAFBlock, MetricWAFCountMatch}})
	} else {
		lines := head + "\n| stats count(*) as " + MetricLinesTotal + ", count(" + p.MatchField + ") as " + MetricLinesMatched +
			" by bin(1d) as day, acl, rule, action" + tail(MetricLinesTotal)
		qs = append(qs, MergedQuery{Name: wafLines, Query: lines, Metrics: []string{MetricLinesTotal, MetricWAFRuleAction, MetricWAFBlock}})
	}

	// 2': BLOCK と許可された探索 (正規の送信元でない)。カウントのルールの位置も軸に入れる (suspect の「BLOCK されたリクエストでの一致」。ADR 0067 の (i))
	blockCond := `action = "BLOCK" or (action = "ALLOW" and ` + probe + ")"
	if trusted != "" {
		blockCond = `action = "BLOCK" or (action = "ALLOW" and ` + and(probe, trusted) + ")"
	}
	blocks := head + "\n| filter " + blockCond +
		"\n| stats count(*) as " + wafActions + " by bin(1d) as day, acl, rule, action, terminatingRuleType, " + strings.Join(terms, ", ") + ", " + groupSentinel +
		", method, path, ip, " + strings.Join(fields, ", ") + ", " + topSentinel + tail(wafActions)
	qs = append(qs, MergedQuery{Name: wafBlocks, Query: blocks, Metrics: []string{MetricWAFBlockIP, MetricWAFBlockPath, MetricWAFAllowProbe, suspectBlockIP, MetricWAFCountMatchSuspect}})

	// 3': Challenge / CAPTCHA (出した・受理)。ADR 0028。
	// 決定: 受理の形は公式文書の説明 (トップレベルの challengeResponse / captchaResponse に solveTimestamp があり failureReason が無い) と
	// 例 (nonTerminatingMatchingRules の要素の action が CHALLENGE / CAPTCHA) が食い違うので、両方を受け付ける。グループの中の一致も位置で見る
	kinds := `["CHALLENGE", "CAPTCHA"]`
	accepted := challengeAcceptedFields()
	solvedConds := []string{"challengeResponse.solveTimestamp > 0", "captchaResponse.solveTimestamp > 0"}
	for _, f := range accepted {
		solvedConds = append(solvedConds, f+" in "+kinds)
	}
	chCond := "action in " + kinds + " or " + strings.Join(solvedConds, " or ")
	if trusted != "" {
		chCond = "(" + chCond + ") and " + trusted
	}
	challenges := head + "\n| filter " + chCond +
		"\n| stats count(*) as " + wafActions + " by bin(1d) as day, acl, rule, action, terminatingRuleType, " + strings.Join(terms, ", ") + ", " + groupSentinel +
		", method, path, ip, challengeResponse.solveTimestamp, challengeResponse.failureReason, captchaResponse.solveTimestamp, captchaResponse.failureReason, " +
		strings.Join(accepted, ", ") + tail(wafActions)
	qs = append(qs, MergedQuery{Name: wafChallenges, Query: challenges, Metrics: []string{MetricWAFChallengeIssued, challengeSolved}})

	if !mergeCount {
		// カウントの一致の合計と、探索パスへの一致 (ip の軸なし)
		count := head + filter("("+strings.Join(present, " or ")+")", trusted) + probeParse +
			"\n| stats count(*) as " + MetricWAFCountMatch + " by bin(1d) as day, acl, " + countAxes + tail(MetricWAFCountMatch)
		qs = append(qs, MergedQuery{Name: MetricWAFCountMatch, Query: count, Metrics: []string{MetricWAFCountMatch}})
	}
	return qs
}

func wafHead(p Profile) string {
	return p.Prelude + "\n" + `| parse webaclId /webacl\/(?<acl>[^\/]+)\//`
}

// WAFRateQuery は 1 IP あたり 5 分間の件数の分布のクエリ。UTC の 1 日ずつ流す (2 段の stats で日を切らないため)。
func WAFRateQuery(p Profile, c config.Checks) string {
	groups := append([]string(nil), c.WAFReview.RatePathGroups...)
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i]) > len(groups[j]) }) // 最長一致
	rate := wafHead(p)
	if t := trustedFilter(c.WAFReview.TrustedCIDRs); t != "" {
		rate += "\n| filter " + t
	}
	return rate + "\n| parse path /^" + regexLiteral(p.StripPrefix) + "(?<grp>" + prefixAlternation(groups) + ")/" +
		"\n| stats count(*) as n by bin(5m) as t, acl, grp, ip" +
		"\n| stats pct(n, 50) as " + MetricWAFIPRateP50 + ", pct(n, 99) as " + MetricWAFIPRateP99 + ", max(n) as " + MetricWAFIPRateMax + " by acl, grp"
}

// countFields はカウントの一致を見る平坦化されたフィールド (トップレベルのルール ID、グループ ID とその中のルール ID)。
func countFields() []string {
	var out []string
	for i := 0; i < countTopPositions; i++ {
		out = append(out, "nonTerminatingMatchingRules."+strconv.Itoa(i)+".ruleId")
	}
	for i := 0; i < groupPositions; i++ {
		g := "ruleGroupList." + strconv.Itoa(i)
		out = append(out, g+".ruleGroupId", g+".nonTerminatingMatchingRules.0.ruleId")
	}
	return out
}

// challengeAcceptedFields はトークンが受理された一致 (CHALLENGE / CAPTCHA が終了しなかった) の action を見る位置。
func challengeAcceptedFields() []string {
	var out []string
	for i := 0; i < countTopPositions; i++ {
		out = append(out, "nonTerminatingMatchingRules."+strconv.Itoa(i)+".action")
	}
	for i := 0; i < groupPositions; i++ {
		out = append(out, "ruleGroupList."+strconv.Itoa(i)+".nonTerminatingMatchingRules.0.action")
	}
	return out
}

// solvedKinds はトークンが受理された行の種類 (challenge / captcha)。
// トップレベルの <kind>Response は solveTimestamp があり failureReason が無く、その種類で止めていないとき。位置の action はそのまま。
func solvedKinds(r map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, k := range ChallengeKinds {
		ts := r[k+"Response.solveTimestamp"]
		if ts != "" && ts != "0" && r[k+"Response.failureReason"] == "" && r["action"] != strings.ToUpper(k) {
			out[k] = true
		}
	}
	for _, f := range challengeAcceptedFields() {
		if v := strings.ToLower(r[f]); v == "challenge" || v == "captcha" {
			out[v] = true
		}
	}
	return out
}

// blockInner は BLOCK の行の、止めたグループの中のルール名。
// 決定: 止めたのがグループ (terminatingRuleType が GROUP / MANAGED_RULE_GROUP) のときだけ、terminatingRule が null でない最後の位置を採る。
// 前にある COUNT のグループ (グループ全体を COUNT) は一致すると terminatingRule が null でなくなるが、止めたグループより後ろのグループは
// 評価されないので、最後の 1 つが止めたグループになる。位置の上限の後ろにグループがある (番兵が埋まっている) なら決めない (グループ単位にする)。
func blockInner(r map[string]string) (inner string, limited bool) {
	if r[groupSentinel] != "" {
		return "", true
	}
	if t := r["terminatingRuleType"]; t != "GROUP" && t != "MANAGED_RULE_GROUP" {
		return "", false
	}
	for i := groupPositions - 1; i >= 0; i-- {
		if v := r["ruleGroupList."+strconv.Itoa(i)+".terminatingRule.ruleId"]; v != "" {
			return v, false
		}
	}
	return "", false
}

// StripPrefix はパスから接頭辞 (strip_path_prefix) を外す。接頭辞の後ろが / か終わりのときだけ (/sandboxes は外さない)。
func StripPrefix(prefix, p string) string {
	if prefix == "" || !strings.HasPrefix(p, prefix) {
		return p
	}
	rest := p[len(prefix):]
	if rest == "" {
		return "/"
	}
	if rest[0] != '/' && rest[0] != '?' && rest[0] != '#' {
		return p
	}
	return rest
}

func trustedFilter(cidrs []string) string {
	var parts []string
	for _, c := range cidrs {
		parts = append(parts, "not isIpInSubnet(ip, "+stringLiteral(c)+")")
	}
	return strings.Join(parts, " and ")
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numRe  = regexp.MustCompile(`^[0-9]+$`)
)

// NormalizePath はパスからクエリとフラグメントを落とし、数字だけ・UUID の区間を `:id` にし、メールアドレスらしき文字列を伏せる。
func NormalizePath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if numRe.MatchString(s) || uuidRe.MatchString(s) {
			segs[i] = ":id"
		}
	}
	return Mask(strings.Join(segs, "/"))
}

// pathAgg は正規化した key ごとの件数と IP の集合。
type pathAgg map[string]map[string]*struct {
	n   float64
	ips map[string]bool
}

func (a pathAgg) add(day, key, ip string, n float64) {
	if a[day] == nil {
		a[day] = map[string]*struct {
			n   float64
			ips map[string]bool
		}{}
	}
	v := a[day][key]
	if v == nil {
		v = &struct {
			n   float64
			ips map[string]bool
		}{ips: map[string]bool{}}
		a[day][key] = v
	}
	v.n += n
	if ip != "" {
		v.ips[ip] = true
	}
}

// topKeys は 1 日分の key を件数の多い順に top 個返す。
func (c *Collector) topKeys(m map[string]*struct {
	n   float64
	ips map[string]bool
}, top int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]].n != m[keys[j]].n {
			return m[keys[i]].n > m[keys[j]].n
		}
		return keys[i] < keys[j]
	})
	if len(keys) > top {
		keys = keys[:top]
	}
	return keys
}

// emitTop は日ごとに件数の多い順に top 個の key の件数と異なり IP 数を出す。
func (c *Collector) emitTop(ctx context.Context, sink collect.RecordSink, a pathAgg, top int, count, ips string) error {
	days := make([]string, 0, len(a))
	for d := range a {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, d := range days {
		for _, k := range c.topKeys(a[d], top) {
			if err := sink.Emit(ctx, c.metric(d, count, k, a[d][k].n)); err != nil {
				return err
			}
			if err := sink.Emit(ctx, c.metric(d, ips, k, float64(len(a[d][k].ips)))); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectWAF は waf_review 用の集計を流して metric を出す。qs は WAFQueries、lines はその先頭 (解釈率 + ルールごとの件数) の結果。
func (c *Collector) collectWAF(ctx context.Context, qs []MergedQuery, lines []map[string]string, from, to time.Time, sink collect.RecordSink) error {
	if err := c.emitRuleActions(ctx, lines, sink); err != nil {
		return err
	}
	limits := dayCounts{} // 位置の上限を超えたリクエストの数 (waf_position_limit)
	blockRows, err := c.fetch(ctx, qs[1], from, to, time.Hour, false)
	if err != nil {
		return err
	}
	chRows, err := c.fetch(ctx, qs[2], from, to, time.Hour, false)
	if err != nil {
		return err
	}
	if err := c.emitActions(ctx, blockRows, chRows, limits, sink); err != nil {
		return err
	}
	// カウントの一致の合計は、全行のクエリか (trusted_cidrs が無いとき)、ip の軸の無い別の 1 本 (ADR 0067)
	countRows, nField := lines, MetricLinesTotal
	if len(qs) > 3 {
		if countRows, err = c.fetch(ctx, qs[3], from, to, time.Hour, false); err != nil {
			return err
		}
		nField = MetricWAFCountMatch
	}
	if err := c.emitCountMatches(ctx, countRows, nField, blockRows, limits, sink); err != nil {
		return err
	}
	rate := WAFRateQuery(c.prof, c.checks)
	if c.hourly() {
		if err := c.collectRateHourly(ctx, rate, from, to, sink); err != nil {
			return err
		}
		return limits.emit(ctx, c, sink)
	}
	for d := from; d.Before(to); d = d.Add(24 * time.Hour) {
		end := d.Add(24 * time.Hour)
		if end.After(to) {
			end = to
		}
		rows, err := c.Query(ctx, rate, d, end)
		c.stats.BytesScanned = c.scanned
		if err != nil {
			return err
		}
		day := d.UTC().Format(record.DateLayout)
		for _, r := range rows {
			grp := r["grp"]
			if grp == "" {
				grp = RateGroupOther
			}
			key := r["acl"] + "|" + grp
			for _, m := range []string{MetricWAFIPRateP50, MetricWAFIPRateP99, MetricWAFIPRateMax} {
				if err := sink.Emit(ctx, c.metric(day, m, key, num(r[m]))); err != nil {
					return err
				}
			}
		}
	}
	return limits.emit(ctx, c, sink)
}

// emitRuleActions は解釈率のクエリの行 (日, WebACL, ルール, action) から waf_rule_action と waf_block (ルール別、WebACL をまたいで足す) を出す。
func (c *Collector) emitRuleActions(ctx context.Context, rows []map[string]string, sink collect.RecordSink) error {
	actions, block := dayCounts{}, dayCounts{}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		n := num(r[MetricLinesTotal])
		actions.add(day, r["acl"]+"|"+r["rule"]+"|"+r["action"], n)
		if r["action"] == "BLOCK" {
			block.add(day, Mask(r["rule"]), n)
		}
	}
	for _, out := range []struct {
		name string
		m    dayCounts
	}{{MetricWAFRuleAction, actions}, {MetricWAFBlock, block}} {
		for _, day := range sortedDays(out.m) {
			for _, k := range sortedNames(out.m[day]) {
				if err := sink.Emit(ctx, c.metric(day, out.name, k, out.m[day][k])); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// emitActions は止めた・出した系の行を振り分けて、waf_block_ip・waf_block_path・waf_allow_probe・Challenge / CAPTCHA の metric を出す。
// blockRows は BLOCK と許可された探索のクエリ (2')、chRows は Challenge / CAPTCHA のクエリ (3') の行 (ADR 0067)。振り分けは前の版のクエリの filter と同じ意味 (ADR 0031)。
func (c *Collector) emitActions(ctx context.Context, blockRows, chRows []map[string]string, limits dayCounts, sink collect.RecordSink) error {
	wr, pp := c.checks.WAFReview, c.checks.ProbePaths
	sp := c.prof.StripPrefix
	signIn := map[string]bool{}
	for _, s := range c.checks.LoginBruteforce.Paths {
		signIn[sp+s] = true
	}
	trusted := parseCIDRs(wr.TrustedCIDRs)
	blockIP, blockIPSuspect, allowProbeIP := dayCounts{}, dayCounts{}, dayCounts{}
	blockPath, allowProbe, issued := pathAgg{}, pathAgg{}, pathAgg{}
	solved := map[string]map[string]map[string]bool{} // 日 → <WebACL>|<種類>|<method>|<パス> → トークンが受理された IP
	for pass, rows := range [][]map[string]string{blockRows, chRows} {
		ch := pass == 1
		for _, r := range rows {
			day, ok := parseDay(r["day"])
			if !ok {
				continue
			}
			n, action, path, ip := num(r[wafActions]), r["action"], r["path"], r["ip"]
			probe := hasPrefixAny(path, sp, pp.Paths) && !hasPrefixAny(path, sp, pp.ExcludePaths)
			normal := !inCIDRs(ip, trusted) // 正規の送信元 (trusted_cidrs) でない
			if action == "BLOCK" && !ch {
				blockIP.add(day, Mask(ip), n)
				// suspect の「BLOCK された IP」と同じ除外 (emitCountMatches・設計書 2 章の決定)。探索パスの BLOCK は数える
				if normal && r["terminatingRuleType"] != "RATE_BASED" && r["rule"] != "Default_Action" && !signIn[path] {
					blockIPSuspect.add(day, ip, n)
				}
				if !probe && normal {
					rule := r["rule"]
					inner, limited := blockInner(r)
					if inner != "" {
						rule += "/" + inner
					}
					if limited {
						limits.add(day, r["acl"]+"|ruleGroupList", n)
					}
					blockPath.add(day, r["acl"]+"|"+rule+"|"+r["method"]+"|"+c.normalize(path), ip, n)
				}
			}
			if !normal {
				continue
			}
			if action == "ALLOW" && probe && !ch {
				allowProbe.add(day, r["acl"]+"|"+c.normalize(path), ip, n)
				allowProbeIP.add(day, ip, n)
			}
			if !ch {
				continue
			}
			if action == "CHALLENGE" || action == "CAPTCHA" {
				rule := r["rule"]
				inner, limited := blockInner(r)
				if inner != "" {
					rule += "/" + inner
				}
				if limited {
					limits.add(day, r["acl"]+"|ruleGroupList", n)
				}
				issued.add(day, r["acl"]+"|"+strings.ToLower(action)+"|"+rule+"|"+r["method"]+"|"+c.normalize(path), ip, n)
			}
			if tokenRow(r) {
				for k := range solvedKinds(r) {
					key := r["acl"] + "|" + k + "|" + r["method"] + "|" + c.normalize(path)
					if solved[day] == nil {
						solved[day] = map[string]map[string]bool{}
					}
					if solved[day][key] == nil {
						solved[day][key] = map[string]bool{}
					}
					solved[day][key][ip] = true
				}
			}
		}
	}
	for _, day := range sortedDays(blockIP) {
		for _, k := range sortedNames(blockIP[day]) {
			if err := sink.Emit(ctx, c.metric(day, MetricWAFBlockIP, k, blockIP[day][k])); err != nil {
				return err
			}
		}
	}
	if c.IPList {
		for _, out := range []struct {
			name string
			m    dayCounts
		}{{MetricWAFBlockIPSuspect, blockIPSuspect}, {MetricWAFAllowProbeIP, allowProbeIP}} {
			for _, day := range sortedDays(out.m) {
				for _, k := range sortedNames(out.m[day]) {
					if err := sink.Emit(ctx, c.metric(day, out.name, k, out.m[day][k])); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := c.emitTop(ctx, sink, blockPath, wr.TopPaths, MetricWAFBlockPath, MetricWAFBlockPathIPs); err != nil {
		return err
	}
	if err := c.emitTop(ctx, sink, allowProbe, wr.TopPaths, MetricWAFAllowProbe, MetricWAFAllowProbeIPs); err != nil {
		return err
	}
	return c.emitChallenges(ctx, sink, issued, solved)
}

// tokenRow はトークンが受理された行の条件 (クエリの filter と同じ。solveTimestamp > 0 か、一致の action が CHALLENGE / CAPTCHA)。
func tokenRow(r map[string]string) bool {
	if num(r["challengeResponse.solveTimestamp"]) > 0 || num(r["captchaResponse.solveTimestamp"]) > 0 {
		return true
	}
	for _, f := range challengeAcceptedFields() {
		if v := r[f]; v == "CHALLENGE" || v == "CAPTCHA" {
			return true
		}
	}
	return false
}

func parseCIDRs(l []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range l {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// inCIDRs は ip が prefixes のどれかに入るか (Insights の isIpInSubnet と同じ。IP として読めなければ入らない)。
func inCIDRs(ip string, prefixes []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// emitChallenges は日ごとに出した件数の多い順に top_paths 個の key について、出した件数・異なり IP と、そのうち解いた IP の数を出す。
// 決定 (ADR 0028): 解いた IP は「出した IP」との積集合 (同じ日・同じ method とパス・同じ種類)。トークンは WebACL のルールで共有されるので
// ルールでは突き合わせない。後からトークンを持って別の画面に来た IP は数えない (割合が 1 を超えない)
func (c *Collector) emitChallenges(ctx context.Context, sink collect.RecordSink, issued pathAgg, solved map[string]map[string]map[string]bool) error {
	if err := c.emitTop(ctx, sink, issued, c.checks.WAFReview.TopPaths, MetricWAFChallengeIssued, MetricWAFChallengeIssuedIPs); err != nil {
		return err
	}
	for _, d := range sortedDays(issued) {
		for _, k := range c.topKeys(issued[d], c.checks.WAFReview.TopPaths) {
			parts := strings.SplitN(k, "|", 5)
			if len(parts) != 5 {
				continue
			}
			got := solved[d][parts[0]+"|"+parts[1]+"|"+parts[3]+"|"+parts[4]]
			n := 0
			for ip := range issued[d][k].ips {
				if got[ip] {
					n++
				}
			}
			if err := sink.Emit(ctx, c.metric(d, MetricWAFChallengeSolvedIPs, k, float64(n))); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Collector) normalize(p string) string {
	return NormalizePath(StripPrefix(c.prof.StripPrefix, p))
}

// dayCounts は日 → key → 件数。
type dayCounts map[string]map[string]float64

func (d dayCounts) add(day, key string, n float64) {
	if d[day] == nil {
		d[day] = map[string]float64{}
	}
	d[day][key] += n
}

func (d dayCounts) emit(ctx context.Context, c *Collector, sink collect.RecordSink) error {
	for _, day := range sortedDays(d) {
		for _, k := range sortedNames(d[day]) {
			if err := sink.Emit(ctx, c.metric(day, MetricWAFPositionLimit, k, d[day][k])); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitCountMatches は平坦化された位置ごとのルール ID を分解して、ルールごとの一致の件数を出す。
// ルールはトップレベルなら WebACL のルール名、グループの中なら `<ruleGroupId>/<ルール>`。
func (c *Collector) emitCountMatches(ctx context.Context, rows []map[string]string, nField string, blockRows []map[string]string, limits dayCounts, sink collect.RecordSink) error {
	total, suspect := map[string]map[string]float64{}, map[string]map[string]float64{}
	add := func(m map[string]map[string]float64, day, key string, n float64) {
		if m[day] == nil {
			m[day] = map[string]float64{}
		}
		m[day][key] += n
	}
	for _, r := range rows {
		day, ok := parseDay(r["day"])
		if !ok {
			continue
		}
		seen := countRules(r)
		if len(seen) == 0 && r[topSentinel] == "" {
			continue // カウントのルールに一致していない行 (全行のクエリの行)
		}
		n := num(r[nField])
		if r[topSentinel] != "" {
			limits.add(day, r["acl"]+"|nonTerminatingMatchingRules", n)
		}
		if r[groupSentinel] != "" {
			limits.add(day, r["acl"]+"|ruleGroupList", n)
		}
		bad := r["probe"] != "" && r["probe_ex"] == ""
		for id := range seen {
			key := r["acl"] + "|" + id
			add(total, day, key, n)
			add(suspect, day, key, 0)
			if bad {
				add(suspect, day, key, n)
			}
		}
	}
	// 決定 (ADR 0067 の (i)): suspect のもう半分は「BLOCK されたリクエストでもカウントのルールが一致した件数」。
	// BLOCK された IP の扱い (ADR 0023) と同じく、レートベースのルール・既定の action・sign-in のパス・正規の送信元の BLOCK は数えない。
	// 探索パスへの一致は上で数え済みなので、二重に数えない
	pp, sp := c.checks.ProbePaths, c.prof.StripPrefix
	trusted := parseCIDRs(c.checks.WAFReview.TrustedCIDRs)
	signIn := map[string]bool{}
	for _, p := range c.checks.LoginBruteforce.Paths {
		signIn[sp+p] = true
	}
	for _, r := range blockRows {
		day, ok := parseDay(r["day"])
		if !ok || r["action"] != "BLOCK" {
			continue
		}
		path := r["path"]
		if hasPrefixAny(path, sp, pp.Paths) && !hasPrefixAny(path, sp, pp.ExcludePaths) {
			continue
		}
		if r["terminatingRuleType"] == "RATE_BASED" || r["rule"] == "Default_Action" || signIn[path] || inCIDRs(r["ip"], trusted) {
			continue
		}
		for id := range countRules(r) {
			key := r["acl"] + "|" + id
			if total[day][key] > 0 {
				add(suspect, day, key, num(r[wafActions]))
			}
		}
	}
	for _, day := range sortedDays(total) {
		for _, key := range sortedNames(total[day]) {
			if err := sink.Emit(ctx, c.metric(day, MetricWAFCountMatch, key, total[day][key])); err != nil {
				return err
			}
			if err := sink.Emit(ctx, c.metric(day, MetricWAFCountMatchSuspect, key, suspect[day][key])); err != nil {
				return err
			}
		}
	}
	return nil
}

// countRules は行の、一致したカウントのルール (トップレベルの ID と、<グループ>/<グループの中の ID>)。
func countRules(r map[string]string) map[string]bool {
	seen := map[string]bool{}
	for i := 0; i < countTopPositions; i++ {
		if id := r["nonTerminatingMatchingRules."+strconv.Itoa(i)+".ruleId"]; id != "" {
			seen[id] = true
		}
	}
	for i := 0; i < groupPositions; i++ {
		g := "ruleGroupList." + strconv.Itoa(i)
		if id := r[g+".nonTerminatingMatchingRules.0.ruleId"]; id != "" {
			seen[r[g+".ruleGroupId"]+"/"+id] = true
		}
	}
	return seen
}

func sortedDays[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedNames(m map[string]float64) []string { return sortedDays(m) }
