package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/docs/ai"
	"github.com/CircleAround/arata/internal/report/schema"
)

// Block Kit の通知 (slack.format: blocks。ADR 0029)。
//
// 決定:
//   - 構成: header (重大度の絵文字 + arata <profile> — <name>) → fields (期間・新規の件数を重大度別・変化/再発・解消/未対応・情報)
//     → 要約 1〜2 文 → (取れていないもの) → 「まず対応」→「確認推奨」→ context (arata review・playbook・WAF の提案は別のメッセージ)。
//   - 「まず対応」= new / changed / recurred のうち urgent_severity (緊急の振り分けと同じ下限) 以上。1 件ずつ、1 行の「→ 何をするか」を付ける。
//     「確認推奨」= それ未満。同じチェック (と key の種類) の指摘は groupRules の対応表で 1 項目にまとめ、主体を `code` で並べる。
//     対応表に無いチェックと、1 件だけのグループは 1 件ずつ。解消・未対応・報告済み・情報は fields の件数だけ。
//   - まとめ方・振り分け・件数・重大度・取れていないものは規則で書く (LLM に任せない)。LLM が書くのは要約と「→」だけ (BlockNotes)。
//   - Slack の上限 (blocks 50、section 3000 字、header 150 字) を超えるときは、後ろの項目を「ほか N 件は `arata review`」に縮める。

// BlocksFallbackNotice は LLM が使えず、規則だけで組み立てた Block Kit を送るときの注記。
const BlocksFallbackNotice = "要約に失敗したため規則で組み立てました"

// LLM の文字列の上限 (rune 数)。
const (
	maxBlockSummaryRunes = 200
	maxActionRunes       = 80
	maxGroupNames        = 10
)

// finding の ID の表示 (aratam 設計書 3-5 章)。
const (
	// maxIDRunes は表示する id の上限。arata の id は 12 桁の 16 進だが、report.json の値も信用せず長さを規則で止める。
	maxIDRunes = 32
	// maxGroupIDs はまとめた項目に並べる id の数 (残りは件数と `arata review`)。
	maxGroupIDs = 5
	// maxItemLineRunes は項目の見出し・主体の行の上限。ログ由来の値がどれだけ長くても、section の上限 (3000 字) の切り詰めが id の表記に届かないようにする。
	maxItemLineRunes = 2000
)

// idText は表示用の id (1 行にし、長さを止める)。値は report.json の finding の id で、LLM の出力からは取らない。
func idText(id string) string { return clipRunes(oneLine(id), maxIDRunes) }

// idTag は finding 1 件の行の末尾に添える `id: 7f16a4507445` (id が空なら何も出さない)。
func idTag(id string) string {
	s := idText(id)
	if s == "" {
		return ""
	}
	return code("id: " + s)
}

// withID は行の末尾に id の表記を添える。
func withID(line, id string) string {
	if tag := idTag(id); tag != "" {
		return line + " " + tag
	}
	return line
}

// groupIDLine はまとめた項目の id の行 (主体と同じ順)。「id: `a` `b` … ほか N 件は `arata review`」。
func groupIDLine(fs []findingRef) string {
	var ids []string
	for _, f := range fs {
		if s := idText(f.id); s != "" {
			ids = append(ids, code(s))
		}
	}
	if len(ids) == 0 {
		return ""
	}
	rest := ""
	if len(ids) > maxGroupIDs {
		rest = fmt.Sprintf(" ほか %d 件は `arata review`", len(ids)-maxGroupIDs)
		ids = ids[:maxGroupIDs]
	}
	return "id: " + strings.Join(ids, " ") + rest
}

// noTick はバッククォートを ' に置き換える (ログ由来の値の 1 つだけのバッククォートが、後ろの id のコード表記と組になって崩さないように)。
func noTick(s string) string { return strings.ReplaceAll(s, "`", "'") }

// boldSummary は項目の見出しにする summary (1 行・エスケープ・太字。長さは maxItemLineRunes まで)。
func boldSummary(s string) string {
	return "*" + clipRunes(Escape(noTick(oneLine(s))), maxItemLineRunes) + "*"
}

// clipCode は `code` を含む行を maxItemLineRunes までにする。コード表記の途中で切れたら閉じる。
func clipCode(s string) string {
	s = clipRunes(s, maxItemLineRunes)
	if strings.Count(s, "`")%2 == 1 {
		s += "`"
	}
	return s
}

var severityEmoji = map[string]string{"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func sevEmoji(s string) string {
	if e, ok := severityEmoji[s]; ok {
		return e
	}
	return "⚪"
}

// BlockNotes は LLM が書くもの (blocks の契約)。Summary は要約 1〜2 文、Next は「まず対応」の finding_id ごとの「→」の 1 行。
type BlockNotes struct {
	Summary string            `json:"summary"`
	Next    map[string]string `json:"-"`
	// Rejected は検査で捨てた項目の理由 (ログ用。内容は書かない)。
	Rejected []string `json:"-"`
}

// groupRule はまとめ方の対応表の 1 行。name は 1 件の主体の表示 (mrkdwn。値はエスケープ済み)。
type groupRule struct {
	label, unit, sep string
	name             func(f findingRef) string
	// single は 1 件だけでも summary ではなく「*見出し* — 名前」の形で出す (summary が長いチェック)。
	single bool
	// next は項目の下に添える「→」(確認推奨の項目にも付けたいチェックだけ。規則の固定の文言)。
	next string
}

// groupRules は (check または check/key の種類) ごとのまとめ方。key の種類は key の最初の `|` より前 (credential_hygiene の no_mfa など)。
// 決定: 並べる値は IAM ユーザー名・ARN の末尾・IP・ルール名まで (個人を特定できる値を出さない。主体は ID で表す)。
var groupRules = map[string]groupRule{
	"credential_hygiene/no_mfa":          {"MFA の無いコンソールユーザー", "人", " ", func(f findingRef) string { return code(dataOrKey(f, "user", 1)) }, false, ""},
	"credential_hygiene/unused_key":      {"使われていないアクセスキー", "本", " ・ ", func(f findingRef) string { return code(dataOrKey(f, "user", 1)) + numSuffix(f, "days_unused", "日") }, false, ""},
	"credential_hygiene/root_access_key": {"ルートユーザーのアクセスキー", "本", " ", func(f findingRef) string { return code("キー " + dataOrKey(f, "key", 1)) }, false, ""},
	"new_principal":                      {"新しく観測した主体", "件", " ・ ", principalName, false, ""},
	"principal_new_source":               {"新しい送信元から使われた主体", "件", " ・ ", principalName, false, ""},
	"secret_access":                      {"秘匿値を読んだ主体", "件", " ・ ", principalName, false, ""},
	"access_denied":                      {"アクセス拒否が続く主体", "件", " ・ ", principalName, false, ""},
	"access_analyzer":                    {"外部からアクセスできるリソース", "件", " ・ ", func(f findingRef) string { return code(arnTail(dataOrKey(f, "resource", -1))) }, false, ""},
	"login_bruteforce":                   {"ログイン試行の急増", "件", " ・ ", func(f findingRef) string { return code(dataOrKey(f, "ip", 0)) + numSuffix(f, "count", "回") }, false, ""},
	"probe_paths":                        {"探索的なパスへのアクセス", "件", " ・ ", func(f findingRef) string { return code(dataOrKey(f, "ip", 0)) + numSuffix(f, "count", "回") }, false, ""},
	"waf_block_trend/top_ip":             {"WAF のブロックが多い IP", "件", " ・ ", func(f findingRef) string { return code(dataOrKey(f, "ip", 1)) + numSuffix(f, "count", "回") }, false, ""},
	"waf_block_trend/rule":               {"WAF の新しいルールのブロック", "件", " ・ ", func(f findingRef) string { return code(dataOrKey(f, "rule", 1)) + numSuffix(f, "count", "回") }, false, ""},
	// ADR 0030。playbook どおり確認・保留の運用へ回す (遮断は勧めない)
	"endpoint_abuse":        {"画面への分散した集中", "件", " ・ ", endpointName, true, abuseNext},
	"endpoint_abuse/follow": {"「A のあと B」の連鎖", "件", " ・ ", followName, true, abuseNext},
}

const abuseNext = "その時間幅の登録・送信をアプリの運営者が確認し、保留・承認待ちの運用へ回す (遮断はしない)"

// endpointName は「`signup` 25 IP / 10 分」(期間レポートは key だけ)。
func endpointName(f findingRef) string {
	return code(dataOrKey(f, "endpoint", -1)) + abuseIPs(f, "distinct_ips")
}

// followName は「`signup → post` 12 IP / 10 分」。
func followName(f findingRef) string {
	from, to, _ := strings.Cut(f.key, ">")
	return code(from+" → "+to) + abuseIPs(f, "ips")
}

func abuseIPs(f findingRef, field string) string {
	if f.finding == nil {
		return ""
	}
	v, ok := f.finding.Data[field].(float64)
	if !ok {
		return ""
	}
	s := fmt.Sprintf(" %g IP", v)
	if w, ok := f.finding.Data["window"].(string); ok && w != "" {
		if d, err := time.ParseDuration(w); err == nil {
			if d%time.Hour == 0 {
				w = fmt.Sprintf("%d 時間", int(d/time.Hour))
			} else {
				w = fmt.Sprintf("%d 分", int(d/time.Minute))
			}
		}
		s += " / " + Escape(oneLine(w)) // window もログ由来の値と同じく 1 行にする (FuzzFindingID で見つけた)
	}
	return s
}

func groupKeyOf(f findingRef) string {
	if f.check == "endpoint_abuse" && strings.Contains(f.key, ">") {
		return "endpoint_abuse/follow" // 「A のあと B」の key は from>to
	}
	kind, _, _ := strings.Cut(f.key, "|")
	if _, ok := groupRules[f.check+"/"+kind]; ok && kind != "" {
		return f.check + "/" + kind
	}
	if _, ok := groupRules[f.check]; ok {
		return f.check
	}
	return ""
}

// dataOrKey は data[field] (文字列) を返す。無ければ key を `|` で分けた i 番目 (i < 0 なら key 全体)。期間レポートの events は data を持たないため。
func dataOrKey(f findingRef, field string, i int) string {
	if f.finding != nil {
		if v, ok := f.finding.Data[field].(string); ok && v != "" {
			return v
		}
	}
	if i < 0 {
		return f.key
	}
	parts := strings.Split(f.key, "|")
	if i < len(parts) {
		return parts[i]
	}
	return f.key
}

func numSuffix(f findingRef, field, unit string) string {
	if f.finding == nil {
		return ""
	}
	if v, ok := f.finding.Data[field].(float64); ok {
		return fmt.Sprintf(" %g %s", v, unit)
	}
	return ""
}

// principalName は ARN の末尾 (user/x・role/x)。data に external_account があればアカウント ID を添える。
func principalName(f findingRef) string {
	arn, _, _ := strings.Cut(f.key, "|")
	// 決定 (account_only.go): アカウントしか分からない主体 (`arn:aws:iam::NNN:root`) は「外部アカウント NNN」と書く (ARN の末尾の `root` を出さない)
	if a, ok := accountOnlyOf(f); ok && schema.AccountRootARNRe.FindString(arn) == arn {
		return code("外部アカウント " + a)
	}
	s := code(arnTail(arn))
	if f.finding != nil {
		if a, ok := f.finding.Data["external_account"].(string); ok && a != "" {
			s += " (" + Escape(a) + ")"
		}
	}
	return s
}

// arnTail は ARN のリソースの部分 (arn:aws:iam::123456789012:user/x → user/x)。ARN でなければそのまま。
func arnTail(s string) string {
	if !strings.HasPrefix(s, "arn:") {
		return s
	}
	parts := strings.SplitN(s, ":", 6)
	if len(parts) == 6 && parts[5] != "" {
		return parts[5]
	}
	return s
}

// code は値を `code` にする (バッククォートは書式を崩すので ' に置き換える)。
func code(s string) string {
	return "`" + Escape(strings.ReplaceAll(oneLine(s), "`", "'")) + "`"
}

// diffMark は変化・再発の印 (新規は付けない)。
func diffMark(f findingRef) string {
	if f.diff == "変化" || f.diff == "再発" {
		return " (" + f.diff + ")"
	}
	return ""
}

// item はブロック 1 つ分の項目 (n は含む finding の数。縮めるときの「ほか N 件」に使う)。
type item struct {
	sev   string
	text  string
	n     int
	first int
}

// splitUrgent は new / changed / recurred を「まず対応」(urgent_severity 以上) とそれ未満に分ける (report.json の順)。
func splitUrgent(in *Input, urgent string) (top, rest []findingRef) {
	list, _ := findingIndex(in)
	for _, f := range list {
		if !f.required {
			continue
		}
		if severityRank[f.severity] >= severityRank[urgent] {
			top = append(top, f)
		} else {
			rest = append(rest, f)
		}
	}
	// 重大度の高い順 (同じなら report.json の順)
	sort.SliceStable(top, func(i, j int) bool { return severityRank[top[i].severity] > severityRank[top[j].severity] })
	return top, rest
}

// urgentItems は「まず対応」の項目 (1 件ずつ、「→」付き。見出しの行の末尾に id)。
func urgentItems(top []findingRef, notes *BlockNotes) []item {
	var out []item
	for i, f := range top {
		action := ""
		if notes != nil {
			action = notes.Next[f.id]
		}
		if action == "" {
			action = ruleAction(f.check)
		}
		if action == "" {
			action = "`arata review` で詳細を確認する"
		} else {
			action = Escape(action)
		}
		out = append(out, item{sev: f.severity, n: 1, first: i,
			text: withID(fmt.Sprintf("%s %s%s", sevEmoji(f.severity), boldSummary(f.summary), diffMark(f)), f.id) + "\n→ " + action})
	}
	return out
}

// groupItems は「確認推奨」の項目。対応表にあるチェックは 1 項目にまとめる。並びは重大度の高い順、同じなら最初の出現順。
// 1 件ずつの項目は行の末尾に id、まとめた項目は主体の行の下に id の行 (groupIDLine)。
func groupItems(rest []findingRef) []item {
	type group struct {
		key string
		fs  []findingRef
	}
	var order []*group
	byKey := map[string]*group{}
	for _, f := range rest {
		k := groupKeyOf(f)
		if k == "" {
			order = append(order, &group{fs: []findingRef{f}})
			continue
		}
		g, ok := byKey[k]
		if !ok {
			g = &group{key: k}
			byKey[k] = g
			order = append(order, g)
		}
		g.fs = append(g.fs, f)
	}
	var out []item
	for i, g := range order {
		sev := g.fs[0].severity
		for _, f := range g.fs {
			if severityRank[f.severity] > severityRank[sev] {
				sev = f.severity
			}
		}
		if r, ok := groupRules[g.key]; ok && r.single && len(g.fs) == 1 {
			f := g.fs[0]
			text := withID(clipCode(fmt.Sprintf("%s *%s* — %s%s", sevEmoji(sev), r.label, r.name(f), diffMark(f))), f.id)
			if r.next != "" {
				text += "\n→ " + r.next
			}
			out = append(out, item{sev: sev, n: 1, first: i, text: text})
			continue
		}
		if len(g.fs) == 1 {
			f := g.fs[0]
			out = append(out, item{sev: sev, n: 1, first: i, text: withID(fmt.Sprintf("%s %s%s", sevEmoji(sev), boldSummary(f.summary), diffMark(f)), f.id)})
			continue
		}
		r := groupRules[g.key]
		var names []string
		for j, f := range g.fs {
			if j == maxGroupNames {
				names = append(names, fmt.Sprintf("ほか %d", len(g.fs)-maxGroupNames))
				break
			}
			names = append(names, r.name(f)+diffMark(f))
		}
		text := fmt.Sprintf("%s *%s* %d %s\n%s", sevEmoji(sev), r.label, len(g.fs), r.unit, clipCode(strings.Join(names, r.sep)))
		if ids := groupIDLine(g.fs); ids != "" {
			text += "\n" + ids
		}
		if r.next != "" {
			text += "\n→ " + r.next
		}
		out = append(out, item{sev: sev, n: len(g.fs), first: i, text: text})
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank[out[i].sev] > severityRank[out[j].sev] })
	return out
}

var (
	optionsHeading = "## 対処の選択肢"
	parenWithCode  = regexp.MustCompile("\\s*\\([^()]*`[^()]*\\)")
	trailingParen  = regexp.MustCompile(`\s*\([^()]*\)$`)
)

// ruleAction は provider: none (と LLM が書かなかった項目) の「→」。playbook の「対処の選択肢」の先頭の項目を、
// 太字とコマンドの括弧を除いて最初の文まで (80 字まで) にする。playbook が無ければ空。
// 決定: 先頭の項目は「封じ込め (不審な使用がある)」のように条件が付くので、条件ごと残す (条件を落とすと過剰な対処を勧めることになる)。
func ruleAction(check string) string {
	body, ok := ai.Playbook(check)
	if !ok {
		return ""
	}
	_, sec, ok := strings.Cut(body, optionsHeading)
	if !ok {
		return ""
	}
	for _, l := range strings.Split(sec, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "## ") {
			break
		}
		s, ok := strings.CutPrefix(l, "1. ")
		if !ok {
			continue
		}
		s = parenWithCode.ReplaceAllString(s, "")
		s = strings.NewReplacer("**", "", "`", "").Replace(s)
		s, _, _ = strings.Cut(s, "。")
		s = strings.TrimRight(strings.TrimSpace(s), "、, ")
		s = trailingParen.ReplaceAllString(s, "") // 末尾の補足 (「(ルートでサインインして…)」など) は落とす。条件の括弧は「:」の前なので残る
		return clipRunes(s, maxActionRunes)
	}
	return ""
}

// windowText は blocks の期間の表示。run の窓 (RFC 3339) は設定のゾーンの MM/DD HH:MM とその略称、
// 期間レポートの期間は日付だけ (arata が UTC の日として決めた値) なので、そのまま UTC と書く。
func windowText(in *Input) string {
	if in.Run != nil {
		return in.Zone.span(in.Run.Window.From, in.Run.Window.To)
	}
	return dateSpan(in.Period.Period.From, in.Period.Period.To)
}

// bySeverity は「🔴 high 1 ・ 🟠 medium 10」(0 件なら「0 件」)。
func bySeverity(sevs []string) string {
	n := map[string]int{}
	for _, s := range sevs {
		n[s]++
	}
	var parts []string
	for _, s := range severityOrder {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %s %d", sevEmoji(s), s, n[s]))
		}
	}
	if len(parts) == 0 {
		return "0 件"
	}
	return strings.Join(parts, " ・ ")
}

func headerTitle(in *Input) (string, string) {
	if in.Run != nil {
		return "arata " + in.Run.Profile, in.Run.Name
	}
	return "arata 期間レポート", in.Period.Name
}

// countFields は fields (件数は report.json の値)。
// 決定: ラベルと値を 2 段に分けず、1 つの値に「解消 1 件 ・ 未対応 0 件」のように書く (2 段の表示は分かりにくいという意見があったため)。
func countFields(in *Input) []string {
	fs := []string{"*期間* " + Escape(windowText(in))}
	if r := in.Run; r != nil {
		var sevs []string
		for _, f := range r.Findings.New {
			sevs = append(sevs, f.Severity)
		}
		fs = append(fs, "*新規* "+bySeverity(sevs))
		if r.Summary.Changed+r.Summary.Recurred > 0 {
			fs = append(fs, fmt.Sprintf("変化 %d 件 ・ 再発 %d 件", r.Summary.Changed, r.Summary.Recurred))
		}
		fs = append(fs, fmt.Sprintf("解消 %d 件 ・ 未対応 %d 件", r.Summary.Resolved, r.Summary.StillOpen))
		if n := len(r.AlreadyReported); n > 0 {
			fs = append(fs, fmt.Sprintf("本日報告済み %d 件", n))
		}
		if n := len(r.Info); n > 0 {
			fs = append(fs, fmt.Sprintf("情報 %d 件 (件数のみ)", n))
		}
		return fs
	}
	p := in.Period
	var sevs []string
	for _, e := range p.Events.New {
		sevs = append(sevs, e.Severity)
	}
	fs = append(fs, "*新規* "+bySeverity(sevs))
	if p.Summary.Changed+p.Summary.Recurred > 0 {
		fs = append(fs, fmt.Sprintf("変化 %d 件 ・ 再発 %d 件", p.Summary.Changed, p.Summary.Recurred))
	}
	fs = append(fs, fmt.Sprintf("解消 %d 件 ・ 未対応の残存 %d 件", p.Summary.Resolved, p.Summary.Open))
	return fs
}

// maxSeverityOf は header の絵文字に使う重大度 (run は summary.max_severity、期間レポートは events の最大)。
func maxSeverityOf(in *Input) string {
	if in.Run != nil {
		return in.Run.Summary.MaxSeverity
	}
	best := ""
	list, _ := findingIndex(in)
	for _, f := range list {
		if f.required && severityRank[f.severity] > severityRank[best] {
			best = f.severity
		}
	}
	return best
}

// notifyText は通知用の text (プッシュ通知・検索に使われる 1 行)。
func notifyText(in *Input) string {
	var s string
	if in.Run != nil {
		s = fmt.Sprintf("%s: 新規 %d 件", title(in), in.Run.Summary.New)
	} else {
		s = fmt.Sprintf("%s %s: 新規 %d 件", title(in), period(in), in.Period.Summary.New)
	}
	if m := maxSeverityOf(in); m != "" {
		s += "、最大 " + m
	}
	return clipRunes(Escape(s), maxNotifyRunes)
}

// ruleSummary は provider: none の要約 (規則)。
func ruleSummary(top, rest []findingRef, urgent string) string {
	switch {
	case len(top) > 0:
		return fmt.Sprintf("まず対応 %d 件 (最も重いのは「%s」)、確認推奨 %d 件。", len(top), Escape(oneLine(top[0].summary)), len(rest))
	case len(rest) > 0:
		return fmt.Sprintf("確認推奨 %d 件。%s 以上の指摘はありません。", len(rest), urgent)
	default:
		return "新規・変化・再発の指摘はありません。"
	}
}

// topSection はメンション・注記・警告の section (無ければ nil)。
func topSection(route Route, r Rules, notice string, warnings []string) []Block {
	if lines := head(route, r, notice, warnings); len(lines) > 0 {
		return []Block{sectionBlock(strings.Join(lines, "\n"))}
	}
	return nil
}

// RunBlocks は run / 期間レポートの Block Kit。notes は LLM の要約と「→」(nil なら規則)。notice は LLM が使えなかったときの注記。
func RunBlocks(in *Input, d Decision, r Rules, warnings []string, notes *BlockNotes, notice string) Message {
	top, rest := splitUrgent(in, r.UrgentSeverity)
	name, target := headerTitle(in)
	var head []Block
	head = append(head, topSection(d.Route, r, notice, warnings)...)
	head = append(head, headerBlock(fmt.Sprintf("%s %s — %s", sevEmoji(maxSeverityOf(in)), name, target)), fieldsBlock(countFields(in)...))
	summary := ""
	if notes != nil && strings.TrimSpace(notes.Summary) != "" {
		summary = Escape(clipRunes(oneLine(notes.Summary), maxBlockSummaryRunes))
	} else {
		summary = ruleSummary(top, rest, r.UrgentSeverity)
	}
	head = append(head, sectionBlock(summary))
	if cov := nonEmpty(coverageLines(in)); len(cov) > 0 {
		head = append(head, sectionBlock("⚠️ *取れていないもの* (結果が欠けている可能性があります)\n"+strings.Join(cov, "\n")))
	}

	foot := []string{"全文と対処手順: `arata review` ・ `arata help ai playbook <check>`"}
	if in.Run != nil && len(in.Run.Proposals) > 0 {
		foot = append(foot, "WAF の改善提案は別のメッセージ")
	}
	if notes != nil {
		foot = append(foot, LLMNotice)
	}
	foot = append(foot, Escape(filepath.Join(in.Dir, ReportMD)))
	tail := []Block{contextBlock(strings.Join(foot[:len(foot)-1], "  |  "), foot[len(foot)-1])}

	// 項目を順に入れ、入らなくなったら残りを「ほか N 件」にまとめる (縮めた行の 1 ブロックは残しておく)
	type piece struct {
		blocks []Block
		n      int
	}
	var pieces []piece
	for _, s := range []struct {
		title string
		items []item
	}{{"*まず対応*", urgentItems(top, notes)}, {"*確認推奨*", groupItems(rest)}} {
		for i, it := range s.items {
			p := piece{blocks: []Block{sectionBlock(it.text)}, n: it.n}
			if i == 0 {
				p.blocks = append([]Block{dividerBlock(), sectionBlock(s.title)}, p.blocks...)
			}
			pieces = append(pieces, p)
		}
	}
	budget := MaxBlocks - len(head) - len(tail)
	var body []Block
	dropped := 0
	for i, p := range pieces {
		reserve := 0
		if i < len(pieces)-1 {
			reserve = 1
		}
		if dropped > 0 || len(body)+len(p.blocks)+reserve > budget {
			dropped += p.n
			continue
		}
		body = append(body, p.blocks...)
	}
	if dropped > 0 {
		body = append(body, sectionBlock(fmt.Sprintf("ほか %d 件は `arata review` で確認してください", dropped)))
	}
	blocks := append(append(head, body...), tail...)
	return Message{Text: notifyText(in), Blocks: blocks}
}

func nonEmpty(ls []string) []string {
	var out []string
	for _, l := range ls {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// QuietBlocks は on_quiet: short の Block Kit。
func QuietBlocks(in *Input, d Decision, r Rules, warnings []string) Message {
	name, target := headerTitle(in)
	blocks := topSection(d.Route, r, "", warnings)
	blocks = append(blocks,
		headerBlock(fmt.Sprintf("✅ %s — %s", name, target)),
		sectionBlock(fmt.Sprintf("%s: *新規なし* (変化・再発なし、取得の失敗なし。未対応 %d 件)", Escape(windowText(in)), in.Run.Summary.StillOpen)))
	return Message{Text: clipRunes(Escape(title(in))+": 新規なし", maxNotifyRunes), Blocks: blocks}
}

// InputProblemBlocks は arata の出力が無い・読めない・古いときの Block Kit (緊急用)。
func InputProblemBlocks(dir string, e *InputError, r Rules) Message {
	blocks := topSection(RouteUrgent, r, "", nil)
	blocks = append(blocks,
		headerBlock("⚠️ arata の出力が無いか古い — "+r.Name),
		sectionBlock("*監査結果を通知できません*\n• 理由: "+Escape(clipRunes(oneLine(e.reasonIn(r.Zone)), maxProblemRunes))+" (`"+e.Code+"`)\n• 入力: "+Escape(dir)),
		contextBlock("arata が実行されていないか、失敗しています。cron と arata のログを確認してください。"))
	return Message{Text: clipRunes(Escape(fmt.Sprintf("arata の出力が無いか古いため、監査結果を通知できません (%s)", r.Name)), maxNotifyRunes), Blocks: blocks}
}

// BlocksSystemPrompt は blocks の書式で LLM に渡す system。LLM が書くのは要約と「まず対応」の「→」だけ。
// targets は「まず対応」の finding (規則で決めたもの)。
func BlocksSystemPrompt(kind, context, playbooks string, targets []findingRef) string {
	t, err := ai.Lookup("report")
	if err != nil {
		panic(err) // 埋め込んだ文書なので起きない
	}
	input := "arata の report.json (日次などのプロファイル実行の結果)"
	if kind == KindPeriod {
		input = "arata の期間レポートの report.json (\"kind\": \"period\")"
	}
	var ts []string
	for _, f := range targets {
		ts = append(ts, fmt.Sprintf("- %s (%s, %s): %s", f.id, f.check, f.severity, oneLine(f.summary)))
	}
	list := "(なし。next は空の配列にする)"
	if len(ts) > 0 {
		list = strings.Join(ts, "\n")
	}
	return fmt.Sprintf(`あなたは AWS 監査ツール arata の Slack 通知に、短い文を書く担当です。ユーザーのメッセージは %s です。
通知の構成 (件数・重大度・振り分け・同じチェックのまとめ) は規則で作ります。あなたが書くのは次の 2 つだけです。
下の「report.json の読み方と要約の手順」に従って読み、次の JSON だけを出力してください (前後に文章やコードフェンスを付けない)。

{
  "summary": "全体の要約 1〜2 文 (日本語、100 字程度)",
  "next": [{"finding_id": "下の「まず対応」の id", "action": "人が次にすること 1 文 (日本語、60 字程度)"}]
}

「まず対応」の finding (この id にだけ action を書く。1 件 1 つ):
%s

規則:
- summary は、読む人が最初に知るべきこと (何が起きたか・急ぐものがあるか) を 1〜2 文で書く。件数の一覧や重大度の羅列はしない (通知に別に表示される)。
- action は「→」の後に表示される。対処手順 (playbook) と利用者の前提に沿って、人が次にする具体的な 1 つのことを書く。確かめていないことを確かめたことにしない。
- 重大度は変えない。critical / high を軽く見せる書き方をしない。
- 封じ込め・設定の変更・approve / ack / snooze / resolve は人への提案にとどめる。あなたは実行しない。
- 個人を特定できる値 (氏名・メールアドレスなど) を書かない。主体は ARN や ID で書く。
- 追加の照会はできない。report.json に書かれていることだけで判断し、推測は「可能性」と書く。
%s
%s

---

%s%s%s`, input, list, untrustedInputRule, accountOnlyRule, t.Markdown(), playbooks, contextSection(context))
}

// ParseBlockNotes は blocks の契約の出力を検証する。summary が空なら形が不正 (再試行し、だめなら規則で組み立てる)。
// 知らない id・「まず対応」以外の id・同じ id の 2 件目以降・空の action は捨てる (捨てた項目は規則の「→」になる)。
// 決定 (account_only.go): 主体がアカウントしか分からない finding をルートユーザーの利用と書いた文は、ARN を置き換え、root の語が残れば捨てる
// (summary は形の不正、「→」は規則の文に戻る)。in は報告の全体 (summary の検査に使う)。
func ParseBlockNotes(raw []byte, in *Input, targets []findingRef) (*BlockNotes, error) {
	b := bytes.TrimSpace(raw)
	if i, j := bytes.IndexByte(b, '{'), bytes.LastIndexByte(b, '}'); i >= 0 && j > i {
		b = b[i : j+1]
	}
	var out struct {
		Summary string `json:"summary"`
		Next    []struct {
			FindingID string `json:"finding_id"`
			Action    string `json:"action"`
		} `json:"next"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("llm output is not the expected JSON: %w", err)
	}
	if strings.TrimSpace(out.Summary) == "" {
		return nil, errors.New("llm output has no summary")
	}
	if why := rejectLLMText(out.Summary); why != "" {
		return nil, fmt.Errorf("llm summary rejected: %s", why)
	}
	all, _ := findingIndex(in)
	summary, why := newRootGuard(all...).apply(out.Summary, false)
	if why != "" {
		return nil, fmt.Errorf("llm summary rejected: %s", why)
	}
	allowed := map[string]findingRef{}
	for _, f := range targets {
		allowed[f.id] = f
	}
	n := &BlockNotes{Summary: summary, Next: map[string]string{}}
	for _, x := range out.Next {
		a := oneLine(x.Action)
		f, ok := allowed[x.FindingID]
		if !ok || a == "" {
			continue
		}
		if _, dup := n.Next[x.FindingID]; dup {
			continue
		}
		if why := rejectLLMText(a); why != "" {
			n.Rejected = append(n.Rejected, x.FindingID+": "+why)
			continue
		}
		if a, why = newRootGuard(f).apply(a, true); why != "" {
			n.Rejected = append(n.Rejected, x.FindingID+": "+why)
			continue
		}
		n.Next[x.FindingID] = clipRunes(strings.TrimPrefix(a, "→ "), maxActionRunes)
	}
	return n, nil
}
