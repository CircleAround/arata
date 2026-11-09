// Package schema は arata が書く report.json (日次などのプロファイル実行と期間レポート) の型と、report.md の書き出し。
//
// 決定 (ADR 0018): 標準ライブラリだけに依存させる。arata の出力を読む aratam が import しても、
// ストア (SQLite) や AWS SDK のサービスがバイナリに入らないようにするため。組み立て (Build / BuildPeriod) は internal/report に置く。
package schema

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Report は report.json の骨子。
type Report struct {
	Profile         string    `json:"profile"`
	Window          Window    `json:"window"`
	Name            string    `json:"name"`
	RunID           string    `json:"run_id"`
	GeneratedAt     string    `json:"generated_at"`
	Summary         Summary   `json:"summary"`
	Findings        Findings  `json:"findings"`
	AlreadyReported []Finding `json:"already_reported"`
	Info            []Finding `json:"info"`
	Coverage        Coverage  `json:"coverage"`
	// Proposals は WAF の修正提案の候補 (waf_review。ADR 0023)。finding ではなく、毎回その時点の候補を出す (差分判定に乗せない)。
	// waf_review が走らなかった run では出さない (omitempty)。読む側は無い節を「候補なし」として扱う。
	Proposals []Proposal `json:"proposals,omitempty"`
}

// Proposal は WAF の修正提案の候補 1 件。arata が決まった規則で作り、根拠の数字を Evidence に持つ。適用は人が判断する。
type Proposal struct {
	// Kind は候補の種類 (false_positive / challenge_on_app_path / probe_allowed / rate_limit_missing / rate_limit_loose / rate_limit_tight / unused_rule)、
	// または observation (提案はしないが、WAF の設定の観点で気づいた観測。COUNT のルールの状況 count_rule_status、
	// Challenge / CAPTCHA の状況 challenge_impact もここ)。
	Kind string `json:"kind"`
	// About は observation が関わる候補の種類 (false_positive など) か count_rule_status (COUNT のルールの状況)・
	// challenge_impact (Challenge / CAPTCHA の状況)。提案では空。
	About string `json:"about,omitempty"`
	// Reason は observation で提案しなかった理由: below_threshold (閾値未満) / undetermined (判断できない) /
	// excluded_by_config (除外設定に一致) / excluded_by_rule (決まった除外に一致。レートベースのルールなど) / position_limit (数え漏れの可能性) /
	// informational (提案の候補ではない情報。count_rule_status・challenge_impact)。
	Reason string `json:"reason,omitempty"`
	// Stage は提案の段階: count_first (まず COUNT で様子を見る) / review (人が見直す。変更は勧めない) / none (observation。提案なし)。
	// COUNT → BLOCK の切り替えは運用で計画して行うので、arata は勧めない (ADR 0023)。
	Stage  string `json:"stage"`
	WebACL string `json:"web_acl"`
	Scope  string `json:"scope,omitempty"`
	Region string `json:"region,omitempty"`
	// Rule は WebACL のルール名。RuleInGroup はルールグループの中のルール名 (グループの中の 1 つが対象のとき)。
	Rule        string `json:"rule,omitempty"`
	RuleInGroup string `json:"rule_in_group,omitempty"`
	Method      string `json:"method,omitempty"`
	// Path は正規化したパス (クエリを落とし、数字・UUID の区間は :id)。
	Path    string `json:"path,omitempty"`
	Summary string `json:"summary"`
	// Evidence は根拠の数字 (件数・異なり IP 数・日数・p99 など) と、提案する値 (レート制限の limit など)。
	Evidence map[string]any `json:"evidence"`
	// FindingKey は同じ候補を low の finding にもしたときの key (重大な候補だけ)。
	FindingKey string `json:"finding_key,omitempty"`
}

// Window は対象期間。
type Window struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Summary は通知の分岐に使う要約。
type Summary struct {
	New           int            `json:"new"`
	Changed       int            `json:"changed"`
	Recurred      int            `json:"recurred"`
	Resolved      int            `json:"resolved"`
	StillOpen     int            `json:"still_open"`
	MaxSeverity   string         `json:"max_severity"`
	CollectErrors []CollectError `json:"collect_errors"`
}

// CollectError は収集失敗 1 件。covered_from / covered_until は失敗するまでに取得できた期間 (取れていなければ空)。
// CloudTrail LookupEvents は新しい順に返すので、取りこぼすのは covered_from より古い側。
type CollectError struct {
	Source string `json:"source"`
	Code   string `json:"code"`
	// Action は不足した IAM action (ACCESS_DENIED のとき)。
	Action string `json:"action,omitempty"`
	// Partial は一部の項目だけ取れなかった (取れた項目でチェックは走った) こと。
	Partial      bool   `json:"partial,omitempty"`
	Message      string `json:"message"`
	CoveredFrom  string `json:"covered_from,omitempty"`
	CoveredUntil string `json:"covered_until,omitempty"`
}

// SourceFailure は coverage.sources_failed の 1 件。
type SourceFailure struct {
	Source       string `json:"source"`
	Code         string `json:"code"`
	Action       string `json:"action,omitempty"`
	Partial      bool   `json:"partial,omitempty"`
	CoveredFrom  string `json:"covered_from,omitempty"`
	CoveredUntil string `json:"covered_until,omitempty"`
}

// Findings は差分クラスごとの一覧。
type Findings struct {
	New       []Finding `json:"new"`
	Changed   []Finding `json:"changed"`
	Recurred  []Finding `json:"recurred"`
	Resolved  []Finding `json:"resolved"`
	StillOpen []Finding `json:"still_open"`
}

// Finding は finding 1 件の出力形。
type Finding struct {
	ID          string         `json:"id"`
	Check       string         `json:"check"`
	Key         string         `json:"key"`
	Severity    string         `json:"severity"`
	Summary     string         `json:"summary"`
	Status      string         `json:"status"`
	FirstSeen   string         `json:"first_seen"`
	LastSeen    string         `json:"last_seen"`
	LastChanged string         `json:"last_changed"`
	ReportedAt  string         `json:"reported_at,omitempty"`
	Data        map[string]any `json:"data"`
}

// Coverage は「取れていたか」を示す。必ず出す。
type Coverage struct {
	SourcesOK     []string        `json:"sources_ok"`
	SourcesFailed []SourceFailure `json:"sources_failed"`
	ChecksRun     []string        `json:"checks_run"`
	ChecksSkipped []SkippedCheck  `json:"checks_skipped"`
	// Formats は cloudwatch-logs ソースの解釈率 (設計書 2-2)。「取れていたか」の一部として必ず出す。
	Formats []FormatCoverage `json:"formats"`
}

// FormatCoverage はソース 1 つの解釈率。match_rate は行が無ければ null。
// code は FORMAT_MISMATCH (閾値未満。ソースは失敗扱い) / FORMAT_DRIFT (直近平均から急落。警告) / 空。
type FormatCoverage struct {
	Source        string   `json:"source"`
	Format        string   `json:"format"`
	LogGroup      string   `json:"log_group"`
	Total         int64    `json:"total"`
	Matched       int64    `json:"matched"`
	MatchRate     *float64 `json:"match_rate"`
	Expected      float64  `json:"expected"`
	RecentAverage *float64 `json:"recent_average,omitempty"`
	BytesScanned  float64  `json:"bytes_scanned"`
	Code          string   `json:"code,omitempty"`
	// Truncated は結果が行の上限 (10000) に当たった集計の名前 (件数は少なめ)。
	Truncated []string `json:"truncated,omitempty"`
}

// SkippedCheck は走らなかったチェックと理由。
type SkippedCheck struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// JSON は整形済み JSON を返す。
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Parse は JSON からレポートを復元する。
func Parse(b []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// PeriodReport は期間レポート (`report --from --to`、月次は `--month`) の report.json。
// 決定 (ADR 0016): 収集も評価もせず、ストア (finding_events / findings / principals / metrics / runs) だけから作る。
type PeriodReport struct {
	Kind        string `json:"kind"` // "period"
	Name        string `json:"name"`
	Period      Period `json:"period"`
	GeneratedAt string `json:"generated_at"`
	// HistorySince は状態遷移の履歴を記録し始めた時刻。Notes にこれより前は履歴が無いことを書く。
	HistorySince  string          `json:"history_since,omitempty"`
	Notes         []string        `json:"notes"`
	Summary       PeriodSummary   `json:"summary"`
	Events        PeriodEvents    `json:"events"`
	NewPrincipals []PrincipalRow  `json:"new_principals"`
	Open          []Finding       `json:"open"`
	Metrics       MetricTable     `json:"metrics"`
	RunsMissing   []RunProblem    `json:"runs_missing"`
	Profiles      []ProfileRunSum `json:"profiles"`
}

// Period は対象の日付 (UTC、両端を含む)。
type Period struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// PeriodSummary は件数。severity=info は数えない。
type PeriodSummary struct {
	New      int `json:"new"`
	Changed  int `json:"changed"`
	Recurred int `json:"recurred"`
	Resolved int `json:"resolved"`
	// BySeverity は期間内に新規・再発した finding (重複なし) の重大度別件数。
	BySeverity map[string]int `json:"by_severity"`
	// Open は期間の終わりの時点ではなく、レポート生成時点で未対応 (open / acked) の件数。
	Open int `json:"open"`
}

// PeriodEvents は期間内の状態遷移 (時刻順)。
type PeriodEvents struct {
	New      []EventRow `json:"new"`
	Changed  []EventRow `json:"changed"`
	Recurred []EventRow `json:"recurred"`
	Resolved []EventRow `json:"resolved"`
}

// EventRow は状態遷移 1 件。Profile が空なら人の操作 (resolve / approve) か allowlist の編集による解消。
type EventRow struct {
	FindingID string `json:"finding_id"`
	Check     string `json:"check"`
	Key       string `json:"key"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	At        string `json:"at"`
	Profile   string `json:"profile,omitempty"`
}

// PrincipalRow は期間内に初めて観測した主体。
type PrincipalRow struct {
	ARN       string `json:"arn"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	FirstSeen string `json:"first_seen"`
	Status    string `json:"status"`
}

// MetricTable はアプリ層の日次集計の推移 (日 × 指標、全ソース・全 key の合計)。日は UTC。
type MetricTable struct {
	Metrics []string    `json:"metrics"`
	Rows    []MetricRow `json:"rows"`
}

// MetricRow は 1 日分。Values は Metrics と同じ順。
type MetricRow struct {
	Date   string    `json:"date"`
	Values []float64 `json:"values"`
}

// RunProblem は取れなかった run (partial / failed) か、走らなかった期間 (RUN_MISSED)。
type RunProblem struct {
	Profile string `json:"profile"`
	Kind    string `json:"kind"` // partial / failed / RUN_MISSED
	RunID   string `json:"run_id,omitempty"`
	At      string `json:"at"`              // run の開始時刻、RUN_MISSED なら空いた期間の始まり
	Until   string `json:"until,omitempty"` // RUN_MISSED の空いた期間の終わり
	Detail  string `json:"detail,omitempty"`
}

// ProfileRunSum はプロファイルごとの run の件数。
type ProfileRunSum struct {
	Profile string `json:"profile"`
	Runs    int    `json:"runs"`
	OK      int    `json:"ok"`
	Partial int    `json:"partial"`
	Failed  int    `json:"failed"`
}

// JSON は整形済み JSON を返す。
func (r *PeriodReport) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Markdown は人向けの期間レポート。
//
// 決定 (ADR 0041。ファズで見つけた): summary と主体の表示はログ由来なので、run の report.md と同じく改行を空白にする (inline)。
// 期間レポートだけ抜けていて、summary の改行で偽の見出しや指摘の行を作れた (report.md は Slack の本文にもなる)。
func (r *PeriodReport) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# arata 期間レポート (%s)\n\n", r.Name)
	fmt.Fprintf(&b, "- 期間: %s 〜 %s (UTC、両端を含む)\n", r.Period.From, r.Period.To)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "- **注意**: %s\n", n)
	}
	fmt.Fprintf(&b, "- 新規 %d / 変化 %d / 再発 %d / 解消 %d / 未対応の残存 %d (info は数えない)\n", r.Summary.New, r.Summary.Changed, r.Summary.Recurred, r.Summary.Resolved, r.Summary.Open)
	var sevs []string
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if n := r.Summary.BySeverity[s]; n > 0 {
			sevs = append(sevs, fmt.Sprintf("%s %d", s, n))
		}
	}
	if len(sevs) > 0 {
		fmt.Fprintf(&b, "- 期間内に新規・再発した指摘の重大度: %s\n", strings.Join(sevs, " / "))
	}
	b.WriteString("\n")
	eventSection(&b, "新規", r.Events.New)
	eventSection(&b, "再発", r.Events.Recurred)
	eventSection(&b, "変化", r.Events.Changed)
	eventSection(&b, "解消", r.Events.Resolved)

	fmt.Fprintf(&b, "## 新規の主体 (%d)\n\n", len(r.NewPrincipals))
	if len(r.NewPrincipals) == 0 {
		b.WriteString("期間内に初めて観測した主体はありません。\n\n")
	} else {
		b.WriteString("| 主体 | 種類 | 初出 | 状態 |\n|---|---|---|---|\n")
		for _, p := range r.NewPrincipals {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", inline(p.Label), p.Kind, p.FirstSeen, p.Status)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## 未対応の残存 (%d)\n\n", len(r.Open))
	if len(r.Open) == 0 {
		b.WriteString("未対応 (open / acked) の指摘はありません。\n\n")
	} else {
		for _, f := range r.Open {
			fmt.Fprintf(&b, "- **[%s]** %s `%s` (%s、初出 %s、id %s)\n", f.Severity, inline(f.Summary), f.Check, f.Status, f.FirstSeen, f.ID)
		}
		b.WriteString("\n")
	}

	b.WriteString("## アプリ層の日次推移 (UTC)\n\n")
	if len(r.Metrics.Rows) == 0 {
		b.WriteString("日次集計はありません (cloudwatch-logs ソースが無いか、期間内に集計していない)。\n\n")
	} else {
		fmt.Fprintf(&b, "| 日 | %s |\n|---|%s\n", strings.Join(r.Metrics.Metrics, " | "), strings.Repeat("---:|", len(r.Metrics.Metrics)))
		for _, row := range r.Metrics.Rows {
			vals := make([]string, len(row.Values))
			for i, v := range row.Values {
				vals[i] = fmt.Sprintf("%.0f", v)
			}
			fmt.Fprintf(&b, "| %s | %s |\n", row.Date, strings.Join(vals, " | "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 実行の状況\n\n")
	if len(r.Profiles) == 0 {
		b.WriteString("期間内に run がありません。\n")
	}
	for _, p := range r.Profiles {
		fmt.Fprintf(&b, "- %s: run %d (ok %d / partial %d / failed %d)\n", p.Profile, p.Runs, p.OK, p.Partial, p.Failed)
	}
	if len(r.RunsMissing) == 0 {
		b.WriteString("- 取れなかった run: なし\n")
	} else {
		b.WriteString("- 取れなかった run:\n")
		for _, m := range r.RunsMissing {
			line := fmt.Sprintf("  - %s `%s` %s", m.Profile, m.Kind, m.At)
			if m.Until != "" {
				line += " 〜 " + m.Until
			}
			if m.Detail != "" {
				line += " (" + m.Detail + ")"
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func eventSection(b *strings.Builder, title string, l []EventRow) {
	fmt.Fprintf(b, "## %s (%d)\n\n", title, len(l))
	if len(l) == 0 {
		b.WriteString("ありません。\n\n")
		return
	}
	for _, e := range l {
		by := e.Profile
		if by == "" {
			by = "人の操作 / allowlist"
		}
		fmt.Fprintf(b, "- %s **[%s]** %s `%s` (%s、id %s)\n", e.At, e.Severity, inline(e.Summary), e.Check, by, e.FindingID)
	}
	b.WriteString("\n")
}
