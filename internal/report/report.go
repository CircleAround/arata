// Package report は report.json (機械向け) と report.md (人向け) を生成する (設計書 8 章)。
package report

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/store"
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
}

// SkippedCheck は走らなかったチェックと理由。
type SkippedCheck struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// Input は Build への入力。
type Input struct {
	Profile       string
	Name          string
	RunID         string
	Window        collect.Window
	Now           time.Time
	Results       []checks.Result
	CollectErrors []CollectError
	SourcesOK     []string
	ChecksRun     []string
	ChecksSkipped []SkippedCheck
	Formats       []FormatCoverage
}

// Build は差分判定の結果からレポートを組み立てる。
//
// 決定:
//   - severity=info の finding は new / changed でも `info` に入れ、summary のカウントと max_severity には含めない。
//   - still_open のうち first_seen が窓内 (始点より後) かつ既に reported_at があるものは、別プロファイル (hourly など) で報告済みとみなし `already_reported` に入れる。
//   - max_severity は new / changed / recurred の最大 (still_open を含めると毎回鳴るため)。
//   - suppressed (acked / snoozed) はレポートに出さない。
func Build(in Input) *Report {
	r := &Report{
		Profile:         in.Profile,
		Name:            in.Name,
		RunID:           in.RunID,
		GeneratedAt:     ts(in.Now),
		Window:          Window{From: ts(in.Window.From), To: ts(in.Window.To)},
		Summary:         Summary{CollectErrors: nonNil(in.CollectErrors)},
		Findings:        Findings{New: []Finding{}, Changed: []Finding{}, Recurred: []Finding{}, Resolved: []Finding{}, StillOpen: []Finding{}},
		AlreadyReported: []Finding{},
		Info:            []Finding{},
		Coverage: Coverage{
			SourcesOK:     nonNil(in.SourcesOK),
			SourcesFailed: failures(in.CollectErrors),
			ChecksRun:     nonNil(in.ChecksRun),
			ChecksSkipped: nonNil(in.ChecksSkipped),
			Formats:       nonNil(in.Formats),
		},
	}
	var sevs []checks.Severity
	for _, res := range in.Results {
		f := toFinding(res.Finding)
		switch res.Class {
		case checks.ClassNew, checks.ClassChanged, checks.ClassRecurred:
			if f.Severity == string(checks.Info) {
				r.Info = append(r.Info, f)
				continue
			}
			sevs = append(sevs, checks.Severity(f.Severity))
			switch res.Class {
			case checks.ClassNew:
				r.Findings.New = append(r.Findings.New, f)
			case checks.ClassChanged:
				r.Findings.Changed = append(r.Findings.Changed, f)
			default:
				r.Findings.Recurred = append(r.Findings.Recurred, f)
			}
		case checks.ClassResolved:
			r.Findings.Resolved = append(r.Findings.Resolved, f)
		case checks.ClassStillOpen:
			if f.Severity == string(checks.Info) {
				r.Info = append(r.Info, f)
				continue
			}
			if !res.Finding.ReportedAt.IsZero() && res.Finding.FirstSeen.After(in.Window.From) {
				r.AlreadyReported = append(r.AlreadyReported, f)
			} else {
				r.Findings.StillOpen = append(r.Findings.StillOpen, f)
			}
		}
	}
	for _, l := range [][]Finding{r.Findings.New, r.Findings.Changed, r.Findings.Recurred, r.Findings.Resolved, r.Findings.StillOpen, r.AlreadyReported, r.Info} {
		sortFindings(l)
	}
	r.Summary.New = len(r.Findings.New)
	r.Summary.Changed = len(r.Findings.Changed)
	r.Summary.Recurred = len(r.Findings.Recurred)
	r.Summary.Resolved = len(r.Findings.Resolved)
	r.Summary.StillOpen = len(r.Findings.StillOpen)
	r.Summary.MaxSeverity = string(checks.MaxSeverity(sevs))
	return r
}

// JSON は整形済み JSON を返す。
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// failures は collect_errors から sources_failed を作る (同じ値を 2 か所に出す)。
func failures(errs []CollectError) []SourceFailure {
	out := []SourceFailure{}
	for _, e := range errs {
		out = append(out, SourceFailure{Source: e.Source, Code: e.Code, Action: e.Action, Partial: e.Partial, CoveredFrom: e.CoveredFrom, CoveredUntil: e.CoveredUntil})
	}
	return out
}

func toFinding(f store.Finding) Finding {
	d := f.Data
	if d == nil {
		d = map[string]any{}
	}
	return Finding{
		ID: f.ID, Check: f.Check, Key: f.Key, Severity: f.Severity, Summary: f.Summary, Status: f.Status,
		FirstSeen: ts(f.FirstSeen), LastSeen: ts(f.LastSeen), LastChanged: ts(f.LastChanged), ReportedAt: tsOrEmpty(f.ReportedAt), Data: d,
	}
}

func sortFindings(l []Finding) {
	sort.SliceStable(l, func(i, j int) bool {
		ri, rj := checks.Severity(l[i].Severity).Rank(), checks.Severity(l[j].Severity).Rank()
		if ri != rj {
			return ri > rj
		}
		if l[i].Check != l[j].Check {
			return l[i].Check < l[j].Check
		}
		return l[i].Key < l[j].Key
	})
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func tsOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return ts(t)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Parse は JSON からレポートを復元する (report コマンドが保存済みレポートを読むため)。
func Parse(b []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
