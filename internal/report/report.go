// Package report は report.json (機械向け) と report.md (人向け) を生成する (設計書 8 章)。
package report

import (
	"sort"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report/schema"
	"github.com/CircleAround/arata/internal/store"
)

// report.json の型は、標準ライブラリだけに依存する schema パッケージに置く (aratam が SQLite や AWS SDK を持ち込まずに読めるように)。
// 決定 (ADR 0018): 既存の呼び出しを変えないよう、ここでは型エイリアスで同じ名前を出す。
type (
	Report         = schema.Report
	Window         = schema.Window
	Summary        = schema.Summary
	CollectError   = schema.CollectError
	SourceFailure  = schema.SourceFailure
	Findings       = schema.Findings
	Finding        = schema.Finding
	Coverage       = schema.Coverage
	FormatCoverage = schema.FormatCoverage
	SkippedCheck   = schema.SkippedCheck
)

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
	Proposals     []schema.Proposal
	// DiffFrom は差分判定の境界 (ゼロなら Window.From)。試しの実行が定時の実行の境界に合わせるのに使う (ADR 0049)。
	DiffFrom time.Time
}

// Build は差分判定の結果からレポートを組み立てる。
//
// 決定:
//   - severity=info の finding は new / changed でも `info` に入れ、summary のカウントと max_severity には含めない。
//   - still_open のうち first_seen が窓内 (始点より後) かつ既に reported_at があるものは、別プロファイル (hourly など) で報告済みとみなし `already_reported` に入れる。
//   - max_severity は new / changed / recurred の最大 (still_open を含めると毎回鳴るため)。
//   - suppressed (acked / snoozed) はレポートに出さない。
func Build(in Input) *Report {
	diffFrom := in.Window.From
	if !in.DiffFrom.IsZero() {
		diffFrom = in.DiffFrom
	}
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
		Proposals: in.Proposals,
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
			if !res.Finding.ReportedAt.IsZero() && res.Finding.FirstSeen.After(diffFrom) {
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
		ID: f.ID, Check: f.Check, Key: record.MaskIdentity(f.Key), Severity: f.Severity, Summary: record.MaskIdentity(f.Summary), Status: f.Status,
		FirstSeen: ts(f.FirstSeen), LastSeen: ts(f.LastSeen), LastChanged: ts(f.LastChanged), ReportedAt: tsOrEmpty(f.ReportedAt), Data: maskData(d),
	}
}

// maskData は data の文字列から個人を特定できる値を伏せた複製を返す。
// 決定 (ADR 0037): メール形式の IAM ユーザー名は、approve の対象を引くためにストアには残し、レポートと通知には出さない。人が見るのは `arata review`。
func maskData(d map[string]any) map[string]any {
	out := make(map[string]any, len(d))
	for k, v := range d {
		out[k] = maskValue(v)
	}
	return out
}

func maskValue(v any) any {
	switch x := v.(type) {
	case string:
		return record.MaskIdentity(x)
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			out[i] = record.MaskIdentity(s)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = maskValue(e)
		}
		return out
	case map[string]any:
		return maskData(x)
	}
	return v
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
func Parse(b []byte) (*Report, error) { return schema.Parse(b) }
