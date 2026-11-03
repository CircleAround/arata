package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
	"github.com/CircleAround/arata/internal/store"
)

// DefaultInitWindow は init のベースライン収集の既定の窓。
// 決定: profiles の最大 window (24h) ではベースラインが薄く導入翌日から新規主体が多数鳴るため、既定を 7d にする。
const DefaultInitWindow = 7 * 24 * time.Hour

// InitProfile は init の run の profile 名。
const InitProfile = "init"

// InitOptions は init の指定。
type InitOptions struct {
	Window time.Duration // 既定 7d。Resume のときは使わない
	// Resume は直近の未完了の init (status が running / partial) を、記録した進捗の続きから再開する。
	Resume bool
}

// InitResult は init の結果。
type InitResult struct {
	CollectResult
	RunID       string
	ChunksDone  int
	ChunksTotal int
	DoneUntil   time.Time
	Complete    bool
	Resumed     bool
	// NothingToResume は Resume を指定したが未完了の init が無かった。
	NothingToResume bool
}

// initChunks は窓を UTC の日の境界で区切る (古い順)。最初と最後は日の途中から / 途中までになる。
func initChunks(w collect.Window) []collect.Window {
	var out []collect.Window
	for from := w.From; from.Before(w.To); {
		to := dayStartUTC(from).Add(24 * time.Hour)
		if to.After(w.To) {
			to = w.To
		}
		out = append(out, collect.Window{From: from, To: to})
		from = to
	}
	return out
}

func dayStartUTC(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// Init はベースライン収集を行う (findings は作らない)。
//
// 決定 (ADR 0011):
//   - 窓を UTC の日の境界で区切り、古い順に 1 日ずつ収集する。日次集計 (metrics) の日と揃うので、Logs Insights の問い合わせもちょうど 1 日ずつになる
//   - 1 日終わるごとに runs (profile=init) の stats に進捗 (chunks_done / done_until) を書く。LookupEvents は 2 req/s なので 7 日で数時間かかり得る
//   - どれかのソースが失敗した日で止める (status=partial)。中断 (SIGINT / SIGTERM) も同じ。`init --resume` はその日の頭から再開し、窓の終わりを今に延ばす
//   - 再開で同じ日を引き直しても、events は event_id、metrics は置き換えで重複しない。principal_ips.count だけは二重に数え得る (件数は判定に使わない)
func (e *Engine) Init(ctx context.Context, o InitOptions) (*InitResult, error) {
	now := e.deps.Now()
	res := &InitResult{CollectResult: CollectResult{SourcesOK: []string{}, SourcesFailed: []string{}, Errors: []report.CollectError{}, Formats: []report.FormatCoverage{}}}
	var run store.Run
	var from time.Time
	var stats map[string]any
	last, err := e.st.LastRun(ctx, InitProfile, nil)
	if err != nil {
		return nil, err
	}
	unfinished := last != nil && (last.Status == "running" || last.Status == "partial")
	if o.Resume {
		if !unfinished {
			res.NothingToResume = true
			e.log.Info("no unfinished init to resume")
			return res, nil
		}
		run, stats = *last, last.Stats
		if stats == nil {
			stats = map[string]any{}
		}
		from = run.WindowFrom
		if t, err := time.Parse(time.RFC3339Nano, str(stats["done_until"])); err == nil {
			from = t
		}
		run.WindowTo = now
		res.Resumed = true
		res.ChunksDone = intOf(stats["chunks_done"])
		e.log.Info("resuming init", "run_id", run.ID, "from", from.UTC().Format(time.RFC3339), "to", now.UTC().Format(time.RFC3339), "chunks_done", res.ChunksDone)
	} else {
		if unfinished {
			e.log.Warn("previous init did not finish; starting over (use `init --resume` to continue it instead)", "run_id", last.ID, "status", last.Status)
		}
		window := o.Window
		if window <= 0 {
			window = DefaultInitWindow
		}
		run = store.Run{ID: e.deps.NewID(), Profile: InitProfile, WindowFrom: now.Add(-window), WindowTo: now, StartedAt: now, Status: "running"}
		from = run.WindowFrom
		stats = map[string]any{}
		if err := e.st.BeginRun(ctx, run); err != nil {
			return nil, err
		}
	}
	res.RunID = run.ID
	chunks := initChunks(collect.Window{From: from, To: run.WindowTo})
	res.ChunksTotal = res.ChunksDone + len(chunks)
	res.DoneUntil = from
	// 中断されても進捗は書き残す
	bg := context.WithoutCancel(ctx)
	stats["chunks_total"] = res.ChunksTotal
	stats["done_until"] = from.UTC().Format(time.RFC3339Nano)
	if err := e.st.UpdateRun(bg, run.ID, run.WindowTo, stats); err != nil {
		return nil, err
	}
	totals := map[string]*report.FormatCoverage{}
	sourcesOK := map[string]bool{}
	for i, w := range chunks {
		cr := e.Collect(ctx, w, CollectOptions{PrincipalStatus: store.PrincipalBaseline, RunID: run.ID})
		res.Records += cr.Records
		for _, f := range cr.Formats {
			if t, ok := totals[f.Source]; ok {
				t.Total, t.Matched, t.BytesScanned = t.Total+f.Total, t.Matched+f.Matched, t.BytesScanned+f.BytesScanned
			} else {
				f := f
				totals[f.Source] = &f
			}
		}
		if cr.partial() || ctx.Err() != nil {
			res.SourcesFailed, res.Errors = cr.SourcesFailed, cr.Errors
			res.SourcesOK = cr.SourcesOK
			stats["records"] = intOf(stats["records"]) + cr.Records
			stats["interrupted"] = ctx.Err() != nil
			stats["failed_chunk"] = w.From.UTC().Format(time.RFC3339)
			addFormatStats(stats, formatTotals(totals))
			if err := e.st.FinishRun(bg, run.ID, "partial", stats); err != nil {
				return nil, err
			}
			e.log.Warn("init stopped; run `arata init --resume` to continue from the failed day",
				"run_id", run.ID, "chunks_done", res.ChunksDone, "chunks_total", res.ChunksTotal, "done_until", res.DoneUntil.UTC().Format(time.RFC3339), "interrupted", ctx.Err() != nil)
			return res, nil
		}
		for _, s := range cr.SourcesOK {
			sourcesOK[s] = true
		}
		// done_until までの CloudTrail を収集し終えた印 (ADR 0027)。途中で止まっても done_until までは数えられる
		if e.trailCollected(cr.SourcesOK) {
			stats[checks.TrailCollectedStat] = true
		}
		addOutOfRange(stats, cr.outOfRange, w.From)
		res.ChunksDone++
		res.DoneUntil = w.To
		stats["chunks_done"] = res.ChunksDone
		stats["done_until"] = w.To.UTC().Format(time.RFC3339Nano)
		stats["records"] = intOf(stats["records"]) + cr.Records
		if err := e.st.UpdateRun(bg, run.ID, run.WindowTo, stats); err != nil {
			return nil, err
		}
		e.log.Info("init progress", "run_id", run.ID, "chunk", fmt.Sprintf("%d/%d", res.ChunksDone, res.ChunksTotal),
			"from", w.From.UTC().Format(time.RFC3339), "to", w.To.UTC().Format(time.RFC3339), "records", cr.Records, "chunk_index", i)
	}
	for _, src := range e.cfg.Sources {
		if sourcesOK[src.ID] || len(chunks) == 0 {
			res.SourcesOK = append(res.SourcesOK, src.ID)
		}
	}
	res.Formats = formatTotals(totals)
	addFormatStats(stats, res.Formats)
	stats["sources_ok"] = len(res.SourcesOK)
	stats["sources_failed"] = 0
	if err := e.st.FinishRun(bg, run.ID, "ok", stats); err != nil {
		return nil, err
	}
	res.Complete = true
	if _, err := os.Stat(e.cfg.Allowlist); errors.Is(err, os.ErrNotExist) {
		e.log.Warn("allowlist file not found; treating as empty", "path", e.cfg.Allowlist)
	}
	e.log.Info("init finished", "run_id", run.ID, "status", "ok", "records", res.Records, "chunks", res.ChunksTotal)
	return res, nil
}

// addOutOfRange は、範囲がロググループの作成前 / 保持期間外で問い合わせなかった日を stats["logs_out_of_range"] (ソース → 日付の配列) に足す。
// 決定: report.json のスキーマは変えず、init の run の記録とログ (INFO) にだけ残す。daily などの run は窓の終わりが今なので該当しない。
func addOutOfRange(stats map[string]any, oor map[string]string, day time.Time) {
	if len(oor) == 0 {
		return
	}
	m, _ := stats["logs_out_of_range"].(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	d := day.UTC().Format(record.DateLayout)
	for src := range oor {
		var days []any
		switch l := m[src].(type) {
		case []any:
			days = l
		case []string:
			for _, s := range l {
				days = append(days, s)
			}
		}
		m[src] = append(days, d)
	}
	stats["logs_out_of_range"] = m
}

// formatTotals は日ごとの解釈率を合算して解釈率を計算し直す。
func formatTotals(m map[string]*report.FormatCoverage) []report.FormatCoverage {
	out := []report.FormatCoverage{}
	for _, f := range m {
		c := *f
		c.MatchRate, c.Code, c.RecentAverage = nil, "", nil
		if c.Total > 0 {
			r := round3(float64(c.Matched) / float64(c.Total))
			c.MatchRate = &r
		}
		out = append(out, c)
	}
	sortFormats(out)
	return out
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}
