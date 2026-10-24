// Package notify は aratam の中心: 入力の検査、規則による振り分け、メッセージの組み立てと検証、送信と二重送信の防止 (aratam 設計書 2 章)。
// LLM とネットワークには依存しない (どちらもインターフェースで受ける)。
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// 終了コード (aratam 設計書 5 章)。
const (
	ExitOK       = 0 // 送った (または on_quiet=silent / 通知済みで送らなかった)
	ExitConfig   = 2 // 設定エラー
	ExitFallback = 3 // LLM が使えず report.md で送った
	ExitInput    = 4 // 入力が無い・古い (その旨は送った)
	ExitSend     = 5 // 送信に失敗した
)

// ログの code (固定語彙)。
const (
	CodeConfigInvalid   = "CONFIG_INVALID"
	CodeSendFailed      = "SEND_FAILED"
	CodeAlreadyNotified = "ALREADY_NOTIFIED"
	CodeNameMismatch    = "NAME_MISMATCH"
	CodeMarkFailed      = "MARK_FAILED"
	CodeLLMRetry        = "LLM_RETRY"
	CodeLLMFailed       = "LLM_FAILED"
)

// FallbackNotice は LLM が使えず原文を送るときに冒頭へ書く注記。
const FallbackNotice = "要約に失敗したため原文を送ります"

// Route は送り先。
type Route string

// 送り先の種類。
const (
	RouteNormal Route = "normal"
	RouteUrgent Route = "urgent"
)

// Rules は LLM に任せない規則 (設定から作る)。
type Rules struct {
	Name           string
	MaxAge         time.Duration
	UrgentSeverity string
	OnQuiet        string // short | silent
	// UrgentMention は緊急用を通常用の Webhook に送るときに冒頭へ付けるメンション (緊急用の Webhook があれば空)。
	UrgentMention string
}

// Sender は送信先。aratam は Slack の Webhook、--dry-run は標準出力。
type Sender interface {
	Send(ctx context.Context, route Route, text string) error
}

// Summarizer は LLM のプロバイダ (aratam 設計書 3-1)。system と report.json を渡し、LLM の出力をそのまま返す。
// JSON の検証と組み立てはプロバイダごとに書かず、ここ (ParseSummary / SummaryText) で行う。
type Summarizer interface {
	Summarize(ctx context.Context, system string, reportJSON []byte) ([]byte, error)
}

// Options は Run への入力。
type Options struct {
	Dir    string
	Now    time.Time
	Rules  Rules
	Force  bool // .aratam-notified に同じ報告があっても送る
	DryRun bool // .aratam-notified を書かない (Sender は呼び出し側が標準出力に向ける)
	Sender Sender
	Logger *slog.Logger
	// Summarizer は nil なら LLM を使わない (provider: none)。
	Summarizer Summarizer
	// LLMTimeout は LLM 呼び出し 1 回の時間切れ (再試行は 1 回まで)。
	LLMTimeout time.Duration
}

// Result は Run の結果。
type Result struct {
	Exit  int
	Route Route
	Sent  bool
}

// Decision は規則による振り分けの結果。
type Decision struct {
	Route Route
	// Quiet は新規・変化・再発が 0 件で、取れなかったものも無いこと (on_quiet に従う)。
	Quiet bool
}

// Decide は送り先と「静か」かを規則で決める (LLM を使わない)。
//
//   - 送り先: summary.max_severity が urgent_severity 以上、または coverage.sources_failed がある → 緊急用。それ以外 → 通常用。
//   - 期間レポートは常に通常用で、静かとはみなさない (決定: 月次などの定期の報告は件数が 0 でも送る)。
func Decide(in *Input, r Rules) Decision {
	if in.Run == nil {
		return Decision{Route: RouteNormal}
	}
	s := in.Run.Summary
	failed := len(in.Run.Coverage.SourcesFailed) > 0
	d := Decision{Route: RouteNormal, Quiet: s.New+s.Changed+s.Recurred == 0 && !failed}
	if failed || (s.MaxSeverity != "" && severityRank[s.MaxSeverity] >= severityRank[r.UrgentSeverity]) {
		d.Route = RouteUrgent
	}
	return d
}

// Run は aratam notify の本体。
func Run(ctx context.Context, o Options) Result {
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	in, err := ReadInput(o.Dir, o.Now, o.Rules.MaxAge)
	if err != nil {
		var ie *InputError
		if !errors.As(err, &ie) {
			ie = &InputError{Code: CodeInputMissing, Reason: err.Error()}
		}
		log.Error("arata の出力が無いか古い", "code", ie.Code, "reason", ie.Reason)
		if !send(ctx, o, log, RouteUrgent, InputProblemText(o.Dir, ie, o.Rules)) {
			return Result{Exit: ExitSend, Route: RouteUrgent}
		}
		return Result{Exit: ExitInput, Route: RouteUrgent, Sent: true}
	}

	key := in.Key()
	if !o.Force && Notified(o.Dir, key) {
		log.Info("通知済みのため送りません (再送は --force)", "code", CodeAlreadyNotified, "run_id", key)
		return Result{Exit: ExitOK}
	}
	var warnings []string
	if in.Name() != o.Rules.Name {
		w := fmt.Sprintf("設定の name (%s) と report.json の name (%s) が違います", o.Rules.Name, in.Name())
		log.Warn(w, "code", CodeNameMismatch)
		warnings = append(warnings, w)
	}

	d := Decide(in, o.Rules)
	exit := ExitOK
	var text string
	switch {
	case d.Quiet && o.Rules.OnQuiet == "silent":
		mark(o, log, key)
		return Result{Exit: ExitOK, Route: d.Route}
	case d.Quiet:
		text = QuietText(in, d, o.Rules, warnings)
	case o.Summarizer == nil:
		text = ReportText(in, d, o.Rules, warnings, "")
	default:
		if s, err := summarize(ctx, o, log, in); err != nil {
			log.Error("LLM の要約に失敗したため原文を送ります", "code", CodeLLMFailed, "error", err.Error())
			text = ReportText(in, d, o.Rules, warnings, FallbackNotice)
			exit = ExitFallback
		} else {
			text = SummaryText(in, d, o.Rules, warnings, s)
		}
	}
	if !send(ctx, o, log, d.Route, text) {
		return Result{Exit: ExitSend, Route: d.Route}
	}
	mark(o, log, key)
	return Result{Exit: exit, Route: d.Route, Sent: true}
}

// summarize は LLM に要約させ、出力を検証する。失敗 (エラー・時間切れ・形が合わない) なら 1 回だけ再試行する。
// 決定: 形が合わない出力も再試行の対象にする (同じ入力でも 2 回目は契約どおりに返すことが多いため)。
func summarize(ctx context.Context, o Options, log *slog.Logger, in *Input) (*Summary, error) {
	system := SystemPrompt(in.Kind)
	var last error
	for attempt := 1; attempt <= 2; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, o.LLMTimeout)
		raw, err := o.Summarizer.Summarize(cctx, system, in.JSON)
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("timed out after %s: %w", o.LLMTimeout, context.DeadlineExceeded)
		}
		cancel()
		if err == nil {
			var s *Summary
			if s, err = ParseSummary(raw, in); err == nil {
				return s, nil
			}
		}
		last = err
		if ctx.Err() != nil {
			break
		}
		if attempt == 1 {
			log.Warn("LLM の要約に失敗したので再試行します", "code", CodeLLMRetry, "error", err.Error())
		}
	}
	return nil, last
}

func send(ctx context.Context, o Options, log *slog.Logger, route Route, text string) bool {
	if err := o.Sender.Send(ctx, route, text); err != nil {
		log.Error("通知の送信に失敗しました", "code", CodeSendFailed, "route", string(route), "error", err.Error())
		return false
	}
	return true
}

// mark は .aratam-notified を書く。書けなくても送信は済んでいるので終了コードは変えず、警告だけ出す (次回は再送になる)。
func mark(o Options, log *slog.Logger, key string) {
	if o.DryRun {
		return
	}
	if err := MarkNotified(o.Dir, key); err != nil {
		log.Warn("通知済みの記録を書けませんでした (次回同じ報告を再送します)", "code", CodeMarkFailed, "error", err.Error())
	}
}
