// Package notify は aratam の中心: 入力の検査、規則による振り分け、メッセージの組み立てと検証、送信と二重送信の防止 (aratam 設計書 2 章)。
// LLM とネットワークには依存しない (どちらもインターフェースで受ける)。
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
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
	// CodeLLMOutputRejected は LLM の出力の項目を検査で捨てた (WARN。ADR 0037)。
	CodeLLMOutputRejected = "LLM_OUTPUT_REJECTED"
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
	// UrgentMention は緊急用を通常用の送り先 (Webhook かチャンネル) に送るときに冒頭へ付けるメンション (緊急用の送り先があれば空)。
	UrgentMention string
}

// Sender は送信先。aratam は Slack (Webhook か bot トークンの chat.postMessage)、--dry-run は標準出力。
type Sender interface {
	Send(ctx context.Context, route Route, m Message) error
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
	// Context は利用者が書いた「この監査対象の前提」(llm.context_file の中身)。LLM の system に足すだけで、規則の判定には使わない。
	Context string
	// Format は slack.format (blocks | text)。空なら text (v0.3.0 までの mrkdwn の本文。設定では必須にしている)。
	Format string
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
		m := Message{Text: InputProblemText(o.Dir, ie, o.Rules)}
		if o.Format == FormatBlocks {
			m = InputProblemBlocks(o.Dir, ie, o.Rules)
		}
		if !send(ctx, o, log, RouteUrgent, m) {
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
	// 決定 (ADR 0024): WAF の改善提案 (proposals) は 2 通目として常に通常用に送る。on_quiet: silent でも提案は送る (週 1 回の改善提案のまとめ)
	hasProposals := in.Run != nil && len(in.Run.Proposals) > 0
	llmOK := o.Summarizer != nil
	blocks := o.Format == FormatBlocks
	var msg Message
	switch {
	case d.Quiet && o.Rules.OnQuiet == "silent":
		if !hasProposals {
			mark(o, log, key)
			return Result{Exit: ExitOK, Route: d.Route}
		}
	case d.Quiet && blocks:
		msg = QuietBlocks(in, d, o.Rules, warnings)
	case d.Quiet:
		msg = Message{Text: QuietText(in, d, o.Rules, warnings)}
	case o.Summarizer == nil && blocks:
		msg = RunBlocks(in, d, o.Rules, warnings, nil, "")
	case o.Summarizer == nil:
		msg = Message{Text: ReportText(in, d, o.Rules, warnings, "")}
	case blocks:
		// 決定 (ADR 0029): blocks では LLM は要約と「→」だけを書く。失敗したら原文ではなく、規則だけの Block Kit を送る (終了コード 3 は同じ)
		if n, err := summarizeBlocks(ctx, o, log, in); err != nil {
			log.Error("LLM の要約に失敗したため規則で組み立てて送ります", "code", CodeLLMFailed, "error", err.Error())
			msg = RunBlocks(in, d, o.Rules, warnings, nil, BlocksFallbackNotice)
			exit = ExitFallback
			llmOK = false
		} else {
			msg = RunBlocks(in, d, o.Rules, warnings, n, "")
		}
	default:
		if s, err := summarize(ctx, o, log, in); err != nil {
			log.Error("LLM の要約に失敗したため原文を送ります", "code", CodeLLMFailed, "error", err.Error())
			msg = Message{Text: ReportText(in, d, o.Rules, warnings, FallbackNotice)}
			exit = ExitFallback
			llmOK = false // 決定: 要約が失敗したら提案の書き起こしは呼ばない (LLM が使えない見込みが高い)
		} else {
			msg = Message{Text: SummaryText(in, d, o.Rules, warnings, s)}
		}
	}
	text := msg.Text
	res := Result{Exit: exit, Route: d.Route}
	if text != "" {
		if !send(ctx, o, log, d.Route, msg) {
			return Result{Exit: ExitSend, Route: d.Route}
		}
		res.Sent = true
		mark(o, log, key) // 本文を送れたら記録する (提案の送信に失敗しても本文を二重に送らない)
	}
	if !hasProposals {
		return res
	}
	if text == "" {
		res.Route = RouteNormal
	}
	var writeups map[string]Writeup
	notice := ""
	if llmOK {
		var err error
		if writeups, err = writeUp(ctx, o, log, in); err != nil {
			log.Warn("提案の書き起こしに失敗したため、候補をそのまま載せます", "code", CodeLLMProposalsFailed, "error", err.Error())
			notice = ProposalsFallbackNotice
		}
	}
	pm := Message{Text: ProposalsText(in, warnings, writeups, notice)}
	if blocks {
		// 決定 (ADR 0029): Slack には短い形だけを載せ、何を・なぜ・進め方・設定例の全文は入力ディレクトリの waf-proposals.md に書く。
		// --dry-run では書かない (パスだけ出す)。書けなくても通知は続け、report.md を案内する
		file := filepath.Join(o.Dir, ProposalsMD)
		if o.DryRun {
			log.Info("--dry-run のため "+ProposalsMD+" は書きません", "path", file)
		} else if _, err := writeProposalsFile(o.Dir, ProposalsMarkdown(in, writeups, notice)); err != nil {
			log.Warn(ProposalsMD+" を書けませんでした (通知は続けます)", "code", CodeProposalsFileFailed, "error", err.Error())
			file = ""
		}
		pm = ProposalsBlocks(in, warnings, writeups, notice, file)
	}
	if !send(ctx, o, log, RouteNormal, pm) {
		res.Exit = ExitSend
		return res
	}
	if text == "" {
		mark(o, log, key)
	}
	res.Sent = true
	return res
}

// writeUp は提案の候補だけを LLM に渡して書き起こさせる (要約とは別の呼び出し。再試行は要約と同じく 1 回まで)。
func writeUp(ctx context.Context, o Options, log *slog.Logger, in *Input) (map[string]Writeup, error) {
	props, _, _ := splitProposals(in.Run.Proposals)
	if len(props) == 0 {
		return nil, nil // observation だけなら LLM に渡すものが無い (observation は規則の書式で載せる)
	}
	var got map[string]Writeup
	err := callLLM(ctx, o, log, ProposalsSystemPrompt(o.Context, playbooksPrompt([]string{"waf_review"}, log)), proposalsInput(props), func(raw []byte) error {
		w, rejected, err := ParseWriteups(raw, props)
		if err != nil {
			return err
		}
		for _, r := range rejected {
			log.Warn("提案の書き起こしを捨てました (規則の行だけを載せます)", "code", CodeLLMProposalRejected, "reason", r)
		}
		got = w
		return nil
	})
	return got, err
}

// summarize は LLM に要約させ、出力を検証する。失敗 (エラー・時間切れ・形が合わない) なら 1 回だけ再試行する。
// 決定: 形が合わない出力も再試行の対象にする (同じ入力でも 2 回目は契約どおりに返すことが多いため)。
func summarize(ctx context.Context, o Options, log *slog.Logger, in *Input) (*Summary, error) {
	var s *Summary
	system := SystemPrompt(in.Kind, o.Context, playbooksPrompt(orderedChecks(in), log))
	err := callLLM(ctx, o, log, system, in.JSON, func(raw []byte) error {
		var err error
		s, err = ParseSummary(raw, in, o.Rules.UrgentSeverity)
		return err
	})
	if err == nil {
		logRejected(log, s.Rejected)
	}
	return s, err
}

// summarizeBlocks は blocks の契約で LLM に要約と「→」を書かせる (再試行は 1 回まで)。
func summarizeBlocks(ctx context.Context, o Options, log *slog.Logger, in *Input) (*BlockNotes, error) {
	top, _ := splitUrgent(in, o.Rules.UrgentSeverity)
	var n *BlockNotes
	system := BlocksSystemPrompt(in.Kind, o.Context, playbooksPrompt(orderedChecks(in), log), top)
	err := callLLM(ctx, o, log, system, in.JSON, func(raw []byte) error {
		var err error
		n, err = ParseBlockNotes(raw, in, top)
		return err
	})
	if err == nil {
		logRejected(log, n.Rejected)
	}
	return n, err
}

// logRejected は検査で捨てた LLM の項目を警告に出す。理由だけを書き、文の中身は書かない (攻撃者の文をログに写さない)。
func logRejected(log *slog.Logger, rejected []string) {
	for _, r := range rejected {
		log.Warn("LLM の出力の項目を捨てました (規則の行を載せます)", "code", CodeLLMOutputRejected, "reason", r)
	}
}

// callLLM は LLM を呼び、parse で検証する。失敗 (エラー・時間切れ・形が合わない) なら 1 回だけ再試行する。timeout は 1 回ごと。
func callLLM(ctx context.Context, o Options, log *slog.Logger, system string, input []byte, parse func([]byte) error) error {
	var last error
	for attempt := 1; attempt <= 2; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, o.LLMTimeout)
		raw, err := o.Summarizer.Summarize(cctx, system, input)
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("timed out after %s: %w", o.LLMTimeout, context.DeadlineExceeded)
		}
		cancel()
		if err == nil {
			if err = parse(raw); err == nil {
				return nil
			}
		}
		last = err
		if ctx.Err() != nil {
			break
		}
		if attempt == 1 {
			log.Warn("LLM の呼び出しに失敗したので再試行します", "code", CodeLLMRetry, "error", err.Error())
		}
	}
	return last
}

func send(ctx context.Context, o Options, log *slog.Logger, route Route, m Message) bool {
	if err := o.Sender.Send(ctx, route, m); err != nil {
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
