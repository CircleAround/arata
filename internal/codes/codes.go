// Package codes は、標準エラーの構造化ログ (JSON 行) の code の一覧と、ログの行の安定な項目 (log スキーマ) を持つ。
//
// 決定 (ADR 0054): code の一覧を 1 か所に持つ。arata と aratam のどのパッケージも、ログの code にはここの定数を使う
// (各パッケージの Code* の定数はここを指す)。テストで次を固定する:
//
//   - コードの中で code として渡す値が、すべてここにある (文字列の直書きをしない)
//   - 文書の code の表 (arata help ai、docs/aratam.md、設計書) が、この一覧と一致する
//   - log スキーマ (schemas/log.schema.json) の code の既知の値が、この一覧と一致する
//   - コマンドが実際に出すログの行が log スキーマに合い、その code がそのコマンドの一覧にある
//
// code は開いた語彙。足すのは互換 (読む側は、知らない code を「その他の警告・エラー」として扱う)。
// 消す・名前を変える・意味を変えるのは互換を壊す変更で、Release の本文に書く。
// 標準ライブラリだけに依存する (aratam も import する)。
package codes

import "sort"

// arata (監査エンジン) の code。
const (
	FormatMismatch         = "FORMAT_MISMATCH"
	FormatDrift            = "FORMAT_DRIFT"
	AccessDenied           = "ACCESS_DENIED"
	LogGroupMissing        = "LOG_GROUP_MISSING"
	QueryLimit             = "QUERY_LIMIT"
	QueryInvalid           = "QUERY_INVALID"
	CollectFailed          = "COLLECT_FAILED"
	StoreLocked            = "STORE_LOCKED"
	StoreCorrupt           = "STORE_CORRUPT"
	StoreConflict          = "STORE_CONFLICT"
	StoreUnavailable       = "STORE_UNAVAILABLE"
	Interrupted            = "INTERRUPTED"
	RunMissed              = "RUN_MISSED"
	CheckUnused            = "CHECK_UNUSED"
	ReportNotFound         = "REPORT_NOT_FOUND"
	SourceCatchup          = "SOURCE_CATCHUP"
	SourceCatchupTruncated = "SOURCE_CATCHUP_TRUNCATED"
)

// arata と aratam の両方が出す code。
const (
	ConfigInvalid = "CONFIG_INVALID"
)

// aratam (要約と通知) の code。
const (
	SendFailed          = "SEND_FAILED"
	AlreadyNotified     = "ALREADY_NOTIFIED"
	NameMismatch        = "NAME_MISMATCH"
	MarkFailed          = "MARK_FAILED"
	LLMRetry            = "LLM_RETRY"
	LLMFailed           = "LLM_FAILED"
	LLMOutputRejected   = "LLM_OUTPUT_REJECTED"
	LLMProposalsFailed  = "LLM_PROPOSALS_FAILED"
	LLMProposalRejected = "LLM_PROPOSAL_REJECTED"
	LLMUnavailable      = "LLM_UNAVAILABLE"
	DryRunReport        = "DRY_RUN_REPORT"
	ProposalsFileFailed = "PROPOSALS_FILE_FAILED"
	PlaybooksOmitted    = "PLAYBOOKS_OMITTED"
	ContextUnreadable   = "CONTEXT_UNREADABLE"
	ContextTooLarge     = "CONTEXT_TOO_LARGE"
	InputMissing        = "INPUT_MISSING"
	InputInvalid        = "INPUT_INVALID"
	InputStale          = "INPUT_STALE"
	WebhookUnset        = "WEBHOOK_UNSET"
	UrgentWebhookUnset  = "URGENT_WEBHOOK_UNSET"
	BotTokenUnset       = "BOT_TOKEN_UNSET" // #nosec G101 -- ログの code の名前で、秘密の値ではない
	SlackAuthFailed     = "SLACK_AUTH_FAILED"
	SlackScopeMissing   = "SLACK_SCOPE_MISSING"
)

// コマンドの名前。
const (
	Arata  = "arata"
	Aratam = "aratam"
)

// Code は code 1 つ。Tools は出すコマンド、Meaning は意味 (人向けの 1 行。対処は文書の表に書く)。
type Code struct {
	Name    string
	Tools   []string
	Meaning string
}

// Pattern は code の形。これから足す code もこの形にする (log スキーマに書く)。
const Pattern = "^[A-Z][A-Z0-9_]*$"

var (
	arataOnly  = []string{Arata}
	aratamOnly = []string{Aratam}
	both       = []string{Arata, Aratam}
)

// All は code の一覧。並びは文書の表と log スキーマの順 (足すときは、そのコマンドの並びの最後に足す)。
var All = []Code{
	{AccessDenied, arataOnly, "IAM の権限が足りない (action に不足した action)"},
	{LogGroupMissing, arataOnly, "ロググループが無い・名前が変わった"},
	{FormatMismatch, arataOnly, "解釈率が閾値未満 (そのソースは失敗扱い)"},
	{FormatDrift, arataOnly, "解釈率が直近の平均から急落した (警告)"},
	{QueryLimit, arataOnly, "Logs Insights の同時実行・スキャンの上限、LookupEvents のスロットル"},
	{QueryInvalid, arataOnly, "クエリ・設定の不備 (Insights の構文エラーなど)"},
	{StoreLocked, arataOnly, "同じストアを別のプロセスが使っている"},
	{StoreCorrupt, arataOnly, "SQLite を開けない・S3 のストアに raw があるのに SQLite が無い"},
	{StoreConflict, arataOnly, "s3:// のストアを別の実行が先に書いた (何も上書きしていない)"},
	{StoreUnavailable, arataOnly, "s3:// のストアに問い合わせられない (権限・通信)"},
	{Interrupted, arataOnly, "SIGINT / SIGTERM で止まった"},
	{RunMissed, arataOnly, "前回の実行から周期の 2 倍以上空いた"},
	{CollectFailed, arataOnly, "ほかに分類できない収集エラー"},
	{ConfigInvalid, both, "設定ファイル・引数・環境変数の誤り"},
	{CheckUnused, arataOnly, "どのプロファイルにも入っていないチェックがある (警告)"},
	{ReportNotFound, arataOnly, "arata report で出す報告が無い (そのプロファイルの run がまだ無い)"},
	{SourceCatchup, arataOnly, "前に失敗したソースを、取れていた位置から引き直している (警告)"},
	{SourceCatchupTruncated, arataOnly, "ソースの遅れが max_catchup を超え、古い分を取りこぼした (警告)"},

	{InputMissing, aratamOnly, "report.json が無い・読めない (その旨を緊急用に送る)"},
	{InputInvalid, aratamOnly, "report.json を解釈できない・知らない版 (その旨を緊急用に送る)"},
	{InputStale, aratamOnly, "report.json が max_age より古い (その旨を緊急用に送る)"},
	{SendFailed, aratamOnly, "Slack への送信に失敗した"},
	{AlreadyNotified, aratamOnly, "同じ報告を通知済みなので送らなかった (INFO)"},
	{NameMismatch, aratamOnly, "report.json の name が設定の name と違う (警告)"},
	{MarkFailed, aratamOnly, "通知済みの印を書けなかった (次回は再送になる。警告)"},
	{DryRunReport, aratamOnly, "arata の試しの実行の報告なので送らなかった (警告)"},
	{LLMRetry, aratamOnly, "LLM の呼び出しを再試行する (警告)"},
	{LLMFailed, aratamOnly, "LLM が使えず、規則で組み立てた文か原文 (report.md) を送った"},
	{LLMOutputRejected, aratamOnly, "LLM の出力の項目を検査で捨てた (警告)"},
	{LLMProposalsFailed, aratamOnly, "WAF の提案の書き起こしに失敗し、候補をそのまま載せた (警告)"},
	{LLMProposalRejected, aratamOnly, "WAF の提案の書き起こしの項目を検査で捨てた (警告)"},
	{ProposalsFileFailed, aratamOnly, "waf-proposals.md を書けなかった (通知は続ける。警告)"},
	{PlaybooksOmitted, aratamOnly, "上限に入らず、LLM に渡さなかった playbook がある (警告)"},
	{ContextUnreadable, aratamOnly, "llm.context_file を読めない (前提なしで続ける。警告)"},
	{ContextTooLarge, aratamOnly, "llm.context_file が 16 KiB を超える (前提なしで続ける。警告)"},
	{WebhookUnset, aratamOnly, "slack.webhook_env の環境変数が無い (doctor)"},
	{UrgentWebhookUnset, aratamOnly, "slack.urgent_webhook_env の環境変数が無い (緊急の通知は通常用に送る。警告)"},
	{BotTokenUnset, aratamOnly, "slack.bot_token_env の環境変数が無い (doctor)"},
	{SlackAuthFailed, aratamOnly, "bot トークンを確かめられない (doctor の auth.test)"},
	{SlackScopeMissing, aratamOnly, "bot トークンの scope に chat:write が無い (doctor。警告)"},
	{LLMUnavailable, aratamOnly, "LLM に繋がらない (doctor)"},
}

// Names は tool (Arata / Aratam) が出す code の名前。tool が空なら全部。並びは All の順。
func Names(tool string) []string {
	var out []string
	for _, c := range All {
		if tool == "" || contains(c.Tools, tool) {
			out = append(out, c.Name)
		}
	}
	return out
}

// Known は name が tool の code かを返す。
func Known(tool, name string) bool {
	return contains(Names(tool), name)
}

// Sorted は名前の順に並べた全部の code の名前。
func Sorted() []string {
	out := Names("")
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// log スキーマの名前と版 (ADR 0054)。行ごとに schema の項目は出さない (行が長くなるだけで、読む側は行ごとに確かめない)。
const (
	LogSchema        = "log"
	LogSchemaVersion = 1
)

// Line は標準エラーの JSON 行 1 つの、安定な項目 (arata と aratam で共通)。
// ここに無い属性 (error・log_group・dir など) も行には出るが、人が原因を調べるための値で、名前も中身も固定しない。
// ログ由来の値を含み得るので、公開されるログ (GitHub Actions のログ) には出さない。
type Line struct {
	Time       string `json:"time" desc:"出した時刻 (RFC 3339)"`
	Level      string `json:"level" jsonschema:"enum=DEBUG|INFO|WARN|ERROR" desc:"閉じた語彙 (大文字)"`
	Msg        string `json:"msg" desc:"人向けの文。文言は固定しない (機械で読まない)"`
	Code       string `json:"code,omitempty" jsonschema:"open=code" desc:"何が起きたかを表す固定の語。開いた語彙 (知らない値は、その他の警告・エラーとして扱う)。ERROR の行には必ずある。無い行もある"`
	Source     string `json:"source,omitempty" desc:"設定の sources の名前。その行がソースに関するときだけ"`
	RunID      string `json:"run_id,omitempty" desc:"実行の ID。あるときだけ"`
	SlackError string `json:"slack_error,omitempty" desc:"SEND_FAILED のとき、Slack の Web API が返した error コード (not_in_channel など。英小文字・数字・_ の 64 文字まで)。bot トークンの方式で、Slack がコードを返したときだけ"`
}
