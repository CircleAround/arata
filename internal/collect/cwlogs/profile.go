// Package cwlogs は CloudWatch Logs Insights の集計クエリで日次集計 (metric) を作る collector と、
// 形式プロファイル (= Insights クエリテンプレート集) を持つ (設計書 2 章、ADR 0006 / 0009)。
//
// クエリは 3 層で組み立てる。
//
//  1. 前処理 (Prelude): 形式プロファイルごと。ストリームの絞り込みと、生ログ → 正規化フィールド (ip, method, path, status ...) の変換
//  2. 集計 (MergedQuery): 正規化レコードの種類ごと (http_access / waf_action)。前処理が作ったフィールド名だけを使うので形式に依らない。ソースごとに数本にまとめる (ADR 0031)
//  3. 共通の後処理: `stats count(*) as <metric> by bin(1d) as day, <key>` と件数上限
//
// 生ログは引かない。例外は FORMAT_MISMATCH 時のサンプル (最大 3 行) と doctor のサンプル (100 行) だけ。
package cwlogs

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// Profile は 1 ソース分の形式プロファイル。
type Profile struct {
	Format string
	Yields record.Kind
	// Prelude は生ログを正規化フィールドに変換する Insights コマンド列 (先頭の `|` なし)。
	Prelude string
	// MatchField は解釈できたかの判定に使う正規化フィールド。count(MatchField) が matched になる。
	MatchField string
	// StripPrefix はパスの前に付く接頭辞 (wafv2 の strip_path_prefix)。探索パス・パスの群の判定と正規化の前に外す。
	StripPrefix string
	// fields は前処理が作る正規化フィールド (ip / path 以外の任意のもの。method, status, ua など)。
	fields map[string]bool
	// req は request_lines の 1 段目の材料 (request.go)。nil なら 1 行 = 1 リクエスト。
	req *requestStage
}

// Has は前処理が正規化フィールド name を作るか。
func (p Profile) Has(name string) bool { return p.fields[name] }

// nginx の combined 形式: `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`。
// path はクエリ文字列を除く。
const nginxParse = `parse @message /^(?<ip>\S+) \S+ \S+ \[[^\]]*\] "(?<method>[A-Z]+) (?<path>[^ ?"]*)[^"]*" (?<status>\d{3}) \S+ "[^"]*" "(?<ua>[^"]*)"/`

// ALB アクセスログ: `type time elb client:port target:port req_t target_t resp_t elb_status target_status rx tx "request" "ua" ...`。
// client は IPv6 でも最後の `:port` を外す。path は `METHOD scheme://host:port/path?query HTTP/x` から取り出す。
const albParse = `parse @message /^\S+ \S+ \S+ (?<ip>\S+):\d+ \S+ \S+ (?<duration>\S+) \S+ (?<status>\d{3}|-) \S+ \S+ \S+ "(?<method>[A-Z]+|-) [a-z]+:\/\/[^\/ ]+(?<path>\/[^ ?"]*)[^"]*" "(?<ua>[^"]*)"/`

// WAFv2 のログは JSON なので Insights が自動でフィールド化する。
const wafPrelude = `fields action, terminatingRuleId as rule, httpRequest.clientIp as ip, httpRequest.uri as path, httpRequest.httpMethod as method`

var plainField = regexp.MustCompile(`^[A-Za-z_@][A-Za-z0-9_.@]*$`)

// ProfileFor は設定のソースから形式プロファイルを作る。config.Validate を通ったソースを前提とする。
func ProfileFor(src config.Source) (Profile, error) {
	p := Profile{Format: src.Format, Yields: record.Kind(src.Yields), StripPrefix: src.StripPathPrefix}
	var body string
	p.fields = map[string]bool{}
	if src.Format == config.FormatText {
		// 行を解釈しない (前処理も判定フィールドも無い)。log_hygiene だけが読む (ADR 0050)
		return p, nil
	}
	switch src.Format {
	case config.FormatNginxAccess:
		body, p.MatchField = nginxParse, "path"
		p.setFields("ip", "path", "method", "status", "ua")
	case config.FormatALBAccess:
		body, p.MatchField = albParse, "path"
		p.setFields("ip", "path", "method", "status", "ua", "duration")
	case config.FormatWAFv2:
		body, p.MatchField = wafPrelude, "action"
		p.setFields("action", "rule", "ip", "path", "method")
	case config.FormatJSON:
		body, p.MatchField = jsonPrelude(src.Fields), "path"
		for k := range src.Fields {
			p.setFields(k)
		}
	case config.FormatRegex:
		groups, err := config.RegexGroups(src.Regex, src.Yields)
		if err != nil {
			return Profile{}, err
		}
		p.setFields(groups...)
		body, p.MatchField = "parse @message /"+insightsRegex(src.Regex)+"/", "path"
	case config.FormatRequestLines:
		if src.Request == nil {
			return Profile{}, fmt.Errorf("cwlogs: request is required for format %s", src.Format)
		}
		b, err := requestProfile(&p, src.Request)
		if err != nil {
			return Profile{}, err
		}
		body, p.MatchField = b, rlID
	default:
		return Profile{}, fmt.Errorf("cwlogs: unsupported format %q", src.Format)
	}
	if src.StreamPrefix != "" {
		body = "filter @logStream like /^" + regexLiteral(src.StreamPrefix) + "/\n| " + body
	}
	if len(src.Resources) > 0 {
		// 決定 (ADR 0028): 資源 (httpSourceId) で絞るのは前処理に入れる。解釈率・全集計が同じ範囲を数える。
		// Insights はロググループ全体をスキャンするので費用は減らない
		alts := make([]string, len(src.Resources))
		for i, r := range src.Resources {
			alts[i] = GlobRegex(r)
		}
		body += "\n| filter httpSourceId like /^(" + strings.Join(alts, "|") + ")$/"
	}
	p.Prelude = body
	return p, nil
}

func (p *Profile) setFields(names ...string) {
	for _, n := range names {
		p.fields[n] = true
	}
}

// jsonPrelude は対応表から `fields <元> as <正規化名>, ...` を作る。time は Insights の @timestamp を使うので落とす。
func jsonPrelude(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for dst := range fields {
		if dst != "time" {
			names = append(names, dst)
		}
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, dst := range names {
		if fields[dst] == dst {
			// 同名への別名 (`path as path`) はフィールドの再定義になり得るので書かない
			parts = append(parts, fieldRef(dst))
			continue
		}
		parts = append(parts, fieldRef(fields[dst])+" as "+dst)
	}
	return "fields " + strings.Join(parts, ", ")
}

// fieldRef は記号を含むフィールド名をバッククォートで囲む。
func fieldRef(name string) string {
	if plainField.MatchString(name) {
		return name
	}
	return "`" + strings.ReplaceAll(name, "`", "") + "`"
}

// insightsRegex は Python 形式の名前付きキャプチャ (?P<name>) を Insights の (?<name>) に直し、`/` を `\/` にする。
func insightsRegex(expr string) string {
	return escapeSlashes(strings.ReplaceAll(expr, "(?P<", "(?<"))
}

// escapeSlashes はエスケープされていない `/` を `\/` にする (Insights の /.../ を途中で閉じない)。
func escapeSlashes(expr string) string {
	var b strings.Builder
	escaped := false
	for _, r := range expr {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '/':
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// regexLiteral は文字列を Insights の /.../ 内で文字どおりに一致させる表現にする。
func regexLiteral(s string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(s), "/", `\/`)
}

// GlobRegex は glob (`*` = 任意の文字列、`?` = 任意の 1 文字) を Insights の /.../ 内の正規表現にする。
func GlobRegex(glob string) string {
	r := regexLiteral(glob)
	return strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(r)
}

// stringLiteral は Insights の "..." 文字列リテラル。
func stringLiteral(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
