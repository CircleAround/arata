package cwlogs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// log_hygiene の収集 (ADR 0050)。ロググループごとに Insights のクエリを 1 本流し、種類ごとの「当たった行数」だけを受け取る。
//
// 決定 (ADR 0050): クエリは `fields` (条件ごとの 0 / 1) と `stats` (行数と、条件ごとの合計) だけ。`@message` もその一部も結果に出さない。
// サンプルの行は伏せた形でも引かない。受け取るのは数だけで、読めなければ収集の失敗にする (0 件として解消に倒さない)。
//
// 決定: stream_prefix のあるソースは、先頭に `filter @logStream like /^<接頭辞>/` を 1 段だけ足す (同じロググループを
// stream_prefix で分けた 2 つのソースを別に数えるため)。`filter` は行を絞るだけで、結果に値を出さない。
// wafv2 の `resources` は見ない (1 ソース = 1 ロググループ。資源で絞るには行を解釈する必要がある)。
//
// 決定: `stats` に `count(*) as n_lines` (見た行数) を足す。値ではなく数で、「何行を見て 0 件だったか」をログに残せる
// (0 行のロググループと、読めて 0 件だったことを区別する)。finding には載せない。

// 保持期間の表し方 (finding の data.retention)。無期限は never で、retention_days を書かない (0 は「0 日」とも読める)。
const (
	RetentionSet     = "set"
	RetentionNever   = "never"
	RetentionUnknown = "unknown"
)

// MaxHygieneCount は受け取る行数の上限 (2^53 - 1。これより大きい数は JSON と SQLite で正確に持てない)。
const MaxHygieneCount = 1<<53 - 1

// hygieneLines は見た行数の列の名前。
const hygieneLines = "n_lines"

// 正規表現 (設計書 7 章「log_hygiene」)。先読み・後方参照を使わず、Go の regexp (RE2) でも同じ意味になる書き方だけを使う
// (TestHygieneConditions が意味を固定する)。Insights の `/.../` にそのまま入れるので `/` を含めない。
const (
	// 長期のアクセスキーの ID: AKIA + 英大文字と数字 16 字。後ろに英大文字・数字が続くもの (もっと長い並び) は数えない。
	reAccessKeyID = `AKIA[A-Z0-9]{16}([^A-Z0-9]|$)`
	// 署名付き URL の、長期のキーで署名した印。
	rePresignedLongTerm = `X-Amz-Credential=AKIA`
	rePresigned         = `X-Amz-Signature=`
	// Slack のトークン: 接頭辞 (xoxb- / xoxp- / xoxa- / xoxr- / xoxs- / xoxe- / xapp-) + 英数字とハイフン 10 字以上。
	reSlackToken = `(xox[abeprs]|xapp)-[0-9A-Za-z-]{10,}` // #nosec G101 -- トークンの形を探す正規表現で、秘密の値ではない
	// PEM の秘密鍵の先頭の行 (RSA / EC / OPENSSH / ENCRYPTED などの語は任意。PGP の BLOCK も)。
	rePrivateKey = `-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----`
	// 実行時間の付いた SQL の文 (ORM の debug の出力)。実行時間と文の間に、空白と色付けの ANSI のエスケープ (ESC `[` 数字と `;` `m`) を任意で許す。
	// 決定: ESC の字そのものは書かず「任意の 1 字 + `[…m`」で表す (`\x1b` の書き方が Insights の方言で通るかに依らない)。
	// 文は値を持ち得る SELECT / INSERT / UPDATE / DELETE だけ (BEGIN / COMMIT は数えない)。
	reDebugSQL = `\(\d+(\.\d+)?m?s\)(\s|.\[[0-9;]*m)*(SELECT|INSERT|UPDATE|DELETE)\s`
	// 送信項目の、鍵の後ろ: `=>` か `:` (前後の空白は任意) と、空でも `[` 始まりでもない文字列の値の先頭。
	// `[` 始まりを除くのは、[FILTERED] でないことを先読みなしで書くため。
	reParamTail = `"\s*(=>|:)\s*"[^"\[]`
)

// credentialParam は署名付き URL の、キー ID の直前の文字列。この直後のキー ID は secret_aws_access_key に数えない。
const credentialParam = "X-Amz-Credential=" // #nosec G101 -- 署名付き URL のパラメータの名前で、秘密の値ではない

// notPrecededBy は「直前が lit でない位置」に一致する正規表現 (後方参照の否定を、選択肢の並びで書く)。
// lit = c1…cn のとき、直前が lit でないとは、ある j について「直前が c(j+1)…cn で、その前が cj でない (か行頭)」こと。
func notPrecededBy(lit string) string {
	alts := make([]string, 0, len(lit))
	for j := len(lit) - 1; j >= 0; j-- {
		alts = append(alts, "(^|[^"+classLiteral(lit[j])+"])"+regexLiteral(lit[j+1:]))
	}
	return "(" + strings.Join(alts, "|") + ")"
}

// classLiteral は文字クラス `[^…]` の中に 1 字を文字どおりに置く表現。
func classLiteral(c byte) string {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '=' {
		return string(c)
	}
	return `\` + string(c)
}

// HygieneCond は行ごとの条件 1 つ。Insights では `(<Expr>) as <Field>` が 0 / 1 になり、`sum(<Field>) as <Sum>` で行数になる。
type HygieneCond struct {
	// Field / Sum は一時フィールドと合計の名前。種類の名前と番号から作る (設定の値を識別子に入れない。同じ名前を 2 度定義しない)。
	Field, Sum string
	// Kind は種類。Param は項目ごとの条件のときの項目名 (種類の条件なら空)。
	Kind, Param string
	// Like / NotLike は `@message like /Like/` と `@message not like /NotLike/` (NotLike は空なら無し) の正規表現。
	Like, NotLike string
}

// Expr は Insights の条件式。
func (c HygieneCond) Expr() string {
	s := "@message like /" + c.Like + "/"
	if c.NotLike != "" {
		s += " and @message not like /" + c.NotLike + "/"
	}
	return s
}

// HygieneQuery は src に流すクエリと、その条件 (決まった順) を返す。
//
// 決定 (ADR 0050): 項目名は設定の検査 (config) を通っていても、ここでもう一度形を確かめ、regexLiteral を通してから入れる。
// 形に合わない名前・制御文字を含む stream_prefix はクエリに入れずエラーにする (検査が緩んでも、クエリの段が増えない)。
func HygieneQuery(src config.Source, h config.LogHygiene) (string, []HygieneCond, error) {
	conds, err := hygieneConds(h)
	if err != nil {
		return "", nil, err
	}
	var b strings.Builder
	if src.StreamPrefix != "" {
		if strings.ContainsFunc(src.StreamPrefix, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return "", nil, errors.New("log_hygiene: stream_prefix must not contain control characters")
		}
		b.WriteString("filter @logStream like /^" + regexLiteral(src.StreamPrefix) + "/\n| ")
	}
	b.WriteString("fields ")
	for i, c := range conds {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("(" + c.Expr() + ") as " + c.Field)
	}
	b.WriteString("\n| stats count(*) as " + hygieneLines)
	for _, c := range conds {
		b.WriteString(", sum(" + c.Field + ") as " + c.Sum)
	}
	return b.String(), conds, nil
}

func hygieneConds(h config.LogHygiene) ([]HygieneCond, error) {
	if len(h.Kinds) == 0 {
		return nil, errors.New("log_hygiene: kinds is empty")
	}
	kind := func(k, like, notLike string) HygieneCond {
		return HygieneCond{Field: "f_" + k, Sum: "n_" + k, Kind: k, Like: like, NotLike: notLike}
	}
	var out []HygieneCond
	// 設定に書いた順ではなく、決まった順に並べる
	for _, k := range config.LogHygieneKinds() {
		if !h.HasKind(k) {
			continue
		}
		switch k {
		case config.HygieneSecretAWSAccessKey:
			out = append(out, kind(k, notPrecededBy(credentialParam)+reAccessKeyID, ""))
		case config.HygieneSecretSlackToken:
			out = append(out, kind(k, reSlackToken, ""))
		case config.HygieneSecretPrivateKey:
			out = append(out, kind(k, rePrivateKey, ""))
		case config.HygienePresignedLongTerm:
			out = append(out, kind(k, rePresignedLongTerm, ""))
		case config.HygienePresignedURL:
			out = append(out, kind(k, rePresigned, rePresignedLongTerm))
		case config.HygieneDebugSQL:
			out = append(out, kind(k, reDebugSQL, ""))
		case config.HygieneUnfilteredParam:
			if len(h.ParamFields) == 0 || len(h.ParamFields) > config.MaxHygieneParamFields {
				return nil, fmt.Errorf("log_hygiene: param_fields must have 1-%d names", config.MaxHygieneParamFields)
			}
			lits := make([]string, len(h.ParamFields))
			seen := map[string]bool{}
			for i, f := range h.ParamFields {
				if !config.ValidHygieneParamField(f) || seen[f] {
					return nil, fmt.Errorf("log_hygiene: param_fields[%d] is not a valid name", i)
				}
				seen[f] = true
				lits[i] = regexLiteral(f)
			}
			// 鍵は前後の `"` まで含めて完全に一致させる (name は file_name に当たらない)
			out = append(out, kind(k, `"(`+strings.Join(lits, "|")+`)`+reParamTail, ""))
			for i, f := range h.ParamFields {
				n := strconv.Itoa(i)
				out = append(out, HygieneCond{Field: "f_param_" + n, Sum: "n_param_" + n, Kind: k, Param: f, Like: `"` + lits[i] + reParamTail})
			}
		}
	}
	return out, nil
}

// countValue は受け取る数の書き方: 10 進の数字、任意で小数部と指数 (Insights は合計を `12`・`12.0`・`1.2E7` のように返し得る)。符号・空白・16 進は受け取らない。
var countValue = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?(?:[eE]\+?([0-9]{1,3}))?$`)

// hygieneCount は結果の値を「有限で負でない整数」として読む。読めなければ ok = false。
// 決定: 浮動小数を経ずに桁の列で読む (丸めで、整数でない値や大きすぎる値が別の数に化けない)。
func hygieneCount(s string) (int64, bool) {
	if len(s) > 32 {
		return 0, false
	}
	m := countValue.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	exp := 0
	if m[3] != "" {
		exp, _ = strconv.Atoi(m[3])
	}
	digits, point := m[1]+m[2], len(m[1])+exp
	if point > len(digits) {
		digits += strings.Repeat("0", point-len(digits))
	}
	if strings.Trim(digits[point:], "0") != "" {
		return 0, false // 整数でない
	}
	whole := strings.TrimLeft(digits[:point], "0")
	if whole == "" {
		return 0, true
	}
	if len(whole) > 16 {
		return 0, false
	}
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || n > MaxHygieneCount {
		return 0, false
	}
	return n, true
}

// hygieneCounts は結果の行から、合計の名前 → 行数 と、見た行数を読む。
// 行が無ければ (ログが 1 行も無い) 全部 0。行が 2 つ以上・列が無い・数として読めない値は失敗にする。
// 決定 (ADR 0050): エラーの文に結果の値を写さない (列の名前だけを書く)。
func hygieneCounts(source string, conds []HygieneCond, rows []map[string]string) (map[string]int64, int64, error) {
	fail := func(format string, a ...any) (map[string]int64, int64, error) {
		return nil, 0, &collect.Error{Code: collect.CodeCollectFailed, Source: source, Err: fmt.Errorf("log_hygiene: "+format, a...)}
	}
	out := make(map[string]int64, len(conds))
	if len(rows) == 0 {
		for _, c := range conds {
			out[c.Sum] = 0
		}
		return out, 0, nil
	}
	if len(rows) != 1 {
		return fail("expected a single result row, got %d", len(rows))
	}
	read := func(name string) (int64, bool) {
		v, ok := rows[0][name]
		if !ok {
			return 0, false
		}
		return hygieneCount(v)
	}
	lines, ok := read(hygieneLines)
	if !ok {
		return fail("result column %s is not a non-negative integer", hygieneLines)
	}
	for _, c := range conds {
		n, ok := read(c.Sum)
		if !ok {
			return fail("result column %s is not a non-negative integer", c.Sum)
		}
		out[c.Sum] = n
	}
	return out, lines, nil
}

// hygieneCovered はこのソースを log_hygiene が読む設定か。
func (c *Collector) hygieneCovered() bool { return c.checks.LogHygiene.Covers(c.src.ID) }

// retention はロググループの保持期間 (set / never / unknown と日数)。DescribeLogGroups で取れなければ unknown。
func (c *Collector) retention() (string, int) {
	if c.group == nil {
		return RetentionUnknown, 0
	}
	if days := aws.ToInt32(c.group.RetentionInDays); days > 0 {
		return RetentionSet, int(days)
	}
	return RetentionNever, 0
}

// collectHygiene は窓 [From, To) にクエリを 1 本流し、種類ごとの行数をスナップショットの項目 (種類ごとに 1 つ。0 件も 0 として) で出す。
//
// 決定: 範囲は run の窓 (HygieneFrom があればそこから)。再走査 (ScanFrom) の分は足さない (状態を見るチェックで、遅れて届いた行は次の週の窓に入る)。
// 項目は最後にまとめて出す (途中で失敗したら何も出さない。engine は成功したときだけスナップショットを置き換える)。
// 範囲がロググループの作成前・保持期間の外なら、問い合わせずに全部 0 とする (既存の扱いと同じ「データなし」)。
func (c *Collector) collectHygiene(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	h := c.checks.LogHygiene
	query, conds, err := HygieneQuery(c.src, h)
	if err != nil {
		return &collect.Error{Code: collect.CodeQueryInvalid, Source: c.src.ID, Err: err}
	}
	if !c.HygieneFrom.IsZero() && c.HygieneFrom.Before(w.To) {
		w.From = c.HygieneFrom
	}
	rows, err := c.Query(ctx, query, w.From, w.To)
	if c.stats != nil {
		c.stats.BytesScanned = c.scanned
	}
	switch {
	case errors.Is(err, ErrOutOfRange):
		c.Logger.Info("log_hygiene: query range is outside the log group's lifetime; treating as no data", "source", c.src.ID, "log_group", c.src.LogGroup,
			"from", w.From.Format(time.RFC3339), "to", w.To.Format(time.RFC3339))
		rows = nil
	case err != nil:
		return err
	}
	counts, lines, err := hygieneCounts(c.src.ID, conds, rows)
	if err != nil {
		return err
	}
	at := w.CollectedAt
	if at.IsZero() {
		at = c.Now()
	}
	retention, days := c.retention()
	hours := int(w.To.Sub(w.From).Round(time.Hour) / time.Hour)
	attrs := []any{"source", c.src.ID, "log_group", c.src.LogGroup, "lines", lines, "bytes_scanned", c.scanned, "retention", retention}
	var items []record.SnapshotItem
	for _, cond := range conds {
		if cond.Param != "" {
			continue
		}
		data := map[string]any{"log_group": c.src.LogGroup, "kind": cond.Kind, "count": counts[cond.Sum], "retention": retention, "window_hours": hours}
		if retention == RetentionSet {
			data["retention_days"] = days
		}
		if cond.Kind == config.HygieneUnfilteredParam {
			fields := map[string]any{}
			for _, pc := range conds {
				if pc.Param != "" && counts[pc.Sum] > 0 {
					fields[pc.Param] = counts[pc.Sum]
				}
			}
			data["fields"] = fields
		}
		attrs = append(attrs, cond.Kind, counts[cond.Sum])
		items = append(items, record.SnapshotItem{Kind: record.KindLogHygiene, Time: at, Source: c.src.ID, Key: cond.Kind, Data: data})
	}
	if lines == 0 {
		c.Logger.Warn("log_hygiene: no log lines in window; check log_group / stream_prefix", attrs...)
	} else {
		c.Logger.Info("log_hygiene: counted lines by kind (no values are read)", attrs...)
	}
	for _, it := range items {
		if err := sink.Emit(ctx, it); err != nil {
			return err
		}
	}
	return nil
}
