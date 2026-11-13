package checks

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// LogHygiene はアプリのログ (CloudWatch Logs) に残った「載せるべきでない値」を、ロググループ × 種類の行数で報告する (週次、state。ADR 0050)。
// key は `<ソースの id>|<種類>`。窓 (7 日) の行数が 1 以上なら finding、0 なら次の週に解消する。
//
//   - secret_aws_access_key / secret_slack_token / secret_private_key: 秘密の値の形 — high
//   - presigned_url_long_term_key / presigned_url: S3 の署名付き URL (長期のキーで署名したものは分けて数える) — medium
//   - unfiltered_param: 設定に書いた送信項目が、隠されずに残っている — medium
//   - debug_sql: 本番での debug の SQL の出力 — low
//
// 決定 (ADR 0050):
//   - arata が持つのは行数だけ。値もサンプルの行も引かない (collector のクエリが返さない)。どの行かは分からない
//   - 解消は「直近 7 日のログに無い」という意味で、古い行が消えたという意味ではない。見出しに範囲と保持期間を書く
//   - 保持期間は重大度に加えない (重大度は「何が漏れたか」で決める)。行数の下限は置かない (秘密の値は 1 行で足りる)
//   - Fingerprint は重大度 + 種類 (+ unfiltered_param では当たった項目名の集合)。行数と保持期間は入れない (毎週 changed にしない)
//   - 収集に失敗したソースのスナップショットは置き換わらない (engine)。前回の項目を読み直すので finding は維持される
//
// 決定: 設定から外したソース・種類・項目名は、前のスナップショットに残っていても報告しない (設定に書いたものだけを見る。ADR 0014)。
// 決定: finding に載せる文字列は、設定の値 (ソースの id・種類・項目名) と決まった語だけにする。スナップショットの中の文字列は、
// ロググループの名前 (名前の形のときだけ) を除いて写さない (ストアの中身を信用しない。ADR 0037)。
type LogHygiene struct {
	Config config.LogHygiene
}

func (LogHygiene) Name() string         { return "log_hygiene" }
func (LogHygiene) Cadence() Cadence     { return Weekly }
func (LogHygiene) Mode() Mode           { return ModeState }
func (LogHygiene) Needs() []record.Kind { return []record.Kind{record.KindLogHygiene} }

// Disabler は、設定が空で何も見ないチェックが、その理由を返す (engine が skip にして coverage.checks_skipped に出す)。
type Disabler interface {
	Disabled() string
}

// Disabled は sources か kinds が空のときの理由 (空でなければ "")。
// 決定 (ADR 0014): 既定は空で、設定を書くまで読み取りは起きない。「ソースが無い」ではなく、何を書けば動くかを理由にする。
func (c LogHygiene) Disabled() string {
	switch {
	case len(c.Config.Sources) == 0:
		return "checks.log_hygiene.sources is empty (nothing to read; see `arata help ai playbook log_hygiene`)"
	case len(c.Config.Kinds) == 0:
		return "checks.log_hygiene.kinds is empty (nothing to count; see `arata help ai playbook log_hygiene`)"
	}
	return ""
}

// hygieneSeverity は種類ごとの重大度 (ADR 0050 の表)。
var hygieneSeverity = map[string]Severity{ // #nosec G101 -- 種類の名前と重大度の表で、秘密の値は含まない
	config.HygieneSecretAWSAccessKey: High,
	config.HygieneSecretSlackToken:   High,
	config.HygieneSecretPrivateKey:   High,
	config.HygienePresignedLongTerm:  Medium,
	config.HygienePresignedURL:       Medium,
	config.HygieneUnfilteredParam:    Medium,
	config.HygieneDebugSQL:           Low,
}

// hygieneLabel は見出しに書く、種類の呼び名。
var hygieneLabel = map[string]string{ // #nosec G101 -- 種類の名前と呼び名の表で、秘密の値は含まない
	config.HygieneSecretAWSAccessKey: "AWS の長期のアクセスキーの ID の形",
	config.HygieneSecretSlackToken:   "Slack のトークンの形",
	config.HygieneSecretPrivateKey:   "秘密鍵 (PEM) の先頭の行",
	config.HygienePresignedLongTerm:  "長期のアクセスキーで署名した署名付き URL",
	config.HygienePresignedURL:       "署名付き URL",
	config.HygieneUnfilteredParam:    "隠されていない送信項目",
	config.HygieneDebugSQL:           "debug の SQL の出力",
}

// logGroupName は CloudWatch Logs のロググループの名前の形。
var logGroupName = regexp.MustCompile(`^[A-Za-z0-9_\-/.#]{1,512}$`)

func (c LogHygiene) Evaluate(ctx context.Context, q store.Query, _ collect.Window, _ *allowlist.List) ([]Observation, error) {
	if c.Disabled() != "" {
		return nil, nil
	}
	items, err := q.Snapshot(ctx, record.KindLogHygiene)
	if err != nil {
		return nil, err
	}
	// ソース → 種類 → 項目
	bySource := map[string]map[string]record.SnapshotItem{}
	for _, it := range items {
		if bySource[it.Source] == nil {
			bySource[it.Source] = map[string]record.SnapshotItem{}
		}
		bySource[it.Source][it.Key] = it
	}
	var obs []Observation
	for _, src := range c.Config.Sources {
		for _, kind := range config.LogHygieneKinds() {
			it, ok := bySource[src][kind]
			if !ok || !c.Config.HasKind(kind) {
				continue
			}
			count, ok := wholeNumber(it.Data["count"])
			if !ok || count < 1 {
				continue
			}
			sev := hygieneSeverity[kind]
			data := map[string]any{"kind": kind, "count": count}
			where := "ソース " + src
			if lg := it.String("log_group"); logGroupName.MatchString(lg) {
				data["log_group"] = lg
				where = "ロググループ " + lg
			}
			what := hygieneLabel[kind]
			var names []string
			if kind == config.HygieneUnfilteredParam {
				fields := map[string]int64{}
				raw, _ := it.Data["fields"].(map[string]any)
				for _, name := range c.Config.ParamFields {
					if n, ok := wholeNumber(raw[name]); ok && n >= 1 {
						fields[name] = n
						names = append(names, name)
					}
				}
				sort.Strings(names)
				data["fields"] = fields
				if len(names) > 0 {
					what += " (" + strings.Join(names, ", ") + ")"
				}
			}
			span := "直近 7 日"
			if h, ok := wholeNumber(it.Data["window_hours"]); ok && h >= 1 && h <= 24*366 {
				data["window_hours"] = h
				span = spanText(h)
			}
			retention := "不明"
			data["retention"] = "unknown"
			switch it.String("retention") {
			case "never":
				data["retention"], retention = "never", "無期限"
			case "set":
				if d, ok := wholeNumber(it.Data["retention_days"]); ok && d >= 1 && d <= math.MaxInt32 {
					data["retention"], data["retention_days"], retention = "set", int(d), fmt.Sprintf("%d 日", d)
				}
			}
			obs = append(obs, Observation{Check: c.Name(), Key: src + "|" + kind, Severity: sev,
				Summary:     fmt.Sprintf("%s のログに、%s が %d 行 (%s。保持期間は%s)", where, what, count, span, retentionText(retention)),
				Fingerprint: fingerprint(sev, nil, kind, strings.Join(names, ",")),
				Data:        data})
		}
	}
	return obs, nil
}

// retentionText は「保持期間は」の後ろに続ける語 (数字で始まるときだけ空白を挟む)。
func retentionText(s string) string {
	if s != "" && s[0] >= '0' && s[0] <= '9' {
		return " " + s
	}
	return s
}

// spanText は見た範囲の表記 (日で割り切れれば日、そうでなければ時間)。
func spanText(hours int64) string {
	if hours%24 == 0 {
		return fmt.Sprintf("直近 %d 日", hours/24)
	}
	return fmt.Sprintf("直近 %d 時間", hours)
}

// wholeNumber は v が負でない整数の値 (Go の整数か、JSON から戻した float64) なら、その値を返す。
func wholeNumber(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), x >= 0
	case int64:
		return x, x >= 0
	case int32:
		return int64(x), x >= 0
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 || x > 1<<53 || x != math.Trunc(x) {
			return 0, false
		}
		return int64(x), true
	}
	return 0, false
}
