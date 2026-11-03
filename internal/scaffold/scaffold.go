// Package scaffold は `arata config init` が書き出す設定の雛形と、現在の設定と雛形の差分 (`--diff`) を作る。
//
// 決定 (ADR 0014): arata は実行時に暗黙の既定のプロファイルを持たない。推奨の設定は雛形として書き出し、
// 実行時は設定ファイルに書いたものだけが効く。雛形のチェック一覧とパラメータの既定値は Registry と config.DefaultChecks() から
// 生成し、手書きの一覧とずれないようにする。
package scaffold

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// Descriptions はチェックの 1 行説明 (雛形のコメントに出す)。登録済みのチェックは全部ここに書く (テストで保証する)。
var Descriptions = map[string]string{
	"root_usage":          "ルートユーザーの利用 (critical)",
	"unknown_assume_role": "allowlist に無い呼び出し元の AssumeRole (high)",
	"new_principal":       "allowlist にもベースラインにも無い主体 (medium)",
	"iam_changes":         "IAM の変更。deploy タグの主体なら info (medium)",
	"access_denied":       "拒否された API 呼び出しの急増。種類が多ければ権限の列挙の兆候 (medium / high)",
	"login_bruteforce":    "sign-in 失敗の IP 別件数が平常帯超え (medium)",
	"probe_paths":         "機密パス探索の 403/404 が平常帯超え (low)",
	"waf_block_trend":     "WAF の新しく鳴り始めたルール・Top IP の入れ替わり (low)",
	"ai_path_usage":       "allowlist で tags: [ai] の主体の利用を主体 × 送信元 IP で毎回 1 行 (info。自己監査)",
	"credential_hygiene":  "未使用のアクセスキー・MFA 無しのコンソールユーザー・ルートのアクセスキー (medium / high)",
	"guardduty_findings":  "GuardDuty の findings。新規と件数の増加 (重大度は GuardDuty 準拠)",
	"posture":             "CloudTrail 証跡と検証・GuardDuty 有効・ルート MFA・S3 Public Access Block・パスワードポリシー (high / medium)",
	"access_analyzer":     "IAM Access Analyzer の外部アクセス findings (公開は high、他は medium)",
	"waf_review":          "WAF の修正提案の候補を report.json の proposals に (正規の画面での大量 BLOCK は low の finding にも)",
}

// paramComments は checks.<check>.<key> の説明。
var paramComments = map[string]string{
	"login_bruteforce.paths":              "sign-in の送信先。前方一致ではなく完全一致 (クエリ文字列は除いて比べる)。Devise のスコープ付きパス (/admin/users/sign_in など) は実際のパスに合わせる。集計条件なので overrides では変えられない",
	"login_bruteforce.methods":            "sign-in 試行とみなす HTTP メソッド",
	"login_bruteforce.failure_statuses":   "失敗とみなすステータス (Devise の再表示は 401 / 422、成功は 302 / 303)",
	"login_bruteforce.baseline_days":      "平常帯 = その IP 自身の直近 baseline_days 日の中央値 × factor",
	"login_bruteforce.factor":             "平常帯の倍率",
	"login_bruteforce.min_count":          "平常帯の下限 (中央値 0 の IP もこの件数までは鳴らさない)",
	"login_bruteforce.min_baseline_days":  "「初出」判定に要る、データのある過去日数 (導入直後に全部が初出になるのを防ぐ)",
	"login_bruteforce.top_ip_min_count":   "その日の最多 IP が初出なら、この件数以上で報告",
	"probe_paths.paths":                   "機密パスの接頭辞。集計条件なので overrides では変えられない",
	"probe_paths.exclude_paths":           "対象から外す接頭辞 (正規の管理画面など)",
	"probe_paths.statuses":                "探索とみなすステータス",
	"probe_paths.baseline_days":           "平常帯の日数",
	"probe_paths.factor":                  "平常帯の倍率",
	"probe_paths.min_count":               "平常帯の下限",
	"probe_paths.min_baseline_days":       "「初出」判定に要る過去日数",
	"probe_paths.top_ip_min_count":        "その日の最多 IP が初出なら、この件数以上で報告",
	"waf_block_trend.top_n":               "BLOCK 件数の Top IP の入れ替わりを見る数",
	"waf_block_trend.min_count":           "Top IP の新顔として報告する BLOCK 件数の下限",
	"waf_block_trend.new_rule_min_count":  "新しく鳴り始めたルールとして報告する BLOCK 件数の下限",
	"waf_block_trend.baseline_days":       "過去と比べる日数",
	"waf_block_trend.min_baseline_days":   "「初出」判定に要る過去日数",
	"access_denied.error_codes":           "拒否とみなす CloudTrail の errorCode (完全一致)。events に残す条件なので overrides では変えられない。後から足したコードは過去分が無いので平常帯 0 から始まる",
	"access_denied.min_distinct_apis":     "拒否された API の種類がこれ以上 (かつ平常帯超え) で報告 (medium)",
	"access_denied.high_distinct_apis":    "種類がこれ以上なら high (列挙ツールは数十種類を叩く)",
	"access_denied.baseline_days":         "平常帯 = その主体自身の直近 baseline_days 日の中央値 × factor (件数・種類それぞれ)",
	"access_denied.factor":                "平常帯の倍率",
	"access_denied.min_count":             "件数の条件の下限 (同じ API を叩き続ける設定ミスなど。medium 止まり)",
	"access_denied.min_baseline_days":     "平常帯を使うのに要る、拒否のある過去日数 (それ未満は平常帯 0 として絶対の閾値だけで判定)",
	"credential_hygiene.unused_days":      "アクセスキーを未使用とみなす日数 (最終使用、使われていなければ作成・ローテーションから)",
	"posture.min_password_length":         "IAM パスワードポリシーの最小文字数の下限",
	"waf_review.top_paths":                "wafv2 の BLOCK / 許可された探索のパスを日ごとに残す数 (件数の多い順)。集計条件なので overrides では変えられない",
	"waf_review.rate_path_groups":         "1 IP あたりの件数を分けて測るパスの接頭辞 (どれにも当たらなければ「その他」)。集計条件",
	"waf_review.trusted_cidrs":            "監視・開発会社などの正規の送信元 (例 [203.0.113.0/24])。wafv2 の新しい集計と候補から外す。集計条件",
	"waf_review.expected_high_rate_paths": "リクエストが多いのが仕様のパスの接頭辞 (決済など)。レート制限の候補から外す (observation には残る)",
	"waf_review.days":                     "候補を作るのに見る直近の日数 (daily が貯めた日次集計を読む。weekly は wafv2 を引かない)",
	"waf_review.min_distinct_ips":         "誤検知の疑いに要る異なり IP 数 (日ごとの最大。下限の見積もり)",
	"waf_review.finding_distinct_ips":     "誤検知の疑いを low の finding にもする異なり IP 数",
	"waf_review.min_count":                "すり抜けている探索の件数の下限。誤検知の observation (異なり IP が足りない) の件数の下限にも使う",
	"waf_review.rate_factor":              "レート制限が無いとみなす条件: 1 IP の 5 分あたりの最大が p99 のこの倍を超える",
	"waf_review.rate_margin":              "提案する limit = max(p99 × rate_margin, rate_floor) (5 分あたり)",
	"waf_review.rate_floor":               "提案する limit の下限",
	"waf_review.rate_loose_factor":        "既存のレート制限が観測の最大のこの倍より高ければ緩すぎる (p99 より低ければ厳しすぎる)",
	"waf_review.unused_days":              "使われていないルールとみなす一致 0 の日数 (この日数分のデータが要る)",
	"waf_review.max_proposals":            "候補の種類ごとに出す上限 (根拠の強い順)",
}

// Profile は雛形のプロファイル 1 つ。
type Profile struct {
	Name    string
	Window  string
	Comment string
	// Cadences はこのプロファイルに入れるチェックの周期。
	Cadences []checks.Cadence
}

// Profiles は雛形のプロファイル。決定: daily には hourly のチェックも入れる (hourly を回さず daily だけ運用しても拾えるように。
// 両方回しても hourly で報告済みの事象は daily の already_reported に回り、二重には鳴らない)。
var Profiles = []Profile{
	{Name: "hourly", Window: "1h", Comment: "発生そのものが異常な事象の早期検知。Logs Insights を使うチェックは入れない (費用)", Cadences: []checks.Cadence{checks.Hourly}},
	{Name: "daily", Window: "24h", Comment: "前兆・試行の発見と平常帯との比較。hourly を回さない運用でも拾えるよう hourly のチェックも入れる", Cadences: []checks.Cadence{checks.Hourly, checks.Daily}},
	{Name: "weekly", Window: "7d", Comment: "設定不備・衛生状態の差分", Cadences: []checks.Cadence{checks.Weekly}},
}

// ProfileChecks は雛形のプロファイルに入るチェック (周期の順、周期内は登録順)。
func ProfileChecks(reg *checks.Registry, p Profile) []string {
	var out []string
	for _, cad := range p.Cadences {
		for _, n := range reg.Names() {
			if c, _ := reg.Get(n); c.Cadence() == cad {
				out = append(out, n)
			}
		}
	}
	return out
}

// Generate は雛形の YAML を返す。全プロファイル・全チェック・各チェックの既定パラメータを明示し、`default-*` は使わない。
func Generate(reg *checks.Registry) []byte {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	cm := func(text, comment string) { w("%-48s # %s\n", text, comment) }
	ctDelay, logsDelay := dur(config.DefaultIngestDelay[config.KindCloudTrailLookup]), dur(config.DefaultIngestDelay[config.KindCloudWatchLogs])
	w(`# arata の設定 (arata config init が書き出した雛形)。監査対象ごとに 1 ファイル。allowlist.yaml と一緒に git 管理する。
#
# arata は実行時に暗黙の既定を持たない: 実行されるのは profiles に書いたチェックだけ。
# 新しい版で増えたチェックや変わった既定値は arata config init --diff -c <この設定> で、
# 実際に効いているチェックとパラメータは arata profiles -c <この設定> で確かめる。
# 手順: arata config init → (この設定を編集) → arata doctor → arata init → arata run

`)
	cm("name: my-service", "レポートに出す監査対象の名前")
	cm("store: dir:///var/lib/arata/my-service", "ストア (JSONL 原本 + SQLite)。書き込める場所にする")
	cm("allowlist: allowlist.yaml", "既知リスト。相対パスはこの設定ファイルから。無ければ空として扱う")
	w("\naws:\n")
	w("  region: %s\n", config.DefaultRegion)
	cm("  # profile: my-service-audit", "AWS SDK の標準認証チェーン (profile / 環境変数 / ロール) に従う")
	w("\nsources:\n")
	w("  - id: trail\n")
	cm("    kind: "+config.KindCloudTrailLookup, "CloudTrail を API 経由で取得 (CloudWatch Logs 配信が無くても動く)")
	cm(fmt.Sprintf("    # regions: [%s, %s]", config.DefaultRegion, config.GlobalRegion),
		fmt.Sprintf("省略時は [aws.region, %s]。IAM・ConsoleLogin・STS の一部は %s にしか記録されない", config.GlobalRegion, config.GlobalRegion))
	cm("    # ingest_delay: "+ctDelay, "記録の遅れの見込み。run は窓の前をこの分だけ引き直す (0 で引き直さない)")
	w(`
  # アカウント単位の状態 (週次チェック用)。取るたびに丸ごと置き換える。プロファイルが必要とする run (weekly) でだけ取る。
  # 一部の権限が無ければ、そのソースのチェックだけ skip される (coverage と doctor に不足 action が出る)。
`)
	w("  - id: iam\n")
	cm("    kind: "+config.KindCredentialReport, "認証情報レポート → credential_hygiene")
	w("    # iam:GenerateCredentialReport は書き込み系 (レポートの生成のみ)。拒否されても 4 時間以内に生成済みのレポートがあれば使う\n")
	w("  - id: guardduty\n")
	cm("    kind: "+config.KindGuardDuty, "→ guardduty_findings。無効なら skip (無効であることは posture が報告)")
	cm(fmt.Sprintf("    # regions: [%s]", config.DefaultRegion), "省略時は aws.region。使っているリージョンを並べる")
	w("  - id: access_analyzer\n")
	cm("    kind: "+config.KindAccessAnalyzer, "→ access_analyzer。アナライザーが無ければ skip")
	w("  - id: posture\n")
	cm("    kind: "+config.KindPosture, "→ posture (CloudTrail・GuardDuty・ルート MFA・S3・パスワードポリシー)")
	w("  # - id: waf_config\n")
	cm("  #   kind: "+config.KindWAFConfig, "WebACL の設定 → waf_review (下の wafv2 のソースも要る)。REGIONAL は regions、CLOUDFRONT は us-east-1")
	w(`
  # アプリ層 (CloudWatch Logs): ロググループ → 形式プロファイル → 正規化レコード。取得は Logs Insights の集計クエリだけ。
  # 足したら arata doctor で解釈率とクエリを確かめる。
  # - id: nginx_prod
`)
	w("  #   kind: %s\n", config.KindCloudWatchLogs)
	w("  #   log_group: /my-app/nginx/access.log\n")
	cm("  #   format: nginx_access", "nginx_access / alb_access → http_access、wafv2 → waf_action")
	cm("  #   # stream_prefix: web/", "混在ストリームはストリーム名で絞る")
	cm(fmt.Sprintf("  #   # expected_match_rate: %.1f", config.DefaultExpectedMatchRate), "解釈率の閾値。混在ストリームは下げる")
	cm("  #   # max_scan_gb: 5", "1 回の収集でスキャンしてよい量 (既定 0 = 無制限)")
	cm("  #   # ingest_delay: "+logsDelay, "取り込みの遅れの見込み")
	w("  # - id: rails_app\n")
	w("  #   kind: %s\n", config.KindCloudWatchLogs)
	w("  #   log_group: /my-app/rails\n")
	cm("  #   format: json", "JSON 行ログ。対応表 (ip と path は必須)")
	w("  #   fields: { ip: remote_ip, method: method, path: path, status: status }\n")
	cm("  #   # sample_lines: false", "FORMAT_MISMATCH のログに行の例を添えない (個人情報を含み得るログ)")
	w("  # - id: waf\n")
	w("  #   kind: %s\n", config.KindCloudWatchLogs)
	w("  #   log_group: aws-waf-logs-my-app\n")
	w("  #   format: wafv2\n")
	cm("  #   # strip_path_prefix: /prod", "API Gateway の REST API はパスの前にステージ名が付く。探索パス・パスの群の判定の前に外す\n")

	w("# チェック一覧 (周期 / 型 / 必要なレコード)。event 型は窓内の出来事、state 型は今の状態を報告する。\n")
	width := 0
	for _, n := range reg.Names() {
		width = max(width, len(n))
	}
	for _, n := range reg.Names() {
		c, _ := reg.Get(n)
		w("#   %-*s  %-6s  %-5s  %-14s  %s\n", width, n, c.Cadence(), c.Mode(), kinds(c.Needs()), Descriptions[n])
	}
	w("# 必要なレコードを出すソースが無いチェックは skip される (coverage に理由が出る)。http_access / waf_action は cloudwatch-logs が出す。\n")
	w("profiles:\n")
	for _, p := range Profiles {
		names := ProfileChecks(reg, p)
		if len(names) == 0 {
			w("  # %s: この版には %s のチェックが無い\n", p.Name, cadences(p.Cadences))
			continue
		}
		cm("  "+p.Name+":", p.Comment)
		w("    window: %s\n", p.Window)
		cm("    # max_catchup: "+dur(config.DefaultMaxCatchup), "cron が遅れた時に前回の窓の終わりから追いつく上限")
		w("    checks:\n")
		for _, n := range names {
			w("      - %-*s  # %s\n", width, n, Descriptions[n])
		}
		if p.Name == "daily" {
			cm("    # overrides:", "このプロファイルでだけ判定のパラメータを変える (書かなければ checks: の値)")
			cm("    #   login_bruteforce: { min_count: 50 }", "集計条件 (paths / methods / statuses など) は変えられない")
		}
	}

	w("\n# チェックのパラメータ (すべてのプロファイルに効く)。下の値はこの版の既定値。\n")
	w("checks:\n")
	params := config.DefaultChecks().Params()
	for i, p := range params {
		if i == 0 || params[i-1].Check != p.Check {
			w("  %s:\n", p.Check)
		}
		cm(fmt.Sprintf("    %s: %s", p.Key, flow(p.Value)), paramComments[p.Check+"."+p.Key])
	}

	r := config.DefaultRetention
	w("\n# 保持期間 (prune は後続の版)。\nretention:\n")
	cm("  raw_jsonl: "+r.RawJSONLRaw, "原本")
	w("  events: %s\n", r.EventsRaw)
	cm("  metrics: "+r.MetricsRaw, "前年同月比較のため 13 か月")
	cm("  findings: "+r.FindingsRaw, "resolved から")
	w("  runs: %s\n", r.RunsRaw)
	return []byte(b.String())
}

// flow は値を 1 行の YAML (配列は [a, b]) にする。
func flow(v any) string {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		panic(err) // 既定値の型は固定なので起きない
	}
	if n.Kind == yaml.SequenceNode {
		n.Style = yaml.FlowStyle
	}
	out, err := yaml.Marshal(&n)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(out))
}

// dur は期間を設定の書式 (7d / 24h / 15m) にする。
func dur(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0 && d >= 24*time.Hour:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func kinds(ks []record.Kind) string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return strings.Join(out, ",")
}

func cadences(cs []checks.Cadence) string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c)
	}
	return strings.Join(out, " / ")
}
