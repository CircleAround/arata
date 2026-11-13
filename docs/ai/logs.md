# 記録の集め方 (arata を活かすためのログの出し方)

## 使い方

arata のチェックは、設定の `sources` に書いた記録からしか動かない。記録が無いチェックは skip され、指摘は出ない (安全という意味ではない)。
この文書は「どの記録があればどのチェックが動くか」と、その記録の勧める出し方をまとめる。

- arata は**読み取り専用**。ログの配信・保存期間・アプリのログ形式を変えるのは**人が**行う。LLM は現状を読み取りの操作で確かめ、足りないものと直し方を提案するまで
- 順番: 下の表で動かしたいチェックの記録を決める → 記録を出す → `sources` に書く → `arata doctor` で確かめる → `arata init` (流れは `arata help ai onboarding`)
- 例の名前・ID はすべて架空。実際の値に置き換える

## チェックと記録の対応

実行されるのは `profiles` に書いたチェックだけ (`arata profiles` で確かめる)。この表はコードから作り、テストで固定している。

| ソース (kind。括弧は format) | 出る記録 | 動くチェック (周期) |
|---|---|---|
| cloudtrail-lookup | trail_event, principal_seen | root_usage (hourly), unknown_assume_role (hourly), new_principal (daily), iam_changes (daily), access_denied (daily), defense_evasion (daily), public_exposure (daily), principal_new_source (daily), secret_access (daily), ai_path_usage (daily) |
| cloudwatch-logs (alb_access / json / nginx_access / regex / request_lines) | http_access | login_bruteforce (daily), probe_paths (daily), endpoint_abuse (daily) |
| cloudtrail-unused-regions | unused_region_event | unused_region_activity (daily) |
| cost-anomaly | cost_anomaly | cost_anomaly (daily) |
| cloudwatch-logs (wafv2) | waf_action | waf_block_trend (daily) |
| iam-credential-report | iam_credential_report | credential_hygiene (weekly) |
| guardduty | guardduty | guardduty_findings (weekly) |
| posture | posture_item | posture (weekly) |
| access-analyzer | access_analyzer | access_analyzer (weekly) |
| waf-config + cloudwatch-logs (wafv2) | waf_config, waf_action | waf_review (weekly) |
| cloudwatch-logs (text) | log_hygiene | log_hygiene (weekly) |

- `cloudtrail-lookup` だけで 10 個のチェックが動く。最初はこれとアカウント単位のソース (追加の準備が要らない) から始め、アプリ層 (`cloudwatch-logs`) を足していく
- `http_access` は、送信元 IP・パス・ステータスが**同じ 1 行**にあるアクセスログ。ALB・nginx・アプリの JSON 行ログのどれか 1 つあればよい (同じリクエストを二重に数えないよう、1 つの入口につき 1 つ)。
  1 リクエストが複数行に分かれるアプリのログしか無いときは、`format: request_lines` でリクエスト単位にまとめて読む (書き方は `arata help ai request_lines`)
- `waf_review` は weekly に WebACL の設定を読み、daily が貯めた wafv2 の日次集計と突き合わせる (両方のソースが要る)
- `log_hygiene` は、設定の `checks.log_hygiene.sources` に書いたソースだけを読む (既定は空で、書くまで何も読まない)。アプリのログ (アクセスログでないもの) は
  `format: text` (行を解釈しない) で登録する。表の他の形式のソースも `sources` に書ける (アクセスログのクエリ文字列に署名付き URL が残ることがある)
- `guardduty`・`access-analyzer`・`cost-anomaly` は AWS 側でその機能を有効にしていることが前提 (無効なら posture が指摘するか、そのチェックが skip)

## 記録ごとの集め方

- **CloudTrail**: `cloudtrail-lookup` は LookupEvents (イベント履歴) を読むので、証跡も CloudWatch Logs への配信も**無くても動く**。
  ただし遡れるのは 90 日の管理イベントだけで、消せない原本にはならない。証跡 (全リージョン・ログファイルの検証) は別に作る (無ければ posture が `cloudtrail_logging` を指摘する)
- **ALB**: アプリにもサーバーにも触れずに `http_access` が取れる。ALB の **Integrations タブ**から、アクセスログを CloudWatch Logs へ配信する
  (従来のアクセスログの設定 = Attributes タブの S3 への出力とは別の仕組み)。**形式は plain、項目は既定 (全部)** にし、`format: alb_access` で読む。
  これが動作を確かめた形 (実環境で解釈率は約 0.96)。ほかの形 (json、項目の変更、区切りの変更) は未確認なので、変えるなら doctor の解釈率で確かめる。
  ALB の前に CloudFront などのプロキシがあると送信元がプロキシの IP になり、IP ごとの判定はできない
- **WAF (WAFv2)**: WebACL のログの宛先を CloudWatch Logs にする。ロググループ名は **`aws-waf-logs-` で始める** (AWS の決まり。それ以外は宛先に選べない)。`format: wafv2`。
  量が多いので `max_scan_gb` を**必ず**書く (下の「保存期間と費用」)
- **nginx**: アクセスログを **combined 形式**のまま標準出力に出し、コンテナなら awslogs ドライバで送る (EC2 なら CloudWatch エージェント)。`format: nginx_access`。
  `log_format` を独自にしているなら combined に戻すか、`format: regex` で合わせる
- **アプリの JSON 行ログ**: 1 リクエストを **1 行の JSON** にして標準出力に出す。`format: json` と `fields` (対応表) で読む。要るのは送信元 IP とパス (メソッド・ステータスもあるとよい)
  - Rails: 標準のログは 1 リクエストが複数行で、IP・パス・ステータスが別の行に分かれる。アプリを変えられるなら lograge で 1 行の JSON にする (`Lograge::Formatters::Json`)。
    lograge は既定では送信元 IP を出さないので、`custom_payload` などで `remote_ip` (`request.remote_ip`) を足す。
    アプリを変えないなら、標準のログのまま `format: request_lines` で読む (書き方は `arata help ai request_lines`)
  - Go の slog (`slog.NewJSONHandler`)、Node の pino なども同じ。リクエストごとに 1 行、IP・メソッド・パス・ステータスを項目にする
  - 行の全体が JSON であること (時刻やタグを JSON の前に付けると、Logs Insights が項目として読めない)。パスにクエリ文字列を入れない。個人を特定できる値 (メールアドレス、氏名) を項目に入れない
- **アプリのログの中身 (log_hygiene)**: 形を問わない。ロググループを `format: text` のソースにして、`checks.log_hygiene` に `sources`・`kinds`・`param_fields` を書く
  (`arata help ai playbook log_hygiene`)。weekly の run ごとに Insights のクエリを 1 本流し、種類ごとの**行数だけ**を受け取る (値もサンプルの行も引かない)。
  `max_scan_gb` を書く (1 回に読むのは窓 = 7 日分)
- **ECS / Fargate**: タスク定義の `logConfiguration` を awslogs ドライバにして標準出力を送る。コンテナごとにストリームの接頭辞 (`awslogs-stream-prefix`) を分けておくと、
  1 つのロググループに混ざっていても `stream_prefix` で絞れる

## 保存期間と費用

- **保存期間**: アプリ層のチェックの平常帯は、過去 `baseline_days` (既定 14) 日の日次集計から作る。集計は arata のストアに残るが、`init` や作り直しはロググループから読み直すので、
  ロググループの保存期間は `baseline_days` より**長く**する。目安は 90 日以上 (調査で元の行を読める期間でもある)。「期限なし」は費用が増え続けるので、期間を決める
- 保存期間を短くする操作 (PutRetentionPolicy) は defense_evasion が見る。`checks.defense_evasion.min_log_retention_days` (既定 90) より短くすると報告され、arata が読むロググループなら critical。
  意図して短くするなら、この値も合わせて直す
- **読み取りの費用**: `cloudwatch-logs` のソースは Logs Insights の集計クエリだけを流し、課金はスキャンした量に比例する (東京で 1 GB あたり約 0.0076 USD。リージョンと改定で変わる)。
  集計は窓に重なる UTC の日の 0 時から引くので、daily の 1 回は最大で 2 日分 × クエリの本数。hourly に `http_access` / `waf_action` のチェックを入れなければ hourly では流れない
- **`max_scan_gb`**: 1 回の収集でスキャンしてよい量の上限 (既定 0 = 無制限)。超えるとそのソースは `QUERY_LIMIT` で止まり、その日の集計は欠ける。
  WAF のログには必ず書く。値は `arata doctor` の `cost` の行の推奨値 (実測 × 余裕) を使う。nginx・ALB・アプリのログも、量が読めないうちは書いておく
- 配信する側の費用 (CloudWatch Logs の取り込みと保管) は利用者のアカウントに出る。量に比例するので、ヘルスチェックなど要らない行を出さない工夫が効く
- LookupEvents とアカウント単位のソースの API は無料 (例外は `cost-anomaly`: Cost Explorer の API が 1 リクエスト 0.01 USD)

## 設定の書き方

```yaml
sources:
  - id: trail
    kind: cloudtrail-lookup          # 証跡が無くても動く。regions の既定は [aws.region, us-east-1]
  - id: alb_prod
    kind: cloudwatch-logs
    log_group: /aws/vendedlogs/prod-alb-access   # ALB の配信先に選んだロググループ
    format: alb_access
    max_scan_gb: 5
  - id: nginx_prod
    kind: cloudwatch-logs
    log_group: prod-nginx-access
    format: nginx_access
    # stream_prefix: web/            # 1 つのロググループに複数のコンテナが混ざるとき
    # expected_match_rate: 0.3       # 混ざった行を数えるので閾値を下げる (doctor の解釈率を見て決める。既定 0.8)
  - id: waf
    kind: cloudwatch-logs
    log_group: aws-waf-logs-prod
    format: wafv2
    max_scan_gb: 50                  # doctor の cost の行の推奨値
  - id: rails_app
    kind: cloudwatch-logs
    log_group: prod-app
    format: json
    fields: { ip: remote_ip, method: method, path: path, status: status }   # 正規化名: ログの項目名
    sample_lines: false              # 個人情報を含み得るログでは、エラーに行の例を添えない
```

全項目の雛形は `arata config init`。チェックの側 (`checks.login_bruteforce.paths` など) も、アプリの実際のパスとステータスに合わせる (下の「よく詰まる点」)。

## 確かめ方

`arata doctor` (読み取りのみ。問題があれば終了コード 2) の表を、ソースごとに上から読む。`--format json` なら足りない記録の行に `hint` (この文書の節) が付く。

| ITEM | 読み方 |
|---|---|
| `permission` | `ACCESS_DENIED` なら、読み取り専用ロールにその action が無い。必要な action の一覧は表の最後 |
| `log_group` | `LOG_GROUP_MISSING` なら名前かリージョンが違う。名前は完全一致 (`aws logs describe-log-groups --log-group-name-prefix <接頭辞>` で確かめる) |
| `queries` | `QUERY_INVALID` なら `regex` や `fields` の書き方を Logs Insights が受け付けていない |
| `match_rate` | 直近 `--window` (既定 24h) の 100 行を形式で読めた割合。`expected_match_rate` 未満なら `FORMAT_MISMATCH` (ng) で、読めなかった行の例が出る。「行が無い」(warn) は、ログが届いていないか `stream_prefix` の誤り |
| `requests` | `request_lines` のソースだけ。直近 `--window` の行をまとめた結果。まとめられた割合 (最初の行のあるリクエスト / request_id の数) が `expected_complete_rate` 未満、または request_id の異なりの数が最初の行の数の半分未満 (鍵の取り違え) なら `FORMAT_MISMATCH` (ng)。「行の種類」は種類ごとの当たった行数で、0 の種類があれば warn (その行の正規表現を見直す)。使い回し・タグの無い最初の行があるときも warn |
| `cost` | wafv2 のソースの 1 日のスキャン量と費用の概算、`max_scan_gb` の推奨値 |
| `check` | 「skip される: no ... source」は、そのチェックの記録を出すソースが設定に無い (上の対応表)。使わないチェックなら `profiles` から外す |

- 解釈率が 1.00 に近ければよい。混在するロググループでは低くて正常なので、落ち着いた値の少し下を `expected_match_rate` にする。低すぎる閾値は形式の変化を見逃す
- 行の例を見て直す: 形式が違う (→ format を合わせる)、別のコンテナの行が混ざる (→ `stream_prefix`)、1 リクエストが複数行 (→ アプリのログを 1 行にするか、`format: request_lines`)
- run の後は report.json の `coverage.formats` (ソースごとの `match_rate`・`bytes_scanned`・`code`) と `coverage.sources_failed`、skip されたチェックとその理由を見る。
  解釈率が直近の平均から急に落ちると `FORMAT_DRIFT` (デプロイでログの形が変わった合図)
- 解釈率が高くても、チェックの条件 (パス・ステータス) が合っていなければ鳴らない。ログイン失敗を 1 回起こし、その行のパスとステータスを Logs Insights で見て設定と比べる

## よく詰まる点

- **Devise のログイン失敗は 200 で返ることがある**: Devise は失敗時にフォームを再表示し、そのステータスは responder の `error_status` で決まる。ライブラリの既定は `:ok` (200) で、
  4.9 以降に生成した initializer は 422 にしている。古い initializer のままのアプリでは失敗が 200、成功が 302 (設定によっては 303) なので、
  `checks.login_bruteforce` を `failure_statuses: [200]` にする (既定の `[401, 403, 422]` では 1 件も数えない)。実際のログで確かめてから決める
- **ログインの送信先は 1 つとは限らない**: Devise はモデルごとに送信先を持つ (`/users/sign_in` と `/admins/sign_in` など)。`paths` は完全一致なので、全部を書く
- **ALB の配信先のロググループ名**: CloudWatch Logs への配信は、名前が `/aws/vendedlogs/` で始まるロググループになりがち。`log_group` には配信の設定に出ている名前をそのまま書く
- **Rails の標準ログをそのまま標準出力に出している** (ECS、AWS Copilot の既定の構成など): 1 リクエストが複数行で、1 行ずつの形式 (`regex`) ではステータスが別の行なのでログイン失敗を数えられない。
  ALB のログを使うか、lograge にするか、`format: request_lines` でリクエスト単位にまとめる (`arata help ai request_lines`。`requests` が `FORMAT_MISMATCH` のときの直し方もそこ)
- **nginx が ALB の後ろにある**: `$remote_addr` が ALB の IP になり、全リクエストが同じ送信元に見える。realip モジュールで X-Forwarded-For から戻すか、ALB のログを使う。
  アプリの JSON ログも同じで、プロキシを信頼する設定をしたうえでの送信元 IP (Rails なら `request.remote_ip`) を出す
- **ヘルスチェックの行が多い**: 解釈率は変わらないが、スキャン量と取り込みの費用が増える。出さない設定にできるなら出さない
- **CloudTrail の証跡も CloudWatch Logs への配信も無い**: `cloudtrail-lookup` は LookupEvents で読むので動く (遡れるのは 90 日)。証跡は posture の指摘として別に直す。作っても arata の設定は変えなくてよい

## 外部の拠り所

何を記録すべきかの一般的な基準は次を見る。arata の設定の書き方はこの文書と `arata config init` の雛形が正。

- AWS Well-Architected フレームワーク セキュリティの柱「検知 (Detection)」: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/detection.html
- CIS AWS Foundations Benchmark (Logging・Monitoring の章): https://www.cisecurity.org/benchmark/amazon_web_services
- 各サービスの公式文書: ALB のアクセスログ https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html /
  WAF のログを CloudWatch Logs へ https://docs.aws.amazon.com/waf/latest/developerguide/logging-cw-logs.html /
  ECS の awslogs https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html /
  CloudTrail のイベント履歴 https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
