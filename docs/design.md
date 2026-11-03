# arata 設計書

作成: 2026-10-21

`arata` は AWS のログと設定を定期的に改め、**前回から新しく発生したもの**を報せる監査エンジン。名前は「改め」と「新た」から。
前段の検討 (検知対象の整理、周期の考え方、組み込み方の比較) は別資料にある。

## 1. 決定事項

| 項目 | 決定 |
|---|---|
| 言語 | Go。単一静的バイナリ。SQLite は `modernc.org/sqlite` (純 Go、cgo 不要) で aarch64 オンプレと Lambda arm64 に同一ソースからクロスコンパイル。CLI は標準の `flag` の上の小さなコマンド層 |
| 依存 | 決定: 標準ライブラリで無理なく書けるものは依存にしない。CLI は cobra をやめ標準の `flag` で書き (ヘルプ書式とエラー文言は cobra と同じ)、LookupEvents のレート制限は `golang.org/x/time/rate` をやめ自前の `IntervalLimiter` (2 req/s・バースト 1、時刻は差し替え可能) にした。決定: SQLite (`modernc.org/sqlite`) は残す。ADR 0019 |
| 責務の境界 | エンジンは **収集・保存・差分判定・レポート生成** まで。通知・起動・LLM 要約は組み込み側。決定: LLM 要約と通知の標準品として別コマンド `aratam` を置き、arata とは出力 (`--out` の report.json / report.md) だけで連携する (`docs/aratam.md`、ADR 0018) |
| 認証 | 顧客ごとの読み取り専用ロールに Roles Anywhere で入る。エンジンは AWS SDK の標準認証チェーンに従うだけ (profile / 環境変数 / Lambda ロール) |
| 共通化 | AWS 層のチェックは全顧客共通。アプリ層は「ログの形式プロファイル」とロググループの紐付けを設定で行う (2 章) |
| ストア | JSONL (原本) + SQLite (派生) の二層。保持期間は設定で指定し自動削除 (5 章) |
| 姿勢チェック | 含める (CloudTrail / GuardDuty 有効、ルート MFA など) |
| LLM | エンジン内では使わない。LLM 向けの使い方 (レポートの読み方・承認判断の基準) は `arata help ai` としてバイナリに埋め込む (決定: skill ファイルの同梱は取りやめ。ADR 0012) |
| 任意期間レポート | `report --from --to` で月次・四半期・任意期間を生成 |
| リポジトリの例 | 決定: リポジトリ (例・テスト・文書) に特定の顧客の情報を書かない。例は架空の値を使う (アカウント ID は `123456789012` / 外部 SaaS は `111122223333`) |
| 設定の名前 | 決定: 設定のトップレベルキーは `customer` ではなく `name` (レポートに出す監査対象の名前)。`customer` は受託側の目線に寄りすぎており、自社アカウントを自社で監査する使い方もあるため中立な名前にした。利用者がいない段階の改名なので旧キーの互換は持たず、`customer` は未知のキーとして設定エラーになる |
| サプライチェーン | 決定: GitHub Actions は 40 桁の SHA で固定し版をコメントに書く。全ワークフローに最小権限の `permissions:`、checkout は `persist-credentials: false`。依存は公開から 7 日待つ 2 段構え (提案: Dependabot の `cooldown`、強制: CI の `tools/agegate` が indirect を含む全モジュールの公開時刻を GOPROXY で確かめる)。CI で `go mod verify` と `govulncheck`。release は build provenance attestation (来歴証明) を付ける (公開リポジトリまたは Enterprise Cloud で有効。非公開の間は SHA256SUMS のみ)。ADR 0017 |

## 2. ログの種類とロググループの紐付け (質問 2 への回答)

懸念は正しい。ロググループ名は顧客ごとに違い、中身の形式も違う (nginx の 1 行ログ、WAF の JSON、ECS の混在ストリーム)。
そこで **「ロググループ → 形式プロファイル → 正規化レコード → チェック」** の 3 段で切り離す。

```yaml
sources:
  - id: nginx_prod
    kind: cloudwatch-logs
    log_group: prod-nginx-access
    format: nginx_access            # 形式プロファイル
  - id: ecs_web
    kind: cloudwatch-logs
    log_group: /ecs/my-app-production
    stream_prefix: web/             # 混在ストリームはストリーム名で絞る (例: ECS でリバースプロキシとアプリが同じストリームに出る構成)
    format: nginx_access
    expected_match_rate: 0.3        # 混在している分だけ閾値を下げる
  - id: waf
    kind: cloudwatch-logs
    log_group: aws-waf-logs-prod
    format: wafv2
  - id: rails_admin
    kind: cloudwatch-logs
    log_group: prod-app.log
    format: regex
    regex: 'Started (?P<method>\w+) "(?P<path>/admin/[^"]*)" for (?P<ip>[\d.]+).*user_id=(?P<user_id>\d+)'
  - id: trail
    kind: cloudtrail-lookup         # CloudTrail は API 経由 (CloudWatch Logs 配信が無くても動く)
    # regions: [ap-northeast-1, us-east-1]   # 決定: 既定は [aws.region, us-east-1]。IAM / ConsoleLogin / STS の一部は us-east-1 に記録される
```

決定: `cloudtrail-lookup` の `regions` (配列。`region` 単数も 1 要素として受ける) の既定は `[aws.region, us-east-1]` の重複除去。
LookupEvents はリージョン単位で、グローバルサービス (IAM の書き込み、ルート / IAM ユーザーの ConsoleLogin、STS の一部) は us-east-1 にしか記録されないため、既定で両方を引く。

- **形式プロファイル**は「このログからどんな正規化レコードが取れるか」を宣言する。
  `nginx_access` と `alb_access` はどちらも `http_access` レコード (time, ip, method, path, status, ua, duration) を出す。
  `wafv2` は `waf_action` レコード、`regex` は名前付きキャプチャをそのままフィールドにする。
- **チェック**は「必要な正規化レコードの種類」だけを宣言する (例: `login_bruteforce` は `http_access` が要る)。
  必要なレコードを出すソースが設定に無ければ、そのチェックは「設定不足」として skip し、`doctor` が警告する。
- **実際の取得は Logs Insights の集計クエリ**で行い、生ログは引かない。形式プロファイル = 「Insights クエリのテンプレート集」。
  nginx 1 行ログなら `parse` でフィールド化してから `stats count() by ip, status` のように集計して返す。
  スキャン量課金なので、ウィンドウとフィルタを必ず付ける。
- 紐付けの妥当性は `arata doctor` で検証する: 各ソースから直近 100 行を取り、形式プロファイルで解釈できた割合を出す
  (80% 未満なら設定ミスの疑い)。ロググループの存在と IAM 権限もここで確認する。

初期に用意する形式プロファイル: `nginx_access`, `alb_access`, `wafv2`, `cloudtrail` (CloudWatch Logs 配信版), `regex`。
Rails / unicorn / delayed_job は顧客差が大きいので `regex` で対応し、使い回せる正規表現をサンプル集として同梱する。

決定 (cloudwatch-logs ソース。Step 2 の実装。クエリテンプレートの構造は ADR 0009):
- 実装したプロファイルは `nginx_access` (combined 形式) / `alb_access` / `wafv2` / `json` / `regex`。`cloudtrail` (CloudWatch Logs 配信版) は未実装 (`cloudtrail-lookup` で足りるため後回し)。
- `region` は 1 つ (既定 `aws.region`)。ロググループはリージョンに属するため、`cloudtrail-lookup` のような us-east-1 の自動追加はしない。
- `yields` の既定は形式ごとに決まる (`nginx_access` / `alb_access` / `json` / `regex` → `http_access`、`wafv2` → `waf_action`)。
- `http_access` の必須フィールドは `ip` と `path`。`method` / `status` / `ua` / `duration` は任意で、無ければそのフィールドを使う集計が 0 件になる。
  `json` の `fields` と `regex` の名前付きキャプチャは必須フィールドを含まなければ `CONFIG_INVALID`。`fields.time` は受け付けるが使わない (Insights の `@timestamp` で日を切る)。
- `regex` は Python 形式 `(?P<name>...)` を Insights の `(?<name>...)` に、`/` を `\/` に直して `parse @message /.../` にする。
  Go (RE2) で解釈できない表現 (後方参照・先読み) は設定読み込み時に弾き、Insights 側の方言の差は `doctor` の構文検査 (`QUERY_INVALID`) で見つける。
- `stream_prefix` は `filter @logStream like /^<prefix>/` を前処理の先頭に置く。
- 取得するのは日次集計 (metrics) だけ。`http_access` からは `sign_in_failures` (key=ip)、`probe_hits` (key=ip)、`probe_paths` (key=path)、
  `waf_action` からは `waf_block` (key=rule)、`waf_block_ip` (key=ip)、全形式で `lines_total` / `lines_matched`。集計の条件 (パス・ステータス) は設定の `checks:` から入れる (7 章)。
- `QUERY_LIMIT` になるのは次のとき: 同時実行上限 (`LimitExceededException`) を 5 回待って再試行しても通らない / Insights 側のタイムアウト /
  完了待ちが 15 分を超えた (StopQuery する) / ソースの `max_scan_gb` (1 回の収集でのスキャン量。既定 0 = 無制限) を超えた (実行中なら StopQuery、以後のクエリは流さない)。
  集計クエリは窓に重なる UTC 日の 0 時から引くので (3 章)、1 回のスキャンは最大で窓 + 24h 分になる。`max_scan_gb` はこれを見込んで決める。
- 決定 (問い合わせ範囲とロググループの寿命): Logs Insights は、問い合わせの**終わり**がロググループの作成時刻より前、または保持期間 (今 − `retentionInDays`) より古いと
  `MalformedQueryException` で拒否する。始まりが作成前・保持期間外でも、終わりが範囲内なら受理される (2026-11 に実 AWS で確認。「終わりが作成後かつ保持期間外」は未確認だが、文言から拒否される前提で扱う)。
  そこで collector は DescribeLogGroups の `creationTime` と `retentionInDays` を 1 回引き、終わりだけで判定する。外れていれば問い合わせず「データなし」とし (エラーにしない)、
  INFO ログと、init では run の stats の `logs_out_of_range` (ソース → 日付) に残す。report.json のスキーマは変えない (daily などの run は終わりが今なので該当しない)。
  始まりは作成時刻までは寄せる (作成前のデータは無く結果は同じ)。保持期間の境界には寄せない: 日次集計は後の値で置き換えるので (5-2)、日の頭を寄せると完全な日の値を一部だけの値で上書きし得る。
  判定は Collect・FORMAT_MISMATCH のサンプル・doctor の構文検査と解釈率のすべての問い合わせに効く。DescribeLogGroups が失敗したとき・グループが見つからないときは WARN を出して従来どおり問い合わせる
  (グループが無ければ StartQuery の `LOG_GROUP_MISSING`)。飛ばした日は metrics を持たないので、`min_baseline_days` の「データのある過去日」に数えない。
  経緯: 作ったばかりのロググループで `init` すると最初の日が `QUERY_INVALID` で止まった (フェイクがこの挙動を知らず見逃した。cwlogstest は作成時刻と保持期間を持ち、範囲外を同じ例外で拒否する)。

決定 (アカウント単位のソース。Step 3、ADR 0015): 週次チェック用に、窓に依らない「今の状態」を取る source.kind を 4 つ置く。

```yaml
  - id: iam
    kind: iam-credential-report   # IAM 認証情報レポート → iam_credential_report → credential_hygiene
  - id: guardduty
    kind: guardduty               # アーカイブされていない findings → guardduty → guardduty_findings
    regions: [ap-northeast-1]     # 既定は aws.region。使っているリージョンを並べる
  - id: access_analyzer
    kind: access-analyzer         # ACTIVE なアナライザーの ACTIVE な findings → access_analyzer
  - id: posture
    kind: posture                 # CloudTrail 証跡・GuardDuty 有効・ルート MFA・S3 Public Access Block・パスワードポリシー → posture_item
```

- 取ったものは `record.SnapshotItem` として `snapshot_items` に保存し、**収集が成功したときだけ (kind, source) 単位で丸ごと置き換える** (5-2)。
  失敗したら前回のまま残し、そのソースのチェックは skip する (権限を失ったことを「解消」と誤認しない)。
- GuardDuty が無効 (detector が無い / 停止中)、アナライザーが無いときは、収集は成功として「その種類は取れない」理由を返し、チェックを skip して
  `coverage.checks_skipped` に理由を出す。GuardDuty が無効であることは posture が finding として報告する。
- posture は一部の API だけ拒否されても他の項目を取る。取れなかった項目は `unknown` で保存し、`coverage.sources_failed` に `partial: true` と `action`、終了コード 3。
- `iam:GenerateCredentialReport` は書き込み系 (レポートの生成のみ)。拒否されても 4 時間以内に生成済みのレポートがあれば使い、生成時刻を Data に残す。
- `regions` の既定は aws.region だけ。`ingest_delay` は使わない (窓に依らないため)。

決定 (WAF の修正提案の素材。ADR 0023): `waf_review` (7 章) のために、wafv2 の集計と WebACL の設定のソースを足す。

- `waf-config` (アカウント単位のソース): `ListWebACLs` / `GetWebACL` / `GetLoggingConfiguration` / `ListResourcesForWebACL` で WebACL 1 件
  (`acl|<scope>|<region>|<WebACL>`) とルール 1 件ずつ (`rule|<scope>|<region>|<WebACL>|<ルール>`) を `snapshot_items` (kind `waf_config`) に置く。
  REGIONAL は `regions` (既定 aws.region)、CLOUDFRONT は regions に関係なく us-east-1 のクライアントで引く。`ListResourcesForWebACL` は CloudFront に使えないので REGIONAL だけ、資源の種類ごとに呼ぶ。
  決定: ListResourcesForWebACL は種類ごとに資源のサービス側の権限も要る (COGNITO_USER_POOL → `cognito-idp:ListResourcesForWebACL`。sandbox の本物の AWS で拒否されて判明)。
  守っている資源は提案の補助なので、読み取りロールに各サービスの権限は足さず (最小権限)、呼べない種類はその種類だけ WebACL の `resources_unknown` (`<種類>: <code>`) に残して WARN を出し、ソースは失敗にしない。
  エラー文は解釈しない (種類ごとに文言がばらばらで、Verified Access・AgentCore Gateway は action を名指ししない。sandbox で確認)。代わりに wafv2 の権限だけで呼べる
  APPLICATION_LOAD_BALANCER を最初に呼び、それが拒否されたときだけ `wafv2:ListResourcesForWebACL` 自体の拒否 (ロールの更新漏れ) としてソースの失敗にする。
  ALB が通った後の拒否・パラメータエラー (その種類がリージョンで使えない `WAFInvalidParameterException` など) は、すべてその種類だけ不明にする。
  doctor も同じ規則で、実際に呼ぶ種類ごとに試し、ALB の拒否は ng、他の種類の失敗は warn にする。
  Statement の全体は保存せず、action (BLOCK / ALLOW / COUNT など、グループは OverrideAction の NONE / COUNT)・種類 (`managed_group` / `rule_group` / `rate_based` / `regular`)・
  マネージドの名前・グループの中で COUNT にしたルール (`RuleActionOverrides` と古い `ExcludedRules`)・レート制限の値・評価窓・集約・scope-down の URI 条件だけを持つ。
  scope-down は UriPath の ByteMatch (STARTS_WITH / EXACTLY) とその And だけを解釈し、他を含めば `rate_scope_parsed: false`。WebACL が 1 つも無ければ Unavailable (waf_review は skip)
- wafv2 の日次集計に足すもの (`cloudwatch-logs` の wafv2 ソース。daily で回る):

| metric | key | 値 |
|---|---|---|
| `waf_rule_action` | `<WebACL>\|<終了ルール>\|<action>` | 件数。既存の `waf_block` (ルール別) はここから作り、クエリを 1 本減らす |
| `waf_block_path` / `_ips` | `<WebACL>\|<ルール>[/<グループの中のルール>]\|<method>\|<正規化パス>` | BLOCK の件数 / 異なり IP 数。探索パスは除く。日ごとに上位 `top_paths` (既定 50) |
| `waf_allow_probe` / `_ips` | `<WebACL>\|<正規化パス>` | 探索パス (probe_paths) への ALLOW の件数 / 異なり IP 数。上位 `top_paths` |
| `waf_rule_count_match` / `_suspect` | `<WebACL>\|<ルール>` (グループの中は `<ruleGroupId>/<ルール>`) | カウントモードの一致の件数 / そのうち探索パスか、その日「BLOCK された IP」(下の決定) からの件数 |
| `waf_ip_rate_p50` / `_p99` / `_max` | `<WebACL>\|<パスの群>` | 1 IP あたり 5 分間の件数の分布。群は `rate_path_groups` の接頭辞 (最長一致)、どれにも当たらなければ `*` |
| `waf_position_limit` | `<WebACL>\|<配列の名前>` | 配列の位置の上限を超えた (数え漏れの可能性がある) リクエストの数 |

- 決定: ヘッダー・クエリ文字列・Cookie・User-Agent・本文は引かない。WebACL 名は `webaclId` の ARN から `parse` で取る
- 決定: パスはクエリと `#` 以降を落とし、数字だけ・UUID の区間を `:id` にし、メールアドレスらしき文字列を伏せる。Insights に正規表現の置換が無いので Go 側で行う。
  そのため Insights では (パス, IP) で集計し、Go で正規化してから異なり IP を数える (生パスごとの異なり IP を足すと、1 IP が /items/1..500 を列挙したときに 500 IP と数え、攻撃を誤検知と取り違える)
- 決定: 1 回の結果は 10000 行まで。超えたら件数の多い組だけが残る (少なめに数え、候補は出にくい側に倒れる)。WARN を出し、`coverage.formats[].truncated` と run の stats の `truncated_aggregates` (ソース → 集計の名前) に残す
- 決定 (カウントの一致): Insights は JSON の配列を `name.0.field` に平坦化し、group by できる (2026-11 に sandbox の実ログで確認)。トップレベルの `nonTerminatingMatchingRules` は先頭 3 個、
  `ruleGroupList` は先頭 8 グループ (各グループの中の `nonTerminatingMatchingRules` は先頭 1 個) を group by に並べて 1 回のスキャンで取り、Go で分解する。
  グループ全体を COUNT にした場合はトップレベルに WebACL 上のルール名が出て、グループの中の 1 ルールを COUNT に上書きした場合は `ruleGroupList.N.nonTerminatingMatchingRules` に中のルール名が出る (実ログで確認)。
  `ruleGroupList` には一致しなかったグループも WebACL の順に全部入る。上限のすぐ後ろの位置 (番兵) も group by に入れ、埋まっていれば `waf_position_limit` に数える (それより後ろは数え漏れる。waf_review は observation で伝える)
- 決定 (止めたグループの中のルール名): BLOCK の行は `ruleGroupList.N.terminatingRule.ruleId` を位置で取り、`terminatingRuleType` がグループ (GROUP / MANAGED_RULE_GROUP) のときだけ、
  null でない**最後の**位置のものを採る。前にある COUNT のグループは一致すると `terminatingRule` が null でなくなるが、止めたグループより後ろのグループは評価されないので、最後の 1 つが止めたグループになる。
  番兵 (9 番目のグループ) が埋まっているときは判断できないので、中のルール名を付けずグループ単位にする (安全側)。`parse @message` の正規表現で最初の `terminatingRule` を取る案は、
  前にある COUNT のグループのものを取り違える (実ログで確認) のでやめた
- 決定 (カウントの一致の suspect の「BLOCK された IP」): 専用のクエリ (保存しない) で、レートベースのルール (`terminatingRuleType` が RATE_BASED)・既定の action (`Default_Action`)・
  sign-in のパス (`login_bruteforce.paths`) での BLOCK を除いた BLOCK の IP を日ごとに取る。正規の利用者も一時的にレート制限に当たり得て (決済などリクエストが多いのが仕様の画面がある)、
  それを「悪い IP」とみなすと、正規の利用者に当たっている COUNT ルールを「怪しい通信ばかり」と見せてしまう (危ない方向に間違える)。sandbox で、/login のレート制限で止まった 1 IP のせいで
  COUNT の一致が 100% suspect になって判明した。count_rule_status の evidence に `suspect_blocked_ip_excludes` (除いた BLOCK) を残す
- 決定 (1 IP あたりの件数): `stats count(*) as n by bin(5m), acl, grp, ip | stats pct(n, 50), pct(n, 99), max(n) by acl, grp` を UTC の 1 日ずつ流す (2 段目で日を切る書き方に頼らない。
  1 日ずつでもスキャン量は同じ)。2 段の stats と pct は sandbox で確認済み
- 決定: `checks.waf_review.trusted_cidrs` (監視・開発会社など) は `isIpInSubnet` で `waf_rule_action` 以外の新しい集計から外す (`waf_rule_action` は「使われていないルール」の判定に使うので外さない)。
  `top_paths` / `rate_path_groups` / `trusted_cidrs` は集計条件なので overrides では変えられない
- 決定 (`strip_path_prefix`): API Gateway の REST API では `httpRequest.uri` の前にステージ名が付く (`/prod/login`。sandbox で確認。ALB・CloudFront では付かない)。
  wafv2 ソースの `strip_path_prefix` (`/` で始まり `/` で終わらない) を、探索パス・パスの群の判定では必須の接頭辞として正規表現の前に付け、正規化の前に外す (`/prod` は `/prod/x` と `/prod` だけを外し、`/products` は外さない)。集計条件
- 費用: wafv2 ソースのクエリは lines + `waf_block_ip` + 5 本 + レート (日数分)。既存の `max_scan_gb` がそのまま効く (超えたら QUERY_LIMIT で、その日の集計は欠ける)。
  sandbox の 1 時間・約 300 リクエストのログで 1 本 0.3〜0.5 MB

### 2-1. 形式プロファイルの種類 (JSON ログと非 JSON ログ)

アプリの言語・フレームワークで形式は変わるので、プロファイルは「組み込み」と「汎用」の 2 系統にする。

| プロファイル | 対象 | 指定 |
|---|---|---|
| `nginx_access`, `alb_access`, `wafv2`, `cloudtrail` | 形式が固定のもの | 名前だけ |
| `json` | lograge (Rails)、zap/slog (Go)、pino/winston (Node) など JSON 行ログ | どの JSON フィールドが ip / path / status / user_id に当たるかの対応表 |
| `regex` | 非 JSON の素のアプリログ | 名前付きキャプチャ付き正規表現 |

```yaml
  - id: rails_app
    kind: cloudwatch-logs
    log_group: prod-app.log
    format: json
    yields: http_access              # このソースが出す正規化レコード
    fields: { ip: remote_ip, method: method, path: path, status: status, user_id: user_id, time: "@timestamp" }
    expected_match_rate: 0.6         # 混在ストリームなど、全行が該当しないことが分かっている場合は下げる
```

`json` は Logs Insights が JSON を自動でフィールド化するので、エンジン側は対応表を使ってクエリを組むだけで済む。
`regex` は Insights の `parse` に変換する。Insights の正規表現方言に合わない表現は `doctor` で検出する。

### 2-2. 形式の検証とエラー出力

形式が合っていないことを**実行のたびに**検出し、エラーとして外に出す。

- **解釈率の計測**: 各ソースのクエリに `count(*) as total, count(<必須フィールド>) as matched` を必ず含め、`matched / total` を解釈率として記録する (`runs.stats` と `report.json` の `coverage`)。
- **閾値判定**: 解釈率が `expected_match_rate` (既定 0.8) を下回ったら `FORMAT_MISMATCH`。そのソースを必要とするチェックは skip し、終了コード 3。
- **ドリフト判定**: 閾値を上回っていても、直近 7 回の平均から 20 ポイント以上落ちたら `FORMAT_DRIFT` (警告)。アプリのデプロイでログ形式が変わった時に気づくため。
- **サンプルの扱い**: 解釈できなかった行の例を最大 3 行、長さ 200 文字に切り、メールアドレスらしき文字列をマスクしてエラーに添える (原因特定用)。個人情報を含み得るログでは `sample_lines: false` で抑止できる。
- **エンジン自身のログ**: 標準エラーに JSON 行で出し、`code` を固定語彙にする。組み込み側はこの `code` を監視して通知すればよい。

```json
{"level":"error","code":"FORMAT_MISMATCH","source":"rails_app","log_group":"prod-app.log","format":"json","match_rate":0.12,"expected":0.6,"samples":["..."],"run_id":"..."}
```

| code | 意味 |
|---|---|
| `FORMAT_MISMATCH` | 解釈率が閾値未満 |
| `FORMAT_DRIFT` | 解釈率が急落 |
| `LOG_GROUP_MISSING` | ロググループが無い / 名前変更 |
| `ACCESS_DENIED` | IAM 権限不足 (不足した action を含む) |
| `QUERY_LIMIT` | Insights のスキャン上限・同時実行上限に当たった |
| `QUERY_INVALID` | クエリ / 設定の不備 (Insights の構文エラー、不正な時間範囲など)。決定: 上限 (`QUERY_LIMIT`) とは区別する |
| `STORE_LOCKED` / `STORE_CORRUPT` | ストアの排他失敗 / SQLite 破損 (rebuild を促す) |
| `RUN_MISSED` | 前回実行から profile の周期の 2 倍以上空いた (起動側の障害) |
| `COLLECT_FAILED` | 決定: 上記に分類できない収集エラー (ネットワーク断など) |
| `CONFIG_INVALID` | 決定: 設定ファイルの読み込み・検証エラー (終了コード 2) |
| `CHECK_UNUSED` | 決定: どのプロファイルにも入っていないチェックがある (警告。run / evaluate / doctor が出す。3 章、ADR 0014) |

`doctor` は同じ検査を実行前に行い、全ソースの解釈率を表で出す。

決定 (解釈率と形式エラーの扱い):
- 解釈率は `stats count(*) as lines_total, count(<判定フィールド>) as lines_matched by bin(1d)` で測る。判定フィールドは `http_access` が `path`、`waf_action` が `action`。
- 解釈率を**先に**測り、`FORMAT_MISMATCH` なら集計クエリを流さず metrics も保存しない (誤った集計で平常帯を汚さず、スキャン費用も抑える)。そのソースは失敗扱い (`coverage.sources_failed`、終了コード 3)。
- 窓内に 1 行も無いときは解釈率を判定せず (`match_rate: null`)、WARN ログ (code なし) を出す。ロググループや `stream_prefix` の誤りの手がかり。
- `FORMAT_DRIFT` の平均は、このソースの解釈率を記録した直近 7 回の run (`runs.stats.match_rates`) から取る。過去の計測が 3 回未満なら判定しない。警告のみで終了コードは変えない。
- サンプル行は標準エラーの `FORMAT_MISMATCH` ログにだけ添え、report.json / report.md には出さない (マスク済みでも氏名などは検出できないため)。マスクはメールアドレス (URL エンコード形を含む) を `<email>` に置き換えてから 200 文字に切る。metrics の key (パスなど) にも同じマスクをかける。
- Insights の方言の注意 (本番の doctor で確認): 前処理 (`parse` / `fields ... as`) で定義したフィールドを後段の `fields` で列挙し直すと
  `Ephemeral field is already defined` で拒否される。doctor のサンプルは判定フィールドを列挙せず `ispresent(<判定フィールド>) as arata_matched` で返し、
  `json` の対応表で元と正規化名が同じ (`path: path`) ときは別名を付けない。doctor の `queries` 検査は集計クエリに加えてサンプル用と doctor 自身のクエリも対象にする。
- report.json の `coverage.formats` に各 cloudwatch-logs ソースの `total` / `matched` / `match_rate` / `expected` / `recent_average` / `bytes_scanned` / `code` を必ず出す。

## 3. 周期と「重視するデータ」 (複数周期の整理)

複数の周期を持つ、という感覚は同じ。ただし **収集の周期・評価の周期・レポートの周期は別物**として扱う。

| 周期 | 役割 | 重視するデータ | 収集 | 評価 |
|---|---|---|---|---|
| hourly (即時に近い) | 発生そのものが異常な事象の早期検知 | CloudTrail の少数イベント (ルート利用、証跡停止、既知外主体の AssumeRole、秘匿値取得)、GuardDuty High | CloudTrail LookupEvents 1h 分 (安い)、GuardDuty findings | event 型チェックのみ |
| daily | 前兆・試行の発見、平常帯との比較 | IAM 変更、ログイン失敗、探索パス、WAF BLOCK、新規主体 / IP、GuardDuty Medium 以下 | Logs Insights 集計 24h 分、CloudTrail 24h 分 | event 型 + 平常帯比較型 |
| weekly | 設定不備・衛生状態の差分 | 認証情報レポート、Access Analyzer、SG / 公開設定、姿勢チェック、未対応一覧 | IAM / describe 系 | 状態差分型 |
| monthly / quarterly / 任意期間 | 傾向と棚卸し。顧客向け報告 | 期間内の findings 集計、新規主体一覧、日次メトリクスの推移、解消した指摘、既知リストの削除候補 | **収集しない** (ストアから集計) | 集計のみ |

設計上の帰結:

- **チェックは周期を宣言する** (`Cadence: hourly|daily|weekly`)。周期ごとの有効チェックは設定の `profiles` で上書きできる。
- **「新規」の状態はチェック単位で持ち、周期ごとには持たない**。hourly で報告済みの事象は daily では「本日報告済み」欄に回り、二重に鳴らない。
- **収集は必要な最小の粒度で行い、ストアに貯める**。daily のメトリクスが貯まっていれば、monthly はストアだけで作れる。
- hourly は Lambda / cron どちらでも動くが、Logs Insights を hourly で回すのは費用が無駄なので、hourly プロファイルには Insights を使うチェックを入れない。

決定 (実行が遅れた時の窓): `run` の窓は通常 `[now - window, now)` だが、同じ profile の直近の ok / partial な run があれば
From = min(now - window, 前回の window_to) として、cron の遅延・欠落で空いた期間を取りこぼさない。追いつきは `profiles.<name>.max_catchup` (既定 7d) まで。
超えた分は諦めて From = now - max_catchup とし、`RUN_MISSED` のログに `gap` と `covered_from`、`truncated: true` を添える。
失敗した run (status=failed) は前回として数えない。前回から周期の 2 倍以上空いた場合も `RUN_MISSED` を警告する (追いつけた場合は `truncated: false`)。
`init` のベースライン収集の窓は `init --window` (既定 7d)。

決定 (記録の遅延と再走査。ADR 0013): CloudTrail はイベントの記録まで通常 5〜15 分、CloudWatch Logs は取り込みに数分遅れる。
窓の終わり To は now のまま記録し (次回の From になる)、**各ソースの収集範囲は `[From - ingest_delay, To)`** とする (前回の窓の末尾を遅延分だけ再走査する)。
`sources[].ingest_delay` は ParseDuration 形式で、既定は cloudtrail-lookup = 15m、cloudwatch-logs = 5m (`0` で再走査しない)。

- events は event_id で重複を排除し、最初に収集した run の時刻を `collected_at` に残す (再走査で同じイベントが来ても変わらない)。
- イベント型チェック (root_usage / unknown_assume_role / iam_changes) は `[From, To)` に加えて、`[From - 最大の ingest_delay, From)` のうち
  **今回の収集で初めて保存したもの** (遅れて届いたもの) を評価する。重なり区間の収集済みイベントは前回評価済みなので含めない
  (件数の水増しと、resolve 済みの事象の再報告を防ぐ)。
- recurred の境界は再走査を含まない本来の From (4-2)。前回の run で観測した事象が再走査で recurred になることは無い。
- principal_seen の件数 (`principal_ips.count`) は `[From, To)` の分だけを足す。重なり区間の件数は (arn, ip) の行を初めて作るときだけ足す
  (前回まで一度も数えていないことが確かなため)。主体の初出・最終観測 (principals) と新規主体の判定には重なり区間も使う。
- metrics (日次集計) は日の頭から引き直して置き換えるので、再走査が日をまたぐと前日分も丸 1 日で置き換わる。アプリ層チェックの評価は日単位なので窓は広げない。
- `init` のチャンクは取り込み済みの過去の日を続けて引くので再走査しない。窓の終わり (init の実行時刻) 側の遅れたイベントは、次の run の再走査が拾う
  (ベースラインではなく unknown として入るので、init 直前の主体が new_principal になることがある)。`collect` も再走査しない。
- 代替案の「To を now - ingest_delay にずらす」は採らない (hourly の検知が常に遅延分遅れる。ADR 0013)。

決定 (init の分割と再開。ADR 0011): init の窓は UTC の日の境界で区切り、古い順に 1 日ずつ収集する。1 日終わるごとに `runs` (profile=init) の `stats` に
`chunks_done` / `chunks_total` / `done_until` を書く。どれかのソースが失敗した日、または中断 (SIGINT / SIGTERM) で止まり (status=partial、終了コード 3)、
`init --resume` は `done_until` (失敗した日の頭) から再開時点までを引く。完了した init に `--resume` しても何もしない。未完了の init があるのに `--resume` なしで init すると、警告して最初からやり直す。

決定 (プロファイルと収集するソース): `run` はプロファイルのチェックが必要とするレコードを出すソースだけを引く。hourly に `http_access` / `waf_action` を使うチェックを入れなければ Logs Insights は回らない。
`init` と `collect` は全ソースを引く。

決定 (日次集計の日): 日次集計 (metrics) の日は **UTC** の日 (`bin(1d)` が UTC で切るため)。report.md では日付に `(UTC)` を付ける。
集計クエリは窓に重なる UTC 日の 0 時から窓の終わりまでを引き、同じ日の値は置き換える (5-2)。例えば daily を 07:00 JST (22:00 UTC) に回すと、
窓は前日 22:00 〜 当日 22:00 UTC だが、問い合わせは前日 0:00 UTC からになり、前日分は丸 1 日の値で置き換わる。当日分は途中までの値で、翌日の run が丸 1 日分で置き換える。

```yaml
profiles:
  hourly: { window: 1h,  checks: [root_usage, trail_tampering, unknown_assume_role, secret_access_unknown, guardduty_high] }
  daily:  { window: 24h, checks: [default-daily] }            # Cadence=daily のチェック全部
  weekly: { window: 7d,  checks: [default-weekly] }
```

決定 (既定は雛形として書き出す。ADR 0014):
- エンジンは実行時に暗黙の既定のプロファイルを持たない。`profiles` は必須で、**実行されるのは設定に書いたチェックだけ**。
  推奨の設定は `arata config init [--out PATH] [--force]` が雛形として書き出す。雛形は全プロファイル (hourly / daily / weekly。その周期のチェックが無い版ではコメントで示す)・
  全チェック・各チェックの既定パラメータをすべてコメント付きで明示し、`default-*` の省略記法は使わない。sources は cloudtrail-lookup を有効にし、cloudwatch-logs はコメントの例で示す。
  daily には hourly のチェックも入れる (hourly を回さない運用でも拾える。両方回しても hourly で報告済みの事象は already_reported に回る)。
- 雛形のチェック一覧は Registry、パラメータの既定値は `config.DefaultChecks()`、保持期間は `config.DefaultRetention` から生成する (手書きの一覧とずれない)。
  雛形の出力はゴールデンで固定し、「雛形をそのまま Load して Validate が通る」「雛形の checks: が DefaultChecks と一致する」「全チェックがどれかのプロファイルに入る」をテストで保証する。
- `default-<cadence>` の省略記法は手書きの設定のために残す (後方互換)。ただし版が上がって増えたチェックが黙って入るので、雛形では使わない。
- `arata config init --diff` は現在の設定と最新の雛形の差分を出す: どのプロファイルにも入っていないチェック (`unused_check`)、
  プロファイルに書かれているがこの版に無いチェック (`unknown_check`)、雛形にあって設定に無いプロファイル (`missing_profile`)、
  `checks:` に書いた値がこの版の既定値と違うパラメータ (`param_changed`)、arata が知らないキー (`unknown_key`)。設定は Load せずに緩く読む (未知のキーで読めない設定にも使える)。
  `checks:` に書いていないパラメータは実行時にこの版の既定値が効くので差分にしない。overrides は意図した上書きなので比べない。
- `arata profiles [--format table|json]` は、プロファイルごとに実際に走るチェック (省略記法は展開済み、`via` に explicit / default-<cadence>) と、
  そのチェックのパラメータの値と由来 (`overrides` / `checks:` / 既定値) を出す。どのプロファイルにも入っていないチェックも示す。
- どのプロファイルにも入っていないチェックがあれば、`run` / `evaluate` は標準エラーに WARN (`code: CHECK_UNUSED`、`checks` に名前) を出し、`doctor` は表に warn 行を出す。終了コードは変えない。
- プロファイル内でチェックのパラメータを上書きできる (`profiles.<name>.overrides.<check>: {...}`)。書かなければ全体の `checks:` の値。
  **上書きできるのは判定のパラメータだけ** (baseline_days / factor / min_count / min_baseline_days / top_ip_min_count / top_n / new_rule_min_count)。
  集計条件 (paths / methods / failure_statuses / statuses / exclude_paths) は Logs Insights の集計クエリに使われ、metrics は (date, source, metric, key) で
  全プロファイル共有・置き換え保存なので、プロファイルごとに変えると交互に別条件の値で上書きして平常帯が壊れる。overrides に書いたら CONFIG_INVALID (「checks: で変える」と案内)。

## 4. 全体構成

```
arata run --profile daily
  ├ collect   : sources ごとに AWS から取得 → 正規化レコード / 集計 → JSONL 追記 + SQLite 反映
  ├ evaluate  : checks を走らせ observations を作り、findings テーブルと突合 → new / changed / resolved / still_open
  ├ report    : report.json + report.md を出力 (stdout または --out)
  └ prune     : retention に従い削除
```

### 4-1. Go パッケージ構成

```
cmd/arata/                 CLI (標準の flag の上の小さなコマンド層 internal/subcmd。ADR 0019。決定: aratam と共有するため internal/ に移した)
cmd/aratam/                LLM 要約と通知 (arata の出力だけを読む別コマンド。docs/aratam.md、ADR 0018)
cmd/arata-lambda/          Lambda ハンドラ (同じ internal を呼ぶ。runtime provided.al2023, arm64)
internal/config/              YAML 読み込み・検証・既定値
internal/scaffold/            設定の雛形 (config init) と雛形との差分 (決定: config と checks の両方を使うので別パッケージ)
internal/store/               Store インターフェース、sqlite 実装、jsonl 書き出し、backend (dir / s3)
internal/collect/             Collector インターフェース
    cloudtrail/               LookupEvents / CloudWatch Logs 配信版
    cwlogs/                   Logs Insights 実行、形式プロファイル (クエリテンプレート)
    guardduty/ iam/ accessanalyzer/ posture/ (ec2 SG, s3 public, rds public, cloudtrail status ...)
                              決定: Step 3 では 4 つを account/ にまとめた (同じ形の小さな collector で SDK クライアントの束を共有する。ADR 0015)
internal/record/              正規化レコード型 (http_access, waf_action, trail_event, principal_seen, metric, posture_item)
internal/checks/              Check インターフェースと各チェック (1 ファイル 1 チェック)
internal/allowlist/           既知リストの読み書き (approve / expire)
internal/report/              JSON / Markdown 生成、期間集計 (period.go)。決定: report.json の型は標準ライブラリだけに依存する report/schema に置く (aratam と共有。ADR 0018)
tools/agegate/                CI 用の依存の age-gate (エンジンには入らない小さな main。決定: internal/ ではなく tools/ に置く。ADR 0017)
docs/ai/*.md                  LLM 向けの使い方。embed でバイナリに入り `arata help ai [report|approve]` で出る (決定: skills/ の同梱は取りやめ。ADR 0012)
deploy/iam/readonly-role.yaml 顧客に配る読み取りロール + Roles Anywhere 用信頼ポリシーの CloudFormation (決定: 信頼先は AWS の主体と Roles Anywhere のトラストアンカーをパラメータで受ける。action は collector の一覧と Go のテストで一致させる。ADR 0020)
deploy/sandbox/               試験環境 (sandbox = arata の試験用に条件を整えた開発用アカウント上の環境) の CDK (TypeScript)。Go モジュールとは独立。readonly-role.yaml を CfnInclude で取り込む (ADR 0020)
deploy/lambda/                Lambda 配備用 CDK or SAM テンプレート (S3 ストア、別アカウント推奨)
```

### 4-2. 主要インターフェース

```go
type Collector interface {
    ID() string
    Collect(ctx context.Context, w Window, sink RecordSink) error
}

type Check interface {
    Name() string
    Cadence() Cadence                // hourly / daily / weekly
    Mode() Mode                      // event / state (決定: 下記)
    Needs() []record.Kind            // 必要な正規化レコード
    Evaluate(ctx context.Context, q store.Query, w Window, al *allowlist.List) ([]Observation, error)
}

type Observation struct {
    Check       string
    Key         string            // 同一事象の識別子 (例: principalARN, ip, findingID, "sg-xxxx/0.0.0.0/0")
    Severity    Severity          // critical / high / medium / low / info
    Summary     string
    Fingerprint string            // changed 判定に使う安定した要素 (決定: 下記)
    Data        map[string]any    // 根拠 (件数、時刻、ARN など。個人特定値は入れない)
}
```

差分判定はエンジン共通部で行う。`(Check, Key)` で findings テーブルを引き、無ければ **new**、あって Data が変わっていれば **changed**、
前回あって今回無ければ **resolved**、同じなら **still_open**。チェック側は「今の観測」を返すだけで、履歴を意識しない。

決定 (差分判定の詳細):
- `Mode()` を追加。`event` (root_usage / iam_changes / unknown_assume_role など、窓内の事象を報告するもの) と `state` (new_principal / posture / credential_hygiene など、現在の状態を報告するもの)。
- `Fingerprint` が空でなければ changed 判定は Fingerprint の比較のみ (空なら Data 全体を比較)。イベント型は重大度 + 送信元 IP 集合 (+ 対象) のような安定した要素だけを Fingerprint に入れ、count / first_time / last_time は Data に残す。
- `event` の finding は窓内に観測されなくても resolved にせず open のまま沈黙する (レポートの still_open にも出さない)。前回の窓より前が last_seen の finding が再観測されたら **recurred** として報告し Data を更新する。`state` は従来どおり未観測で resolved。
- resolved だった finding が再観測されたら new。acked は再報告しない。snoozed は期日を過ぎた再観測で new として再報告する。
- 判定に使う時刻は実行時刻 (now)。finding の `first_seen` / `last_changed` もこれで記録する。
- recurred の境界は `last_seen < 今回の窓の From` (last_seen は前回観測した run の実行時刻)。前回の窓と今回の窓が連続していれば still_open、途切れていれば recurred。
  From は再走査 (3 章、ADR 0013) を含まない本来の From。

## 5. ストア設計

### 5-1. 二層構造

- `raw/<source>/<YYYY-MM-DD>.jsonl` — collect が取得した正規化レコード・集計の原本。追記のみ。人が読め、S3 へそのまま退避できる。
- `audit.sqlite` — raw から再構築可能な派生物。差分判定と期間集計のためのインデックス。`arata rebuild` で raw から作り直せる。
- `allowlist.yaml` — 人が承認した既知リスト。**git 管理**。エンジンは読むだけ (approve コマンドは書く)。

バックエンドは 2 種類。`dir:///var/lib/arata/<name>` (オンプレ) と `s3://bucket/prefix` (Lambda。実行開始時に取得、終了時に書き戻し、
S3 の条件付き書き込みでロック)。SQLite ファイルは数十 MB 程度に収まる想定 (集計のみ保存するため)。

### 5-2. テーブル

| テーブル | 主なカラム | 用途 |
|---|---|---|
| `runs` | id, profile, window_from, window_to, started_at, status, stats | 実行履歴。欠損 (走らなかった日) の検出にも使う |
| `principals` | arn, kind (user/role/assumed-role/root), first_seen, last_seen, status (unknown/approved/expired/baseline) | 主体の初出判定。決定: `init` のベースライン収集で初出した主体は `baseline` とし new_principal の対象外。evaluate 時に allowlist から approved / expired を同期する |
| `principal_ips` | arn, ip, country, first_seen, last_seen, count | 主体 × IP の初出判定。決定: count は各 run の窓 [From, To) の件数の和 (再走査の重なり区間は行を初めて作るときだけ数える。3 章) |
| `events` | time, source, name, principal_arn, ip, region, resource, data | 「注目イベント」のみ (ルート利用、IAM 変更など)。全 CloudTrail は保存しない。決定: 注目の判定は collector 側 (`cloudtrail.DefaultNotable`) で行い、ルート利用・AssumeRole*・IAM / CloudTrail / GuardDuty / Organizations の書き込み・秘匿値取得・SSM セッション・公開設定変更を残す。決定: 拒否された呼び出し (errorCode が `checks.access_denied.error_codes` に入るもの) も読み取りを含めて残す (access_denied の元。コードは設定から `cloudtrail.NotableWith` に渡す。ADR 0021)。`event_id` で重複を排除する (複数リージョンを引いた場合の二重も同じ仕組みで防ぐ。collector 側でも同一 Collect 内の event_id は 1 回だけ数える)。決定: `collected_at` (最初に収集した run の時刻) を持ち、再走査で遅れて届いたイベントを見分ける (3 章、ADR 0013) |
| `metrics` | date, source, metric, key, value | 日次集計 (`sign_in_failures` by ip、`admin_404` by ip、`waf_block` by rule)。平常帯の計算元。決定: 集計元のレコード種類 `from` 列を追加。主キーは (date, source, metric, key) で、後から来た値で**置き換える** (3 章の決定により後の値ほど完全)。raw JSONL には追記されるので rebuild は行順に適用すれば同じ結果になる。日は UTC |
| `findings` | id, check, key, severity, first_seen, last_seen, last_changed, status (open/resolved/acked/snoozed), reported_at, fingerprint, data | 差分判定の中核。決定: `fingerprint` 列を追加 (4-2) |
| `posture` | check, resource, value, first_seen, last_changed | 姿勢チェックの現在値。決定: 作らず `snapshot_items` にまとめた (ADR 0015) |
| `snapshot_items` | kind, source, key, data, collected_at | 決定: アカウント単位の状態 (認証情報レポート・GuardDuty・Access Analyzer・姿勢・WAF の WebACL の設定) の最新のスナップショット。収集が成功したときだけ (kind, source) 単位で丸ごと置き換える (ADR 0015) |
| `finding_events` | finding_id, check, key, class, severity, summary, at, run_id, profile, data | 決定: finding の状態遷移 (new / changed / recurred / resolved) の履歴。run の差分判定、人の resolve / approve、allowlist の編集による解消で追記する。期間レポートの元 (ADR 0016) |
| `meta` | key, value | 決定: `history_since` (schema 4 以降の最初の run の開始時刻。これより前の状態遷移は残っていない) |

### 5-3. 保持期間 (自動削除)

```yaml
retention:
  raw_jsonl: 365d      # 原本
  events:    90d
  metrics:   400d      # 前年同月比較のため 13 か月
  findings:  resolved から 180d
  runs:      400d
```

`prune` は `run` の最後に自動で走り、`arata prune --dry-run` で対象を確認できる。

## 6. 既知リスト (allowlist) と承認フロー (質問 8 への回答)

### 6-1. ファイル形式

```yaml
# allowlist.yaml (git 管理、顧客ごと)
principals:
  - arn: arn:aws:iam::123456789012:role/partner_developers_switch_role
    note: パートナー開発者の switch role。引き受け元ユーザーの増加は別途検知
    approved_by: alice
    approved_at: 2026-10-21
    tags: [deploy]               # 決定: 任意のタグ。deploy を持つ主体の IAM 変更は info に下げる (7 章 iam_changes)
  - arn: arn:aws:iam::123456789012:user/contractor-x
    approved_at: 2026-10-21
    expires: 2026-12-31          # 期限付き承認。過ぎたら expired として再報告
source_ips:
  - cidr: 203.0.113.0/24
    note: 本社オフィス
admin_users: [113, 2048]         # アプリ層の管理者 ID
secrets_access:
  - principal: arn:aws:iam::...:role/ProdEcsTaskRoleMyApp
    secrets: ["prod/db/*"]
```

決定: `allowlist.yaml` が無い場合は空のリストとして扱う (init 直後の運用を許す)。主体 ARN の突合は完全一致。AssumedRole 主体はセッション ARN ではなくロール ARN (`sessionContext.sessionIssuer.arn`) に正規化してから突合する (セッション名に個人名やメールが入るため)。

決定 (principals の指定方法。Step 2):
- 1 エントリの主体の指定は `arn` (完全一致) / `account` (12 桁の文字列。そのアカウントの全主体を承認。監視 SaaS など SaaS 連携用) / `arn_pattern` (glob。`*` は `/` や `:` も含む任意の文字列、`?` は 1 文字) のどれか 1 つ。
- 複数のエントリに一致するときは、有効な (expires 前の) 承認が 1 つでもあれば approved。返すエントリ (タグの判定に使う) は有効なもののうち最も具体的なもの (arn > arn_pattern > account)。一致したものが全部期限切れなら expired。
- CloudTrail の `userIdentity.type` が `AWSAccount` (他アカウントからのクロスアカウント AssumeRole) の主体は `arn:aws:iam::<アカウント>:root` (kind は unknown) に正規化される。
  レポートの文面ではこれを「外部アカウント NNN」と書き、Data に `external_account` を添える。自アカウントの Root (kind=root、root_usage が扱う) とは区別する。
- `tags` の語彙は `deploy` (ADR 0008) と `ai` (決定: Step 3。監査ロール・AI 用の主体。ai_path_usage が利用を毎回 info に出す)。approve は語彙外のタグを拒否する。

### 6-2. 状態遷移

```
観測 ──(allowlist に無い)──> finding: open (new として報告)
   │
   ├─ arata approve <finding-id> --note "..." [--expires 2026-12-31]
   │     → allowlist.yaml に追記 (approved_by は OS ユーザーか --by)、finding は resolved
   │     → 追記後の allowlist で対象主体が承認済みになる他の finding (new_principal / unknown_assume_role) も resolved
   │     → git への commit は人が行う (--commit で代行も可)
   ├─ arata ack <finding-id>         → acked。再報告しないが週次の未対応一覧には残る
   ├─ arata snooze <finding-id> --until 2026-11-01   → 期日まで沈黙、期日に再報告
   ├─ arata resolve <finding-id>     → resolved。再び観測されたら new
   └─ 放置                              → still_open。週次の未対応一覧に残り続ける

allowlist.yaml を人が直接編集して承認 ──> 次の evaluate の冒頭で該当 finding を resolved (reason: allowlisted)
expires 到来 ──> その主体の次回観測は new (expired) として再報告
90 日間観測の無い approved 主体 ──> 四半期レポートで「削除候補」
```

`arata review` は open / acked の一覧を対話なしで表示する (組み込み側の LLM が「承認してよいか」を人に聞く材料)。
approve は allowlist を書き換えるので、組み込み側ではなく人 (または人の承認を得た LLM) が実行する前提。

決定 (承認フローの実装。Step 2):
- `approve` の対象: new_principal は Key の主体、unknown_assume_role は呼び出し元、iam_changes は変更した主体 (`--tag deploy` で既知デプロイ主体にする用途)。
  主体が外部アカウントの root なら `account:` で承認する。`--account` で主体のアカウント全体、`--arn-pattern` で glob を承認できる (パターンが主体に一致するときだけ)。
  それ以外のチェック (root_usage やアプリ層) は主体の承認ではないので approve できず、ack / snooze / resolve を使う。ルートユーザーは承認できない。
- `--note` は必須。`approved_by` は `--by`、省略時は OS のユーザー名。`approved_at` は今日 (UTC)。`--expires` は過去日を拒否する。
- allowlist.yaml への書き込みは、元のテキストを保ったまま principals の末尾に行を差し込む (ADR 0010)。同じ対象のエントリが既にあれば拒否する (期限の延長などは人が直接編集する)。
- `--commit` は allowlist.yaml だけをパス指定で commit する (stage 済みの他の変更を巻き込まない)。allowlist.yaml が git の作業ツリーに無ければ、書き込む前に失敗する。push は人が行う。
- 承認による一括解消: approve の直後と evaluate の冒頭で、open / acked / snoozed の new_principal / unknown_assume_role のうち対象主体 (主体 / 呼び出し元) が
  allowlist で承認済みのものを resolved にし、Data に `resolved_reason: allowlisted` と `allowlist_subject` を残す。evaluate で解消したものはレポートの `resolved` に出る。
  unknown_assume_role は event 型で、観測されなくても resolved にならないため、これが無いと承認後も未対応一覧に残り続ける。
  iam_changes は対象外 (承認済みでも deploy タグの無い主体の IAM 変更は報告するチェックなので、承認を理由に解消すると次の観測で new に戻る)。approve した 1 件だけを resolved にする。
- `snooze --until YYYY-MM-DD` はその日の 0 時 (UTC) まで沈黙し、以後の再観測で new として再報告する。`resolve` / `ack` / `snooze` は resolved の finding には使えない。
- `review` は既定で open / acked を重大度の高い順 → 初出の古い順に出す。`--status` で snoozed / resolved も出せる。approve できるものは対象 (`approve`) を示す。`--format table|json`。

## 7. チェック一覧 (初期セット)

| チェック | 周期 | 必要レコード | 判定 | 重大度 |
|---|---|---|---|---|
| root_usage | hourly | trail_event | Root の利用 | critical |
| trail_tampering | hourly | trail_event | StopLogging / DeleteTrail / UpdateTrail / DeleteDetector / 監査ロールの変更 | critical |
| unknown_assume_role | hourly | trail_event | 呼び出し元 ARN が allowlist に無い AssumeRole。決定: AWS サービス主体 (EC2 / Lambda がインスタンスロールを引き受けるもの) は対象外 | high |
| secret_access_unknown | hourly | trail_event | 主体 × シークレットの組が allowlist に無い GetSecretValue / GetParameter(decrypt) | high |
| guardduty_findings | hourly (High) / daily (他)。決定: Step 3 は weekly のみ (state) | guardduty | finding ID 初出、count 増加 | severity 準拠 |
| iam_changes | daily | trail_event | CreateAccessKey / CreateUser / Attach*Policy / Put*Policy / UpdateAssumeRolePolicy / CreateLoginProfile | medium (既知デプロイ主体なら info。決定: 既知デプロイ主体 = allowlist の principals で `tags: [deploy]` を持つもの) |
| access_denied | daily | trail_event | 拒否された API 呼び出しの主体ごとの種類 (幅) と件数 (量) が平常帯超え。権限の列挙の兆候。決定: ADR 0021 | 幅は medium (種類が多ければ high)、量は medium |
| console_login | daily | trail_event | 失敗が閾値超え、MFA 無し成功 | medium / high |
| new_principal | daily | principal_seen | allowlist にも principals にも無い主体。決定: principals.status が unknown / expired の主体を毎回観測する (承認されるまで still_open として残る)。root は root_usage が扱うので対象外 | medium |
| new_source_ip | daily | principal_seen | 主体 × IP (国) の初出 | low (国外なら medium) |
| foreign_region | daily | trail_event | ap-northeast-1 以外のイベント | medium |
| network_exposure | daily | trail_event | SG 0.0.0.0/0 開放、RDS PubliclyAccessible | high |
| ssm_session | daily | trail_event | StartSession の主体が allowlist 外、または深夜帯 | medium |
| login_bruteforce | daily | http_access | sign-in 失敗の IP 別件数が平常帯 (14 日中央値 × 係数) 超え、Top IP 初出 | medium |
| probe_paths | daily | http_access | 機密パス探索の 403/404 が平常帯超え | low |
| request_burst | daily | http_access | IP 別件数が平常帯超え (決済画面など除外パスを設定可) | low |
| waf_block_trend | daily | waf_action | 新規に鳴り始めたルール、Top IP 入れ替わり | low |
| admin_ops_unknown | daily | regex (admin) | 実行ユーザーが admin_users に無い | high |
| ai_path_usage | daily | principal_seen (決定: trail_event ではなく主体 × IP の観測を使う) | allowlist の `tags: [ai]` を持つ主体の利用を主体 × IP で常に 1 行 (info) | info |
| credential_hygiene | weekly | iam_credential_report | 未使用キー 90 日超、MFA 無し、ルートのアクセスキー の増減 (決定: 古いパスワードは後続) | medium (ルートのキーは high) |
| access_analyzer | weekly | access_analyzer | ACTIVE な finding の増減 | medium (公開は high) |
| posture (決定: posture_* ではなく 1 チェックで項目ごとに finding) | weekly | posture_item | CloudTrail 有効・検証 ON、GuardDuty 有効、ルート MFA、S3 Public Access Block、パスワードポリシー | high (検証とパスワードポリシーは medium) |
| waf_review | weekly | waf_config (+ 保存済みの waf_action の日次集計) | WAF の修正提案の候補を report.json の `proposals` に (finding ではない)。決定: ADR 0023 | 正規の画面での多数の IP の BLOCK だけ low |
| allowlist_stale | quarterly (report) | principals | 90 日未観測の approved 主体 | info |

決定 (Step 1 の 4 チェックの Mode と Fingerprint。ADR 0005):

| チェック | Mode | Key | Fingerprint |
|---|---|---|---|
| root_usage | event | `<root ARN>\|<ip>` | 重大度 + IP 集合 + MFA の有無 |
| unknown_assume_role | event | `<caller ARN>-><role ARN>` | 重大度 + IP 集合 + allowlist 状態 (unknown / expired) |
| iam_changes | event | `<event name>\|<caller ARN>\|<対象>` | 重大度 + IP 集合 + 対象 + policy ARN (全件拒否のときは denied) |
| new_principal | state | `<ARN>` | 重大度 + IP 集合 + 種類 + allowlist 状態 |

決定: iam_changes は集約した呼び出しがすべてエラー (ErrorCode あり) のとき、変更は起きていないので見出しを「IAM 変更の試行 (拒否)」とし、Data に `denied: true` と `error_codes` を残す (重大度と Key は変えない。権限の無い主体が IAM を変えようとしたこと自体が指摘になるため)。成功が混ざるときは「IAM 変更」のまま `has_errors: true`。対象が取れないとき (拒否では requestParameters が記録されない) は表示を「不明」とする。Fingerprint は全件拒否のときだけ `denied` を足す (既存の finding の指紋は変わらない)。

決定 (アプリ層チェック。Step 2 の 3 つ。ADR 0005 の event 型):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| login_bruteforce | event | `<ip>` | 重大度 + 理由 (`above_baseline` / `new_top_ip`) | `sign_in_failures` の日次値が「その IP 自身の直近 14 日の中央値 × factor (既定 3)、ただし min_count (既定 20) 以上」を超えた。または閾値未満でもその日の最多 IP が過去 14 日に一度も無く、top_ip_min_count (既定 5) 件以上 |
| probe_paths | event | `<ip>` | 重大度 + 理由 | `probe_hits` について同上 (min_count 既定 10)。Data にその日の多かったパス (全 IP 合計の上位 5) を添える |
| waf_block_trend | event | `rule\|<ルール ID>` / `top_ip\|<IP>` | 重大度 + 理由 (`new_rule` / `new_top_ip`) | 過去 14 日に BLOCK の無いルールが new_rule_min_count (既定 1) 件以上 BLOCK した / その日の BLOCK 件数 Top N (既定 5、min_count 10 以上) に過去 14 日合計の Top N に居ない IP が入った |

決定 (access_denied。ADR 0021):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| access_denied | event | `<主体 ARN>` | 重大度 + IP 集合 | 窓の拒否 (errorCode が `error_codes` に完全一致) を主体ごとに数える。拒否された API (`eventSource:eventName`) の種類が min_distinct_apis (既定 5) 以上かつ平常帯超えで medium、high_distinct_apis (既定 20) 以上で high。件数が max(min_count (既定 50), 中央値 × factor) 超えで medium。両方なら重い方を 1 件 |

- 評価するのは窓のイベント (再走査で遅れて届いた分を含む。ADR 0013)。UTC の日では分けない (日をまたぐ列挙が割れないように)。平常帯は窓の始まりの日の前日から baseline_days 日の、その主体自身の日ごとの件数・種類 (無い日は 0) の中央値 × factor。拒否のある過去日が min_baseline_days 未満なら平常帯 0
- 決定: 平常帯は丸 1 日と比べるので、daily (窓 24h) を前提とする。窓が 24h より短いプロファイル (hourly に入れた場合) では窓が短い分だけ鳴りにくい (いまは daily だけ。hourly は将来の課題)
- 決定: error_codes は保存 (events) の条件なので overrides では変えられない。後から足したコードは、足す前の拒否が保存されていないので平常帯 0 から始まる
- サービス主体と root は対象外。allowlist で承認済みでも対象 (止めるのは ack / snooze)。Data: principal, principal_kind, allowlist_status, external_account, count, distinct_apis, apis (件数の多い順に最大 10 個、`iam:ListUsers × 3`), error_codes, ips, first_time, last_time, baseline_median_count, baseline_median_distinct, threshold (`breadth` / `volume`)

決定 (週次チェックと ai_path_usage。Step 3、ADR 0015):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| credential_hygiene | state | `unused_key\|<user>\|<n>` / `no_mfa\|<user>` / `root_access_key\|<n>` | 重大度 + ユーザー (+ キー番号) | 有効なアクセスキーの最終使用 (使われていなければ作成・ローテーション) から `checks.credential_hygiene.unused_days` (既定 90) 日超 / パスワード有効で MFA 無し / ルートに有効なキー。経過日数は Data |
| guardduty_findings | state | finding ID | 重大度 + count | アーカイブされていない finding。GuardDuty の重大度 7 以上 → high、4 以上 → medium、他は low。count の増加は changed |
| posture | state | `cloudtrail_logging` / `cloudtrail_log_validation` / `guardduty_enabled\|<region>` / `root_mfa` / `s3_public_access_block` / `password_policy` | 重大度 + 問題の中身 (無効な項目・最小文字数など) | 記録中のマルチリージョン証跡が無い (high)、ログファイル検証が無効な証跡 (medium)、GuardDuty 無効 (high)、ルート MFA 無し (high)、PAB 未設定 / 無効な項目 (high)、パスワードポリシー未設定 / 最小文字数 < `checks.posture.min_password_length` (既定 14) (medium)。取れなかった項目は前回の finding を維持 |
| access_analyzer | state | finding ID | 重大度 + リソース + 許可先 + action | ACTIVE な外部アクセスのアナライザーの ACTIVE な finding。公開は high、他は medium |
| ai_path_usage | event | `<ARN>\|<ip>` | info + IP | allowlist の `tags: [ai]` を持つ承認済みの主体で、principal_ips.last_seen が窓内の組を毎回 info に 1 行 (件数は累計) |

決定 (waf_review。ADR 0023): 週次に、daily が貯めた wafv2 の日次集計 (2 章) と `waf-config` の設定から、決まった規則で WAF の修正提案の候補を作る。
arata は LLM を使わず候補だけを作り、aratam の LLM は候補を文章と設定例に書き起こすだけ (候補に無い提案を作らない)。適用は人が判断する。

| 候補 (`kind`) | 段階 (`stage`) | 条件 (閾値はすべて `checks.waf_review`) |
|---|---|---|
| `false_positive` (誤検知の疑い) | count_first | 探索パスではない正規化パスで、ルールの BLOCK の異なり IP (日ごとの最大) が `min_distinct_ips` (10) 以上。`finding_distinct_ips` (50) 以上は low の finding にも (key `false_positive\|<WebACL>\|<ルール>\|<method> <path>`、state 型) |
| `probe_allowed` (すり抜けている探索) | count_first | 探索パスへの ALLOW が直近 `days` (7) 日で `min_count` (10) 件以上 (WebACL ごとに 1 件、パスは上位 10) |
| `rate_limit_missing` (レート制限の不足) | count_first | パスの群を受け持つレートベースのルールが無く、5 分あたりの最大が p99 の `rate_factor` (10) 倍超え、かつ提案する limit より大きい。limit = max(p99 × `rate_margin` (3), `rate_floor` (100)) |
| `rate_limit_loose` / `rate_limit_tight` | review | 受け持つルールが 1 つで解釈できるとき、limit (5 分あたりに換算) が観測の最大の `rate_loose_factor` (10) 倍より高い / 観測の p99 より低い |
| `unused_rule` (使われていないルール) | review | 直近 `unused_days` (30) 日すべてにデータがあり、終了ルールにもカウントの一致にもならなかった (COUNT のルールは除く)。削除は勧めない |
| `observation` (提案なし) | none | 下の「不審な事実は必ず伝える」。`about` (関わる候補) と `reason` (提案しなかった理由) を持つ |
| `observation` / about `count_rule_status` (COUNT のルールの状況) | none | COUNT で動いているルール (グループ全体の COUNT、グループの中の COUNT の上書きを含む) ごとに毎回 1 件 (`reason: informational`)。直近 `days` 日の一致件数・怪しい通信の割合・一致した日数。一致 0 も載せる |

- 決定: COUNT → BLOCK の切り替えは提案しない (当初の `count_to_block` は廃止)。切り替えは運用で計画して行う作業 (COUNT で入れるときに期間を決めて様子を見る) で、
  アプリの事情も絡むので、ログの数字だけで勧めると正規の利用者を止める危険がある。代わりに COUNT のルールの状況を計画の材料として毎回載せ、Summary は事実だけを書く
  (例「COUNT の X: 直近 7 日で 6 件一致、うち怪しい通信 100%、一致した日 1 / 7 日」)。怪しい通信 = 探索パスか、レート制限・既定の action・sign-in のパス以外で BLOCK された IP からの一致。
  COUNT のルールは一致 0 でも count_rule_status に載るので、`unused_rule` の対象から外す (重ならないように)。閾値 `count_days` / `count_ratio` / `count_min_matches` は設定から外した
  (書いたままの設定は `config init --diff` で unknown_key と出る。Load は未知のキーで止まるので消す)
- 決定: 「迷ったら提案しない」。設定と突き合わせられない (WebACL が waf-config に無い・同じ名前の WebACL が複数ある・ルールが設定に無い)、scope-down を解釈できない、
  IP 以外の集約のレートベースのルール、複数の条件の scope-down、群の一部だけを受け持つルール、データの日数が足りない、のどれでも提案しない
- 決定: 誤検知の候補から外すもの: 探索パス、sign-in のパス (`login_bruteforce.paths`。多数の IP からの BLOCK はクレデンシャルスタッフィングかもしれない)、
  レートベースのルール (レート制限の候補で扱う)、送信元の評判で止めるグループ (`IpReputation` / `AnonymousIp`)、既定の action (`Default_Action`)
- 決定 (不審な事実は必ず伝える): 規則が提案に至らなかったが不審な観測があれば、`kind: observation` で理由 (`below_threshold` 閾値未満 / `undetermined` 判断できない /
  `excluded_by_config` 除外設定に一致 / `excluded_by_rule` 決まった除外に一致 / `position_limit` 数え漏れの可能性) と根拠の数字を添えて残す。
  対象は、異なり IP が足りない BLOCK (2 IP 以上・`min_count` 件以上)、除外に当たった多数の IP の BLOCK、閾値未満の許可された探索、日数が足りないが不審な一致ばかりのカウントルール、
  判断できない・除外したパスの群の突出、配列の位置の上限超え。正規の通信にも当たっているカウントルール (割合が足りない) は不審ではないので出さない。
  攻撃そのものの検知は既存のチェック (waf_block_trend・probe_paths・login_bruteforce) の finding が担い、observation は「WAF の設定の観点で気づいたこと」に限る
- 決定: 異なり IP 数は日ごとの値の最大 (日をまたいで足せない。下限の見積もり)。Evidence に `distinct_ips_is_lower_bound: true` を付ける
- 決定: `expected_high_rate_paths` (決済など、リクエストが多いのが仕様のパス) はレート制限の候補から外す (突出していれば observation に残る)。判定のパラメータ
- 決定: 候補は種類ごとに `max_proposals` (20) まで (根拠の強い順)。候補は差分判定に乗せず毎週その時点の候補を出す
- 決定: waf_review は保存済みの日次集計だけを読む (`StoredNeeds`)。weekly の run は wafv2 のソースを引かない (Insights の費用)。wafv2 のソースが設定に無ければ skip (`no waf_action source`)。
  候補を見るには daily が回っている必要がある

- 評価する日は窓に重なる UTC の日。key ごとに件数が最大の日を 1 件にまとめる。複数ソースが同じ metric を出す場合は合算する。
- 件数・日付・中央値・閾値は Data に残し、Fingerprint には入れない (翌日も同じ IP が続けば still_open で沈黙し、窓が途切れてから再び現れたら recurred)。
- 「初出」系 (`new_top_ip` / `new_rule`) は過去にデータのある日が min_baseline_days (既定 7) 未満の間は判定しない (導入直後に全部が初出になるのを防ぐ)。閾値超えは導入直後から判定する。
- allowlist の `source_ips` に含まれる IP は 3 チェックとも対象外。
- パス・メソッド・ステータス・閾値は設定の `checks:` で顧客ごとに変える (examples/arata.yaml)。既定: sign-in は `POST` で `/users/sign_in`, `/login`, `/signin` へ 401 / 403 / 422、
  機密パスは `/.env`, `/.git/`, `/wp-login.php` などへの 403 / 404。`probe_paths.exclude_paths` で正規の管理画面などを外す。

## 8. CLI

```
arata config init [--out FILE|-] [--force] | --diff   # 推奨設定の雛形を書き出す (既定 ./arata.yaml) / 雛形との差分 (3 章、ADR 0014)
arata profiles  [--format table|json]   # プロファイルごとに実際に効いているチェックとパラメータ、その由来
arata init      [--window 7d | --resume]   # ストア作成、設定検証、ベースライン収集 (findings は出さない)
arata doctor                   # 権限・ロググループ・形式プロファイルの解釈率を検査
arata run       --profile daily [--out dir]   # collect → evaluate → report → prune
arata collect   --window 24h [--source id]
arata evaluate  --profile daily
arata report    --from 2026-10-01 --to 2026-10-31 --format md|json [--template monthly]
                # 決定: --month 2026-10 を糖衣にし、--template は作らない。収集せずストアだけから作る (ADR 0016)
                # 決定: 期間を指定せず、そのプロファイルの run がまだ無ければ REPORT_NOT_FOUND を 1 行出して終了コード 2 (--out のディレクトリも作らない)
arata review    [--status open|acked]
arata approve   <finding-id> --note "..." [--expires date] [--tag deploy] [--by name] [--commit] [--account | --arn-pattern glob]
arata ack|snooze|resolve <finding-id>        # snooze は --until date
arata help ai [report|approve] [--format json]   # LLM 向けの使い方 (arata ai と同じ)
arata prune     [--dry-run]
arata rebuild                  # raw JSONL から SQLite を再構築
```

- 決定: 設定ファイルのパスには既定を持たせる。解決順は `-c` (`--config`) > 環境変数 `ARATA_CONFIG` > カレントディレクトリの `./arata.yaml`。
  どれも無ければ探した場所を並べて `CONFIG_INVALID` (終了コード 2)。`-c` や `ARATA_CONFIG` で指したファイルが無いときは次へ落ちずに設定エラーにする
  (指定の打ち間違いで別の設定が黙って使われるのを防ぐ)。`config init` の `--out` の既定も `./arata.yaml` (既存ファイルは `--force` が無ければ上書きしない。
  標準出力へは `--out -`)。`run --out` などデータの出力先には既定を足さない。サンプルは `examples/arata.yaml`。aratam の設計とそろえる
- 終了コード: 0 = 正常 (findings の有無に関係なく)、2 = 設定 / 権限エラー、3 = 収集の一部失敗 (レポートは出す)。
  組み込み側は終了コードと `report.json` の `summary.new_count` / `summary.max_severity` で通知を分岐する。
- 出力は `report.json` (機械向け、LLM 要約の入力) と `report.md` (人向け)。Slack / Issue への投稿はしない。

決定 (`doctor`):
- ストアを開かない (ロックを取らないので run と並行でき、ストアが無くても動く)。`--window` (既定 24h) は解釈率のサンプルを探す範囲、`--format table|json`。
- 検査項目: `permission` (LookupEvents を 1 件だけ引く / 各 API の AccessDenied に不足 action を添える)、`log_group` (DescribeLogGroups で完全一致を探す)、
  `match_rate` (直近 100 行を `fields @timestamp, @message, ispresent(<判定フィールド>) as arata_matched | sort @timestamp desc | limit 100` で取り、手元で数える。生ログを引くのはここだけ)、
  `queries` (集計・解釈率・サンプル・doctor 自身のクエリを StartQuery して直ちに StopQuery し、Insights の構文検査だけを受ける。match_rate より先に行う)、`check` (必要なレコードを出すソースが無いチェック = warn)、`config` (allowlist の検証)。
- ng が 1 つでもあれば終了コード 2。ng の行は標準エラーに固定語彙の `code` 付きで 1 行ずつ出す。warn だけなら 0。
- 表の最後に、設定のソースに必要な IAM action (`cloudtrail:LookupEvents`, `logs:DescribeLogGroups`, `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`) を列挙する。
- 決定 (Step 3): アカウント単位のソースは、collector の読み取り API を 1 回ずつ試して action ごとに permission 行を出す (拒否は ng / ACCESS_DENIED)。
  必要な action: iam-credential-report = `iam:GenerateCredentialReport` (書き込み系。doctor では試さない)・`iam:GetCredentialReport`、
  guardduty = `guardduty:ListDetectors`・`ListFindings`・`GetFindings`、access-analyzer = `access-analyzer:ListAnalyzers`・`ListFindings`、
  posture = `cloudtrail:DescribeTrails`・`GetTrailStatus`、`guardduty:ListDetectors`・`GetDetector`、`iam:GetAccountSummary`・`GetAccountPasswordPolicy`、`s3:GetAccountPublicAccessBlock`、
  waf-config = `wafv2:ListWebACLs`・`GetWebACL`・`GetLoggingConfiguration`・`ListResourcesForWebACL` (決定: ADR 0023。WebACL があれば最初の 1 つで残りを試す)。
  doctor の `queries` は wafv2 の新しい集計のクエリも構文検査する。`check` の warn は waf_review が読む日次集計の元 (wafv2 ソース) が無いときも出す。
  run では、権限の無いソースのチェックだけが skip され (posture は取れた項目で評価)、他のチェックは続行する。

### report.json の骨子

```json
{
  "profile": "daily", "window": {"from": "...", "to": "..."}, "name": "example",
  "summary": {"new": 3, "changed": 1, "recurred": 0, "resolved": 2, "still_open": 7, "max_severity": "high", "collect_errors": []},
  "findings": {"new": [...], "changed": [...], "recurred": [...], "resolved": [...], "still_open": [...]},
  "already_reported": [...],
  "info": [{"check": "ai_path_usage", ...}],
  "coverage": {"sources_ok": [...], "sources_failed": [...], "checks_skipped": [{"check": "...", "reason": "no http_access source"}]}
}
```

`coverage` を必ず出す。「静かだったのは平和だからか、取れていなかったからか」を区別するため。

決定 (report.json の詳細):
- `findings.recurred` を追加 (4-2 の event 型の再観測)。`summary.recurred` も出す。
- `summary.max_severity` は new / changed / recurred の最大。still_open を含めると毎回鳴るため含めない。
- severity=info の finding は new / changed でも `findings` には入れず `info` に入れ、summary のカウントにも含めない。
- `already_reported` は still_open のうち first_seen が窓内かつ reported_at が付いているもの (hourly で報告済みの事象が daily に現れた場合)。
- acked / snoozed 中の finding はレポートに出さない。
- `coverage.checks_run` を追加し、実際に走ったチェック名を出す。
- 決定 (Step 3): `coverage.sources_failed` / `summary.collect_errors` に `action` (不足した IAM action) と `partial` (一部の項目だけ取れず、取れた項目で評価した) を足す。
- 決定 (ADR 0023): `proposals` (WAF の修正提案の候補と observation。waf_review が走った run だけ。無ければ節ごと出さない) を足す。1 件は `kind` / `stage` / `web_acl` / `scope` / `region` /
  `rule` / `rule_in_group` / `method` / `path` / `summary` / `evidence` (根拠の数字と提案する値) / `finding_key` (low の finding にもした候補)、observation は `about` / `reason`。
  aratam は未知のフィールドを無視するので、古い aratam でも止まらない (テストで固定)。`coverage.formats[].truncated` (行の上限に当たった集計) も足す。report.md には「WAF の修正提案の候補」の節を出す

決定 (期間レポート。ADR 0016): `report --from --to` (`--month`) は `"kind": "period"` の別の形を出す。
`period` / `notes` (履歴の無い期間の注意) / `summary` (new / changed / recurred / resolved / by_severity / open) / `events` / `new_principals` / `open` /
`metrics` (日 × 指標の合計、UTC) / `runs_missing` (partial / failed / RUN_MISSED) / `profiles` (プロファイルごとの run 数)。info は数えない。

## 9. 組み込み方 (エンジンの外側)

| 方式 | 構成 | 向く顧客 |
|---|---|---|
| オンプレ cron | `cron → arata run → 終了コードと report.json で Slack 投稿 / claude -p で要約` | CircleAround が運用を預かる顧客。監視対象の外で動く |
| Lambda | `EventBridge Scheduler → arata-lambda (S3 ストア) → SNS` | 顧客アカウント内で完結させたい顧客。**ストアと SNS は別の監査用アカウントか Object Lock バケット**に置き、侵害時に改ざんされにくくする |
| AgentConsole タイマー | 一時的な追跡のみ | 恒常運用には使わない |

LLM 要約は `arata help ai report` (バイナリに埋め込んだ手順) に従い、`report.json` を入力に「新規 / 変化 / 再発 / 解消 / 未対応 / 取れなかったもの」の順で書く。
approve は人の判断を経て実行する。

決定 (LLM 向けの使い方の配り方。ADR 0012): skill ファイル (`skills/aws-audit/SKILL.md`) を別に配る案は取りやめ、`docs/ai/*.md` を embed で
バイナリに入れて `arata help ai` / `arata help ai report` / `arata help ai approve` で出す (`--format json` で `{topic, title, sections: [{title, body}]}`)。
組み込み側の LLM には「最初に `arata help ai` を読む」とだけ指示すればよく、手順とエンジンの版がずれない。
引数なしの `arata` (ルートのヘルプ) は、人向けの手順 (config init → doctor → init → run。決定: Step 3 で config init を先頭に足した。ADR 0014) と `arata help ai` への案内を最初に出す。

### 9-1. report.json から通知までの LLM の仕事

決定 (ADR 0018): この章の仕事と規則は `aratam` (`docs/aratam.md`) が実装する。arata 自体は変えない。

エンジンは「新規かどうか」と規則ベースの重大度までを決める。LLM はその先の **トリアージと説明** を担う。

1. **相関と文脈付け**: 個々の finding を横断して読む。「新規主体 + 国外 IP + 秘匿値取得」が同じ主体なら 1 件のインシデント候補にまとめる。allowlist のメモ、前回レポート、時間帯 (デプロイ時刻、メンテ時間) を踏まえ、規則では判断できない「怪しさ」を評価する。
2. **追加の裏取り (任意)**: high 以上の finding については、同じ読み取りロールで追加照会を行い根拠を足す (`alert-investigation` の流儀)。追加照会は読み取りのみ。
3. **分類**: 各 finding を「要対処 (今動く)」「確認依頼 (人が判断する)」「情報 (記録のみ)」に分け、理由を根拠付きで書く。
4. **人向け文章の生成**: 新規 / 変化 / 解消 / 未対応 / 取れなかったもの (coverage) の順で日本語の要約を書く。個人特定値は書かない。
5. **承認の提案**: 新規主体のうち正当と思われるものは「approve してよいか」を人に提案する。**LLM 自身は approve しない**。

LLM がやらないこと、組み込み側で規則として固定すること:

- **重大度の下限**: `summary.max_severity` が high 以上なら LLM の判断に関係なく緊急チャンネルへ通知する。LLM が critical を「情報」に格下げして沈黙させる経路を作らない。
- **フォールバック**: LLM 呼び出しが失敗したら `report.md` をそのまま投稿する。LLM の障害で監査が止まって見えないようにする。
- **実行の有無の監視**: `RUN_MISSED` やエンジンの終了コードは LLM を経由せず直接通知する。

つまり LLM の役割は「危険の判定を代行する」より「人が 1 分で判断できる材料に整える」こと。判定の責任は規則 (エンジン) と人に置く。

## 10. 実装順

1. config / store (dir backend) / cloudtrail collector / `root_usage`, `unknown_assume_role`, `new_principal`, `iam_changes` / report.json — ここで日次が最小構成で回る
2. cwlogs collector と形式プロファイル (`nginx_access`, `wafv2`, `regex`) / `login_bruteforce`, `probe_paths`, `waf_block_trend` / `doctor`
3. guardduty / iam credential report / posture / weekly チェック / allowlist の approve フロー (決定: Step 3 で実装。設定の雛形 config init / profiles / overrides も。ADR 0014・0015)
4. `report --from --to` と monthly テンプレート / prune / rebuild (決定: 期間レポートは Step 3 で実装。ADR 0016。prune / rebuild は後続)
5. Lambda ハンドラと S3 backend / deploy テンプレート (決定: skill 同梱は `arata help ai` に置き換えて Step 2 で実装済み)

## 11. 未決事項

- 国判定 (IP → 国) をどうするか。MaxMind のオフライン DB を同梱するか、GuardDuty の `remoteIpDetails` に頼るか。
- Logs Insights の費用上限。1 日あたりのスキャン量に上限を設け、超えたら daily チェックを縮退させるか。
  (Step 2 でソース単位・1 回の収集単位の `max_scan_gb` を入れた。1 日あたり・顧客全体の上限と縮退は未決)
- 顧客間での allowlist の雛形共有 (CircleAround の switch role 等は全顧客共通になり得る)。
