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
| 公開できない情報の検査 | 決定: 一般的な秘密は gitleaks (`.gitleaks.toml`)、禁止語は Actions の secrets の一覧と `tools/wordscan` で全履歴と GitHub の本文を CI で検査する。ログに語を出さない。運用は `docs/sensitive-scan.md`。ADR 0036 |
| ファズテスト | 決定: 信用できない入力 (ログの行と Insights の結果・CloudTrail のイベント・LLM の出力・利用者のファイル) を解釈する箇所に、Go 標準のファズテスト (`testing.F`) を置く。性質は「パニックしない」だけでなく、その関数が守る規則 (伏せ字が元の値を残さない、通知に `<` `>` や目に見えない文字が残らない、公開の判定が見逃す側に倒れない、など) を書く。`go test ./...` は seed と `testdata/fuzz` だけを走らせ、探索は週次の `fuzz.yml` (`tools/fuzz.sh`、対象ごとに 30 秒)。見つかった失敗は seed か `testdata/fuzz` に残して本体を直す。対象の一覧と手順は `docs/fuzzing.md`。ADR 0041 |
| 設定の名前 | 決定: 設定のトップレベルキーは `customer` ではなく `name` (レポートに出す監査対象の名前)。`customer` は受託側の目線に寄りすぎており、自社アカウントを自社で監査する使い方もあるため中立な名前にした。利用者がいない段階の改名なので旧キーの互換は持たず、`customer` は未知のキーとして設定エラーになる |
| サプライチェーン | 決定: GitHub Actions は 40 桁の SHA で固定し版をコメントに書く。全ワークフローに最小権限の `permissions:`、checkout は `persist-credentials: false`。依存は公開から 7 日待つ 2 段構え (提案: Dependabot の `cooldown`、強制: CI の `tools/agegate` が indirect を含む全モジュールの公開時刻を GOPROXY で確かめる)。CI で `go mod verify` と `govulncheck`。release は build provenance attestation (来歴証明) を付ける (公開リポジトリまたは Enterprise Cloud で有効。非公開の間は SHA256SUMS のみ)。ADR 0017。CI の常時の検査 (Actions の固定と待機の強制、zizmor、週次の脆弱性検査)、release の権限の分離、SBOM は ADR 0035 と [supply-chain.md](supply-chain.md) |

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
- 決定 (クエリをまとめる。ADR 0031): Insights は 1 本ごとに範囲のログ全体を読むので、同じソースの集計を細かい group by の数本にまとめ、振り分けを Go で行う。
  http_access は 2 本 (解釈率 + `probe_paths`、`sign_in_failures` + `probe_hits`) + endpoint_abuse があれば全画面で 1 本、wafv2 は 4 本 (2 章の下の決定)。
  値は前の版と同じ (同じログから同じ metrics。`cwlogstest.Sim` とゴールデン `testdata/equiv_*.golden` で固定)。行数の上限 (10000) に当たったら
  その範囲を半分に分けて引き直し (1h まで。スキャン量は範囲に比例するので、増えるのは引き直した分だけ)、それでも当たればまとめた集計から作る metric を全部 `truncated` に残す
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
    kind: posture                 # CloudTrail 証跡・GuardDuty 有効・ルート MFA・S3 Public Access Block・パスワードポリシー・インターネット向けの ALB の WebACL → posture_item
```

- 取ったものは `record.SnapshotItem` として `snapshot_items` に保存し、**収集が成功したときだけ (kind, source) 単位で丸ごと置き換える** (5-2)。
  失敗したら前回のまま残し、そのソースのチェックは skip する (権限を失ったことを「解消」と誤認しない)。
- GuardDuty が無効 (detector が無い / 停止中)、アナライザーが無いときは、収集は成功として「その種類は取れない」理由を返し、チェックを skip して
  `coverage.checks_skipped` に理由を出す。GuardDuty が無効であることは posture が finding として報告する。
- posture は一部の API だけ拒否されても他の項目を取る。取れなかった項目は `unknown` で保存し、`coverage.sources_failed` に `partial: true` と `action`、終了コード 3。
- 決定 (ADR 0048): posture は、ソースの `regions` の各リージョンで、インターネット向け (Scheme = internet-facing) の Application Load Balancer に
  WAFv2 の WebACL が付いているかを見る (`elasticloadbalancing:DescribeLoadBalancers` と、ALB ごとの `wafv2:GetWebACLForResource`。どちらも読み取り)。
  項目はリージョンごとに 1 つ (`alb_waf|<region>`。WebACL の無い ALB の名前と ARN だけを持つ)。internal の ALB、NLB・GWLB、CloudFront、API Gateway は見ない。
  一覧か WebACL の確認が失敗したリージョンは取れなかったことにし、そのリージョンの前回の finding を維持する。
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
| `waf_rule_action` | `<WebACL>\|<終了ルール>\|<action>` | 件数。既存の `waf_block` (ルール別) はここから作る。解釈率のクエリと 1 本 (ADR 0031) |
| `waf_block_path` / `_ips` | `<WebACL>\|<ルール>[/<グループの中のルール>]\|<method>\|<正規化パス>` | BLOCK の件数 / 異なり IP 数。探索パスは除く。日ごとに上位 `top_paths` (既定 50) |
| `waf_allow_probe` / `_ips` | `<WebACL>\|<正規化パス>` | 探索パス (probe_paths) への ALLOW の件数 / 異なり IP 数。上位 `top_paths` |
| `waf_rule_count_match` / `_suspect` | `<WebACL>\|<ルール>` (グループの中は `<ruleGroupId>/<ルール>`) | カウントモードの一致の件数 / そのうち探索パスか、その日「BLOCK された IP」(下の決定) からの件数 |
| `waf_ip_rate_p50` / `_p99` / `_max` | `<WebACL>\|<パスの群>` | 1 IP あたり 5 分間の件数の分布。群は `rate_path_groups` の接頭辞 (最長一致)、どれにも当たらなければ `*` |
| `waf_position_limit` | `<WebACL>\|<配列の名前>` | 配列の位置の上限を超えた (数え漏れの可能性がある) リクエストの数 |
| `waf_challenge_issued` / `_issued_ips` / `_solved_ips` | `<WebACL>\|<challenge\|captcha>\|<ルール>[/<グループの中のルール>]\|<method>\|<正規化パス>` | Challenge / CAPTCHA を出した件数 / 出した異なり IP / そのうち解いた異なり IP (ADR 0028)。日ごとに上位 `top_paths` |

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
- 費用 (ADR 0031): wafv2 ソースのクエリは 4 本 (解釈率 + `waf_rule_action`、止めた・出した系、カウントの一致、レート (日数分。合わせて範囲 1 本分))。前の版は 10 本。
  止めた・出した系は filter を `action = "BLOCK" or ((CHALLENGE / CAPTCHA or 許可された探索 or トークンの受理) and 正規の送信元でない)` にし、group by を各集計の軸の和集合にして、
  `waf_block_ip`・`waf_block_path`・`waf_allow_probe`・「BLOCK された IP」・Challenge の出した / 受理を Go で振り分ける (trusted_cidrs・探索パス・sign-in のパス・レートベース / 既定の action の除外も Go)。
  カウントの一致は path の軸に入れると行が爆発するので別のまま。既存の `max_scan_gb` がそのまま効く (超えたら QUERY_LIMIT で、その日の集計は欠ける)。
  sandbox の 1 時間・約 300 リクエストのログで 1 本 0.3〜0.5 MB
- 決定 (資源で絞る。ADR 0028): wafv2 ソースの `resources` (ログの `httpSourceId` の完全一致か `*` / `?` の glob) を前処理に `filter httpSourceId like /^(...)$/` として入れる。
  解釈率と全集計が同じ範囲を数える。集計の key には資源を入れない (分けたいならソースを 2 つ書く)。Insights はロググループ全体をスキャンするので費用は減らない。集計条件
- 決定 (Challenge / CAPTCHA。ADR 0028): 出した行 (`action` が CHALLENGE / CAPTCHA) と、トークンが受理された行を別のクエリで (日, method, パス, IP) まで取り、Go で数える。
  受理は公式文書の説明 (トップレベルの `<種類>Response` に solveTimestamp があり failureReason が無い) と例 (`nonTerminatingMatchingRules.N.action` が CHALLENGE / CAPTCHA、
  グループの中は `ruleGroupList.N.nonTerminatingMatchingRules.0.action`) が食い違うので両方を受け付ける。期限切れ (failureReason あり) は受理としない。
  解いた IP は「出した IP」との積集合 (同じ日・同じ method とパス・同じ種類)。トークンはルールで共有されるのでルールでは突き合わせない

決定 (endpoint_abuse の集計。ADR 0030): http_access のソースは、`checks.endpoint_abuse.endpoints` の画面ごとに 1 本
`filter <パス・メソッド・ステータス> | stats count(*), min(@timestamp), max(@timestamp) by bin(<window>), ip, ua` を流し、
件数・異なり IP・同じ UA の広がり・連鎖を Go で数える (指標ごとに分けると画面 × 3 回スキャンし、Insights の count_distinct は概数のため)。
- UA は結果を受け取った直後にハッシュにし、原文は保存・ログ出力しない。UA を出さない形式 (json で `ua` の対応が無いなど) では ua で group by しない
- 行数の上限 (10000) は UTC の 1 日ずつ流して避け、それでも当たればその範囲を時間幅に揃えて半分に分けて引き直す (1h まで。分けてもスキャン量は範囲に比例するので、増えるのは引き直した分だけ)。
  それでも当たれば WARN と `stats.truncated` (`endpoint_abuse:<画面>`)
- 費用: 画面ごとに 1 回、既存の集計と同じ範囲 (窓の始まりの日の 0 時から窓の終わり) をスキャンする。画面 2 つなら http_access のソースのスキャンは 4 本 → 6 本 (約 1.5 倍)。
  決定 (ADR 0031 で置き換え): 全画面で 1 本にまとめる。filter は画面ごとの条件の和、group by に method・status と glob ごとの印 (一致したときだけ先頭の `/` を捕獲する parse) を足し、
  Go で画面に振り分ける。http_access のソースは endpoint があっても 3 本
  `max_scan_gb` がそのまま効く (超えたら QUERY_LIMIT)。`endpoints` が空なら流さない
- 拡張点: 集計の軸 (`endpointGroupFields`) にフィールドを足せば行ごとの値として Go に渡る。次の段階でアプリのログからメールのドメインだけを取り出して画面に添えるときはここに足す

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
  決定 (ADR 0041): マスクの前に制御文字・向きの制御・ゼロ幅の文字を除き、空白類は空白にする。サンプル行は doctor が端末に出すので、ログの行のエスケープシーケンスで端末を操作させない。
- **エンジン自身のログ**: 標準エラーに JSON 行で出し、`code` を固定語彙にする。組み込み側はこの `code` を監視して通知すればよい。
- **集計値の読み取り**: 決定 (ADR 0041): Insights の結果の数値 (件数・パーセンタイル) は、読めない値に加えて `NaN`・無限大・負の値も 0 として扱う。そのまま metric の値にすると JSON に書けず、その run の保存が失敗する。

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
| `STORE_LOCKED` / `STORE_CORRUPT` | ストアの排他失敗 / SQLite 破損 (rebuild を促す。`arata rebuild` で既存の SQLite が読めないときもこれで、`--from-scratch` を案内する) |
| `STORE_CONFLICT` / `STORE_UNAVAILABLE` | 決定: `s3://` のストアを別の実行が先に書いた / S3 に問い合わせられない (権限・通信。破損ではない)。どちらも終了コード 2 (5-5、ADR 0034) |
| `INTERRUPTED` | 決定: SIGINT / SIGTERM で止まった (終了コード 2。設定の誤りとは区別する。`dir://` でも同じ。init は除く: 進捗を確定して終了コード 3) |
| `RUN_MISSED` | 前回実行から profile の周期の 2 倍以上空いた (起動側の障害) |
| `COLLECT_FAILED` | 決定: 上記に分類できない収集エラー (ネットワーク断など) |
| `CONFIG_INVALID` | 決定: 設定ファイルの読み込み・検証エラー (終了コード 2) |
| `CHECK_UNUSED` | 決定: どのプロファイルにも入っていないチェックがある (警告。run / evaluate / doctor が出す。3 章、ADR 0014) |

`doctor` は同じ検査を実行前に行い、全ソースの解釈率を表で出す。

決定 (解釈率と形式エラーの扱い):
- 解釈率は `stats count(*) as lines_total, count(<判定フィールド>) as lines_matched by bin(1d)` で測る。判定フィールドは `http_access` が `path`、`waf_action` が `action`。
- 解釈率を**先に**測り (決定: ADR 0031 で、最初のクエリは解釈率と集計 1 種を兼ねる。そのクエリの集計も、`FORMAT_MISMATCH` なら保存しない)、`FORMAT_MISMATCH` なら残りの集計クエリを流さず metrics も保存しない (誤った集計で平常帯を汚さず、スキャン費用も抑える)。そのソースは失敗扱い (`coverage.sources_failed`、終了コード 3)。
- 窓内に 1 行も無いときは解釈率を判定せず (`match_rate: null`)、WARN ログ (code なし) を出す。ロググループや `stream_prefix` の誤りの手がかり。
- `FORMAT_DRIFT` の平均は、このソースの解釈率を記録した直近 7 回の run (`runs.stats.match_rates`) から取る。過去の計測が 3 回未満なら判定しない。警告のみで終了コードは変えない。
- サンプル行は標準エラーの `FORMAT_MISMATCH` ログにだけ添え、report.json / report.md には出さない (マスク済みでも氏名などは検出できないため)。マスクはメールアドレス (URL エンコード形を含む) を `<email>` に置き換えてから 200 文字に切る。metrics の key (パスなど) にも同じマスクをかける。
- Insights の方言の注意 (本番の doctor で確認): 前処理 (`parse` / `fields ... as`) で定義したフィールドを後段の `fields` で列挙し直すと
  `Ephemeral field is already defined` で拒否される。doctor のサンプルは判定フィールドを列挙せず `ispresent(<判定フィールド>) as arata_matched` で返し、
  `json` の対応表で元と正規化名が同じ (`path: path`) ときは別名を付けない。doctor の `queries` 検査は集計クエリに加えてサンプル用と doctor 自身のクエリも対象にする。
- report.json の `coverage.formats` に各 cloudwatch-logs ソースの `total` / `matched` / `match_rate` / `expected` / `recent_average` / `bytes_scanned` / `code` を必ず出す。

### 2-3. ALB のアクセスログから http_access を取る (提案。未実装・未確認)

**ここは提案。** 案の比較 (S3 を直接読む、Athena、S3 Select)・費用の見積もり・出典は ADR 0046 (状態: 提案)。実際のログで確かめて採用を決めたら、この節を仕様に書き直す。

目的: nginx のログを CloudWatch Logs に送っていない利用者でも、`http_access` を使うチェック (`login_bruteforce`・`probe_paths`・`endpoint_abuse`) を動かす。
ALB のアクセスログは 1 リクエスト 1 行で ip・method・path・status・ua・処理時間が揃い、アプリにもサーバーにも手を入れずに有効にできる。

今の `alb_access` の前提: cloudwatch-logs のソースの形式プロファイルで、ロググループの `@message` が ALB の従来のアクセスログ (S3 に出るもの) の 1 行そのままであることを前提に
Insights の `parse` で先頭 14 項目を解釈する。S3 は読まない。

**第 1 段 (推奨): ALB から CloudWatch Logs へ配信し、既存のソースで読む。** arata の変更は無いか最小。

```yaml
sources:
  - id: alb_prod
    kind: cloudwatch-logs
    log_group: prod-alb-access      # ALB の配信先に選んだロググループ
    format: alb_access
```

- 利用者の準備: ALB の Integrations タブ (CloudWatch Logs の配信の仕組み。従来のアクセスログの設定とは別) で、アクセスログを CloudWatch Logs へ配信する。
  **形式は plain、項目は既定 (全部)、区切りは空白**にする。項目を選ぶ・区切りを変えると `alb_access` が合わない
- 配信の既定の項目の並びは、従来のログの先頭 34 項目と同じ (API で確認)。ただし plain の行が従来の行と文字の単位で同じか (引用符、`client_port` の形) は**未確認**で、
  実際のログで doctor の解釈率を見て確かめる。違っていたら `alb_access` の `parse` を両方に合うように直す
- json 形式は今の `format: json` では読めない (メソッドとパスが `request_line` の 1 項目にまとまっていて、対応表では分けられない)。json 用の組み込みのプロファイルは今は作らない
- 読み取り専用ロールは変えない。解釈率・`FORMAT_MISMATCH`・doctor・`max_scan_gb` は今のまま効く
- 費用: 利用者側に CloudWatch Logs の取り込み料金 (量に比例) と保管料が出る。量が小さければ小さい (ADR 0046 の見積もり。推測を含む)
- 対象外: ALB の前に CloudFront などのプロキシがある構成 (ログの送信元がプロキシの IP になり、IP ごとの判定ができない)。WebSocket は接続が閉じたときの 1 行だけ

**第 2 段 (取り込み料金を避けたい利用者・量が多い利用者向け): S3 の従来のアクセスログを直接読む。** ソースの種類を 1 つ足し、arata が gzip のファイルを読んで Go で解釈・集計する。名前はどれも仮。

```yaml
sources:
  - id: alb_prod
    kind: s3-access-logs            # 新しい種類 (仮)
    bucket: prod-alb-logs
    prefix: alb                     # ALB のログの設定に書いた接頭辞。無ければ省く
    format: alb_access              # 今ある形式の名前を使う。yields は http_access
    # account_id: "123456789012"    # キーの AWSLogs/<ここ>/。既定は監査対象のアカウント
    # region: ap-northeast-1        # 既定 aws.region
    # load_balancers: ["app.prod-alb.*"]   # 同じ接頭辞に複数の ALB が出るとき、ファイル名の ALB の ID で絞る
    max_download_gb: 2              # 1 回の収集で読んでよい量 (圧縮後。既定 0 = 無制限)。目安は doctor の cost
    # ingest_delay: 10m             # 既定の案。ALB は 5 分おきに配信し、遅れることがある
```

- **保存するもの**: 今の cloudwatch-logs の `http_access` のソースと同じ日次集計 (`sign_in_failures`・`probe_hits`・`probe_paths`・endpoint_abuse の集計・`lines_total`・`lines_matched`) だけ。
  生の行はストアにもディスクにも残さない。User-Agent は読んだ直後にハッシュにし、パスの正規化と伏せ字は今と同じ規則
- **読む範囲**: 窓に重なる UTC の日の 0 時から窓の終わり (+ `ingest_delay` の再走査) まで読み、日次集計を置き換える (ADR 0009・0013 と同じ)。
  「どのファイルまで読んだか」の位置は持たない。遅れて届いたファイルは、その日を読み直すときに入る
- **一覧**: キーは `.../AWSLogs/<アカウント ID>/elasticloadbalancing/<region>/<yyyy>/<mm>/<dd>/` の下にあり、日付は配信日。日 D の行のために D と D+1 のディレクトリを ListObjectsV2 で一覧する。
  行は、ファイル名ではなく行の `time` で UTC の日に振り分け、範囲の外の行は捨てる
- **解釈**: 先頭 14 項目 (`"user_agent"` まで) だけを読む。新しい項目は行の末尾に足されるので、後ろは読まない。対応は今の `alb_access` と同じ
  (`ip` = `client:port` の IP、`status` = `elb_status_code`、`duration` = `target_processing_time`、`method`・`path` = `"request"` の URL からクエリを除いたパス、`ua`)。
  Insights の `parse` と Go の解釈が同じ結果になることをテストで固定する。ログの行は信用できない入力なので、ファズテストを足し、1 行の長さと 1 ファイルの展開後の大きさに上限を置く (ADR 0041)
- **形式の検証**: 解釈率・`FORMAT_MISMATCH`・`FORMAT_DRIFT` は 2-2 と同じ規則。範囲にファイルが 1 つも無いときは `match_rate: null` と WARN
- **上限**: 一覧でサイズが分かるので、読む前に `max_download_gb` と比べる。超えるならそのソースは読まずに失敗とし (code は既存の語彙に合わせて決める)、次回に追いつく (ADR 0038)。
  認証は 1 時間で切れる構成があるので (GitHub Actions、読み取り専用ロールの `MaxSessionDuration`)、時間の上限も置く
- **権限**: `s3:ListBucket` と `s3:GetObject` だけ (読み取り専用。8 章の例外を増やさない)。`deploy/iam/readonly-role.yaml` に、バケットと接頭辞のパラメータを足し、
  その範囲だけを許す文を条件つきで作る (空なら作らない。`Resource: '*'` にしない)。ALB のログのバケットは SSE-S3 だけが使えるので、`kms:Decrypt` は足さない
- **doctor**: `permission` (一覧 1 件と、最新のファイル 1 つの読み取り)、`match_rate` (最新のファイルの先頭 100 行)、`freshness` (最新のファイルが古ければ warn)、
  `cost` (直近 24 時間の一覧からファイル数と圧縮後の量を読まずに測り、GET とデータ転送の概算と `max_download_gb` の推奨値を出す。AWS の外で動かすと転送料が出ることを書く)
- **利用者の準備**: ALB のアクセスログを有効にする (同じリージョンのバケット、`logdelivery.elasticloadbalancing.amazonaws.com` に `s3:PutObject` を許すバケットポリシー、暗号化は SSE-S3)。
  CDK なら `ApplicationLoadBalancer` の `logAccessLogs(bucket, prefix)` (スタックにリージョンの指定が要る)、Copilot なら environment の manifest の `http.public.access_logs`
  (`true` ならバケットも作られる。Copilot 自体はサポート終了が告知されている)。そのうえで読み取り専用ロールのスタックにバケットを渡して更新する
- **対象外**: ALB の前に CloudFront などのプロキシがある構成 (ALB のログの送信元がプロキシの IP になり、IP ごとの判定ができない)。WebSocket は接続が閉じたときの 1 行だけ

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

決定 (ADR 0038): 窓は全ソース共通だが、失敗したソースは stats の `source_covered_to` の位置から次の run で追いつく (`max_catchup` まで)。追いついた run は stats の `catchup_from` と `SOURCE_CATCHUP` の WARN で分かる。集計のソースが遅れたらチェックの窓も広げる。

決定 (実行が遅れた時の窓): `run` の窓は通常 `[now - window, now)` だが、同じ profile の直近の ok / partial な run があれば
From = min(now - window, 前回の window_to) として、cron の遅延・欠落で空いた期間を取りこぼさない。追いつきは `profiles.<name>.max_catchup` (既定 7d) まで。
超えた分は諦めて From = now - max_catchup とし、`RUN_MISSED` のログに `gap` と `covered_from`、`truncated: true` を添える。
失敗した run (status=failed) は前回として数えない。前回から周期の 2 倍以上空いた場合も `RUN_MISSED` を警告する (追いつけた場合は `truncated: false`)。
`init` のベースライン収集の窓は `init --window` (既定 7d)。

決定 (記録の遅延と再走査。ADR 0013): CloudTrail はイベントの記録まで通常 5〜15 分、CloudWatch Logs は取り込みに数分遅れる。
窓の終わり To は now のまま記録し (次回の From になる)、**各ソースの収集範囲は `[From - ingest_delay, To)`** とする (前回の窓の末尾を遅延分だけ再走査する)。
`sources[].ingest_delay` は ParseDuration 形式で、既定は cloudtrail-lookup = 15m、cloudwatch-logs = 5m (`0` で再走査しない)。
決定 (ADR 0041): `d` (日) で書ける上限は time.Duration に収まる日数 (約 292 年)。超える値は桁あふれで別の長さになる (`213504d` が 25 分になった) ので、エラーにする (aratam の `max_age` も同じ)。

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
  hourly: { window: 1h,  checks: [root_usage, unknown_assume_role, secret_access_unknown, guardduty_high] }
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
  `checks:` に書いた値がこの版の既定値と違うパラメータ (`param_changed`)、雛形が必ず書くのに設定に無いキー (`missing_key`。`audit_account`。ADR 0045)、arata が知らないキー (`unknown_key`)。設定は Load せずに緩く読む (未知のキーで読めない設定にも使える)。
  `checks:` に書いていないパラメータは実行時にこの版の既定値が効くので差分にしない。overrides は意図した上書きなので比べない。
- 決定 (ADR 0045): `arata config init` は **監査する側のアカウント** を `--audit-account` で必ず選ばせる (既定は無い。無ければ 2 つの選択肢を示して `CONFIG_INVALID`)。
  - `--audit-account <12 桁の ID>`: 別のアカウントのロールが、監査対象の読み取り専用ロールを引き受けて監査する。設定に `audit_account: "<ID>"` を書き、
    既知リスト (`--out` と同じ場所の `allowlist.yaml`) の `principals` に `account: "<ID>"` を note つきで書く。ロール側の CloudTrail には呼び出し元の
    アカウント ID しか残らないので `account:` で書く。既にある既知リストには approve と同じ差し込み (ADR 0010) で末尾に足し、同じ項目があれば足さない。
    `approved_at` は今日 (UTC)。`approved_by` は `--by` を付けたときだけ (init は承認者を知らない。OS のユーザー名を既定にしない)。
    `dynamic_source` は書かない (principal_new_source が見るのは IAM ユーザーとロールで、外部アカウントそのものは対象でない)。`--out -` では既知リストを書かず、足す項目を標準エラーに出す
  - `--audit-account none`: 外から監査しない (同じアカウントの中で動かす・手元の認証で直接動かす)。設定に `audit_account: none` を書き、既知リストには書かない
  - `audit_account` は判定に使わない。承認は既知リストだけが持つ。`config check` と `doctor` が食い違いを確かめる: ID を書いたのに期限内の `account:` の項目が
    既知リストに無ければ ng。`doctor` はさらに、その ID が監査対象のアカウントそのもの (`sts:GetCallerIdentity`) なら ng (`account:` が自アカウントの全主体を承認してしまう)
  - この項目より前の版で作った設定 (`audit_account` が無い) は `run` / `doctor` を止めない。`config check` は warn、`config init --diff` は `missing_key` で知らせる。
    `config check` の規則は run / doctor の起動時の検証と同じ、という ADR 0042 の原則の例外 (run は止めず、PR の時点で止める)
- 決定 (ADR 0042): `arata config check` は、設定とそれが指す allowlist.yaml の形を **オフラインで** 検査する (AWS にもストアにも繋がず、認証も要らない)。
  PR の CI で allowlist.yaml の書き間違いをマージの前に止めるためのもの。規則は run / doctor が起動時にする検証そのもの
  (`config.Load`、`allowlist.Parse`、profiles のチェック名は `engine.UnknownChecks`) で、check のための規則は足さない。check が通した設定は run でも読め、逆も同じ。
  - `config init --diff` との関係: 目的が違うので両方を残す。`--diff` は「この版の雛形との差」を見る道具で、読めない設定にも使えるよう緩く読み、
    差があっても終了コードは 0 (差は誤りではない)。`check` は「この設定で run が起動するか」を見る門で、厳密に読み、誤りがあれば終了コード 2。
    未知のキーと未知のチェック名は両方に出る (`--diff` では直し方を探す手がかり、`check` では止める理由)。
    入っていないチェックや既定値との差は `check` では見ない (誤りではないので、PR を止めない)
  - 出力は 1 行 1 件の `ok` / `warn` / `ng` / `skip` で、分かるときは「ファイル:行」を添える。allowlist の項目のエラーは項目の行、YAML の構文と型のエラーは yaml の示す行。
    設定の値の検証 (必須項目など) は行を持たない。`ng` があれば終了コード 2 (設定エラーの慣例。標準エラーにも `CONFIG_INVALID`)、`warn` だけなら 0
  - allowlist の同じ主体の重複は `warn`。run は重複を受け付ける (`expected_denied` は項目ごとに書けて和で判定する。6-1) のでエラーにすると規則が食い違う。
    ただし `expires`・`tags`・`dynamic_source` は 1 つの項目のものしか使われないので、片方だけ直した誤りに気づけるよう知らせる
  - allowlist.yaml が無いのも `warn` (run は空として動く。init の直後)。設定が読めないときは allowlist の場所が決まらないので `skip` と出す
  - 権限・ロググループ・ログの形式は見ない (`doctor` の仕事で、AWS に問い合わせる)
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
tools/actionsgate/            CI 用の Actions の検査 (SHA 固定・版の一致・7 日待機。ADR 0035)
tools/wordscan/               CI 用の禁止語の検査 (語の一覧は secrets から読む。ADR 0036)
docs/ai/*.md                  LLM 向けの使い方。embed でバイナリに入り `arata help ai [report|approve|runtime|onboarding|playbook <check>]` で出る (決定: skills/ の同梱は取りやめ。ADR 0012)
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
- 決定 (ADR 0022): acked / 期日前の snoozed でも、観測の重大度が ack / snooze したときの重大度 (`suppressed_severity`) より重ければ **changed** として再報告し open に戻す (全チェック共通)。Data に `escalated_from_suppressed: true`・`suppressed_status`・`suppressed_severity` を、Summary の先頭に「(確認済み (ack) だったが重大度が medium → high に上昇)」を付ける。event 型の recurred の条件と重なっても changed。重大度が同じか軽ければ suppressed のまま。Fingerprint の変化 (IP の増減) では解かない
- 判定に使う時刻は実行時刻 (now)。finding の `first_seen` / `last_changed` もこれで記録する。
- recurred の境界は `last_seen < 今回の窓の From` (last_seen は前回観測した run の実行時刻)。前回の窓と今回の窓が連続していれば still_open、途切れていれば recurred。
  From は再走査 (3 章、ADR 0013) を含まない本来の From。

## 5. ストア設計

### 5-1. 二層構造

- `raw/<source>/<YYYY-MM-DD>.jsonl` — collect が取得した正規化レコード・集計の原本。追記のみ。人が読め、S3 へそのまま退避できる。
- `audit.sqlite` — raw から再構築可能な派生物。差分判定と期間集計のためのインデックス。`arata rebuild` で raw から作り直せる (ただし raw に無いものがある。5-4)。
- `allowlist.yaml` — 人が承認した既知リスト。**git 管理**。エンジンは読むだけ (approve コマンドは書く)。

バックエンドは 2 種類。`dir:///var/lib/arata/<name>` (オンプレ) と `s3://bucket/prefix` (GitHub Actions など毎回消える実行環境。5-5)。
SQLite ファイルは数十 MB 程度に収まる想定 (集計のみ保存するため)。

### 5-2. テーブル

| テーブル | 主なカラム | 用途 |
|---|---|---|
| `runs` | id, profile, window_from, window_to, started_at, status, stats | 実行履歴。欠損 (走らなかった日) の検出にも使う |
| `principals` | arn, kind (user/role/assumed-role/root), first_seen, last_seen, status (unknown/approved/expired/baseline) | 主体の初出判定。決定: `init` のベースライン収集で初出した主体は `baseline` とし new_principal の対象外。evaluate 時に allowlist から approved / expired を同期する |
| `principal_ips` | arn, ip, country, first_seen, last_seen, count | 主体 × IP の初出判定。決定: count は各 run の窓 [From, To) の件数の和 (再走査の重なり区間は行を初めて作るときだけ数える。3 章) |
| `events` | time, source, name, principal_arn, ip, region, resource, data | 「注目イベント」のみ (ルート利用、IAM 変更など)。全 CloudTrail は保存しない。決定: 注目の判定は collector 側 (`cloudtrail.DefaultNotable`) で行い、ルート利用・AssumeRole*・IAM / CloudTrail / GuardDuty / Access Analyzer / Organizations の書き込み・秘匿値取得・SSM セッション・公開設定変更を残す。決定: defense_evasion / public_exposure が見る操作 (ログの削除・保持期間、フローログの削除、Config・Security Hub の停止、WAF のログ設定、S3 のバケットポリシーの削除・ライフサイクル、スナップショットの共有、Lambda の AddPermission など) だけを足し、全書き込みは足さない。一覧はチェック側 (`checks.DefenseEvasionAPIs` / `PublicExposureAPIs`) にあり、collector のテストで突き合わせる。該当する操作だけ requestParameters から判定に要る値を `data` に取り出す (ポリシー全文は残さない。ADR 0026)。決定: 拒否された呼び出し (errorCode が `checks.access_denied.error_codes` に入るもの) も読み取りを含めて残す (access_denied の元。コードは設定から `cloudtrail.NotableWith` に渡す。ADR 0021)。決定 (ADR 0027): 秘匿値の読み取り (GetSecretValue・BatchGetSecretValue・GetParameter(s)・GetParametersByPath) は名前 / ARN・パス・`recursive`・`with_decryption` (常に残す。無いのは以前の版で集めたもの) だけを `data` に取り出す (値は CloudTrail に入らない)。BatchGetSecretValue も注目イベントに足した (一覧は `checks.SecretReadAPIs`)。`event_id` で重複を排除する (複数リージョンを引いた場合の二重も同じ仕組みで防ぐ。collector 側でも同一 Collect 内の event_id は 1 回だけ数える)。決定: `collected_at` (最初に収集した run の時刻) を持ち、再走査で遅れて届いたイベントを見分ける (3 章、ADR 0013)。決定 (ADR 0032): `cloudtrail-unused-regions` のソースは、ふだん使わないリージョンの AWS のサービス以外の主体の書き込みを (失敗を含めて) すべて残す (使っていないリージョンでは 0〜数件)。source 列がそのソースの ID で、unused_region_activity だけが見る (他のチェックの Query は除く) |
| `metrics` | date, source, metric, key, value | 日次集計 (`sign_in_failures` by ip、`admin_404` by ip、`waf_block` by rule)。平常帯の計算元。決定: 集計元のレコード種類 `from` 列を追加。主キーは (date, source, metric, key) で、後から来た値で**置き換える** (3 章の決定により後の値ほど完全)。raw JSONL には追記されるので rebuild は行順に適用すれば同じ結果になる (ソースが主キーに入るので、ソースの中の日付順・行順で足りる。5-4)。日は UTC。決定 (ADR 0027): cloudtrail collector も主体の活動の日次集計を出す: `principal_source` (key `<主体 ARN>\|<送信元の /24・/48>`)、`principal_source_writes` (同じ key の成功した書き込み)、`principal_write_region` (key `<主体 ARN>\|<リージョン>` の成功した書き込み)。対象は IAM ユーザーとロール (のセッション)、送信元は IP のときだけ。cloudtrail は日の頭から引き直さないので、置き換えの規則のため値は「その日を最後に引いた run が見た件数」(下限) になる。判定は「その日に有ったか」と下限値にだけ使う。期間レポートの推移表には出さない。Yields に metric は足さない (http_access / waf_action のチェックの skip 判定を変えないため)。行数の見積もり: 1 日あたり (主体数 × その日の送信元の数) × 2 + (主体数 × 書き込みのリージョン数)。主体 50・送信元 2 なら 1 日 250 行、400 日で 10 万行 (数十 MB 未満)。Lambda などサービスが引き受けるロールは送信元が多く、数十のロールが 1 日数十の /24 を使う環境では年 100 万行に近づく。多ければ prune を入れるときに `principal_*` の保持を baseline_days の数倍 (例 90 日) に短くする (判定は 30 日しか見ない)。決定 (ADR 0030): cloudwatch-logs の http_access のソースは endpoint_abuse の画面ごとに `endpoint_abuse_count` / `endpoint_abuse_ips` (key `<画面>\|<HH:MM>`。時間幅の始まり、UTC)、`endpoint_abuse_ua_ips` (key `<画面>\|<HH:MM>\|<UA のハッシュ>`。その幅で最も多くの IP にまたがった UA 1 つ、2 IP 以上のときだけ)、`endpoint_abuse_follow` (key `<from>><to>\|<HH:MM>`。1 以上のときだけ) を出す。IP と UA の原文は保存しない。行数の見積もり: 1 日あたり最大で画面数 × 144 (10 分幅) × 3 + 連鎖数 × 144。画面 3・連鎖 1 で 1 日最大 1,440 行、400 日で 58 万行 (実際は来訪のある幅だけなのでずっと少ない) |
| `findings` | id, check, key, severity, first_seen, last_seen, last_changed, status (open/resolved/acked/snoozed), reported_at, fingerprint, data, suppressed_severity | 差分判定の中核。決定: `fingerprint` 列を追加 (4-2)。決定: `suppressed_severity` (ack / snooze したときの重大度。open / resolved では空) を追加 (schema 5、ADR 0022)。移行では既存の acked / snoozed の行に今の severity を入れる |
| `posture` | check, resource, value, first_seen, last_changed | 姿勢チェックの現在値。決定: 作らず `snapshot_items` にまとめた (ADR 0015) |
| `snapshot_items` | kind, source, key, data, collected_at | 決定: アカウント単位の状態 (認証情報レポート・GuardDuty・Access Analyzer・姿勢・WAF の WebACL の設定) の最新のスナップショット。収集が成功したときだけ (kind, source) 単位で丸ごと置き換える (ADR 0015)。決定 (ADR 0033): 置き換えたら raw に `snapshot_replaced` の行 (置き換えた収集の時刻と件数) を書く (0 件の置き換えと失敗した収集を rebuild が見分ける) |
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

### 5-4. 再構築 (`arata rebuild`)

決定 (ADR 0033): `arata rebuild` は raw から作れる表だけを作り直し、raw に無いものは既存の `audit.sqlite` から引き継ぐ。

| 表 | raw から | 作り直し方 |
|---|---|---|
| `events` | 作れる | event_id ごとに最初に収集した行 (collected_at が最小。同じ run なら設定で先のソース) を残す。InsertEvent の INSERT OR IGNORE と同じ結果 |
| `principals` / `principal_ips` | 作れる (状態を除く) | first_seen / last_seen は保存と同じ文字列の MIN / MAX。count は Count の和に、(arn, ip) の行を最初に作った記録の rescan_count を足す (ADR 0013)。「最初」は (collected_at, 設定のソースの順, 行順) |
| `metrics` | 作れる | ソースごとに日付順・行順に置き換える |
| `snapshot_items` | 作れる | (kind, source) ごとに、最後の `snapshot_replaced` の収集の項目 |
| `runs` / `findings` / `finding_events` / `meta` | **作れない** | 既存の SQLite から引き継ぐ (ack / snooze・`suppressed_severity`・reported_at・期間レポートの履歴を含む) |
| `principals.status` | **作れない** | ARN ごとに既存の SQLite から引き継ぐ。既存に無い主体は unknown (次の run が allowlist と同期する) |

- 決定: raw の行の版の違い。`principal_seen` の `collected_at` と `snapshot_replaced` は ADR 0033 で足したもので、以前の版の raw には無い。
  無いときは時刻の順 (principal_seen) と時刻が最大の収集 (スナップショット。失敗した収集を含み得る、0 件の置き換えは再現できない) で近似し、警告に出す。
  `trail_event` の `collected_at` が無い行 (schema 3 より前の収集) は '' として最も古い扱い (今の SQLite と同じ)。
  知らない種類の行と読めない行 (書き込み途中で止まった最後の行など) は飛ばし、件数と場所 (`raw/<source>/<日付>.jsonl:<行>`) を出す
- 決定: 既存の SQLite は Open と同じ移行 (schema_version) を通してから読む。無い・読めないときは `STORE_CORRUPT` で止め、`--from-scratch` を案内する
- 決定: `--from-scratch` は既存の SQLite を読まない (壊れていてもよい)。runs・findings・finding_events・meta は空から。次の run で未解決の finding が全部 new として
  再報告されるので標準エラーに警告を出す。主体は既定で unknown (監査の安全側。一度全部報告され人が片付ける)、`--baseline` なら baseline (init と同じ扱い)。
  `--baseline` は `--from-scratch` のときだけ使える
- 決定: 一時ファイル (`audit.sqlite.rebuild-tmp`、journal は DELETE) に作り、元のファイルを `audit.sqlite.bak` にハードリンク (できなければコピー) してから
  rename で入れ替える。途中で失敗・中断しても `audit.sqlite` は元のまま。`.bak` は 1 世代 (次の rebuild で上書き)。ロック (`audit.lock`) を取ってから行う
- 決定: rebuild の規則と記録の規則の一致は、engine を通したテスト (`internal/engine/rebuild_test.go`) で「run を重ねたストアと rebuild したストアの全テーブルが一致する」として固定する

### 5-5. S3 ストア (`store: s3://<bucket>/<prefix>`)

決定 (ADR 0034): 実行のたびに一時ディレクトリへ作業用の複製を出し入れし、読み書きは `dir://` の実装がそのまま担う。`s3://` と書いたときだけ有効で、`dir://` の動きは変わらない。

決定 (ADR 0041): prefix に空の区間 (`//`、先頭の `/`) があればエラー。末尾の `/` 1 つは外す。検査は外す前に行う (`s3://b/p//` を通さない)。

| オブジェクト (prefix の下) | 取得 | 書き戻し |
|---|---|---|
| `audit.sqlite.gz` | 開始時 | 最後に。書けたら確定 |
| `raw/<source>/<日付>.jsonl` | その日のファイルに初めて追記するとき | 変わったものだけ、丸ごと置き換え |
| `reports/<profile>.{json,md}` | 開始時 | 変わったものだけ |

- 決定: 書き戻しはすべて条件付き (`If-Match: <開始時の ETag>`、開始時に無ければ `If-None-Match: *`)。先に SQLite の ETag を HeadObject で確かめ、raw・reports、SQLite の順に送る。
  別の実行が先に書いていたら `STORE_CONFLICT` (終了コード 2) で失敗し、何も上書きしない。もう一度実行すればよい
- 決定: 確定は `Engine.Commit` が行い、書き込み系のコマンド (`init` / `run` / `collect` / `evaluate` / `approve` / `ack` / `snooze` / `resolve`) が成功したときだけ呼ぶ。`rebuild` は自分で書き戻す。
  呼ばずに終われば (失敗・中断・パニック、読むだけの `report` / `review`) S3 は開始前のまま。一時ディレクトリは最後に消す
- 決定: `run` の partial は Commit する。`init` は中断・部分失敗でも Commit する (`--resume` のため)。Commit に失敗したら、その実行の収集が失われたことと再実行の手順を出す
- 決定 (ADR 0038): レポートの出力は 2 段にする。`--out` の一時ファイルまでを準備し、saveReport・報告済みの印・Commit の後に rename で公開する。
- 決定: `run` / `evaluate` は Commit してからレポートを出す。衝突したら `--out` に何も書かないので、aratam が入力の問題として知らせる (`docs/aratam.md` 2 章)
- 決定: S3 に問い合わせられない (権限・通信) ときは `STORE_UNAVAILABLE`。404 だけを「まだ無い」と扱う
- 決定: S3 に SQLite が無いのに raw があれば、消えた可能性が高いので `init` / `run` / `collect` / `evaluate` / `approve` / `ack` / `snooze` / `resolve` は `STORE_CORRUPT` (終了コード 2) で止め、`arata rebuild --from-scratch` (とバージョニングからの復元) を案内する。
  続けると空の SQLite を Commit して findings・承認・ack の状態を空で上書きし、次からは気づけない。止まれば aratam が「実行されていない」と知らせる。`init` も止める (raw があるのに init するのは rebuild の誤用の可能性が高い)。`report` / `review` は警告して続け、doctor は `store_read` を ng にする。`rebuild` は止めない。
  最初の `init` で SQLite の送信だけが失敗したときも同じ状態になる。そのときは `arata rebuild --from-scratch --baseline` で、収集した主体を baseline にして続ける
- 決定: raw だけが先に進む (SQLite の書き込みが失敗する) ことは受け入れる。次の run は古い SQLite から同じ窓を引き直すので SQLite では二重に数えない。
  rebuild でも events・metrics・スナップショットは同じ結果で、`principal_ips.count` だけが増え得る (判定に使わない。ADR 0011・0034)
- 決定: `rebuild` は raw を全部取得して作り直し、SQLite だけを条件付きで置き換える。`.bak` は残さない (世代はバケットのバージョニング)
- 決定: バケットの認証は `store_profile` (省略時は SDK の標準の連鎖) と `store_region` (省略時は `aws.region`) で監査対象の `aws:` と分ける
- 決定: 「読み取り専用」は監査対象のアカウントへの約束で、ストアのバケットは別 (8 章)。必要な権限は `s3:GetObject`・`s3:PutObject`・`s3:ListBucket` で、prefix に限定する

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
  - arn: arn:aws:iam::123456789012:role/ai-investigation-readonly
    tags: [ai]
    note: 個人情報を含むロググループは IAM で Deny している。その読み取りの拒否は想定内
    expected_denied: ["logs:StartQuery", "logs:GetLogEvents", "logs:FilterLogEvents"]  # access_denied で数えない拒否 (ADR 0022)
    approved_by: alice
    approved_at: 2026-11-03
source_ips:
  - cidr: 203.0.113.0/24
    note: 本社オフィス
admin_users: [113, 2048]         # アプリ層の管理者 ID
secrets_access:
  - principal: arn:aws:iam::...:role/ProdEcsTaskRoleMyApp
    secrets: ["prod/db/*"]
assume_destinations:             # 外向きの引き受けで、行き先として既知のアカウント (ADR 0047)。principals (呼び出し元) とは別
  - account: "111122223333"
    note: 運用を受託しているアカウント
    approved_by: alice
    approved_at: 2026-11-13
    expires: 2027-03-31
```

決定: `allowlist.yaml` が無い場合は空のリストとして扱う (init 直後の運用を許す)。主体 ARN の突合は完全一致。AssumedRole 主体はセッション ARN ではなくロール ARN (`sessionContext.sessionIssuer.arn`) に正規化してから突合する (セッション名に個人名やメールが入るため)。
決定 (ADR 0041): userIdentity の種類が知らないものでも、ARN がセッションの形 (`arn:aws:sts::<アカウント>:assumed-role/<ロール>/<セッション>`) ならロール ARN に寄せる。アカウントの欄が無い壊れた ARN は寄せない。

決定 (principals の指定方法。Step 2):
- 1 エントリの主体の指定は `arn` (完全一致) / `account` (12 桁の文字列。そのアカウントの全主体を承認。監視 SaaS など SaaS 連携用) / `arn_pattern` (glob。`*` は `/` や `:` も含む任意の文字列、`?` は 1 文字) のどれか 1 つ。
  決定 (ADR 0041): glob (`arn_pattern`・`expected_denied`・`secrets`) は UTF-8 として不正ならエラーにする (不正なバイト列どうしが同じものとして一致するため)。
- 複数のエントリに一致するときは、有効な (expires 前の) 承認が 1 つでもあれば approved。返すエントリ (タグの判定に使う) は有効なもののうち最も具体的なもの (arn > arn_pattern > account)。一致したものが全部期限切れなら expired。
- CloudTrail の `userIdentity.type` が `AWSAccount` (他アカウントからのクロスアカウント AssumeRole) の主体は `arn:aws:iam::<アカウント>:root` (kind は unknown) に正規化される。
  レポートの文面ではこれを「外部アカウント NNN」と書き、Data に `external_account` を添える。自アカウントの Root (kind=root、root_usage が扱う) とは区別する。
- 決定 (呼び出し元がアカウントしか分からない主体): 上の `arn:aws:iam::NNN:root` はアカウントそのものを指す ARN で、そのアカウントのルートユーザーが使われたことを表さない
  (引き受けられた側の CloudTrail には呼び出し元のアカウント ID しか残らない。正規の CI や SaaS のロールも同じ形)。
  内向きの unknown_assume_role で、読む人と LLM が「NNN の root から引き受けられた」と読み、ルートユーザーの利用として緊急に扱ったことがあったため、次のとおり区別する。
  - finding の data に、`external_account` と並べて `caller_identity: account_only` (unknown_assume_role) / `principal_identity: account_only`
    (new_principal・access_denied・secret_access・principal_new_source) を足す (`checks.markAccountOnly`)。
    `caller_kind` などの主体の種類 (user / role / assumed-role / root / service / unknown) は変えない。種類の語彙に「分からない範囲」を混ぜず、approve が種類として読む値を保つため
  - unknown_assume_role の見出しは「既知リストに無い外部アカウント 111122223333 (呼び出した主体は記録に無い) が自アカウントのロール Admin を 3 回引き受け (内向き、MFA 不明)」。
    ARN の末尾の `root` を表記に使わない (呼び出し元もロールも自アカウントなら「自アカウント (呼び出した主体は記録に無い)」)
  - report.md は、その finding の data の値がその ARN そのものなら「外部アカウント NNN (呼び出した主体は記録に無い)」と書く (`schema.Finding.AccountOnlyText`)。
    見分けるのは `external_account` (この決定より前の版が作った finding にもある。still_open は data を書き換えない)
  - Key・Fingerprint・data の `caller` / `principal`・report.json の値は ARN のまま。変えると既存の ack / snooze・既知リスト (`account:`)・approve の対象との一致が外れ、
    open の finding が一斉に解消 + 新規になる。却下: Key を `account:NNN->...` に変える (移行が要り、得るものは表記だけ)、`caller_kind` を `account_only` にする (上の理由)
  - LLM の要約の側の守りは aratam (aratam 設計書 3 章。プロンプトと、出力の置換・検査)
- 決定: `userIdentity.type` も `arn` も無い記録は、`invokedBy` があればそのサービス、`sourceIPAddress` か `userAgent` が `AWS Internal` なら `eventSource` のサービスを主体 (kind=service) にする。
  監査対象アカウントの accountId だけが入った ECR の `PolicyExecutionEvent` などが、自アカウントの `:root` (unknown) として new_principal に出るのを避けるため。
  サービスの主体は principal_seen にも new_principal にも出ない。本物の root は `type=Root` で root_usage が扱う。`type=AWSAccount` の外部アカウントは従来どおり `外部アカウント NNN`。
- 決定: AWS のサービスが主体 (root・ロールなど) の代わりに呼んだ記録 (`sourceIPAddress` がサービス名で IP が無い。`userIdentity.invokedBy` も同じ名前) は、
  どのサービス経由かを events の `data.invoked_by` に残す (`invokedBy` を優先、形に合わなければ `sourceIPAddress`。サービスの主体の記録には足さない)。
  root_usage は送信元の IP が無いとき、見出しを「… が AWS のサービス (`<名前>`) 経由で N 件の操作」とし、finding の data に `invoked_by` (一覧) を出す。
- 決定 (unknown_assume_role の向き): 引き受けの向きを規則で決め、見出しと data (`direction`: outbound / inbound / internal、`caller_account`、`role_account`) に出す。
  見出しは「既知リストに無い自アカウントの user/alice が外部アカウント 111122223333 のロール partner-admin を 1 回引き受け (外向き、MFA あり)」の形。
  向きが無いと、読む人と LLM が「外部の主体が監査対象のロールを引き受けた」と逆に読むことがあったため。
  - 監査対象のアカウントは、記録の `recipientAccountId` (その記録を受け取ったアカウント = 証跡のアカウント。CloudTrail の文書「record contents」) とする。
    collector が 12 桁の数字のときだけ events の `data.recipient_account` に残す。設定には書かせない (暗黙の既定も足さない。記録ごとに決まる値で足りる)。
    呼び出し元のアカウントは主体の ARN、ロールのアカウントは `requestParameters.roleArn` (無ければ `resources[0].ARN`) から読む。
  - 外向き (outbound): 呼び出し元 = 監査対象、ロール = 別のアカウント。内向き (inbound): 呼び出し元 = 別のアカウント、ロール = 監査対象。内部 (internal): どちらも監査対象。
  - `recipientAccountId` が無い記録 (以前の版で集めたイベントなど) は、AWS の文書 (IAM ユーザーガイド「Logging IAM and AWS STS API calls with AWS CloudTrail」) にある記録の形から決まるときだけ決める:
    同じアカウントどうしは内部 (そのアカウントにしか記録されない)、呼び出し元が `type=AWSAccount` (アカウント ID と principalId だけ。ロール側の記録の形) なら内向き、
    呼び出し元が IAM ユーザーの ARN (呼び出し側の記録の形) なら外向き。ロールからのクロスアカウントは決めない。
  - 決めないとき (推測しない): ARN が決まった形 (12 桁のアカウント、IAM が許す名前の文字、128 文字まで) でない、`recipientAccountId` が呼び出し元とロールのどちらのアカウントでもない、
    上の記録の形と食い違う、1 つの finding のイベントで `recipientAccountId` が揃わない。このとき見出しは従来の形 (ARN のまま) で、`direction` は出さない。
    同じ文書の呼び出し側の記録の例は `recipientAccountId` がロール側のアカウントになっており、定義と合わない。この形の記録は「食い違い」として向きを書かない側に倒れる。
  - 却下: 設定にアカウント ID を書かせる (記録にある値と二重になり、書き忘れ・書き間違いで向きが逆になる)。`sts:GetCallerIdentity` で引く (hourly の収集に API 呼び出しを足す。組織の証跡では実行アカウントと記録のアカウントが違いうる)。
- 決定 (unknown_assume_role の MFA): data に `mfa` (true / false / unknown / mixed) を出し、見出しに「MFA あり / なし / 不明 / の有無が混在」を付ける。
  - あり: 呼び出しに MFA デバイスを指定した (`requestParameters.serialNumber` がある。STS の AssumeRole は MFA を `SerialNumber` と `TokenCode` で渡し、CloudTrail の記録には呼び出し側・ロール側とも `serialNumber` が載る)、
    または呼び出し元のセッションが MFA で認証済み (`userIdentity.sessionContext.attributes.mfaAuthenticated` が `true`。一時的な認証情報とコンソールのセッションに載る)。
  - なし: `mfaAuthenticated` が `false` と記録にあり、`serialNumber` が無いときだけ。
  - 不明: どちらの項目も無い (長期のアクセスキーでの呼び出し、ロール側の記録など)。項目が無いことを「なし」と書かない。
  - mixed: 1 つの finding のイベントで判定が揃わない (1 件の「あり」で全体を「あり」と書かない)。
  - `serialNumber` の値は残さない (MFA デバイスの ARN に利用者名が入る)。collector は AssumeRole* のときだけ、有無を `data.mfa_serial: true` に残す。
- 決定 (unknown_assume_role の送信元): collector は `sourceIPAddress` が IP ならそのまま残し、チェックは finding の `ips` に出す (落としていない)。`ips` が無いのは、
  記録の送信元が AWS のサービス名 (`AWS Internal` など) で IP が無いとき。このとき root_usage と同じく `invoked_by` (経由したサービスの一覧) を出し、IP が無い理由が分かるようにする。
- 決定: unknown_assume_role の Key と Fingerprint は変えない。向きは Key (呼び出し元とロール) から決まる。MFA を Fingerprint に足すと、既存の finding が一斉に changed になる。
  IP もサービス名も無ければ「IP の記録の無い送信元から」。以前は「… が  から N 件」と崩れ、読む人と aratam の LLM が送信元不明の操作と受け取った。
  Key・重大度・Fingerprint は変えない (表示だけの変更。既存の finding は changed にならない)。IP があるときの見出しと data も変えない。
  送信元を見出しに書く他のチェック (principal_new_source・login_bruteforce など) は、送信元が空なら句ごと出さないので崩れない (確認済み)。
- 決定 (ADR 0037・0041): サービス名はログ由来の値なので、見出しと data に出すのは決まった形だけ (`record.ServiceName`)。`AWS Internal` か、
  `<名前>.amazonaws.com` (小文字の英数字・`.`・`-`、64 文字まで)。形に合わない値は捨てる (記法や改行を含む値を見出しに出さない)。ファズ `FuzzServiceName` で固定する。
  中国などのパーティションの `.amazonaws.com.cn` は対象外 (必要になったら足す)。
- 決定 (ADR 0027): 主体の項目の `dynamic_source: true` は「送信元が毎回変わる主体」(CI のランナーなど)。principal_new_source の low (新しい送信元だけ) を出さない (medium 以上は出す)。
- 決定 (ADR 0027): `secrets_access` は「主体 (ARN の完全一致) × 読んでよい秘匿値 (名前・パスの glob)」。secret_access は一致する秘匿値を初出に数えない (一括読み出しの数には数える)。シークレットの ARN はシークレット名の部分でも比べる。空の `secrets`・空の要素・`principal` の無い項目は読み込みエラー。
- `tags` の語彙は `deploy` (ADR 0008) と `ai` (決定: Step 3。監査ロール・AI 用の主体。ai_path_usage が利用を毎回 info に出す)。approve は語彙外のタグを拒否する。
- 決定 (ADR 0022): `expected_denied` は access_denied で数えない「想定済みの拒否」(「サービス:操作」の glob。`*` は任意の文字列、`?` は 1 文字、大文字小文字を区別)。
  主体に一致する期限内の項目すべての `expected_denied` の和で判定する (項目ごとに理由と期限が違ってよいため。タグの判定に使う項目の選び方と、同じ arn の重複の後勝ちは変えない)。
  期限切れの項目の分は除かない。空のリスト・空の要素・コロンの無いもの・空白を含むものは読み込みエラー。`expected_denied` を持つ項目は `note` が必須。
  項目そのものは主体も承認する (expected_denied のためだけに項目を作ると new_principal なども止まる)。
- 決定 (ADR 0047): `assume_destinations` は、外向きの引き受けで「行き先として既知のアカウント」。unknown_assume_role は、
  **外向き・行き先のアカウントが期限内で載っている・MFA あり (その組の全イベントで)** の全部を満たす引き受けだけを報告しない。
  知らない行き先、MFA なし・不明・混在、内向き、内部、向きが決まらない引き受けは今までどおり high。
  - `principals` の `account:` (呼び出し元として既知。そのアカウントの全主体を承認する) とは意味が逆なので、節を分ける。
    行き先を既知にしても呼び出し元は承認されず、呼び出し元を承認しても行き先は既知にならない
  - `account` (12 桁。必須) と `note` (必須) を書く。`roles` (任意) はロール名の glob (ARN の `role/` より後ろ。パスを含む。先頭から末尾までの一致) で、
    書けばそのロールだけに絞る。ARN や `arn_pattern` は書けない (アカウントを決めるのは `account` だけ)。`expires` は principals と同じ
  - 同じアカウントの項目は複数書ける (ロールごとに理由と期限を分けられる)。期限内の項目が 1 つでも一致すれば既知
  - 報告しなかった分は、行き先のアカウントごとに info で 1 行出す (Key は `known-destination:<アカウント>`。data に件数・`callers`・`roles`・`ips`)。
    黙って消さない。info は件数・通知に数えない。Fingerprint は固定 (顔ぶれが変わっても changed にしない)
  - 既知にした行き先なのに報告するときは、data に `destination_status` (approved / expired) を出し、見出しの括弧に理由
    (「行き先は既知だが、MFA ありと確かめられないので報告」「行き先の承認は期限切れ」) を足す。Key・重大度・Fingerprint は変えない
  - 却下した案「MFA があれば行き先に関係なく報告しない」: 知らないアカウントへの移動・MFA 後のセッションの奪取・本人の不正が見えなくなる。
    行き先を既知にしても、MFA 後のセッションの奪取は見えない (principal_new_source と、行き先のアカウント側の監査で補う)。契約が終わったら項目を消す
  - `config check` は重なる項目と期限切れを warn にする。`doctor` は監査対象のアカウントそのものを書いた項目を ng にする (sts:GetCallerIdentity で比べる)

### 6-2. 状態遷移

```
観測 ──(allowlist に無い)──> finding: open (new として報告)
   │
   ├─ arata approve <finding-id> --note "..." [--expires 2026-12-31]
   │     → allowlist.yaml に追記 (approved_by は OS ユーザーか --by)、finding は resolved
   │     → 追記後の allowlist で対象主体が承認済みになる他の finding (new_principal / unknown_assume_role) も resolved
   │     → git への commit は人が行う (--commit で代行も可)
   ├─ arata approve <finding-id> --destination --note "..." [--destination-role glob] [--expires 2027-03-31]
   │     → unknown_assume_role の外向き・MFA ありの finding の行き先のアカウントを assume_destinations に追記 (主体は承認しない)、finding は resolved (ADR 0047)
   │     → 同じ行き先への外向き・MFA ありの他の finding (ack 済みを含む) も resolved
   ├─ arata ack <finding-id>         → acked。再報告しないが週次の未対応一覧には残る (重大度が上がれば changed で再報告)
   ├─ arata snooze <finding-id> --until 2026-11-01   → 期日まで沈黙、期日に再報告
   ├─ arata resolve <finding-id>     → resolved。再び観測されたら new
   └─ 放置                              → still_open。週次の未対応一覧に残り続ける

allowlist.yaml を人が直接編集して承認 ──> 次の evaluate の冒頭で該当 finding を resolved (reason: allowlisted。行き先を足したときは known_destination)
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
- 決定 (ADR 0047): `approve <id> --destination` は、主体ではなく行き先のアカウントを `assume_destinations` の末尾に追記する (差し込み方は principals と同じ。節が無ければ末尾に足す)。
  対象は unknown_assume_role の外向きで MFA ありの finding だけ (MFA が無い・不明の finding は、行き先を足しても報告が続くので断る)。
  アカウントは finding の data (ログ由来) の `role_arn` から取り、12 桁のロールの ARN として読めて `role_account` と一致するときだけ書く。
  `--destination-role <glob>` (複数可) でロールに絞る (finding のロールに一致するものを求める)。`--account` / `--arn-pattern` / `--tag` / `--expected-denied` とは一緒に使えない。
  重なる項目が既にあれば拒否する。`review --format json` は、使える finding に `approve_destination` (行き先のアカウント ID) を出す。
- 決定 (ADR 0047): 行き先による一括解消も、同じ 2 か所 (approve の直後と evaluate の冒頭) でする。open / acked / snoozed の unknown_assume_role のうち、
  外向き・行き先が期限内で既知・finding の `mfa` が true のものを resolved にし、`resolved_reason: known_destination` と `allowlist_subject` を残す。
  ack 済みの finding も同じ (MFA が無い・不明のものは残る)。行き先を消す・期限が切れると、次の引き受けは new として報告される。
  報告しなかった分の info の行は、その行き先の期限内の項目が無くなったら resolved にする (`resolved_reason: destination_removed`)。
- 決定 (ADR 0022): access_denied は `approve <id> --expected-denied <glob>` (複数可) でだけ approve できる。主体 (外部アカウントの root なら `account:`) の項目を
  `expected_denied` 付きで追記し、finding は resolved にしない (次の run で除いて数え直す。event 型なので閾値を下回れば open のまま沈黙する)。
  主体の項目が既にあれば書き換えずに止まり、足す行 (`expected_denied: [...]`) をエラーに示す。`--expected-denied` を付けない approve は拒否する。
- 決定 (ADR 0022): ack / snooze はその時点の重大度を `suppressed_severity` に記録する。それより重い観測で再報告される (4-2)。
- `snooze --until YYYY-MM-DD` はその日の 0 時 (UTC) まで沈黙し、以後の再観測で new として再報告する。`resolve` / `ack` / `snooze` は resolved の finding には使えない。
- `review` は既定で open / acked を重大度の高い順 → 初出の古い順に出す。`--status` で snoozed / resolved も出せる。approve できるものは対象 (`approve`) を示す。`--format table|json`。

## 7. チェック一覧 (初期セット)

| チェック | 周期 | 必要レコード | 判定 | 重大度 |
|---|---|---|---|---|
| root_usage | hourly | trail_event | Root の利用 | critical |
| defense_evasion (決定: 当初の trail_tampering を置き換え。daily) | daily | trail_event | 監査・検知の仕組み (CloudTrail・GuardDuty・Access Analyzer・ログ・フローログ・Config・Security Hub・WAF のログ・証跡の宛先バケット) を止める・弱める操作の成功。決定: ADR 0026 | critical / high (deploy タグなら 1 段下げる) |
| unknown_assume_role | hourly | trail_event | 呼び出し元 ARN が allowlist に無い AssumeRole。決定: AWS サービス主体 (EC2 / Lambda がインスタンスロールを引き受けるもの) は対象外。向き (外向き / 内向き / 内部) と MFA の有無を見出しと data に出す (6 章の決定)。決定 (ADR 0047): 外向きで、行き先のアカウントが allowlist の `assume_destinations` に期限内で載っていて、MFA ありの引き受けは報告しない (行き先ごとに info で 1 行残す) | high (報告しなかった分の行は info) |
| secret_access (決定: 当初の secret_access_unknown を置き換え。daily) | daily | trail_event | 秘匿値 (Secrets Manager・SSM SecureString) の「主体 × 秘匿値」の初出と一括読み出し。決定: ADR 0027 | low / medium / high |
| guardduty_findings | hourly (High) / daily (他)。決定: Step 3 は weekly のみ (state) | guardduty | finding ID 初出、count 増加 | severity 準拠 |
| iam_changes | daily | trail_event | CreateAccessKey / CreateUser / Attach*Policy / Put*Policy / UpdateAssumeRolePolicy / CreateLoginProfile | medium (既知デプロイ主体なら info。決定: 既知デプロイ主体 = allowlist の principals で `tags: [deploy]` を持つもの) |
| access_denied | daily | trail_event | 拒否された API 呼び出しの主体ごとの種類 (幅) と件数 (量) が平常帯超え。権限の列挙の兆候。決定: ADR 0021 | 幅は medium (種類が多ければ high)、量は medium |
| console_login | daily | trail_event | 失敗が閾値超え、MFA 無し成功 | medium / high |
| new_principal | daily | principal_seen | allowlist にも principals にも無い主体。決定: principals.status が unknown / expired の主体を毎回観測する (承認されるまで still_open として残る)。root は root_usage が扱うので対象外 | medium |
| principal_new_source (決定: 当初の new_source_ip を置き換え。国の判定はしない) | daily | trail_event, principal_seen (+ 主体の活動の日次集計) | 既知の主体の初めての送信元 (/24・/48)・書き込みのリージョン。決定: ADR 0027 | low / medium / high |
| unused_region_activity (決定: 当初の foreign_region を置き換え) | daily | unused_region_event (`cloudtrail-unused-regions`) | ふだん使わないリージョン (有効なリージョン − cloudtrail-lookup の regions) での書き込み。決定: ADR 0032 | critical / high / medium |
| cost_anomaly | daily | cost_anomaly (`cost-anomaly`) | AWS Cost Anomaly Detection の異常を予想に対する増加の割合で。決定: ADR 0032 | high / medium |
| public_exposure (決定: 当初の network_exposure を置き換え) | daily | trail_event | SG の 0.0.0.0/0・::/0 開放、S3 の公開 (ポリシー・ACL・Public Access Block)、RDS PubliclyAccessible、スナップショット / AMI の公開共有、Lambda の Principal `*`。決定: ADR 0026 | high / medium / low (deploy タグでも下げない) |
| ssm_session | daily | trail_event | StartSession の主体が allowlist 外、または深夜帯 | medium |
| login_bruteforce | daily | http_access | sign-in 失敗の IP 別件数が平常帯 (14 日中央値 × 係数) 超え、Top IP 初出 | medium |
| probe_paths | daily | http_access | 機密パス探索の 403/404 が平常帯超え | low |
| endpoint_abuse | daily | http_access (+ ログの総行数 `lines_total`) | 設定した画面 (会員登録・メッセージ送信など) への時間幅 (既定 10 分) ごとの異なり IP 数・件数がふだん (過去の幅の p99) 超え、「A の画面のあと B の画面」の連鎖がふだん超え。決定: ADR 0030 | medium / low |
| request_burst | daily | http_access | IP 別件数が平常帯超え (決済画面など除外パスを設定可) | low |
| waf_block_trend | daily | waf_action | 新規に鳴り始めたルール、Top IP 入れ替わり | low |
| admin_ops_unknown | daily | regex (admin) | 実行ユーザーが admin_users に無い | high |
| ai_path_usage | daily | principal_seen (決定: trail_event ではなく主体 × IP の観測を使う) | allowlist の `tags: [ai]` を持つ主体の利用を主体 × IP で常に 1 行 (info) | info |
| credential_hygiene | weekly | iam_credential_report | 未使用キー 90 日超、MFA 無し、ルートのアクセスキー の増減 (決定: 古いパスワードは後続) | medium (ルートのキーは high) |
| access_analyzer | weekly | access_analyzer | ACTIVE な finding の増減 | medium (公開は high) |
| posture (決定: posture_* ではなく 1 チェックで項目ごとに finding) | weekly | posture_item | CloudTrail 有効・検証 ON、GuardDuty 有効、ルート MFA、S3 Public Access Block、パスワードポリシー、インターネット向けの ALB の WebACL | high (検証・パスワードポリシー・ALB の WebACL は medium) |
| waf_review | weekly | waf_config (+ 保存済みの waf_action の日次集計) | WAF の修正提案の候補を report.json の `proposals` に (finding ではない)。決定: ADR 0023 | 正規の画面での多数の IP の BLOCK だけ low |
| allowlist_stale | quarterly (report) | principals | 90 日未観測の approved 主体 | info |

決定 (Step 1 の 4 チェックの Mode と Fingerprint。ADR 0005):

| チェック | Mode | Key | Fingerprint |
|---|---|---|---|
| root_usage | event | `<root ARN>\|<ip>` | 重大度 + IP 集合 + MFA の有無 |
| unknown_assume_role | event | `<caller ARN>-><role ARN>` (報告しなかった分の info の行は `known-destination:<行き先のアカウント>`) | 重大度 + IP 集合 + allowlist 状態 (unknown / expired)。info の行は固定 |
| iam_changes | event | `<event name>\|<caller ARN>\|<対象>` | 重大度 + IP 集合 + 対象 + policy ARN (全件拒否のときは denied) |
| new_principal | state | `<ARN>` | 重大度 + IP 集合 + 種類 + allowlist 状態 |

決定: iam_changes は集約した呼び出しがすべてエラー (ErrorCode あり) のとき、変更は起きていないので見出しを「IAM 変更の試行 (拒否)」とし、Data に `denied: true` と `error_codes` を残す (重大度と Key は変えない。権限の無い主体が IAM を変えようとしたこと自体が指摘になるため)。成功が混ざるときは「IAM 変更」のまま `has_errors: true`。対象が取れないとき (拒否では requestParameters が記録されない) は表示を「不明」とする。Fingerprint は全件拒否のときだけ `denied` を足す (既存の finding の指紋は変わらない)。

決定 (アプリ層チェック。Step 2 の 3 つ。ADR 0005 の event 型):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| login_bruteforce | event | `<ip>` | 重大度 + 理由 (`above_baseline` / `new_top_ip`) | `sign_in_failures` の日次値が「その IP 自身の直近 14 日の中央値 × factor (既定 3)、ただし min_count (既定 20) 以上」を超えた。または閾値未満でもその日の最多 IP が過去 14 日に一度も無く、top_ip_min_count (既定 5) 件以上 |
| probe_paths | event | `<ip>` | 重大度 + 理由 | `probe_hits` について同上 (min_count 既定 10)。Data にその日の多かったパス (全 IP 合計の上位 5) を添える |
| waf_block_trend | event | `rule\|<ルール ID>` / `top_ip\|<IP>` | 重大度 + 理由 (`new_rule` / `new_top_ip`) | 過去 14 日に BLOCK の無いルールが new_rule_min_count (既定 1) 件以上 BLOCK した / その日の BLOCK 件数 Top N (既定 5、min_count 10 以上) に過去 14 日合計の Top N に居ない IP が入った |

決定 (endpoint_abuse。ADR 0030):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| endpoint_abuse | event | `<endpoint 名>` / 連鎖は `<from>><to>` | 重大度 + 理由 (`distributed_burst` / `volume` / `same_user_agent` / `follow_up`) | 時間幅ごとの異なり IP 数が `min_distinct_ips` (既定 10) 以上かつ平常帯 × factor (既定 3) 超えで medium。件数が `min_count` (既定 20) 以上かつ平常帯 × factor 超えで low (両方なら 1 件)。同じ UA が `ua_concentration.min_ips` (既定 5) 以上の IP にまたがり平常帯 × factor も超えれば根拠に添える (単独では報告しない)。連鎖した IP 数が `min_ips` (既定 5) 以上かつ平常帯 × factor 超えで medium |

- 決定: 既定は `endpoints` が空 = 何もしない (Insights のクエリも流さない。ADR 0014)。画面は利用者が設定で増やす (会員登録・ログイン・モバイルアプリの API など、数の上限なし)。画面ごとに数えるソースを `sources: [<ソース ID>]` で選べる (空なら http_access を出す全部。複数のソースが同じ画面を数えると件数が重なる)
- 決定: 今回は http_access のソース (nginx_access・alb_access・json・regex) だけ。wafv2 (ステータスが無く、UA はヘッダーの配列の中) と、アプリのログからの追加フィールド (メールのドメインなど) は次の段階。wafv2 のソースを `sources` に書くと「未対応」の読み込みエラー。対応するときは Needs を設定 (画面ごとのソース) から決める
- 決定: 結果は事実 (件数・異なり IP・同じ UA の広がり・ふだんの上限) として伝え、遮断の提案にしない。重大度は medium まで。IP は保存しない (件数だけ)。UA は sha256 の先頭 8 文字と IP 数だけ (原文は保存・ログ出力しない)
- 決定: 平常帯は評価する最初の日の前日から `baseline_days` (既定 14) 日のうち、ログを収集した日 (http_access のソースの `lines_total` のある日) の全部の時間幅の値 (無い幅は 0) の p99。`lines_total` はロググループ全体の行数なので、画面に来ない日も収集した日として数える (ADR 0027 の「収集し終えた日」の考え方。Web のログに行の無い日はほぼ無いので、run の stats に印を足す方式にはしない)。収集した日が `min_baseline_days` (既定 7) 未満の間は絶対の閾値 (`min_*`) だけで判定し、Data の `baseline_used: false` と Summary に出す。まれにしか使われない画面は p99 が 0 になり、閾値は `min_*` になる
- 決定: 評価する幅は終わりが窓 (From, To] に入るもの (完了した幅を 1 回だけ)。連鎖は幅の終わり + `within` が窓に入るもの (to に来るのを待つ)。窓が 0 時の近くで始まるときは前日の連鎖の幅を前回の run の値 (それより後の to を見ていない) で評価する
- 決定: 連鎖は同じソースの中で突き合わせる (from と to の画面を別々のソースで数えると連鎖は数えない。IP を保存しないため)
- 決定: 報告は run ごとに画面 1 件と連鎖 1 件。Summary は最も異なり IP の多い幅、超えた幅は Data の `bins` (最大 10、`bins_total`)
- 決定: パスはクエリを落とし、数字・UUID の区間を `:id` とみなして照合する (waf_review の正規化と同じ意味)。glob の `*` は 1 区間、`**` は 0 区間以上、`:id` (と数字だけの区間) は数字か UUID。Insights に正規表現の置換が無いので、glob を同じ意味の正規表現にして Insights の filter で絞る。`exclude_paths` も glob
- 決定: ログインのパスは login_bruteforce と重なってよい (login_bruteforce は IP ごとの失敗、こちらは画面全体への分散した集中を見る)

決定 (access_denied。ADR 0021):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| access_denied | event | `<主体 ARN>` | 重大度 + IP 集合 | 窓の拒否 (errorCode が `error_codes` に完全一致) を主体ごとに数える。拒否された API (`eventSource:eventName`) の種類が min_distinct_apis (既定 5) 以上かつ平常帯超えで medium、high_distinct_apis (既定 20) 以上で high。件数が max(min_count (既定 50), 中央値 × factor) 超えで medium。両方なら重い方を 1 件 |

- 評価するのは窓のイベント (再走査で遅れて届いた分を含む。ADR 0013)。UTC の日では分けない (日をまたぐ列挙が割れないように)。平常帯は窓の始まりの日の前日から baseline_days 日の、その主体自身の日ごとの件数・種類 (無い日は 0) の中央値 × factor。拒否のある過去日が min_baseline_days 未満なら平常帯 0
- 決定: 平常帯は丸 1 日と比べるので、daily (窓 24h) を前提とする。窓が 24h より短いプロファイル (hourly に入れた場合) では窓が短い分だけ鳴りにくい (いまは daily だけ。hourly は将来の課題)
- 決定: error_codes は保存 (events) の条件なので overrides では変えられない。後から足したコードは、足す前の拒否が保存されていないので平常帯 0 から始まる
- 決定 (ADR 0027 で見直し、変えない): 平常帯を使うかは「拒否のある過去日」で数えたまま (principal_new_source / secret_access の「収集し終えた日」にしない)。拒否の少ない主体は収集済みの日で数えても中央値 0 で同じ閾値になり、拒否の多い主体は拒否のある日が min_baseline_days に届くので結果は実質変わらない (足りない間は平常帯 0 = 絶対の閾値で、鳴りやすい側に倒れる)
- 決定 (ADR 0022): 想定済みの拒否 (allowlist の `expected_denied`。窓の終わりの時点で期限内の項目) は数える前に除く。窓にも平常帯の過去分にも同じく適用する (平常帯に残すと、ふだんの想定内の拒否で平常帯が膨らみ想定外の拒否を吸収するため)。窓で除いた件数は Data の `expected_denied_excluded`
- 決定: サービスリンクロール (主体の ARN が `:role/aws-service-role/` を含む。AWS のサービスだけが引き受け、権限は利用者が変えられない) の拒否は窓にも平常帯にも数えない。仕様由来のノイズ (例: AWS Config のロールが毎日多数の API で拒否される) で、盗んだ認証情報による権限の探索に当たらないため。どの利用者でも同じなので設定にせず固定の規則とする (ADR 0021 の延長)。events への保存は変えない
- サービス主体と root は対象外。allowlist で承認済みでも対象 (想定内の拒否は `expected_denied` で除く。主体ごと止めるなら ack / snooze だが、重大度が上がれば再報告される)。Data: principal, principal_kind, allowlist_status, external_account, principal_identity (`account_only`。主体がアカウントしか分からないときだけ), count, distinct_apis, expected_denied_excluded, apis (件数の多い順に最大 10 個、`iam:ListUsers × 3`), error_codes, ips, first_time, last_time, baseline_median_count, baseline_median_distinct, threshold (`breadth` / `volume`)

決定 (defense_evasion / public_exposure。ADR 0026):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| defense_evasion | event | `<サービス>:<操作>\|<主体 ARN>\|<対象>` | 重大度 + IP 集合 + 対象 + 理由 | 下の表の操作が成功した (errorCode なし) |
| public_exposure | event | `<サービス>:<操作>\|<資源>\|<開いた中身>` (例 `ec2:AuthorizeSecurityGroupIngress\|sg-0abc\|tcp/22 0.0.0.0/0`) | 重大度 + IP 集合 + 資源 + 開いた中身 | 下の表の変更が成功した。同じ資源を同じように開いた呼び出しは主体をまとめて 1 件 (Data の principals) |

| defense_evasion の操作 | 報告する条件 | 重大度 |
|---|---|---|
| cloudtrail: StopLogging / DeleteTrail | 常に | critical |
| cloudtrail: UpdateTrail | isMultiRegionTrail=false / enableLogFileValidation=false / s3BucketName の指定 (それ以外の変更は報告しない) | high |
| cloudtrail: PutEventSelectors | 管理イベントを減らす (基本形: includeManagementEvents=false・readWriteType が All 以外・excludeManagementEventSources。高度な形: Management のセレクタが無い・他の項目で絞る)。データイベントの追加だけなら報告しない | high |
| cloudtrail: PutInsightSelectors | 空にした | high |
| guardduty: DeleteDetector / Disassociate* / DeletePublishingDestination | 常に | high |
| guardduty: UpdateDetector | enable=false か features のどれかが DISABLED | high |
| guardduty: CreateFilter / UpdateFilter | action=ARCHIVE (自動アーカイブ) | high |
| access-analyzer: DeleteAnalyzer / CreateArchiveRule | 常に | high |
| logs: DeleteLogGroup / DeleteSubscriptionFilter | 常に | high (監査対象のロググループなら critical) |
| logs: PutRetentionPolicy | retentionInDays < `min_log_retention_days` (既定 90) | 同上。監査対象で arata の平常帯の日数 (login_bruteforce / probe_paths の baseline_days の大きい方) より短ければ Data に `shorter_than_baseline_days` |
| logs: DeleteLogStream | 監査対象のロググループだけ (アプリのストリームの整理はノイズ) | critical |
| ec2: DeleteFlowLogs / config: Stop・DeleteConfigurationRecorder・DeleteDeliveryChannel / securityhub: DisableSecurityHub・BatchDisableStandards / wafv2: DeleteLoggingConfiguration | 常に | high |
| wafv2: PutLoggingConfiguration | LoggingFilter がある (記録を減らせる) | high |
| s3: DeleteBucketPolicy / PutBucketLifecycle | 証跡の宛先バケット (設定の `trail_buckets` と保存済みの CreateTrail / UpdateTrail の宛先) だけ | high |

- 決定: CloudTrail には前の値が残らないので、「弱めた」かは要求の内容だけで判断し、判断できない変更は報告しない (状態は weekly の posture が見る)。保持期間は前の値の代わりに下限と比べる
- 決定: 監査対象のロググループは cloudwatch-logs のソースの log_group から自動で作る (`Config.AuditLogGroups`。checks: のパラメータにしない。Registry に `SetAuditLogGroups` で渡す)
- 決定: allowlist で `tags: [deploy]` の承認済み主体なら 1 段下げる (critical → high、high → medium)。info にはしない。Data に `known_deploy_principal`

| public_exposure の変更 | 条件 | 重大度 |
|---|---|---|
| ec2: AuthorizeSecurityGroupIngress | 0.0.0.0/0・::/0 の ingress で、ポート範囲が `sensitive_ports` (既定 22, 3389, 3306, 5432, 1433, 1521, 6379, 11211, 27017, 9200, 5601, 2375) に重なるか全ポート (protocol -1・0-65535) | high |
| 同上 | その他のポート・ICMP | low |
| ec2: ModifySecurityGroupRules | 同上。記録に向き (ingress / egress) が無いので 1 段下げ、Data に `direction_unknown` (既定の egress の編集を high にしないため) | medium / low |
| s3: PutBucketPolicy | Principal `*` / AWS `*` の Allow で、送信元・組織・アカウントで絞る条件キー (aws:SourceIp・SourceVpce・SourceVpc・PrincipalOrgID・PrincipalOrgPaths・PrincipalAccount・PrincipalArn・SourceAccount・SourceArn・SourceOrgID・SourceOrgPaths) が無い。aws:SecureTransport だけの条件は公開とみなす | high |
| s3: PutBucketAcl | AllUsers / AuthenticatedUsers への付与 (ACL の本文・x-amz-grant-* のヘッダー)、既定 ACL の public-read / public-read-write / authenticated-read | high |
| s3: Put(Account)PublicAccessBlock / Delete(Account)PublicAccessBlock | いずれかの項目が false (省略は false) / 削除 | high |
| rds: ModifyDBInstance / CreateDBInstance / ModifyDBCluster | publiclyAccessible=true | high |
| ec2: ModifySnapshotAttribute / ModifyImageAttribute、rds: ModifyDBSnapshotAttribute / ModifyDBClusterSnapshotAttribute | `all` (全員) の追加。特定アカウントへの共有は対象外 | high |
| lambda: AddPermission* (eventName に API の版が付く) | principal `*` で、functionUrlAuthType=NONE か送信元の条件 (sourceArn・sourceAccount・principalOrgID) が無い | medium |

- 決定: deploy タグでも下げない (公開は意図していても毎回見るべき)。止めたいときは ack (重大度が上がれば再報告される)
- 決定: 2 つとも成功した呼び出しだけを見る (失敗は access_denied)。注目イベントの追加で既存のチェック・principal_seen の結果が変わらないことをテストで固定する

決定 (principal_new_source / secret_access。ADR 0027):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| principal_new_source | event | `<主体 ARN>` | 重大度 + 新しい送信元の集合 + 新しいリージョンの集合 | 既知の主体 (allowlist で承認済み、または principals が baseline / approved) の窓の日 (UTC) の送信元・書き込みのリージョンが、窓の始まりの日の前日から `baseline_days` (30) 日に無い |
| secret_access | event | `<主体 ARN>` | 重大度 + 一括読み出しか + 初めて読む秘匿値の集合 | 窓の成功した秘匿値の読み取り (ssm は復号したもの) の初出と異なり数 |

- principal_new_source の重大度: 新しい送信元だけ → low。新しい送信元からの書き込み (窓の日の下限値の和) が `min_writes` (5) 以上、または新しいリージョンでの書き込み → medium。
  新しい送信元 + 同じ窓で access_denied の観測もある → high
- 決定: access_denied との相関は、principal_new_source の中で AccessDenied の Evaluate を同じ (store, 窓, allowlist) で呼んで得る (チェックは互いの結果を見られないため。順序にも依らない)。
  access_denied がプロファイルに入っていなくても相関の材料として呼ぶ (読むだけで、access_denied の finding は出さない。ADR 0014 の「設定に書いたものだけ動かす」は finding の話で、判定の材料は含まない)
- 決定: 導入直後 (CloudTrail を収集し終えた過去日が `min_baseline_days` (既定は baseline_days の半分) 未満) は報告しない。
  「収集し終えた日」は、stats に `trail_collected: true` のある run の窓の和で、日の全体が覆われた日を数える (init は stats の `done_until` まで)。
  engine は cloudtrail-lookup のソースの収集が成功した run と init のチャンクにこの印を付ける (CloudTrail を引かない weekly・CloudTrail が失敗した run には付かない)。
  収集済みで日次集計の無い日は「活動なし」。データ (日次集計) のある日で数えると、操作の少ないアカウント (漏れたキーが使われると目立つはずのアカウント) ほどいつまでも判定しないため。
  印の無い過去の版の run は数えないので、版を上げた既存のストアは 15 日経つまで報告しない (日次集計の無い過去を「活動なし」とみなして全部を新しいとしないため。init し直せば即時)
- 決定: 過去 `baseline_days` に活動が無く、その間に初めて現れた主体 (principals.first_seen が期間の始まり以降) は「すべてが初めて」なので報告しない (new_principal と承認の流れが扱う)。
  それより前から居て活動の無かった主体 (休眠していたキー) は報告する (`active_in_baseline: false`)
- 決定: allowlist の `source_ips` の内の送信元は新しい送信元にしない。allowlist の `dynamic_source: true` の主体と、AWS のサービスが引き受けるロール
  (保存済みの AssumeRole の呼び出し元がサービス主体。Lambda・ECS のタスク・EC2 のインスタンスプロファイル。`service_assumed: true`) は low を出さない (medium 以上は出す)。
  サービスのロールの送信元は AWS の管理する NAT などで毎回変わるため。持ち出したセッションの悪用は、書き込み・新しいリージョン・拒否で拾う
- 決定: 送信元が IP でないもの (サービス名・"AWS Internal") と root (root_usage が扱う)・サービス主体は数えない。リージョンは成功した書き込み (readOnly=false、errorCode なし) のあったリージョン
  (送信元が IP でない書き込みも数える)。LookupEvents で引くのは `cloudtrail-lookup` の `regions` だけなので、それ以外のリージョンは見えない (P-D の unused_region_activity で扱う)
- secret_access の対象: 成功した GetSecretValue / BatchGetSecretValue と、`with_decryption=true` の GetParameter / GetParameters / GetParametersByPath。サービス主体と root は除く
- secret_access の重大度: 初めて読む秘匿値 (窓の前 `baseline_days` (14) 日にその主体が読んでいない) → low。その主体が秘匿値を読むこと自体が初めて → medium。
  窓に読んだ異なる秘匿値の数が `max(min_distinct (10), その主体の日ごとの異なり数の中央値 × factor (3))` を超えた → high (一括読み出し)。主体ごとに 1 件 (重い方)
- 決定: GetParametersByPath はパス単位で 1 と数え、Data の `paths` に `(recursive)` を残す。BatchGetSecretValue のフィルタ指定は名前が分からないので `(filters)` を 1 と数える
- 決定: 初出の履歴は日の区切りに依らず窓の直前まで見る。「その名前を読んだことがある」には復号しない読み取りも数え、「秘匿値を読んだことがある」は復号した読み取りか、
  `with_decryption` の無い (以前の版で集めた) ssm の読み取り。導入直後 (CloudTrail を収集し終えた過去日が `min_baseline_days` (7) 未満。数え方は principal_new_source と同じ) は初出を報告しない (一括読み出しは報告する)
- 決定: allowlist の `secrets_access` に一致する秘匿値は初出に数えない。それを読む主体は「初めての読み手」として重くしない。承認済みの主体でも下げない
- 決定: 保存量 (秘匿値の読み取りとして出した trail_event の数) を run の stats の `secret_read_events` に残す。GetParameter はアプリの起動ごとに呼ばれて多い
- 2 つとも追加の権限は要らない (`cloudtrail:LookupEvents` だけ)。日次集計と秘匿値の取り出しで既存のチェックの結果が変わらないことをテストで固定する

決定 (unused_region_activity / cost_anomaly。ADR 0032):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| unused_region_activity | event | `<リージョン>\|<主体 ARN>` | 重大度 + 操作 (`<サービス>:<操作>`) の集合 | `cloudtrail-unused-regions` のソースのイベントのうち、サービスの主体と `ignore_event_sources` を除いた書き込み。成功すれば high、`compute_apis` (計算資源の作成) なら critical。計算資源の作成の失敗 (試行) は medium、他の失敗は報告しない。deploy タグの承認済み主体なら 1 段下げる |
| cost_anomaly | event | 異常の ID | 重大度 | 直近 `lookback_days` (7) 日に終わった異常で、影響額が `min_impact_usd` (10 USD) 以上。予想に対する増加の割合 (TotalImpactPercentage、無ければ影響額 / 予想額) が `medium_impact_ratio` (0.5) 以上で medium、`high_impact_ratio` (1.0) 以上で high。予想額が無ければ medium。Feedback が NO / PLANNED_ACTIVITY のものは報告しない |

- 決定: 主体がサービスリンクロール (`arn:aws:iam::<アカウント>:role/aws-service-role/<サービス名>/<ロール名>`。`record.ServiceLinkedRole`) のとき、
  見出しの末尾に「主体は `<サービス名>` のサービスリンクロール (人の操作に付随することが多い)」と書き、data に `service_linked_role`・`service_linked_service` を出す。
  利用者が機能を有効にした結果として AWS が書き込むことが多いが、重大度は下げない (有効にしたのが正規の人かはこのチェックでは分からない。確かめ方は対処手順に書く)。
  Fingerprint にも入れない。ロールの ARN がセッションの ARN からの復元 (パスが落ちる) のときは見分けられない
- 決定: ふだん使わないリージョンは毎回 `account:ListRegions` (ENABLED / ENABLED_BY_DEFAULT) から全 cloudtrail-lookup の `regions` を除いて決める (設定に active_regions を書かせない。opt-in したリージョンは次の run から対象)。
  cloudtrail-lookup のソースが無ければ設定の誤り。各リージョンで LookupEvents を `ReadOnly=false` で窓 (再走査を含む) の分だけ引く (使っていないリージョンはふつう 1 回。レート制限は共有)
- 決定: 未使用リージョンのイベントは events に残すが、source 列 (`cloudtrail-unused-regions` のソースの ID) で分け、unused_region_activity だけが見る。
  engine は他のチェックに source を除いた Query を渡す (defense_evasion・public_exposure・access_denied などの二重の報告と、平常帯・結果の変化を防ぐ)。principal_seen と主体の活動の日次集計も出さない。
  run の stats に `unused_region_events` と `unused_regions_scanned` を残す (`denied_events` / `secret_read_events` には数えない)
- 決定: cost_anomaly の重大度は固定の金額ではなく予想に対する増加の割合で決める (同じ 100 USD でもサービスの規模で意味が変わる)。金額は小さすぎる異常を除く下限にだけ使う (1 USD → 5 USD の +400% のような誤報を防ぐ)。
  Data と Summary に予想額・実際の額・割合・影響額を並べる。critical は出さない (費用だけでは侵害と言えない)。費用の削減の提案はしない
- 決定: cost-anomaly はスナップショット (ADR 0015)。モニターが無ければ Unavailable でチェックを skip し、GetAnomalies は呼ばない。`lookback_days` と `min_impact_usd` は GetAnomalies の問い合わせの条件
  (`min_impact_usd` はサーバー側の TotalImpact の絞り込み) なので overrides では変えられない。連結アカウントの名前 (LinkedAccountName) は残さない (ID だけ)
- 費用: LookupEvents は無料。Cost Explorer の API は公式の料金表で 1 リクエスト 0.01 USD (GetAnomalies / GetAnomalyMonitors が対象かは明記が無いので対象とみなす)。
  1 回の run で GetAnomalyMonitors 1 回 + GetAnomalies 1 ページ (多くは 1 ページ) = 約 0.02 USD、daily だけなら月 0.6 USD ほど。doctor も約 0.02 USD。SDK のリトライの再試行も課金されうる

決定 (週次チェックと ai_path_usage。Step 3、ADR 0015):

| チェック | Mode | Key | Fingerprint | 判定 |
|---|---|---|---|---|
| credential_hygiene | state | `unused_key\|<user>\|<n>` / `no_mfa\|<user>` / `root_access_key\|<n>` | 重大度 + ユーザー (+ キー番号) | 有効なアクセスキーの最終使用 (使われていなければ作成・ローテーション) から `checks.credential_hygiene.unused_days` (既定 90) 日超 / パスワード有効で MFA 無し / ルートに有効なキー。経過日数は Data |
| guardduty_findings | state | finding ID | 重大度 + count | アーカイブされていない finding。GuardDuty の重大度 7 以上 → high、4 以上 → medium、他は low。count の増加は changed |
| posture | state | `cloudtrail_logging` / `cloudtrail_log_validation` / `guardduty_enabled\|<region>` / `root_mfa` / `s3_public_access_block` / `password_policy` / `alb_waf\|<region>\|<ALB の名前>` | 重大度 + 問題の中身 (無効な項目・最小文字数など) | 記録中のマルチリージョン証跡が無い (high)、ログファイル検証が無効な証跡 (medium)、GuardDuty 無効 (high)、ルート MFA 無し (high)、PAB 未設定 / 無効な項目 (high)、パスワードポリシー未設定 / 最小文字数 < `checks.posture.min_password_length` (既定 14) (medium)、インターネット向けの ALB に WAFv2 の WebACL が付いていない (medium。ALB ごと。Data は region・name・arn。決定 (ADR 0048): 最低限の防御として推奨するが、無くても直ちに侵害の兆候ではないので medium)。取れなかった項目は前回の finding を維持 (ALB はリージョン単位) |
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
| `challenge_on_app_path` (正規の画面に Challenge / CAPTCHA。ADR 0028) | review | 探索パスではない GET の正規化パスで、出した異なり IP (日ごとの最大) が `challenge_min_distinct_ips` (10) 以上、解かれた割合 (解いた IP / 出した IP、日ごとの値の合計の比) が `challenge_solve_ratio` (0.5) 以上。sign-in のパス・レートベース・送信元の評判のグループは observation (`excluded_by_rule`) |
| `unused_rule` (使われていないルール) | review | 直近 `unused_days` (30) 日すべてにデータがあり、終了ルールにもカウントの一致にもならなかった (COUNT のルールは除く)。削除は勧めない |
| `observation` (提案なし) | none | 下の「不審な事実は必ず伝える」。`about` (関わる候補) と `reason` (提案しなかった理由) を持つ |
| `observation` / about `challenge_impact` (Challenge / CAPTCHA の状況。ADR 0028) | none | 毎回、出した数の多い `challenge_top_rules` (10) 個のルール (`reason: informational`)。出した数・解かれた割合・GET 以外の件数・主なパス。事実だけを書く |
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
- 決定 (Challenge / CAPTCHA。ADR 0028): 解かれた割合が高い = 人が解いている = 正規の利用者が巻き込まれている疑い、と読む (仮説。検証方法と前提は ADR)。
  止めるのではなく緩める提案なので stage は review。GET 以外は解けない構造なので提案の対象にせず、challenge_impact に「GET 以外 N 件」を添える。
  割合が低いものは提案しない (ボットを止めているのか、解けない通信なのかを区別できない)
- 決定: waf_review は保存済みの日次集計だけを読む (`StoredNeeds`)。weekly の run は wafv2 のソースを引かない (Insights の費用)。wafv2 のソースが設定に無ければ skip (`no waf_action source`)。
  候補を見るには daily が回っている必要がある

- 評価する日は窓に重なる UTC の日。key ごとに件数が最大の日を 1 件にまとめる。複数ソースが同じ metric を出す場合は合算する。
- 件数・日付・中央値・閾値は Data に残し、Fingerprint には入れない (翌日も同じ IP が続けば still_open で沈黙し、窓が途切れてから再び現れたら recurred)。
- 「初出」系 (`new_top_ip` / `new_rule`) は過去にデータのある日が min_baseline_days (既定 7) 未満の間は判定しない (導入直後に全部が初出になるのを防ぐ)。閾値超えは導入直後から判定する。
- allowlist の `source_ips` に含まれる IP は 3 チェックとも対象外。
- パス・メソッド・ステータス・閾値は設定の `checks:` で顧客ごとに変える (examples/arata.yaml)。既定: sign-in は `POST` で `/users/sign_in`, `/login`, `/signin` へ 401 / 403 / 422、
  機密パスは `/.env`, `/.git/`, `/wp-login.php` などへの 403 / 404。`probe_paths.exclude_paths` で正規の管理画面などを外す。

決定 (対処手順。ADR 0025): チェックごとに `docs/ai/playbooks/<check>.md` (見出しは固定: この指摘の意味 / まず確かめること / 判断の分かれ目 / 対処の選択肢 / やってはいけないこと) を書き、
`arata help ai playbook <check>` で出す。登録済みのチェックすべてに playbook が要る (テストで固定)。新しいチェックを足すときは playbook も書く。封じ込めは人が判断して実行し、LLM は提案まで。

## 8. CLI

```
arata config init --audit-account <12 桁の ID>|none [--by NAME] [--out FILE|-] [--force] | --diff
                               # 推奨設定の雛形を書き出す (既定 ./arata.yaml。監査する側のアカウントは必須。ID なら既知リストにも書く。ADR 0045) / 雛形との差分 (3 章、ADR 0014)
arata config check             # 設定と allowlist.yaml の形をオフラインで検査 (AWS・ストアに繋がない。問題があれば終了コード 2。3 章、ADR 0042)
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
arata approve   <finding-id> --destination --note "..." [--destination-role glob] [--expires date] [--by name] [--commit]   # 行き先のアカウントを既知にする (ADR 0047)
arata ack|snooze|resolve <finding-id>        # snooze は --until date
arata help ai [report|approve|runtime|onboarding|playbook [check]] [--format json]   # LLM 向けの使い方 (arata ai と同じ)。playbook はチェックごとの対処手順
arata prune     [--dry-run]
arata rebuild   [--from-scratch [--baseline]] [--format text|json]   # raw JSONL から SQLite を再構築 (5-4、ADR 0033)
```

- 決定: 設定ファイルのパスには既定を持たせる。解決順は `-c` (`--config`) > 環境変数 `ARATA_CONFIG` > カレントディレクトリの `./arata.yaml`。
  どれも無ければ探した場所を並べて `CONFIG_INVALID` (終了コード 2)。`-c` や `ARATA_CONFIG` で指したファイルが無いときは次へ落ちずに設定エラーにする
  (指定の打ち間違いで別の設定が黙って使われるのを防ぐ)。`config init` の `--out` の既定も `./arata.yaml` (既存ファイルは `--force` が無ければ上書きしない。
  標準出力へは `--out -`)。`run --out` などデータの出力先には既定を足さない。サンプルは `examples/arata.yaml`。aratam の設計とそろえる
- 終了コード: 0 = 正常 (findings の有無に関係なく)、2 = 設定 / 権限エラー、3 = 収集の一部失敗 (レポートは出す)。
  組み込み側は終了コードと `report.json` の `summary.new_count` / `summary.max_severity` で通知を分岐する。
- 出力は `report.json` (機械向け、LLM 要約の入力) と `report.md` (人向け)。Slack / Issue への投稿はしない。

決定 (`doctor`):
- 決定 (ADR 0034): `s3://` のストアでは `store_scope` (読み取り専用は監査対象への約束で、ストアのバケットは別という表示)、`store_read` (ListObjectsV2 と HeadObject。書き込みは試さない。読めなければ ng)、`store_versioning`・`store_encryption`・`store_public_access` (推奨。満たさなければ warn、確かめる権限が無ければ skip) を足す。バケットに要る action は監査用の action とは別に出す (`store_actions`)
- ストアを開かない (ロックを取らないので run と並行でき、ストアが無くても動く)。`--window` (既定 24h) は解釈率のサンプルを探す範囲、`--format table|json`。
- 検査項目: `permission` (LookupEvents を 1 件だけ引く / 各 API の AccessDenied に不足 action を添える)、`log_group` (DescribeLogGroups で完全一致を探す)、
  `match_rate` (直近 100 行を `fields @timestamp, @message, ispresent(<判定フィールド>) as arata_matched | sort @timestamp desc | limit 100` で取り、手元で数える。生ログを引くのはここだけ)、
  `queries` (集計・解釈率・サンプル・doctor 自身のクエリを StartQuery して直ちに StopQuery し、Insights の構文検査だけを受ける。match_rate より先に行う)、`check` (必要なレコードを出すソースが無いチェック = warn)、`config` (allowlist の検証)。
- ng が 1 つでもあれば終了コード 2。ng の行は標準エラーに固定語彙の `code` 付きで 1 行ずつ出す。warn だけなら 0。
- 表の最後に、設定のソースに必要な IAM action (`cloudtrail:LookupEvents`, `logs:DescribeLogGroups`, `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`) を列挙する。
- 決定 (Step 3): アカウント単位のソースは、collector の読み取り API を 1 回ずつ試して action ごとに permission 行を出す (拒否は ng / ACCESS_DENIED)。
  必要な action: iam-credential-report = `iam:GenerateCredentialReport` (書き込み系。doctor では試さない)・`iam:GetCredentialReport`、
  guardduty = `guardduty:ListDetectors`・`ListFindings`・`GetFindings`、access-analyzer = `access-analyzer:ListAnalyzers`・`ListFindings`、
  posture = `cloudtrail:DescribeTrails`・`GetTrailStatus`、`guardduty:ListDetectors`・`GetDetector`、`iam:GetAccountSummary`・`GetAccountPasswordPolicy`、`s3:GetAccountPublicAccessBlock`、`elasticloadbalancing:DescribeLoadBalancers`・`wafv2:GetWebACLForResource`
  (ADR 0048。インターネット向けの ALB が無ければ GetWebACLForResource は試せないので「未確認」と出す)、
  waf-config = `wafv2:ListWebACLs`・`GetWebACL`・`GetLoggingConfiguration`・`ListResourcesForWebACL` (決定: ADR 0023。WebACL があれば最初の 1 つで残りを試す)、
  cloudtrail-unused-regions = `account:ListRegions`・`cloudtrail:LookupEvents` (有効なリージョンの数と対象のリージョンを出し、対象の各リージョンで 1 件だけ引く。`cost` の行は「無料」)、
  cost-anomaly = `ce:GetAnomalyMonitors`・`ce:GetAnomalies` (モニターが無ければ warn。`cost` の行に Cost Explorer の API の 1 日・30 日の見込み。ADR 0032)。
  doctor の `queries` は wafv2 の新しい集計のクエリも構文検査する。`check` の warn は waf_review が読む日次集計の元 (wafv2 ソース) が無いときも出す。
- 決定 (ADR 0028): wafv2 のソースには `cost` の行を出す。1 日のログの量 (直近 24h に解釈率の集計を流して実測。実測した範囲・読み取り量・その費用も出す。`--no-measure-scan` なら解釈率のサンプルのクエリのスキャン量を 24h に換算した推定。
  sort+limit のスキャン量は sandbox で約 75% に少なく出たので推定は既定にしない) ×
  範囲 (窓 + ingest_delay + 24h) × クエリの本数で 1 回の run を見積もり、wafv2 を引くプロファイルの 1 日の run 数を掛けて、東京の単価 (0.0076 USD/GB) で 1 日・30 日の概算を出す。
  決定 (ADR 0031): 範囲は実行時刻で決まる (範囲の始まり = 窓の終わり − 窓 − ingest_delay の、UTC の時刻の分だけ長くなる) ので、最小になる時刻
  (UTC 0 時 + 窓 + ingest_delay + 余裕 15 分。daily なら UTC 00:20 = JST 09:20、約 24.3 時間) とその時の 1 回の量・30 日の概算も出す。直近の run の時刻は
  保存したレポート (`reports/<profile>.json` の窓の終わり) から読み、あればその範囲と量も出す (ストアは開かない)。
  `max_scan_gb` が無い・見積もりより小さいときは warn (推奨値は見積もりの 1.5 倍)。`resources` があれば `resources` の行で、ログの宛先が同じ WebACL の資源と照合する
  (httpSourceId の形は公式文書で食い違うので候補を複数作る。当たらなければ warn。waf-config のソースが無くても読む)
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
- acked / snoozed 中の finding はレポートに出さない。決定 (ADR 0022): ただし重大度が ack / snooze したときより上がったものは `changed` に出す (Data の `escalated_from_suppressed`)。
- `coverage.checks_run` を追加し、実際に走ったチェック名を出す。
- 決定 (Step 3): `coverage.sources_failed` / `summary.collect_errors` に `action` (不足した IAM action) と `partial` (一部の項目だけ取れず、取れた項目で評価した) を足す。
- 決定 (ADR 0023): `proposals` (WAF の修正提案の候補と observation。waf_review が走った run だけ。無ければ節ごと出さない) を足す。1 件は `kind` / `stage` / `web_acl` / `scope` / `region` /
  `rule` / `rule_in_group` / `method` / `path` / `summary` / `evidence` (根拠の数字と提案する値) / `finding_key` (low の finding にもした候補)、observation は `about` / `reason`。
  aratam は未知のフィールドを無視するので、古い aratam でも止まらない (テストで固定)。`coverage.formats[].truncated` (行の上限に当たった集計) も足す。report.md には「WAF の修正提案の候補」の節を出す

決定 (期間レポート。ADR 0016): `report --from --to` (`--month`) は `"kind": "period"` の別の形を出す。
決定 (ADR 0041): 期間レポートの report.md でも、summary と主体の表示 (ログ由来) の改行は空白にする (run の report.md と同じ。抜けていて、改行で偽の見出しや指摘の行を作れた)。
`period` / `notes` (履歴の無い期間の注意) / `summary` (new / changed / recurred / resolved / by_severity / open) / `events` / `new_principals` / `open` /
`metrics` (日 × 指標の合計、UTC) / `runs_missing` (partial / failed / RUN_MISSED) / `profiles` (プロファイルごとの run 数)。info は数えない。

## 9. 組み込み方 (エンジンの外側)

| 方式 | 構成 | 向く顧客 |
|---|---|---|
| オンプレ cron | `cron → arata run → 終了コードと report.json で Slack 投稿 / claude -p で要約` | CircleAround が運用を預かる顧客。監視対象の外で動く |
| Lambda | `EventBridge Scheduler → arata-lambda (S3 ストア) → SNS` | 顧客アカウント内で完結させたい顧客。**ストアと SNS は別の監査用アカウントか Object Lock バケット**に置き、侵害時に改ざんされにくくする |
| GitHub Actions | `schedule → arata run (S3 ストア。5-5) → aratam notify` | サーバーを持たずに定期実行したい顧客。ストアのバケットは監査対象とは別のアカウントが望ましい。同時実行は `concurrency:` でも止める (衝突しても後のほうが失敗するだけ)。見本は [examples/github-actions](../examples/github-actions/README.md)、実行の仕組みは `deploy/github-actions/runner.yaml` |
| AgentConsole タイマー | 一時的な追跡のみ | 恒常運用には使わない |

決定 (GitHub Actions の見本): 認証は OIDC の実行用ロール 1 つから分ける。監査は `aws.profile` で読み取り専用ロールへ連鎖し、ストアは `store_profile` を書かず実行用ロールのまま書く (`credential_source` は `role_arn` なしでは使えない)。
Actions のログには arata / aratam の `level`・`code`・`source` と終了コードだけを出す。`::add-mask::` で値を列挙する案は、監査の結果に何が出るかを列挙できないので採らない。

決定 (GitHub Actions の実行の仕組み。ADR 0040): OIDC プロバイダ・ストアのバケット・実行用ロールは、素の CloudFormation (`deploy/github-actions/runner.yaml`) で 1 コマンドで置く。
監査対象には `deploy/iam/readonly-role.yaml` を置き、`TrustedPrincipalArn` に実行用ロールを渡す (2 つの `aws cloudformation deploy`。同じアカウントでも別のアカウントでも同じ手順)。
- 決定: 信頼は `StringEquals` だけで、`aud` = `sts.amazonaws.com` と `sub` = `repo:<リポジトリ>:ref:refs/heads/<ブランチ>` の完全一致。パラメータの `AllowedPattern` がワイルドカードとコロンを拒む。
  リポジトリは `sub` の `repo:` の部分をそのまま受ける (2026-07-15 より後に作ったリポジトリは `owner@ID/repo@ID` の形になるため、両方の形を受け付ける)
- 決定: `job_workflow_ref` の条件は任意のパラメータ (`GitHubWorkflowRef`) にし、既定では足さない。AWS は GitHub 固有の条件キーとしてこれを受け付けるが、
  GitHub の文書は値を「再利用ワークフローへの参照」としか定めておらず、ふつうのワークフローでの値が保証されていない。既定で足すと、文書に無い挙動に定時の監査が依存する。
  実際のトークンで値を確かめてから、既定にするかを決め直す
- 決定: 監査ロールの ARN は一覧 (`AuditRoleArns`) で受ける。複数のアカウントを 1 つのリポジトリ・1 つの実行用ロールで監査できる。ワイルドカードは拒む
- 決定: 権限はストアの `s3:GetObject`・`s3:PutObject` (`StorePrefix` の下。空ならバケット全体)・`s3:ListBucket` (バケット。`s3:prefix` で絞らない。5-5) と、監査ロールへの `sts:AssumeRole` だけ。
  doctor の `store_actions` と一致することをテストで固定する。削除の権限と、doctor の推奨の確認に使うバケットの設定の読み取りは付けない (doctor は権限が無ければ飛ばす)
- 決定 (aratam の `provider: bedrock`): 任意のパラメータ `BedrockInferenceProfileArn` を指定したときだけ、`bedrock:InvokeModel` を足す (aratam は Converse を 1 回ずつ呼ぶだけで、ストリーミングは使わない)。
  対象は、その推論プロファイルと、`bedrock:InferenceProfileArn` がそのプロファイルに完全に一致する基盤モデルの呼び出し。振り分け先のリージョンの基盤モデルは列挙しない
  (テンプレートから分からず、AWS が足すこともある)。基盤モデルを直接は呼べない。読み取り専用ロールには足さない (Bedrock を呼ぶのは aratam で、arata は読み取り専用のまま)
- 決定: バケットとバケットポリシーは `Retain` (監査の状態と原本を失わない)。OIDC プロバイダはアカウントに 1 つなので、既存の ARN を渡せば作らず、作ったものも `Retain` (ほかのロールが後から使い始め得る)
- 決定: バケットは古い版を既定 90 日で消す (SQLite は run のたびに置き換わり、版が増え続ける)。暗号化は SSE-S3 (鍵の管理と費用を足さない)
- 決定: 説明に日本語を書けるのはパラメータの `Description` まで。IAM の `Description` と `ConstraintDescription` は ASCII にする (後者は日本語がエラーの表示で `?` に化ける。実機で確かめた)
- 決定: テンプレートの守りは Go のテスト (`internal/engine/runner_template_test.go`) で固定する。cfn-lint は CI に足さない (Python の依存と待機期間の検査が増えるわりに、守りたい性質 (信頼の条件・権限の範囲) は見ない)
- 決定 (複数のアカウント): 見本は `arata-audit-multi.yml`。アカウントごとに matrix のジョブ・`aws/<名前>/` の設定・ストアの prefix・`concurrency` の group を分ける。
  監査ロールの ARN は 1 つの secret (名前から引く JSON) にまとめ、step の中で取り出して `::add-mask::` で隠す。`secrets[...]` で動的に選ぶ形は、ジョブにすべての secrets が渡るので採らない。
  2 つの見本の step は、この取り出しのほかは同じであることをテストで固定する
- 決定 (利用者のリポジトリの前提): 監査のリポジトリの守り (非公開・fork の禁止、fork の PR と `pull_request_target` を使わない、ID 入りの `sub`、main の保護、
  書き込み権限の最小化、Actions の許可リストと SHA 固定) を、見本の README「実行するリポジトリと環境を堅くする」と `arata help ai runtime` (LLM が点検するときのチェックリスト) に書く。
  `sub` を 1 つのブランチに絞っているので「main に入れられる人 = 実行用ロールを使える人」になり、main の保護が権限の境界になる。
  確かめる `gh api` は読み取りだけを載せ、設定を変えるのは人とする (テストが書き込みの例を拒む)。
  見本が前提を満たすこと (secrets か OIDC を使う見本は定時と手動だけ、action は 2 つだけ、environment を使わない) はテストで固定する
- 決定 (secrets と environment): リポジトリの secrets は書き込み権限のある人なら別のブランチのワークフローで読み出せる。読み出されて困るのは Webhook (bot トークンの方式ならトークン。`docs/aratam.md` 4-1 章) で、
  ロールの ARN は `sub` が合わないので引き受けられない。GitHub の environment に置いてデプロイできるブランチを main に限る案は、ジョブの `sub` が
  `repo:...:environment:<名前>` に変わり (ブランチが `sub` から消える)、今の `runner.yaml` では引き受けられないので、いまは採らない (ADR 0040 のまま)。
  テンプレートの対応はロードマップに残し、それまでは書き込み権限を持つ人を最小にすることで守る
- 決定 (最初の run と Slack の疎通): 最初の run は手元で実行して `aratam notify --dry-run` で中身を見てから、定時の実行に任せる (見本の README の手順 6)。
  run は finding を報告済みとしてストアに確定するので (ADR 0038)、以後の定時の実行は新しく起きたことだけを報せる。
  見本のワークフローに「通知しない」入力や test-notify の入力は足さない: 初回の収集で手元にストアを書ける認証が既にあり、Actions では中身を見る場所が無い
  (ログと Summary に finding の中身を出さない方針)。入力を増やすと、定時の監査と同じワークフローに分岐とテストが増える。
  Slack の疎通は手元の `aratam test-notify` (実際に送る。`doctor` は送らない) と、最初の `workflow_dispatch` (`on_quiet: short` の 1 行) で確かめる
aratam は arata の失敗後も動かす (`if: always()`)。実行環境が毎回消えるので report.json が無く、`max_age` を待たずに緊急用に届く。`waf-proposals.md` は実行環境と一緒に消えるのでストアの `reports/` に置く。artifacts はリポジトリを読める人に見えるので使わない。

LLM 要約は `arata help ai report` (バイナリに埋め込んだ手順) に従い、`report.json` を入力に「新規 / 変化 / 再発 / 解消 / 未対応 / 取れなかったもの」の順で書く。
approve は人の判断を経て実行する。

決定 (LLM 向けの使い方の配り方。ADR 0012): skill ファイル (`skills/aws-audit/SKILL.md`) を別に配る案は取りやめ、`docs/ai/*.md` を embed で
バイナリに入れて `arata help ai` / `arata help ai report` / `arata help ai approve` / `arata help ai runtime` (利用者の環境のチェックリスト) で出す (`--format json` で `{topic, title, sections: [{title, body}]}`)。
組み込み側の LLM には「最初に `arata help ai` を読む」とだけ指示すればよく、手順とエンジンの版がずれない。
引数なしの `arata` (ルートのヘルプ) は、人向けの手順 (config init → doctor → init → run。決定: Step 3 で config init を先頭に足した。ADR 0014) と `arata help ai` への案内を最初に出す。

決定 (導入の流れを arata から引けるようにする): init は finding を出さず、その後の最初の run で溜まっていた指摘が一度に出る。
それを通知に流さず、run → review → 1 件ずつ approve / 設定で直す / snooze / ack で片付け、CloudTrail の遅れ (最大 15 分) の後にもう一度 daily を流して
導入作業の記録を拾ってから定時の通知を始める。この流れを `arata help ai onboarding` (docs/ai/onboarding.md) に書き、次の 3 か所から案内する。

- `arata init` が最後まで終わったとき、標準出力に次の手順を 3 行で出す (標準エラーは JSON 行なので使わない。途中で止まった init・再開するものが無い init には出さない)。
  run に渡すプロファイルは設定に書いたものを窓の短い順に並べる (暗黙の既定の名前を出さない。ADR 0014)
- ルートのヘルプの手順に 5 行目 (`arata review`) を足す
- README の「はじめての手順」と aratam の節から参照する
- ack と snooze の選び方も同じ文書に置く: 直すつもりなら snooze (期日以降に再報告される。直れば解消)、ack は正規の動きか終わった出来事にだけ使い、
  報告が来なくなると困るものを ack にしない。規則 (6 章の状態遷移) は変えず、使い方の基準だけを書く
- 却下: init が run まで続けて行う (init が finding を出さない前提が崩れ、通知をつないだ実行と区別できない)。
  「最初の run は通知しない」を arata の機能にする (arata は通知を知らない。ADR 0018)。README だけに書く (版とずれる。ADR 0012)

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
4. `report --from --to` と monthly テンプレート / prune / rebuild (決定: 期間レポートは Step 3 で実装。ADR 0016。rebuild は 5-4・ADR 0033 で実装。prune は後続)
5. Lambda ハンドラと S3 backend / deploy テンプレート (決定: skill 同梱は `arata help ai` に置き換えて Step 2 で実装済み)

## 11. 未決事項

- 国判定 (IP → 国) をどうするか。MaxMind のオフライン DB を同梱するか、GuardDuty の `remoteIpDetails` に頼るか。
- Logs Insights の費用上限。1 日あたりのスキャン量に上限を設け、超えたら daily チェックを縮退させるか。
  (Step 2 でソース単位・1 回の収集単位の `max_scan_gb` を入れた。1 日あたり・顧客全体の上限と縮退は未決)
- 顧客間での allowlist の雛形共有 (CircleAround の switch role 等は全顧客共通になり得る)。
