# sandbox のシナリオ

sandbox (arata の試験用に条件を整えた、開発用アカウント上の環境。[../README.md](../README.md)) で「怪しい出来事」を起こすスクリプト。
起こした後に arata を回し、決めたチェックが決めた重大度で出るか、出ないはずのものが出ないかを確かめる。

- **sandbox を置いた開発用アカウントでだけ実行する**。どのスクリプトも `SANDBOX_ACCOUNT` と今の認証情報のアカウントが違えば何もせずに終わる (終了コード 2)
- スタック名が `arata-sandbox` でなければ `SANDBOX_STACK` で指定する。値はスタックの出力から読む (`lib.sh`)
- 必要なもの: aws CLI v2、bash (06 は curl も)。書き込む操作は各スクリプトの先頭のコメントに書いてある
- CloudTrail への記録は 5〜15 分、CloudWatch Logs の取り込みは数分遅れる。起こしてから 15 分ほど待って arata を回す

## 一覧

| スクリプト | 起こすこと | arata で出るはず | 周期 |
|---|---|---|---|
| `01-nginx-bruteforce.sh [失敗行数=50] [探索行数=30]` | nginx のロググループに `POST /users/sign_in` 401 を 203.0.113.10 から、`/.env` などへの 404 を 198.51.100.7 から書き込む (行を書くだけで通信は起きない。送信元は文書用アドレス) | `login_bruteforce` medium (203.0.113.10、`above_baseline`。既定の `min_count` 20 を超える)、`probe_paths` low (198.51.100.7。`min_count` 10) | daily |
| `02-external-assume-role.sh` | 外部アカウントの profile (`EXTERNAL_PROFILE`) から外部用ロールを AssumeRole する (ロールは権限なし。一時認証情報は捨てる) | `unknown_assume_role` high (「外部アカウント 111122223333」)。`arata approve` すると `account:` 単位で承認され、次の run から出ない | hourly / daily |
| `03-iam-changes.sh create` / `cleanup` | スタックの外で IAM ユーザーとアクセスキーを作る / 消す (ポリシーなし。秘密値は表示しない) | `iam_changes` medium が CreateUser と CreateAccessKey に 1 件ずつ。呼び出した主体を allowlist で `tags: [deploy]` にすると info | daily |
| `04-guardduty-sample-findings.sh [種類 ...]` | GuardDuty のサンプル finding を作る (`[SAMPLE]`。config の `guardDuty.enabled: true` のとき) | `guardduty_findings`。既定の 2 種類は high と medium | weekly |
| `05-access-denied-enumeration.sh` | 外部アカウントの profile (`EXTERNAL_PROFILE`) から外部用ロールを引き受け、権限の無い読み取り API を 8 種類 (iam / s3 / ec2 / secretsmanager / kms / dynamodb / lambda / rds) 呼ぶ。`--apis N` で最大 24 種類 (どれも List / Describe)。すべて拒否される (一時認証情報は表示しない) | `access_denied` medium (外部用ロールの ARN、`threshold: breadth`、8 種類)。`--apis 20` 以上なら high。外部用ロールを allowlist で承認しても出る。想定内なら `expected_denied` で除き、ack 後に high へ上がれば changed で再報告 | daily |
| `06-waf-traffic.sh [正規=60] [探索=20] [攻撃=20] [/login=150] [Challenge・CAPTCHA 宛=20]` | 試験用の WAF の API (config の `waf.enabled: true`) に curl で送る: 正規らしい通信、探索パス、XSS などの攻撃らしいクエリ、/login の連打、Challenge / CAPTCHA 宛 (`waf.challenge` / `waf.captcha` のとき。送信元はこのホストの IP 1 つ。下の「06 の期待」) | `waf_block_trend` low (`new_rule`: `AWSManagedRulesCommonRuleSet` と `login-rate-limit`。BLOCK が `min_count` 10 を超えればこのホストの IP の `new_top_ip` も)。WAF の修正提案 (実装中) の素材 | daily |
| `07-defense-evasion.sh` | 試験用のロググループ `<stack>-scenario-07` を作り、保持期間を 1 日にして消す。sandbox のアナライザー (config の `accessAnalyzer.enabled: true`) にアーカイブルール `arata-scenario-07` (存在しないバケットにだけ一致) を作って消す。**CloudTrail の証跡は止めない** | `defense_evasion` high が 3 件: `logs:PutRetentionPolicy` (1 日 < 既定の `min_log_retention_days` 90)・`logs:DeleteLogGroup`・`access-analyzer:CreateArchiveRule` (`<prefix>/arata-scenario-07`。アナライザーがあるとき)。呼び出した主体を `tags: [deploy]` にすると medium (info にはならない)。試験用のロググループは arata の監査対象ではないので critical にはならない | daily |
| `08-public-exposure.sh` [`VPC_ID=...`] | 試験用のセキュリティグループ `<stack>-scenario-08` をデフォルト VPC (または `VPC_ID`) に作り、tcp/22 を 0.0.0.0/0 に開けて、すぐ閉じて消す。どこにも付けない | `public_exposure` high (`ec2:AuthorizeSecurityGroupIngress\|<sg>\|tcp/22 0.0.0.0/0`)。すぐ閉じても出る。`tags: [deploy]` の主体でも下がらない (`known_deploy_principal: true`) | daily |
| `09-new-source-region.sh <リージョン>` | 実行する主体 (既知で、過去 30 日に活動のある開発者の主体) が、ふだん書き込まないリージョン (arata の cloudtrail-lookup の regions に入っているもの) に String のパラメータ `/<stack>/scenario-09` を作って消す。送信元の初出も試すなら AWS CloudShell など別の送信元から実行する | `principal_new_source` medium (実行した主体の ARN、`reasons` に `new_region`、`new_regions` に指定のリージョンと書き込み 2 件)。arata が CloudTrail を収集し終えた日 (この版の init・daily の窓) が 15 日 (`min_baseline_days`) 未満なら出ない (導入直後)。下の「09・10 の期待」 | daily |
| `10-secret-bulk-read.sh` | (`secretAccess.enabled: true` のとき) SecureString のパラメータを 9 つ作り、読み手のロール `<stack>-secret-reader` でシークレット 3 つ (個別と BatchGetSecretValue)・パラメータ 9 つ (個別に復号)・パス 1 つ (再帰・復号) を読み、パラメータを消す。値は表示しない | `secret_access` high (読み手のロールの ARN、`distinct_secrets` 13 > `min_distinct` 10、`bulk: true`、`paths` に `(recursive)`)。収集し終えた日が 7 日以上なら `first_reader: true` と `new_secrets` 13 個。読み手のロールの `new_principal` medium も出る (承認すれば止まる) | daily |
| `11-endpoint-abuse.sh [登録の IP 数=25] [送信する IP 数=8]` | nginx のロググループに、`POST /signup` 302 を 203.0.113.11〜 の 25 IP から 1 件ずつ約 1 分の間に (22 IP は同じ UA)、そのうち 8 IP の `POST /messages` 200 を登録の約 5 分後に書き込む (行を書くだけで通信は起きない。時刻は約 20 分前から)。arata の設定に `checks.endpoint_abuse` の画面と連鎖を書いておく (下の「11 の期待」) | `endpoint_abuse` medium (`signup`。`reasons` に `distributed_burst`・`volume`・`same_user_agent`、異なり IP 25、同じ UA が 22 IP) と medium (`signup>message`。`follow_up`、8 IP)。収集した過去日が 7 日未満なら `baseline_used: false` (絶対の閾値で判定) | daily |

## 06 の期待 (WAF の action)

WebACL のルール ([lib/waf.ts](../lib/waf.ts)): `login-rate-limit` (優先度 0、/login に絞った 1 IP あたり 60 秒に 10 件、BLOCK)、
`AWSManagedRulesKnownBadInputsRuleSet` (1、全体を COUNT)、`AWSManagedRulesCommonRuleSet` (2、`NoUserAgent_HEADER`・`SizeRestrictions_QUERYSTRING`・
`SizeRestrictions_BODY` だけ COUNT、他は BLOCK)。既定の action は ALLOW。
`waf.challenge: true` なら `search-challenge` (3、URI の末尾が `/search` に Challenge)、`waf.captcha: true` なら `contact-captcha` (4、末尾が `/contact` に CAPTCHA)。

| 群 (出力の名前) | 送るもの | WAF の action | ログで見えるはずのもの |
|---|---|---|---|
| `normal` | `/`、`/api/items/<n>`、`/api/users/<n>/orders`、`/search?q=...`、`POST /api/posts` (UA は 3 種類)、`/health` (監視役の UA) | ALLOW | `terminatingRuleId: Default_Action`。応答は 200 |
| `probe` | `/.env`、`/.git/config`、`/wp-login.php`、`/phpmyadmin/`、`/.aws/credentials`、`/xmlrpc.php` | ALLOW (すり抜けの素材) | API に無いパスなので応答は API Gateway の 403 (WAF の BLOCK ではない)。CommonRuleSet の `RestrictedExtensions_URIPATH` などに当たって BLOCK になるものがあれば、実データの結果を正とする |
| `xss` | `/search?q=<script>alert(1)</script>` | BLOCK | `terminatingRuleId: AWSManagedRulesCommonRuleSet`、`ruleGroupList` の終了ルール `CrossSiteScripting_QUERYARGUMENTS` |
| `lfi` | `/api/files?file=../../../../etc/passwd` | BLOCK | 同じく `GenericLFI_QUERYARGUMENTS` |
| `sqli` | `/search?q=' OR 1=1 --` | ALLOW | SQLi のルールセット (`AWSManagedRulesSQLiRuleSet`) は入れていない (費用を抑えるため)。「検出されずに通った攻撃」の素材 |
| `log4j` | ヘッダー `X-Api-Version: ${jndi:ldap://...}` | ALLOW (COUNT の一致あり) | KnownBadInputs の `Log4JRCE_HEADER` が COUNT (`ruleGroupList` の `nonTerminatingMatchingRules`) |
| `no_ua` | User-Agent ヘッダーなし | ALLOW (COUNT の一致あり) | CommonRuleSet の `NoUserAgent_HEADER` が COUNT |
| `long_q` | 3000 文字のクエリ (`/search?q=aaa...`) | ALLOW (COUNT の一致あり) | CommonRuleSet の `SizeRestrictions_QUERYSTRING` (2048 バイト超) が COUNT。「正規の長い検索が引っかかる」誤検知の素材 |
| `challenge` | `GET /search?q=...` (Accept: text/html) | `waf.challenge` なら CHALLENGE (応答 202)、無効なら ALLOW | `action: CHALLENGE`、`terminatingRuleId: search-challenge`、`challengeResponse` の `failureReason: TOKEN_MISSING` (ADR 0028)。normal の `/search` も同じく Challenge を受ける |
| `captcha` | `GET /api/contact` (Accept: text/html) | `waf.captcha` なら CAPTCHA (応答 405)、無効なら ALLOW | `action: CAPTCHA`、`terminatingRuleId: contact-captcha`、`captchaResponse` の `responseCode: 405`・`failureReason: TOKEN_MISSING` |
| `login` | `POST /login` を `LOGIN_INTERVAL` (既定 0.4 秒) おきに 150 件 | 最初の数十件は ALLOW、その後 BLOCK | `terminatingRuleId: login-rate-limit` (`terminatingRuleType: RATE_BASED`)。WAF が数えて止めるまで数十秒かかる。ALLOW の分は API Gateway のスロットリング (10 件/秒) で 429 になることがある |

- 応答コードの内訳はスクリプトの最後に出る (403 は WAF の BLOCK と API に無いパスの両方)
- REST API の URI にはステージ名が付くはず (`/sandbox/login`)。レート制限は末尾 (`ENDS_WITH /login`) で一致させている。
  ログの `httpRequest.uri` の実際の形は、arata の集計 (パスの正規化) のために実データで確かめる
- 送信元は 1 つなので、「多くの IP から BLOCK される正規のパス」(誤検知の候補。異なり IP 数の条件) は sandbox では作れない
- Challenge / CAPTCHA は curl では解けない (トークンを得るにはブラウザが要る)。sandbox で確かめるのは「出した」行の形 (`action`・`terminatingRuleId`・
  `challengeResponse` / `captchaResponse`) と、`waf_challenge_issued` の集計・`challenge_impact` (解かれた割合 0%) まで。「解かれた」行の形は公式文書の例をテストのフェイクで固定している。
  ブラウザで `/search` を開いて Challenge を通れば、トークンが受理された行 (`nonTerminatingMatchingRules` の `action: CHALLENGE` か、トップレベルの `challengeResponse.solveTimestamp`) も確かめられる
- 資源で絞る (`resources`、ADR 0028): ログの `httpSourceId` の形を Insights で確かめ (`fields httpSourceName, httpSourceId | limit 5`)、その値を wafv2 のソースの `resources` に書く。
  当たる値なら件数が変わらず、当たらない値 (例 `nomatch`) なら doctor の `match_rate` が「行が無い」の warn、`resources` が warn になる
- ログの `authorization` と `cookie` のヘッダーは WAF が落とす (redacted fields)。シナリオはどちらも送らない

## スクリプト無しで出るもの (deploy しただけで出る)

| 状態 | arata で出るはず | 周期 |
|---|---|---|
| `consolePassword: true` の試験ユーザー (MFA なし) | `credential_hygiene` medium (`no_mfa\|<prefix>-<name>`) | weekly |
| `accessKey: true` の試験ユーザー (キーは一度も使わない) | `credential_hygiene` medium (`unused_key\|...`)。arata の `checks.credential_hygiene.unused_days` を 1 にして、deploy の翌日以降に出る (既定 90 日のままでは出ない) | weekly |
| 外部アカウントを信頼する外部用ロール | `access_analyzer` medium (config の `accessAnalyzer.enabled: true` のとき) | weekly |
| deploy そのもの (CloudFormation がユーザー・キー・パスワードを作る) | `iam_changes` medium (CreateUser / CreateAccessKey / CreateLoginProfile、呼び出し元は CDK の実行ロール)。実行ロールを allowlist で `tags: [deploy]` にすると info | daily |
| deploy そのもの (CloudFormation が nginx・WAF のロググループの保持期間を `retentionDays` (例の 7 日) にする) | `defense_evasion`: nginx のロググループを arata の cloudwatch-logs のソースにしていれば `logs:PutRetentionPolicy` が critical (監査対象。7 日は既定の `min_log_retention_days` 90 未満で、平常帯の日数 14 より短いので Data に `shorter_than_baseline_days`)。ソースにしていないグループは high。CDK の実行ロールを `tags: [deploy]` にすると 1 段下がる (high / medium)。sandbox では想定内なので ack する | daily |
| GuardDuty を有効にしていない | `posture` high (`guardduty_enabled\|<region>`)。他の posture の項目 (CloudTrail・パスワードポリシーなど) は開発用アカウントの設定どおりに出る | weekly |

## 手で起こすもの (スクリプトにしない)

- `root_usage` (critical): ルートユーザーでコンソールにサインインする。ルートの認証情報を扱うのでスクリプトにしない。必要なときだけ、管理者が行う
- `new_principal` (medium): `arata init` の後に初めて現れた主体。02 の外部アカウントのセッションや、新しく使い始めた開発者の主体で出る

## 07・08 の期待 (出ないはずのもの)

- 07: `CreateLogGroup`・`DeleteArchiveRule` は出ない (弱める操作ではない)。アーカイブルールは既存の findings に一致しないので、weekly の `access_analyzer` の結果は変わらない
- 08: `CreateSecurityGroup`・`RevokeSecurityGroupIngress`・`DeleteSecurityGroup` は出ない。weekly の `posture` / `access_analyzer` にも出ない (グループは消えている)
- どちらも、既存のチェック (`iam_changes`・`access_denied` など) の結果は変わらない。失敗した呼び出しは `defense_evasion` / `public_exposure` に出ない (拒否なら `access_denied` の材料)
- 読み取りロールに権限は足していない (`cloudtrail:LookupEvents` だけで判定する)

## 09・10 の期待 (出ないはずのもの・注意)

- 09: 新しく作ったロールで試さない。過去 30 日に活動が無く、その間に初めて現れた主体は「すべてが初めて」なので principal_new_source は報告しない (new_principal・承認の流れが扱う)。
  実行する主体が CI のように `dynamic_source: true` でも、新しいリージョンは medium なので出る。パラメータの作成・削除はほかのチェックに出ない
- 09: arata が LookupEvents で引くのは `cloudtrail-lookup` の `regions` だけ。それ以外のリージョンでの書き込みは見えない (使っていないリージョンの監視は後続の unused_region_activity)
- 10: SecureString の復号は AWS 管理の鍵 (`aws/ssm`) のキーポリシーで許される (読み手のロールに KMS の権限は付けていない)。顧客管理の鍵は使わない
- 10: 同じ日にもう一度実行しても still_open で沈黙する (イベント型)。読み手のロールの `secrets_access` を allowlist に書くと初出に数えなくなる (一括読み出しは数える)
- どちらも読み取りロールに権限は足していない (`cloudtrail:LookupEvents` だけで判定する)

## 11 の期待 (設定・出ないはずのもの)

arata の設定 (`checks:`) に次を書いてから daily を回す (画面のパスは架空。sandbox の nginx のロググループに合わせたもの):

```yaml
checks:
  endpoint_abuse:
    endpoints:
      - { name: signup, paths: [/signup], methods: [POST] }
      - { name: message, paths: [/messages, "/messages/*"], methods: [POST] }
    follow_ups:
      - { from: signup, to: message, within: 30m, min_ips: 5 }
```

- `signup` は 10 分幅の異なり IP が 25 (幅の境目をまたげば 2 つの幅に分かれるが、どちらかに 10 IP 以上が残る)。件数 25 も `min_count` 20 を超えるので `volume` も付く。
  境目で分かれて件数が 20 未満になった幅は `volume` が付かない (`bins` で確かめる)。UA は `ua_hash` (8 文字) と `ua_ips` だけで、原文は report・metrics・ログのどこにも出ない
- `signup>message` は登録した 25 IP のうち 8 IP が 5 分後にメッセージ送信。窓の終わりが登録の幅の終わり + 30 分より前なら、この run では評価せず次の run で出る
  (daily の窓の終わりの近くで入れたときは、次の daily で出る)
- `message` (8 IP・8 件) は `min_distinct_ips` 10・`min_count` 20 未満なので画面としては出ない
- 既存のチェック (`login_bruteforce`・`probe_paths`) の結果は変わらない。01 と同じ日に入れても、01 の 2 件はそのまま出る
- 結果は事実だけ (件数・異なり IP・ふだんの上限)。遮断の提案は出ない。同じ日にもう一度実行しても still_open で沈黙する (イベント型)
- Insights のクエリは画面ごとに 1 本増える (この設定なら 2 本)。`max_scan_gb` を付けておく

## 片付け

- 03 で作ったユーザーは `03-iam-changes.sh cleanup` で消す (`cdk destroy` はスタックの外のものを消さない)
- 01・11 のログと 04 のサンプル finding は `cdk destroy` でロググループ・detector ごと消える
- 10 のシークレットと読み手のロールは `secretAccess.enabled: false` で deploy し直すか `cdk destroy` で消える (シークレットは削除の猶予期間 (30 日) の後に消える。名前は CloudFormation が付けるので、すぐ作り直してもぶつからない)
- 07・08・09・10 はスクリプトの中で作ったもの (ロググループ・ルール・セキュリティグループ・パラメータ) を消す (途中で失敗しても終了時に消す)。08 で「消せませんでした」と出たら、そのセキュリティグループを手で消す
- 06 の WAF のログは `cdk destroy` (または `waf.enabled: false` で deploy) でロググループごと消える
