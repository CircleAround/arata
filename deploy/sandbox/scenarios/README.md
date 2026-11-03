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
| `05-access-denied-enumeration.sh` | 外部アカウントの profile (`EXTERNAL_PROFILE`) から外部用ロールを引き受け、権限の無い読み取り API を 8 種類 (iam / s3 / ec2 / secretsmanager / kms / dynamodb / lambda / rds) 呼ぶ。すべて拒否される (一時認証情報は表示しない) | `access_denied` medium (外部用ロールの ARN、`threshold: breadth`、8 種類)。外部用ロールを allowlist で承認しても出る (止めるなら ack / snooze) | daily |
| `06-waf-traffic.sh [正規=60] [探索=20] [攻撃=20] [/login=150]` | 試験用の WAF の API (config の `waf.enabled: true`) に curl で送る: 正規らしい通信、探索パス、XSS などの攻撃らしいクエリ、/login の連打 (送信元はこのホストの IP 1 つ。下の「06 の期待」) | `waf_block_trend` low (`new_rule`: `AWSManagedRulesCommonRuleSet` と `login-rate-limit`。BLOCK が `min_count` 10 を超えればこのホストの IP の `new_top_ip` も)。WAF の修正提案 (実装中) の素材 | daily |

## 06 の期待 (WAF の action)

WebACL のルール ([lib/waf.ts](../lib/waf.ts)): `login-rate-limit` (優先度 0、/login に絞った 1 IP あたり 60 秒に 10 件、BLOCK)、
`AWSManagedRulesKnownBadInputsRuleSet` (1、全体を COUNT)、`AWSManagedRulesCommonRuleSet` (2、`NoUserAgent_HEADER`・`SizeRestrictions_QUERYSTRING`・
`SizeRestrictions_BODY` だけ COUNT、他は BLOCK)。既定の action は ALLOW。

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
| `login` | `POST /login` を `LOGIN_INTERVAL` (既定 0.4 秒) おきに 150 件 | 最初の数十件は ALLOW、その後 BLOCK | `terminatingRuleId: login-rate-limit` (`terminatingRuleType: RATE_BASED`)。WAF が数えて止めるまで数十秒かかる。ALLOW の分は API Gateway のスロットリング (10 件/秒) で 429 になることがある |

- 応答コードの内訳はスクリプトの最後に出る (403 は WAF の BLOCK と API に無いパスの両方)
- REST API の URI にはステージ名が付くはず (`/sandbox/login`)。レート制限は末尾 (`ENDS_WITH /login`) で一致させている。
  ログの `httpRequest.uri` の実際の形は、arata の集計 (パスの正規化) のために実データで確かめる
- 送信元は 1 つなので、「多くの IP から BLOCK される正規のパス」(誤検知の候補。異なり IP 数の条件) は sandbox では作れない
- ログの `authorization` と `cookie` のヘッダーは WAF が落とす (redacted fields)。シナリオはどちらも送らない

## スクリプト無しで出るもの (deploy しただけで出る)

| 状態 | arata で出るはず | 周期 |
|---|---|---|
| `consolePassword: true` の試験ユーザー (MFA なし) | `credential_hygiene` medium (`no_mfa\|<prefix>-<name>`) | weekly |
| `accessKey: true` の試験ユーザー (キーは一度も使わない) | `credential_hygiene` medium (`unused_key\|...`)。arata の `checks.credential_hygiene.unused_days` を 1 にして、deploy の翌日以降に出る (既定 90 日のままでは出ない) | weekly |
| 外部アカウントを信頼する外部用ロール | `access_analyzer` medium (config の `accessAnalyzer.enabled: true` のとき) | weekly |
| deploy そのもの (CloudFormation がユーザー・キー・パスワードを作る) | `iam_changes` medium (CreateUser / CreateAccessKey / CreateLoginProfile、呼び出し元は CDK の実行ロール)。実行ロールを allowlist で `tags: [deploy]` にすると info | daily |
| GuardDuty を有効にしていない | `posture` high (`guardduty_enabled\|<region>`)。他の posture の項目 (CloudTrail・パスワードポリシーなど) は開発用アカウントの設定どおりに出る | weekly |

## 手で起こすもの (スクリプトにしない)

- `root_usage` (critical): ルートユーザーでコンソールにサインインする。ルートの認証情報を扱うのでスクリプトにしない。必要なときだけ、管理者が行う
- `new_principal` (medium): `arata init` の後に初めて現れた主体。02 の外部アカウントのセッションや、新しく使い始めた開発者の主体で出る

## 片付け

- 03 で作ったユーザーは `03-iam-changes.sh cleanup` で消す (`cdk destroy` はスタックの外のものを消さない)
- 01 のログと 04 のサンプル finding は `cdk destroy` でロググループ・detector ごと消える
- 06 の WAF のログは `cdk destroy` (または `waf.enabled: false` で deploy) でロググループごと消える
