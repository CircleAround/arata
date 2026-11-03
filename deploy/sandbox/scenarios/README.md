# sandbox のシナリオ

sandbox (arata の試験用に条件を整えた、開発用アカウント上の環境。[../README.md](../README.md)) で「怪しい出来事」を起こすスクリプト。
起こした後に arata を回し、決めたチェックが決めた重大度で出るか、出ないはずのものが出ないかを確かめる。

- **sandbox を置いた開発用アカウントでだけ実行する**。どのスクリプトも `SANDBOX_ACCOUNT` と今の認証情報のアカウントが違えば何もせずに終わる (終了コード 2)
- スタック名が `arata-sandbox` でなければ `SANDBOX_STACK` で指定する。値はスタックの出力から読む (`lib.sh`)
- 必要なもの: aws CLI v2、bash。書き込む操作は各スクリプトの先頭のコメントに書いてある
- CloudTrail への記録は 5〜15 分、CloudWatch Logs の取り込みは数分遅れる。起こしてから 15 分ほど待って arata を回す

## 一覧

| スクリプト | 起こすこと | arata で出るはず | 周期 |
|---|---|---|---|
| `01-nginx-bruteforce.sh [失敗行数=50] [探索行数=30]` | nginx のロググループに `POST /users/sign_in` 401 を 203.0.113.10 から、`/.env` などへの 404 を 198.51.100.7 から書き込む (行を書くだけで通信は起きない。送信元は文書用アドレス) | `login_bruteforce` medium (203.0.113.10、`above_baseline`。既定の `min_count` 20 を超える)、`probe_paths` low (198.51.100.7。`min_count` 10) | daily |
| `02-external-assume-role.sh` | 外部アカウントの profile (`EXTERNAL_PROFILE`) から外部用ロールを AssumeRole する (ロールは権限なし。一時認証情報は捨てる) | `unknown_assume_role` high (「外部アカウント 111122223333」)。`arata approve` すると `account:` 単位で承認され、次の run から出ない | hourly / daily |
| `03-iam-changes.sh create` / `cleanup` | スタックの外で IAM ユーザーとアクセスキーを作る / 消す (ポリシーなし。秘密値は表示しない) | `iam_changes` medium が CreateUser と CreateAccessKey に 1 件ずつ。呼び出した主体を allowlist で `tags: [deploy]` にすると info | daily |
| `04-guardduty-sample-findings.sh [種類 ...]` | GuardDuty のサンプル finding を作る (`[SAMPLE]`。config の `guardDuty.enabled: true` のとき) | `guardduty_findings`。既定の 2 種類は high と medium | weekly |
| `05-access-denied-enumeration.sh` | 外部アカウントの profile (`EXTERNAL_PROFILE`) から外部用ロールを引き受け、権限の無い読み取り API を 8 種類 (iam / s3 / ec2 / secretsmanager / kms / dynamodb / lambda / rds) 呼ぶ。すべて拒否される (一時認証情報は表示しない) | `access_denied` medium (外部用ロールの ARN、`threshold: breadth`、8 種類)。外部用ロールを allowlist で承認しても出る (止めるなら ack / snooze) | daily |

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
