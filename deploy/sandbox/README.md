# sandbox (arata の試験環境)

**sandbox = arata の試験用に条件を整えた、開発用 AWS アカウント上の環境。** 本物の AWS で arata と aratam を動かし、
各チェックが決めたとおりに出るか (出ないはずのものが出ないか) を確かめるために使う。AWS CDK (TypeScript) で作り、`cdk destroy` で全部消える。
判断の経緯は [ADR 0020](../../docs/adr/0020-sandbox-cdk.md)。

- **開発用のアカウントにだけ置く**。顧客や本番のアカウントには置かない (試験用ユーザーなど、監査で指摘される物をわざと作る)
- 置くものには実権限を付けない。試験用ユーザーと外部用ロールはポリシーを持たず、漏れても何もできない (テストで固定)
- 設定 (アカウント ID など) はリポジトリの外に置く。リポジトリには架空の値の例 [config.example.json](config.example.json) だけを置く

## 作るもの

| リソース | 名前 | 用途 |
|---|---|---|
| 読み取り専用ロール | `<prefix>-readonly` | 顧客に配る [deploy/iam/readonly-role.yaml](../iam/readonly-role.yaml) をそのまま取り込む (CfnInclude)。arata はこのロールで動かす |
| ロググループ | config の `nginxLogGroup.name` | nginx のアクセスログ。シナリオが行を入れ、arata の cloudwatch-logs ソースが読む。保持期間は config (試験には 7 日程度) |
| 試験用 IAM ユーザー | `<prefix>-<name>` | `consolePassword: true` は MFA なしのコンソールパスワード付き (パスワードは Secrets Manager で生成し、誰も見ない)。`accessKey: true` は使わないアクセスキー付き (秘密値はどこにも出さない) |
| 外部用ロール | `<prefix>-external` | 外部アカウント (SaaS 役、config の `externalRole.trustedAccountId`) から AssumeRole される役。権限なし |
| GuardDuty detector (任意) | — | `guardDuty.enabled`。リージョンに 1 つしか作れないので、既に有効なアカウントでは `false` |
| IAM Access Analyzer (任意) | `<prefix>` | `accessAnalyzer.enabled`。外部アクセスのアナライザー (アカウント単位)。外部用ロールの信頼が finding になる |
| Bedrock の application inference profile (任意) | `<prefix>` | `bedrock.enabled`。aratam の `bedrock` プロバイダの試験用。コピー元のモデル (またはシステム定義の推論プロファイル) の ARN を `bedrock.modelSourceArn` に書く |
| 試験用の WAF (任意) | API `<prefix>-waf`、WebACL `<prefix>`、ロググループ `aws-waf-logs-<prefix>` | `waf.enabled`。WAF の修正提案を本物の WAF のログで確かめる用。下の「試験用の WAF」。**費用がかかる** (月 8 USD 程度) ので試験のときだけ有効にする |
| 秘匿値の読み取りの試験用 (任意) | シークレット 3 つ (名前は CloudFormation が付ける)、ロール `<prefix>-secret-reader` | `secretAccess.enabled`。シナリオ 10 (secret_access) 用。シークレットの値は生成した無意味な文字列。読み手のロールは `readonlyRole.trustedPrincipalArn` を信頼し、権限はこのシークレットと `/<prefix>/scenario-10` のパラメータの読み取りだけ (テストで固定)。シークレットは月 1.2 USD 程度かかるので試験のときだけ有効にする |
| Cost Anomaly Detection のモニター (任意) | `<prefix>` | `costAnomaly.enabled`。cost_anomaly 用 (AWS のサービスごとのモニター。無料。通知の購読は作らない)。AWS のサービスのモニターはアカウントに 1 つしか作れないので、既にあるアカウントでは `false` (既存のモニターを arata がそのまま読む)。異常の発生は試験できないので、doctor の権限とモニターの検出だけを確かめる |

スタック名は `prefix` (既定 `arata-sandbox`)。出力: `ReadonlyRoleArn`、`NginxLogGroupName`、`ExternalRoleArn`、`TestUserNames`、(Bedrock を有効にしたとき) `InferenceProfileArn`、
(WAF を有効にしたとき) `ApiUrl`・`WebAclArn`・`WafLogGroupName`、(secretAccess を有効にしたとき) `SecretReaderRoleArn`・`ScenarioSecretArns`・`ScenarioParameterPath`。

## 必要なもの

- **Node 24** (`.node-version` の版。24.22.1 以上、25 未満)。TypeScript は Node の型除去でそのまま動かす (ts-node などは使わない)。
  範囲外の Node では `pnpm install` がエラーで止まる (`pnpm-workspace.yaml` の `engineStrict: true`)
- pnpm 10 (`package.json` の `packageManager` の版。`corepack enable` で揃う)
- aws CLI v2 (シナリオと arata の profile 用)
- 開発用アカウントで CloudFormation・IAM・CloudWatch Logs・Secrets Manager (と任意の GuardDuty・Access Analyzer・Bedrock・API Gateway・WAFv2) を作れる認証情報
- curl (シナリオ 06 だけ)

## 使い方

### 1. 依存を入れる・試験する (AWS に接続しない)

```sh
cd deploy/sandbox
pnpm install --frozen-lockfile   # 公開から 7 日経った版だけ (pnpm-workspace.yaml の minimumReleaseAge)
pnpm typecheck                   # tsc --noEmit
pnpm test                        # CDK の assertions (node:test)
pnpm synth                       # config.example.json (架空の値) で cdk synth
```

### 2. 設定を作る (リポジトリの外に)

```sh
mkdir -p ~/arata-sandbox
cp config.example.json ~/arata-sandbox/config.json
# account / region / readonlyRole.trustedPrincipalArn / externalRole.trustedAccountId などを開発用アカウントの値にする
```

| キー | 意味 |
|---|---|
| `account` / `region` | sandbox を置く開発用アカウントとリージョン。スタックはこのアカウントに固定され、別アカウントの認証情報では deploy できない |
| `prefix` | スタック名とリソース名の頭 (省略時 `arata-sandbox`) |
| `readonlyRole.trustedPrincipalArn` | 読み取り専用ロールを引き受けてよい主体。開発用アカウント自身なら `arn:aws:iam::<account>:root` |
| `nginxLogGroup.name` / `retentionDays` | ロググループの名前と保持日数 (CloudWatch Logs の決まった値: 1, 3, 5, 7, 14, 30 ...) |
| `testUsers[]` | `name` (prefix の後ろ)、`consolePassword`、`accessKey`。要らなければ `[]` |
| `externalRole.trustedAccountId` / `externalId` | 外部用ロールを引き受けてよい外部アカウントと、要求する ExternalId (省略可) |
| `guardDuty.enabled` / `accessAnalyzer.enabled` / `bedrock.enabled` / `waf.enabled` / `secretAccess.enabled` / `costAnomaly.enabled` | 任意の機能。暗黙の既定は持たないので、6 つとも書く (`waf`・`secretAccess` は例でも `false`。費用がかかる)。以前の設定ファイルには `"secretAccess": { "enabled": false }`・`"costAnomaly": { "enabled": false }` を足す |
| `waf.challenge` / `waf.captcha` | 任意 (省略時は false)。試験用の WAF に Challenge (GET /search) と CAPTCHA (/contact) のルールを足す (ADR 0028)。`waf.enabled` が true のときだけ書ける。ルール 1 つにつき月 1 USD |
| `bedrock.modelSourceArn` | `bedrock.enabled: true` のとき必須 |

未知のキー・型の誤り・不足は deploy の前にまとめて報告される (`cdk synth` で確かめられる)。

### 3. bootstrap と deploy

```sh
export AWS_PROFILE=<開発用アカウントの profile>
pnpm cdk bootstrap aws://<account>/<region> -c config=$HOME/arata-sandbox/config.json   # アカウント × リージョンで初回だけ
pnpm cdk deploy -c config=$HOME/arata-sandbox/config.json
```

- bootstrap は `CDKToolkit` スタック (資材用の S3 バケットと deploy 用のロール) を作る。`cdk destroy` では消えない (下の「片付け」)
- IAM のリソースを作るので、deploy は変更内容の確認を求める

### 4. シナリオを起こす

[scenarios/README.md](scenarios/README.md) に、何を起こし、arata のどのチェックで何が出るはずかをまとめた。

```sh
export SANDBOX_ACCOUNT=<account>
scenarios/01-nginx-bruteforce.sh
EXTERNAL_PROFILE=<外部アカウントの profile> EXTERNAL_ID=<config の externalId> scenarios/02-external-assume-role.sh
scenarios/06-waf-traffic.sh                  # waf.enabled: true で deploy したときだけ
scenarios/07-defense-evasion.sh              # 試験用のロググループとアーカイブルールを作って弱めて消す (証跡は止めない)
scenarios/08-public-exposure.sh              # 試験用の SG の 22 を 0.0.0.0/0 に開けてすぐ閉じて消す
scenarios/09-new-source-region.sh <リージョン> # ふだん書き込まないリージョンで無害な書き込み (principal_new_source)
scenarios/10-secret-bulk-read.sh             # secretAccess.enabled: true で deploy したときだけ。試験用の秘匿値をまとめて読む
scenarios/11-endpoint-abuse.sh               # 多数の IP からの登録の集中と直後のメッセージ送信の行を書く (checks.endpoint_abuse を設定しておく)
scenarios/12-unused-region-write.sh eu-west-1  # ふだん使わないリージョンに SSM の String パラメータを作って消す (計算資源は作らない)
```

### 5. arata を回す

arata は読み取り専用ロールで動かす。`~/.aws/config` に profile を作る (`role_arn` は出力の `ReadonlyRoleArn`):

```ini
[profile arata-sandbox]
role_arn = arn:aws:iam::123456789012:role/arata-sandbox-readonly
source_profile = <開発用アカウントの profile>
region = ap-northeast-1
```

arata の設定は `arata config init` の雛形から作り、次を変える:

- `aws.profile: arata-sandbox`、`store` は手元の書き込める場所
- `sources` に nginx のロググループを足す (`kind: cloudwatch-logs`、`log_group: <NginxLogGroupName>`、`format: nginx_access`)
- (シナリオ 11 を試すとき) `checks.endpoint_abuse` に画面と連鎖を書く (書き方は [scenarios/README.md](scenarios/README.md) の「11 の期待」)
- `checks.credential_hygiene.unused_days: 1` (試験用のアクセスキーを翌日から「未使用」として出す)
- (WAF を有効にしたとき) `sources` に WAF のロググループと WebACL の設定 (`waf-config`) を足し、daily の `checks` に `waf_block_trend`、
  weekly の `checks` に `waf_review` (WAF の修正提案の候補。ADR 0023) を入れる:

```yaml
sources:
  - id: waf
    kind: cloudwatch-logs
    log_group: aws-waf-logs-arata-sandbox     # 出力の WafLogGroupName
    format: wafv2                             # → waf_action
    strip_path_prefix: /sandbox               # API Gateway の REST API はパスの前にステージ名が付く
    max_scan_gb: 1                            # 試験のログは小さい。念のため上限を付ける (doctor の cost の行に見積もり)
    # resources: ["<アカウント>:<api-id>:sandbox"]   # 資源で絞る試験 (ログの httpSourceId。scenarios/README.md の 06)
  - id: waf_config
    kind: waf-config                          # WebACL の設定 → waf_review
```

  waf_review は daily が貯めた日次集計を読む (weekly は WAF のログを引かない)。候補を見るには先に daily を回す。
  `unused_days` (30) は試験では満たないので「使われていないルール」は出ない。COUNT のルールの状況は `observation` (`about: count_rule_status`) として毎回出る

```sh
arata doctor -c arata.yaml                   # 権限・ロググループ・解釈率
arata init   -c arata.yaml --window 1d       # ベースライン
# シナリオを起こし、15 分ほど待つ
arata run    -c arata.yaml --profile daily  --out /tmp/arata-sandbox/daily
arata run    -c arata.yaml --profile weekly --out /tmp/arata-sandbox/weekly
aratam notify -c aratam.yaml --in /tmp/arata-sandbox/daily --dry-run   # aratam も試すなら
```

### 6. 片付け

```sh
scenarios/03-iam-changes.sh cleanup          # 03 を使ったときだけ (スタックの外に作ったユーザー)
pnpm cdk destroy -c config=$HOME/arata-sandbox/config.json
```

- スタックのリソースは `DeletionPolicy` / `UpdateReplacePolicy` に Retain / Snapshot を持たない (テストで固定)。明示しているのは
  ロググループとシークレット (CDK の既定が Retain のため `Delete` にした) だけで、他 (IAM のロール・ユーザー・アクセスキー、detector、アナライザーなど) は
  CloudFormation の既定で削除される。ロググループ・試験ユーザー・シークレット・detector も消える
- 生成したパスワードのシークレットは名前を自動で付けるので、削除の猶予期間中に再 deploy しても衝突しない
- `CDKToolkit` (bootstrap) は残る。もう使わないなら CloudFormation から消し、資材用の S3 バケットを空にして消す

## 費用の目安

小さな開発用アカウントで、シナリオを数回起こす程度の場合 (2026-11 時点の東京リージョンの単価から。正確には各サービスの料金表を見る)。

| 項目 | 目安 |
|---|---|
| Secrets Manager | 試験ユーザー 1 人 (`consolePassword: true`) あたり月 0.40 USD |
| CloudWatch Logs | 取り込み 1 GB あたり 0.76 USD。シナリオの行は数 KB なので実質 0。Logs Insights はスキャン 1 GB あたり 0.0076 USD |
| GuardDuty (任意) | 初回の 30 日は無料試用。その後は CloudTrail のイベント量などに応じて、小さなアカウントで月数 USD 程度 |
| IAM Access Analyzer (外部アクセス) | 無料 |
| Bedrock (任意) | 推論プロファイル自体は無料。呼び出した分のトークン課金 |
| 試験用の WAF (任意) | WebACL 月 5 USD + ルール 1 USD/個 × 3 (レート制限と、追加料金の無い AWS マネージドルール 2 つ) + リクエスト 100 万件あたり 0.60 USD。時間割りで、置いておくと月 8 USD 程度 (1 日なら 0.3 USD 程度)。API Gateway (REST) はリクエスト 100 万件あたり数 USD でシナリオの量なら実質 0。WAF のログは CloudWatch Logs の取り込みの料金 (行は 1 件 1〜2 KB) |
| IAM・CloudFormation | 無料 |

使わない間は `cdk destroy` しておく。WAF は試験のときだけ `waf.enabled: true` で deploy し、終わったら `cdk destroy` するか `false` に戻して deploy する
(WebACL・API・WAF のロググループが消える)。

## 試験用の WAF (`waf.enabled`)

WAF の修正提案 (arata が WAF のログと設定から候補を作り、aratam が通知に書く。実装中) を本物の WAF のログで確かめるための、小さな構成 ([lib/waf.ts](lib/waf.ts))。

- **API Gateway (REST、REGIONAL)** `<prefix>-waf`: mock 統合で固定の 200 を返す。パスは `/`、`/health`、`/search` (GET)、`/login` (POST)、`/api/{proxy+}` (全メソッド)。
  認証なし。ステージは `sandbox` で、スロットリングは 10 件/秒 (バースト 20)。裏に何も無いので、漏れても固定の応答を返すだけ。
  POST は `Content-Type: application/json` で送る (mock 統合のテンプレートが JSON だけのため)
- **WebACL (REGIONAL)** `<prefix>` を API のステージに関連付ける。既定の action は ALLOW。ルール:
  `login-rate-limit` (/login に絞った 1 IP あたり 60 秒に 10 件。WAF の下限。BLOCK)、
  `AWSManagedRulesKnownBadInputsRuleSet` (全体を COUNT)、
  `AWSManagedRulesCommonRuleSet` (`NoUserAgent_HEADER`・`SizeRestrictions_QUERYSTRING`・`SizeRestrictions_BODY` だけ COUNT、他は BLOCK)。
  BLOCK・COUNT・ALLOW の行がそれぞれ出る。`waf.challenge` / `waf.captcha` で `search-challenge` (末尾が /search に Challenge) と `contact-captcha` (末尾が /contact に CAPTCHA) を足す。
  シナリオ 06 で何がどれになるはずかは [scenarios/README.md](scenarios/README.md)
- **ログ**: CloudWatch Logs の `aws-waf-logs-<prefix>` (WAF の決まりで名前は `aws-waf-logs-` で始める)。保持は `nginxLogGroup.retentionDays` と同じ。
  `authorization` と `cookie` のヘッダーは WAF が落とす (redacted fields)。
  配信の許可はこのロググループに絞ったリソースポリシー `<prefix>-waf-logs` で与える (無いと WAF がアカウントのリソースポリシーを自動で作り、destroy で残るため)
- **アカウント全体の設定は変えない**: API Gateway が CloudWatch Logs に書くためのアカウントの設定 (`AWS::ApiGateway::Account` と CloudWatch 用のロール) は作らない。
  アクセスログ・実行ログは出さない (見たいのは WAF のログだけ。テストで固定)
- destroy で全部消える (ロググループは明示で Delete。他は CloudFormation の既定)

## 手動の部分

- **Bedrock のモデルの利用**: Anthropic のモデルは、アカウントで初めて使う前に利用目的の申請 (Bedrock コンソールのモデルカタログ / Model access) が要る。
  クロスリージョン推論プロファイル (`apac.` などで始まるもの) をコピー元にする場合は、振り分け先のリージョンでもモデルが使える必要がある。
  申請と承認は CDK では行わない。aratam の `doctor` で応答が返ることを確かめる
- **GuardDuty が既に有効なアカウント**: detector を作れないので `guardDuty.enabled: false` にする (既存の detector で `04-guardduty-sample-findings.sh` は動く)
- **posture の項目** (CloudTrail の証跡、パスワードポリシー、S3 Public Access Block、ルート MFA): アカウント全体の設定なので sandbox では変えない。開発用アカウントの設定どおりに出る
- **ルートユーザーの利用** (`root_usage`): スクリプトにしない (scenarios/README.md)

## 開発

- テストは CDK の assertions (`Template.fromStack`) を Node 標準の `node:test` で回す。実 AWS には接続しない
- `cdk.json` で CloudFormation の検証の警告をエラーにしている (`@aws-cdk/core:validateAgainstDefaultRules`)。テストも同じ
- 依存は `aws-cdk-lib` / `constructs` / `aws-cdk` (CLI) / `typescript` / `@types/node` だけ。足す前に PR で理由を書く
- 依存の 7 日待機は pnpm の `minimumReleaseAge` (解決時に強制) と Dependabot の cooldown の 2 段構え。CI は `pnpm install --frozen-lockfile`
- cdk の CLI のテレメトリと notices (ネットワークに出る) は `cdk.json` で止めている
