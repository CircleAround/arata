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

スタック名は `prefix` (既定 `arata-sandbox`)。出力: `ReadonlyRoleArn`、`NginxLogGroupName`、`ExternalRoleArn`、`TestUserNames`、(Bedrock を有効にしたとき) `InferenceProfileArn`。

## 必要なもの

- **Node 24** (`.node-version` の版。24.22.1 以上、25 未満)。TypeScript は Node の型除去でそのまま動かす (ts-node などは使わない)。
  範囲外の Node では `pnpm install` がエラーで止まる (`pnpm-workspace.yaml` の `engineStrict: true`)
- pnpm 10 (`package.json` の `packageManager` の版。`corepack enable` で揃う)
- aws CLI v2 (シナリオと arata の profile 用)
- 開発用アカウントで CloudFormation・IAM・CloudWatch Logs・Secrets Manager (と任意の GuardDuty・Access Analyzer・Bedrock) を作れる認証情報

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
| `guardDuty.enabled` / `accessAnalyzer.enabled` / `bedrock.enabled` | 任意の機能。暗黙の既定は持たないので、3 つとも書く |
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
- `checks.credential_hygiene.unused_days: 1` (試験用のアクセスキーを翌日から「未使用」として出す)

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
| IAM・CloudFormation | 無料 |

使わない間は `cdk destroy` しておく。

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
