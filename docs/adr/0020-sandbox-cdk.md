# 0020. 試験環境 (sandbox) は開発用の AWS アカウントに CDK (TypeScript) で作り、配布用のロールは素の CloudFormation のまま取り込む

- 日付: 2026-11-01
- 状態: 採用

## 背景

sandbox = arata の試験用に条件を整えた、開発用アカウント上の環境。

arata の自動テストは AWS を偽物 (固定値のクライアント・`httptest`) に差し替えて、「AWS がこう返したらこう判定する」を固めている。
足りないのは「本物の AWS が本当にそう返すか」の確認で、これは利用者の環境で初めて分かっていた
(CloudTrail の記録のされ方、Logs Insights のクエリの受理、認証情報レポートの中身、権限の過不足など)。
利用者の環境は試験のために条件を変えられず、怪しい出来事も起こせない。
そこで、開発用のアカウントに「各チェックに中身が出る状態」を作り、怪しい出来事を起こして arata を回せる環境が要る。

また、顧客に配る読み取り専用ロール (`deploy/iam/readonly-role.yaml`。設計書 4-1) はまだ無く、action の一覧は README・設計書・doctor の 3 か所に散っていた。

## 決定

- **sandbox は AWS CDK (TypeScript) で作る** (`deploy/sandbox/`)。読み取り専用ロール、nginx のロググループ、試験用 IAM ユーザー、
  外部アカウントから引き受けられるロール、任意で GuardDuty・IAM Access Analyzer・Bedrock の application inference profile を作り、
  `cdk destroy` で全部消える (全リソース `DeletionPolicy: Delete` をテストで固定)
- 置くものには実権限を付けない。試験用ユーザーと外部用ロールはポリシーを持たない (漏れても何もできない。テストで固定)。
  パスワードは Secrets Manager で生成して動的参照で渡し、アクセスキーの秘密値はどこからも参照しない
- 設定はリポジトリの外の JSON を `cdk deploy -c config=<path>` で渡す。未知のキー・型の誤り・不足は deploy の前にまとめて報告する。
  リポジトリには架空の値の例だけを置く。スタックの env を設定のアカウントに固定し、別アカウントの認証情報では deploy できない
- 怪しい出来事は `deploy/sandbox/scenarios/` のスクリプトで起こし、何を起こして arata のどのチェックで何が出るはずかを README に書く。
  スクリプトは今の認証情報のアカウントが `SANDBOX_ACCOUNT` と違えば何もしない
- **Go モジュールとは分ける**。`deploy/sandbox` は独立した `package.json` を持ち、arata と aratam のバイナリにも go.mod にも入らない。
  CI も別のワークフロー (`sandbox.yml`、`deploy/**` の変更でだけ走る)。AWS には接続しない (synth は架空の値の設定で)
- **配布用のロールは素の CloudFormation** (`deploy/iam/readonly-role.yaml`)。顧客に CDK を強いない。sandbox はこれを `CfnInclude` で取り込み、
  定義は 1 か所にする。信頼先は AWS の主体と IAM Roles Anywhere のトラストアンカーをパラメータで受ける (どちらも空なら Rules で拒否)。
  action は Go の collector の一覧 (`cwlogs.RequiredActions`・`account.RequiredActions`・LookupEvents) と過不足なく一致することを Go のテストで固定する
- **パッケージマネージャは pnpm**。公開日の待機 (`minimumReleaseAge`) をツール側で強制でき、依存の解決が厳格 (宣言していない依存を読めない) だから。
  版は `packageManager` で sha512 付きで固定し、Node 24 同梱の corepack で使う
- サプライチェーンは ADR 0017 と同じ 2 段構え: 提案は Dependabot (npm、cooldown 7 日)、強制は pnpm の `minimumReleaseAge` (10080 分) と CI の
  `scripts/agegate.ts` (ロックファイルの全パッケージの公開時刻を npm レジストリで確かめる。`--frozen-lockfile` は既にロックされた版の公開日を見ないため)。
  依存は `aws-cdk-lib`・`constructs`・`aws-cdk`・`typescript`・`@types/node` だけ。テストは Node 標準の `node:test`、実行は Node の型除去で、
  jest・ts-node は使わない
- CloudFormation の検証の警告をエラーにする (`@aws-cdk/core:validateAgainstDefaultRules`)。deploy して初めて分かる誤り (IAM の説明に使えない文字など) を synth で止める。
  cdk の CLI のテレメトリ・notices・バージョン報告は止める

## 検討した選択肢

- **docker のフェイク AWS (LocalStack / moto)**: 手元で無料で動くが、こちらの想定どおりに返すものを作るだけで、本物との差 (記録の遅れ、
  Insights の構文、認証情報レポートの形式、権限の評価) を検出できない。既存の自動テスト (固定値の偽クライアント) と役割が重なる。却下
- **Terraform**: 社内の標準が CDK で、state の置き場所と管理 (ロック、漏れたときの秘密値) を別に持つことになる。却下
- **sandbox も素の CloudFormation**: 試験ユーザーの数・任意機能の on/off を設定で変えるには条件とパラメータが増えすぎ、テストも書きにくい。却下
- **配布用のロールも CDK で書く**: 顧客に CDK (Node と bootstrap) を強いる。生成した CloudFormation を配る案も、生成物と元の 2 つを持つことになる。却下
- **npm**: `minimumReleaseAge` に当たる待機をツール側で強制できない (CI の検査だけになる)。却下
- **jest / ts-jest / ts-node**: 依存の木が大きくなる。Node の標準 (`node:test`・型除去) で足りる。却下
- **Go の tools/agegate を npm に対応させる**: Go と npm の両方を知る道具になり、sandbox を Go モジュールから分ける方針に反する。依存なしの小さなスクリプトにした

## 結果

- 本物の AWS で、各チェックが決めたとおりに出るかを、利用者の環境に触れずに確かめられる
- 配布用ロールの action が collector とずれると Go のテストが落ちる
- 引き受けるコスト: 開発用アカウントの費用 (Secrets Manager は試験ユーザー 1 人あたり月 0.40 USD、GuardDuty は 30 日の試用の後に数 USD/月など)。
  使わない間は destroy する
- 引き受けるコスト: Node 24 と pnpm を開発環境に入れる (sandbox を触る人だけ)。Node の型除去に頼るので、型除去で消せない構文 (enum など) は使えない
- 引き受けるコスト: `gofmt -l .` は `deploy/sandbox/node_modules` の中の Go の雛形まで読むので、`gofmt -l $(git ls-files '*.go')` にした (CLAUDE.md)
- アカウント全体の設定 (CloudTrail の証跡、パスワードポリシー、S3 Public Access Block) は sandbox では変えない。posture は開発用アカウントの設定どおりに出る
