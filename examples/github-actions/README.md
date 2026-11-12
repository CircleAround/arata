# GitHub Actions で定期実行する

サーバーを持たずに arata と aratam を定期実行する見本です。[arata-audit.yml](arata-audit.yml) を自分のリポジトリの `.github/workflows/` に写して使います。
実行環境は毎回消えるので、ストアは S3 に置きます (README「S3 ストア」、ADR 0034)。ここの値はすべて架空です。
複数の AWS アカウントを 1 つのリポジトリで監査するなら [arata-audit-multi.yml](arata-audit-multi.yml) を使います (下の「複数のアカウントを 1 つのリポジトリで監査する」)。

| 見本 | いつ動くか | すること |
|---|---|---|
| [arata-audit.yml](arata-audit.yml) / [arata-audit-multi.yml](arata-audit-multi.yml) | 定時 (と手動) | 監査して Slack に通知する |
| [arata-triage.yml](arata-triage.yml) | 手動 (Actions の画面) | finding を ack / snooze / resolve する (下の「finding を片付ける」) |
| [arata-check.yml](arata-check.yml) | PR | 設定と allowlist.yaml の形を検査する (下の「PR で設定を検査する」) |

```
schedule → OIDC で実行用ロール ┬→ 読み取り専用ロールへ連鎖 → 監査対象 (読むだけ)
                               └→ ストアのバケット (読み書き)
         → arata run → aratam notify → Slack
```

arata の版は v0.5.1 以降を使います (S3 ストアは v0.4.0 から。v0.5.0 までは、Bedrock の新しいモデルで aratam の要約が失敗します)。

## 用意するもの

設定ファイルを置くリポジトリは **非公開** にしてください。allowlist にはアカウント ID や ARN が入り、Actions のログもリポジトリを読める人に見えます。
このリポジトリは、ストアへの書き込み・Slack の Webhook・監査対象の読み取りロールへの入口を持ちます。fork の禁止、main の保護、Actions の設定などの前提は、下の「実行するリポジトリと環境を堅くする」にまとめています。手順 1〜7 と合わせて設定してください。

### 1. 実行の仕組み (OIDC プロバイダ・ストアのバケット・実行用ロール)

arata を動かす側のアカウントに [deploy/github-actions/runner.yaml](../../deploy/github-actions/runner.yaml) を置きます (素の CloudFormation。`cdk bootstrap` は要りません)。
監査対象と同じアカウントでも動きますが、ストアのバケットはできれば監査対象とは別のアカウントに置きます。
テンプレートは arata のリポジトリにあります。clone するか、使う版のタグから 2 つのファイル (`runner.yaml` と手順 2 の `readonly-role.yaml`) を取得して、パスを読み替えます。

```sh
aws cloudformation deploy --stack-name arata-runner \
  --template-file deploy/github-actions/runner.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubRepository=example-org/security-audit \
    AuditRoleArns=arn:aws:iam::123456789012:role/arata-readonly

aws cloudformation describe-stacks --stack-name arata-runner --query 'Stacks[0].Outputs' --output table
```

出力の `RunnerRoleArn` (実行用ロール) と `StoreUrl` (ストア) を後の手順で使います。

| パラメータ | 中身 |
|---|---|
| `GitHubRepository` (必須) | 設定ファイルを置くリポジトリ。OIDC トークンの `sub` の `repo:` の部分と同じ形で書く (下の注意) |
| `AuditRoleArns` (必須) | 手順 2 で作る読み取り専用ロールの ARN。まだ無くてよい (名前は既定で `arata-readonly`)。複数ならカンマ区切り |
| `OIDCProviderArn` | アカウントに GitHub の OIDC プロバイダが既にあれば、その ARN。空なら作る |
| `GitHubBranch` | 既定は `main`。定時実行は既定のブランチでだけ動く |
| `GitHubWorkflowRef` | (任意) ワークフローのファイルまで絞る。下の注意 |
| `StoreBucketName` / `StorePrefix` | バケットの名前 (空なら自動) と、実行用ロールが読み書きできる prefix (空ならバケット全体) |
| `NoncurrentVersionDays` | 古い版のオブジェクトを消すまでの日数 (既定 90)。SQLite は run のたびに置き換わる |
| `BedrockInferenceProfileArn` | (任意) aratam の `llm.provider: bedrock` で使う推論プロファイルの ARN。空なら Bedrock の権限を足さない (手順 3) |
| `RoleName` | 既定は `arata-runner` |

- **OIDC プロバイダはアカウントに 1 つ**しか作れません。先に確かめます: `aws iam list-open-id-connect-providers`。`token.actions.githubusercontent.com` があれば `OIDCProviderArn=<その ARN>` を足します
- **`GitHubRepository` の形**: 信頼は `sub` の完全一致 (`repo:<GitHubRepository>:ref:refs/heads/<GitHubBranch>`) で、ワイルドカードは受け付けません。
  2026-07-15 より後に作った (または名前を変えた・移した) リポジトリは、`sub` に ID が入ります (`repo:example-org@1234567/security-audit@7654321:ref:refs/heads/main`)。
  その場合は `GitHubRepository=example-org@1234567/security-audit@7654321` と書きます。値は次で作れます

  ```sh
  gh api repos/example-org/security-audit --jq '"\(.owner.login)@\(.owner.id)/\(.name)@\(.id)"'
  ```

  どちらの形かは次で分かります。`use_immutable_subject` が `true` なら ID 入りで、`sub_claim_prefix` の `repo:` より後ろが `GitHubRepository` に書く値です。
  従来の形のリポジトリも ID 入りに切り替えられます (下の「実行するリポジトリと環境を堅くする」の 3)

  ```sh
  gh api repos/example-org/security-audit/actions/oidc/customization/sub
  ```
- **`GitHubWorkflowRef`**: 指定すると、トークンの `job_workflow_ref` が完全に一致するワークフローだけが引き受けられます
  (例 `example-org/security-audit/.github/workflows/arata-audit.yml@refs/heads/main`)。同じリポジトリの `main` にある別のワークフローからは使えなくなります。
  既定は空です (GitHub の文書は、再利用しないワークフローでのこの値を定めていないため。設計書 9 章)
- **GitHub の environment は使いません**。ジョブに `environment:` を付けると `sub` の形が変わり (`repo:...:environment:<名前>`)、このロールを引き受けられなくなります
  (secrets を environment に置く案との関係は、下の「実行するリポジトリと環境を堅くする」の 5)
- **スタックを消しても、バケットと OIDC プロバイダは残ります** (監査の状態を失わないため・プロバイダはアカウントで共有されるため)。作り直すときは `OIDCProviderArn` に残ったプロバイダを渡します

実行用ロールの権限は、ストアの `s3:GetObject`・`s3:PutObject`・`s3:ListBucket` と、`AuditRoleArns` への `sts:AssumeRole` だけです (削除の権限はありません)。
`BedrockInferenceProfileArn` を指定したときだけ、そのプロファイルを通した `bedrock:InvokeModel` が加わります。
`s3:ListBucket` は `s3:prefix` の条件を付けません。S3 は `ListBucket` の無い主体に、無いキーを 404 ではなく 403 で返します。arata は 404 だけを「無い」とみなすので、403 になると初回の run が `STORE_UNAVAILABLE` で止まるおそれがあります。見えるのはキーの名前だけなので、バケットは arata 専用にします (テンプレートが作るバケットは専用です)。

### 2. 監査対象の読み取りロール

監査対象のアカウントに [deploy/iam/readonly-role.yaml](../../deploy/iam/readonly-role.yaml) を置き、`TrustedPrincipalArn` に手順 1 の出力 `RunnerRoleArn` を渡します。
同じアカウントを監査するなら同じ認証のまま、別のアカウントならそのアカウントの認証で実行します。ストアへの権限は足しません。

```sh
aws cloudformation deploy --stack-name arata-readonly \
  --template-file deploy/iam/readonly-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustedPrincipalArn=arn:aws:iam::123456789012:role/arata-runner
```

順序は 1 → 2 です。信頼ポリシーに書く主体 (実行用ロール) は、先に存在している必要があります。
出力の `RoleArn` が手順 1 の `AuditRoleArns` と違う (ロールの名前を変えた) ときは、手順 1 を正しい ARN でもう一度実行します。

実行用ロールの `AssumeRole` は CloudTrail に残るので、allowlist に足さないと `unknown_assume_role` が毎回報告します。

```yaml
principals:
  - arn: arn:aws:iam::123456789012:role/arata-runner
    note: GitHub Actions の実行用ロール
    approved_at: 2026-11-04
    dynamic_source: true   # ランナーの送信元は毎回変わる (ADR 0027)
```

<details>
<summary>テンプレートを使わない場合</summary>

手で作るときも、中身は 2 つのテンプレートと同じにします (定義はテンプレートが正で、ここには写しません)。

- OIDC プロバイダ: URL は `https://token.actions.githubusercontent.com`、対象者は `sts.amazonaws.com`
- バケット: バージョニング・既定の暗号化・パブリックアクセスブロック (4 項目)・TLS 必須のバケットポリシー
- 実行用ロール: 信頼ポリシーは `sts:AssumeRoleWithWebIdentity` で、`StringEquals` の `token.actions.githubusercontent.com:aud` (`sts.amazonaws.com`) と `:sub` (上の形)。
  `StringLike` と `repo:example-org/*` のようなワイルドカードは使いません。権限は `runner.yaml` の `Policies` の 3 つの文、最大セッションは 1 時間
- GitHub の environment で承認や secrets を分けたいときは、`sub` を `repo:example-org/security-audit:environment:audit` にしたロールを自分で作ります (ブランチの条件は効かなくなります)

</details>

### 3. 設定ファイル

`arata/` に `arata.yaml`・`aratam.yaml`・`allowlist.yaml` を置きます (任意で `llm.context_file` のファイル)。

```yaml
# arata/arata.yaml
store: s3://example-arata-store/example   # 手順 1 の出力 StoreUrl (の下の prefix)。ワークフローの ARATA_STORE_URL と同じ値
aws:
  region: ap-northeast-1
  profile: arata-audit                    # ワークフローが書くプロファイル。監査の読み取りはこのロールで行う
# store_profile は書かない。ストアは標準の連鎖 (実行用ロール) で書く
```

バケットを別のロールで書くときだけ、ワークフローの AWS の設定に `[profile arata-store]` (`role_arn` と `credential_source = Environment`) を足して `store_profile: arata-store` と書きます。`credential_source` は `role_arn` なしでは使えません。

```yaml
# arata/aratam.yaml (抜粋)
max_age: 26h
on_quiet: short            # 死活監視を兼ねるので silent にしない
llm:
  provider: none           # claude-cli は実行環境に入っていない。bedrock は下
slack:
  webhook_env: ARATAM_SLACK_WEBHOOK
  urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK
```

bot トークンで送るなら (手順 4 の「bot トークンで送る」)、Webhook の 2 つを空にして、トークンの環境変数の名前とチャンネル ID を書きます。
チャンネル ID は秘密ではないので、設定に書きます。

```yaml
# arata/aratam.yaml (抜粋。bot トークンの方式)
slack:
  webhook_env: ""
  urgent_webhook_env: ""
  bot_token_env: ARATAM_SLACK_BOT_TOKEN   # 環境変数の名前 (トークンは書かない)
  channel: C0123456789                    # 通常用のチャンネル ID
  urgent_channel: C0123456780             # 緊急用。空なら channel に送り、冒頭に urgent_mention を付ける
```

LLM で要約するなら `provider: bedrock` にします。実行用ロールに権限が要るので、手順 1 のコマンドに `BedrockInferenceProfileArn` を足してもう一度実行します
(読み取り専用ロールには足しません。Bedrock を呼ぶのは aratam で、実行用ロールのまま呼びます)。

```sh
    BedrockInferenceProfileArn=arn:aws:bedrock:ap-northeast-1:123456789012:inference-profile/<推論プロファイル ID>
```

```yaml
# arata/aratam.yaml (抜粋)
llm:
  provider: bedrock
  model: <推論プロファイル ID>   # BedrockInferenceProfileArn の末尾と同じもの (ARN をそのまま書いてもよい)
  region: ap-northeast-1         # ARN のリージョンと同じ
  timeout: 120s
  # profile は書かない (標準の連鎖 = 実行用ロールで呼ぶ)
```

- 推論プロファイルの ID と ARN は `aws bedrock list-inference-profiles --region ap-northeast-1` で分かります。モデルの利用申請は Bedrock のコンソールで先に済ませます
- 許すのは、指定した 1 つのプロファイルを通した呼び出しだけです。プロファイルが振り分ける先のリージョンの基盤モデルは、`bedrock:InferenceProfileArn` の条件でそのプロファイル経由に限って許します (基盤モデルを直接は呼べません)
- `model` を別のプロファイルに変えたら、`BedrockInferenceProfileArn` も変えます。食い違うと aratam は LLM の失敗として report.md の原文を送ります (通知は止まりません)

### 4. Secrets

| 名前 | 中身 |
|---|---|
| `ARATA_RUNNER_ROLE_ARN` | 実行用ロールの ARN (手順 1 の出力 `RunnerRoleArn`) |
| `ARATA_AUDIT_ROLE_ARN` | 読み取り専用ロールの ARN (手順 2 の出力 `RoleArn`) |
| `ARATAM_SLACK_WEBHOOK` | 通常用の Webhook |
| `ARATAM_SLACK_URGENT_WEBHOOK` | 緊急用の Webhook |

**Slack の疎通を確かめる**: Webhook を secrets に入れたら、同じ URL で手元から試験メッセージを 1 通送ります。チャンネルと Webhook の対応 (通常用と緊急用の取り違え) は、送ってみないと分かりません。

```sh
read -rs ARATAM_SLACK_WEBHOOK && export ARATAM_SLACK_WEBHOOK                  # 貼り付けて Enter (シェルの履歴に残さない)
read -rs ARATAM_SLACK_URGENT_WEBHOOK && export ARATAM_SLACK_URGENT_WEBHOOK
aratam doctor -c arata/aratam.yaml                  # 送らない。Webhook の環境変数があるかと、LLM の疎通を見る
aratam test-notify -c arata/aratam.yaml             # 実際に送る。通常用のチャンネルに 1 通
aratam test-notify -c arata/aratam.yaml --urgent    # 実際に送る。緊急用のチャンネルに 1 通
```

- `doctor` は Slack に何も送りません (届くかは分かりません)。`test-notify` は本当に届くので、チャンネルの人に一言伝えてから実行します
- secrets に入れた値そのものは、最初の `workflow_dispatch` の実行 (手順 5 の最後) で確かめられます。`on_quiet: short` なら、新規が無くても 1 行届きます。
  決定: 見本のワークフローに test-notify 用の入力は足しません。手動の実行が同じことを確かめ、入力を増やすと監査のワークフローの分岐が増えるためです

#### bot トークンで送る (secret は 1 つ)

Webhook はチャンネルごとに URL (秘密) が要ります。bot トークンなら秘密は 1 つで、送り先はチャンネル ID を `aratam.yaml` に書くだけです。
監査対象ごとにチャンネルを分けるとき (下の「複数のアカウント」) に向きます。Webhook の 2 つの secret の代わりに、次の 1 つを置きます。

| 名前 | 中身 |
|---|---|
| `ARATAM_SLACK_BOT_TOKEN` | Slack アプリの Bot User OAuth Token (`xoxb-` で始まる) |

Slack アプリは、利用する組織が manifest から自分で作ります (Slack のワークスペースごとに 1 つ)。arata は公開配布のアプリを持ちません。
配布用のアプリにすると、インストールを受けるサーバーと各組織のトークンを開発側が預かることになるためです。トークンを持つのは、アプリを入れた組織だけです。

1. <https://api.slack.com/apps> →「Create New App」→「From a manifest」→ ワークスペースを選び、arata のリポジトリの `deploy/slack/app-manifest.yaml` の中身を貼ります。
   bot の scope は `chat:write` だけで、受け口 (Event Subscriptions など) を持たない、投稿だけのアプリです。scope は足しません
2. 「Install to Workspace」で入れ、「OAuth & Permissions」の Bot User OAuth Token を secret `ARATAM_SLACK_BOT_TOKEN` に入れます
3. 通知先のチャンネルで `/invite @arata` を実行します (緊急用のチャンネルを分けるなら、そちらでも)。招待していないチャンネルには送れません
4. チャンネル ID (チャンネルの詳細の一番下。`C0123456789` の形) を `aratam.yaml` の `slack.channel` / `urgent_channel` に書きます (手順 3)
5. ワークフローの notify の `env` を、Webhook の 2 行から `ARATAM_SLACK_BOT_TOKEN` の 1 行に替えます (見本にコメントで書いてあります)

```sh
read -rs ARATAM_SLACK_BOT_TOKEN && export ARATAM_SLACK_BOT_TOKEN   # 貼り付けて Enter (シェルの履歴に残さない)
aratam doctor -c arata/aratam.yaml                  # 送らない。auth.test でトークンが有効かと、LLM の疎通を見る
aratam test-notify -c arata/aratam.yaml             # 実際に送る。通常用のチャンネルに 1 通
aratam test-notify -c arata/aratam.yaml --urgent    # 実際に送る。緊急用のチャンネルに 1 通
```

- `doctor` は投稿しないので、bot がチャンネルにいるかは分かりません (`chat:write` だけでは調べられません)。`test-notify` が `not_in_channel` で失敗したら、
  そのチャンネルで `/invite @arata` を実行します。`channel_not_found` は、チャンネル ID の誤りか、招待していない非公開チャンネルです
- 同じワークスペースの複数のチャンネルに送るなら、アプリもトークンも 1 つです。監査対象ごとに `aratam.yaml` のチャンネル ID を変えるだけです。
  別の組織と Slack Connect で共有するチャンネルも、招待すれば同じアプリで送れます
- トークンのローテーションは有効にしません (manifest は無効にしてあります)。有効にするとトークンが 12 時間で切れますが、aratam は更新の仕組みを持ちません
- トークンは、bot を招待したすべてのチャンネルに投稿できます (Webhook は 1 つのチャンネルだけ)。招待するチャンネルを通知用だけにします。
  漏れた疑いがあれば、Slack アプリの設定でトークンを取り消し、入れ直して新しい値を secret に入れます
- トークンを AWS Secrets Manager に置き、main のワークフローだけが読めるようにする形は今後の課題です (arata の `docs/roadmap.md`、ADR 0044)

### 5. 初回の収集は手元で

`arata init` はワークフローの認証の期限 (1 時間) を超え得るので、手元で同じ `arata.yaml` を使って実行します。**定時のワークフローを main に入れるのは、この収集が終わってから**にしてください (理由は下)。

```sh
# ~/.aws/config に同じ名前の arata-audit のプロファイルを用意し、ストアを書ける認証を標準の連鎖で渡す
AWS_PROFILE=example-store-writer arata doctor -c arata/arata.yaml
AWS_PROFILE=example-store-writer arata init -c arata/arata.yaml
```

`store: s3://` のまま実行するので、結果はそのままバケットへ置かれ、次のワークフローの run が続きから動きます。実行できたら `workflow_dispatch` で 1 回動かして確かめます (その前に手順 6 と、LLM を使うなら手順 7)。

- **かかる時間**: 収集する期間 (`--window`。既定は 7 日、CloudTrail の履歴は最長 90 日) とリージョンの数、その間のイベントの量に比例し、数十分〜数時間です。
  CloudTrail の LookupEvents は毎秒 2 リクエストまでで、arata はこれを超えないように引くためです。進み具合は標準エラーのログで分かります (1 日分ずつ進みます)
  - 例: CloudTrail のみ・有効なリージョン 17 のアカウントで、既定の 7 日分が約 20 分 (約 1.1 万件)。2 回目以降の daily は Actions で約 3 分
- **手元の認証の期限で止まり得ます**: 収集は読み取りの認証 (`arata-audit` のプロファイル) を、結果の保存はストアを書く認証を使います。
  どちらも期限が収集より短いと途中で切れます。自動で更新される認証 (`role_arn` を書いたプロファイルや IAM Identity Center のプロファイル) を使うか、期限に収まる `--window` にします
  - 読み取りの認証だけが切れたとき: その日の収集が失敗して止まり (終了コード 3)、終わった日までをストアに確定します。認証を取り直して `arata init --resume -c arata/arata.yaml` で続きから再開できます
  - ストアを書く認証も切れていたとき: 最後の保存ができず、**その実行で収集した分は失われます** (メッセージで知らせます。S3 のストアは実行の最後にまとめて書き戻すため)。
    `arata init --resume` (保存済みの init が無ければ `arata init`) でやり直します
- **中断しても続きから再開できます**: Ctrl-C (SIGINT) や SIGTERM で止めると、終わった日までをストアに確定して終了コード 3 で終わります。
  `arata init --resume` は止まった日の頭から引き直し、窓の終わりは再開した時点まで延びます。完了した init に `--resume` しても何もしません。
  `--resume` を付けずに `arata init` すると最初からやり直しになるので注意してください
- **実行中は Actions の定時の実行を止めておきます**: 収集の途中で定時の監査が同じストアに書くと、後から書こうとした側が `STORE_CONFLICT` で失敗します。
  ストアは壊れませんが、init が後になれば数時間の収集を失います (`concurrency` は Actions の中の排他で、手元の実行は止められません)。
  初めてなら、ワークフローを main に入れるのを init の後にします。既に動いているなら、Actions の画面でワークフローを無効 (Disable workflow) にし、init が終わったら有効に戻します

### 6. 最初の run は通知せずに中身を見る

`arata init` はベースラインを作るだけで、finding を出しません。その後の**最初の run** は、長く溜まっていた設定や主体 (古いアクセスキー、公開の設定、承認していない主体など) が一度に出て、通知が多くなり得ます。
チャンネルの人を驚かせないよう、最初の run は手元で実行し、Slack に送らずに中身を見ます。手順 5 と同じ認証で、init の直後に行います (定時のワークフローを main に入れる前)。

```sh
out=$(mktemp -d)
AWS_PROFILE=example-store-writer arata run -c arata/arata.yaml --profile daily --out "$out/daily"
aratam notify -c arata/aratam.yaml --in "$out/daily" --dry-run --llm none    # 送らずに、通知になる内容を標準出力へ
AWS_PROFILE=example-store-writer arata review -c arata/arata.yaml            # 未対応の一覧

# weekly も同じ (アカウントの今の状態を見るチェックは weekly にあり、最初は多くなりやすい)
AWS_PROFILE=example-store-writer arata run -c arata/arata.yaml --profile weekly --out "$out/weekly"
aratam notify -c arata/aratam.yaml --in "$out/weekly" --dry-run --llm none
```

- **手元の run もストアに確定します** (`store: s3://` のまま実行するため)。ここで出た finding は報告済みになり、以後の定時の実行は「新規」としては報せません
  (未対応の件数には残ります。重大度が上がれば再報告されます)。定時の実行が報せるのは、その後に新しく起きたことだけです
- `--dry-run` は Slack に送らず、Webhook の環境変数も要りません。`--llm none` を外すと LLM の要約も確かめられます (手元の認証で LLM を呼びます)
- 出た finding は、定時の実行に任せる前に片付けます。正当な主体は allowlist.yaml の PR で承認し (下の「approve は PR で allowlist.yaml を直す」)、
  確認が済んだものは `arata ack`、直したものは `arata resolve`、後で直すものは `arata snooze --until` にします。直すべきものは、ここで担当を決めます
- `$out` には ARN などが入っています。見終わったら消します
- 通知の本文には上限があり、多いときは情報の行や理由文から削って収めます (全文はストアの `reports/`)。それでも最初の 1 通が長くなるのは変わらないので、この手順を踏みます
- 決定: 見本のワークフローに「通知しない」入力は足しません。手順 5 で手元にストアを書ける認証が既にあり、同じ場所で続けて行えること、
  Actions で動かすと中身を見る場所が無いこと (ログと Summary には finding の中身を出さない方針です) が理由です

### 7. 監査対象の前提 (LLM を使うとき)

`llm.provider` を `none` 以外にしたら、最初の通知の前 (定時のワークフローを main に入れる前) に、`llm.context_file` を書きます。
aratam が LLM に「この監査対象の前提」として渡す Markdown です。**無くても動きます**。ただ、無いと LLM はアプリの事情を知らないので、正規の動作にも一般的で慎重な助言しか書けません。
判定 (重大度・緊急用に送るか) は規則が決めるので、前提を書いても変わりません。

```yaml
# arata/aratam.yaml (抜粋)
llm:
  context_file: aratam-context.md   # 設定ファイルと同じディレクトリに置く (16 KiB まで)
```

書くとよいこと (形の例は [examples/aratam-context.md](../aratam-context.md)。値は架空):

- どのアプリが本番か (アカウント、入口、ログインや決済のパス)
- デプロイの流れ。どの主体が何を引き受けるか (例: CI の OIDC のロール `github-actions-deploy` が CloudFormation の実行ロールを引き受ける)
- 起動時に秘匿値をまとめて読むロール (例: ECS の実行ロールが、タスクの起動のたびに `prod/app/*` を読む)
- 正規の送信元 (外形監視、拠点、CI)
- 監査の仕組み自体 (実行用ロール `arata-runner` と読み取り専用ロール `arata-readonly`) を誰が・何で置いたか
- 秘密 (Webhook・キー)、氏名、メールアドレスは書きません

同じレポートで前提の有無を比べると、前提ありの要約は「前提のどれに合うか・何だけ確かめればよいか」を書き、前提と食い違う点 (未承認の主体など) は隠さずに指摘しました。
前提は承認の代わりにはなりません。「正規」と書いても allowlist には入らず、未承認の主体は報告され続けます。

最初の収集と最初の run (手順 5・6) の後なら、AI (LLM) に下書きさせられます。`arata help ai runtime` を読ませ、`arata review` の結果と、読み取り専用ロールで読める構成から下書きを PR にさせて、
**人が事実を確かめてマージします**。事実が変わったら (デプロイの方式、送信元、ロールの入れ替え) PR で直します。古い前提は、LLM に誤った安心を書かせます。
`aratam config check` (下の「PR で設定を検査する」) が、ファイルが読めるかと大きさを確かめます。

## 実行するリポジトリと環境を堅くする

監査のリポジトリを使える人は、実行用ロール (ストアの読み書き・監査対象の読み取り) と Slack の Webhook (bot トークンの方式ならトークン) を使えます。目指す状態は次の 2 つです。

- **main にコミットを入れられる人だけが、実行用ロールを使える** (fork、ほかのブランチ、PR からは使えない)
- **secrets を読める人が最小**

下の `gh api` はすべて読み取りです (`example-org/security-audit` は自分のリポジトリに読み替えます)。組織の設定は、組織の所有者でないと読めないものがあります。
AI (LLM) に点検させるときは `arata help ai runtime` (同じ項目のチェックリスト) を読ませます。設定を変えるのは人です。
main の保護 (4) と environment (5) は、非公開のリポジトリでは GitHub の有料プラン (Team など) が要ります。

### 1. リポジトリは非公開にし、fork を禁止する

監査のリポジトリは fork される必要がありません。fork は、allowlist (アカウント ID・ARN) と履歴の写しを、元のリポジトリの管理の外に作ります。

```sh
gh api repos/example-org/security-audit --jq '{private, visibility, allow_forking, fork}'
gh api orgs/example-org --jq '.members_can_fork_private_repositories'
gh api repos/example-org/security-audit/forks --jq 'length'
```

- `private: true`、`allow_forking: false`、組織の `members_can_fork_private_repositories: false`、既にある fork が 0 件
- 設定の場所: リポジトリの Settings → General → 「Allow forking」を外す。組織の Settings → Member privileges → 「Allow forking of private repositories」を外す

### 2. fork の PR と、PR のワークフローに権限を渡さない

```sh
gh api repos/example-org/security-audit/actions/permissions/fork-pr-workflows-private-repos
```

- `run_workflows_from_fork_pull_requests: false` (`send_write_tokens_to_workflows`・`send_secrets_and_variables` も `false`)。
  fork を禁止していれば fork の PR は来ませんが、禁止が外れたときの 2 段目として閉じておきます (Settings → Actions → General → 「Fork pull request workflows」。組織で無効なら、リポジトリでは有効にできません)
- **`pull_request_target` を使いません** (`workflow_run` も)。PR の内容を、secrets を持つ文脈で動かす経路になります
- `pull_request` で動かすのは [arata-check.yml](arata-check.yml) の形に留めます。権限は `contents: read` だけで、secrets も OIDC も使いません。
  secrets か OIDC を使うワークフロー (監査、finding の片付け) は、定時と手動でだけ動かします

### 3. OIDC の信頼は、ID 入りの `sub` で 1 つのブランチに絞る

実行用ロールは、OIDC トークンの `sub` が次の 1 つの文字列に完全に一致するときだけ引き受けられます (手順 1 の `runner.yaml`。ワイルドカードは受け付けません)。

```
repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main
```

- **fork は引き受けられません**。fork は別のリポジトリなので、fork で動くワークフローの `sub` は fork 自身の名前と ID になります
- **同じ名前で作り直したリポジトリも引き受けられません** (ID 入りの形のとき)。従来の形 (`repo:example-org/security-audit:...`) は名前だけで決まるので、
  リポジトリや組織を消した後に同じ名前が別の人に取られると、同じ `sub` を作られます。ID は使い回されません
- **ほかのブランチと PR からも引き受けられません**。ほかのブランチは `ref` が違い、PR のワークフローは `sub` が `...:pull_request` になります

```sh
gh api repos/example-org/security-audit/actions/oidc/customization/sub
aws iam get-role --role-name arata-runner --query 'Role.AssumeRolePolicyDocument'
```

- 1 つ目が `use_default: true`・`use_immutable_subject: true` なら ID 入りです (2026-07-15 より後に作った・名前を変えた・移したリポジトリは、最初からこの形です)
- `use_immutable_subject: false` (従来の形) なら、リポジトリか組織の Actions の OIDC の設定で ID 入りに切り替えます。
  切り替えたら、`GitHubRepository` を `sub_claim_prefix` の `repo:` より後ろの値にしてスタックを更新します (揃うまでは引き受けに失敗します。定時の実行の合間に行います)
- 2 つ目の信頼ポリシーが `StringEquals` だけで、`sub` が上の 1 つだけであること。手で直して `StringLike` や `*` を足さないでください

### 4. main を保護し、書き込み権限を持つ人を最小にする

`sub` を main に絞っているので、**main に入れられる人 = 実行用ロールを使える人**です。main の保護が、実行用ロールの権限の境界になります。

```sh
gh api repos/example-org/security-audit/rules/branches/main --jq '[.[].type]'
gh api repos/example-org/security-audit/rulesets --jq '.[] | {id, name, enforcement}'
gh api repos/example-org/security-audit/collaborators --jq '.[] | select(.permissions.push) | .login'
gh api repos/example-org/security-audit/keys --jq '.[] | {title, read_only}'
```

- main の規則に `pull_request` (PR 必須)・`non_fast_forward` (強制 push の禁止)・`deletion` (削除の禁止) があること。
  迂回できる主体 (`gh api repos/example-org/security-audit/rulesets/<id>` の `bypass_actors`) は置かないか、理由を説明できるものだけにします
- 書き込み権限 (`push`) を持つ人を、監査の運用に要る人だけにします。組織の既定の権限 (base permissions) が write だと、組織の全員が持ちます
- 書き込みのできるデプロイキーや、書き込み権限を持つ外部のアプリを置きません
- `arata-check` を必須のチェックにすると、形の誤った設定は main に入りません (「PR で設定を検査する」)
- PR のレビューを必須にすれば、1 人では main を変えられなくなります。人数が足りずに必須にできないときは、PR の差分を誰が見るかを決めておきます

### 5. secrets は、書き込み権限のある人なら読み出せる

リポジトリの secrets は、**どのブランチのワークフローからも読めます**。書き込み権限のある人は、ブランチにワークフローを足して push すれば、main の保護を通らずに読み出せます。

- 読み出されて困るのは Slack の Webhook か bot トークンです (偽の通知を送れます。bot トークンは、bot を招待したすべてのチャンネルに送れます)。ロールの ARN は読めても、3 の `sub` が合わないので引き受けられません (分かるのはアカウント ID です)
- 今の守りは 4 の「書き込み権限を持つ人を最小に」です。漏れた疑いがあれば Webhook を作り直します (bot トークンなら取り消して入れ直します)。長期の AWS のアクセスキーは secrets に置きません
- **案: GitHub の environment に置き、デプロイできるブランチを main に限る**。environment の secrets は、その environment を参照するジョブにしか渡らず、
  デプロイできるブランチを限れば、ほかのブランチのジョブは environment を使えません
- **ただし、今の `runner.yaml` とは組み合わせられません**。ジョブに `environment:` を付けると、`sub` が `repo:...:environment:<名前>` に変わり (ブランチは `sub` に入らなくなります)、
  実行用ロールを引き受けられなくなります。見本のジョブは OIDC と Webhook を同じジョブで使うので、Webhook だけを environment に移すこともできません。
  テンプレートを environment の `sub` に対応させるのは今後の課題です (arata の `docs/roadmap.md`)
- それまでに environment を使うなら、手順 1 の「テンプレートを使わない場合」のとおり、`sub` を `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:<名前>` にしたロールを自分で作ります。
  この形ではブランチの条件が `sub` から消えるので、**environment のデプロイできるブランチの制限が、実行用ロールの境界になります**。次で確かめます

  ```sh
  gh api repos/example-org/security-audit/environments --jq '[.environments[] | {name, deployment_branch_policy}]'
  gh api repos/example-org/security-audit/environments/audit/deployment-branch-policies --jq '[.branch_policies[] | {name, type}]'
  ```

### 6. Actions の設定

```sh
gh api repos/example-org/security-audit/actions/permissions
gh api repos/example-org/security-audit/actions/permissions/selected-actions
gh api repos/example-org/security-audit/actions/permissions/workflow
gh api repos/example-org/security-audit/actions/permissions/access
```

Settings → Actions → General で設定します。

- 許可する action: `allowed_actions: selected` で、GitHub 製 (`github_owned_allowed: true`) と `aws-actions/configure-aws-credentials@*` (`patterns_allowed`) だけ。
  見本が使う action は `actions/checkout` とこれの 2 つです。action を足すときは、ここにも足します (足さないとワークフローが起動しません)
- 「Require actions to be pinned to a full-length commit SHA」を有効にします (`sha_pinning_required: true`)
- `GITHUB_TOKEN` の既定は read (`default_workflow_permissions: read`)、「Actions が PR を作成・承認する」は無効 (`can_approve_pull_request_reviews: false`)
- ほかのリポジトリからワークフローを使わせません (`access` の応答が `none`)
- checkout は `persist-credentials: false` にします (見本のとおり)。トークンを作業ツリーに残しません

### 7. 見本のワークフローが満たしていること

見本をそのまま写せば、上の前提に合います (arata のリポジトリのテストが固定しています)。書き換えるときは崩さないでください。

- ワークフローの先頭は `permissions: {}`。権限はジョブごとで、監査と片付けは `id-token: write` と `contents: read`、PR の検査は `contents: read` だけ
- secrets か OIDC を使う見本は `schedule` と `workflow_dispatch` でだけ動き、`pull_request_target`・`workflow_run`・`environment:` を使わない
- action は 2 つだけで、どちらも commit SHA で固定。checkout は `persist-credentials: false`
- `run:` に式を埋め込まず、secrets は使う step にだけ渡す

## 複数のアカウントを 1 つのリポジトリで監査する

[arata-audit-multi.yml](arata-audit-multi.yml) を使います。アカウントごとにジョブを分け (matrix)、設定・ストアの prefix・排他をアカウントごとにします。1 つのアカウントが失敗しても、ほかは続きます。

```
aws/
  prod/     arata.yaml  aratam.yaml  allowlist.yaml
  staging/  arata.yaml  aratam.yaml  allowlist.yaml
```

```yaml
# aws/prod/arata.yaml
store: s3://example-arata-store/prod      # prefix はディレクトリの名前と同じにする
aws:
  region: ap-northeast-1
  profile: arata-audit
```

```yaml
# aws/prod/aratam.yaml (抜粋)
name: prod                                # 通知に出す名前。アカウントごとに変えると Slack で見分けられる
```

1 つのアカウントのときとの違いは次のとおりです。

- **手順 1**: 実行の仕組みは 1 つです。`AuditRoleArns` に全アカウントの読み取り専用ロールをカンマ区切りで渡し、`StorePrefix` は空のままにします

  ```sh
  aws cloudformation deploy --stack-name arata-runner \
    --template-file deploy/github-actions/runner.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
      GitHubRepository=example-org/security-audit \
      AuditRoleArns=arn:aws:iam::123456789012:role/arata-readonly,arn:aws:iam::444455556666:role/arata-readonly
  ```

- **手順 2**: 監査対象のアカウントごとに、同じ `TrustedPrincipalArn` で 1 回ずつ実行します
- **ワークフロー**: `matrix.account` にディレクトリの名前を並べます (小文字の英数字とハイフン)。アカウントを足すときは、ディレクトリ・matrix・`AuditRoleArns`・下の secret の 4 か所です
- **Secrets**: `ARATA_AUDIT_ROLE_ARN` の代わりに `ARATA_AUDIT_ROLE_ARNS` を 1 つ置きます。名前からロールを引く JSON です

  ```json
  {"prod": "arn:aws:iam::123456789012:role/arata-readonly", "staging": "arn:aws:iam::444455556666:role/arata-readonly"}
  ```

  アカウントごとに secret を分けて `secrets[...]` で選ぶ形にはしません (式で動的に選ぶと、ジョブにすべての secrets が渡ります)
- **allowlist**: 実行用ロールの `principals` の行を、各アカウントの `allowlist.yaml` に書きます
- **初回の収集**: アカウントごとに手元で `arata init -c aws/<名前>/arata.yaml` を実行します (ストアはアカウントごとなので、順番でも並べてもかまいません。時間と認証の期限の注意は「初回の収集は手元で」)
- **Slack**: Webhook は全アカウントで共通です。宛先を分けたいときは、アカウントごとの `aratam.yaml` の `webhook_env` に別の名前を書き、ワークフローの notify の `env` に足します
  (アカウントを足すたびに secret が増えます)。**bot トークンの方式なら secret は 1 つのまま**で、アカウントごとの `aratam.yaml` の `slack.channel` / `urgent_channel` に
  チャンネル ID を書くだけです (手順 4 の「bot トークンで送る」)

  ```yaml
  # aws/prod/aratam.yaml (抜粋)                    # aws/staging/aratam.yaml (抜粋)
  slack:                                           # slack:
    bot_token_env: ARATAM_SLACK_BOT_TOKEN          #   bot_token_env: ARATAM_SLACK_BOT_TOKEN   (同じ secret)
    channel: C0123456789                           #   channel: C0123456781                    (チャンネルだけ違う)
    urgent_channel: C0123456780                    #   urgent_channel: C0123456780
  ```

実行用ロールは全アカウントの prefix を読み書きできます (分けるのは置き場所で、権限ではありません)。権限まで分けたいときは、アカウントごとにリポジトリと実行の仕組みを分けます。

## finding を片付ける (ack / snooze / resolve)

ストアが S3 にあると、手元にストアを書ける認証が無い人は `arata ack` を実行できません。[arata-triage.yml](arata-triage.yml) を `.github/workflows/` に置くと、Actions の画面から行えます。
見本は複数のアカウントの形です。1 つのアカウントで使うときの直し方は、ファイルの先頭のコメントにあります。

1. Slack の通知で finding の ID (`id: 0123456789ab` の 12 桁) を確かめます
2. GitHub の Actions → **arata-triage** → **Run workflow** を開き、ブランチは **main** のまま、次を入れて実行します

   | 入力 | 中身 |
   |---|---|
   | `account` | アカウント (ディレクトリの名前) |
   | `action` | `ack` = 確認した。再報告しないが未対応の一覧には残る / `snooze` = 期日まで沈黙させる / `resolve` = 対応が終わった (再び観測されたら新規として報告) |
   | `finding_id` | 通知の ID |
   | `reason` | 理由 (必須、1 行)。ARN やアカウント ID は書かないでください (リポジトリを読める人に見えます) |
   | `until` | `snooze` の期日 (`YYYY-MM-DD`。その日の 0 時 UTC まで)。`snooze` のときだけ |

3. 実行の Summary に、誰が・どの finding を・どうしたか・理由が残ります

知っておくこと:

- **理由と操作した人はストアに残りません**。arata の `ack` / `snooze` / `resolve` には理由や操作した人を記録する欄が無いので、記録は Actions の実行履歴 (Summary) が持ちます。
  Actions の実行の記録には保持期間があります (リポジトリの設定。ログの既定は 90 日)。長く残したい判断は、Issue などにも書いてください
- **main で動かします**。実行用ロールの信頼は 1 つのブランチだけ (既定は `main`) なので、ほかのブランチを選ぶと OIDC の引き受けで失敗します。
  `runner.yaml` の `GitHubWorkflowRef` で監査のワークフローのファイルに絞っている場合は、このワークフローからは引き受けられません (`GitHubWorkflowRef` を空にするか、手元で実行します)
- **監査が走っていれば待ちます**。定時の監査と同じ `concurrency` の group (アカウントごと) なので、同じストアへは順番に書きます。
  同じ group で待てるのは 1 つだけです。待っている間にもう 1 つ実行すると、先に待っていたほうが取り消されます。続けて行うときは、前の実行が終わってからにします
- **失敗の見分け**: ログの方針は監査と同じで、出るのは `code` と終了コードだけです。`CONFIG_INVALID` は ID が無い・既に resolved・期日が過去、`STORE_CONFLICT` は同時に書かれた (もう一度実行します)
- ack / snooze 中でも、重大度が上がれば再報告されます (ADR 0022)

### approve は PR で allowlist.yaml を直す

主体の承認 (approve) はこのワークフローに入れていません。`arata approve` は allowlist.yaml への追記と同時にストアの finding も解消するので、追記の PR がマージされる前に finding が消えてしまいます。
承認は allowlist.yaml の差分としてレビューします。

1. ブランチを切り、`aws/<名前>/allowlist.yaml` (1 つのアカウントなら `arata/allowlist.yaml`) の `principals` の末尾に項目を足します

   ```yaml
     - arn: arn:aws:iam::123456789012:role/github-actions-deploy   # arn / account / arn_pattern のどれか 1 つ
       note: GitHub Actions のデプロイロール
       approved_by: alice
       approved_at: 2026-11-09
       tags: [deploy]
   ```

2. PR を作ります。[arata-check.yml](arata-check.yml) が形を検査します
3. 人が差分を見てマージします
4. 次の定時の監査が、承認に一致する finding を allowlisted として解消します (`resolve` は要りません)

AI に頼むときは、`arata help ai approve` (承認してよい主体の目安、`account` と `arn_pattern` の使い分け、期限、PR の作り方) を最初に読ませてから PR を作らせ、**人が差分を見てマージします**。
AI には `arata approve` を実行させません。手元で形を確かめるなら `arata config check -c aws/<名前>/arata.yaml` です (AWS にもストアにも繋ぎません)。

## PR で設定を検査する

[arata-check.yml](arata-check.yml) を `.github/workflows/` に置くと、PR のたびにリポジトリの中の `arata.yaml` と `aratam.yaml` のすべてに
`arata config check` / `aratam config check` をかけます (1 つのアカウントの形でも、複数のアカウントの形でも、そのまま使えます)。

- 検査するのは形だけです: 未知のキー、型、必須項目、allowlist.yaml の各項目 (主体の指定は 1 つだけ、`expires` の日付、`expected_denied` の書式など)。定時の監査が起動時にする検証と同じ規則なので、ここを通った設定は、監査でも同じように読めます
- AWS にも Slack にも繋がず、認証も secrets も使いません。権限は `contents: read` だけです
- 誤りは「ファイル:行」と一緒に出ます。同じ主体の重複は `warn` で、PR は止めません (片方の `expires` や `tags` しか使われないので、1 つにまとめます)
- 権限やロググループは見ません (AWS に問い合わせる `arata doctor` の仕事です)
- `config check` を含む版 (v0.6.0 以降) が要ります。監査のワークフローも v0.6.0 以降に上げたら、`ARATA_VERSION` を同じ版に揃えます (版が違うと、検査を通った設定が監査で読めないことがあります。新しい版で足されたキーなど)
- main のブランチ保護で必須のチェックにすると、形の誤った allowlist.yaml はマージできなくなります

## 失敗したとき

| 起きたこと | Slack | ジョブ |
|---|---|---|
| 新規なし | 通常用に 1 行 (`on_quiet: short`) | 成功 |
| 一部のソースが取れない (arata の終了コード 3) | 取れた分の報告を緊急用に | 失敗 |
| `STORE_CONFLICT`・`INTERRUPTED`・設定の誤り・OIDC の失敗など | 「arata の出力が無いか古い」を緊急用に | 失敗 |
| バイナリの取得の失敗、checkout の失敗 | 届かない | 失敗 |

`STORE_CONFLICT` は再実行で解消します (手元の `arata ack` と重なったときなど)。走らなかった窓は次の run が引き直します。

**ログには原因の詳細を出しません**。Actions に出るのは `level`・`code`・`source` と終了コードだけです。`msg` と `error` には ARN やアカウント ID が入り得るためです。詳細は手元で同じコマンドを実行して確かめます。
`::add-mask::` で値を列挙して隠す方式は採りません。監査の結果に何が出るかは列挙できないからです。アカウント ID はロールの ARN を secrets に置くことと `mask-aws-account-id: true` で隠します。

## 死活監視

毎日の Slack で足ります。`on_quiet: short` なら何も無い日も 1 行届くので、**届かなければ止まっています**。上の表の「届かない」場合も、GitHub の定時実行が止まった場合も、これで気づけます。

## 詳しい内容の置き場所

Slack に載らない詳細はストアのバケットの `reports/` にあります。

- `reports/<profile>.md`・`reports/<profile>.json`: 最新のレポート (arata が置く)
- `reports/waf-proposals.md`: WAF の提案の全文 (ワークフローの最後の step が置く)。Slack に出るパスは消えた実行環境のものなので、こちらを見ます。バージョニングで過去の版も残ります

Actions の artifacts はリポジトリを読める人に見えるので使いません。

## 費用の目安

| 項目 | 目安 |
|---|---|
| Actions | 1 回 1〜3 分として月 34 回で 100 分ほど。非公開リポジトリでも GitHub Free の無料枠 (月 2,000 分) に収まる。分単位で切り上げ |
| Logs Insights | 使うときの主な費用。`arata doctor` の `cost` の行に 1 日・30 日の概算が出る (東京 0.0076 USD/GB)。`max_scan_gb` を必ず設定する |
| Cost Explorer | `cost-anomaly` のソースを使うと 1 リクエスト 0.01 USD。1 回の run で 2 回ほどなので月 1 USD 未満 |
| S3 | SQLite の gzip と raw の出し入れだけで、ふつうは僅か |

単価は改定されるので、最新の価格は各サービスの料金表で確かめてください。

## 注意

- **定時実行は遅れます**。GitHub の負荷が高いと遅れ、落ちることもあります。監査の窓は実行時刻から決まるので、遅れても次の run が続きから引きます
- **定時実行は止まることがあります**。公開リポジトリでは、活動が 60 日無いと定時実行が無効になります。ワークフローを最後に編集した人が組織から外れた場合も止まることがあります。Slack が届かなくなったら Actions の画面を見てください
- **時刻の変更**: weekly の `cron` を変えたら、`PROFILE` の式の文字列も揃えます (`github.event.schedule` を文字列で比べているため)
- **Action の更新**: この見本の SHA は写した時点で固定されます。自分のリポジトリの Dependabot で更新してください
- **取得の照合の限界**: `SHA256SUMS` は同じリリースのものなので、壊れた取得は防げてもリリース自体のすり替えは防げません。arata が公開リポジトリになったら `gh attestation verify` を足せます (README「来歴の検証」)
