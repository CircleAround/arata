# GitHub Actions で定期実行する

サーバーを持たずに arata と aratam を定期実行する形です。監査を回すリポジトリの一式は、**`arata repo init` で書き出し、`arata repo check` で確かめます** (ADR 0059・0060)。
この文書は、その一式の手順の理由と、設定の点検のしかたを説明します。実行環境は毎回消えるので、ストアは S3 に置きます (README「S3 ストア」、ADR 0034)。ここの値はすべて架空です。

```sh
arata repo init --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 \
  --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 \
  --channel prod=C0123456789,staging=C0123456781 --urgent-channel prod=C0123456780,staging=same --out ./security-audit
```

Slack へは bot トークンで送ります (arata の ADR 0061)。決めるのはチャンネル ID だけです (秘密ではありません)。**端末から打って足りなければ聞かれます**。
端末でないとき (CI や LLM から打つとき) は、足りない引数の名前を出して終了コード 2 で止まります (黙って既定では進みません)。

| 引数 | 中身 |
|---|---|
| `--alert-channel <ID>\|none` | 定時の通知が送れなかったことを知らせるチャンネル (下の「定時の通知が送れなかったとき」)。知らせないなら `none`。ワークフローに入ります |
| `--channel <アカウント>=<ID>,…` | アカウントごとの通常用のチャンネル。`aratam.yaml` を新しく作るアカウントに要ります |
| `--urgent-channel <アカウント>=<ID>\|same,…` | アカウントごとの緊急用のチャンネル。分けないなら `same` (通常用に、メンション付きで送ります)。`aratam.yaml` を新しく作るアカウントに要ります |

書き出される一式の見本が [examples/audit-repo](../audit-repo) です (上の引数に `--schedule` を足した出力そのもの。緊急用を分けるアカウントと分けないアカウントが 1 つずつ、知らせのチャンネルあり、の形です。arata のテストが、雛形と 1 バイトも違わないことを固定しています)。
置く順番は、書き出される [README.md](../audit-repo/README.md) にあります。

| 書き出すもの | 中身 |
|---|---|
| [arata-audit.yml](../audit-repo/.github/workflows/arata-audit.yml) | 定時 (と手動) に、アカウントごとに監査して Slack に通知する |
| [arata-triage.yml](../audit-repo/.github/workflows/arata-triage.yml) | 手動 (Actions の画面) で、finding を ack / snooze / resolve する (下の「finding を片付ける」) |
| [arata-check.yml](../audit-repo/.github/workflows/arata-check.yml) | PR で、設定と allowlist.yaml の形と、この一式が揃っていること (`arata repo check`) を検査する (下の「PR で設定を検査する」) |
| [arata-notify-test.yml](../audit-repo/.github/workflows/arata-notify-test.yml) | 手動で、監査をせずに Slack へ試験メッセージを 1 通送る (通常用・緊急用・知らせ。下の「Slack への送信だけを確かめる」) |
| [github/](../audit-repo/github) | GitHub の設定の Terraform (非公開、fork の禁止、main の保護、Actions の許可、environment `audit`)。秘密には触れない。下の「GitHub の設定を Terraform で当てる」 |
| [aws/<アカウント>/](../audit-repo/aws) | アカウントごとの `arata.yaml`・`allowlist.yaml`・`aratam.yaml` の雛形 (`arata config init`・`aratam config init` と同じ。`aratam.yaml` には、引数のチャンネル ID を書き入れる) |

```
schedule → OIDC で実行用ロール ┬→ 読み取り専用ロールへ連鎖 → 監査対象 (読むだけ)
                               └→ ストアのバケット (読み書き)
         → arata run → aratam notify → Slack
```

- **ワークフローの版は、書き出した arata の版**です (`ARATA_VERSION`)。版を上げるとき・アカウントを足すとき・定時を有効にするときは、
  同じ引数に `--force` を足して書き直し、PR の差分で確かめます。書き直すのは生成物 (`.github/`、`github/`、`README.md`、`.gitignore`) だけで、
  `aws/<アカウント>/` は、どの指定でも書き直しません
- **既にあるファイルは上書きしません**。無いファイルだけを作り、中身の違う生成物があれば一覧を出して終了コード 1 で終わります
- `arata repo init --diff` は、何も書かずに、今ある一式とこの版の一式を比べます (差があれば終了コード 1。機械で読むなら `--format json`。スキーマは `arata schema repo-diff`)
- **秘密は書き出しません。最初は 1 つも登録されていません**。`arata repo check --github` が、足りない秘密の名前と、そのまま打てる登録のコマンドを出します (下の「一式と秘密を確かめる」)
- **定時は最初は入りません**。導入の流れ (手順 5・6) が済んでから、`--schedule --force` で入れます。最初から入れると、ベースラインの収集の前に監査が走ります
- アカウントが 1 つでも、同じ形です (`--accounts` に名前を 1 つ書きます。matrix の要素が 1 つになるだけです)。
  以前の見本にあった 1 アカウント用の形 (`arata/` に設定を置く `arata-audit.yml`) は、持つのをやめました。その形で動いている監査は、そのまま動き続けます

## 用意するもの

設定ファイルを置くリポジトリは **非公開** にしてください。allowlist にはアカウント ID や ARN が入り、Actions のログもリポジトリを読める人に見えます。
このリポジトリは、ストアへの書き込み・Slack の bot トークン・監査対象の読み取りロールへの入口を持ちます。fork の禁止、main の保護、Actions の設定などの前提は、
書き出される `github/` の Terraform が宣言します (下の「GitHub の設定を Terraform で当てる」)。Terraform に無い項目と点検のしかたは、「実行するリポジトリと環境を堅くする」にまとめています。
下の手順の番号は、この文書の中のものです (書き出される README.md の「置く順番」が、全体の順番です)。

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
    GitHubEnvironment=audit \
    AuditRoleArns=arn:aws:iam::123456789012:role/arata-readonly

aws cloudformation describe-stacks --stack-name arata-runner --query 'Stacks[0].Outputs' --output table
```

出力の `RunnerRoleArn` (実行用ロール) と `StoreUrl` (ストア) を後の手順で使います。

| パラメータ | 中身 |
|---|---|
| `GitHubRepository` (必須) | 設定ファイルを置くリポジトリ。OIDC トークンの `sub` の `repo:` の部分と同じ形で書く (下の注意) |
| `AuditRoleArns` (必須) | 手順 2 で作る読み取り専用ロールの ARN。まだ無くてよい (名前は既定で `arata-readonly`)。複数ならカンマ区切り |
| `OIDCProviderArn` | アカウントに GitHub の OIDC プロバイダが既にあれば、その ARN。空なら作る |
| `GitHubEnvironment` | (勧める) GitHub の environment の名前。書き出す一式は `audit` (固定)。指定すると、ジョブに `environment: audit` を付けたワークフローだけが引き受けられる。空なら environment を使わない (下の注意) |
| `GitHubBranch` | 既定は `main`。定時実行は既定のブランチでだけ動く。`GitHubEnvironment` が空なら `sub` に、指定したときは `ref` の条件に使う |
| `GitHubWorkflowRef` | (任意) ワークフローのファイルまで絞る。下の注意 |
| `KeepBranchSubject` | (移行のときだけ) `true` の間は、environment の `sub` とこれまでのブランチの `sub` の両方を受ける。既定は `false` (下の「既に動いている監査を environment に移す」) |
| `StoreBucketName` / `StorePrefix` | バケットの名前 (空なら自動) と、実行用ロールが読み書きできる prefix (空ならバケット全体) |
| `NoncurrentVersionDays` | 古い版のオブジェクトを消すまでの日数 (既定 90)。SQLite は run のたびに置き換わる |
| `BedrockInferenceProfileArn` | (任意) aratam の `llm.provider: bedrock` で使う推論プロファイルの ARN。空なら Bedrock の権限を足さない (手順 3) |
| `RoleName` | 既定は `arata-runner` |

- **OIDC プロバイダはアカウントに 1 つ**しか作れません。先に確かめます: `aws iam list-open-id-connect-providers`。`token.actions.githubusercontent.com` があれば `OIDCProviderArn=<その ARN>` を足します
- **`GitHubRepository` の形**: 信頼は `sub` の完全一致 (environment を使うなら `repo:<GitHubRepository>:environment:<GitHubEnvironment>`、
  使わないなら `repo:<GitHubRepository>:ref:refs/heads/<GitHubBranch>`) で、ワイルドカードは受け付けません。
  2026-07-15 より後に作った (または名前を変えた・移した) リポジトリは、`sub` に ID が入ります (`repo:example-org@1234567/security-audit@7654321:environment:audit`)。
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
- **`GitHubEnvironment`**: 書き出すワークフローは、秘密か OIDC を使うジョブに `environment: audit` を付けています (秘密を environment に置き、main のジョブにだけ渡すため。
  下の「実行するリポジトリと環境を堅くする」の 5)。ジョブに `environment:` を付けると、`sub` は `repo:...:environment:<名前>` に変わり、ブランチは `sub` に入らなくなります。
  `GitHubEnvironment=audit` を指定すると、信頼の条件は次の 3 つの完全一致になります (ADR 0057)
  - `sub` = `repo:<GitHubRepository>:environment:audit` (その environment を参照するジョブだけ)
  - `ref` = `refs/heads/<GitHubBranch>` (そのブランチで起動した実行だけ。environment の「デプロイできるブランチ」を付け忘れても・外されても、AWS の側で止まります)
  - `aud` = `sts.amazonaws.com`

  名前は GitHub の設定と、大文字・小文字まで同じに書きます (小文字の英数字とハイフンにしておくと取り違えません)。
  **environment を使えない・使わないとき** (非公開のリポジトリで GitHub Free のとき。environment の secrets と保護は効きません) は、`GitHubEnvironment` を書かず、
  書き出したワークフローから `environment: audit` の行を消します (生成物を手で直すことになるので、`arata repo init --diff` は差を出し続け、`--force` は行を戻します)。信頼はブランチの `sub` の形になり、秘密はリポジトリの secrets に置きます (5 の「environment を使えないとき」)
- **environment と `GitHubWorkflowRef`**: `GitHubWorkflowRef` は environment のときにも効きます。実行用ロールを使うワークフローが監査の 1 つだけなら、指定を勧めます
  (environment を参照する、main の別のワークフローからも引き受けられなくなります)
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

監査のロールにも読ませたくないロググループ (個人情報だけを書くメールの送信ログなど) があれば、`DeniedLogGroupNames=prod-mail-delivery,prod-mail-bounce` のように名前を足します。
そのロググループの中身を読む操作を明示の Deny で止めます (ADR 0053)。読ませないロググループは arata の設定の `sources` に書きません。
既にあるロールに足すときも同じコマンドです (`--parameter-overrides DeniedLogGroupNames=…` だけを書けば、ほかのパラメータは前の値のままです)。

順序は 1 → 2 です。信頼ポリシーに書く主体 (実行用ロール) は、先に存在している必要があります。
出力の `RoleArn` が手順 1 の `AuditRoleArns` と違う (ロールの名前を変えた) ときは、手順 1 を正しい ARN でもう一度実行します。

実行用ロールの `AssumeRole` は監査対象の CloudTrail に残るので、allowlist に足さないと `unknown_assume_role` が監査そのものを high で毎回報告します。
書き方は、実行の仕組み (手順 1) を置いたアカウントで決まります。`arata config init` は、どちらなのかを `--audit-account` で必ず選ばせます (手順 3。ADR 0045)。

- **監査対象とは別のアカウントに置いた** (例: 実行の仕組みが `111122223333`、監査対象が `123456789012`): 監査対象の CloudTrail には、呼び出し元の
  アカウント ID しか残りません (どのロールかは残りません)。`arata config init --audit-account 111122223333` が、allowlist にアカウントを書きます

  ```yaml
  principals:
    - account: "111122223333"
      note: 監査する側のアカウント。このアカウントの実行用ロールが、監査対象の読み取り専用ロールを引き受けて arata を動かす (arata config init --audit-account が記入)
      approved_at: 2026-11-13
  ```

  `account:` はそのアカウントの全主体を承認します。読み取り専用ロールを引き受けられる主体は、信頼ポリシー (`TrustedPrincipalArn`) で実行用ロールだけに絞ります

- **監査対象と同じアカウントに置いた**: `arata config init --audit-account none` で作り、実行用ロールを `arn:` で手で足します
  (`--audit-account` に監査対象のアカウント自身の ID を書くと、`account:` がそのアカウントの全主体を承認してしまいます。`arata doctor` が ng にします)

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
- GitHub の environment を使うときは、`:sub` を `repo:example-org/security-audit:environment:audit` にし、`token.actions.githubusercontent.com:ref` (`refs/heads/main`) の条件を足します
  (environment の `sub` にはブランチが入らないため)

</details>

### 3. 設定ファイル

アカウントごとに、`aws/<名前>/` に `arata.yaml`・`aratam.yaml`・`allowlist.yaml` を置きます (任意で `llm.context_file` のファイル)。
`arata repo init` が、`--accounts` に書いた名前ごとに雛形を書き出します (中身は `arata config init`・`aratam config init` と同じで、
`name`・`store`・`aws.region`・`aws.profile` は引数から記入済みです)。監査する側のアカウント (実行の仕組みを置いたアカウント) の指定は必須です (手順 2 の 2 つの場合)。

```sh
arata repo init … --audit-account 111122223333 …   # 別のアカウントから監査する: 各アカウントの allowlist.yaml にも書く
arata repo init … --audit-account none …           # 同じアカウントの中で動かす: 実行用ロールを arn: で allowlist に足す
```

`--audit-account` は全アカウントに同じ値が入ります。実行の仕組みと同じアカウントの監査対象が 1 つだけあるときは、ID で書き出してから、
そのアカウントの `arata.yaml` の `audit_account` を `none` にし、`allowlist.yaml` の `account:` の項目を実行用ロールの `arn:` に直します (`arata config check` が食い違いを確かめます)。

選んだ結果は `arata.yaml` の `audit_account` に残り、PR の `arata config check` (下の「PR で設定を検査する」) が、allowlist に書き忘れていないかを確かめます。

```yaml
# aws/prod/arata.yaml (arata repo init が記入済み)
store: s3://example-arata-store/prod      # 手順 1 の出力 StoreUrl の下の、アカウントの名前の prefix。ワークフローの ARATA_STORE_URL と同じ値
aws:
  region: ap-northeast-1
  profile: arata-audit                    # ワークフローが書くプロファイル。監査の読み取りはこのロールで行う
# store_profile は書かない。ストアは標準の連鎖 (実行用ロール) で書く
```

バケットを別のロールで書くときだけ、ワークフローの AWS の設定に `[profile arata-store]` (`role_arn` と `credential_source = Environment`) を足して `store_profile: arata-store` と書きます。`credential_source` は `role_arn` なしでは使えません。

```yaml
# aws/prod/aratam.yaml (抜粋)
max_age: 26h
on_quiet: short            # 死活監視を兼ねるので silent にしない
timezone: Asia/Tokyo       # 通知に出す時刻のゾーン (表示だけ。書かなければ UTC)
llm:
  provider: none           # claude-cli は実行環境に入っていない。bedrock は下
slack:
  bot_token_env: ARATAM_SLACK_BOT_TOKEN   # 環境変数の名前 (トークンは書かない。arata repo init が記入済み)
  channel: "C0123456789"                  # 通常用のチャンネル ID (--channel の値。秘密ではない)
  urgent_channel: "C0123456780"           # 緊急用 (--urgent-channel の値)。same なら空で、channel に送り、冒頭に urgent_mention を付ける
```

送り方は bot トークンだけです。この一式のワークフローは、bot トークンだけを aratam に渡します。Webhook の方式 (`webhook_env`) の `aratam.yaml` は、
`arata repo check` (と、PR の検査) が ng にし、`slack` の節に書く行を出します (Webhook の方式は非推奨です。arata の `docs/aratam.md` 4-1 章)。
チャンネルを後から変えるときは、下の「通知のチャンネルを変える」。

LLM で要約するなら `provider: bedrock` にします。実行用ロールに権限が要るので、手順 1 のコマンドに `BedrockInferenceProfileArn` を足してもう一度実行します
(読み取り専用ロールには足しません。Bedrock を呼ぶのは aratam で、実行用ロールのまま呼びます)。

```sh
    BedrockInferenceProfileArn=arn:aws:bedrock:ap-northeast-1:123456789012:inference-profile/<推論プロファイル ID>
```

```yaml
# aws/prod/aratam.yaml (抜粋)
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

### 4. environment と Secrets

秘密は、リポジトリの secrets ではなく **environment の secrets** に置きます。先に environment を作ります (設定できるのは、リポジトリの admin を持つ人です)。
書き出される `github/` の Terraform を当てると、下の 1・2・4 の状態になります (「GitHub の設定を Terraform で当てる」)。画面で作るときは、次のとおりです。

1. リポジトリの Settings → Environments → 「New environment」で `audit` を作ります (手順 1 の `GitHubEnvironment` と同じ名前)
2. 「Deployment branches and tags」を「Selected branches and tags」にし、`main` だけを足します。**これを忘れると、どのブランチのジョブにも秘密が渡ります**
3. 秘密を登録します (下)。リポジトリの secrets (Settings → Secrets and variables → Actions) には置きません
4. 「Required reviewers」と「Wait timer」は付けません (定時の実行が、承認を待って止まります)

**environment は必ずワークフローより先に作ります**。無い environment を参照するワークフローが動くと、GitHub は同じ名前の environment を、制限なしで自動で作ります。
設定は次で確かめます (下の「実行するリポジトリと環境を堅くする」の 5)。非公開のリポジトリで environment を使うには、GitHub の有料プラン (Team など) が要ります。

```sh
gh api repos/example-org/security-audit/environments/audit --jq '{name, deployment_branch_policy}'
gh api repos/example-org/security-audit/environments/audit/deployment-branch-policies --jq '[.branch_policies[] | {name, type}]'
```

| 名前 | 中身 |
|---|---|
| `ARATA_RUNNER_ROLE_ARN` | 実行用ロールの ARN (手順 1 の出力 `RunnerRoleArn`) |
| `ARATA_AUDIT_ROLE_ARNS` | 読み取り専用ロールの ARN (手順 2 の出力 `RoleArn`) を、アカウントの名前から引く JSON (下の「アカウントを足す」) |
| `ARATAM_SLACK_BOT_TOKEN` | Slack アプリの Bot User OAuth Token (`xoxb-` で始まる。下の「Slack アプリを作る」) |

要る秘密は、この 3 つだけです (アカウントの数や設定で増えません)。**最初は、1 つも登録されていません**。environment を作ったら、`arata repo check` に `--github` を付けて流します。
足りない名前ごとに、そのまま打てる登録のコマンドと、値の形・取得元が出ます (下の「一式と秘密を確かめる」)。

```sh
GITHUB_TOKEN="$(gh auth token)" arata repo check --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 \
  --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 --out . --github

gh secret set ARATA_RUNNER_ROLE_ARN --env audit -R example-org/security-audit     # 出たコマンドを打つ。値は gh が端末で聞くので、貼り付ける
```

- `gh secret set` は、値を引数に取らなければ端末で聞きます。値がシェルの履歴に残りません。画面 (Environment secrets) から入れても同じです
- 登録したら、同じ `arata repo check … --github` をもう一度流し、`ng` が無くなることを確かめます
- arata は秘密を登録しません。秘密の値も読みません (GitHub は、名前と更新日時しか返しません)。**値が正しいかは、下の疎通の確認と、試しの実行で確かめます**
- 書き出す Terraform は、秘密に触れません (これまでの版の「秘密の箱」は、やめました。仮の値が残る・本物の値を上書きし得る、ためです。arata の ADR 0060)

#### Slack アプリを作る

Slack アプリは、利用する組織が manifest から自分で作ります (Slack のワークスペースごとに 1 つ)。arata は公開配布のアプリを持ちません。
配布用のアプリにすると、インストールを受けるサーバーと各組織のトークンを開発側が預かることになるためです。トークンを持つのは、アプリを入れた組織だけです。

1. <https://api.slack.com/apps> →「Create New App」→「From a manifest」→ ワークスペースを選び、arata のリポジトリの `deploy/slack/app-manifest.yaml` の中身を貼ります。
   bot の scope は `chat:write` だけで、受け口 (Event Subscriptions など) を持たない、投稿だけのアプリです。scope は足しません
2. 「Install to Workspace」で入れ、「OAuth & Permissions」の Bot User OAuth Token を secret `ARATAM_SLACK_BOT_TOKEN` に入れます (上の `gh secret set`)
3. 通知先のチャンネルで `/invite @arata` を実行します。**通常用・緊急用 (分けるなら)・知らせのチャンネルの全部で**行います。招待していないチャンネルには送れません
4. チャンネル ID (チャンネルの詳細の一番下。`C0123456789` の形) を、`arata repo init` の引数に渡します (手順 3)

**Slack の疎通を確かめる**: トークンを手元に持つ人は、同じ値で試験メッセージを 1 通送れます。bot がチャンネルにいるかは、送ってみないと分かりません。

```sh
read -rs ARATAM_SLACK_BOT_TOKEN && export ARATAM_SLACK_BOT_TOKEN   # 貼り付けて Enter (シェルの履歴に残さない)
aratam doctor -c aws/prod/aratam.yaml                  # 送らない。auth.test でトークンが有効かと、LLM の疎通を見る
aratam test-notify -c aws/prod/aratam.yaml             # 実際に送る。通常用のチャンネルに 1 通
aratam test-notify -c aws/prod/aratam.yaml --urgent    # 実際に送る。緊急用のチャンネルに 1 通
```

- `doctor` は投稿しないので、bot がチャンネルにいるかは分かりません (`chat:write` だけでは調べられません)。`test-notify` は本当に届くので、チャンネルの人に一言伝えてから実行します。
  `not_in_channel` で失敗したら、そのチャンネルで `/invite @arata` を実行します。`channel_not_found` は、チャンネル ID の誤りか、招待していない非公開チャンネルです
- secrets に入れた値そのものは、[arata-notify-test.yml](../audit-repo/.github/workflows/arata-notify-test.yml) を Actions の画面から実行して確かめられます (監査は回りません。下の「Slack への送信だけを確かめる」)。
  トークンを手元に持たない人も、これで確かめられます。知らせのチャンネルも、ここで確かめます (`route: alert`)
  決定: 監査のワークフローに test-notify 用の入力は足しません。入力を増やすと監査のワークフローの分岐が増えるためです。送信だけを確かめる手段は、別のワークフローにしました
  (試しの実行の入力 `dry_run` は監査のワークフローに足しています。監査と同じ認証・設定・版で動かす必要があり、別のワークフローにすると同じ step を二重に持つためです。下の「定時の前に試す」)
- 同じワークスペースの複数のチャンネルに送るなら、アプリもトークンも 1 つです。監査対象ごとに `aratam.yaml` のチャンネル ID が違うだけです。
  別の組織と Slack Connect で共有するチャンネルも、招待すれば同じアプリで送れます
- トークンのローテーションは有効にしません (manifest は無効にしてあります)。有効にするとトークンが 12 時間で切れますが、aratam は更新の仕組みを持ちません
- **トークンは、bot を招待したすべてのチャンネルに投稿できます** (読むことはできません)。招待するチャンネルを通知用だけにし、**Slack アプリは会社ごとに分けます** (下の「会社ごとに、リポジトリと実行用ロールを分ける」)。
  漏れた疑いがあれば、Slack アプリの設定でトークンを取り消し、入れ直して新しい値を secret に入れます (`gh secret set`)。入れ替えたら、`arata-notify-test` で確かめます
- トークンを AWS Secrets Manager に置き、main のワークフローだけが読めるようにする形は今後の課題です (arata の `docs/roadmap.md`、ADR 0044)

### 5. 初回の収集は手元で

`arata init` はワークフローの認証の期限 (1 時間) を超え得るので、手元で同じ `arata.yaml` を使って実行します。**定時のワークフローを main に入れるのは、この収集が終わってから**にしてください (理由は下)。

```sh
# ~/.aws/config に同じ名前の arata-audit のプロファイルを用意し、ストアを書ける認証を標準の連鎖で渡す
AWS_PROFILE=example-store-writer arata doctor -c aws/prod/arata.yaml
AWS_PROFILE=example-store-writer arata init -c aws/prod/arata.yaml
```

`store: s3://` のまま実行するので、結果はそのままバケットへ置かれ、次のワークフローの run が続きから動きます。実行できたら `workflow_dispatch` で 1 回動かして確かめます (その前に手順 6 と、LLM を使うなら手順 7)。

- **かかる時間**: 収集する期間 (`--window`。既定は 7 日、CloudTrail の履歴は最長 90 日) とリージョンの数、その間のイベントの量に比例し、数十分〜数時間です。
  CloudTrail の LookupEvents は毎秒 2 リクエストまでで、arata はこれを超えないように引くためです。進み具合は標準エラーのログで分かります (1 日分ずつ進みます)
  - 例: CloudTrail のみ・有効なリージョン 17 のアカウントで、既定の 7 日分が約 20 分 (約 1.1 万件)。2 回目以降の daily は Actions で約 3 分
- **手元の認証の期限で止まり得ます**: 収集は読み取りの認証 (`arata-audit` のプロファイル) を、結果の保存はストアを書く認証を使います。
  どちらも期限が収集より短いと途中で切れます。自動で更新される認証 (`role_arn` を書いたプロファイルや IAM Identity Center のプロファイル) を使うか、期限に収まる `--window` にします
  - 読み取りの認証だけが切れたとき: その日の収集が失敗して止まり (終了コード 3)、終わった日までをストアに確定します。認証を取り直して `arata init --resume -c aws/prod/arata.yaml` で続きから再開できます
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
AWS_PROFILE=example-store-writer arata run -c aws/prod/arata.yaml --profile daily --out "$out/daily"
aratam notify -c aws/prod/aratam.yaml --in "$out/daily" --dry-run --llm none    # 送らずに、通知になる内容を標準出力へ
AWS_PROFILE=example-store-writer arata review -c aws/prod/arata.yaml            # 未対応の一覧

# weekly も同じ (アカウントの今の状態を見るチェックは weekly にあり、最初は多くなりやすい)
AWS_PROFILE=example-store-writer arata run -c aws/prod/arata.yaml --profile weekly --out "$out/weekly"
aratam notify -c aws/prod/aratam.yaml --in "$out/weekly" --dry-run --llm none
```

- **手元の run もストアに確定します** (`store: s3://` のまま実行するため)。ここで出た finding は報告済みになり、以後の定時の実行は「新規」としては報せません
  (未対応の件数には残ります。重大度が上がれば再報告されます)。定時の実行が報せるのは、その後に新しく起きたことだけです
- `--dry-run` は Slack に送らず、bot トークンの環境変数も要りません。`--llm none` を外すと LLM の要約も確かめられます (手元の認証で LLM を呼びます)
- 出た finding は、定時の実行に任せる前に片付けます。正当な主体は allowlist.yaml の PR で承認し (下の「approve は PR で allowlist.yaml を直す」)、
  確認が済んだものは `arata ack`、直したものは `arata resolve`、後で直すものは `arata snooze --until` にします。直すべきものは、ここで担当を決めます
- `$out` には ARN などが入っています。見終わったら消します
- 通知の本文には上限があり、多いときは情報の行や理由文から削って収めます (全文はストアの `reports/`)。それでも最初の 1 通が長くなるのは変わらないので、この手順を踏みます
- 決定: ワークフローに「通知しない」入力は足しません。手順 5 で手元にストアを書ける認証が既にあり、同じ場所で続けて行えること、
  Actions で動かすと中身を見る場所が無いこと (ログと Summary には finding の中身を出さない方針です) が理由です

### 7. 監査対象の前提 (LLM を使うとき)

`llm.provider` を `none` 以外にしたら、最初の通知の前 (定時のワークフローを main に入れる前) に、`llm.context_file` を書きます。
aratam が LLM に「この監査対象の前提」として渡す Markdown です。**無くても動きます**。ただ、無いと LLM はアプリの事情を知らないので、正規の動作にも一般的で慎重な助言しか書けません。
判定 (重大度・緊急用に送るか) は規則が決めるので、前提を書いても変わりません。

```yaml
# aws/prod/aratam.yaml (抜粋)
llm:
  context_file: aratam-context.md   # 設定ファイルと同じディレクトリに置く (16 KiB まで)
```

書くとよいこと (形の例は [examples/aratam-context.md](../aratam-context.md)。値は架空):

- どのアプリが本番か (アカウント、入口、ログインや決済のパス)
- デプロイの流れ。どの主体が何を引き受けるか (例: CI の OIDC のロール `github-actions-deploy` が CloudFormation の実行ロールを引き受ける)
- 起動時に秘匿値をまとめて読むロール (例: ECS の実行ロールが、タスクの起動のたびに `prod/app/*` を読む)
- 正規の送信元 (外形監視、拠点、CI)
- 監査の仕組み自体 (実行用ロール `arata-runner` と読み取り専用ロール `arata-readonly`) を誰が・何で置いたか
- 秘密 (トークン・キー)、氏名、メールアドレスは書きません

同じレポートで前提の有無を比べると、前提ありの要約は「前提のどれに合うか・何だけ確かめればよいか」を書き、前提と食い違う点 (未承認の主体など) は隠さずに指摘しました。
前提は承認の代わりにはなりません。「正規」と書いても allowlist には入らず、未承認の主体は報告され続けます。

最初の収集と最初の run (手順 5・6) の後なら、AI (LLM) に下書きさせられます。`arata help ai runtime` を読ませ、`arata review` の結果と、読み取り専用ロールで読める構成から下書きを PR にさせて、
**人が事実を確かめてマージします**。事実が変わったら (デプロイの方式、送信元、ロールの入れ替え) PR で直します。古い前提は、LLM に誤った安心を書かせます。
`aratam config check` (下の「PR で設定を検査する」) が、ファイルが読めるかと大きさを確かめます。

## GitHub の設定を Terraform で当てる

`arata repo init` は、GitHub の側の設定を Terraform (`integrations/github` の provider) の宣言として書き出します。画面で 1 つずつ設定すると、
付け忘れても動くので気づけません (environment の「デプロイできるブランチ」を忘れると、どのブランチのジョブにも秘密が渡ります)。
宣言にしておけば、何が設定されるかを plan で先に読めます。**当てるのは、リポジトリの admin を持つ人が手元で**行います。書き込みのできる鍵を CI に置きません。

```sh
export GITHUB_TOKEN="$(gh auth token)"       # 認証は環境変数で渡す。ファイルに書かない
terraform -chdir=github init
terraform -chdir=github plan                 # 何が変わるかを読む
terraform -chdir=github apply
```

当てたら、`arata repo check … --github` で、environment とデプロイできるブランチが宣言のとおりかを確かめ、足りない秘密を登録します (下の「一式と秘密を確かめる」)。

**`github/` が宣言するもの** (セキュリティに効く項目だけ。説明・トピック・マージの方式などは宣言に持たず、画面で自由に変えられます)

| 設定 | 中身 | 点検 (下の節) |
|---|---|---|
| リポジトリ | 非公開、fork の禁止。新しく作るときは最初のコミット付き (空のリポジトリには PR を出せないため) | 1 |
| main のルールセット | PR 必須、削除と force push の禁止、必須のチェック (`check` = `arata-check.yml`)。迂回できる主体は置かない | 4 |
| Actions の許可 | GitHub 製と `aws-actions/configure-aws-credentials` だけ。commit SHA の固定を必須 | 6 |
| `GITHUB_TOKEN` | 既定は read。Actions に PR を承認させない | 6 |
| environment `audit` | デプロイできるブランチは `main` だけ。レビュー担当と待ち時間は付けない | 5 |

- **リポジトリや設定が既にあるとき** (GitHub の設定の Terraform を手で作っていた場合を含む) は、先に、今あるものを state に取り込みます。
  手順は、書き出される README.md の「[既にあるリポジトリを取り込む](../audit-repo/README.md#既にあるリポジトリを取り込む)」にあります
  (古い `.tf` と state をどける → リポジトリ・ルールセット・environment などを `terraform import` で取り込む (ID の調べ方つき) → plan の「destroy」が 0 であることを確かめる)。
  `arata repo check` は、`github/` に残っている古い `.tf` と、これまでの版の `github/secrets/` も「この版の一式に無い」と出します
- リポジトリには `prevent_destroy` を付けています。`terraform destroy` でリポジトリを消しません
- PR の承認の数は変数です (既定は 0。`-var required_approving_review_count=1`)。2 人以上で運用するなら 1 以上を勧めます
- **宣言に無いもの**は、下の節の `gh api` で点検します: fork の PR へのワークフローの権限 (2)、OIDC の `sub` の ID 入りの形 (3)、組織の fork の設定 (1)、書き込み権限を持つ人 (4)
- provider は完全な版で固定し、`.terraform.lock.hcl` (linux と darwin の amd64・arm64 のハッシュ) を一緒に書き出します。版を上げるのは arata の側で、新しい版の `arata repo init --force` で届きます
- state は手元に残ります (`.gitignore` 済み)。別の人が当てるときは、`import` で取り込み直します
- main の保護と environment は、非公開のリポジトリでは GitHub の有料プランが要ります。Terraform を使わないときは、下の節の手順を画面で行います

**Terraform は、秘密に触れません**。宣言は environment とデプロイできるブランチまでで、秘密のリソースも、秘密の一覧を読む data source も持ちません。
これまでの版の「秘密の箱」(`github/secrets/`。秘密の名前を仮の値で作る Terraform) は、やめました (arata の ADR 0060)。

- 仮の値が残ります。使わない箱は仮の値のままで、environment の秘密の一覧からは、本物と見分けられません
- 秘密の作成は「作るか上書きする」API です。計画を見てから当てるまでの間に入った本物の値を、仮の値で置き換え得ます
- 使わない箱のために、仮の値を見分ける検査・警告・別の root・テストが要ります
- `github/secrets/` が残っているリポジトリでは、`arata repo check` が ng にします。ディレクトリを、手元の state ごと消します。登録済みの秘密には、何も起きません。
  箱として作られた、使わない秘密 (仮の値のままのもの) は、`arata repo check --github` が出す `gh secret delete` のコマンドで消します

arata のテストは、この Terraform を `terraform fmt` と `validate` に通しています。plan も apply もしません (実際の GitHub では確かめていません。ADR 0059・0060)。

## 実行するリポジトリと環境を堅くする

監査のリポジトリを使える人は、実行用ロール (ストアの読み書き・監査対象の読み取り) と Slack の bot トークンを使えます。目指す状態は次の 2 つです。

- **main にコミットを入れられる人だけが、実行用ロールを使える** (fork、ほかのブランチ、PR からは使えない)
- **main にコミットを入れられる人だけが、secrets を使える** (environment に置き、デプロイできるブランチを main だけにする)

下の `gh api` はすべて読み取りです (`example-org/security-audit` は自分のリポジトリに読み替えます)。組織の設定は、組織の所有者でないと読めないものがあります。
AI (LLM) に点検させるときは `arata help ai runtime` (同じ項目のチェックリスト) を読ませます。設定を変えるのは人です。
main の保護 (4) と environment (5) は、非公開のリポジトリでは GitHub の有料プラン (Team など) が要ります (使えないときの形は 5 の「environment を使えないとき」)。

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
- `pull_request` で動かすのは [arata-check.yml](../audit-repo/.github/workflows/arata-check.yml) の形に留めます。権限は `contents: read` だけで、secrets も OIDC も使いません。
  secrets か OIDC を使うワークフロー (監査、finding の片付け) は、定時と手動でだけ動かします

### 3. OIDC の信頼は、ID 入りの `sub` で 1 つの environment と 1 つのブランチに絞る

実行用ロールは、OIDC トークンが次に完全に一致するときだけ引き受けられます (手順 1 の `runner.yaml`。ワイルドカードは受け付けません)。

```
sub = repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:audit
ref = refs/heads/main
```

environment を使わない構成 (`GitHubEnvironment` が空) では、`sub` = `repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main` の 1 つです。

- **fork は引き受けられません**。fork は別のリポジトリなので、fork で動くワークフローの `sub` は fork 自身の名前と ID になります
- **同じ名前で作り直したリポジトリも引き受けられません** (ID 入りの形のとき)。従来の形 (`repo:example-org/security-audit:...`) は名前だけで決まるので、
  リポジトリや組織を消した後に同じ名前が別の人に取られると、同じ `sub` を作られます。ID は使い回されません
- **ほかのブランチと PR からも引き受けられません**。ほかのブランチで起動した実行は `ref` が違います (environment の「デプロイできるブランチ」の制限より手前の、AWS の側の守りです)。
  PR のワークフローは `ref` が `refs/pull/...` で、environment を参照しなければ `sub` も `...:pull_request` になります
- **environment を参照しないジョブからも引き受けられません** (`sub` がブランチの形になります)。別の名前の environment を参照しても、`sub` が違います

```sh
gh api repos/example-org/security-audit/actions/oidc/customization/sub
aws iam get-role --role-name arata-runner --query 'Role.AssumeRolePolicyDocument'
```

- 1 つ目が `use_default: true`・`use_immutable_subject: true` なら ID 入りです (2026-07-15 より後に作った・名前を変えた・移したリポジトリは、最初からこの形です)
- `use_immutable_subject: false` (従来の形) なら、リポジトリか組織の Actions の OIDC の設定で ID 入りに切り替えます。
  切り替えたら、`GitHubRepository` を `sub_claim_prefix` の `repo:` より後ろの値にしてスタックを更新します (揃うまでは引き受けに失敗します。定時の実行の合間に行います)
- 2 つ目の信頼ポリシーが `StringEquals` だけで、`sub` が上の 1 つだけ、`ref` が `refs/heads/main` であること。手で直して `StringLike` や `*` を足さないでください。
  `sub` に `...:environment:audit` と `...:ref:refs/heads/main` の 2 つが並んでいたら、移行の期間の許可 (`KeepBranchSubject=true`) が残っています。移行が済んでいれば外します

### 4. main を保護し、書き込み権限を持つ人を最小にする

信頼を main に絞っているので (`ref`。environment を使わない構成では `sub`)、**main に入れられる人 = 実行用ロールと秘密を使える人**です。main の保護が、権限の境界になります。

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
- admin を持つ人は、さらに少なくします。admin は main の保護も environment の設定 (デプロイできるブランチ、secrets) も変えられます
- `arata-check` を必須のチェックにすると、形の誤った設定は main に入りません (「PR で設定を検査する」)
- PR のレビューを必須にすれば、1 人では main を変えられなくなります。人数が足りずに必須にできないときは、PR の差分を誰が見るかを決めておきます

### 5. secrets は environment に置き、デプロイできるブランチを main だけにする

リポジトリの secrets は、**どのブランチのワークフローからも読めます**。書き込み権限のある人 (と、その人のアカウントを乗っ取った人) は、ブランチにワークフローを足して push すれば、
main の保護を通らずに読み出せます。乗っ取ったアカウントでワークフローを書き換え、CI の秘密を持ち出す攻撃は、実際に広く起きています。

書き出す一式は、秘密を **GitHub の environment (`audit`) の secrets** に置きます (手順 4)。

- environment の secrets は、その environment を参照するジョブにしか渡りません。デプロイできるブランチを main だけにすると、ほかのブランチのジョブは environment を使えず、
  始まる前に止まります (秘密も OIDC のトークンも渡りません)
- ワークフローのうち、秘密か OIDC を使うジョブ (監査、finding の片付け、Slack への送信のテスト) は `environment: audit` を付けています。
  PR の検査 ([arata-check.yml](../audit-repo/.github/workflows/arata-check.yml)) は秘密も OIDC も使わないので、付けていません (付けると PR のブランチで動けません)
- 実行用ロールも、同じ environment に絞ります (手順 1 の `GitHubEnvironment=audit`)。environment の `sub` にはブランチが入らないので、`runner.yaml` は `ref` の条件でもブランチに絞ります。
  デプロイできるブランチの設定が外れても、ほかのブランチからは実行用ロールを引き受けられません (**秘密のほうは、この設定だけが守りです**)
- 読み出されて困るのは Slack の bot トークンです (偽の通知を送れます。bot を招待したすべてのチャンネルに送れます)。漏れた疑いがあれば、トークンを取り消して入れ直します
  (bot トークンなら取り消して入れ直します)。長期の AWS のアクセスキーは secrets に置きません
- environment の設定を変えられるのは、リポジトリの admin を持つ人です (4)。書き込み権限だけの人は、ワークフローで別の名前の environment を作れますが、
  そこには秘密が無く、`sub` も違うので実行用ロールを引き受けられません

次で確かめます。

```sh
gh api repos/example-org/security-audit/environments --jq '[.environments[] | {name, deployment_branch_policy}]'
gh api repos/example-org/security-audit/environments/audit/deployment-branch-policies --jq '[.branch_policies[] | {name, type}]'
gh api repos/example-org/security-audit/environments/audit/secrets --jq '[.secrets[].name]'
gh api repos/example-org/security-audit/actions/secrets --jq '[.secrets[].name]'
```

- `audit` の `deployment_branch_policy` が `{"protected_branches": false, "custom_branch_policies": true}` で、2 つ目の一覧が `main` (`type: branch`) だけであること。
  `deployment_branch_policy` が `null` なら、どのブランチからも使えます
- 秘密の名前が 3 つ目 (environment) にあり、4 つ目 (リポジトリ) が空であること。同じ名前が両方にあると、environment を参照しないジョブはリポジトリの値を読めます
- 覚えのない environment が無いこと (秘密を置いていなければ害はありませんが、誰かがワークフローで作った跡です)

知っておくこと:

- environment を参照するジョブは、実行のたびに GitHub の「Deployments」に記録が 1 件増えます (matrix ならアカウントの数だけ)。動作には影響しません
- 手動実行 (`workflow_dispatch`) で main 以外のブランチを選ぶと、ジョブは environment の制限で始まる前に失敗します。
  設定を直すブランチで試したいときは、手元で `arata config check` / `aratam config check` を流すか、PR の検査を使います

#### environment を使えないとき

非公開のリポジトリで GitHub Free のときは、environment の secrets と保護が効きません。このときは次の形にします (environment を使う前の見本と同じ守りです)。

- `runner.yaml` に `GitHubEnvironment` を書かない (信頼は `sub` = `repo:...:ref:refs/heads/main` の 1 つ)
- 書き出したワークフローから `environment: audit` の行を消す (残すと、実行用ロールを引き受けられません)。`github/` の Terraform は当てません (environment を作るため)
- 秘密はリポジトリの secrets に置く。守りは 4 の「書き込み権限を持つ人を最小に」だけになり、書き込み権限のある人は別のブランチから秘密を読み出せます。
  ロールの ARN は読めても、`sub` が合わないので引き受けられません (分かるのはアカウント ID です)

#### 既に動いている監査を environment に移す

environment を使う前の見本 (environment なし、リポジトリの secrets) で動いている監査を、定時の実行を止めずに移す順番です。
`KeepBranchSubject=true` の間は、実行用ロールが environment の `sub` とブランチの `sub` の両方を受けるので、ワークフローを変える前後のどちらでも引き受けられます。

1. **environment を作り、スタックを更新する**。手順 4 の 1・2 のとおり `audit` を作り、デプロイできるブランチを `main` だけにします (秘密はまだ入れなくてかまいません)。
   次に、スタックを更新します (書かなかったパラメータは前の値のままです)

   ```sh
   aws cloudformation deploy --stack-name arata-runner \
     --template-file deploy/github-actions/runner.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides GitHubEnvironment=audit KeepBranchSubject=true
   ```

   この時点では、まだ environment を参照しない今のワークフローが、これまでどおり動きます
2. **ワークフローに `environment: audit` を足す**。秘密か OIDC を使うジョブ (監査、finding の片付け、送信のテスト) に足す PR を作り、マージします (PR の検査には足しません)。
   マージしたら、監査のワークフローを手動で実行して (`dry_run` でかまいません) 実行用ロールを引き受けられることを確かめます。
   秘密は、まだリポジトリの secrets から読まれます (environment を参照するジョブにも、リポジトリの secrets は渡ります)
3. **秘密を environment に移す**。同じ名前で environment の secrets に入れます (GitHub から値は読み出せないので、ARN はスタックの出力から、bot トークンは Slack の設定から用意します。足りない名前は `arata repo check --github` が出します。
   この機会にトークンを入れ直すと、これまでに読み出されていた場合にも備えられます)。
   同じ名前が両方にあるときは environment の値が使われます。[arata-notify-test.yml](../audit-repo/.github/workflows/arata-notify-test.yml) で届くことを確かめてから、**リポジトリの secrets を消します**
4. **移行の期間の許可を外す**。スタックを `KeepBranchSubject=false` で更新し、もう一度、手動の実行で確かめます

   ```sh
   aws cloudformation deploy --stack-name arata-runner \
     --template-file deploy/github-actions/runner.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides KeepBranchSubject=false
   aws iam get-role --role-name arata-runner --query 'Role.AssumeRolePolicyDocument'
   ```

   `sub` が `...:environment:audit` の 1 つだけになっていれば終わりです。4 を済ませるまでは、environment を参照しない main のワークフローからも実行用ロールを引き受けられます

- 順番を変えないでください。スタックより先にワークフローを変えると、`sub` が合わず、定時の監査が OIDC の引き受けで失敗します (「arata の出力が無いか古い」が緊急用に届きます)
- 実行の仕組みを置いたアカウントを `oidc_assume_role` で監査していて、既知リストの `oidc_subjects` に実行用ロールを書いているなら、2 の PR より前に
  その項目へ `environments: ["audit"]` を足します (足さないと、`sub` が変わった最初の引き受けを high で報告します)。4 が済んだら、その項目の `refs` を消します
- 新しい版の `runner.yaml` に更新しただけ (`GitHubEnvironment` を書かない) なら、信頼は変わりません
- 戻すとき: ワークフローから `environment: audit` を消してマージし、秘密をリポジトリの secrets に戻してから、スタックを `GitHubEnvironment=` (空) で更新します
  (`KeepBranchSubject=true` にしてあれば、どちらの順でも止まりません)

### 6. Actions の設定

```sh
gh api repos/example-org/security-audit/actions/permissions
gh api repos/example-org/security-audit/actions/permissions/selected-actions
gh api repos/example-org/security-audit/actions/permissions/workflow
gh api repos/example-org/security-audit/actions/permissions/access
```

Settings → Actions → General で設定します。

- 許可する action: `allowed_actions: selected` で、GitHub 製 (`github_owned_allowed: true`) と `aws-actions/configure-aws-credentials@*` (`patterns_allowed`) だけ。
  ワークフローが使う action は `actions/checkout` とこれの 2 つです。action を足すときは、ここにも足します (足さないとワークフローが起動しません)
- 「Require actions to be pinned to a full-length commit SHA」を有効にします (`sha_pinning_required: true`)
- `GITHUB_TOKEN` の既定は read (`default_workflow_permissions: read`)、「Actions が PR を作成・承認する」は無効 (`can_approve_pull_request_reviews: false`)
- ほかのリポジトリからワークフローを使わせません (`access` の応答が `none`)
- checkout は `persist-credentials: false` にします (書き出すワークフローのとおり)。トークンを作業ツリーに残しません

### 7. 書き出すワークフローが満たしていること

`arata repo init` が書き出すワークフローは、上の前提に合います (arata のリポジトリのテストが固定しています)。生成物は手で直さないでください。

- ワークフローの先頭は `permissions: {}`。権限はジョブごとで、監査と片付けは `id-token: write` と `contents: read`、PR の検査と送信のテストは `contents: read` だけ
- secrets か OIDC を使うワークフローは `schedule` と `workflow_dispatch` でだけ動き、`pull_request_target`・`workflow_run` を使わない
- secrets か OIDC を使うジョブは `environment: audit` で動く (名前は式にせず、そのまま書く)。PR の検査には付けない
- action は 2 つだけで、どちらも commit SHA で固定。checkout は `persist-credentials: false`
- `run:` に式を埋め込まず、secrets は使う step にだけ渡す
- 手動実行の `dry_run` では、通知せず、ストアのバケットに何も置かず、結果は件数と重大度だけをログに出す

## アカウントを足す

ワークフローは、アカウントごとにジョブを分け (matrix)、設定・ストアの prefix・排他をアカウントごとにします。1 つのアカウントが失敗しても、ほかは続きます。

```
aws/
  prod/     arata.yaml  aratam.yaml  allowlist.yaml
  staging/  arata.yaml  aratam.yaml  allowlist.yaml
```

```yaml
# aws/prod/arata.yaml
store: s3://example-arata-store/prod      # prefix はディレクトリの名前と同じ
aws:
  region: ap-northeast-1
  profile: arata-audit
```

```yaml
# aws/prod/aratam.yaml (抜粋)
name: prod                                # 通知に出す名前。アカウントごとに違うので Slack で見分けられる
```

アカウントを足すときは、`--accounts` に名前を足して `--force` で書き直します (新しい `aws/<名前>/` が作られ、ワークフローの matrix と選択肢に名前が入ります。既にある `aws/` の設定は変わりません)。
ほかに要るのは次のとおりです。

- **実行の仕組み**: 1 つのままです。`AuditRoleArns` に全アカウントの読み取り専用ロールをカンマ区切りで渡し、`StorePrefix` は空のままにします

  ```sh
  aws cloudformation deploy --stack-name arata-runner \
    --template-file deploy/github-actions/runner.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
      GitHubRepository=example-org/security-audit \
      GitHubEnvironment=audit \
      AuditRoleArns=arn:aws:iam::123456789012:role/arata-readonly,arn:aws:iam::444455556666:role/arata-readonly
  ```

- **読み取り専用ロール**: 監査対象のアカウントごとに、同じ `TrustedPrincipalArn` で 1 回ずつ実行します
- **Secrets**: environment は全アカウントで 1 つ (`audit`) です。`ARATA_AUDIT_ROLE_ARNS` は、名前からロールを引く JSON です。足したアカウントの行を足します

  ```json
  {"prod": "arn:aws:iam::123456789012:role/arata-readonly", "staging": "arn:aws:iam::444455556666:role/arata-readonly"}
  ```

  アカウントごとに secret を分けて `secrets[...]` で選ぶ形にはしません (式で動的に選ぶと、ジョブにすべての secrets が渡ります)
- **allowlist**: 監査する側のアカウントは、`arata repo init` が各アカウントの `allowlist.yaml` に書きます (実行の仕組みと同じアカウントの監査対象だけは、
  手順 3 のとおり `none` と実行用ロールの `arn:` に直します)。書き忘れると、足したアカウントの最初の監査が `unknown_assume_role` (high) を通知します。
  `audit_account` を書いた設定なら、PR の `arata config check` が ng で止めます
- **初回の収集**: アカウントごとに手元で `arata init -c aws/<名前>/arata.yaml` を実行します (ストアはアカウントごとなので、順番でも並べてもかまいません。時間と認証の期限の注意は「初回の収集は手元で」)
- **Slack**: 秘密は増えません (bot トークンは 1 つのまま)。足すアカウントのチャンネル ID を `--channel <名前>=<ID>` と `--urgent-channel <名前>=<ID>|same` で渡します (端末なら聞かれます)。
  `arata repo init` が、そのアカウントの `aratam.yaml` に書き入れます。bot を、そのチャンネルに招待しておきます。既にあるアカウントのチャンネルは、聞かれません

  ```yaml
  # aws/prod/aratam.yaml (抜粋)                    # aws/staging/aratam.yaml (抜粋)
  slack:                                           # slack:
    bot_token_env: ARATAM_SLACK_BOT_TOKEN          #   bot_token_env: ARATAM_SLACK_BOT_TOKEN   (同じ secret)
    channel: C0123456789                           #   channel: C0123456781                    (チャンネルだけ違う)
    urgent_channel: C0123456780                    #   urgent_channel: C0123456780
  ```

実行用ロールは全アカウントの prefix を読み書きできます (分けるのは置き場所で、権限ではありません)。権限まで分けたいときは、リポジトリと実行の仕組みを分けます (次の節)。

## 会社ごとに、リポジトリと実行用ロールを分ける

決定: 監査のリポジトリは、**会社 (監査を任される組織) ごとに 1 つ**にすることを勧めます。1 つのリポジトリで複数のアカウントを回す形 (上の「アカウントを足す」) は、
同じ会社のアカウント (prod と staging など) に使います。

- 理由: 実行用ロール・リポジトリ・秘密の 1 組が複数の会社に届いていると、乗っ取り (リポジトリの書き込み権限、Slack の秘密) や取り違え (ある会社の指摘が、別の会社の Slack に届く。
  matrix の名前と `ARATA_AUDIT_ROLE_ARNS` の対応の誤りなど) の被害が、全部の会社に及びます。分けておけば、1 つのリポジトリで起きたことは、その会社の中で止まります
- 会社ごとに `arata repo init` を別のリポジトリに向けて流し、実行用ロールも会社ごとに作ります。同じ AWS アカウントに 2 つ目以降の実行の仕組みを置くときのパラメータ
  (スタックの名前と `RoleName` を変える、`OIDCProviderArn` で OIDC プロバイダを共有する、`AuditRoleArns` はその会社のロールだけ、ストアのバケットはスタックごとに別にできる) は、
  書き出される README.md の「[会社ごとに、リポジトリと実行用ロールを分ける](../audit-repo/README.md#会社ごとにリポジトリと実行用ロールを分ける)」にあります
- Slack の秘密は、リポジトリごとの environment に置きます。bot トークンをアカウントごとに分けて 1 つの JSON にまとめる形は採りません (リポジトリを会社ごとに分ければ、
  1 つのリポジトリの中で宛先ごとにトークンを分ける必要が無くなります)。同じ bot トークンを複数の会社のリポジトリに置くと、1 つから読み出されたときに、ほかの会社のチャンネルにも投稿できます。
  Slack アプリ (トークン) は、会社ごとに作ります

## finding を片付ける (ack / snooze / resolve)

ストアが S3 にあると、手元にストアを書ける認証が無い人は `arata ack` を実行できません。[arata-triage.yml](../audit-repo/.github/workflows/arata-triage.yml) で、Actions の画面から行えます。

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
- **main で動かします**。environment のデプロイできるブランチも、実行用ロールの信頼も main だけなので、ほかのブランチを選ぶと、ジョブが始まる前に失敗します。
  `runner.yaml` の `GitHubWorkflowRef` で監査のワークフローのファイルに絞っている場合は、このワークフローからは引き受けられません (`GitHubWorkflowRef` を空にするか、手元で実行します)
- **監査が走っていれば待ちます**。定時の監査と同じ `concurrency` の group (アカウントごと) なので、同じストアへは順番に書きます。
  同じ group で待てるのは 1 つだけです。待っている間にもう 1 つ実行すると、先に待っていたほうが取り消されます。続けて行うときは、前の実行が終わってからにします
- **失敗の見分け**: ログの方針は監査と同じで、出るのは `code` と終了コードだけです。`CONFIG_INVALID` は ID が無い・既に resolved・期日が過去、`STORE_CONFLICT` は同時に書かれた (もう一度実行します)
- ack / snooze 中でも、重大度が上がれば再報告されます (ADR 0022)

### approve は PR で allowlist.yaml を直す

主体の承認 (approve) はこのワークフローに入れていません。`arata approve` は allowlist.yaml への追記と同時にストアの finding も解消するので、追記の PR がマージされる前に finding が消えてしまいます。
承認は allowlist.yaml の差分としてレビューします。

1. ブランチを切り、`aws/<名前>/allowlist.yaml` の `principals` の末尾に項目を足します

   ```yaml
     - arn: arn:aws:iam::123456789012:role/github-actions-deploy   # arn / account / arn_pattern のどれか 1 つ
       note: GitHub Actions のデプロイロール
       approved_by: alice
       approved_at: 2026-11-09
       tags: [deploy]
   ```

2. PR を作ります。[arata-check.yml](../audit-repo/.github/workflows/arata-check.yml) が形を検査します
3. 人が差分を見てマージします
4. 次の定時の監査が、承認に一致する finding を allowlisted として解消します (`resolve` は要りません)

AI に頼むときは、`arata help ai approve` (承認してよい主体の目安、`account` と `arn_pattern` の使い分け、期限、PR の作り方) を最初に読ませてから PR を作らせ、**人が差分を見てマージします**。
AI には `arata approve` を実行させません。手元で形を確かめるなら `arata config check -c aws/<名前>/arata.yaml` です (AWS にもストアにも繋ぎません)。

## 一式と秘密を確かめる (`arata repo check`)

`arata repo check` は、書き出した一式と、GitHub の側の設定を、**読むだけで**確かめます。引数は `arata repo init` と同じです
(書き出される README.md のコマンドの `init` を `check` に替えます)。何も書きません。秘密の値は扱いません。

```sh
# ファイルだけを見る (手元でも、PR の検査でも。秘密も GitHub も要らない)
arata repo check --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 \
  --store-bucket example-arata-store --region ap-northeast-1 --alert-channel C0123456782 --schedule --out .

# GitHub の environment と、秘密の名前も見る (読むだけ。鍵は環境変数で渡す)
GITHUB_TOKEN="$(gh auth token)" arata repo check … --out . --github
```

| 範囲 | 項目 | 見ること | 合わないとき |
|---|---|---|---|
| ファイル (いつも) | `files` | 生成物が、この版・この引数の一式と同じか。古い版の残り (`.github/` の `arata-` で始まるファイル) が無いか | ng。`arata repo init … --force` で書き直す |
| | `terraform` | `github/` の Terraform が、この版の形と同じか。ほかの `.tf` や `github/secrets/` が残っていないか | ng |
| | `workflow_secrets` | ワークフローが参照する秘密が、3 つ (`ARATA_RUNNER_ROLE_ARN`・`ARATA_AUDIT_ROLE_ARNS`・`ARATAM_SLACK_BOT_TOKEN`) だけか。名前を式で作る参照 (`secrets[…]`) が無いか | ng |
| | `notify` | アカウントごとの `aratam.yaml` が、bot トークンの方式 (`ARATAM_SLACK_BOT_TOKEN`) か | ng。`slack` の節に書く行を出す |
| | `accounts` | `aws/<アカウント>/` に `arata.yaml` と `aratam.yaml` があるか (中身の形は `config check`) | ng |
| GitHub (`--github`) | `environment` | environment `audit` があるか | ng |
| | `deployment_branches` | デプロイできるブランチが、既定のブランチ 1 つだけか | ng |
| | `environment_protection` | レビュー担当・待ち時間が付いていないか (定時の実行が止まります) | warn |
| | `secret` | 3 つの秘密が、environment にあるか | ng。登録のコマンドと、値の形・取得元を出す |
| | `secret_unused` | この一式が使わない秘密が、environment に残っていないか (Webhook の秘密など) | warn。消すコマンドを出す |
| | `repository_secret` | リポジトリの (environment でない) 秘密が残っていないか | この一式の名前なら ng (どのブランチのジョブにも渡ります)。ほかは warn |

足りない秘密があると、次のように出ます。コマンドをそのまま打ち、値は `gh` が聞いたところに貼り付けます。

```
足りない秘密 (コマンドをそのまま打つ。値は gh が端末で聞くので、貼り付ける。登録したら、もう一度 arata repo check … --github):
  gh secret set ARATA_RUNNER_ROLE_ARN --env audit -R example-org/security-audit
      値の形: arn:aws:iam::123456789012:role/arata-runner
      取得元: 実行の仕組み (deploy/github-actions/runner.yaml) のスタックの出力 RunnerRoleArn
```

- **終了コード**: ng があれば 2、warn だけなら 0 (`arata doctor` と同じ)。ng と warn の行は、標準エラーにも `code` 付きで出ます (`REPO_SECRET_MISSING` など)
- **機械で読むときは `--format json`** です (スキーマは `arata schema repo-check`。`rows[]` と、足りない秘密の `missing_secrets[]`)。表の出力は人向けで、文言と並びは版をまたいで変わります。
  読む側の決まり (どの `--format json` でも同じ): 知らない項目は無視する。`schema_version` が知っている版より大きければ止める
- **`--github` は読むだけ**です。呼ぶのは GitHub の API の GET だけで、秘密の名前の一覧と、environment の設定を読みます。GitHub は秘密の値を返さないので、**値は読めませんし、読みません**。
  値が正しいかは、試しの通知 (下の「Slack への送信だけを確かめる」) と、試しの実行 (「定時の前に試す」) で確かめます
- 鍵は、環境変数 `GITHUB_TOKEN` (無ければ `GH_TOKEN`) で渡します。arata は `gh` を起動しません。鍵には、environment と秘密の名前を読める権限 (リポジトリの admin) が要ります。
  足りないときは、その項目が ng (`GITHUB_API_FAILED`) になります。「足りない秘密」としては出しません
- 向き先は `https://api.github.com` に固定です (GitHub Enterprise Server は対象外です)
- **arata は秘密を登録しません**。値を受け取る経路と、書き込みのできる鍵を、arata に持たせません。登録は、出たコマンドを人が打ちます
- `--github` を付けないと、GitHub は読みません (鍵が環境変数にあっても)。PR の検査は、付けずに流します

## 通知のチャンネルを変える

通知のチャンネル ID は、`aws/<アカウント>/aratam.yaml` だけが持っています。`arata repo init` は、既にある `aratam.yaml` を書き直しません (`--force` でも)。

1. 新しいチャンネルに、bot を招待します (`/invite @arata`)
2. `aws/<アカウント>/aratam.yaml` の `slack.channel` (緊急用なら `slack.urgent_channel`) の 1 行を、新しいチャンネル ID に直します
3. PR を出します。PR の検査が、ID の形 (`aratam config check`) と、一式との組 (`arata repo check`) を確かめます
4. マージしたら、`arata-notify-test` で、新しいチャンネルに届くことを確かめます

- 秘密は変わりません (トークンは同じです)。登録し直すものはありません
- `aratam.yaml` を書き換えるコマンドは、ありません。直すのは 1 行で、形は PR の検査が止め、届くかは `arata-notify-test` が確かめます
- **知らせのチャンネル** (`--alert-channel`) は、ワークフローに書いてあります。変えるときは、書き出される README.md のコマンドの値を直して `--force` を足して流し、PR で入れます
- Webhook で送っていた `aratam.yaml` を、この一式に持ち込むとき: `arata repo check` が、`slack` の節に書く行 (`webhook_env: ""`、`bot_token_env: ARATAM_SLACK_BOT_TOKEN`、`channel: "…"`) を出します。
  そのとおりに直し、トークンを登録し、`arata-notify-test` で確かめてから、Webhook の秘密を消します (`arata repo check --github` が、消すコマンドを出します)

## PR で設定を検査する

[arata-check.yml](../audit-repo/.github/workflows/arata-check.yml) は、PR のたびにリポジトリの中の `arata.yaml` と `aratam.yaml` のすべてに
`arata config check` / `aratam config check` をかけ、続けて `arata repo check` (ファイルの検査) を流します。ジョブの名前 (`check`) は、main のルールセットの必須のチェックです (`github/` の Terraform)。
定時の監査と同じ版の arata / aratam で、マージの前に流します。

- **版が揃っていること**: arata を使うワークフロー (`env.ARATA_VERSION` を持つもの) が、すべて同じ版 (`v1.2.3` の形) に固定されているかを確かめます。
  片方だけ版を上げると、PR の検査は新しい版で通り、定時の実行は古い版で動きます。ワークフローは YAML として読みます (`yq`。GitHub の実行環境に入っています)
- **一式が揃っていること** (`arata repo check`): 生成物が、この版・この引数の一式と同じか、ワークフローが参照する秘密が 3 つだけか、アカウントごとの `aratam.yaml` が bot トークンの方式か、を確かめます
  (上の「一式と秘密を確かめる」のファイルの検査)。引数は、書き出したときのものがワークフローに入っています。`--github` は付けません (PR の検査は、秘密も、GitHub の設定を読む鍵も持ちません)。
  生成物を手で直した PR・`aratam.yaml` を Webhook の方式にした PR・古い版の残りがある PR を、定時の実行より前に止めます

- `config check` が検査するのは形だけです: 未知のキー、型、必須項目、allowlist.yaml の各項目 (主体の指定は 1 つだけ、`expires` の日付、`expected_denied` の書式など)。定時の監査が起動時にする検証と同じ規則なので、ここを通った設定は、監査でも同じように読めます
- AWS にも Slack にも繋がず、認証も secrets も使いません。権限は `contents: read` だけです
- 誤りは「ファイル:行」と一緒に出ます。同じ主体の重複は `warn` で、PR は止めません (片方の `expires` や `tags` しか使われないので、1 つにまとめます)
- 権限やロググループは見ません (AWS に問い合わせる `arata doctor` の仕事です)
- `ARATA_VERSION` は監査のワークフローと同じ版にします (版が違うと、検査を通った設定が監査で読めないことがあります。新しい版で足されたキーなど)。v0.14.0 以降が要ります
- main のブランチ保護で必須のチェックにすると、形の誤った allowlist.yaml はマージできなくなります

## 定時の前に試す (手動実行の `dry_run`)

設定や allowlist.yaml を直した後など、定時の実行の前に「いま流したら何が出るか」を見たいときは、監査のワークフローを Actions の画面から手動で実行し、`dry_run` にチェックを入れます
(`arata run --dry-run`。arata の ADR 0049)。

| 入力 | 意味 |
|---|---|
| `dry_run` | 試しの実行。**ストアのバケットに何も書かず、Slack にも送りません** |
| `window` | 試しの実行で見る期間 (例 `1h`)。空ならプロファイルの `window`。`dry_run` のときだけ使います |

- ストアは読むだけです。出た指摘は報告済みにならず、窓も進まないので、**次の定時の実行は、試さなかったときと同じ通知を出します**
- `window` を短くすると、CloudTrail の読み取りの時間と Logs Insights のスキャン量 (費用) が減ります。前回の実行からの追いつきはしません
- 結果は Actions のログの「試しの実行の結果 (件数だけ)」に、**件数と重大度だけ**が出ます (新規・変化・再発・解消・未対応の数、最大の重大度、重大度ごとの数、
  取れなかったソースとスキップしたチェックの数、注記の数、見た範囲の時刻)。個々の指摘の中身 (主体・IP・要約) は、ほかの step と同じ理由でログに出しません。
  中身を読むときは、手元で同じ認証で `arata run -c aws/prod/arata.yaml --profile daily --dry-run --window 1h --out "$(mktemp -d)"` を流して report.md を見ます
  (手元の試しの実行もストアに書きません)
- `notes` が 1 以上なら、見た範囲が定時の実行より狭く、入っていない期間があります (report.md のカバレッジの「注意」)。日次集計を使うチェックは、短い窓では前日を評価しません
- `aratam notify` は呼びません。arata が失敗しても「実行されていない」は届きません (ジョブは失敗で終わります)。aratam 自身も、試しの実行の報告 (`dry_run: true`) は送りません
- 排他の group は定時の実行と別です。試しの実行はストアに書かないので、定時の実行と重なってもかまいません
- `ARATA_VERSION` は `--dry-run` のある版 (v0.11.0 より後) にします。それより前の版は `--dry-run` を知らず、終了コード 2 で止まります (何も書かれません)
- 導入時の「最初の run」(手順 6) には使いません。あれは溜まっていた指摘を報告済みにするための実行です

## Slack への送信だけを確かめる

[arata-notify-test.yml](../audit-repo/.github/workflows/arata-notify-test.yml) で、Actions の画面から `aratam test-notify` を実行できます。
監査 (`arata run`) は回さず、試験メッセージを 1 通送るだけです。environment の secrets と、リポジトリの `aratam.yaml` の組み合わせで届くかが分かります。

使いどころ:

- 新しい通知先を足したとき・変えたとき (アカウントを足した、`aratam.yaml` のチャンネル ID を直した)。bot がそのチャンネルに投稿できるかを、最初の定時の実行より前に確かめます
- bot トークンを登録したとき・入れ替えたとき (secrets に入れた値が正しいか)
- 知らせのチャンネルに bot を招待したとき (`route: alert`。知らせは、ふだん使われないので、ここで確かめます)
- 通知が届かないとき (Slack の側か、監査の側かを切り分ける)

1. GitHub の Actions → **arata-notify-test** → **Run workflow** を開き、次を選んで実行します

   | 入力 | 中身 |
   |---|---|
   | account | アカウント (`aws/` の下のディレクトリの名前)。その `aratam.yaml` の通知先に送ります |
   | route | `normal` = 通常用に 1 通 / `urgent` = 緊急用に 1 通 (`aratam test-notify --urgent`) / `alert` = 知らせのチャンネルに 1 通 (`--alert-channel` を `none` にした一式には、ありません) |

2. Slack に「aratam の試験通知です」が届けば、その通知先の設定は動いています。通常用と緊急用は別の経路なので、両方を 1 回ずつ確かめます。
   `alert` は、定時の通知が送れなかったことの知らせ (下) と同じ送り方で、知らせのチャンネルに 1 通送ります (aratam を通しません。アカウントによりません)

- **本当に届きます**。`urgent` は緊急用のチャンネルに届き、緊急用を分けていなければ通常用に `urgent_mention` (`<!channel>` など) が付きます。チャンネルの人に一言伝えてから実行します
- AWS には繋ぎません。`test-notify` は `aratam.yaml` を読んで Slack に送るだけで、LLM (Bedrock など) も呼びません。OIDC も実行用ロールも使わず、権限は `contents: read` だけです。
  ストアにも触れないので、監査が走っている間でも実行できます (finding の状態は変わりません)
- secrets の渡し方は、監査の notify と同じです (bot トークンだけを渡します)。`alert` の送り方は、監査の最後の段階と 1 文字も違いません (arata のテストが固定しています)。
  `ARATA_VERSION` も監査と同じ版にします (PR の検査が、揃っていることを確かめます)
- `account` の選択肢は、監査の `matrix.account` と同じ並びです (`arata repo init` が同じ引数から書きます)
- **main で動かします**。秘密は environment にあり、main のジョブにしか渡りません (「実行するリポジトリと環境を堅くする」の 5)。
  チャンネル ID を足す PR は、マージしてから確かめます (マージの前に確かめたいときは、手元で `aratam test-notify` を実行します。手順 4)

失敗したときは、ジョブが失敗 (赤) になり、ログに `code` と終了コードが出ます。

| ログ | 意味 | すること |
|---|---|---|
| `CONFIG_INVALID` (終了コード 2) | `aratam.yaml` の誤りか、トークンが未登録 | `aratam config check` (PR の [arata-check.yml](../audit-repo/.github/workflows/arata-check.yml))。手元で `arata repo check … --github` を流し、足りない秘密を登録する |
| `SEND_FAILED` + `slack error=not_in_channel` | bot がそのチャンネルにいない | そのチャンネルで `/invite @arata` |
| `SEND_FAILED` + `slack error=channel_not_found` | チャンネル ID の誤りか、招待していない非公開チャンネル | `aratam.yaml` の `slack.channel` / `urgent_channel` を確かめ、bot を招待する |
| `SEND_FAILED` + `slack error=invalid_auth` / `token_revoked` など | トークンが無効 | トークンを入れ直す (手順 4 の「Slack アプリを作る」) |
| `SEND_FAILED` だけ (終了コード 5) | Slack に繋がらなかった | 少し待って、もう一度実行する。詳しい原因は手元で同じコマンドを実行する |
| `知らせを送れなかった (slack error=…)` (`route: alert`) | 知らせのチャンネルに bot がいない (`not_in_channel`)・トークンが無効 | 知らせのチャンネルで `/invite @arata`。トークンを入れ直す |

ログに足して出すのは、Slack の error コードだけです。ログの行の `slack_error` (機械が読む項目。`aratam schema log`) から読みます。
aratam が形を確かめた値で、人向けの `error` の文からは切り出しません (`slack_error` は v0.15.0 以降の aratam が出します。それより前の版では `slack error=…` の行が出ないだけです)。エラーの文・チャンネル ID・Slack の応答の本文は、監査と同じく出しません。

## 失敗したとき

| 起きたこと | Slack | ジョブ |
|---|---|---|
| 新規なし | 通常用に 1 行 (`on_quiet: short`) | 成功 |
| 一部のソースが取れない (arata の終了コード 3) | 取れた分の報告を緊急用に | 失敗 |
| `STORE_CONFLICT`・`INTERRUPTED`・設定の誤り・OIDC の失敗など | 「arata の出力が無いか古い」を緊急用に | 失敗 |
| バイナリの取得の失敗、checkout の失敗、認証に使う秘密が未登録 | 届かない (定時の実行なら、知らせのチャンネルに 1 行。下) | 失敗 |
| 通知の設定の誤り (aratam の終了コード 2)、Slack が受け取らない (終了コード 5。bot がチャンネルにいない、など) | 届かない (定時の実行なら、知らせのチャンネルに 1 行。下) | 失敗 |
| bot トークンが未登録・失効 | **届かない。知らせも届かない** (同じトークンで送るため。下) | 失敗 |
| 手動実行の `dry_run` (成功でも失敗でも) | 届かない (試しの実行は通知しない) | arata の終了コードのとおり |

`STORE_CONFLICT` は再実行で解消します (手元の `arata ack` と重なったときなど)。走らなかった窓は次の run が引き直します。

**ログには原因の詳細を出しません**。Actions に出るのは `level`・`code`・`source` と終了コードだけです (この 3 つは、版をまたいで変わらない項目です。`arata schema log`。
code は増えることがあるので、知らない code は「その他の警告・エラー」として扱います。v0.15.0 以降は、ERROR と WARN の行に必ず code が付き、
再試行のように自動で回復するものは INFO なので、ここには出ません)。`msg` と `error` には ARN やアカウント ID が入り得るためです。詳細は手元で同じコマンドを実行して確かめます。
`::add-mask::` で値を列挙して隠す方式は採りません。監査の結果に何が出るかは列挙できないからです。アカウント ID はロールの ARN を secrets に置くことと `mask-aws-account-id: true` で隠します。

## 定時の通知が送れなかったとき

通知そのものが壊れると、aratam は知らせられません。`aratam.yaml` の誤り、バイナリが取れない、認証の失敗、bot が通知のチャンネルにいない、のどれでも、通知のチャンネルには何も届きません。
監査のワークフローの最後の段階 (`alert`) は、**定時の実行で Slack に何も届かなかったとき**に、**知らせのチャンネル** (`--alert-channel`) へ 1 行を送ります。
aratam を通さず、同じ bot トークンで Slack の `chat.postMessage` を直接呼びます (別の Webhook は要りません。arata の ADR 0060)。

```
arata の定時の通知を送れていません。対象: prod / プロファイル: daily / 失敗した段階: audit, notify / https://github.com/…/actions/runs/…
```

- 送るのは **監査対象の名前・プロファイル・失敗した段階の id・その実行の URL** だけです。指摘の中身・件数・ログの文は送りません (報告のファイルを読みません)。
  どの監査対象の通知が送れなかったかが分かれば、あとは実行のログと手元の再実行で調べられます
- 失敗した段階は、`toJSON(steps)` の `outcome` から拾います。拾うのは段階の id (ワークフローに書いた名前) だけです
- 送らない場合: 手動実行 (実行した人が結果を見ています)。aratam が Slack に何かを送れたとき (取れた分の報告を緊急用に送った、「arata の出力が無いか古い」を送った)。
  このときジョブは失敗 (赤) のままですが、Slack で気づけます
- **知らせのチャンネルは、通知のチャンネルとは別にすることを勧めます**。bot が通知のチャンネルから外されたときにも、知らせは届きます。
  対象の名前 (`ARATA_TARGET`。アカウントの名前) が届くので、その名前を見てよい人のいるチャンネルにします。bot を、知らせのチャンネルにも招待しておきます
- Slack は、失敗でも HTTP 200 を返します。この段階は、応答の `ok` が `true` のときだけ、届いたとみなします。届かなければ `::error::知らせを送れなかった (slack error=…)` と出します
  (出すのは Slack の error コードだけです。トークン・応答の本文は出しません。トークンは、`curl` の引数ではなく標準入力で渡します)
- **トークンそのものが使えないとき (未登録・失効・取り消し) は、知らせも届きません**。通知と知らせが、同じトークンを使うためです。このときも、ジョブは失敗 (赤) のままで、ログに `::error::` が出ます。
  その先は、下の「死活監視」と GitHub の実行失敗の通知が頼りです。定時の前に、次の 2 つで確かめておきます
  - `arata repo check … --github`: トークンが登録されているか (名前があるか)
  - `arata-notify-test` の `route: alert`: トークンが有効で、bot が知らせのチャンネルにいるか。トークンを入れ替えたときにも流します
- `--alert-channel none` で書き出した一式には、この段階がありません (知らせを使わない設定です)
- ジョブが取り消されたとき・ジョブ全体の時間切れで止められたときは `failure()` にならないので、この段階は動きません (下の「死活監視」で気づきます)

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
- **Action の更新**: action の SHA は、書き出した arata の版のものに固定されます。新しい版の `arata repo init --force` で届きます。自分のリポジトリの Dependabot で先に上げると、`arata repo init --diff` が差を出します
- **取得の照合の限界**: `SHA256SUMS` は同じリリースのものなので、壊れた取得は防げてもリリース自体のすり替えは防げません。arata が公開リポジトリになったら `gh attestation verify` を足せます (README「来歴の検証」)
