# @@REPO@@

AWS のログを [arata](https://github.com/CircleAround/arata) で定時に監査し、aratam で Slack に通知するリポジトリです。
この一式は `arata repo init` (arata @@ARATA_VERSION@@) が書き出しました。

```sh
@@COMMAND@@
```

- 手順の理由と、設定の点検のしかたは、arata のリポジトリの [examples/github-actions/README.md](https://github.com/CircleAround/arata/blob/@@ARATA_VERSION@@/examples/github-actions/README.md) (以下「説明書」) にあります
- AI (LLM) に手伝わせるときは、`arata help ai runtime` と `arata help ai onboarding` を読ませます

## 入っているもの

| 場所 | 中身 | 直し方 |
|---|---|---|
| `.github/workflows/`、`.github/scripts/` | 定時の監査、finding の片付け、試しの通知、PR の検査 | 手で直さない (下の「版を上げる・アカウントを足す」) |
| `github/` | GitHub の設定の Terraform (非公開、fork の禁止、main の保護、Actions の許可、environment `audit`) | 同上 |
| `github/secrets/` | 秘密の箱の Terraform (秘密の名前を、仮の値で作る。既にある秘密には書かない) | 同上 |
| `aws/<アカウント>/` | アカウントごとの `arata.yaml`・`allowlist.yaml`・`aratam.yaml` | **PR で育てる** (`arata repo init` は、既にあるものを書き直さない) |

監査するアカウント: @@ACCOUNTS_TEXT@@

## 置く順番

順番を守ってください。特に、**environment (3) はワークフロー (5) より先**に作ります。
無い environment を参照するワークフローが動くと、GitHub は同じ名前の environment を、制限なしで自動で作ります。

### 1. AWS のスタック

arata のリポジトリの @@ARATA_VERSION@@ のタグから、2 つのテンプレートを取得して置きます (説明書の「用意するもの」の 1 と 2)。

```sh
# 実行の仕組み (OIDC プロバイダ・ストアのバケット・実行用ロール)。arata を動かす側のアカウントに 1 つ
aws cloudformation deploy --stack-name arata-runner \
  --template-file deploy/github-actions/runner.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    GitHubRepository=@@OWNER@@/@@REPO@@ \
    GitHubEnvironment=audit \
    StoreBucketName=@@STORE_BUCKET@@ \
    AuditRoleArns=<読み取り専用ロールの ARN。アカウントの数だけ、カンマ区切り>

# 読み取り専用ロール。監査対象のアカウントごとに 1 つ
aws cloudformation deploy --stack-name arata-readonly \
  --template-file deploy/iam/readonly-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustedPrincipalArn=<実行用ロールの ARN (上のスタックの出力 RunnerRoleArn)>
```

- `GitHubRepository` は、OIDC トークンの `sub` の形に合わせます。2026-07-15 より後に作ったリポジトリは ID 入りの形です (説明書の 1 の注意)。
  リポジトリをこれから作るなら、3 の後に ID が決まるので、3 → 1 の順でもかまいません
- ストアのバケットは `@@STORE_BUCKET@@` (ワークフローと `aws/<アカウント>/arata.yaml` に書いてある名前)、リージョンは `@@AWS_REGION@@` です

### 2. この一式を手元に置く

もう済んでいます (この README がその結果です)。まだ push しません。

### 3. GitHub の設定を当てる

Terraform (1.7 以降) を使い、リポジトリの admin を持つ人が手元で当てます。認証は環境変数で渡し、ファイルに書きません。

```sh
export GITHUB_TOKEN="$(gh auth token)"
terraform -chdir=github init
terraform -chdir=github plan     # 何が変わるかを読む
terraform -chdir=github apply
```

- **リポジトリがまだ無いとき**: そのまま当てると、非公開のリポジトリを最初のコミット付きで作ります
- **リポジトリが既にあるとき**: 先に取り込みます (取り込まずに当てると、「同じ名前がある」というエラーで止まります。何も変わりません)

  ```sh
  terraform -chdir=github import github_repository.audit @@REPO@@
  ```

  environment `audit` や Actions の設定が既にあるときも、同じように取り込めます (`github_repository_environment.audit` は `@@REPO@@:audit`、
  `github_actions_repository_permissions.audit` と `github_workflow_repository_permissions.audit` は `@@REPO@@`)
- 宣言に持つのは、セキュリティに効く項目だけです。説明やマージの方式などは、画面で自由に変えられます
- PR の承認を必須にするなら、`-var required_approving_review_count=1` を付けます (2 人以上で運用するときに勧めます)
- main の保護と environment は、非公開のリポジトリでは GitHub の有料プランが要ります
- Terraform の state は手元に残ります (`.gitignore` 済み)。別の人が当てるときは、上の `import` で取り込み直します
- Terraform に無い設定 (fork の PR へのワークフローの権限、OIDC の `sub` の形、組織の fork の設定、書き込み権限を持つ人) は、説明書の「実行するリポジトリと環境を堅くする」で点検します

### 4. 秘密の箱を作り、値を入れる

```sh
terraform -chdir=github/secrets init
terraform -chdir=github/secrets plan     # 「作る」と出た名前が、まだ無いことを確かめる
terraform -chdir=github/secrets apply
```

- 既にある秘密は取り込むだけで、書き換えません。無い名前だけを、仮の値で作ります
- 計画を見てから承認するまでの間に、同じ名前の秘密を入れないでください (仮の値で置き換わります)。値を入れるのは、箱を作った後です
- 箱ができたら、Settings → Environments → `audit` → Environment secrets で、本物の値を入れます

| 名前 | 中身 |
|---|---|
| `ARATA_RUNNER_ROLE_ARN` | 実行用ロールの ARN (1 の出力 `RunnerRoleArn`) |
| `ARATA_AUDIT_ROLE_ARNS` | 読み取り専用ロールの ARN を、アカウントの名前から引く JSON (例 `{"<アカウント>": "arn:aws:iam::123456789012:role/arata-readonly"}`) |
| `ARATA_ALERT_WEBHOOK` | 定時の通知が送れなかったことを知らせる、別の Webhook |
| `ARATAM_SLACK_WEBHOOK`、`ARATAM_SLACK_URGENT_WEBHOOK` | Webhook で送るときの、通常用と緊急用 |
| `ARATAM_SLACK_BOT_TOKEN` | bot トークンで送るときのトークン |

- Slack の秘密は、使う送り方のものだけを入れます (Webhook の 2 つか、bot トークンの 1 つ。説明書の 4)。使わないほうは、仮の値のままでかまいません
- 仮の値が残っている秘密を使おうとしたワークフローは、秘密の名前を出して止まります
- リポジトリの secrets (Settings → Secrets and variables → Actions) には置きません

### 5. 最初の PR で一式を入れる

`aws/<アカウント>/` の設定 (`arata.yaml` の `sources`、`aratam.yaml` の通知先) を自分の環境に合わせてから、ブランチを push して PR を作ります。
PR の検査 (`check`) が通ることを確かめてマージします。この時点では、定時の実行は入っていません。

### 6. 試しの通知と、試しの実行

Actions の画面から手動で実行します (どちらも main で)。

- `arata-notify-test`: Slack へ試験メッセージを 1 通送ります
- `arata-audit` を `dry_run` で: 監査と同じ認証・設定で流し、ストアに書かず、通知もしません。結果は件数だけがログに出ます

### 7. 導入の流れ

`arata help ai onboarding` の順番で、手元で行います: `arata doctor` → `arata init` (ベースラインの収集) → 通知をつながない最初の run → 出た指摘の片付け。
最初の run で、長く溜まっていたものが一度に出ます。これを片付けてから、定時の通知を始めます。

### 8. 定時を有効にする

同じ引数に `--schedule --force` を足して書き直し、PR で入れます (変わるのは `arata-audit.yml` の `schedule` だけです)。

## 版を上げる・アカウントを足す

新しい版の arata で、上のコマンドに `--force` を足して流します。アカウントを足すときは `--accounts` に名前を足します。

- 書き直すのは生成物 (`.github/`、`github/`、この README、`.gitignore`) だけです。`aws/<アカウント>/` は、無いものだけを作ります
- 書き直す前に、`--diff` で何が変わるかを見られます (`--format json` で機械向け。差があれば終了コード 1)
- 書き直した結果は PR にして、差分を確かめてからマージします
- アカウントを足したら、1 の `AuditRoleArns`、4 の `ARATA_AUDIT_ROLE_ARNS`、足したアカウントの読み取り専用ロールと `arata init` も要ります
