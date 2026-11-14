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
| `.github/workflows/` | 定時の監査、finding の片付け、試しの通知、PR の検査 | 手で直さない (下の「版を上げる・アカウントを足す」) |
| `github/` | GitHub の設定の Terraform (非公開、fork の禁止、main の保護、Actions の許可、environment `audit`)。秘密には触れない | 同上 |
| `aws/<アカウント>/` | アカウントごとの `arata.yaml`・`allowlist.yaml`・`aratam.yaml` | **PR で育てる** (`arata repo init` は、既にあるものを書き直さない) |

監査するアカウント: @@ACCOUNTS_TEXT@@

この一式が揃っているか・秘密が足りているかは、いつでも `arata repo check` で確かめられます (読むだけです。下の 4)。

```sh
# ファイルだけを見る (PR の検査と同じ)
@@CHECK_COMMAND@@

# GitHub の environment と、秘密の名前も見る
GITHUB_TOKEN="$(gh auth token)" @@CHECK_COMMAND@@ --github
```

## 置く順番

このリポジトリは、**1 つの会社 (監査を任される組織) のアカウントだけ**を監査する形を勧めます (1 の「会社ごとに、リポジトリと実行用ロールを分ける」)。

順番を守ってください。特に、**environment (3) はワークフロー (5) より先**に作ります。
無い environment を参照するワークフローが動くと、GitHub は同じ名前の environment を、制限なしで自動で作ります。

### 1. AWS のスタックと、Slack アプリ

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

通知は Slack の bot で送ります。Slack アプリを、arata のリポジトリの `deploy/slack/app-manifest.yaml` から作ってワークスペースに入れ (arata の README の「bot トークンで送る」)、
bot を、通知のチャンネル (通常用と、分けるなら緊急用) と、知らせのチャンネル (@@ALERT_TEXT@@) に招待します (`/invite @<bot の名前>`)。
招待していないチャンネルには送れません。

### 会社ごとに、リポジトリと実行用ロールを分ける

監査のリポジトリは、**会社 (監査を任される組織) ごとに 1 つ**にすることを勧めます。実行用ロール・リポジトリ・秘密の 1 組が複数の会社に届いていると、
乗っ取りや取り違え (ある会社の指摘が、別の会社の Slack に届く) の被害が、全部の会社に及びます。
1 つのリポジトリで複数のアカウントを回す形 (`--accounts`) は、同じ会社のアカウント (prod と staging など) に使います。

会社ごとに、`arata repo init` を別のリポジトリに向けて流し、**実行用ロールも会社ごとに作ります**。同じ AWS アカウントに 2 つ目以降の実行の仕組みを置くときは、
スタックの名前を変え、次のパラメータを変えます (1 のコマンドとの違いだけ)。

```sh
aws cloudformation deploy --stack-name arata-runner-<会社の名前> \
  --template-file deploy/github-actions/runner.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    RoleName=arata-runner-<会社の名前> \
    OIDCProviderArn=<1 つ目のスタックの出力 OIDCProviderArn> \
    GitHubRepository=<その会社のリポジトリ> \
    GitHubEnvironment=audit \
    AuditRoleArns=<その会社の読み取り専用ロールだけ>
```

| パラメータ | 2 つ目以降で変えること |
|---|---|
| スタックの名前、`RoleName` | 会社ごとに別の名前にする (ロールの名前は、アカウントの中で 1 つだけ)。既定の `arata-runner` は 1 つ目が使っている |
| `OIDCProviderArn` | 1 つ目のスタックの出力を渡す (GitHub の OIDC プロバイダは、アカウントに 1 つしか作れない。空のままだと、作ろうとして失敗する) |
| `GitHubRepository` | その会社のリポジトリ。信頼は 1 つのリポジトリの完全一致なので、ほかの会社のリポジトリからは引き受けられない |
| `AuditRoleArns` | その会社の読み取り専用ロールだけ。ほかの会社のロールを並べない |
| `StoreBucketName` | 空のままにするか、別の名前にする。**ストアのバケットは、スタックごとに別に作られる** (実行用ロールは、自分のスタックのバケットしか読み書きできない)。`--store-bucket` には、そのスタックの出力のバケットを書く |

- 読み取り専用ロール (`readonly-role.yaml`) の `TrustedPrincipalArn` には、その会社の実行用ロールを渡します。ほかの会社の実行用ロールは、信頼ポリシーに無いので引き受けられません
- 既知リストの「監査する側のアカウント」(`account:`) は、そのアカウントの全主体を承認します。実行用ロールを会社ごとに分けても、同じアカウントに置いていれば、arata はどの実行用ロールからの引き受けかを見分けません
  (監査対象の CloudTrail には、呼び出し元のアカウント ID しか残りません)。引き受けられる主体を絞るのは、読み取り専用ロールの信頼ポリシーです
- Slack の秘密は、リポジトリごとの environment に置きます。**bot トークンは、bot を招待したすべてのチャンネルに投稿できます** (読むことはできません)。同じトークンを複数の会社のリポジトリに置くと、
  1 つのリポジトリから読み出されたときに、ほかの会社のチャンネルにも投稿できます。**Slack アプリ (トークン) を会社ごとに作り**、bot を招待するのは通知に使うチャンネルだけにします
- 既に 1 つのリポジトリで複数の会社を回しているときは、会社ごとに新しいリポジトリを書き出し、`aws/<アカウント>/` の設定を移します。ストアは、新しいバケットへ写すか、新しく `arata init` します

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
- **リポジトリが既にあるとき**: 先に、今ある設定を取り込みます (下の「既にあるリポジトリを取り込む」)。取り込まずに当てると、「同じ名前がある」というエラーで止まるか、
  同じ役目のルールセットがもう 1 つできます
- 宣言に持つのは、セキュリティに効く項目だけです。説明やマージの方式などは、画面で自由に変えられます
- PR の承認を必須にするなら、`-var required_approving_review_count=1` を付けます (2 人以上で運用するときに勧めます)
- main の保護と environment は、非公開のリポジトリでは GitHub の有料プランが要ります
- Terraform の state は手元に残ります (`.gitignore` 済み)。別の人が当てるときは、上の `import` で取り込み直します
- Terraform に無い設定 (fork の PR へのワークフローの権限、OIDC の `sub` の形、組織の fork の設定、書き込み権限を持つ人) は、説明書の「実行するリポジトリと環境を堅くする」で点検します

### 4. 秘密を登録する

最初は、秘密は 1 つも登録されていません。`arata repo check` に `--github` を付けて流すと、足りない秘密の名前と、そのまま打てる登録のコマンドが出ます。

```sh
GITHUB_TOKEN="$(gh auth token)" @@CHECK_COMMAND@@ --github
```

出たコマンド (`gh secret set <名前> --env audit -R @@OWNER@@/@@REPO@@`) を、名前ごとに打ちます。`gh` が値を端末で聞くので、貼り付けます (値はシェルの履歴に残りません)。
登録したら、同じ `arata repo check … --github` をもう一度流し、`ng` が無くなることを確かめます。

| 名前 | 値の形 | 取得元 |
|---|---|---|
| `ARATA_RUNNER_ROLE_ARN` | `arn:aws:iam::123456789012:role/arata-runner` | 1 の実行の仕組みのスタックの出力 `RunnerRoleArn` |
| `ARATA_AUDIT_ROLE_ARNS` | 読み取り専用ロールの ARN を、アカウントの名前から引く JSON (例 `{"<アカウント>": "arn:aws:iam::123456789012:role/arata-readonly"}`) | 1 の読み取り専用ロールのスタックの出力 (アカウントごと) |
| `ARATAM_SLACK_BOT_TOKEN` | `xoxb-…` | 1 の Slack アプリの「OAuth & Permissions」の Bot User OAuth Token |

- 要る秘密は、この 3 つだけです。`arata repo check` は GitHub を読むだけで、秘密を登録しません。秘密の値も読みません (GitHub は、名前と更新日時しか返しません)
- `arata repo check --github` は、ほかに次も確かめます: environment `audit` があり、デプロイできるブランチが既定のブランチだけであること。
  この一式が使わない秘密が environment に残っていないこと (消すコマンドが出ます)。リポジトリの secrets (environment でないもの) に秘密が置かれていないこと
- リポジトリの secrets (Settings → Secrets and variables → Actions) には置きません。どのブランチのジョブにも渡ります
- 読むのに使う鍵 (`GITHUB_TOKEN`) には、リポジトリの admin の権限が要ります (3 で使ったものと同じ)。`arata` は鍵を保存しません

### 5. 最初の PR で一式を入れる

`aws/<アカウント>/` の設定 (`arata.yaml` の `sources` など) を自分の環境に合わせてから、ブランチを push して PR を作ります。
PR の検査 (`check`) が通ることを確かめてマージします。検査は、設定の形 (`config check`) と、この一式が揃っていること (`arata repo check`) を見ます。この時点では、定時の実行は入っていません。

### 6. 試しの通知と、試しの実行

Actions の画面から手動で実行します (どちらも main で)。

- `arata-notify-test`: Slack へ試験メッセージを 1 通送ります。送り先 (`route`) を変えて、通常用 (`normal`)・緊急用 (`urgent`)@@ROUTE_ALERT_README@@を、アカウントごとに確かめます。
  bot がそのチャンネルに招待されていなければ、ここで分かります (`slack error=not_in_channel`)
- `arata-audit` を `dry_run` で: 監査と同じ認証・設定で流し、ストアに書かず、通知もしません。結果は件数だけがログに出ます

### 7. 導入の流れ

`arata help ai onboarding` の順番で、手元で行います: `arata doctor` → `arata init` (ベースラインの収集) → 通知をつながない最初の run → 出た指摘の片付け。
最初の run で、長く溜まっていたものが一度に出ます。これを片付けてから、定時の通知を始めます。

### 8. 定時を有効にする

同じ引数に `--schedule --force` を足して書き直し、PR で入れます (変わるのは `arata-audit.yml` の `schedule` だけです)。

## チャンネルを変える

通知のチャンネル ID は、`aws/<アカウント>/aratam.yaml` だけが持っています (`arata repo init` は、既にある `aratam.yaml` を書き直しません)。

1. 新しいチャンネルに、bot を招待します (`/invite @<bot の名前>`)
2. `aws/<アカウント>/aratam.yaml` の `slack.channel` (緊急用なら `slack.urgent_channel`) の 1 行を、新しいチャンネル ID (`C0123456789` の形) に直します
3. PR を出します。PR の検査が、ID の形と、一式との組を確かめます
4. マージしたら、`arata-notify-test` で、新しいチャンネルに届くことを確かめます

- 秘密は変わりません (トークンは同じです)
- **知らせのチャンネル**は、ワークフローに書いてあります。変えるときは、上のコマンドの `--alert-channel` を直して `--force` を足して流し、PR で入れます (下の「版を上げる・アカウントを足す」)。
  `none` にすると、知らせの段階ごと無くなります
- 定時の通知が送れなかったことの知らせは、同じ bot トークンで送ります。**トークンそのものが使えないとき (未登録・失効) は、知らせも届きません**。
  トークンを入れ替えたときは、`arata-notify-test` を流して確かめます

## 既にあるリポジトリを取り込む

リポジトリや、その設定 (ルールセット、environment など) が既にあるときは、`github/` を当てる前に、今あるものを Terraform の state に取り込みます。
GitHub の設定の Terraform を手で作っていた場合も、同じ手順です。取り込みは読むだけで、GitHub の側は何も変わりません。

**1. 古い宣言と state をどける** (Terraform を手で作っていた場合)

- `github/` に残っている、この一式のものでない `.tf` と、`github/secrets/` (これまでの版の「秘密の箱」。この版では使いません) を消します。Terraform は同じディレクトリの `.tf` を全部当てるので、残すと宣言が二重になります。
  `arata repo check` が、残っている `.tf` を「この版の一式に無い」と出します
- **古い state (`terraform.tfstate`) は、`github/` の外へ移します** (消さずに取っておきます)。古い state のまま当てると、Terraform は「古い宣言のリソースを消して、新しい宣言のリソースを作る」と計画します。
  リポジトリそのものが「消す」に入り得ます。新しい state から始めて、下の 2 で取り込み直します

**2. 取り込む**。あるものだけを取り込みます (無いものは、当てたときに作られます)。ID は `gh api` で調べます (どれも読み取りです)。

```sh
export GITHUB_TOKEN="$(gh auth token)"
terraform -chdir=github init

# リポジトリ、Actions の許可、GITHUB_TOKEN の既定の権限 (ID はリポジトリの名前)
terraform -chdir=github import github_repository.audit @@REPO@@
terraform -chdir=github import github_actions_repository_permissions.audit @@REPO@@
terraform -chdir=github import github_workflow_repository_permissions.audit @@REPO@@

# main のルールセット (ID は <リポジトリの名前>:<ルールセットの ID>)
gh api repos/@@OWNER@@/@@REPO@@/rulesets --jq '.[] | "\(.id)  \(.name)  \(.target)  \(.enforcement)"'
terraform -chdir=github import github_repository_ruleset.default_branch @@REPO@@:<ルールセットの ID>

# environment と、デプロイできるブランチ (ID は <リポジトリの名前>:audit と、<リポジトリの名前>:audit:<ポリシーの ID>)
terraform -chdir=github import github_repository_environment.audit @@REPO@@:audit
gh api repos/@@OWNER@@/@@REPO@@/environments/audit/deployment-branch-policies --jq '.branch_policies[] | "\(.id)  \(.name)  \(.type)"'
terraform -chdir=github import github_repository_environment_deployment_policy.audit_branch @@REPO@@:audit:<main のポリシーの ID>
```

- main を守るルールセットが複数あるときは、PR 必須などを持つ 1 つを取り込みます。残りは、当てた後に画面で消すか、そのまま残します (ルールセットは重ねて効き、厳しいほうが勝ちます)。
  取り込まなかった場合は、`arata-default-branch` という名前のルールセットがもう 1 つできます
- デプロイできるブランチが「すべて」のまま (ポリシーが 1 つも無い) なら、最後の取り込みは要りません。当てると `main` だけになります
- 従来のブランチ保護 (ルールセットではないもの) は、この宣言の対象外です。あれば、そのまま残ります (`gh api repos/@@OWNER@@/@@REPO@@/branches/main/protection`)

**3. plan を読んでから当てる**

```sh
terraform -chdir=github plan
```

- **「destroy」が 0 であること**を確かめます (`Plan: … 0 to destroy`)。0 でなければ当てずに、1 の state と、取り込みの漏れを見直します
- 「change」に出るのは、この一式の宣言に揃える変更です。読んで、意図しない緩和が無いことを確かめます。よく出るもの:
  ルールセットの名前が `arata-default-branch` に変わる。迂回できる主体 (`bypass_actors`) が外れる。environment のレビュー担当と待ち時間が外れる (定時の実行が止まるため、付けません)。
  許可する action が、GitHub 製と `aws-actions/configure-aws-credentials` だけになる (ほかの action を使うワークフローがあれば、動かなくなります)
- 説明・トピック・マージの方式などは、変更に出ません (宣言に持たない項目です)。出たら、当てる前に arata の側に知らせてください
- 秘密は、Terraform の対象ではありません。既に登録してある秘密は、そのまま使われます。足りないもの・余っているものは `arata repo check … --github` が出します (4)
- Webhook で送っていた `aratam.yaml` を持ち込むと、`arata repo check` が、`slack` の節に書く行を出します (この一式のワークフローは、bot トークンだけを渡します)

## 版を上げる・アカウントを足す

新しい版の arata で、上のコマンドに `--force` を足して流します。アカウントを足すときは `--accounts` に名前を足します。

- 書き直すのは生成物 (`.github/`、`github/`、この README、`.gitignore`) だけです。`aws/<アカウント>/` は、無いものだけを作ります
- 書き直す前に、`--diff` で何が変わるかを見られます (`--format json` で機械向け。差があれば終了コード 1)
- 足したアカウントには、`--channel <アカウント>=<チャンネル ID>` と `--urgent-channel <アカウント>=<チャンネル ID>|same` も要ります (端末から打てば、聞かれます)。
  既にあるアカウントのチャンネルは、聞かれません
- 書き直した結果は PR にして、差分を確かめてからマージします
- アカウントを足したら、1 の `AuditRoleArns`、4 の `ARATA_AUDIT_ROLE_ARNS` (同じ `gh secret set` で入れ直します)、足したアカウントの読み取り専用ロールと `arata init`、bot の招待も要ります
