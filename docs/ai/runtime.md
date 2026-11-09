# 利用者の環境を作る・見直すときのチェックリスト (GitHub Actions)

## 使い方

arata / aratam を GitHub Actions で動かすリポジトリ (以下「監査のリポジトリ」) を作るとき・見直すときに、上から順に確かめる。
監査のリポジトリは、ストアへの書き込み・Slack の Webhook・監査対象の読み取りロールへの入口を持つ。守るのは次の 2 つ。

- **main に入れられる人 = 実行用ロールを使える人**。それ以外の経路 (fork、ほかのブランチ、PR) からは使えない
- secrets (Webhook) を読める人を最小にする

LLM が行ってよいのは**読み取りだけ** (`gh api` の GET、ファイルを読む)。設定の変更・ワークフローの追加・secrets の操作は、**人が**判断して行う (LLM は差分や手順を提案する)。
`OWNER` / `REPO` は監査のリポジトリに読み替える。API が 403 / 404 を返す項目は、権限が足りないだけのことが多い。「確かめられなかった」と報告し、問題なしにしない。
手順の全体 (テンプレート、secrets の名前、見本) は arata のリポジトリの `examples/github-actions/README.md`。

## リポジトリと fork

監査のリポジトリは fork される必要が無い。fork は allowlist (アカウント ID・ARN) と Actions のログの写しを、元のリポジトリの管理の外に作る。

```sh
gh api repos/OWNER/REPO --jq '{private, visibility, allow_forking, fork}'
gh api orgs/OWNER --jq '.members_can_fork_private_repositories'
gh api repos/OWNER/REPO/forks --jq 'length'
```

- `private: true` (`visibility` が `public` なら、ほかの項目より先に人に知らせる)
- `allow_forking: false`、組織の `members_can_fork_private_repositories: false` (組織の値が `null` なら、組織の所有者に確かめてもらう)
- `fork: false` (監査のリポジトリ自身が fork でない)、既にある fork が 0 件。あれば人に知らせる (消すかは人が決める)

## ワークフローのトリガー

fork の PR と、PR のワークフローに、secrets と書き込みのトークンを渡さない。

```sh
gh api repos/OWNER/REPO/actions/permissions/fork-pr-workflows-private-repos
grep -rnE 'pull_request_target|workflow_run' .github/workflows/
```

- fork の PR の設定は `run_workflows_from_fork_pull_requests: false` (`send_write_tokens_to_workflows`・`send_secrets_and_variables` も `false`)。
  fork を禁止していれば fork の PR は来ないが、fork の禁止が外れたときの 2 段目として閉じておく。組織で無効なら、リポジトリでは有効にできない
- `pull_request_target` と `workflow_run` を使わない (PR の内容を、secrets を持つ文脈で動かす経路になる)
- `pull_request` で動くワークフローは `arata-check.yml` の形に留める: 権限は `contents: read` だけ、`secrets.` を参照しない、`id-token` を持たない
- secrets か OIDC を使うワークフロー (監査、finding の片付け) は、`schedule` と `workflow_dispatch` でだけ動かす

## OIDC の信頼

実行用ロール (`deploy/github-actions/runner.yaml`) は、OIDC トークンの `sub` が次の 1 つの文字列に完全に一致するときだけ引き受けられる。

```
repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main
```

```sh
gh api repos/OWNER/REPO/actions/oidc/customization/sub
aws iam get-role --role-name arata-runner --query 'Role.AssumeRolePolicyDocument'
```

- 1 つ目の応答が `use_default: true`・`use_immutable_subject: true` で、`sub_claim_prefix` が `repo:OWNER@OWNER_ID/REPO@REPO_ID` の形 (ID 入り)。
  `use_immutable_subject` が `false` なら従来の形 (`repo:OWNER/REPO:...`) で、名前だけで決まる。リポジトリや組織を消した後に同じ名前で作り直されると、同じ `sub` になる。
  ID 入りに切り替えるのは人が行い (リポジトリか組織の Actions の OIDC の設定)、切り替えたら `runner.yaml` の `GitHubRepository` も `OWNER@OWNER_ID/REPO@REPO_ID` に変える (揃えないと引き受けに失敗する)
- 信頼ポリシーは `StringEquals` だけで、`aud` = `sts.amazonaws.com`、`sub` = 上の文字列 (`sub_claim_prefix` + `:ref:refs/heads/main`)。
  `StringLike`、`*` を含む `sub`、複数のブランチ、`:pull_request`、`:environment:` の `sub` があれば人に知らせる
- 引き受けられない理由 (確かめるときの見方):
  - fork は別のリポジトリなので、fork で動くワークフローの `sub` は fork 自身の名前と ID になる
  - 同じ名前で作り直したリポジトリは ID が違う (ID 入りの形のとき)
  - 同じリポジトリでも、ほかのブランチは `ref` が違い、PR のワークフローは `sub` が `...:pull_request` になる
- ジョブに `environment:` を書くと `sub` が `...:environment:<名前>` に変わり、`runner.yaml` のロールは引き受けられなくなる。監査のワークフローに書かれていないこと

## main の保護と書き込み権限

`sub` が main に絞られているので、main にコミットを入れられる人が、実行用ロールで動かす内容を決められる。

```sh
gh api repos/OWNER/REPO/rules/branches/main --jq '[.[].type]'
gh api repos/OWNER/REPO/rulesets --jq '.[] | {id, name, enforcement}'
gh api repos/OWNER/REPO/collaborators --jq '.[] | select(.permissions.push) | .login'
gh api repos/OWNER/REPO/keys --jq '.[] | {title, read_only}'
```

- main に効いている規則に `pull_request` (PR 必須)・`non_fast_forward` (強制 push の禁止)・`deletion` (削除の禁止) がある。
  ruleset ではなく従来のブランチ保護なら `gh api repos/OWNER/REPO/branches/main/protection` で読む
- 規則を迂回できる主体 (`gh api repos/OWNER/REPO/rulesets/<id>` の `bypass_actors`) が空か、理由を説明できる
- 書き込み権限 (`push`) を持つ人が、監査の運用に要る人だけ。一覧を人に見せ、要らない人がいないかを確かめてもらう (個人の名前は報告やリポジトリに書き写さない。人数と、確かめる場所を書く)
- 書き込みのできるデプロイキー (`read_only: false`) が無い
- `arata-check.yml` を必須のチェックにしていれば、形の誤った設定は main に入らない (任意)

## secrets

リポジトリの secrets は、どのブランチのワークフローからも読める。書き込み権限のある人は、ブランチにワークフローを足して push すれば、main の保護を通らずに読み出せる。

```sh
gh api repos/OWNER/REPO/actions/secrets --jq '[.secrets[].name]'
gh api repos/OWNER/REPO/environments --jq '[.environments[] | {name, deployment_branch_policy}]'
```

- 置いてあるのが、見本の 4 つ (実行用ロールと監査ロールの ARN、Slack の Webhook 2 つ。複数のアカウントなら ARN は JSON の 1 つ) だけ。長期の AWS のアクセスキーが無い
- 読み出されて困るのは Webhook (偽の通知を送れる)。ロールの ARN は読めても、`sub` が合わないので引き受けられない (分かるのはアカウント ID)
- 守りは「書き込み権限を持つ人を最小に」。漏れた疑いがあれば、人が Webhook を作り直す
- GitHub の environment に Webhook を置き、`deployment_branch_policy` で main だけに限れば、ほかのブランチのジョブからは読めなくなる。
  ただし今の `runner.yaml` は environment の `sub` を受け付けないので、OIDC を使うジョブには `environment:` を付けられない (テンプレートの対応は予定。arata の `docs/roadmap.md`)。
  environment を勧めるときは、この制約と、非公開のリポジトリでは GitHub の有料プランが要ることを添える

## Actions の設定

```sh
gh api repos/OWNER/REPO/actions/permissions
gh api repos/OWNER/REPO/actions/permissions/selected-actions
gh api repos/OWNER/REPO/actions/permissions/workflow
gh api repos/OWNER/REPO/actions/permissions/access
```

- `allowed_actions: selected`、`sha_pinning_required: true`
- 許可リストは `github_owned_allowed: true`、`verified_allowed: false`、`patterns_allowed` は `aws-actions/configure-aws-credentials@*` だけ (見本が使う action は `actions/checkout` とこれの 2 つ)
- `default_workflow_permissions: read`、`can_approve_pull_request_reviews: false`
- ほかのリポジトリからワークフローを使わせない (`access` の応答が `none`)

## ワークフローの形

`.github/workflows/` のファイルを読んで確かめる (見本をそのまま写していれば満たす)。

- ワークフローの先頭は `permissions: {}`。権限はジョブごとに書き、監査は `id-token: write` と `contents: read` だけ
- `uses:` は 40 桁の commit SHA で固定し、版をコメントに書く
- checkout は `persist-credentials: false`
- `run:` に `${{ }}` の式を埋め込まない (値は `env:` で渡す)
- secrets は、使う step の `env:` か `with:` にだけ渡す。`secrets[...]` で動的に選ばない、`secrets: inherit` を使わない
- Actions のログと artifacts に、ARN・アカウント ID・レポートの本文を出さない

## 監査対象の前提 (context_file) の下書き

環境を作るときは、aratam の `llm.context_file` (この監査対象の前提) の下書きまで行う。`llm.provider` が `none` 以外なら、最初の通知の前に置く。
無くても動くが、無いと要約の LLM はアプリの事情を知らず、正規の動作にも一般的で慎重な助言しか書けない。判定 (重大度・送り先) は、あっても変わらない。

1. 最初の収集 (`arata init`) の後に、`arata review --format json` と、読み取り専用ロールで読める構成 (`describe` / `get` / `list`) から事実を拾う
2. 書くこと: どのアプリが本番か、デプロイの流れ (どの主体が何を引き受けるか)、起動時に秘匿値をまとめて読むロール、正規の送信元 (監視・拠点・CI)、
   監査の仕組み自体 (実行用ロール・読み取り専用ロール) を誰が置いたか。形の例は arata のリポジトリの `examples/aratam-context.md`
3. 構成から読み取れず推測したことは「未確認」と書く。秘密 (Webhook・キー)、氏名、メールアドレスは書かない。16 KiB まで
4. 設定ファイルと同じディレクトリに置き、`aratam.yaml` の `llm.context_file` に書く差分と合わせて PR にする。**人が**事実を確かめてマージする (`aratam config check` が読めるかを見る)
5. 前提は承認ではない。前提に「正規」と書いても allowlist には入らず、未承認の主体は報告され続ける。承認は `arata help ai approve` の手順で別に行う
6. 事実が変わったら (デプロイの方式、送信元、ロールの入れ替え) PR で直すよう、人に伝える

## 報告の書き方

- 項目ごとに「満たす / 満たさない / 確かめられなかった (理由)」を書き、満たさないものには直し方 (GitHub の画面の場所か、人が実行するコマンド) を添える
- 急ぐ順: 公開されている・fork がある → `sub` が広い (ワイルドカード、複数のブランチ) → main の保護が無い → 書き込み権限が広い → Actions の設定
- 報告に個人を特定できる値 (氏名、メールアドレス) と、アカウント ID・ARN・Webhook を書かない
