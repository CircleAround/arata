# 利用者の環境を作る・見直すときのチェックリスト (GitHub Actions)

## 使い方

arata / aratam を GitHub Actions で動かすリポジトリ (以下「監査のリポジトリ」) を作るとき・見直すときに、上から順に確かめる。
監査のリポジトリは、ストアへの書き込み・Slack の Webhook (bot トークンの方式ならトークン)・監査対象の読み取りロールへの入口を持つ。守るのは次の 2 つ。

- **main に入れられる人 = 実行用ロールを使える人**。それ以外の経路 (fork、ほかのブランチ、PR) からは使えない
- secrets (Webhook・bot トークン) を読める人を最小にする

LLM が行ってよいのは**読み取りだけ** (`gh api` の GET、ファイルを読む)。設定の変更・ワークフローの追加・secrets の操作は、**人が**判断して行う (LLM は差分や手順を提案する)。
`OWNER` / `REPO` は監査のリポジトリに読み替える。API が 403 / 404 を返す項目は、権限が足りないだけのことが多い。「確かめられなかった」と報告し、問題なしにしない。
手順の全体 (テンプレート、secrets の名前) は arata のリポジトリの `examples/github-actions/README.md`。 監査のリポジトリの一式 (`.github/` のワークフローとスクリプト、`github/` の Terraform、`aws/<アカウント>/` の設定の雛形) は `arata repo init` が書き出したもの (ADR 0059)。生成物 (`.github/`、`github/`、`README.md`、`.gitignore`) は手で直さない。この版の一式と揃っているかは `arata repo init <同じ引数> --diff --format json` で確かめる (何も書かない。`ok` と `files[].status`。スキーマは `arata schema repo-diff`。引数はリポジトリの README.md のコマンド)。揃っていなければ、**人が** `--force` で書き直して PR にする (`aws/<アカウント>/` は書き直されない)。下の設定のうち、非公開・fork の禁止・main のルールセット・Actions の許可・`GITHUB_TOKEN` の既定・environment `audit` は `github/` の Terraform が宣言し、admin を持つ人が手元で当てる (LLM は当てない。当てていない・後から画面で変えた、があり得るので、実際の設定は下の `gh api` で確かめる)。`github/secrets/` は秘密の名前を仮の値で作る Terraform (秘密の箱) で、仮の値のままの秘密を使ったワークフローは `秘密 <名前> が仮の値のまま` と出して止まる (人が environment の secrets に本物の値を入れる)。定時 (`schedule`) は、人が `--schedule --force` で書き直すまで入らない (`arata help ai onboarding`)

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

実行用ロール (`deploy/github-actions/runner.yaml`) は、OIDC トークンが次に完全に一致するときだけ引き受けられる (勧める形。`GitHubEnvironment=audit`):
`sub` = `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:audit` と `ref` = `refs/heads/main`。
environment を使わない構成 (`GitHubEnvironment` が空。非公開のリポジトリで GitHub Free のとき) では、`sub` = `repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main` の 1 つ。

```sh
gh api repos/OWNER/REPO/actions/oidc/customization/sub
aws iam get-role --role-name arata-runner --query 'Role.AssumeRolePolicyDocument'
```

- 1 つ目の応答が `use_default: true`・`use_immutable_subject: true` で、`sub_claim_prefix` が `repo:OWNER@OWNER_ID/REPO@REPO_ID` の形 (ID 入り)。
  `use_immutable_subject` が `false` なら従来の形 (`repo:OWNER/REPO:...`) で、名前だけで決まる。リポジトリや組織を消した後に同じ名前で作り直されると、同じ `sub` になる。
  ID 入りに切り替えるのは人が行い (リポジトリか組織の Actions の OIDC の設定)、切り替えたら `runner.yaml` の `GitHubRepository` も `OWNER@OWNER_ID/REPO@REPO_ID` に変える (揃えないと引き受けに失敗する)
- 信頼ポリシーは `StringEquals` だけで、`aud` = `sts.amazonaws.com`、`sub` = 上の文字列 (`sub_claim_prefix` + `:environment:audit`。environment を使わない構成では `:ref:refs/heads/main`)。`sub` が `:environment:` の形なら、`token.actions.githubusercontent.com:ref` = `refs/heads/main` の条件もあること (environment の `sub` にはブランチが入らない)。
  `StringLike`、`*` を含む `sub`、複数のブランチ、`:pull_request`、`ref` の条件の無い `:environment:` の `sub` があれば人に知らせる
- `sub` に `:environment:audit` と `:ref:refs/heads/main` の 2 つが並んでいたら、移行の期間の許可 (`runner.yaml` の `KeepBranchSubject=true`) が残っている。移行が済んでいるか (ワークフローに `environment: audit` があるか) を確かめ、済んでいれば外すよう人に知らせる
- 引き受けられない理由 (確かめるときの見方):
  - fork は別のリポジトリなので、fork で動くワークフローの `sub` は fork 自身の名前と ID になる
  - 同じ名前で作り直したリポジトリは ID が違う (ID 入りの形のとき)
  - 同じリポジトリでも、ほかのブランチは `ref` が違い、PR のワークフローは `sub` が `...:pull_request` になる
  - environment を参照しないジョブ、別の名前の environment を参照するジョブは `sub` が違う
- ジョブに `environment:` を書くと `sub` が `...:environment:<名前>` に変わる。ワークフローの `environment:` の有無と名前が、信頼ポリシーの `sub` の形と揃っていること (秘密か OIDC を使うジョブは `environment: audit`、PR の検査には無い。名前は式ではなく、そのままの文字列)

## main の保護と書き込み権限

信頼が main に絞られているので (`ref`。environment を使わない構成では `sub`)、main にコミットを入れられる人が、実行用ロールと秘密で動かす内容を決められる。

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

リポジトリの secrets は、どのブランチのワークフローからも読める。書き込み権限のある人 (と、その人のアカウントを乗っ取った人) は、ブランチにワークフローを足して push すれば、main の保護を通らずに読み出せる。勧める形は、秘密を GitHub の environment (`audit`) の secrets に置き、デプロイできるブランチを main だけにすること。

```sh
gh api repos/OWNER/REPO/actions/secrets --jq '[.secrets[].name]'
gh api repos/OWNER/REPO/environments --jq '[.environments[] | {name, deployment_branch_policy}]'
gh api repos/OWNER/REPO/environments/audit/deployment-branch-policies --jq '[.branch_policies[] | {name, type}]'
gh api repos/OWNER/REPO/environments/audit/secrets --jq '[.secrets[].name]'
```

- `audit` の `deployment_branch_policy` が `custom_branch_policies: true` で、ブランチの一覧が `main` だけ。`null` (どのブランチからも使える) や、main のほかのブランチがあれば人に知らせる。environment の secrets は、その environment を参照するジョブにしか渡らず、ほかのブランチのジョブは始まる前に止まる
- 秘密が environment にあり、リポジトリの secrets (1 つ目) が空。同じ名前がリポジトリにも残っていれば、移行の途中か消し忘れ (どのブランチからも読める)
- 覚えのない environment が無い (書き込み権限のある人は、ワークフローで別の名前の environment を作れる。秘密が無く `sub` も違うので使えないが、作った跡)
- environment の設定を変えられるのは admin を持つ人。admin の人数が最小か (`collaborators` の `permissions.admin`) を人に確かめてもらう
- 置いてあるのが、ワークフローが使う 6 つの名前 (`ARATA_RUNNER_ROLE_ARN`、`ARATA_AUDIT_ROLE_ARNS` (アカウントの名前からロールを引く JSON)、`ARATA_ALERT_WEBHOOK`、Slack は Webhook の `ARATAM_SLACK_WEBHOOK`・`ARATAM_SLACK_URGENT_WEBHOOK` か bot トークンの `ARATAM_SLACK_BOT_TOKEN`。使わない送り方の名前は、仮の値の箱のままでよい) だけ。長期の AWS のアクセスキーが無い
- 読み出されて困るのは Webhook と bot トークン (偽の通知を送れる。bot トークンは bot を招待したすべてのチャンネルに送れるので、招待が通知用のチャンネルだけか、Slack アプリの scope が `chat:write` だけかを人に確かめてもらう)。ロールの ARN は読めても、`sub` が合わないので引き受けられない (分かるのはアカウント ID)
- 漏れた疑いがあれば、人が Webhook を作り直す (bot トークンなら取り消して入れ直す)
- environment を使っていない構成 (秘密がリポジトリの secrets、`sub` が `:ref:` の形) なら、守りは「書き込み権限を持つ人を最小に」だけ。environment への移行を勧める (順番は見本の README「既に動いている監査を environment に移す」: environment を作る → スタックを `GitHubEnvironment` と `KeepBranchSubject=true` で更新 → ワークフローに `environment:` を足す → 秘密を移してリポジトリから消す → `KeepBranchSubject=false`)。勧めるときは、非公開のリポジトリでは GitHub の有料プラン (Team など) が要ることを添える。設定を変えるのは人

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

`.github/workflows/` のファイルを読んで確かめる (`arata repo init` が書き出したままなら満たす。`--diff` で揃っているかが分かる)。

- ワークフローの先頭は `permissions: {}`。権限はジョブごとに書き、監査は `id-token: write` と `contents: read` だけ
- `uses:` は 40 桁の commit SHA で固定し、版をコメントに書く
- checkout は `persist-credentials: false`
- `run:` に `${{ }}` の式を埋め込まない (値は `env:` で渡す)
- secrets は、使う step の `env:` か `with:` にだけ渡す。`secrets[...]` で動的に選ばない、`secrets: inherit` を使わない
- Actions のログと artifacts に、ARN・アカウント ID・レポートの本文を出さない
- 手動実行に試しの実行の入力 (`dry_run`) があるなら、次の 3 つを満たす: `dry_run` のときは `aratam notify` を呼ばない、ストアのバケットに何も置かない、
  結果は件数と重大度だけをログに出す (指摘の中身を出さない)。排他の group は定時の実行と分ける (試しの実行が、待っている定時の実行を取り消さないように)

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
