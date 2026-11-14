# GitHub を収集元にする (検討中の設計メモ)

- 状態: **検討中。決めたら ADR を起こす。** ここに書いた「案」は、どれもまだ決めていない
- 調べた日: 2026-11-14 (GitHub の公式文書と公開の分析を読んだ。文書に無いことは「文書に記述なし」、読めなかったことは「未確認」と書く)
- きっかけ: 乗っ取った GitHub のアカウントでワークフローを足し・書き換え、CI の秘密を持ち出す攻撃
  (`arata help ai threats ghostaction-2026-10`、`arata help ai threats wfx-loot-2026-11`)。
  今の arata は AWS の記録だけを読むので、攻撃の GitHub の中の段階は見えない

## 1. 事実

### 1-1. 監査ログはプランで読める範囲が違う

| | Free / Team | Enterprise Cloud |
|---|---|---|
| 画面 | 見られる。org の owner だけ。直近 180 日 (既定の表示は 3 か月) [A] | 同じ [B] |
| JSON / CSV の書き出し | 画面から書き出せる (上限は圧縮で 100 MB か処理 10 分) [A] | 同じ。Git のイベントは JSON だけ [B] |
| REST / GraphQL | **使えない**。文書は「Organizations that use GitHub Enterprise Cloud can interact with the audit log using the GraphQL API and REST API.」とだけ書く [A] | 使える。owner だけ。classic のトークンは `read:audit_log`。1 時間 1,750 回 (利用者と IP ごと) [C] |
| streaming | 文書に記述なし | enterprise の単位で設定する [D] |
| Git のイベント (`git.push` など) | 文書に記述なし | 画面に出ない。API・書き出し・streaming で、保持は 7 日 [B][E] |
| ワークフローの実行 (`workflows.created_workflow_run` など) | 事象の説明は「画面に出ず、REST・streaming・JSON/CSV の書き出しだけ」[E]。**Free / Team の書き出しに入るかは未確認** | 書き出し・REST・streaming で取れる。`workflows.prepared_workflow_job` は、ジョブに渡した secrets の一覧を含む [B] |
| IP | 文書に記述なし | 表示は設定で有効にする (公開プレビュー) [F] |

- Free / Team の org で `GET /orgs/{org}/audit-log` を呼ぶと 404 が返り、`documentation_url` は Enterprise Cloud の版の文書を指す (`read:audit_log` を持たないトークンで確かめた。
  404 の理由がプランかスコープかは応答だけでは分けられないが、文書 [A] が Team の API を否定している)
- fine-grained PAT や GitHub App で監査ログを読めるかは、文書に記述なし。fine-grained の org の権限の一覧に、監査ログの項目は見当たらない [M]
- **Free / Team では、監査ログを機械で定期に読む手段が無い。** owner が手で書き出せば 180 日分は取れる

### 1-2. 監査ログの代わりに読めるもの

権限は fine-grained の権限の対応表 [G] から。レート制限: PAT は 1 時間 5,000、GitHub App の installation は 5,000〜12,500 (Enterprise Cloud は 15,000)、
Actions の `GITHUB_TOKEN` は 1 リポジトリにつき 1 時間 1,000 [H]。GET は 1 回 1 点で、1 分 900 点・同時 100 まで (二次の制限) [H]。

| 情報 | エンドポイント | 取れる項目 | 権限 | 保持 |
|---|---|---|---|---|
| ワークフローの実行 | `GET /repos/{owner}/{repo}/actions/runs` | `head_branch`・`head_sha`・`event`・`path`・`actor`・`triggering_actor`・`run_number`・`run_attempt`・`created_at`・`conclusion` [I] | Actions: read | **既定 90 日**。公開のリポジトリは 1〜90 日、非公開は 1〜400 日で設定できる。2026-10-01 から、実行の記録にもこの期間が効く [J]。絞り込みの検索は 1,000 件まで [I] |
| ジョブとログ | `.../actions/runs/{run_id}/jobs`、`.../actions/jobs/{job_id}/logs` | ステップ名・ランナー。ログは 1 分で切れる URL で返る [I] | Actions: read | 同上 |
| ワークフローの一覧 | `GET /repos/{owner}/{repo}/actions/workflows` | `path`・`name`・`state`・`created_at`・`updated_at` [I] | Actions: read | — |
| リポジトリの activity | `GET /repos/{owner}/{repo}/activity` | `activity_type` (push・force_push・branch_creation・branch_deletion・pr_merge・merge_queue_merge)・`ref`・`before`・`after`・`actor`・`timestamp` [K] | 文書に記述なし (classic の `repo` で読めた) | 文書に記述なし (`time_period` の最長は year) |
| イベント | `GET /repos/{owner}/{repo}/events`、`GET /orgs/{org}/events` | PushEvent の payload は `ref`・`head`・`before` など (コミットの一覧は無い) [L] | 文書に記述なし | **30 日・300 件まで。遅れは 30 秒〜6 時間** [L] |
| コミット | `GET /repos/{owner}/{repo}/commits?path=...` | ファイルごとの変更の履歴、署名の検証 | 文書で確かめていない (Contents: read と思われる) | 履歴がある限り |
| ruleset | `GET /repos/{owner}/{repo}/rulesets`、`.../rules/branches/{branch}` | ruleset の中身、枝に効くルール | Metadata: read | — |
| environment | `GET /repos/{owner}/{repo}/environments` | 名前・保護・デプロイできる枝 | 文書で確かめていない (Environments: read / Actions: read) | — |
| secrets の名前 | `GET .../actions/secrets`、`.../environments/{name}/secrets`、`GET /orgs/{org}/actions/secrets` | `name`・`created_at`・`updated_at` (値は返らない) | Secrets: read / Environments: read。org の一覧は classic で `admin:org` | — |
| org の Actions の設定 | `GET /orgs/{org}/actions/permissions`、`.../permissions/workflow` | 許す action、`GITHUB_TOKEN` の既定の権限 | org の admin か「actions policies」の権限 (`read:org` では 403) | — |
| Dependabot のアラート | `GET .../dependabot/alerts`、org 版 | 状態・パッケージ・却下した人 (API は公開プレビュー) | Dependabot alerts: read | — |
| secret scanning のアラート | `GET .../secret-scanning/alerts`、org 版 | push protection の回避も含む | Secret scanning alerts: read。リポジトリか org の admin | — |
| Issue と PR | `GET .../issues?state=all` | 両方を返す (PR は `pull_request` のキーで分かる) [N] | Issues: read / Pull requests: read | — |
| webhook | org・リポジトリの webhook | push・create・delete など | 受け取るサーバーが要る | — |

- 中心になるのは「ワークフローの実行」「ワークフローの一覧」「activity」の 3 つ。前の 2 つは Actions: read だけで読める
- 実行の記録は 90 日、イベントは 30 日・300 件で消える。**arata が定期に集めてストアに残す前提になる** (CloudTrail と同じ扱い)
- ワークフローの**中身**を読むには Contents: read が要る。Contents: read はソースコードも全部読める権限になる
- 監査ログでしか取れないもの: secrets の利用 (`prepared_workflow_job`)、トークンの種類と利用者、IP、実行の削除 (`workflows.delete_workflow_run`)

### 1-3. 認証の方法

| 方法 | 読める範囲 | 期限 | 長く持つ秘密 | 備考 |
|---|---|---|---|---|
| Actions の `GITHUB_TOKEN` | **そのワークフローのリポジトリだけ** [O] | ジョブの終わりまで (GitHub のランナーでは最長 6 時間) [O] | 無し | org の権限は無い。文書は、足りなければ GitHub App の installation token を作るよう案内する [P] |
| GitHub App の installation token | App をインストールしたリポジトリ。トークンを作るときに、リポジトリ (`repositories`) と権限 (`permissions`) をさらに絞れる [Q] | **1 時間** [Q] | App の秘密鍵 (JWT を作るのに使う) | 人に紐づかない |
| fine-grained PAT | 持ち主 (resource owner) に org を選び、リポジトリを選べる [M] | org の上限は既定で 366 日 [S] | トークンそのもの | **既定で org の owner の承認が要る** [S]。作った人に紐づく。1 人 50 個まで [M] |
| classic PAT | 作った人が見える全部の org の、全部のリポジトリ [M] | 期限は任意 [S] | トークンそのもの | 承認の対象外。org で禁止できる [S] |

**同じ org の中だから使える融通は、文書に無い。**

- `GITHUB_TOKEN` は、同じ org でもほかのリポジトリを読めない [O]
- private の action や再利用のワークフローを org の中で共有する設定は、それを**使わせる**だけで、API で読む権限にはならない (文書に API の記述が無い) [T]
- internal のリポジトリは、Enterprise Cloud で enterprise が持つ org だけ [U]
- Actions の OIDC のトークンを GitHub の API のトークンに換える方法は、文書に無い (文書にあるのはクラウド事業者のトークンとの交換だけ) [V]

**→ 長く持つ秘密なしで、同じ org のほかのリポジトリを読む方法は、文書に無い。** 最も小さくしても、GitHub App の秘密鍵が 1 つ要る。

GitHub App について (開発リードが確かめた):

- private の App は、App を持つ account にしかインストールできない。public の App は、誰でもインストールできる [W]
- REST API でも Terraform でも、App は作れない。Terraform の `integrations/github` 6.13.0 で App に関係する resource は
  `github_app_installation_repository` と `github_app_installation_repositories` だけ (`terraform providers schema` で確かめた)
- manifest の仕組みで半自動にできる。ただし、人がブラウザで「Create GitHub App」を 1 回押す操作が要る。
  コードを交換すると、`id`・`pem` (秘密鍵)・`webhook_secret`・`client_secret` が返る。3 つの手順を 1 時間以内に終える必要がある [X]

### 1-4. 攻撃の痕跡

公開の分析が書く形は、事例の本文 (`arata help ai threats ghostaction-2026-10` / `wfx-loot-2026-11` の「概要」) にまとめた。この節では、検知の設計に効く点だけを挙げる。

- GhostAction は、監査を装った名前のワークフロー (`security-audit.yml` の `Security Audit` など) を、既定の枝へ PR なしで push する。名前は正規の監査のワークフローとぶつかり得る
- wfx-loot は 1 分以内に戻し、実行とログを消す。Aikido は「ワークフローの実行の番号の欠けが唯一の痕跡になることが多い」と書く
- **どの分析にも、PR や Issue の番号が飛んだという報告は無い**

PR と Issue の番号について (1-5 の判断の材料):

- Issue と PR が同じ連番だとは、文書に書いていない。文書は「PR は Issue の一種」「Issues の API は PR も返す」とだけ書く [N]
- `GET /repos/{owner}/{repo}/issues/{issue_number}` は、移した Issue に 301、読めるリポジトリで消した Issue に 410、読めないリポジトリへ移したか消したものに 404 を返す [N]。誰が消したかは API に出ない
- Issue を消せるのは、リポジトリの admin か org の owner。org では、owner が Issue の削除を許している場合だけ。誰がいつ消したかは画面で admin に見える [Y]
- PR を消せるかは文書に記述なし。Discussions の番号、spam の削除、凍結されたアカウントの内容の扱いは未確認

## 2. 案 (想定する方向性。まだ決めていない)

### 2-1. 認証: 会社の org ごとに private な App を作り、全リポジトリに入れる

- 権限は **Actions: read と Metadata: read だけ**。Contents: read は付けない
- 理由:
  - org ごとに App を分け、鍵 1 つで全社を読める状態を作らない
  - 読むリポジトリを選ぶ形にすると、新しく作ったリポジトリが監視から漏れる
  - 権限が小さいので、全リポジトリに入れても、鍵が漏れたときの被害は小さい (ソースコードも secrets の値も読めない)
- この鍵は、GhostAction の型の攻撃で最も狙われる秘密になる。監査を回すリポジトリの environment (main だけ。ADR 0057) に置く
- App の作成は人のブラウザの操作が要る (1-3)。`arata repo init` で一式を書き出すなら、manifest で半自動にする手順になる

### 2-2. 収集とストア

- 集めるところは AWS と GitHub で分け、ストアは共通にする。「アプリ単位」という仕組みは作らない
- 両者は、実行の ID (CloudTrail の `userAgent` の `run_id`。ADR 0055 で既に残している) とリポジトリの名前で突き合わせる
- 設定に GitHub の収集元の節が要る。coverage (どこまで読めたか) も収集元ごとに出す
- レポートに個人を特定できる値を書かない規則がある。GitHub の利用者のログイン名をどう表すか (数値の ID にするなど) を決める必要がある

### 2-3. 最初に作るチェックの候補

| 候補 | 何を見るか | 材料 |
|---|---|---|
| 消えた実行 | AWS に OIDC で入った記録があるのに、GitHub にその実行が無い | CloudTrail の `run_id` + 実行の履歴 |
| 承認していないワークフロー | 既知リストに無いワークフローのファイルが現れた、または実行された | ワークフローの一覧・実行の履歴 |
| 実行の番号の途中の欠け | 同じワークフローの `run_number` の途中が欠けた (保持期間で消えるのは古い側から) | 実行の履歴 |

- 「消えた実行」は、AWS と GitHub の両方を読む arata ならではの突き合わせになる。ただし `run_id` は呼ぶ側が書ける値 (ADR 0055)。
  食い違いは手がかりで、偽の値を書いた呼び出しも「GitHub に無い実行」として出る
- 「workflow の変更と secrets の利用が同時」は、secrets の利用が監査ログにしか無いので、Free / Team では作れない

### 2-4. 攻撃の痕跡の一覧は補助として持つ

- 設定の一部にし、項目ごとに期限 (`expires`) と出典 (URL と日付) を必須にする。組み込みの既定にはしない (ADR 0014)
- 期限が切れた項目は照合せず、`config check` / `doctor` で warn にする (既知リストの期限切れと同じ扱い)
- arata はネットから一覧を取りに行かない。更新は人が PR で行う
- 名前の一致だけで重い重大度にしない (正規の監査のワークフローと名前がぶつかる)。2-3 の一般の検知と重なったときに重大度を上げる
- 痕跡の一覧には、公開の分析が書いた値だけを使う。顧客の情報は入らない

### 2-5. PR 番号の欠けは作らない

- どの分析にも報告が無い。GhostAction は PR を使わずに push し、wfx-loot の下調べの PR は開いたまま残る
- Issue を消せるのは、削除を許した org の admin / owner だけ。乗っ取られた書き込み権限のアカウントでは起こせない
- 欠けの理由 (削除・移動・権限) は API の状態コードで分けられるが、誰が消したかは取れない
- 同じ「番号の欠け」でも、ワークフローの実行の番号の欠け (2-3) のほうが、報告のある手口に当たる

## 3. 決めていない点と、決める順番

1. **守りの棚卸しを先にする**: 各リポジトリに ruleset があるか、secrets を持つか (1-2 の ruleset と secrets の名前の一覧は Metadata: read と Secrets: read で読める)。
   その結果を見て、どのリポジトリを優先して見るかを決める
2. **優先度**: 進めている導入の作業と、利用者ごとのチェックの後
3. GitHub を収集元に足すこと自体 (AWS の外を読む。ADR を起こす)
4. 認証の方式 (2-1 の App か、fine-grained PAT か) と、Contents: read を付けるか
5. 読むリポジトリの範囲 (全部か、選んだものか)
6. 監査ログの書き出しを 1 度試し、Free / Team の書き出しにワークフローの実行の事象が入るかを確かめるか。Enterprise Cloud の価値をどう見るか
7. レポートでの GitHub の利用者の表し方

### 価値の見積もり

- **今は、AWS の外で secrets が使われると見えない。** GitHub の secrets に置いた Slack やパッケージの公開用のトークンが盗まれても、AWS の記録には何も残らない
- **突き合わせは arata ならではになる。** AWS の記録 (OIDC の引き受け) と GitHub の実行の履歴を両方読めば、「GitHub から消えた実行」が見える。どちらか一方だけを読む道具にはできない
- **防ぐ設定が先に効く。** environment で secrets を main に限る (ADR 0057)、ruleset でワークフローの変更に PR を要る形にする、実行に承認を要る形にする。
  検知は、それをすり抜けたもの・付け忘れを見つける役になる。だから 3 の 1 の棚卸しを先にする

## 出典 (2026-11-14 に読んだ)

- [A] https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization
- [B] https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization (「Audit log data available by access method」の表)
- [C] https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization
- [D] https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise
- [E] https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
- [F] https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/displaying-ip-addresses-in-the-audit-log-for-your-organization
- [G] https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens
- [H] https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
- [I] https://docs.github.com/en/rest/actions/workflow-runs 、https://docs.github.com/en/rest/actions/workflows 、https://docs.github.com/en/rest/actions/workflow-jobs
- [J] https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization
- [K] https://docs.github.com/en/rest/repos/repos (List repository activities)
- [L] https://docs.github.com/en/rest/activity/events
- [M] https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- [N] https://docs.github.com/en/rest/issues/issues#get-an-issue 、https://docs.github.com/en/rest/pulls/pulls
- [O] https://docs.github.com/en/actions/concepts/security/github_token
- [P] https://docs.github.com/en/actions/tutorials/authenticate-with-github_token
- [Q] https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
- [S] https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization
- [T] https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-access-to-components-in-a-private-repository
- [U] https://docs.github.com/en/repositories/creating-and-managing-repositories/about-repositories
- [V] https://docs.github.com/en/actions/concepts/security/openid-connect
- [W] https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/making-a-github-app-public-or-private
- [X] https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
- [Y] https://docs.github.com/en/issues/tracking-your-work-with-issues/administering-issues/deleting-an-issue
- 公開の分析は、事例の本文の「出典」(GitGuardian・StepSecurity・Aikido)
