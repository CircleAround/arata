# 0057. 実行の仕組みを GitHub の environment に対応させ、見本は秘密を environment に置く (`sub` は environment、ブランチは `ref` で絞る)

- 日付: 2026-11-14
- 状態: 採用 (実際のトークンでの確認は未了。「結果」)
- 置き換える判断: ADR 0040 の「GitHub の environment を使う構成は、このテンプレートの対象外」と、設計書 9 章の「secrets と environment」の決定 (いまは採らない)

## 背景

見本 (`examples/github-actions`) は、秘密 (Slack の Webhook か bot トークン、ロールの ARN) をリポジトリの secrets に置いていた。
リポジトリの secrets は、どのブランチのワークフローからも読める。書き込み権限のある人、またはその人のアカウントを乗っ取った人は、
ブランチにワークフローを足して push すれば、main の保護を通らずに読み出せる。乗っ取ったアカウントでワークフローを書き換え、CI の秘密を持ち出す攻撃は、実際に広く起きている。

GitHub の environment に秘密を置き、デプロイできるブランチを main だけにすれば、ほかのブランチのジョブには秘密が渡らない。
ただし、ジョブに `environment:` を付けると OIDC トークンの `sub` が `repo:<リポジトリ>:environment:<名前>` に変わり、ブランチは `sub` に入らなくなる。
`runner.yaml` の信頼は `sub` = `repo:<リポジトリ>:ref:refs/heads/<ブランチ>` の完全一致だったので、environment を使うジョブは実行用ロールを引き受けられなかった。
見本のジョブは OIDC と秘密を同じジョブで使うので、秘密だけを environment に移すこともできなかった (ADR 0040 は対象外とし、ロードマップに残していた)。

確かめた文書 (2026-11-14):

- GitHub: environment を参照するジョブの `sub` は `repo:ORG/REPO:environment:NAME`。ブランチの形は、environment を参照しないジョブだけ。名前の中の `:` は `%3A` に変わる。
  `ref` のクレームは「ワークフローの実行を起動した git の ref」
- GitHub: 無い environment を参照するワークフローが動くと、同じ名前の environment が、保護も秘密も無い状態で自動で作られる。設定できるのは admin だけ。
  非公開のリポジトリで environment を設定できるのは、有料のプラン (Team、Pro など)
- AWS: GitHub の OIDC の条件キーとして `ref`・`environment`・`job_workflow_ref`・`repository_id` などが使える

## 決定

- **`runner.yaml` に `GitHubEnvironment` を足す** (既定は空)。空なら信頼はこれまでと同じ (ブランチの `sub` の 1 つ)。既にあるスタックは、テンプレートを更新しても信頼が変わらない
- **指定したら、`sub` = `repo:<GitHubRepository>:environment:<GitHubEnvironment>` の完全一致にする**。`AllowedPattern` は英数字・`.`・`_`・`-` だけ
  (ワイルドカード、コロン、`%` を拒む)
- **指定したら、`ref` = `refs/heads/<GitHubBranch>` の条件も足す**。environment の `sub` にはブランチが入らないので、そのままでは実行用ロールの境界が
  GitHub の側の設定 (デプロイできるブランチ) だけになる。この設定は、付け忘れると「すべてのブランチ」のままで、誰も気づかない。admin が外すこともできる。
  AWS の側でも `ref` でブランチに絞れば、設定が無くても、ほかのブランチで起動した実行からは引き受けられない。
  `GitHubBranch` は、environment を使わないときは `sub` に、使うときは `ref` に使う
- **`job_workflow_ref` (`GitHubWorkflowRef`) は任意のまま残し、environment のときにも効かせる**。実行用ロールを使うワークフローが 1 つなら指定を勧める
- **移行の期間は `KeepBranchSubject=true` で作る**。`true` の間は、`sub` に environment の形とブランチの形の 2 つを並べる (`StringEquals` の 1 つのキーに並べた値は OR)。
  スタックを先に更新してからワークフローに `environment:` を足せば、どの時点でも引き受けられる。既定は `false` で、移行が済んだら戻す。
  `ref` の条件は移行の期間にも付く (ブランチの `sub` のジョブも、同じブランチで起動しているので合う)
- **見本は environment (`audit`) を前提にする**。秘密か OIDC を使うジョブ (監査の 2 つ、finding の片付け、Slack への送信のテスト) に `environment: audit` を付ける。
  PR の検査 (`arata-check.yml`) には付けない (秘密も OIDC も使わない。付けると PR のブランチで動けない)。名前は式にせず、文字列でそのまま書く。テストで固定する
- **README に、environment の作り方・確かめ方・移行の順番を書く**。environment はワークフローより先に作る (自動で作られたものは制限が無い)。
  移行は「environment を作り、スタックを `GitHubEnvironment` と `KeepBranchSubject=true` で更新 → ワークフローに `environment:` を足す →
  秘密を environment に移してリポジトリから消す → `KeepBranchSubject=false`」の順
- **environment を使えない構成を残す**。非公開のリポジトリで environment を使えないプランのときは、`GitHubEnvironment` を書かず、写したワークフローから `environment:` の行を消す

## 検討した選択肢

- **environment を指定して `GitHubWorkflowRef` が空なら、スタックを作らせない (CloudFormation の Rules)**: environment の `sub` で失うブランチの条件を、
  `job_workflow_ref` (`…@refs/heads/<ブランチ>`) で必ず補う案。採らなかった理由は 3 つ。
  (1) `GitHubWorkflowRef` は 1 つのファイルしか書けないが、見本は実行用ロールを使うワークフローが 2 つある (監査と finding の片付け)。必須にすると、片付けのワークフローが使えなくなる。
  (2) GitHub の文書は、ふつうのワークフローでの `job_workflow_ref` の値を定めていない (ADR 0040)。必須にすると、文書に無い挙動に定時の監査が依存する。
  (3) ブランチを絞るという目的は、文書に定義のある `ref` で満たせる。ファイルまで絞るかは、これまでどおり利用者が選ぶ
- **`GitHubWorkflowRef` を複数の値にして必須にする**: (1) は解けるが (2) が残る。ワークフローを足すたびにスタックの更新が要る。採らない
- **ブランチの条件を足さず、environment の「デプロイできるブランチ」だけに任せる**: 付け忘れと、設定の変更に気づけない。AWS の側の条件 1 つで防げるので採らない
- **`sub` の組み立てを変える (リポジトリの OIDC の設定の `include_claim_keys` で、environment と ref の両方を `sub` に入れる)**: 条件が `sub` の 1 つで済む。
  ただし、リポジトリの設定を変えることになり、同じリポジトリのトークンを信頼する、ほかのロールの `sub` も変わる。ID 入りの `sub` (2026-07-15 以降の既定) との組み合わせも文書に無い。
  利用者が調べる・変える場所が増える。採らない
- **`sub` を使わず、`repository_id`・`environment`・`ref` の条件キーだけで絞る**: 名前の変更に強いが、ADR 0040 で `sub` の完全一致を選んでおり、形を 2 通り持つことになる。採らない
- **environment の `sub` とブランチの `sub` を常に両方受ける**: 移行は楽だが、environment を参照しない main のワークフローからも引き受けられるままになる。
  environment に絞った意味が薄れるので、移行の期間だけにする
- **移行のために、ロールをもう 1 つ作る**: 信頼を分けられるが、監査対象の読み取り専用ロールの `TrustedPrincipalArn` と allowlist も 2 つになり、移行の後に片付けが要る。
  パラメータ 1 つのほうが手順が短い
- **秘密を使うジョブと OIDC を使うジョブを分け、秘密のジョブにだけ `environment:` を付ける**: 実行用ロールは今のままで済む。ただし、監査の結果 (report) を
  ジョブの間で渡すことになる。Actions の artifacts はリポジトリを読める人に見えるので使わない方針で (README)、渡す手段が無い。採らない
- **見本は environment を使わない形のままにし、environment は「使いたい人向け」に書く**: 既定の形が弱いままになる。見本を写した人が、そのまま強い形になるほうを選ぶ。
  代わりに、使えないプランの人が `environment:` の行を消す手間を引き受ける
- **「Required reviewers」を付ける**: 定時の実行が承認待ちで止まる。監査には合わない。付けない

## 結果

- 良い点: 秘密が main のジョブにだけ渡る。書き込み権限だけでは、秘密も実行用ロールも使えない。実行用ロールのブランチの条件は、environment を使っても AWS の側に残る
- 引き受けるコスト:
  - **秘密の守りは GitHub の側の設定だけ** (デプロイできるブランチ)。付け忘れると、これまでと同じ弱さに戻る。確かめる `gh api` を README と `arata help ai runtime` に書く
  - admin を持つ人は、environment の設定も main の保護も変えられる。admin を最小にすることは、利用者の運用に残る
  - 非公開のリポジトリでは有料のプランが要る。使えない利用者は、写したワークフローから `environment:` の行を消す
  - 手動実行でほかのブランチを選べなくなる (送信のテストを、マージの前のブランチで流せない。手元の `aratam test-notify` で代える)
  - environment を参照するジョブは、実行のたびに GitHub の Deployments に記録が増える
  - 見本を写し直す既存の利用者は、移行の順番を守る必要がある (順番を誤ると、定時の監査が OIDC の引き受けで失敗する)
- **確かめていないこと**: この ADR の時点では、実際のスタックと GitHub のトークンで確かめていない (テストは YAML の形まで。開発では実環境に接続しない)。
  確かめること: environment を参照する main のジョブが引き受けられる。ほかのブランチ・environment なしのジョブが引き受けられない。
  ID 入りの `sub` と environment の組 (`repo:owner@ID/repo@ID:environment:<名前>`。文書に例が無い)。environment の名前の大文字・小文字が `sub` にそのまま入るか。
  移行の期間の `sub` の 2 つの値。ロードマップに残す
