# 0078. `arata repo init --collect-every <間隔>` で、取得だけを短い間隔で回すワークフロー (`arata-collect.yml`) を書き出す。監査と同じ concurrency の group で順に待たせ、失敗は知らせずに daily に追いつかせる

- 日付: 2026-11-21
- 状態: 提案
- 関係する判断: ADR 0059・0060 (`arata repo init` / `repo check`)、0064・0065 (`collect --incremental`、`collect: hourly`)、0034 (S3 ストアの条件付きの書き込み)、
  0068 の 7 節 (`queue: max`)、0014 (暗黙の既定を持たない)、0057 (environment)

## 背景

ADR 0064・0065 で、取得 (`arata collect --incremental`) と判定 (`arata run --profile daily`) を別のタイミングにできるようになった。
取得を 1 時間ごとに回せば、daily はほとんど読み直さずに判定だけになり、1 回の取得が `max_collect` に当たって partial になることも減る。
ADR 0064 の 4 節は、`repo init` の出力にこのワークフローを足すかを「雛形の版で決める」とし、足すなら S3 ストアの衝突を避けるために同じ concurrency の組にする、と書いた。ここで決める。

行き先は「収集は 1 つの間隔で全部。利用者が決めるのは間隔だけ」(設計書 3 章、ADR 0065 の既定にする道筋)。この ADR はワークフローの側でその間隔を決められるようにする一歩。

### 今の事実 (2026-11-21 の main)

- 雛形 (`internal/repoinit/templates/workflows`) に取得だけのワークフローは無い
- `arata-audit.yml` の concurrency は `arata-audit-<アカウント>` (試しの実行は `-dry-run` を付けた別の group)、`cancel-in-progress: false`、`queue: max`。
  片付け (`arata-triage.yml`) も同じ group と `queue: max` (ADR 0068 の 7 節)
- GitHub の concurrency は、既定 (`queue: single`) では group ごとに待ちを 1 つしか持たず、新しい待ちが古い待ちを取り消す。`queue: max` は最大 100 件を待ち始めた順に待たせる。
  `queue` を実際のリポジトリで確かめるのは、ADR 0068 の 7 節でリリースの前の作業に置いた (まだ記録が無い)。actionlint の今の版は `queue` を知らず、その 1 件だけを無視している (`docs/supply-chain.md`)
- S3 のストアにロックは無い。同時に書くと、後から確定した方が `STORE_CONFLICT` (終了コード 2) で失敗し、その回の収集を捨てる (設計書 5-5)
- `arata collect --incremental` は、CloudTrail の種類と `collect: hourly` の cloudwatch-logs だけを集める。どの profile も CloudTrail のソースを使わなければ `CONFIG_INVALID`。
  ソースの失敗か `max_collect` に当たったら終了コード 3 (partial)。失敗した実行は Commit しないので、S3 のストアに記録が残らない
- 1 つの利用者の実測: daily の 1 回 23 分のうち準備 5 秒、`arata run` 23 分 21 秒 (4 日分の追いつき)、aratam 14 秒
- CloudTrail の `ingest_delay` の既定は 15 分、cloudwatch-logs は 5 分。`collect: hourly` は「今 − ingest_delay」を時に切り捨てた所までしか読まない

## 決定

### 1. 引数 `--collect-every <間隔>`。書かなければ今と同じ (書き出さない)

- `arata repo init` と `arata repo check` に `--collect-every` を足す。受け付けるのは **`1h`・`2h`・`3h`・`4h`・`6h`・`8h`・`12h`** (24 時間を割り切る時間) だけ。ほかは形の誤りで、1 つも書かない
- 付けたときだけ `.github/workflows/arata-collect.yml` を書き出す (生成物)。付けなければ書き出さない。既定の間隔は持たない (ADR 0014)
- **`--schedule` と一緒にだけ使える** (無しで渡すとエラー)。取得は定時に意味があり、また導入の流れ (`arata help ai onboarding`) の `arata init` より前にストアへ書かせないため。
  有効にするのは定時と同じ「置く順番の 8」の PR か、その後の `--force` の PR
- README のコマンド (ADR 0059) と `arata-check.yml` の `repo check` の引数に載る (生成物を決める引数なので)。`repo check` の `files` は、この引数で作った一式と比べる。
  引数を外して `--force` で書き直すと、残った `arata-collect.yml` は「この版の一式に無い」(`arata-` で始まるファイル) と出る (今の仕組みのまま)

### 2. cron の作り方

- **分は 25 に固定**する: `1h` は `25 * * * *`、ほかは `25 */N * * *` (N は時間の数)。引数で分は変えない
  - 毎時ちょうどを避ける (GitHub の定時が混み、遅れたり落ちたりする。今の daily と同じ理由)
  - 分が `ingest_delay` の既定 (CloudTrail 15 分) より後なので、前の時が読み終わる (`collect: hourly` は終わっていない時を読まない)
  - daily (`40 0 * * *`) の 15 分前に、どの間隔でも `00:25` の取得が入る (`*/N` は 0 時を含む)。daily は前の 15 分ほどしか読み直さない
  - weekly (`10 1 * * 1`) とも分がずれる
- daily・weekly の時刻は変えない (今の利用者の通知の時刻を動かさない)

### 3. daily とぶつかったとき: 監査と同じ group、`queue: max`

- `arata-collect.yml` の concurrency は **監査と同じ `arata-audit-<アカウント>`、`cancel-in-progress: false`、`queue: max`** にする。matrix はアカウントごと (監査と同じ)
- 同じストアへの書き込みは順番になり、`STORE_CONFLICT` は起きない。待っている daily は取り消されない (`queue: max`)。daily が 23 分かかれば、その間の取得は待ってから動く。
  取得が長引けば daily が待つ。どちらも「遅れる」だけで、捨てない
- 取得が 1 回で終わらないほど溜まっても、待ちは間隔ごとに 1 つずつしか増えない。1 回の取得の時間は `max_collect` で抑える (README で勧める)
- **arata の側で `STORE_CONFLICT` の取り直しはしない** (この ADR では)。同じ group にすれば、ワークフローどうしの衝突は起きない。
  残るのは手元から同じストアに書いたとき (人が `arata ack` を手で流すなど) だけで、取得なら次の回が続きから集める
- 前提: `queue: max` が実際のリポジトリで効くこと (ADR 0068 の 7 節で未確認)。効かなければ、監査と片付けのぶつかりと同じく、取得が待っている daily を取り消し得る。
  この ADR の実装はその確認をリリースの前の作業に含める (下の「確かめていないこと」)

### 4. 取得のワークフローの中身

- step は監査と同じ準備 (checkout・取得と照合・秘密が登録されているか・OIDC・監査ロールのプロファイル) と、`arata collect --incremental -c aws/<アカウント>/arata.yaml` だけ。
  aratam・通知・WAF の提案の保存・試しの実行の入力は持たない。秘密は `ARATA_RUNNER_ROLE_ARN` と `ARATA_AUDIT_ROLE_ARNS` の 2 つだけを使う (Slack のトークンを渡さない)
- `workflow_dispatch` (入力なし) も付ける。止まった後に手で追いつかせるため
- ログは監査と同じ方針 (INFO 以外の `level`・`code`・`source` だけを出す)
- 時間切れは監査と同じ (step 50 分、ジョブ 60 分。認証の期限 1 時間より短く)
- **終了コード 3 (partial) は、警告 (`::warning::`) にしてジョブを成功にする**。`max_collect` に当たるのは追いつきの途中では毎回起き、次の回が続きから集める。
  赤にすると、追いつきの間ずっと赤になり、本当の失敗が埋もれる。0・3 のほかは失敗 (赤)

### 5. 取得が失敗し続けたときの気づき方: Slack には知らせず、daily を見張りにする

- **取得のワークフローは Slack に知らせない** (知らせの step を持たない)。1 時間ごとの一時的な失敗 (呼び出しの制限・通信) で 1 日に何度も鳴らさない
- 取得が失敗しても、集めるはずだったものは失われない。daily はソースの位置から続きを自分で集める (ADR 0064)。取得が止まって失うのは「daily が軽くなる」効果だけ
- 失敗し続けたときに人が気づく道:
  - 原因が daily と共通 (認証・秘密・ストア・バイナリ・設定) なら、daily も失敗し、今の知らせ (aratam の「実行されていない」・知らせのチャンネル) が届く
  - 取得だけが止まって daily の量が戻ると、daily が `max_collect` に当たり `SOURCE_COLLECT_LIMITED` で partial になり、coverage と通知に出る
  - ジョブは赤になり、Actions の画面と GitHub の通知 (利用者の通知の設定による) で見える
- 引き受けること: 取得だけが失敗し、daily が自分で読み切れている間は、Slack には何も出ない (害は「軽くならない」だけなので、受け入れる)

### 6. `repo check`・見本・説明書

- `repo check`: `--collect-every` を引数に取る (`repo init` と同じ形の検査)。項目は足さない (`files` が中身を、`workflow_secrets` が秘密の名前を確かめる。取得のワークフローの秘密は決まった 3 つの部分集合)
- `examples/audit-repo` (出力そのもの): 見本の引数に `--collect-every 1h` を足して作り直す (actionlint・zizmor・actionsgate が取得のワークフローも読む)。
  付けない形は Go のテストで「書き出さない」を固定する
- `examples/github-actions` のテスト: 取得のワークフローの group が監査と同じであること、`queue: max`、`cancel-in-progress: false`、Slack の秘密を参照しないこと、
  cron の分が 25 でどの間隔でも `00:25` を含むこと、終了コード 3 で成功・2 で失敗すること (偽の `arata` で `run:` を動かす)
- 書き出す README と説明書 (`examples/github-actions/README.md`): 有効にする手順 (`--schedule --collect-every 1h --force` の PR)、効くもの (CloudTrail と `collect: hourly` の
  cloudwatch-logs だけ。日の頭から読み直す cloudwatch-logs のソースは daily が読む)、`max_collect` を書くことの勧め、GitHub Actions の時間 (下)、失敗の気づき方 (5 節)
- `arata help ai runtime` に 1 行足す。設計書の該当箇所に「決定:」を足す

### 7. GitHub Actions の時間 (説明書に書く)

- 1 回あたり、準備とストアの読み書きの数十秒に、取得の時間が乗る。課金は 1 回ごとに分へ切り上げる
- `1h` なら、アカウントごとに 1 日 24 回 (少なくとも 24 分)、30 日で少なくとも 720 分。daily の時間は減るが、切り上げと準備の分だけ合計は増える
- 時間を抑えたい利用者は、間隔を長くする (`6h` なら 1 日 4 回)

## 検討した選択肢

- **監査のワークフロー (`arata-audit.yml`) に cron を足し、取得の回か判定の回かを分岐する**: ファイルは 1 つで済むが、通知・提案の保存・試しの実行の step にそれぞれ条件が要り、
  `PROFILE` の式も 3 つの cron を見分ける形に膨らむ。取得の回に Slack のトークンを渡すことにもなる。ファイルを分ける
- **取得を別の group (`arata-collect-<アカウント>`) にし、ぶつかったら `STORE_CONFLICT` に任せる**: 後から確定した方が失敗する。daily は 23 分かかるので、その間に取得が確定すると
  daily が失敗し、その日の判定と通知が「実行されていない」の知らせに置き換わる。取得より daily の方が失うものが大きい (ADR 0068 の 7 節の片付けと同じ理由)
- **同じ group で `queue` を書かない (既定の `queue: single`)**: 取得の待ちが、待っている daily を取り消す。取り消された daily は aratam も走らず、知らせも届かない
- **arata が `STORE_CONFLICT` のとき取り直して再試行する**: 衝突は「開始時の SQLite が古い」ことなので、確定だけをやり直すことはできず、収集から全部やり直すことになる
  (daily なら 23 分をもう一度)。同じ group にすれば、ワークフローどうしでは衝突しない。手元からの書き込みとの衝突は、取得なら次の回で足りる。要ると分かれば足す (足すのは互換)
- **取得の失敗を、毎回 Slack に知らせる** (監査と同じ知らせの step): 1 時間ごとの一時的な失敗で 1 日に何度も鳴り、知らせが読まれなくなる。失敗しても daily が追いつくので、急ぐ理由が無い
- **N 回続けて失敗したら知らせる**: 前の回の結果を知るには Actions の API (`actions: read`) を読む step か、ストアへの記録が要る (失敗した実行は Commit しないので、ストアには残らない)。
  権限と仕組みが増える割に、5 節の道で気づける。次の段の候補にする (下)
- **daily の報告に「取得だけの run の最後の成功」を出す**: arata は利用者が取得を回しているか (どの間隔か) を知らないので、古いかどうかを判断できない。設定に間隔を持たせる形は、
  「利用者が決めるのは収集の間隔だけ」の行き先 (設計書 3 章) で決める
- **分を引数で選ばせる・daily の時刻から計算する**: daily の時刻は固定の文字列で、引数は増やしたくない。25 分なら上の 3 つの条件を全部満たす
- **24 時間を割り切らない間隔 (`5h` など) や `30m` を受け付ける**: cron の `*/N` は 0 時で切り直されるので、割り切らない間隔は日の終わりで間隔がずれ、`00:25` の取得を保証できない。
  1 時間より短い間隔は、`collect: hourly` が終わった時しか読まないので効果が無く、時間だけが増える
- **`--schedule` 無しでも書き出す**: 導入の流れの `arata init` より前に取得がストアへ書く。定時と同じ PR で入れる

## 結果

- 良い点
  - 取得と判定が別のタイミングになり、daily は判定だけに近づく。1 回の取得は間隔の分だけになり、`max_collect` と資格情報の 1 時間の中に収まりやすい
  - daily と取得が同じストアを取り合っても、どちらも捨てずに順に動く
  - 引数を 1 つ足すだけで有効・無効を切り替えられ、書き直しは今の `--force` と PR の差分で済む
- 引き受けるコスト
  - GitHub Actions の時間が増える (7 節)
  - 取得だけが失敗している間は、Slack に何も出ない (5 節)
  - daily が取得の後ろで待つことがある (取得が長引いたとき)。通知の時刻が遅れ得る
  - `queue: max` が実際に効くことに頼る (3 節の前提)
  - ワークフローの準備の step が、監査と取得の 2 つのファイルにある (雛形の中の重複)。テストで 2 つの step の一致を固定する
- **確かめていないこと**: 実際の GitHub では確かめていない (開発では実環境に接続しない)。リリースの前に、開発リードが試しのリポジトリで、
  `queue: max` で取得の待ちが daily を取り消さないこと、cron の `25 */N` が期待の時刻に動くこと、終了コード 3 が警告として見えることを確かめる
- 攻撃の対応表 (ADR 0058): 新しいチェックではないので変えない
- 次の段 (この ADR では決めない): `repo check --github` で、取得のワークフローの直近の実行の結果を読んで (GET だけ) 失敗が続いていれば warn にする。
  `collect: hourly` を既定にしたときに、`collect --incremental` が全部のソースを集めるようにする (ADR 0065 の既定にする道筋)
