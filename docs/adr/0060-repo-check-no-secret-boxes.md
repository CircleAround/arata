# 0060. 秘密の箱をやめ、通知の方法は `arata repo init` で決め、足りない秘密は `arata repo check` が登録のコマンドと一緒に出す

- 日付: 2026-11-14
- 状態: 採用 (実装は次の PR。実際の GitHub では確かめていない。「結果」)
- 関係する判断: ADR 0059 (この ADR が「秘密の箱」と、送り方を実行のときに判別する形を置き換える。ほかの決定はそのまま)、
  0014 (暗黙の既定を持たない)、0044 (aratam の秘密は環境変数)、0054 (機械が読む出力)、0057 (environment)、0041 (ファズ)

## 背景

ADR 0059 の一式は、秘密の「箱」を `github/secrets/` の Terraform で作る。ワークフローが使う 6 つの名前を、environment に**仮の値**で作り、
人が画面で本物の値に入れ替える。実装 (#103) の後に、利用者と見直した。

- **仮の値が残る**。使わない送り方の箱 (Webhook で送る利用者の bot トークンの箱など) は、仮の値のまま残り続ける。
  environment の秘密の一覧を見ても、どれが本物でどれが仮かは分からない (GitHub は値を返さない)。秘密の管理が煩雑になる
- **上書きの危険が残る**。箱の作成は GitHub の「作るか上書きする」API で、計画 (plan) と apply の間に入った本物の値を仮の値で置き換え得る (ADR 0059 の「引き受けるコスト」)
- **使わない箱のための仕組みが増える**。仮の値を見分けるスクリプト (`arata-secret-check.sh`)、使わない箱の警告、別の root、CI の偽の API への apply。
  どれも「箱を作る」ことから生まれている
- **送り方が、実行のときまで決まらない**。ワークフローは 3 つの Slack の秘密を全部参照し、実行のたびに `aratam.yaml` を読んで渡すものを選ぶ (`arata-slack-method.sh`)。
  ワークフローを読んでも、このリポジトリがどの秘密を使うのかは分からず、「要る秘密の一覧」を機械で出せない

ADR 0059 は「箱を作らず、足りない名前を出力するだけにする」を、「名前の打ち間違いは定時の失敗まで分からない」として採らなかった。
足りない名前と余った名前を、**定時の前に、読み取りだけで確かめる道具**があれば、この理由は無くなる。ADR 0059 が次の段に置いた `arata repo check` を、ここで決める。

ADR 0059 の一式は、まだどのリリースにも入っていない (最新のリリースは、その実装より前)。リリースされた版からの移行は要らない。

## 決定

**最初は、秘密は 1 つも登録されていない。`arata repo check --github` を流すと、足りない秘密の名前と、そのまま打てる登録のコマンドが出る。**
arata は秘密の値を受け取らず、GitHub にも書かない。

### 1. 通知の方法は `arata repo init` で決める

一式を書き出すときに、次の 3 つを決める。**既定値は持たない** (ADR 0014)。

| 引数 | 決めること | 受け付ける形 |
|---|---|---|
| `--notify <アカウント>=webhook\|bot` (カンマ区切り。例 `prod=webhook,staging=bot`) | アカウントごとの Slack への送り方 | `--accounts` の全部の名前に、1 つずつ。足りない・余る・重複は拒む |
| `--urgent-webhook yes\|no` | 緊急用の Webhook を、通常用と分けるか (`no` なら、緊急の通知は通常用にメンション付きで送る) | Webhook で送るアカウントが 1 つでもあれば必須。1 つも無いのに書けばエラー |
| `--alert-webhook yes\|no` | 定時の通知が送れなかったことを知らせる、別の Webhook (`ARATA_ALERT_WEBHOOK`) を使うか | 必須 |
| `--channel <アカウント>=<チャンネル ID>` (カンマ区切り) | bot で送るアカウントの、通常用のチャンネル ID | `aratam.yaml` を**新しく作る** bot のアカウントに必須。形は aratam と同じ (`C0123456789`)。下の「チャンネル ID」 |

- 真偽の 2 つは、付ける・付けないのフラグにしない。付けないことが「使わない」と「決めていない」のどちらなのかを、区別できないため
- **端末 (TTY) から打って、上の引数が足りないときだけ、対話で聞く**。聞くのは上の 4 つだけ (ほかの引数は、これまでどおり足りなければエラー)。
  答えは引数と同じ形で確かめ、通らなければ聞き直す。最後に、答えを引数にした同じコマンドを出す (README にも載る。次からは対話なしで打てる)
- **端末でなく、引数が足りなければ、`CONFIG_INVALID` (終了コード 2) で止める**。足りない引数の名前を出す。CI や LLM が、黙って既定で進まない
- 端末かどうかの判定は、標準入力を見る。標準ライブラリだけで書き、依存を足さない。`/dev/null` を端末と見誤らないことをテストで固定する。
  テストは、判定と入力を差し替える (実際の端末は使わない)
- 緊急用の Webhook を分けるかは、**リポジトリで 1 つ**に決める (アカウントごとには変えない)。1 つのリポジトリ = 1 つの会社が勧める形で、緊急の通知の行き先は会社で 1 つ。
  秘密も `ARATAM_SLACK_URGENT_WEBHOOK` の 1 つしか無い
- README に載せるコマンド (ADR 0059) に、`--notify`・`--urgent-webhook`・`--alert-webhook` を入れる。`--channel` は入れない (下)

### 2. ワークフローは、決めた組み合わせだけを書き出す

- **使わない秘密は、ワークフローに 1 文字も出てこない**。全部のアカウントが Webhook なら、`ARATAM_SLACK_BOT_TOKEN` の行は無い。
  `--alert-webhook no` なら、別の経路で知らせる step ごと無い
- アカウントごとに送り方が違うときは、その秘密を渡すアカウントの名前を、ワークフローの式に書く
  (例 `contains(fromJSON('["prod"]'), matrix.account) && secrets.ARATAM_SLACK_WEBHOOK || ''`)。全部のアカウントが同じ送り方なら、素の `secrets.ARATAM_SLACK_WEBHOOK` になる。
  アカウントの名前は形で絞ってあり (小文字の英数字とハイフン)、式の中の JSON にそのまま入れられる
- **送り方を実行のときに判別するのをやめる**。`.github/scripts/arata-slack-method.sh` は消す。`aratam.yaml` とワークフローが合っていることは、
  PR の検査の `arata repo check` が確かめる (下の 4)。合わないままマージされても、aratam は要る環境変数が空なので `CONFIG_INVALID` で止まり、別の経路の知らせ (使う設定なら) が届く
- **仮の値の検査をやめる**。`.github/scripts/arata-secret-check.sh` は消す (`.github/scripts/` は空になり、書き出さない)。
  代わりに、必ず使う 2 つ (`ARATA_RUNNER_ROLE_ARN`・`ARATA_AUDIT_ROLE_ARNS`) が**空 (未登録) なら、名前と「手元で `arata repo check --github`」を出して止める**小さな step を置く。
  Slack の秘密が空のときは aratam が、`ARATA_ALERT_WEBHOOK` が空のときは知らせる step が、これまでどおり止める
- 組み合わせの差し込みは、これまでと同じ「決まった印を、Go が選んだ断片で置き換える」だけ (定時の有無と同じ形)。条件や繰り返しを持つテンプレートの言語は使わない (ADR 0059)
- 新しく作る `aws/<アカウント>/aratam.yaml` は、そのアカウントの送り方で書く (Webhook: `webhook_env` と、分けるなら `urgent_webhook_env`。bot: `bot_token_env` と `channel`)。
  環境変数の名前は、秘密の名前と同じ決まった名前にする

### 3. 秘密の箱 (`github/secrets/`) をやめる

- **Terraform は environment と、デプロイできるブランチまで**。秘密のリソースも data source も持たない。`github/` の中身は ADR 0059 のまま
- 書き出しから `github/secrets/` を外す。CI の Terraform のテストから、秘密の部分 (偽の GitHub API への apply で「既にある秘密に書かない」を確かめる部分) を外す。
  `github/` の fmt・validate・偽の API への apply は残す
- `github/secrets/` が残っているリポジトリでは、`arata repo check` が「この版の一式に無い」と出す。ディレクトリを (手元の state ごと) 消せばよい。
  登録済みの秘密には何も起きない (Terraform は、消されたディレクトリのリソースに触れない)

### 4. `arata repo check`

名前は `arata repo check` にする (`config init` / `config check` と同じ並び。ADR 0059 が次の段に置いた名前)。
引数は `repo init` と同じものを取り (README のコマンドの `init` を `check` に替えれば打てる。`--out` は検査するディレクトリ)、何も書かない。

**出力**は `arata doctor` と同じ形にする。1 項目 1 行で、状態は `ok` / `warn` / `ng` / `skip`。`--format table` (人向け) と `--format json` (機械向け。スキーマ `repo-check` を
型から作り、`schematest` で固定する。ADR 0054)。**終了コードは、`ng` があれば 2、`warn` だけなら 0** (doctor と同じ)。`ng` の行には `code` を付ける (`internal/codes` に足す)。

**ファイルの検査** (いつも行う。手元のファイルだけを読み、秘密も GitHub も要らない)

| 項目 | 見ること | 合わないとき |
|---|---|---|
| `files` | 生成物の 1 つずつが、この版・この引数の一式と同じか。一式に無い残りもの (`.github/` の `arata-` で始まるファイル、`github/` と `github/secrets/` の `.tf`) が無いか。`repo init --diff` と同じ比べ方 | ng。直し方は `arata repo init … --force` |
| `terraform` | `github/` の `.tf` と lock が、この版の形と同じか (上の `files` のうち、GitHub の設定に効くものを、別の項目として出す) | ng |
| `workflow_secrets` | `.github/workflows/arata-*.yml` が参照する秘密の名前 (`secrets.<名前>`) の集まりが、引数から決まる「要る秘密」と同じか。名前を式で作る参照 (`secrets[…]`) が無いか | ng |
| `notify` (アカウントごと) | `aws/<アカウント>/aratam.yaml` が使う環境変数の名前 (`slack.webhook_env`・`urgent_webhook_env`・`bot_token_env`) が、そのアカウントにワークフローが渡す秘密の名前と、過不足なく同じか | ng。`aratam.yaml` の `slack` の節に書く行を、そのまま貼れる形で出す (下の 6) |
| `accounts` | `aws/<アカウント>/` の `arata.yaml` と `aratam.yaml` があるか (中身の形は `config check` の役目) | ng |

- `aratam.yaml` は arata が自分で読む (上の 3 つの項目だけ)。arata を aratam の通知のパッケージにつながない (ADR 0018・0059)。
  「aratam が判別する送り方と、arata が読んだ結果が同じ」ことは、テストで固定する
- `repo init --diff` は、そのまま残す (終了コード 1 と `repo-diff` のスキーマは変えない。消すのは互換を壊す)

**GitHub の検査** (`--github` を付けたときだけ。付けなければ `skip` の 1 行)

- 読むだけ。呼ぶのは GET だけで、テストが固定する。認証は環境変数 **`GITHUB_TOKEN` (無ければ `GH_TOKEN`)** で受け取る。
  `gh` の認証を使うときは `GITHUB_TOKEN="$(gh auth token)" arata repo check … --github` と打つ (`github/` を当てるときと同じ形)。arata は `gh` を起動しない
  (外の実行ファイルを呼ぶ経路を増やさない。テストが PATH の本物を起動する事故の余地も作らない)
- 向き先は `https://api.github.com` に固定する (環境変数では変えない。鍵を別のホストへ送らせない)。リダイレクトは追わない。GitHub Enterprise Server は対象にしない
- **GitHub は秘密の名前と更新日時しか返さない。値は読めないし、読まない**

| 項目 | 見ること | 状態 |
|---|---|---|
| `environment` | environment `audit` があるか | 無ければ ng |
| `deployment_branches` | デプロイできるブランチが、既定のブランチ 1 つだけか | 「すべてのブランチ」・「保護されたブランチ」・ほかのブランチやタグがある → ng |
| `environment_protection` | レビュー担当・待ち時間が付いていないか (定時が止まる。ADR 0057) | 付いていれば warn |
| `secret` (名前ごと) | 要る秘密が、environment にあるか | 無ければ ng (登録のコマンドを出す) |
| `secret_unused` (名前ごと) | environment に、この一式が使わない名前が残っていないか | warn (消すコマンドを出す) |
| `repository_secret` (名前ごと) | リポジトリの (environment でない) 秘密が残っていないか | この一式の 6 つの名前のどれか → ng (どのブランチのジョブにも渡り、environment の守りを抜ける)。ほかの名前 → warn |

- API の失敗 (認証が無い・権限が足りない・リポジトリが無い) は、その項目を ng にして code を付ける。応答の本文は出さない
- GitHub の応答は信用しない入力として読む。大きさとページの数に上限を置き、名前は秘密の名前の形 (英大文字・数字・`_`) のものだけを出力に運ぶ。ファズテストで固定する (ADR 0041)。
  ワークフローの YAML から秘密の名前を拾う箇所と、`aratam.yaml` を読む箇所も同じ

### 5. 足りない秘密の出し方

`secret` が ng の名前ごとに、**そのまま打てるコマンド**と、値の形・取りに行く場所を 1 行ずつ出す。JSON では `missing_secrets` に同じものを持つ。

```
gh secret set ARATA_RUNNER_ROLE_ARN --env audit -R example-org/security-audit
  値の形: arn:aws:iam::123456789012:role/arata-runner   取得元: runner.yaml のスタックの出力 RunnerRoleArn
```

| 名前 | 要るとき | 値の形 | 取得元 |
|---|---|---|---|
| `ARATA_RUNNER_ROLE_ARN` | いつも | `arn:aws:iam::123456789012:role/…` | `runner.yaml` のスタックの出力 `RunnerRoleArn` |
| `ARATA_AUDIT_ROLE_ARNS` | いつも | `{"prod": "arn:aws:iam::…:role/…", …}` (アカウントの名前から引く JSON。名前は実際の `--accounts`) | `readonly-role.yaml` のスタックの出力 (アカウントごと) |
| `ARATAM_SLACK_WEBHOOK` | Webhook のアカウントがある | `https://hooks.slack.com/services/…` | Slack アプリの Incoming Webhooks (通常用のチャンネル) |
| `ARATAM_SLACK_URGENT_WEBHOOK` | `--urgent-webhook yes` | 同上 | 同上 (緊急用のチャンネル) |
| `ARATAM_SLACK_BOT_TOKEN` | bot のアカウントがある | `xoxb-…` | Slack アプリ (`deploy/slack/app-manifest.yaml`) の Bot User OAuth Token |
| `ARATA_ALERT_WEBHOOK` | `--alert-webhook yes` | `https://hooks.slack.com/services/…` か、`{"text": "…"}` を受け取る URL | 定時の通知とは別のチャンネルの Webhook |

- コマンドは値を引数に取らない形にする。`gh secret set` は値を端末で聞くので、値がシェルの履歴に残らない
- コマンドに入る組織・リポジトリ・秘密の名前は、どれも形で絞った値だけ (引数と、決まった名前の一覧)。GitHub の応答から来た文字列は入れない
- `secret_unused` には `gh secret delete <名前> --env audit -R <owner>/<repo>` を出す (名前は、形を確かめたもの)
- **arata は秘密を登録しない**。値を受け取る経路と、書き込みのできる鍵を、arata に持たせない

### 6. 送り方を後から変える

例: 最初は `prod=webhook` で始め、後から bot に変える。

1. `arata repo init … --notify prod=bot … --force` を流す (README のコマンドの `--notify` を直す。端末なら、足りないものは聞かれる)。
   書き直るのは生成物だけ (ワークフローと README)。**`aws/prod/aratam.yaml` は書き直さない**
2. `repo init` は、書き出しの最後にファイルの検査の `notify` を流し、合わないアカウントを ng で出す。出るのは、`slack` の節に書く行そのもの:

   ```
   ng  notify  prod  aws/prod/aratam.yaml の送り方が、ワークフローと合わない (ワークフロー: bot / aratam.yaml: webhook)
       aws/prod/aratam.yaml の slack の節を、次の行にする:
         webhook_env: ""
         urgent_webhook_env: ""
         bot_token_env: ARATAM_SLACK_BOT_TOKEN
         channel: "C0123456789"
   ```

   チャンネル ID は、`--channel prod=C0123456789` を渡したとき (端末なら、聞かれて答えたとき) は、その値で出す。渡していなければ `channel: "<チャンネル ID>"` と出す
3. `aratam.yaml` を、出た行のとおりに直す。`arata repo check …` が ok になることを手元で確かめる
4. `GITHUB_TOKEN="$(gh auth token)" arata repo check … --github` を流す。**新しく要る秘密の登録のコマンド** (`gh secret set ARATAM_SLACK_BOT_TOKEN …`) が ng で、
   **要らなくなった秘密を消すコマンド** (`gh secret delete ARATAM_SLACK_WEBHOOK …`) が warn で出る (ほかのアカウントが Webhook のままなら、消すほうは出ない)
5. 新しい秘密を登録する → PR を出す (PR の検査の `arata repo check` が、ワークフローと `aratam.yaml` の組を確かめる) → マージ → `arata-notify-test` で届くことを見る →
   要らなくなった秘密を消す。**消すのは最後** (マージの前に消すと、main の定時の通知が止まる。`secret_unused` の行に、この順番を書く)

- **`aratam.yaml` は、どの指定でも書き直さない** (ADR 0059 のまま)。利用者が育てるファイルで、通知先・LLM の設定・コメントが入っている。
  直す行を arata が出し、人が貼る。貼り間違いは、手元と PR の `repo check` が止める
- 緊急用の Webhook を分ける・やめる (`--urgent-webhook`) も同じ流れ (出る行は `urgent_webhook_env` の 1 行)

### チャンネル ID

- bot の送り先は、秘密ではないが `aratam.yaml` に要る (`slack.channel`。無いと `aratam config check` が通らない)。
  `repo init` が bot のアカウントの `aratam.yaml` を**新しく作る**ときは、`--channel <アカウント>=<ID>` が要る (端末なら聞く。端末でなければ `CONFIG_INVALID`)。
  空のまま書き出して、後で直させる形にはしない (最初の PR の検査が、必ず 1 度落ちる)
- **書き出した後は、チャンネル ID は `aratam.yaml` だけが持つ**。README のコマンドにも載せず、`repo check` も比べない。
  チャンネルを変えるたびに `repo init` を流し直すことにしない (送り先は、利用者が PR で育てる値)。`aratam.yaml` が既にあるアカウントの `--channel` は、6 の「直す行」に出すためだけに使う
- 緊急用のチャンネル (`slack.urgent_channel`) は引数にしない。空 (通常用にメンション付きで送る) で書き出し、分けるなら `aratam.yaml` に書く

### 置く順番 (書き出す README。ADR 0059 の順番を置き換える)

1. AWS のスタック
2. `arata repo init` (定時なし)
3. `github/` を当てる (environment をワークフローより先に作る。ADR 0057)
4. `arata repo check … --github` → 出たコマンドで秘密を登録する → もう一度 `repo check` (ng が無くなるまで)
5. 一式を最初の PR で入れる (PR の検査が `arata repo check` のファイルの検査も流す)
6. 試しの通知と、試しの実行
7. 導入の流れ (`arata help ai onboarding`)
8. 定時を有効にする

### PR の検査 (`arata-check.yml`)

- `arata repo check <書き出したときの引数> --out .` を足す (`--github` は付けない。PR の検査は、秘密も、GitHub を読む権限も持たない)。
  引数は、書き出しのときにワークフローへ入れる (README のコマンドと同じもの)
- `ARATA_VERSION` はこの一式を書き出した版なので、「この版の一式との差」は 1 バイトの違いも出る。版を上げる PR では、全部の生成物を新しい版で書き直すので、揃う
- これまでの「`aratam.yaml` ごとに送り方を判別する」部分は、`repo check` の `notify` に置き換える

### 見本とテスト

- 見本 (`examples/audit-repo`) は、これまでどおり出力そのもの。引数は、**組み合わせがいちばん多い形** (`prod=webhook,staging=bot`、緊急用を分ける、別の経路の知らせを使う) にし、
  actionlint・zizmor・actionsgate が、全部の秘密の渡し方を読むようにする
- ほかの組み合わせ (全部 Webhook・全部 bot・混在 × 緊急用の有無 × 知らせの有無) は、Go のテストで「YAML として読める」「参照する秘密の名前が、要る秘密と同じ」
  「使わない秘密の名前が、どのファイルにも出てこない」を固定し、CI では書き出した結果に actionlint と zizmor を通す
- `repo check` のテストは、偽の GitHub API (`httptest`) で行う。実際の GitHub・AWS・Slack・LLM に接続しない。「GET 以外を 1 つも呼ばない」「値を返す API を呼ばない」を固定する
- ファズ: 引数 (`--notify`・`--channel` を含む)、GitHub の応答、ワークフローの YAML、`aratam.yaml`

## 検討した選択肢

- **仮の値の箱を作る** (ADR 0059 の決定): 採らない。(1) **仮の値が残る**。使わない箱は仮の値のままで、一覧からは本物と見分けられない。
  (2) **上書きの危険**。作成が上書きの API なので、計画と apply の間に入った本物の値を置き換え得る。state を使う限り、順番の注意が要る。
  (3) **使わない箱**。使わない送り方・使わない知らせの名前まで作り、それを見分ける検査・警告・別の root・CI のテストが要る。
  箱の利点だった「名前を迷わない」は、`repo check` が名前入りのコマンドを出すことで足りる
- **箱を、使うと決めた名前だけ作る** (通知の方法を決めた上で、Terraform で箱を作る): 使わない箱は無くなるが、仮の値と上書きの危険は残る。採らない
- **arata が秘密を登録する** (`arata repo secrets set` など): 値を受け取る経路と、書き込みのできる鍵が arata に要る。arata は読み取りだけ、という性質を GitHub の側でも保つ。採らない
- **`gh` を起動して認証を取る**: 打つ量は減るが、外の実行ファイルを呼ぶ経路が増え、テストで本物を起動しない仕組みが要る。
  `GITHUB_TOKEN="$(gh auth token)"` を前に付ければ足り、`github/` を当てるときと同じ形になる。採らない
- **送り方を、これまでどおり実行のときに `aratam.yaml` から判別する**: ワークフローが全部の秘密を参照し続けるので、「使わない秘密は出てこない」にならず、要る秘密の一覧も決まらない。
  決める場所が、引数 (ワークフロー) と `aratam.yaml` の 2 つになる。採らない。合っていることは `repo check` が見る
- **送り方を変える専用の操作で、`aratam.yaml` の `slack` の節だけを書き換える** (`arata repo notify prod bot --channel …` など): 手で直す箇所が無くなる。
  ただ、利用者が育てたファイルを機械が書き換える経路が増える。コメント・引用符・並びを直してあるファイルでは、行の差し替えが外れるか、意図しない行に当たる。
  外れたときは、結局「直す行を出して、人が貼る」に落ちる。直すのは多くて 4 行で、貼り間違いは `repo check` が手元と PR で止める。まず「行を出す」だけにし、
  手で直す誤りが実際に起きたら、この操作を足す (足すのは互換)
- **`aratam.yaml` を `--force` で書き直す**: 通知先・LLM の設定・コメントを失う。ADR 0059 の「利用者が育てるものは、どの指定でも書き直さない」を崩す。採らない
- **チャンネル ID を `--notify prod=bot:C0123456789` の形で持ち、README のコマンドにも載せる**: チャンネルを変えるたびに、`aratam.yaml` と README のコマンドの 2 か所を直すことになる。
  載せた値が古くなっても動くので、気づけない。採らない
- **bot のチャンネルを空で書き出し、後で直させる**: 引数は減るが、最初の PR の検査が必ず落ち、空の値という「仮の状態」がファイルに入る。採らない
- **通知の方法に既定を置く (全部 Webhook など)**: 引数は減るが、決めていない利用者が、気づかずにその形で進む (ADR 0014)。採らない
- **引数が足りないとき、いつも対話で聞く**: CI や LLM が、入力を待って止まるか、空の入力で進む。端末のときだけにする
- **GitHub の検査を、いつも行う** (`--github` なしで、鍵があれば読む): 環境変数に鍵があるだけで外へ通信するコマンドになる。PR の検査では要らない。明示したときだけにする
- **`repo check` の引数を無くし、ファイルから読み取る** (ワークフローの中身から、通知の方法を逆算する): 「この版の一式との差」には引数が要る。
  逆算は、手で直されたワークフローで誤る。引数は README と `arata-check.yml` にあり、写せば足りる
- **ワークフローの最初に、全部の秘密が空でないかを確かめる job を置く**: 全部の秘密を、使わない step に渡すことになる。Actions の `GITHUB_TOKEN` では秘密の一覧も読めない。
  必ず使う 2 つだけを、使う直前に確かめる

## 結果

- 良い点
  - environment にあるのは、使う秘密だけ。仮の値はどこにも無く、Terraform が秘密に触れる経路も無い (上書きの危険が無くなる)
  - 要る秘密が、引数から 1 つに決まる。ワークフローを読めば、このリポジトリが使う秘密が分かる
  - 足りない名前・余った名前・リポジトリの側に置いてしまった秘密・開いたままの environment が、定時の前に、読み取りだけで分かる
  - スクリプト 2 つ、Terraform の root 1 つ、CI の秘密のテストが無くなる
- 引き受けるコスト
  - **引数が増える** (3 つ。bot なら 4 つ)。端末では聞かれるが、CI や LLM から打つときは全部書く
  - **`repo check` は、秘密の値が正しいかは分からない** (名前があることだけ)。値の誤りは、試しの通知と試しの実行で確かめる (順番の 6)
  - **送り方を変えるとき、`aratam.yaml` は人が直す** (出た行を貼る)
  - 緊急用の Webhook を分けるかを、アカウントごとには変えられない
  - `--github` には、environment と秘密の名前の一覧を読める鍵が要る (リポジトリの admin の `gh` の鍵なら読める)。足りないときは ng で分かる
  - arata が `aratam.yaml` の 3 つの項目の名前を知ることになる (aratam が項目の名前を変えたら、arata も直す。テストが気づく)
  - ADR 0059 の一式を、リリース前の版から試した利用者は、`github/secrets/` を消し、箱 (仮の値の秘密) のうち使わないものを `repo check --github` の出すコマンドで消す。
    仮の値が残った「使う」秘密は、名前からは見分けられない。値を入れ直す (仮の値のまま動かすと、認証か送信が失敗して止まる)
- **確かめていないこと**: 実際の GitHub では確かめていない (開発では実環境に接続しない)。確かめること: 秘密の名前の一覧と environment を読む API が、偽の API と同じ形で返ること、
  読むのに要る権限、`gh secret set` / `gh secret delete` が出したコマンドのとおりに動くこと
- 攻撃の対応表 (ADR 0058): 新しいチェックではないので変えない
- 次の段 (この ADR では決めない): GitHub の設定の残り (ルールセット、Actions の許可、非公開、fork の禁止) が宣言からずれていないかを `repo check --github` に足す。
  Terraform の state を読まずに、API の応答と、この版の宣言の値を比べる
