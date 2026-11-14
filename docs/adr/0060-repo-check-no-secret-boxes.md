# 0060. 秘密の箱をやめ、一式の送り方は bot だけにして、足りない秘密は `arata repo check` が登録のコマンドと一緒に出す

- 日付: 2026-11-14
- 状態: 採用 (実際の GitHub と Slack では確かめていない。「結果」)
- 関係する判断: ADR 0059 (この ADR が「秘密の箱」と、送り方を実行のときに判別する形を置き換える。ほかの決定はそのまま)、
  0061 (Slack への送り方を bot にそろえる。この ADR の前提)、0014 (暗黙の既定を持たない)、0044 (aratam の秘密は環境変数)、0054 (機械が読む出力)、0057 (environment)、0041 (ファズ)

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

あわせて、Slack への送り方を bot にそろえると決めた (ADR 0061)。一式が書き出す送り方が 1 つなら、秘密は Slack のトークン 1 つで済み、
「途中で送り方を変える」場面も、送り方ごとのワークフローの形も要らない。

ADR 0059 の一式は、まだどのリリースにも入っていない (最新のリリースは、その実装より前)。リリースされた版からの移行は要らない。

## 決定

**最初は、秘密は 1 つも登録されていない。`arata repo check --github` を流すと、足りない秘密の名前と、そのまま打てる登録のコマンドが出る。**
arata は秘密の値を受け取らず、GitHub にも書かない。

### 1. 一式の送り方は bot だけ。`arata repo init` が聞くのはチャンネル ID だけ

- **書き出す `aratam.yaml` は、bot トークンの方式だけ** (`slack.bot_token_env: ARATAM_SLACK_BOT_TOKEN` と `slack.channel`。Webhook の項目は空)。
  送り方を選ぶ引数も問いも持たない (理由は ADR 0061)
- **一式が使う秘密は、いつも同じ 3 つ**になる: `ARATA_RUNNER_ROLE_ARN`・`ARATA_AUDIT_ROLE_ARNS`・`ARATAM_SLACK_BOT_TOKEN`。
  アカウントの数や設定で増減しない。Webhook の 3 つ (`ARATAM_SLACK_WEBHOOK`・`ARATAM_SLACK_URGENT_WEBHOOK`・`ARATA_ALERT_WEBHOOK`) は、ワークフローに 1 文字も出てこない
- 決めることは、チャンネル ID (秘密ではない) だけ。**既定値は持たない** (ADR 0014)

  | 引数 | 決めること | 要るとき |
  |---|---|---|
  | `--channel <アカウント>=<ID>` (カンマ区切り。例 `prod=C0123456789,staging=C0123456780`) | 通常用のチャンネル | `aws/<アカウント>/aratam.yaml` を**新しく作る**アカウントに必須 |
  | `--urgent-channel <アカウント>=<ID>\|same` (カンマ区切り) | 緊急用のチャンネル。`same` は「分けない」(通常用に、メンション付きで送る) | 同上 |
  | `--alert-channel <ID>\|none` | 定時の通知が送れなかったことを知らせるチャンネル (下の 3)。`none` は「知らせない」 | いつも |

- チャンネル ID の形は aratam と同じ (`C0123456789`。名前 `#general` は受け付けない)。アカウントの名前は `--accounts` にあるものだけで、重複は拒む
- 「分けない」「知らせない」は、書かないことでは表さず、`same` / `none` と書く。書いていないことが「使わない」と「決めていない」のどちらなのかを、区別できないため
- **端末 (TTY) から打って、上の引数が足りないときだけ、対話で聞く**。聞くのはチャンネル ID だけ (ほかの引数は、これまでどおり足りなければエラー)。
  答えは引数と同じ形で確かめ、通らなければ聞き直す。最後に、答えを引数にした同じコマンドを出す
- **端末でなく、引数が足りなければ、`CONFIG_INVALID` (終了コード 2) で止める**。足りない引数の名前を出し、1 つも書かない。CI や LLM が、黙って既定で進まない
- 端末かどうかは、標準入力で判定する。標準ライブラリだけで書き、依存を足さない。`/dev/null` を端末と見誤らないことをテストで固定する。
  テストは、判定と入力を差し替える (実際の端末は使わない)

### 2. チャンネル ID の持ち主と、チャンネルを変える操作

チャンネル ID は、**書かれたファイルが持ち主**になる。持ち主を 1 つにして、2 か所を直す手順を作らない。

| 値 | 持ち主 | README のコマンド (ADR 0059) に載るか | 変え方 |
|---|---|---|---|
| 通常用・緊急用のチャンネル | `aws/<アカウント>/aratam.yaml` (利用者が育てるファイル) | 載らない | `aratam.yaml` の `slack.channel` / `slack.urgent_channel` の行を直して PR |
| 知らせのチャンネル | ワークフロー (生成物) | 載る (`--alert-channel`) | README のコマンドの値を直して `arata repo init … --force` を流し、PR |

**チャンネルを変える手順** (書き出す README に、この順で載せる):

1. 新しいチャンネルに、bot を招待する (`/invite @<bot の名前>`。aratam は、入っていないチャンネルには送れない)
2. `aws/<アカウント>/aratam.yaml` の `slack.channel` (緊急用なら `slack.urgent_channel`) の 1 行を、新しい ID に直す
3. PR を出す。PR の検査が、ID の形 (`aratam config check`) と、一式との組 (`arata repo check`) を確かめる
4. マージしたら、`arata-notify-test` で、新しいチャンネルに届くことを見る

- **`aratam.yaml` を書き換えるコマンドは作らない**。直すのは 1 行で、秘密ではなく、形は PR の検査が止め、届くかは `arata-notify-test` が確かめる。
  コマンドにすると、利用者が育てたファイル (コメント・引用符・並びを直してある) を機械が書き換える経路が増え、行が見つからないときは結局「この行を直す」と出すことになる。
  「`aratam.yaml` は、どの指定でも書き直さない」(ADR 0059) を保つ。手で直す誤りが実際に起きたら、足す (足すのは互換)
- `aratam.yaml` が既にあるアカウントに `--channel` / `--urgent-channel` を渡しても、ファイルは書き直さない。値が違えば、「書き直していない。変えるなら、この行を直す」と、直す行を出す
- 秘密は変わらない (トークンは同じ)。チャンネルを変えても、登録し直すものは無い

### 3. 定時の通知が送れなかったことの知らせも、bot で送る

これまでの知らせは、別の Webhook (`ARATA_ALERT_WEBHOOK`) に `curl` で送っていた。**Webhook を新しく求めない**ために、同じ bot トークンで送る。

- 監査のワークフローの最後の step が、`chat.postMessage` を `curl` で直接呼ぶ (aratam を通さない。バイナリが取れないとき・`aratam.yaml` が壊れているときにも送れる)。
  送り先は `--alert-channel` のチャンネル ID (ワークフローに書く。秘密ではない)。送る中身は、これまでと同じ 1 行 (監査対象の名前・プロファイル・失敗した段階の id・実行の URL)
- Slack は、失敗でも HTTP 200 を返す。応答の `ok` を jq で読み、`true` でなければ失敗にする。`error` は、決まった形 (英小文字・数字・`_`) のときだけログに出す
- `--alert-channel none` なら、この step ごと書き出さない
- `arata-notify-test` の送り先の選択に、知らせのチャンネルを足す (`normal` / `urgent` / `alert`)。bot を知らせのチャンネルに招待し忘れていることを、定時の前に確かめられる
- **引き受けること: トークンそのものが使えないとき (未登録・失効・取り消し) は、知らせも送れない**。別の Webhook なら届いていた場面で、ここだけ守りが薄くなる。
  このとき、ジョブは赤のままで、step は「知らせも送れなかった」とエラーを出す。定時の前は `repo check --github` (未登録) と `arata-notify-test` (失効) で確かめる。
  これまでの知らせが拾っていた、ほかの原因 (設定の誤り、バイナリが取れない、認証の失敗、aratam の異常終了) は、これまでどおり拾える
- 通知と知らせを別のチャンネルにすることを勧める (bot が通知のチャンネルから外されたときに、知らせは届く)

### 4. ワークフロー

- **送り方を実行のときに判別するのをやめる**。`.github/scripts/arata-slack-method.sh` は消す。通知の step には、`ARATAM_SLACK_BOT_TOKEN` だけを渡す。
  `aratam.yaml` が bot の方式であることは、PR の検査の `arata repo check` が確かめる (下の 6)。合わないままマージされても、aratam は要る環境変数が空なので `CONFIG_INVALID` で止まり、知らせが届く
- **仮の値の検査をやめる**。`.github/scripts/arata-secret-check.sh` は消す (`.github/scripts/` は書き出さなくなる)。
  代わりに、認証に使う 2 つ (`ARATA_RUNNER_ROLE_ARN`・`ARATA_AUDIT_ROLE_ARNS`) が**空 (未登録) なら、名前と「手元で `arata repo check --github`」を出して止める**小さな step を置く。
  トークンが空のときは、aratam (`CONFIG_INVALID`) と知らせの step が止める
- 差し込みは、これまでと同じ「決まった印を、Go が選んだ断片で置き換える」だけ (知らせの有無は、定時の有無と同じ形)。条件や繰り返しを持つテンプレートの言語は使わない (ADR 0059)

### 5. 秘密の箱 (`github/secrets/`) をやめる

- **Terraform は environment と、デプロイできるブランチまで**。秘密のリソースも data source も持たない。`github/` の中身は ADR 0059 のまま
- 書き出しから `github/secrets/` を外す。CI の Terraform のテストから、秘密の部分 (偽の GitHub API への apply で「既にある秘密に書かない」を確かめる部分) を外す。
  `github/` の fmt・validate・偽の API への apply は残す
- `github/secrets/` が残っているリポジトリでは、`arata repo check` が「この版の一式に無い」と出す。ディレクトリを (手元の state ごと) 消せばよい。
  登録済みの秘密には何も起きない (Terraform は、消されたディレクトリのリソースに触れない)

### 6. `arata repo check`

名前は `arata repo check` にする (`config init` / `config check` と同じ並び。ADR 0059 が次の段に置いた名前)。
引数は `repo init` と同じものを取り (README のコマンドの `init` を `check` に替えれば打てる。`--out` は検査するディレクトリ。`--channel` と `--urgent-channel` は要らない)、何も書かない。

**出力**は `arata doctor` と同じ形にする。1 項目 1 行で、状態は `ok` / `warn` / `ng` / `skip`。`--format table` (人向け) と `--format json` (機械向け。スキーマ `repo-check` を
型から作り、`schematest` で固定する。ADR 0054)。**終了コードは、`ng` があれば 2、`warn` だけなら 0** (doctor と同じ)。`ng` と `warn` の行には `code` を付ける (`internal/codes` に足す)。

**ファイルの検査** (いつも行う。手元のファイルだけを読み、秘密も GitHub も要らない)

| 項目 | 見ること | 合わないとき |
|---|---|---|
| `files` | 生成物の 1 つずつが、この版・この引数の一式と同じか。一式に無い残りもの (`.github/` の `arata-` で始まるファイル、`github/` と `github/secrets/` の `.tf`) が無いか。`repo init --diff` と同じ比べ方 | ng。直し方は `arata repo init … --force` (残りものは消す) |
| `terraform` | `github/` の `.tf` と lock が、この版の形と同じか (上の `files` のうち、GitHub の設定に効くものを、別の項目として出す) | ng |
| `workflow_secrets` | `.github/workflows/arata-*.yml` が参照する秘密の名前 (`secrets.<名前>`) の集まりが、上の 3 つと同じか。名前を式で作る参照 (`secrets[…]`) が無いか | ng |
| `notify` (アカウントごと) | `aws/<アカウント>/aratam.yaml` が bot の方式で、環境変数の名前が `ARATAM_SLACK_BOT_TOKEN` か (`slack.bot_token_env`。`webhook_env`・`urgent_webhook_env` は空) | ng。`slack` の節に書く行を、そのまま貼れる形で出す (下) |
| `accounts` | `aws/<アカウント>/` の `arata.yaml` と `aratam.yaml` があるか (中身の形は `config check` の役目) | ng |

- `notify` が ng になるのは、Webhook の方式の `aratam.yaml` を持ち込んだとき (手で写した一式から移るとき) と、環境変数の名前を変えたとき。出る行:

  ```
  ng  notify  prod  aws/prod/aratam.yaml が bot の方式でない (この一式のワークフローは、bot トークンだけを渡す)
      aws/prod/aratam.yaml の slack の節を、次の行にする:
        webhook_env: ""
        urgent_webhook_env: ""
        bot_token_env: ARATAM_SLACK_BOT_TOKEN
        channel: "<チャンネル ID (例 C0123456789)>"
  ```

- `aratam.yaml` は arata が自分で読む (`slack` の 3 つの項目だけ)。arata を aratam の通知のパッケージにつながない (ADR 0018・0059)。
  「aratam が判別する送り方と、arata が読んだ結果が同じ」ことは、テストで固定する
- `repo init` は、書き出しの最後に同じファイルの検査を流して、結果を出す
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
| `secret` (名前ごと) | 上の 3 つが、environment にあるか | 無ければ ng (登録のコマンドを出す) |
| `secret_unused` (名前ごと) | environment に、この一式が使わない名前が残っていないか (Webhook の 3 つなど) | warn (消すコマンドを出す) |
| `repository_secret` (名前ごと) | リポジトリの (environment でない) 秘密が残っていないか | この一式と、これまでの一式の名前 (6 つ) のどれか → ng (どのブランチのジョブにも渡り、environment の守りを抜ける)。ほかの名前 → warn |

- API の失敗 (認証が無い・権限が足りない・リポジトリが無い) は、その項目を ng にして code を付ける。応答の本文は出さない
- GitHub の応答は信用しない入力として読む。大きさとページの数に上限を置き、名前は秘密の名前の形 (英大文字・数字・`_`) のものだけを出力に運ぶ。ファズテストで固定する (ADR 0041)。
  ワークフローの YAML から秘密の名前を拾う箇所と、`aratam.yaml` を読む箇所も同じ

### 7. 足りない秘密の出し方

`secret` が ng の名前ごとに、**そのまま打てるコマンド**と、値の形・取りに行く場所を 1 行ずつ出す。JSON では `missing_secrets` に同じものを持つ。

```
gh secret set ARATA_RUNNER_ROLE_ARN --env audit -R example-org/security-audit
  値の形: arn:aws:iam::123456789012:role/arata-runner   取得元: runner.yaml のスタックの出力 RunnerRoleArn
```

| 名前 | 値の形 | 取得元 |
|---|---|---|
| `ARATA_RUNNER_ROLE_ARN` | `arn:aws:iam::123456789012:role/…` | `runner.yaml` のスタックの出力 `RunnerRoleArn` |
| `ARATA_AUDIT_ROLE_ARNS` | `{"prod": "arn:aws:iam::…:role/…", …}` (アカウントの名前から引く JSON。名前は実際の `--accounts`) | `readonly-role.yaml` のスタックの出力 (アカウントごと) |
| `ARATAM_SLACK_BOT_TOKEN` | `xoxb-…` | Slack アプリ (`deploy/slack/app-manifest.yaml` から作る) の Bot User OAuth Token |

- コマンドは値を引数に取らない形にする。`gh secret set` は値を端末で聞くので、値がシェルの履歴に残らない
- コマンドに入る組織・リポジトリ・秘密の名前は、どれも形で絞った値だけ (引数と、決まった名前の一覧)。GitHub の応答から来た文字列は、形を確かめた秘密の名前のほかは入れない
- `secret_unused` には `gh secret delete <名前> --env audit -R <owner>/<repo>` を出す。「その名前を使うワークフローが main に残っていないことを確かめてから」と添える
- **arata は秘密を登録しない**。値を受け取る経路と、書き込みのできる鍵を、arata に持たせない

### 置く順番 (書き出す README。ADR 0059 の順番を置き換える)

1. AWS のスタックと、Slack アプリ (bot を、通常用・緊急用・知らせのチャンネルに招待する)
2. `arata repo init` (定時なし)
3. `github/` を当てる (environment をワークフローより先に作る。ADR 0057)
4. `arata repo check … --github` → 出たコマンドで秘密を登録する → もう一度 `repo check` (ng が無くなるまで)
5. 一式を最初の PR で入れる (PR の検査が `arata repo check` のファイルの検査も流す)
6. 試しの通知 (`normal`・`urgent`・`alert`) と、試しの実行
7. 導入の流れ (`arata help ai onboarding`)
8. 定時を有効にする

### PR の検査 (`arata-check.yml`)

- `arata repo check <書き出したときの引数> --out .` を足す (`--github` は付けない。PR の検査は、秘密も、GitHub を読む権限も持たない)。
  引数は、書き出しのときにワークフローへ入れる (README のコマンドと同じもの)
- `ARATA_VERSION` はこの一式を書き出した版なので、「この版の一式との差」は 1 バイトの違いも出る。版を上げる PR では、全部の生成物を新しい版で書き直すので、揃う
- これまでの「`aratam.yaml` ごとに送り方を判別する」部分は、`repo check` の `notify` に置き換える

### 見本とテスト

- 見本 (`examples/audit-repo`) は、これまでどおり出力そのもの。引数は、緊急用を分けるアカウントと分けないアカウントを 1 つずつ、知らせのチャンネルあり、にする
  (actionlint・zizmor・actionsgate が、知らせの step まで読む)。`--alert-channel none` の形は、Go のテストで「YAML として読める」「知らせの step が無い」を固定し、CI で actionlint と zizmor を通す
- どの引数でも「参照する秘密の名前が 3 つと同じ」「Webhook の秘密の名前が、どのファイルにも出てこない」を固定する
- `repo check` のテストは、偽の GitHub API (`httptest`) で行う。実際の GitHub・AWS・Slack・LLM に接続しない。「GET 以外を 1 つも呼ばない」「値を返す API を呼ばない」を固定する
- 知らせの step は、ワークフローの `run:` を偽の `curl` で動かして、「`ok` が `true` でなければ失敗する」「トークンと応答の本文をログに出さない」を固定する
- ファズ: 引数 (`--channel`・`--urgent-channel`・`--alert-channel` を含む)、GitHub の応答、ワークフローの YAML、`aratam.yaml`

## 検討した選択肢

- **仮の値の箱を作る** (ADR 0059 の決定): 採らない。(1) **仮の値が残る**。使わない箱は仮の値のままで、一覧からは本物と見分けられない。
  (2) **上書きの危険**。作成が上書きの API なので、計画と apply の間に入った本物の値を置き換え得る。state を使う限り、順番の注意が要る。
  (3) **使わない箱**。使わない送り方・使わない知らせの名前まで作り、それを見分ける検査・警告・別の root・CI のテストが要る。
  箱の利点だった「名前を迷わない」は、`repo check` が名前入りのコマンドを出すことで足りる
- **箱を、使う名前だけ作る** (Terraform で 3 つの箱を作る): 使わない箱は無くなるが、仮の値と上書きの危険は残る。採らない
- **arata が秘密を登録する** (`arata repo secrets set` など): 値を受け取る経路と、書き込みのできる鍵が arata に要る。arata は読み取りだけ、という性質を GitHub の側でも保つ。採らない
- **`gh` を起動して認証を取る**: 打つ量は減るが、外の実行ファイルを呼ぶ経路が増え、テストで本物を起動しない仕組みが要る。
  `GITHUB_TOKEN="$(gh auth token)"` を前に付ければ足り、`github/` を当てるときと同じ形になる。採らない
- **送り方を `repo init` で選ばせる** (`--notify <アカウント>=webhook|bot`。この ADR の最初の案): 組み合わせ (全部 Webhook・全部 bot・混在 × 緊急用の有無) ごとにワークフローの形が変わり、
  要る秘密が 2〜6 つの間で動く。「後から送り方を変える」手順 (ワークフローを書き直し、`aratam.yaml` を人が直し、古い秘密を消す) も要る。bot にそろえれば (ADR 0061)、どれも要らない
- **送り方を、これまでどおり実行のときに `aratam.yaml` から判別する**: ワークフローが Webhook の秘密も参照し続け、要る秘密の一覧が決まらない。採らない
- **チャンネルを変えるコマンドを作る** (`arata repo channel prod C…` など。`aratam.yaml` の `slack` の節の 1 行だけを書き換える): 上の 2 のとおり。まず「1 行を直して PR」にする
- **チャンネル ID を README のコマンドにも載せる**: チャンネルを変えるたびに、`aratam.yaml` と README のコマンドの 2 か所を直すことになる。載せた値が古くなっても動くので、気づけない。採らない
- **チャンネルを空で書き出し、後で直させる**: 引数は減るが、最初の PR の検査が必ず落ち、空の値という「仮の状態」がファイルに入る。採らない
- **知らせを、別の Webhook のまま残す** (`ARATA_ALERT_WEBHOOK`): トークンが使えないときにも届く。ただ、Webhook を新しく求めることになり、秘密が 1 つ増える。
  bot にそろえる理由 (ADR 0061) は、知らせにも当てはまる。採らない
- **知らせを、別の Slack アプリのトークンで送る** (`ARATA_ALERT_BOT_TOKEN`): トークンが使えないときにも届くが、Slack アプリと秘密がもう 1 組要る。
  守りが薄くなる場面 (トークンの未登録・失効) は、定時の前に `repo check --github` と `arata-notify-test` で確かめられる。まず 1 つのトークンにし、要ると分かれば足す (足すのは互換)
- **知らせを aratam に送らせる** (`aratam alert` など): 知らせは「aratam が動かないとき」のためのもの。バイナリが取れない・設定が読めないときに送れない。`curl` のままにする
- **チャンネルの引数に既定を置く** (緊急用は書かなければ通常用と同じ、など): 引数は減るが、決めていない利用者が、気づかずにその形で進む (ADR 0014)。採らない
- **引数が足りないとき、いつも対話で聞く**: CI や LLM が、入力を待って止まるか、空の入力で進む。端末のときだけにする
- **GitHub の検査を、いつも行う** (`--github` なしで、鍵があれば読む): 環境変数に鍵があるだけで外へ通信するコマンドになる。PR の検査では要らない。明示したときだけにする
- **`repo check` の引数を無くし、ファイルから読み取る**: 「この版の一式との差」には引数が要る。逆算は、手で直されたワークフローで誤る。引数は README と `arata-check.yml` にあり、写せば足りる
- **ワークフローの最初に、全部の秘密が空でないかを確かめる job を置く**: 全部の秘密を、使わない step に渡すことになる。認証に使う 2 つだけを、使う直前に確かめる

## 結果

- 良い点
  - environment にあるのは、使う 3 つの秘密だけ。仮の値はどこにも無く、Terraform が秘密に触れる経路も無い (上書きの危険が無くなる)
  - 要る秘密が、どのリポジトリでも同じ 3 つに決まる。Slack の秘密は 1 つで、チャンネルを足す・変えるときに秘密は動かない
  - 足りない名前・余った名前・リポジトリの側に置いてしまった秘密・開いたままの environment が、定時の前に、読み取りだけで分かる
  - スクリプト 2 つ、Terraform の root 1 つ、CI の秘密のテスト、送り方ごとのワークフローの形が無くなる
- 引き受けるコスト
  - **この一式では、Webhook で送れない**。Webhook の `aratam.yaml` を持ち込むと `repo check` が ng にする (手で写した一式は、そのまま動き続ける。ADR 0061)
  - **トークンが使えないときは、知らせも届かない** (上の 3)
  - **bot のトークンは、bot が入っているどのチャンネルにも書ける** (読めはしない。scope は `chat:write` だけ)。知らせの step にも同じトークンが渡る。
    範囲は、会社ごとにリポジトリと Slack アプリを分けることで閉じる (ADR 0061、書き出す README の「会社ごとに分ける」)
  - **`repo check` は、秘密の値が正しいかは分からない** (名前があることだけ)。値の誤りは、試しの通知と試しの実行で確かめる (順番の 6)
  - 引数が増える (チャンネル ID。端末では聞かれるが、CI や LLM から打つときは全部書く)
  - `--github` には、environment と秘密の名前の一覧を読める鍵が要る (リポジトリの admin の `gh` の鍵なら読める)。足りないときは ng で分かる
  - arata が `aratam.yaml` の `slack` の 3 つの項目の名前を知ることになる (aratam が項目の名前を変えたら、arata も直す。テストが気づく)
  - ADR 0059 の一式を、リリース前の版から試した利用者は、`github/secrets/` を消し、箱 (仮の値の秘密) のうち使わないものを `repo check --github` の出すコマンドで消す。
    仮の値が残った「使う」秘密は、名前からは見分けられない。値を入れ直す (仮の値のまま動かすと、認証か送信が失敗して止まる)
- **確かめていないこと**: 実際の GitHub と Slack では確かめていない (開発では実環境に接続しない)。確かめること: 秘密の名前の一覧と environment を読む API が、偽の API と同じ形で返ること、
  読むのに要る権限、`gh secret set` / `gh secret delete` が出したコマンドのとおりに動くこと、知らせの step の `chat.postMessage` が届くこと
- 攻撃の対応表 (ADR 0058): 新しいチェックではないので変えない
- 次の段 (この ADR では決めない): GitHub の設定の残り (ルールセット、Actions の許可、非公開、fork の禁止) が宣言からずれていないかを `repo check --github` に足す。
  Terraform の state を読まずに、API の応答と、この版の宣言の値を比べる
