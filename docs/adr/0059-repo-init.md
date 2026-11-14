# 0059. 監査を回すリポジトリの一式を `arata repo init` で書き出し、見本はその出力から作る (GitHub の設定は Terraform。秘密の箱は、既にある秘密を取り込んでから作る)

- 日付: 2026-11-14
- 状態: 採用 (実際の GitHub では確かめていない。「結果」)
- 関係する判断: ADR 0014 (雛形と `--diff`)、0040・0057 (実行の仕組みと environment)、0042 (PR の検査)、0054 (機械が読む出力)、0035・0039 (Actions の固定)、0019 (依存の待機期間)

## 背景

GitHub Actions で arata と aratam を定時に動かすリポジトリは、いまは `examples/github-actions` の見本を人が写して作る。
写すときに、arata の版・組織とリポジトリの名前・アカウントの名前・ストアの URL を手で直す。直す場所は 4 つのワークフローにまたがり、ずれや打ち間違いが起きる。
GitHub の側の設定 (非公開、fork の禁止、main の保護、Actions の許可、environment) は、README の手順を人が画面でなぞる。
付け忘れても動くので気づけない (environment の「デプロイできるブランチ」を忘れると、どのブランチのジョブにも秘密が渡る。ADR 0057)。

設定ファイルには、既に雛形がある (`arata config init` と `--diff`。ADR 0014)。同じ考え方をリポジトリの一式に広げる (ロードマップ「使うための道具の配り方」)。

### 確かめたこと (2026-11-14)

Terraform の GitHub の provider (`integrations/github`) の文書と実装 (v6.13.0。2026-07-08 公開で、7 日の待機を過ぎている) を読み、
手元に立てた偽の GitHub API に向けて、実際の provider で plan と apply を流した (実際の GitHub には接続していない)。

- environment の秘密の**名前の一覧を読む data source がある** (`github_actions_environment_secrets`。名前と日時だけを返し、値は返さない)。
  environment かリポジトリが無いときはエラーになる
- 秘密のリソース (`github_actions_environment_secret`) の**作成は、GitHub の「作るか上書きする」API をそのまま呼ぶ**。同じ名前の秘密が既にあれば、黙って上書きする
- 「一覧に無い名前だけを `for_each` に渡す」形は、**1 回目は正しく動くが、2 回目に壊れる**。箱を作ると、その名前が一覧に載る。次の plan では `for_each` から外れ、
  Terraform は「消す」と計画する。人が本物の値を入れた後なら、本物の値を消す
- `import` ブロックは `for_each` を取れ (Terraform 1.7 以降)、data source の結果を渡せる。取り込んだ秘密の値は state に入らない (provider の文書)。
  `ignore_changes = [value]` を付けると、取り込んだ秘密にも、後から人が値を入れた秘密にも、更新は計画されない (偽の API で、書き込みの呼び出しが 0 件であることを見た)
- provider の文書は `ignore_changes = [remote_updated_at]` を勧めるが、Terraform は「provider だけが決める値なので効果が無い」と警告する。効くのは `value` のほう
- Actions の許可 (`github_actions_repository_permissions`) は、許可する action の一覧と `sha_pinning_required` を持つ。
  ルールセット・environment・デプロイできるブランチ・`GITHUB_TOKEN` の既定の権限にも、それぞれリソースがある

## 決定

### コマンド

- **`arata repo init`** にする。`config init` / `config check` と同じ「名詞 + 動詞」に揃える。差分は `arata repo init --diff`
- **arata の側に置く** (aratam ではない)。雛形と `--diff` は arata にあり (`internal/scaffold`)、書き出すものの大半 (ワークフロー、`arata.yaml`、既知リスト) は arata のもの。
  aratam は依存を許可リストで絞っており、足したくない。LLM も通知も使わないので、ADR 0001 と 0018 の境界は変わらない
- 引数。**既定値を持たない** (書かなければエラー。ADR 0014 と同じく、暗黙の値を一式に埋めない)

  | 引数 | 中身 | 受け付ける形 |
  |---|---|---|
  | `--owner` | GitHub の組織 (か利用者) の名前 | 英数字とハイフン |
  | `--repo` | リポジトリの名前 | 英数字・`.`・`_`・`-` |
  | `--accounts` | 監査対象の名前 (カンマ区切り。ディレクトリ・matrix・ストアの prefix に使う) | 小文字の英数字とハイフン。重複は拒む |
  | `--audit-account` | 監査する側のアカウント (12 桁の ID か `none`)。各アカウントの `config init` にそのまま渡す (ADR 0045) | `config init` と同じ |
  | `--store-bucket` | ストアのバケットの名前 (`runner.yaml` の出力 `StoreUrl` のバケット) | S3 のバケット名の形 |
  | `--region` | ワークフローの `AWS_REGION` と `arata.yaml` の `aws.region` | リージョンの名前の形 |
  | `--out` | 書き出す先のディレクトリ | — |
  | `--schedule` | 付けると、監査のワークフローに定時 (`schedule`) を入れる。付けなければ手動実行だけ (下の「置く順番」) | — |
  | `--force` | 生成物だけを書き直す (下の「既にあるリポジトリ」) | — |
  | `--diff` | 書き出さずに、今の一式とこの版の一式を比べる | — |
  | `--format` | `--diff` の出力 (`text` / `json`) | — |

- **版は、そのバイナリの版**を `ARATA_VERSION` に入れる。リリース版 (`vX.Y.Z`) では、ほかの版を指定できない。
  版の付かないビルド (`dev`) では止まり、`--arata-version vX.Y.Z` を書いたときだけ進む (開発とテスト用)
- **引数は書く前に形で絞る**。値は YAML・HCL・シェルの中に入るので、上の表の形に合わないものは 1 つも書かずにエラーにする (引用符・改行・`${{`・`$(` などは、形の時点で入らない)。
  差し込みは決まった印の置換だけで、条件や繰り返しを持つテンプレートの言語は使わない (GitHub の式 `${{ }}` と Go の `text/template` の区切りがぶつかるため)。
  ファズテストで「形を通った引数なら、生成物は YAML として読め、引数の値は決まった場所にだけ現れる。形を通らない引数では何も書かない」を固定する (ADR 0041)
- **書き出すものは引数だけで決まる**。ホスト名・実行した人・環境変数を読まない。生成物 (下の「既にあるリポジトリ」) は時刻も読まず、同じ版と同じ引数なら、同じバイト列になる
  (ゴールデンと `--diff` の前提)。例外は 1 つで、既知リストの監査する側のアカウントの項目の `approved_at` は、`config init` と同じく書き出した日になる
  (利用者が育てるファイルで、`--diff` の対象ではない)。バイナリに入るのは架空の値の雛形だけで、利用者の値は引数からしか入らない

### 書き出すもの

```
.github/workflows/arata-audit.yml         定時の監査 (アカウントの matrix)
.github/workflows/arata-triage.yml        finding の片付け (手動)
.github/workflows/arata-notify-test.yml   試しの通知 (手動)
.github/workflows/arata-check.yml         PR の検査
.github/scripts/arata-slack-method.sh     送り方の判別 (aratam config check --format json の .slack.method。ADR 0054)
github/                                   GitHub の設定の Terraform
github/secrets/                           秘密の箱の Terraform (別の root。下)
aws/<アカウント>/arata.yaml                config init と同じ雛形 (name・store・aws.region・aws.profile は引数から記入)
aws/<アカウント>/allowlist.yaml            同上 (--audit-account の項目)
aws/<アカウント>/aratam.yaml               aratam config init と同じ雛形 (name は引数から記入)
README.md                                 置く順番と、この一式を書き出したコマンド
.gitignore                                Terraform の state と作業ディレクトリ
```

- **ワークフローは複数アカウントの形の 1 つだけ**にする。アカウントが 1 つでも matrix の要素が 1 つになるだけで、動きは同じ。
  1 アカウント用の見本 (`arata-audit.yml`) は持つのをやめる (2 つの形を持つと、片方だけ直す誤りが残る。いまも 2 つの共通部分の一致をテストで縛っている)
- 秘密か OIDC を使うジョブは `environment: audit` (ADR 0057)。PR の検査には付けない。environment の名前は `audit` に固定し、引数にしない
  (`runner.yaml` の `GitHubEnvironment=audit`、Terraform、ワークフローの 3 か所が同じ文字列であることを、生成の時点で保証する)
- **aratam の雛形の本文は、標準ライブラリだけの小さなパッケージに出して、arata と aratam の両方から使う**。arata は `internal/notify`・`internal/llm`・`internal/slack` に
  つながないままにし、テストで固定する (いまも 0 件)
- README には、書き出したときの引数をコマンドの形で載せる (`--diff` や書き直しのときに、同じ引数を打ち直さずに写せる)

### GitHub の設定の Terraform (`github/`)

- provider は `integrations/github` を**完全な版で固定** (`= 6.13.0`)。`.terraform.lock.hcl` を一緒に書き出し、linux と darwin の amd64・arm64 のハッシュを入れる。
  Terraform 本体は 1.7 以降 (`import` の `for_each`)
- **宣言に持つのは、セキュリティに効く項目だけ**

  | リソース | 持つ項目 |
  |---|---|
  | リポジトリ | 非公開 (`visibility = "private"`)、fork の禁止 (`allow_forking = false`)。ほかの項目は `ignore_changes` |
  | 既定のブランチのルールセット | PR 必須、削除の禁止、force push の禁止、必須のチェック (`check` = `arata-check.yml` のジョブ)。迂回できる主体は置かない |
  | Actions の許可 | `selected`。GitHub 製と `aws-actions/configure-aws-credentials@*` だけ。SHA の固定を必須 |
  | `GITHUB_TOKEN` | 既定は read。Actions が PR を承認できない |
  | environment `audit` | デプロイできるブランチは `main` だけ。レビュー担当と待ち時間は付けない (定時が止まる。ADR 0057) |

- PR の承認の人数は Terraform の変数にし、既定は 0 にする (1 人で運用する組織がマージできなくならないように。増やすのは利用者)
- **リポジトリは `prevent_destroy`**。`terraform destroy` や宣言の消し忘れで、リポジトリそのものを消さない
- **新しく作るときは `auto_init = true`** (最初のコミットを GitHub に作らせる)。空のリポジトリには PR を出せないので、一式は最初の PR で入れる。
  この PR から main の保護と `arata-check` が効く。既にあるリポジトリは、README の `terraform import` の手順で取り込む (取り込めば `auto_init` は無視される)
- **当てるのは人が手元で行う**。認証は `GITHUB_TOKEN` の環境変数で渡し、ファイルに書かない。書き込みのできる鍵を CI に置かない。state は手元で、`.gitignore` に入れる
- 宣言に持たないもの (provider に無い・組織の側の設定): fork の PR へのワークフローの権限、OIDC の `sub` の ID 入りの形、組織の fork の設定、書き込み権限を持つ人。
  これらは README と `arata help ai runtime` の点検 (`gh api`) に残す

### 秘密の箱 (`github/secrets/`)

ワークフローが使う秘密の名前 (`ARATA_RUNNER_ROLE_ARN`・`ARATA_AUDIT_ROLE_ARNS`・`ARATAM_SLACK_WEBHOOK`・`ARATAM_SLACK_URGENT_WEBHOOK`・`ARATAM_SLACK_BOT_TOKEN`・`ARATA_ALERT_WEBHOOK`) を、
environment `audit` に仮の値で作る。値を入れる人は、画面で「どの名前に入れるか」を迷わない。**既にある秘密は上書きしない**。

- **`for_each` は、決まった名前の全部**にする (一覧との差にしない)。背景の「2 回目に消す」を避ける
- **既にある名前は、`import` ブロックで state に取り込む** (`for_each` = 決まった名前のうち、data source の一覧に載っているもの)。取り込みは読むだけで、秘密に書かない。
  一覧に無い名前だけが「作る」になる
- **`ignore_changes = [value]`**。取り込んだ秘密にも、後から人が入れた値にも、Terraform は書かない
- **`prevent_destroy`**。`terraform destroy` で本物の値を消さない
- **`github/` とは別の root にする**。data source は environment が無いと読めないので、同じ root に置くと最初の plan が通らない
  (読むのを apply の後に回すと、`for_each` の中身が plan の時点で決まらず、やはり通らない)。`github/` を当ててから `github/secrets/` を当てる。
  environment がまだ無ければ、エラーで止まる (書き込みは起きない)
- state を失っても安全側に倒れる。もう一度当てると、全部の名前が「既にある」になり、取り込むだけで終わる
- **仮の値は 1 つの決まった文字列**にし、ARN・JSON・URL・トークンのどの形にも合わないものにする。
  ワークフローは、秘密を使う直前にこの文字列と比べ、一致したら**秘密の名前を出して止まる** (形が合わずに偶然止まることに頼らない)。
  定時の通知が送れなかったことを知らせる Webhook (`ARATA_ALERT_WEBHOOK`) は、ふだん使われないので、ジョブの最初に確かめる (仮の値のまま気づかずに運用しない)。
  Slack の秘密は、使う送り方のものだけを確かめる (Webhook の方式なら、bot トークンの箱は仮の値のままでよい)。テストで固定する
- 仮の値は秘密ではない (生成物に書いてある)。state に入るのは仮の値だけで、本物の値は入らない

### 既にあるリポジトリ

書き出すファイルを 2 種類に分ける。

| 種類 | ファイル | 既にあるとき |
|---|---|---|
| 生成物 (手で直さない) | `.github/`、`github/` (`.tf` と lock)、`README.md`、`.gitignore` | 同じ中身なら何もしない。違えば**書かずに**知らせる。`--force` で書き直す |
| 利用者が育てるもの | `aws/<アカウント>/` の 3 つ | **どの指定でも書き直さない** (承認の記録が入る)。無いものだけ作る |

- **既定では 1 つも上書きしない**。無いファイルだけを作り、違いのあるファイルは一覧で知らせて終了コード 1 (アカウントを足すときは、新しい `aws/<名前>/` だけが作られる)
- **`--diff`** は何も書かず、生成物の 1 つずつについて「同じ・違う・無い・この版の一式に無い (`.github/workflows` と `.github/scripts` の中の `arata-` で始まるファイル)」を出す。
  `text` は人向けで、違うファイルは行の差分を付ける。`json` は機械向けで、スキーマとテストで固定する (ADR 0054)。差があれば終了コード 1
  (版を上げる PR の CI で「一式がこの版と揃っている」を確かめられる)。`aws/` の中身は `arata config init --diff` の役目なので、ここでは「ある・無い」だけを見る
- **`--force`** は生成物だけを書き直す。版を上げるとき・定時を有効にするとき・アカウントを足すときに、手で 4 つのワークフローを直さずに済む。
  書き直した結果は、利用者のリポジトリの PR の差分でレビューされる。`config init` の `--force` と同じ位置づけ

### 置く順番 (書き出す README)

1. AWS のスタック (`deploy/github-actions/runner.yaml` を `GitHubEnvironment=audit` で、`deploy/iam/readonly-role.yaml` を各アカウントに)。バケットの名前がここで決まる
2. `arata repo init` (定時なし)
3. `github/` を当てる (リポジトリ・ルールセット・Actions の許可・environment)。**environment はワークフローより先に作る** (無い environment を参照すると、制限なしで自動で作られる。ADR 0057)
4. `github/secrets/` を当てる (箱)。箱に本物の値を入れる
5. 一式を最初の PR で入れる (`arata-check` が通ることを見る)
6. 試しの通知 (`arata-notify-test`) と、試しの実行 (`arata-audit` の `dry_run`)
7. 導入の流れ (`arata help ai onboarding`): 手元で `arata init`、通知をつながない最初の run、片付け
8. 定時を有効にする (`arata repo init … --schedule --force` の PR)

- **定時は最後に、PR で有効にする**。最初の PR で定時まで入れると、ベースラインの収集 (7) の前に監査が走り、溜まっていた指摘が一度に通知される (`help ai onboarding`)。
  有効・無効を GitHub の変数で切り替える形にはしない (admin が画面で切ると、監査が黙って止まる。ファイルなら PR に残る)

### 見本との関係

- **見本は、このコマンドの出力そのものにする**。決まった架空の引数 (`example-org` / `security-audit` / `prod,staging` など) での出力を `examples/audit-repo/` に置き、
  テストが「雛形から作った結果と 1 バイトも違わない」を確かめる (`-update` で作り直す)。雛形 (バイナリに埋め込む) が正で、見本を手で直すとテストが落ちる
- いまの見本のテスト (ワークフローの形・秘密の渡し方・`run:` の中身など) は、この出力に向けて残す。CI の actionlint・zizmor・actionsgate と `actions.lock` の対象も、この出力に替える
- `examples/github-actions/README.md` の説明 (手順の理由、堅くする点検、移行) は残し、「手で写す」の部分を `arata repo init` に置き換える

### テスト

- ゴールデン (上の見本)。変えるときは PR に理由を書く
- actionlint・zizmor・actionsgate を、書き出した一式に通す (CI の対象を替える)。`uses` は SHA で固定し、`actions.lock` を `--no-narrow` で更新する
- 引数の形のファズテスト (上)
- `--diff` の JSON のスキーマと `schematest`
- **Terraform は、CI に版と SHA256 を固定して入れる** (zizmor と同じ取得の仕方。Go の依存は足さない)。`terraform fmt -check`・`validate` と、
  **偽の GitHub API (`httptest`) に向けた apply** を回し、「既にある秘密の名前には、書き込みの呼び出しが 1 つも来ない」「2 回目の plan に変化が無い」
  「人が値を入れた後も変化が無い」「destroy が止まる」を固定する。provider の取得にネットワークが要るので、ふだんの `go test ./...` では動かさず、環境変数で有効にする (CI と `make` の的)
- provider の版が公開から 7 日以上であることは、CI でレジストリの公開日を読んで確かめる (`tools/agegate` と同じ考え方の検査を足す)
- **CI の Terraform 本体も、公開から 7 日以上たった版にする** (依存の方針と同じ。ADR 0019)。Terraform 本体は Go のモジュールでも action でもないので、
  `tools/agegate` と `tools/actionsgate` の対象外で、公開日は CI では確かめない (zizmor・osv-scanner と同じ扱い。`docs/supply-chain.md`)。
  版を変える PR で、公式のリリース (`gh api repos/hashicorp/terraform/releases/tags/<版> --jq .published_at`) の公開日と、
  公式の配布元の `SHA256SUMS` の値を本文に書き、レビューで見る。脆弱性の修正版の例外は ADR 0043 のとおり
- どのテストも、実際の GitHub・AWS・Slack・LLM に接続しない

## 検討した選択肢

- **`arata scaffold repo` / `arata scaffold github-actions`** (ロードマップの仮の名前): 動詞が先に来て、`config init`・`config check` と並びが違う。
  後から `repo` の下に足しやすい名前にする (下の「次の段」のずれの検査など)
- **aratam のコマンドにする**: 通知の設定も書くが、書くものの中心は arata の側。aratam の依存を増やす理由が無い
- **引数を設定ファイル (`arata-repo.yaml`) に持ち、そこから作る**: 打ち直しは無くなるが、読むファイルの形と検査が 1 つ増える。README に載せたコマンドを写せば足りる。採らない
- **1 アカウント用の形も書き出す (`--single`)**: いまの見本と同じ 2 つの形を持ち続けることになる。採らない
- **上書きを一切しない (`--force` を持たない)**: 版を上げるたびに、`--diff` を見ながら 4 つのワークフローを手で直すことになり、手で直す誤りという元の問題が残る。
  生成物だけに限り、`aws/` には触れないことで、`config init --force` と同じ危なさに収める
- **秘密の箱: 一覧に無い名前だけを `for_each` で作る** (最初の案): 背景のとおり、2 回目の plan で箱 (と、入れた本物の値) を消す。採れない
- **秘密の箱: 「最初に見たときに無かった」を `terraform_data` に覚えさせて `for_each` を決める**: 動くが、仕組みが読み取りにくい。state を失うと「今は全部ある」になって全部の箱が宣言から外れる。
  `import` のほうが、Terraform の普通の機能だけで同じ結果になり、state を失っても安全
- **秘密の箱: `ignore_changes` だけを付けて、一覧を読まない**: 作成が上書きの API なので、既に本物の値がある environment に当てると、最初の apply で仮の値に置き換わる。採れない
- **秘密の箱を作らず、足りない名前を出力するだけにする** (値は `gh secret set` で入れる): 上書きの余地が無く、いちばん単純。ただ、名前の打ち間違いは定時の失敗まで分からない。
  箱があれば、画面で値を入れるだけになる。`github/secrets/` を別の root にしたので、箱を使わない利用者は当てなければこの形になる
- **秘密の箱を `gh` のシェルスクリプトで作る**: state が要らないが、書き込みのできるスクリプトを一式に足すことになり、検査の対象が増える。plan で「何を作るか」を先に見られない。採らない
- **`github/` と `github/secrets/` を 1 つの root にして `-target` で 2 回に分ける**: 順番を誤ると通らず、`-target` は常用する機能ではない。root を分ける
- **宣言にリポジトリの全項目を持つ**: 説明・トピック・マージの方式などは利用者ごとに違い、セキュリティに効かない。持つと、関係のないずれで plan が騒がしくなり、読まれなくなる
- **Terraform を CI から当てる・state をリモートに置く**: 書き込みのできる鍵 (リポジトリの admin) を CI に置くことになり、environment で守ろうとしているものより強い鍵が増える。採らない
- **CI に terraform を入れず、手元にあるときだけ確かめる**: 「既にある秘密を上書きしない」は、この一式でいちばん壊してはいけない性質で、provider の実際の動きに依る。CI で毎回確かめる
- **定時を最初から入れ、仮の値の秘密で止まることに任せる**: 値を入れた時点で定時が動き出し、収集の前に通知が出る。試しの実行にも本物の値が要るので、分けられない
- **見本を別に持ち、生成物と「ほぼ同じ」をテストで比べる**: どこまで違ってよいかの規則が要る。出力そのものを見本にすれば、規則は「同じ」の 1 つ

## 結果

- 良い点
  - 版・名前・アカウントを手で直す場所が無くなる。ワークフローの版はバイナリの版と必ず揃う
  - GitHub の設定の付け忘れが、宣言と plan で見える。environment は必ずワークフローより先にできる
  - 見本と雛形の二重持ちが無くなる (1 アカウント用との二重持ちも)
  - 版を上げるときは `--force` の 1 回と PR の差分で済み、`--diff` で CI が揃いを確かめられる
- 引き受けるコスト
  - **1 アカウント用の見本をやめる**。その形で動いている利用者は、そのまま動き続けるが、`--diff` は大きな差を出す。移るときは matrix の形に直す
  - **plan と apply の間に入った秘密は上書きし得る**。一覧を読むのは plan のときなので、その後 apply までの間に同じ名前の秘密を誰かが入れると、仮の値で置き換える。
    plan の「作る」に出た名前を見てから承認する、と README に書く (値を入れるのは箱を作った後、という順番を守れば起きない)
  - state は手元にしか無い。別の人・別の端末で `github/` を当てるには、README の `terraform import` が要る (`github/secrets/` は要らない)
  - Terraform (1.7 以降) が利用者の手元に要る。使わない利用者は `github/` を当てず、README の画面の手順と点検で同じ設定にする
  - CI に Terraform の取得と、provider の取得 (レジストリへの通信) が増える。provider の版を上げる作業 (固定の版と lock の 4 つのハッシュ) が、arata の側に増える
  - 生成物を手で直した利用者は、`--force` で直しを失う (PR の差分に出る)。直したい点は arata の側の雛形に入れる
  - `examples/github-actions` の中身が動くので、文書のリンクと CI の対象を直す
- **確かめていないこと**: 実際の GitHub では確かめていない (開発では実環境に書き込まない)。確かめること:
  空のリポジトリに `auto_init` とルールセットを同時に当てた後、最初の PR が出せて `arata-check` が必須のチェックとして効くこと。
  `sha_pinning_required` と許可の一覧が、書き出したワークフローを止めないこと。組織ではなく個人のリポジトリでの `allow_forking`。
  秘密の取り込みと `ignore_changes` が、偽の API と同じに動くこと。OpenTofu は対象にしていない (レジストリと lock の中身が違う)
- 攻撃の対応表 (ADR 0058): 新しいチェックではないので変えない。ワークフローを書き換えて CI の秘密を持ち出す型の事例に対して、
  この一式は「見える」ではなく「起きにくくする」側 (environment とルールセットを付け忘れない) に効く
- 次の段 (この ADR では決めない): GitHub の設定が宣言からずれていないかを、読み取りだけで確かめる `arata repo check`。Release への雛形の添付
