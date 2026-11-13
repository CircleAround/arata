# arata

AWS のログと設定を定期的に改め、**前回から新しく発生したもの** (新規の主体・送信元・設定変更・findings) を報せる監査エンジン。
名前は「改め」と「新た」から。

- 収集 → 保存 → 差分判定 → レポート生成までを担う。通知・起動・LLM による要約は組み込み側の仕事
  (標準品として、出力を要約して Slack に通知する別コマンド `aratam` を同梱する。[下記](#通知-aratam))
- Go 製の単一バイナリ。オンプレの cron でも AWS Lambda でも同じバイナリで動く
- 顧客ごとの差は設定ファイル (ロググループと形式プロファイルの紐付け、既知リスト、閾値) に閉じ込める

設計は [docs/design.md](docs/design.md)、判断の経緯は [docs/adr](docs/adr/README.md) を参照。

## 現在の実装範囲 (設計書 10 章の Step 1〜3)

- ソース: `cloudtrail-lookup` (CloudTrail LookupEvents)、`cloudwatch-logs` (Logs Insights の集計クエリ。形式プロファイル `nginx_access` / `alb_access` / `wafv2` / `json` / `regex` / `request_lines`、行を解釈しない `text`)、
  アカウント単位の状態 `iam-credential-report` / `guardduty` / `access-analyzer` / `posture` / `waf-config` (WAFv2 の WebACL の設定)、
  `cloudtrail-unused-regions` (ふだん使わないリージョンの書き込み)、`cost-anomaly` (AWS Cost Anomaly Detection の異常)
- チェック: `root_usage`, `unknown_assume_role`, `new_principal`, `iam_changes`, `access_denied`, `defense_evasion`, `public_exposure`, `principal_new_source`, `secret_access`, `unused_region_activity`, `cost_anomaly`, `login_bruteforce`, `probe_paths`, `endpoint_abuse`, `waf_block_trend`, `ai_path_usage` (daily)、
  `credential_hygiene`, `guardduty_findings`, `posture`, `access_analyzer`, `waf_review` (weekly。WAF の修正提案の候補を report.json の `proposals` に)、
  `log_hygiene` (weekly。アプリのログに残った秘密の値・署名付き URL・隠されていない送信項目・本番の debug を、種類ごとの行数だけで報告する。値は取り出さない。設定を書くまで何も読まない)
- ストア: `dir://` (JSONL 原本 + SQLite)、`s3://` (毎回消える実行環境向けのオプション。「S3 ストア」の節)
- CLI: `config init` (推奨設定の雛形と `--diff`) / `config check` (設定と allowlist のオフラインの検査) / `profiles` (効いているチェックとパラメータ) / `init` (日単位の分割と `--resume`) / `doctor` / `run` / `collect` / `evaluate` / `report` (`--from --to` / `--month` で期間レポート) / `review` / `approve` / `ack` / `snooze` / `resolve` / `help ai`
- allowlist: `principals[]` の `arn` / `account` (アカウント単位) / `arn_pattern` (glob)、`tags` は `deploy` / `ai`、`expected_denied` (access_denied で数えない想定済みの拒否。ADR 0022)、
  `assume_destinations[]` (外向きの引き受けで行き先として既知のアカウント。そこへの MFA ありの引き受けを unknown_assume_role が報告しない。ADR 0047)
- ack / snooze 中の finding も、重大度が上がれば changed として再報告する (ADR 0022)

## AI (LLM) から使う

`arata help ai` を最初に読ませる (report の読み方は `arata help ai report`、承認判断は `arata help ai approve`、チェックごとの対処手順は `arata help ai playbook <check>`、`--format json` も可)。
内容はバイナリに埋め込まれていて、エンジンの版と常に揃う。
チェックが skip される・解釈率が低いなど、記録が足りないときは `arata help ai logs` (チェックと記録の対応表、ログの出し方) を読ませる。
GitHub Actions で動かす利用者の環境 (リポジトリの設定・OIDC の信頼・secrets) を作る・見直すときは `arata help ai runtime` を読ませる (チェックリスト。設定を変えるのは人)。

## 通知 (aratam)

`aratam` は arata の出力ディレクトリ (`report.json` / `report.md`) を読み、LLM で要約して Slack (Incoming Webhook か、bot トークンとチャンネル ID) に送る別コマンド。
arata を呼ばず、AWS の監査ロールもストアも使わない (出力ディレクトリだけで連携する。設計は [docs/aratam.md](docs/aratam.md)、経緯は ADR 0018)。

- 送り先と「静か」の判定は規則で固定する。`max_severity` が `urgent_severity` 以上か取れなかったソースがあれば緊急用、report.json が無い・古ければ「arata が実行されていない」と緊急用に送る
- 通知は Slack の Block Kit (`slack.format: blocks`。ADR 0029)。見出し・件数のあとに、`urgent_severity` 以上を「まず対応」(1 件ずつ「→ 何をするか」付き)、
  それ未満を「確認推奨」(同じチェックの指摘は規則で 1 項目にまとめ、主体を並べる) に分ける。`slack.format: text` で v0.3.0 までの mrkdwn の本文も選べる (v0.4.0 から `slack.format` は必須)
- LLM が書くのは要約 1〜2 文と「まず対応」の「→」だけ (text のときは分類と説明)。重大度・件数・まとめ方は規則で、report.json の値を表示する。
  LLM が使えなければ規則だけで組み立てた通知を送る (text のときは原文)
- 指摘の行の末尾に finding の ID を `` `id: 7f16a4507445` `` の形で出す (blocks・text とも。まとめた項目は主体と同じ順に 5 個まで)。
  `arata ack / snooze / resolve <ID>` や作業の記録に、`arata review` を引かずに結びつけられる。値は report.json のもので、LLM には書かせない (docs/aratam.md 3-5 章)
- 通知の時刻は `timezone` (IANA 名。例 `timezone: Asia/Tokyo`) に書いたゾーンで出す。書かなければ UTC。変わるのは表示だけで、arata の集計は UTC のまま。
  日付だけの値 (日次集計の日、期間レポートの期間) は UTC の日なので直さず、`(UTC)` と書く。タイムゾーンのデータはバイナリに埋め込んである (docs/aratam.md 4-3 章)
- LLM のプロバイダ: `bedrock` (Converse。`bedrock:InvokeModel` だけ要る) / `claude-cli` (`claude -p` をツール無し・ユーザー設定を読まず・空の一時ディレクトリで起動) / `none` (LLM を呼ばない)
- Slack への送り方は 2 つのうち 1 つ (両方を書くと設定エラー。docs/aratam.md 4-1 章)。
  - Incoming Webhook (`slack.webhook_env`): チャンネルごとに URL (秘密) が要る
  - bot トークン (`slack.bot_token_env` と `slack.channel`): 秘密はトークン 1 つで、送り先はチャンネル ID (秘密ではない) を設定に書く。
    監査対象ごとにチャンネルを分けても秘密が増えない。要る scope は `chat:write` だけで、bot を招待したチャンネルにだけ送れる (下の「bot トークンで送る」)
- Webhook の URL と bot トークンは設定ファイルに書かず、設定に書いた名前の環境変数で渡す。秘密をどこに置き、どう環境変数に入れるかは実行環境が決める (ADR 0044)。
  LLM に渡すデータは report.json (と下の提案の候補・前提) だけ
- weekly の report.json に WAF の修正提案の候補 (`proposals`) があれば、「WAF の改善提案」を 2 通目として通常用に送る (ADR 0024)。
  種類・段階・根拠の数字は規則で書き、LLM は候補だけを受け取って「何を・なぜ・進め方・設定例」を書き起こす (候補に無い提案・BLOCK に強める提案は捨てる。observation は LLM に渡さない)。
  Block Kit では提案 1 件を 4 行 (種類と数字・なぜ困るか・「→ 次の一手」(WebACL・ルール・パス・確認方法まで具体的に)・根拠) にし、全文と設定例は `--in` のディレクトリの `waf-proposals.md` に書き出す
- `llm.context_file` にアプリの事情 (決済画面はリクエストが多い、監視の送信元など) を Markdown で書くと、LLM に「この監査対象の前提」として渡す。
  判定 (重大度・送り先) は変わらない。例は [examples/aratam-context.md](examples/aratam-context.md) (架空の値)。利用者の環境に置き、16 KiB まで

はじめての手順 (arata の `init` と最初の `run` が済んでから):

1. `aratam config init` で雛形を書き出し、Webhook (か bot トークン) の環境変数を用意して `aratam doctor` → `aratam test-notify`
2. LLM を使うなら `llm.provider` を `none` 以外にする
3. **最初の通知の前に、`llm.context_file` (この監査対象の前提) を書く**。無くても動くが、無いと LLM はアプリの事情を知らず、正規の動作にも一般的で慎重な助言しか書けない。
   書くとよいのは、どのアプリが本番か、デプロイの流れ (どの主体が何を引き受けるか)、起動時に秘匿値をまとめて読むロール、正規の送信元、監査の仕組み自体を誰が置いたか。
   AI (LLM) に下書きさせるなら `arata help ai runtime` を読ませ、読み取り専用ロールで読める構成から書かせて、人が事実を確かめる。事実が変わったら直す
4. **最初の run は通知せずに中身を見る**。`init` は finding を出さないが、その後の最初の run は長く溜まっていた設定や主体が一度に出て、通知が多くなり得る。
   手元で `arata run --out <dir>` → `aratam notify --in <dir> --dry-run` で見て、approve・ack・resolve で片付けてから定期実行につなぐ
   (ここは `arata run --dry-run` ではなく、ふつうの run にする。試しの実行はストアに書かないので、指摘が報告済みにならない)
   (run はストアに確定するので、以後の定期実行は新しく起きたことだけを報せる。daily と weekly の両方で行う)。
   片付ける順番と ack / snooze の選び方は `arata help ai onboarding`
   (チェックやソースを後から足すときも同じ順で進める。その流れと、設定の値を実データで決める方法も同じ文書)

```sh
aratam config init                          # ./aratam.yaml (全項目を明示した雛形。provider は none)
export ARATAM_SLACK_WEBHOOK='https://hooks.slack.com/services/...'
aratam config check                         # 設定の形だけを検査 (Slack・LLM に繋がない。PR の CI 向け)
aratam doctor                               # Webhook の環境変数 (bot トークンなら auth.test) と LLM の疎通 (送信はしない)
aratam test-notify                          # Slack に試験メッセージを 1 通 (--urgent で緊急用)
aratam notify --in /var/lib/arata/out/daily --dry-run   # 送らずに標準出力へ (LLM は呼ぶ。--llm none で呼ばない)
aratam notify --in /var/lib/arata/out/daily --dry-run --format json   # Slack に送る payload (blocks) そのもの
```

#### bot トークンで送る

Slack アプリは、利用する組織が manifest から自分で作る (Slack のワークスペースごとに 1 つ)。arata は公開配布のアプリを持たない
(配布用のアプリにすると、インストールを受けるサーバーと各組織のトークンを開発側が預かることになる。トークンを持つのは、アプリを入れた組織だけにする)。

1. <https://api.slack.com/apps> →「Create New App」→「From a manifest」→ ワークスペースを選び、[deploy/slack/app-manifest.yaml](deploy/slack/app-manifest.yaml) の中身を貼る
   (bot の scope は `chat:write` だけ。受け口を持たない、投稿だけのアプリ)
2. 「Install to Workspace」で入れ、「OAuth & Permissions」の Bot User OAuth Token (`xoxb-` で始まる) を、aratam を動かす環境の秘密に入れる
3. 通知先のチャンネルで `/invite @arata` を実行する (緊急用のチャンネルを分けるなら、そちらでも)。招待していないチャンネルには送れない
4. チャンネル ID (チャンネルの詳細の一番下。`C0123456789` の形) を設定に書く

```yaml
# aratam.yaml (抜粋)
slack:
  webhook_env: ""                         # bot トークンを使うなら Webhook の 2 つは空にする
  urgent_webhook_env: ""
  bot_token_env: ARATAM_SLACK_BOT_TOKEN   # 環境変数の名前 (トークンは書かない)
  channel: C0123456789                    # 通常用のチャンネル ID
  urgent_channel: C0123456780             # 緊急用。空なら channel に送り、冒頭に urgent_mention を付ける
```

```sh
read -rs ARATAM_SLACK_BOT_TOKEN && export ARATAM_SLACK_BOT_TOKEN   # 貼り付けて Enter (シェルの履歴に残さない)
aratam doctor                               # auth.test でトークンが有効かを見る (投稿はしない。bot がチャンネルにいるかは分からない)
aratam test-notify                          # 実際に 1 通送る。not_in_channel なら、そのチャンネルで /invite @arata
aratam test-notify --urgent
```

GitHub Actions で動かしているなら、同じ確認を Actions の画面から行える (見本の [arata-notify-test.yml](examples/github-actions/arata-notify-test.yml)。監査は回さない)。
通知先のチャンネルを足したとき、トークンを入れ替えたときに使う。

- 同じワークスペースの複数のチャンネルに送るなら、アプリもトークンも 1 つでよい。監査対象ごとの `aratam.yaml` でチャンネル ID を変える。
  別の組織と Slack Connect で共有するチャンネルも、招待すれば同じアプリで送れる
- トークンのローテーションは有効にしない (manifest は無効)。有効にするとトークンが 12 時間で切れるが、aratam は更新の仕組みを持たない
- Slack は HTTP 200 でも失敗を返すので、aratam は応答の `ok` を見て、失敗は終了コード 5 にする。`ratelimited` だけは `Retry-After` を待って 2 回まで送り直す

cron では arata の後につなぐ。同じ run は `.aratam-notified` で二重に送らない (`--force` で再送)。

```cron
0 9 * * * arata run -c /etc/arata/arata.yaml --profile daily --out /var/lib/arata/out/daily; aratam notify -c /etc/arata/aratam.yaml --in /var/lib/arata/out/daily
```

終了コード: 0 = 送った (または送る必要が無かった)、2 = 設定エラー、3 = LLM が使えず規則だけの通知 (text なら原文) を送った、4 = 入力が無い・古い (その旨は送った)、5 = 送信に失敗した。

## 取得 (リリース版のバイナリ)

`v*` タグを push すると GitHub Actions ([.github/workflows/release.yml](.github/workflows/release.yml)) が arata と aratam の linux/arm64・amd64 の静的バイナリを作り、
`SHA256SUMS` とバイナリごとの SBOM (`<バイナリ名>.spdx.json`、SPDX JSON) と共に [GitHub Releases](https://github.com/CircleAround/arata/releases) に添付する。

```sh
VERSION=v0.5.0                      # 使う版
ARCH=arm64                          # amd64 なら amd64
BASE=https://github.com/CircleAround/arata/releases/download/${VERSION}
curl -sSLO "${BASE}/arata-linux-${ARCH}" -O "${BASE}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS   # arata-linux-${ARCH}: OK を確かめる
install -m 0755 "arata-linux-${ARCH}" /usr/local/bin/arata
arata --version
# aratam も同じ手順 (aratam-linux-${ARCH})
```

リリースの作り方: main で `git tag -a v0.2.0 -m "..." && git push origin v0.2.0` (タグ名がそのまま `arata --version` に入る)。

### 来歴の検証 (build provenance attestation)

公開リポジトリ (または GitHub Enterprise Cloud) では、release がバイナリと SBOM に build provenance attestation を付ける。
取得したバイナリがこのリポジトリの release ワークフローで作られたことを `gh` で確かめられる:

```sh
gh attestation verify "arata-linux-${ARCH}" -R CircleAround/arata \
  --signer-workflow CircleAround/arata/.github/workflows/release.yml
```

**v0.5.0 までの版には来歴証明が付いていない** (リポジトリが非公開の間に作ったため、attestation のステップはスキップされた)。それらの版は上の `SHA256SUMS` で照合する。2026-11-09 の公開の後に作る版から付く。

## 開発

### Go のインストール (sudo 不要)

公式 tarball を `$HOME/.local/go` に展開する。ホストが linux/arm64 の場合:

```sh
GO_VERSION=1.27.4
curl -sSLo /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz"
mkdir -p "$HOME/.local" && rm -rf "$HOME/.local/go" && tar -C "$HOME/.local" -xzf /tmp/go.tgz
export PATH="$HOME/.local/go/bin:$PATH"   # シェルの rc に追記する
go version
```

amd64 なら `linux-amd64` に読み替える。チェックサムは https://go.dev/dl/ で確認できる。
`Makefile` は `$HOME/.local/go/bin/go` があればそれを、無ければ `PATH` 上の `go` を使う。

### ビルド・テスト

```sh
make test          # go test ./... (ユニット + コマンドレベルの e2e)
make lint          # go vet + golangci-lint (入っていれば。gosec・staticcheck。CI の sast.yml と同じ設定)
make fuzz          # ファズテストを対象ごとに 30 秒ずつ探索する (FUZZTIME=2m で変える。docs/fuzzing.md)
make build         # bin/{arata,aratam}-linux-{arm64,amd64} (CGO_ENABLED=0 の静的バイナリ)
make build-local   # このホスト向けの bin/arata と bin/aratam
```

CI は [.github/workflows/test.yml](.github/workflows/test.yml): `go mod verify` → age-gate → go vet → go test → govulncheck → make build。
`go test` はファズテストの seed と `testdata/fuzz` の入力も走らせる。新しい入力の探索は週 1 回の [fuzz.yml](.github/workflows/fuzz.yml) が行う ([docs/fuzzing.md](docs/fuzzing.md))。

### 環境変数 (.env)

Slack の Webhook や bot トークンなど、値をリポジトリに書けないものは `.env` (git の管理外) に置く。書く項目は [.env.sample](.env.sample)。
使うときは `set -a; . ./.env; set +a`。Webhook の URL や bot トークンは知っている人が誰でも投稿できるので、リポジトリ・PR・Issue に貼らない。

サプライチェーン対策 (ADR 0017・0035。点検の結果と運用は [docs/supply-chain.md](docs/supply-chain.md)):

- Actions は 40 桁の SHA で固定し、版をコメントに書く。ワークフローは最小権限の `permissions:`。
  CI の `tools/actionsgate` が固定・版の一致・公開から 7 日を確かめ、actionlint と zizmor がワークフローを検査する
- 依存は公開から 7 日待つ。Dependabot ([.github/dependabot.yml](.github/dependabot.yml)) は cooldown 7 日で提案し、CI は
  `go list -m -json all | go run ./tools/agegate -days 7` で indirect を含む全モジュールの公開時刻を確かめて、7 日未満なら落ちる。
  手で `go get` するときも 7 日以上前の版を選ぶ (`curl -s https://proxy.golang.org/<module>/@v/<version>.info` の `Time`)
- 標準ライブラリで無理なく書けるものは依存にしない (CLI は標準の `flag`、レート制限は自前。SQLite は残す。ADR 0019)

ゴールデンファイル (`internal/report/testdata`, `internal/scaffold/testdata`, `cmd/arata/testdata`) は `report.json` / `report.md` / 設定の雛形 / `doctor` / `profiles` の表の構造を固定している。
構造を意図して変えたときは差分を確認してから `go test ./internal/report ./internal/scaffold ./cmd/arata -update` で更新する。

### はじめての手順 (config init → doctor → init → run)

arata は実行時に暗黙の既定を持たない。**実行されるのは設定の `profiles` に書いたチェックだけ**なので、まず推奨設定の雛形を書き出して編集する
(雛形は全プロファイル・全チェック・各チェックの既定パラメータをコメント付きで明示する。ADR 0014)。

```sh
cd /path/to/target
arata config init --audit-account none   # 雛形を ./arata.yaml に書き出す (既存ファイルは --force が無ければ上書きしない。標準出力へは --out -)
#   --audit-account は必須 (下の「監査する側のアカウント」)。別のアカウントから監査するなら none の代わりにその 12 桁の ID
# name / store / sources (cloudwatch-logs はコメントの例を外す) を編集する
arata doctor                      # 権限・ロググループ・解釈率を検査 (問題があれば終了コード 2。足りない記録の出し方は arata help ai logs)
arata init --window 7d            # ベースライン収集 (findings は出さない)。終わると次の手順を表示する
arata run --profile daily --out /tmp/arata-out   # 最初の run は通知をつながずに流し、arata review で 1 件ずつ片付ける (流れは arata help ai onboarding)
arata run --profile daily --dry-run --window 1h --out /tmp/arata-try   # 試しの実行: ストアに何も書かず、いま流したら何が出るかを見る (下の「試しの実行」)

arata profiles                    # プロファイルごとに実際に走るチェックとパラメータ、その由来 (overrides / checks: / 既定値)
arata config init --diff          # 版を上げたら: 入っていないチェック・既定値と違う値・未知のキー・選んでいない audit_account
arata config check                # 設定と allowlist.yaml の形だけを検査 (AWS・ストアに繋がない。PR の CI 向け。問題があれば終了コード 2)
```

#### 監査する側のアカウント (`--audit-account`)

`arata config init` は、監査する側のアカウントを必ず選ばせる (既定は無い。選ばなければエラー。ADR 0045)。選んだ結果は設定の `audit_account` に残る。

| 指定 | 構成 | init が書くもの |
|---|---|---|
| `--audit-account 111122223333` | 別のアカウント (例 `111122223333`) のロールが、監査対象の読み取り専用ロール (`deploy/iam/readonly-role.yaml`) を引き受けて監査する | 設定に `audit_account: "111122223333"`、既知リスト (`allowlist.yaml`) の `principals` に `account: "111122223333"` (理由の note つき) |
| `--audit-account none` | 外から監査しない (監査対象と同じアカウントの中で動かす・手元の認証で直接動かす) | 設定に `audit_account: none`。既知リストには書かない |

- 別のアカウントからの引き受けは、監査対象の CloudTrail に「外部アカウント 111122223333 が読み取り専用ロールを引き受けた」と毎回記録される。
  既知リストに無いと `unknown_assume_role` が監査そのものを high で報告するので、init の時点で書く
- 既知リストが既にあれば末尾に足すだけで、ほかの行は変えない。`approved_by` は `--by alice` を付けたときだけ書く
- `--audit-account` に監査対象のアカウント自身の ID を書いてはいけない (`account:` がそのアカウントの全主体を承認してしまう。`arata doctor` が確かめる)。
  同じアカウントの中の実行用ロールが読み取り専用ロールを引き受けるなら、その実行用ロールを `arn:` で既知リストに書く
- `arata config check` (オフライン) は、`audit_account` に ID を書いたのに既知リストに期限内の `account:` が無ければ ng (終了コード 2) にする
- **この項目より前の版で作った設定**: `audit_account` が無くても `run` / `doctor` は今までどおり動く。`config check` は warn (終了コード 0)、
  `config init --diff` は `[missing_key] audit_account` を出す。設定に `audit_account: none` か `audit_account: "<12 桁の ID>"` を 1 行足せば消える
  (ID を書くなら既知リストにも `account: "<同じ ID>"` を足す)

設定ファイルは `-c` (`--config`) で指定する。省略時は環境変数 `ARATA_CONFIG`、それも無ければカレントディレクトリの `./arata.yaml` を読む
(`-c` > `ARATA_CONFIG` > `./arata.yaml`)。どれも無ければ探した場所を並べて `CONFIG_INVALID` (終了コード 2)。
定期実行では `-c /path/to/target/arata.yaml` か `ARATA_CONFIG` で明示するとよい。以下の例は `-c` を省略している。

- どのプロファイルにも入っていないチェックがあると、`run` / `evaluate` / `doctor` が `CHECK_UNUSED` を警告する
- `profiles.<name>.overrides.<check>` でそのプロファイルだけ判定の閾値を変えられる (`min_count` など)。集計条件 (`paths` / `statuses` など) は
  全プロファイルで共有する日次集計に効くので `checks:` でだけ変える
- `default-daily` のような省略記法も書けるが、版が上がって増えたチェックが黙って入るので雛形では使わない

### サンプル設定で動かす

`examples/arata.yaml` と `examples/allowlist.yaml` を顧客ごとのディレクトリにコピーして編集してもよい (雛形より短い、アプリ層を含む例)。
AWS の認証は SDK の標準チェーン (環境変数 / `~/.aws/config` の profile / ロール) に従う。読み取り専用の権限があればよい
(`cloudtrail:LookupEvents`。cloudwatch-logs ソースがあれば `logs:DescribeLogGroups`, `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`。
週次のソースは下の「週次チェック」。必要な action は `arata doctor` の表の最後に出る)。

`aws login` (ブラウザでのサインイン) のセッションは Go SDK から直接読めない。試用時は `credential_process` で CLI にクレデンシャルを出させる
profile を `~/.aws/config` に作り、設定の `aws.profile` (または `AWS_PROFILE`) で指定する。本番は Roles Anywhere / インスタンスロールを使う。

```ini
[profile trial]
region = ap-northeast-1
credential_process = aws configure export-credentials --profile <login済みprofile> --format process
```

```sh
cp examples/arata.yaml examples/allowlist.yaml /path/to/target/
cd /path/to/target
# store: の dir:// を書き込める場所に変える

arata doctor                                  # 権限・ロググループ・解釈率を検査 (問題があれば終了コード 2)
arata init     --window 7d                    # ストア作成 + ベースライン収集 (findings は出さない)
arata run      --profile daily --out /tmp/arata-out
cat /tmp/arata-out/report.md                  # 人向け。report.json は機械向け
arata report   --profile daily --format md    # 最後の run のレポートを再表示
arata run      --profile daily --dry-run --window 1h --out /tmp/arata-try   # 試しの実行 (ストアに何も書かない)
arata collect  --window 2h                    # 収集だけ
arata evaluate --profile daily                # 収集せずに評価だけ
arata rebuild                                 # raw JSONL から audit.sqlite を作り直す (findings・runs・主体の状態は引き継ぐ)
```

- `--out` を省略すると `report.json` を標準出力に出す (`--format md` で Markdown)
- 終了コード: `0` 正常 (findings の有無に関係なく)、`2` 設定 / 権限エラー、`3` 収集の一部失敗 (レポートは出す)
- エンジン自身のログは標準エラーに JSON 行で出る。`code` は設計書 2-2 の固定語彙 (`ACCESS_DENIED`, `STORE_LOCKED`, `RUN_MISSED`, `CONFIG_INVALID` など)
- `cloudtrail-lookup` は既定で `aws.region` と `us-east-1` の両方を引く (IAM / ConsoleLogin / STS の一部は us-east-1 にしか記録されない)
- `run` は前回の run の窓の終わりから追いつく (上限 `max_catchup`、既定 7d)。cron が遅れても取りこぼさないが、上限を超えた分は `RUN_MISSED` で知らせる
- **試しの実行** (`run --dry-run`。ADR 0049): 定時の前に、いま流したら何が出るかだけを見る。ストアに何も書かない (raw・SQLite・S3 のどれも変えない) ので、
  出た指摘は報告済みにならず、窓も進まず、次の定時の実行でもう一度出る。ストアは読むだけで、今の状態 (平常帯・既知の主体・指摘の状態) に対して判定する
  - `--window 1h` のように見る期間を短くできる (`--dry-run` のときだけ。省くとプロファイルの `window`)。前回からの追いつきはしない。
    CloudTrail の読み取りの時間と Logs Insights のスキャン量 (費用) が、期間に応じて減る
  - レポートには `"dry_run": true` が付き、`aratam notify` は送らない (文面は `aratam notify --dry-run` で見られる)。
    見た範囲が定時の実行より狭いときは、入っていない期間と、日次集計を使うチェックが評価しなかった日が `coverage.notes` (report.md のカバレッジ) に出る
  - 新規の指摘の id は試しの実行の中だけのもので、`arata review` / `approve` では引けない (定時の実行で付け直される)
  - AWS の読み取りは実際に行う。dir:// のストアは、複製する間だけロックを取る (書き込み中の実行がいれば `STORE_LOCKED`)
  - 導入時の「最初の run」には使わない。あれは溜まっていた指摘を報告済みにするための実行で、試しの実行では報告済みにならない
- CloudTrail は記録まで 5〜15 分、CloudWatch Logs は取り込みに数分遅れるので、`run` は各ソースの `ingest_delay` (既定 cloudtrail-lookup 15m、cloudwatch-logs 5m) だけ
  窓の前を引き直す。前回の窓の末尾に起きて遅れて記録されたイベントは次の run が拾う (前回までに収集済みのイベントは再報告しない)。
  レポートの窓 (`window.from`) は変わらないので、窓より少し前の時刻の事象が載ることがある
- `init --window` の既定は 7d。LookupEvents は毎秒 2 リクエスト・50 件/頁が上限で、エンジンはこのレートで引く (リージョンをまたいで 1 つのレート制限を共有)。
  イベントの多いアカウントでは 7 日分で数時間かかる。init は窓を UTC の日ごとに分けて古い順に引き、1 日終わるごとに進捗を記録する
  (標準エラーに `init progress`、ページ単位の進捗は 20 ページごと)。失敗や Ctrl-C で止まったら終了コード 3 になり、
  原因を直して `arata init --resume` で止まった日の頭から再開できる
- スロットル (`ThrottlingException`) は SDK の adaptive リトライ (最大 10 回) とエンジン側の再試行 (最大 5 回、指数バックオフ) で吸収する。
  それでも失敗した場合は取れた分をストアに残し、`coverage.sources_failed` と `summary.collect_errors` に `covered_from` / `covered_until` (取得できた期間) を出す。
  LookupEvents は新しい順に返すので、取りこぼすのは `covered_from` より古い側
- `init` は現在の主体をベースライン (`baseline`) として記録し、以後に現れた主体だけを `new_principal` で報告する。
  **導入時点で既に侵入している主体はベースラインに紛れる**ので、init の後に `audit.sqlite` の `principals` を一度人が眺めること
- `allowlist.yaml` は人が承認したものだけを書く
- `audit.sqlite` が壊れた・失われたときは `arata rebuild` で raw JSONL から作り直す。runs・findings (ack / snooze を含む)・主体の状態は raw に無いので
  既存の SQLite から引き継ぐ。SQLite が読めなければ `--from-scratch` (findings は空から作るので、次の run で未解決のものが全部 new として再報告される。
  主体は unknown、`--baseline` なら baseline)。元のファイルは `audit.sqlite.bak` に残る (設計書 5-4、ADR 0033)

### 承認と未対応の整理

```sh
arata review                     # 未対応 (open / acked) の一覧。APPROVE 列が approve の対象
arata approve <finding-id> --note "外注先の調査用" --expires 2026-12-31 [--tag deploy] [--commit]
arata approve <finding-id> --destination --note "運用を受託しているアカウント" [--expires 2027-03-31]   # 主体ではなく、外向きの引き受けの行き先を既知にする
arata ack     <finding-id>       # 確認済み。再報告しないが一覧には残る
arata snooze  <finding-id> --until 2026-11-01
arata resolve <finding-id>
```

- `approve` は allowlist.yaml の principals の末尾に追記する (他の行・コメント・空行は変えない)。git への commit は人が行う。`--commit` は allowlist.yaml だけを commit する
- SaaS 連携 (監視 SaaS など) のクロスアカウント AssumeRole は「外部アカウント NNN」と表示され、approve すると `account: "NNN"` で承認される
- 社員が別のアカウント (受託先など) のロールに MFA 付きでスイッチロールするのが通常業務なら、社員を承認するのではなく、行き先のアカウントを既知にする
  (`approve --destination`、または allowlist.yaml の `assume_destinations` に書く。ADR 0047)。

  ```yaml
  assume_destinations:
    - account: "111122223333"        # 行き先のアカウント。principals の account: (呼び出し元の承認) とは別
      note: 運用を受託しているアカウント   # 必須
      approved_by: alice
      approved_at: 2026-11-13
      expires: 2027-03-31            # 任意。roles: ["ReadOnly"] でロールに絞れる
  ```

  報告されなくなるのは「外向き・そのアカウントのロール・MFA あり」の全部を満たす引き受けだけ (行き先ごとに info の 1 行で件数を残す)。
  知らないアカウントへの引き受けと、MFA なし・不明の引き受けは high のまま。社員を承認すると、知らないアカウントへの引き受けまで止まる。
  MFA 済みのセッションを奪われた場合は見えないので principal_new_source と併せて使い、契約が終わったら項目を消す
- 主体に関しない finding (root_usage やアプリ層) は approve できない。ack / snooze / resolve を使う
- LLM には approve を実行させず、人に提案させる (`arata help ai approve`)

### 週次チェックと期間レポート

雛形の `sources` にある `iam-credential-report` / `guardduty` / `access-analyzer` / `posture` は、アカウントの今の状態を取って前回と比べる
(weekly プロファイルの run でだけ取る。hourly / daily では API を呼ばない)。必要な IAM action:

| source.kind | action |
|---|---|
| `iam-credential-report` | `iam:GenerateCredentialReport` (**書き込み系**: レポートの生成のみ)、`iam:GetCredentialReport` |
| `guardduty` | `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings` |
| `access-analyzer` | `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindings` |
| `posture` | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `guardduty:ListDetectors`, `guardduty:GetDetector`, `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `s3:GetAccountPublicAccessBlock`, `elasticloadbalancing:DescribeLoadBalancers`, `wafv2:GetWebACLForResource` |
| `waf-config` | `wafv2:ListWebACLs`, `wafv2:GetWebACL`, `wafv2:GetLoggingConfiguration`, `wafv2:ListResourcesForWebACL` (REGIONAL は `regions`、CLOUDFRONT は us-east-1) |

daily のソースのうち、追加の権限が要るもの:

| source.kind | action | 費用 |
|---|---|---|
| `cloudtrail-unused-regions` | `account:ListRegions`、`cloudtrail:LookupEvents` (有効なリージョン − `cloudtrail-lookup` の `regions` の各リージョン) | 無料 |
| `cost-anomaly` | `ce:GetAnomalyMonitors`, `ce:GetAnomalies` (us-east-1) | Cost Explorer の API は 1 リクエスト 0.01 USD。1 回の run で約 2 回 (daily で月 0.6 USD ほど。`arata doctor` の cost に出る) |

- 既に配ったロールには上の 3 つの action を足す必要がある (無ければそのソースだけが ACCESS_DENIED になり、そのチェックが skip される)。
  `cost_anomaly` は Cost Anomaly Detection のモニター (無料) が無ければ skip される (doctor は warn)
- `iam:GenerateCredentialReport` だけは書き込み系。読み取り専用ロールで拒否されても、4 時間以内に生成済みのレポートがあればそれを使う (生成時刻は finding の Data に残る)
- 権限が足りないソースのチェックだけが skip され、他は続行する (coverage と doctor に不足 action が出る)。前回の指摘は「解消」にならない。
  posture は一部の項目だけ取れなければ取れた項目で評価する (終了コード 3)
- GuardDuty が無効なら guardduty_findings は skip され、posture が「GuardDuty が有効でない」と報告する。アナライザーが無ければ access_analyzer は skip
- `waf_review` (WAF の修正提案の候補) は `waf-config` と wafv2 の `cloudwatch-logs` ソースの両方が要る。daily が貯めた wafv2 の日次集計を読むだけで、
  weekly の run は WAF のログを引かない。候補は report.json の `proposals` に出る (適用は人が判断する。`arata help ai report`)。
  既に配ったロールには wafv2 の 4 つの action を足す必要がある (無ければ waf-config だけが ACCESS_DENIED になり、waf_review が skip される)
- posture は、インターネット向けの ALB に WAF (WAFv2 の WebACL) が付いていなければ ALB ごとに medium で報告する (`alb_waf|<region>|<ALB>`。WebACL を付ければ次の weekly で解消)。
  既に配ったロールには `elasticloadbalancing:DescribeLoadBalancers` と `wafv2:GetWebACLForResource` を足す必要がある (`deploy/iam/readonly-role.yaml` でスタックを更新する。
  無ければこの項目だけが取れず、coverage に `partial: true` と不足の action が出て終了コード 3。他の項目は評価される)
- 監査ロールや AI 用の主体を allowlist で `tags: [ai]` にすると、`ai_path_usage` (daily) が利用を主体 × 送信元 IP で毎回 info に 1 行出す (自己監査)

```sh
arata run    --profile weekly --out /tmp/arata-weekly
arata report --month 2026-10 --format md             # 月次 (ストアだけから作る。収集しない)
arata report --from 2026-10-01 --to 2026-12-31 --out /tmp/arata-q4
```

期間レポートには期間内の new / recurred / changed / resolved、重大度別件数、新規主体、未対応の残存、アプリ層の日次推移、取れなかった run (partial / failed / RUN_MISSED) が入る。
状態遷移の履歴はこの版で最初に run した時点から記録されるので、それより前にかかる期間は先頭に注意書きが出る。

### S3 ストア (任意)

GitHub Actions のように毎回消える環境で定期実行するときだけ使います。`dir://` のままなら準備は要りません。 ワークフローの見本と手順は [examples/github-actions](examples/github-actions/README.md) にあります。OIDC プロバイダ・バケット・実行用ロールは [deploy/github-actions/runner.yaml](deploy/github-actions/runner.yaml) (素の CloudFormation) で置けます。

```yaml
store: s3://example-arata-store/my-service
# store_profile: arata-store   # バケットを書く認証。省略時は SDK の標準の連鎖 (aws.profile は使わない)
# store_region: ap-northeast-1 # 省略時は aws.region
```

実行のたびに SQLite (`audit.sqlite.gz`) と `reports/` を一時ディレクトリへ取得し、raw は追記する日のファイルだけを取得します。
成功したら変わったものを条件付きで書き戻し、失敗・中断したら何も送りません (S3 は開始前のまま。次の run がやり直します)。

- **読み取り専用との区別**: 「arata は読み取り専用」は**監査対象のアカウント**への約束です。ストアのバケットは arata を動かす側が用意するもので、arata はここに書きます。できれば監査対象とは別のアカウントに置いてください
- **権限**: `s3:GetObject`・`s3:PutObject` (prefix に限定)、`s3:ListBucket` (バケットに対して)。条件付きの書き込みにも `s3:GetObject` が要ります。`s3:ListBucket` は `s3:prefix` で絞りません (無いキーが 403 になると arata が「無い」と区別できないおそれがあるため)。監査対象の読み取りロールには付けません
- **バケットの推奨**: バージョニング (誤った上書きから戻す)、暗号化 (SSE-S3 か SSE-KMS)、パブリックアクセスブロック。Object Lock は任意です。`arata doctor` が満たしていないものを warn で示します (確かめる権限が無ければ飛ばします。書き込みは試しません)
- **同時に動いたとき**: 後から終わったほうが `STORE_CONFLICT` (終了コード 2) で失敗し、何も上書きしません。もう一度実行してください。人の `ack` と定時の run が重なったときも同じです。衝突した run は report を出さないので、aratam が「出力が無いか古い」として緊急用に知らせます (`--out` が残る環境では `max_age` を超えたとき)
- **SQLite が壊れた・失われた**: `arata rebuild --from-scratch` で raw から作り直せます。バージョニングがあれば前の版にも戻せます。raw があるのに SQLite が無いと、書き込み系のコマンド (`init` を含む) は `STORE_CORRUPT` で止まります (状態を空で上書きしないため)。`report` / `review` は警告して続き、`doctor` は ng で示します。最初の `init` で SQLite の送信だけが失敗したときも同じ状態になるので、`arata rebuild --from-scratch --baseline` で続けてください
- **中断したとき**: `INTERRUPTED` (終了コード 2) で止まり、S3 には保存しません。もう一度実行してください

### アプリ層 (CloudWatch Logs) を足す

`sources` に `kind: cloudwatch-logs` を足し、ロググループと形式プロファイルを紐付ける (examples/arata.yaml)。生ログは引かず、
Logs Insights の集計クエリで日次集計 (IP 別の sign-in 失敗数など) だけを `metrics` に貯める。スキャン量課金なので次に注意する。

- どの記録があればどのチェックが動くか、ALB・WAF・nginx・アプリのログの出し方、保存期間と費用の目安、よく詰まる点は `arata help ai logs` にまとめてある
  (人が読んでもよい。doctor は足りない記録の行に、読む節を示す)。
- まず `arata doctor` で、ロググループの有無・直近 100 行の解釈率・集計クエリが Insights に受理されるかを確かめる。
  解釈率が `expected_match_rate` (既定 0.8) 未満なら形式の指定 (`format` / `fields` / `regex` / `stream_prefix`) を見直す
- 集計クエリは窓に重なる UTC 日の 0 時から引くので、1 回のスキャンは最大で窓 + 24h 分。`max_scan_gb` でソースごとに上限を付けられる (超えたら `QUERY_LIMIT`)
- WAF のログ (wafv2) は大きく、集計クエリも多い (範囲 4 本分)。範囲は実行時刻で決まり、daily を UTC 0 時過ぎ (doctor が時刻を案内する) に回すと半分ほどになる。`arata doctor` の `cost` の行に 1 日・30 日の概算と `max_scan_gb` の推奨値が出るので、必ず `max_scan_gb` を設定する
  (1 日のスキャン量は直近 24h の集計で実測するので、doctor 1 回で 1 日分の読み取りの費用がかかる。`--no-measure-scan` で推定に切り替えられるが少なく出る)
- 1 つの WebACL を本番と staging の資源が共有しているなら、wafv2 のソースの `resources` (ログの `httpSourceId`。glob 可) で本番だけを集計する。
  doctor が WebACL の資源と突き合わせる。絞ってもスキャン量 (費用) は減らない
- hourly プロファイルに `login_bruteforce` などを入れなければ hourly では Insights を回さない
- 実行のたびに解釈率を測り、閾値未満は `FORMAT_MISMATCH` (そのソースは失敗扱い、終了コード 3)、直近 7 回平均から 20pt 以上の急落は `FORMAT_DRIFT` (警告)。
  `FORMAT_MISMATCH` のログには解釈できなかった行の例 (メールアドレスをマスク、200 文字まで) が付く。個人情報を含み得るログでは `sample_lines: false` にする
- 平常帯は直近 14 日の中央値なので、導入後 1〜2 週間は「閾値 (min_count) 超え」だけが鳴る。「Top IP 初出」「新規 WAF ルール」は過去 7 日分のデータが貯まってから判定する
- 日次集計の日は UTC

### ディレクトリ

```
cmd/arata/              CLI。main_test.go がコマンドレベルの e2e
cmd/aratam/             arata の出力を要約して通知するコマンド (docs/aratam.md)
internal/subcmd/        標準の flag の上の小さなコマンド層 (arata と aratam が共有)
internal/config/        YAML 設定
internal/scaffold/      設定の雛形 (config init) と雛形との差分
internal/store/         Store インターフェース、SQLite + JSONL の dir バックエンド、それを出し入れする s3 バックエンド
internal/collect/       Collector インターフェース、cloudtrail/ (LookupEvents)、cwlogs/ (Logs Insights・形式プロファイル)、account/ (認証情報レポート・GuardDuty・Access Analyzer・姿勢)
internal/record/        正規化レコード (trail_event, principal_seen, metric)
internal/checks/        Check インターフェース、差分判定、各チェック (1 ファイル 1 チェック)
internal/allowlist/     既知リストの読み込みと approve の追記
internal/report/        report.json / report.md (型は schema/ に置き、aratam と共有)
internal/notify/        aratam の設定・入力の検査・振り分け・LLM 出力の検証と組み立て
internal/llm/           aratam の LLM プロバイダ (claude-cli / bedrock)
internal/slack/         Slack への送信 (Incoming Webhook、bot トークンの chat.postMessage)
internal/engine/        collect → evaluate → report の束ねと doctor (CLI と Lambda が共用)
docs/ai/                arata help ai の文書 (embed でバイナリに入る)
examples/               設定サンプル
deploy/iam/              顧客に配る読み取り専用ロール (素の CloudFormation)
deploy/slack/            aratam の通知用の Slack アプリの manifest (bot の scope は chat:write だけ)
deploy/sandbox/          試験環境 (sandbox。開発用アカウントに CDK で作る。deploy/sandbox/README.md、ADR 0020)
```

## ライセンスと脆弱性の報告

MIT License (`LICENSE`)。脆弱性は公開の Issue ではなく、非公開の報告で知らせてください (`SECURITY.md`)。
