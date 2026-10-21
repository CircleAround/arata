# arata

AWS のログと設定を定期的に改め、**前回から新しく発生したもの** (新規の主体・送信元・設定変更・findings) を報せる監査エンジン。
名前は「改め」と「新た」から。

- 収集 → 保存 → 差分判定 → レポート生成までを担う。通知・起動・LLM による要約は組み込み側の仕事
  (標準品として、出力を要約して Slack に通知する別コマンド `aratam` を同梱する。[下記](#通知-aratam))
- Go 製の単一バイナリ。オンプレの cron でも AWS Lambda でも同じバイナリで動く
- 顧客ごとの差は設定ファイル (ロググループと形式プロファイルの紐付け、既知リスト、閾値) に閉じ込める

設計は [docs/design.md](docs/design.md)、判断の経緯は [docs/adr](docs/adr/README.md) を参照。

## 現在の実装範囲 (設計書 10 章の Step 1〜3)

- ソース: `cloudtrail-lookup` (CloudTrail LookupEvents)、`cloudwatch-logs` (Logs Insights の集計クエリ。形式プロファイル `nginx_access` / `alb_access` / `wafv2` / `json` / `regex`)、
  アカウント単位の状態 `iam-credential-report` / `guardduty` / `access-analyzer` / `posture`
- チェック: `root_usage`, `unknown_assume_role`, `new_principal`, `iam_changes`, `login_bruteforce`, `probe_paths`, `waf_block_trend`, `ai_path_usage` (daily)、
  `credential_hygiene`, `guardduty_findings`, `posture`, `access_analyzer` (weekly)
- ストア: `dir://` (JSONL 原本 + SQLite)
- CLI: `config init` (推奨設定の雛形と `--diff`) / `profiles` (効いているチェックとパラメータ) / `init` (日単位の分割と `--resume`) / `doctor` / `run` / `collect` / `evaluate` / `report` (`--from --to` / `--month` で期間レポート) / `review` / `approve` / `ack` / `snooze` / `resolve` / `help ai`
- allowlist: `principals[]` の `arn` / `account` (アカウント単位) / `arn_pattern` (glob)、`tags` は `deploy` / `ai`

## AI (LLM) から使う

`arata help ai` を最初に読ませる (report の読み方は `arata help ai report`、承認判断は `arata help ai approve`、`--format json` も可)。
内容はバイナリに埋め込まれていて、エンジンの版と常に揃う。

## 通知 (aratam)

`aratam` は arata の出力ディレクトリ (`report.json` / `report.md`) を読み、LLM で要約して Slack Incoming Webhook に送る別コマンド。
arata を呼ばず、AWS の監査ロールもストアも使わない (出力ディレクトリだけで連携する。設計は [docs/aratam.md](docs/aratam.md)、経緯は ADR 0018)。

- 送り先と「静か」の判定は規則で固定する。`max_severity` が `urgent_severity` 以上か取れなかったソースがあれば緊急用、report.json が無い・古ければ「arata が実行されていない」と緊急用に送る
- LLM は分類と説明だけ。重大度は report.json の値を表示し、LLM の出力から漏れた新規・変化・再発の finding は規則で末尾に足す。LLM が使えなければ原文を送る
- LLM のプロバイダ: `bedrock` (Converse。`bedrock:InvokeModel` だけ要る) / `claude-cli` (`claude -p` をツール無し・空の一時ディレクトリで起動) / `none` (LLM を呼ばない)
- Webhook の URL は設定ファイルに書かず、`slack.webhook_env` に書いた名前の環境変数で渡す。LLM に渡すデータは report.json だけ

```sh
aratam config init                          # ./aratam.yaml (全項目を明示した雛形。provider は none)
export ARATAM_SLACK_WEBHOOK='https://hooks.slack.com/services/...'
aratam doctor                               # Webhook の環境変数と LLM の疎通 (送信はしない)
aratam test-notify                          # Slack に試験メッセージを 1 通 (--urgent で緊急用)
aratam notify --in /var/lib/arata/out/daily --dry-run   # 送らずに標準出力へ (LLM は呼ぶ。--llm none で呼ばない)
```

cron では arata の後につなぐ。同じ run は `.aratam-notified` で二重に送らない (`--force` で再送)。

```cron
0 9 * * * arata run -c /etc/arata/arata.yaml --profile daily --out /var/lib/arata/out/daily; aratam notify -c /etc/arata/aratam.yaml --in /var/lib/arata/out/daily
```

終了コード: 0 = 送った (または送る必要が無かった)、2 = 設定エラー、3 = LLM が使えず原文を送った、4 = 入力が無い・古い (その旨は送った)、5 = 送信に失敗した。

## 取得 (リリース版のバイナリ)

`v*` タグを push すると GitHub Actions ([.github/workflows/release.yml](.github/workflows/release.yml)) が arata と aratam の linux/arm64・amd64 の静的バイナリを作り、
`SHA256SUMS` と共に [GitHub Releases](https://github.com/CircleAround/arata/releases) に添付する。

```sh
VERSION=v0.2.0                      # 使う版
ARCH=arm64                          # amd64 なら amd64
BASE=https://github.com/CircleAround/arata/releases/download/${VERSION}
curl -sSLO "${BASE}/arata-linux-${ARCH}" -O "${BASE}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS   # arata-linux-${ARCH}: OK を確かめる
install -m 0755 "arata-linux-${ARCH}" /usr/local/bin/arata
arata --version
# aratam も同じ手順 (aratam-linux-${ARCH})
```

非公開リポジトリの間は `gh release download "${VERSION}" -R CircleAround/arata -p "arata-linux-${ARCH}" -p SHA256SUMS` で取得する。
リリースの作り方: main で `git tag -a v0.2.0 -m "..." && git push origin v0.2.0` (タグ名がそのまま `arata --version` に入る)。

### 来歴の検証 (build provenance attestation)

公開リポジトリ (または GitHub Enterprise Cloud) では、release がバイナリに build provenance attestation を付ける。
取得したバイナリがこのリポジトリの release ワークフローで作られたことを `gh` で確かめられる:

```sh
gh attestation verify "arata-linux-${ARCH}" -R CircleAround/arata \
  --signer-workflow CircleAround/arata/.github/workflows/release.yml
```

**非公開リポジトリの間は来歴証明は付かない** (attestation のステップはスキップされる)。その間は上の `SHA256SUMS` で照合する。

## 開発

### Go のインストール (sudo 不要)

公式 tarball を `$HOME/.local/go` に展開する。ホストが linux/arm64 の場合:

```sh
GO_VERSION=1.27.3
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
make lint          # go vet + golangci-lint (入っていれば)
make build         # bin/{arata,aratam}-linux-{arm64,amd64} (CGO_ENABLED=0 の静的バイナリ)
make build-local   # このホスト向けの bin/arata と bin/aratam
```

CI は [.github/workflows/test.yml](.github/workflows/test.yml): `go mod verify` → age-gate → go vet → go test → govulncheck → make build。

サプライチェーン対策 (ADR 0017):

- Actions は 40 桁の SHA で固定し、版をコメントに書く。ワークフローは最小権限の `permissions:`
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
arata config init                 # 雛形を ./arata.yaml に書き出す (既存ファイルは --force が無ければ上書きしない。標準出力へは --out -)
# name / store / sources (cloudwatch-logs はコメントの例を外す) を編集する
arata doctor                      # 権限・ロググループ・解釈率を検査 (問題があれば終了コード 2)
arata init --window 7d
arata run --profile daily --out /tmp/arata-out

arata profiles                    # プロファイルごとに実際に走るチェックとパラメータ、その由来 (overrides / checks: / 既定値)
arata config init --diff          # 版を上げたら: 入っていないチェック・既定値と違う値・未知のキー
```

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
arata collect  --window 2h                    # 収集だけ
arata evaluate --profile daily                # 収集せずに評価だけ
```

- `--out` を省略すると `report.json` を標準出力に出す (`--format md` で Markdown)
- 終了コード: `0` 正常 (findings の有無に関係なく)、`2` 設定 / 権限エラー、`3` 収集の一部失敗 (レポートは出す)
- エンジン自身のログは標準エラーに JSON 行で出る。`code` は設計書 2-2 の固定語彙 (`ACCESS_DENIED`, `STORE_LOCKED`, `RUN_MISSED`, `CONFIG_INVALID` など)
- `cloudtrail-lookup` は既定で `aws.region` と `us-east-1` の両方を引く (IAM / ConsoleLogin / STS の一部は us-east-1 にしか記録されない)
- `run` は前回の run の窓の終わりから追いつく (上限 `max_catchup`、既定 7d)。cron が遅れても取りこぼさないが、上限を超えた分は `RUN_MISSED` で知らせる
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

### 承認と未対応の整理

```sh
arata review                     # 未対応 (open / acked) の一覧。APPROVE 列が approve の対象
arata approve <finding-id> --note "外注先の調査用" --expires 2026-12-31 [--tag deploy] [--commit]
arata ack     <finding-id>       # 確認済み。再報告しないが一覧には残る
arata snooze  <finding-id> --until 2026-11-01
arata resolve <finding-id>
```

- `approve` は allowlist.yaml の principals の末尾に追記する (他の行・コメント・空行は変えない)。git への commit は人が行う。`--commit` は allowlist.yaml だけを commit する
- SaaS 連携 (監視 SaaS など) のクロスアカウント AssumeRole は「外部アカウント NNN」と表示され、approve すると `account: "NNN"` で承認される
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
| `posture` | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `guardduty:ListDetectors`, `guardduty:GetDetector`, `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `s3:GetAccountPublicAccessBlock` |

- `iam:GenerateCredentialReport` だけは書き込み系。読み取り専用ロールで拒否されても、4 時間以内に生成済みのレポートがあればそれを使う (生成時刻は finding の Data に残る)
- 権限が足りないソースのチェックだけが skip され、他は続行する (coverage と doctor に不足 action が出る)。前回の指摘は「解消」にならない。
  posture は一部の項目だけ取れなければ取れた項目で評価する (終了コード 3)
- GuardDuty が無効なら guardduty_findings は skip され、posture が「GuardDuty が有効でない」と報告する。アナライザーが無ければ access_analyzer は skip
- 監査ロールや AI 用の主体を allowlist で `tags: [ai]` にすると、`ai_path_usage` (daily) が利用を主体 × 送信元 IP で毎回 info に 1 行出す (自己監査)

```sh
arata run    --profile weekly --out /tmp/arata-weekly
arata report --month 2026-10 --format md             # 月次 (ストアだけから作る。収集しない)
arata report --from 2026-10-01 --to 2026-12-31 --out /tmp/arata-q4
```

期間レポートには期間内の new / recurred / changed / resolved、重大度別件数、新規主体、未対応の残存、アプリ層の日次推移、取れなかった run (partial / failed / RUN_MISSED) が入る。
状態遷移の履歴はこの版で最初に run した時点から記録されるので、それより前にかかる期間は先頭に注意書きが出る。

### アプリ層 (CloudWatch Logs) を足す

`sources` に `kind: cloudwatch-logs` を足し、ロググループと形式プロファイルを紐付ける (examples/arata.yaml)。生ログは引かず、
Logs Insights の集計クエリで日次集計 (IP 別の sign-in 失敗数など) だけを `metrics` に貯める。スキャン量課金なので次に注意する。

- まず `arata doctor` で、ロググループの有無・直近 100 行の解釈率・集計クエリが Insights に受理されるかを確かめる。
  解釈率が `expected_match_rate` (既定 0.8) 未満なら形式の指定 (`format` / `fields` / `regex` / `stream_prefix`) を見直す
- 集計クエリは窓に重なる UTC 日の 0 時から引くので、1 回のスキャンは最大で窓 + 24h 分。`max_scan_gb` でソースごとに上限を付けられる (超えたら `QUERY_LIMIT`)
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
internal/store/         Store インターフェース、SQLite + JSONL の dir バックエンド
internal/collect/       Collector インターフェース、cloudtrail/ (LookupEvents)、cwlogs/ (Logs Insights・形式プロファイル)、account/ (認証情報レポート・GuardDuty・Access Analyzer・姿勢)
internal/record/        正規化レコード (trail_event, principal_seen, metric)
internal/checks/        Check インターフェース、差分判定、各チェック (1 ファイル 1 チェック)
internal/allowlist/     既知リストの読み込みと approve の追記
internal/report/        report.json / report.md (型は schema/ に置き、aratam と共有)
internal/notify/        aratam の設定・入力の検査・振り分け・LLM 出力の検証と組み立て
internal/llm/           aratam の LLM プロバイダ (claude-cli / bedrock)
internal/slack/         Slack Incoming Webhook の送信
internal/engine/        collect → evaluate → report の束ねと doctor (CLI と Lambda が共用)
docs/ai/                arata help ai の文書 (embed でバイナリに入る)
examples/               設定サンプル
```
