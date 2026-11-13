# arata を AI (LLM) から使う

## 概要

arata は AWS のログと設定を定期的に改め、**前回から新しく発生したもの**を報せる監査エンジン。
エンジンが行うのは収集・保存・差分判定・レポート生成 (report.json / report.md) まで。
通知・定期起動・要約は組み込み側 (cron スクリプトや LLM) の仕事。

LLM の役割は「危険の判定を代行する」ことではなく「人が短時間で判断できる材料に整える」こと。
判定の責任は規則 (エンジン) と人にある。LLM は allowlist を書き換えない (approve は人が実行する)。

## 概念

- **新規の二層判定**: 「新規」は 2 つの基準で決まる。
  - allowlist.yaml: 人が承認した既知リスト (git 管理)。ここにある主体は報告しない
  - 前回の観測状態 (ストア): 機械が前回見たもの。一度報告したものは翌日は鳴らない
- **baseline**: `arata init` で導入時に見えた主体。new_principal の対象外だが allowlist には入っていない。
  導入時点で侵入済みの主体も紛れるので、init 後に人が一度眺める
- **イベント型 (event)**: 窓内の出来事を報告する (root_usage, iam_changes, access_denied, unknown_assume_role, login_bruteforce など)。
  窓に現れなくても「解消」にはしない。途切れた後に再び現れたら **recurred (再発)**
- **状態型 (state)**: 今の状態を報告する (new_principal と週次の credential_hygiene / guardduty_findings / posture / access_analyzer / waf_review / log_hygiene)。観測されなくなったら **resolved (解消)**
- **週次チェックとスナップショット**: 週次はアカウントの「今の状態」(認証情報レポート・GuardDuty・Access Analyzer・姿勢) を取って前回と比べる。
  取れなかったソースのチェックは skip され、前回の finding は解消にならない (権限が外れたことを「直った」と誤認しない)。
  posture は一部の項目だけ取れなければ取れた項目で評価し、`coverage.sources_failed` に `partial: true` と `action` が出る
- **ingest_delay (再走査)**: CloudTrail / CloudWatch Logs は記録まで数分〜15 分遅れるので、run は窓の前を `ingest_delay` だけ引き直す。前回の窓の末尾の出来事が今回のレポートに入ることがある (時刻が窓の From より前でも誤りではない)
- **プロファイル**: 周期ごとの窓とチェックの組。**実行されるのは設定の `profiles` に書いたチェックだけ** (暗黙の既定は無い)。
  実際に何が走りどの閾値が効いているかは `arata profiles` で見る。どのプロファイルにも入っていないチェックは `CHECK_UNUSED` で警告される
- **重大度**: critical / high / medium / low / info。info は findings ではなく `info` 欄に入り、件数に数えない
- **coverage**: 「静かだったのは平和だからか、取れていなかったからか」を区別する欄。要約では必ず確認する
- **日付**: 日次集計 (アプリ層チェックの `date`) の日は UTC。時刻は RFC3339 (UTC)

## コマンド

| コマンド | 用途 | LLM が実行してよいか |
|---|---|---|
| `arata config init --audit-account <12 桁の ID>\|none [--out FILE]` | 推奨設定の雛形を書き出す (既定は `./arata.yaml`。`--out -` で標準出力。既存ファイルは `--force` 無しでは上書きしない)。`--audit-account` は必須で、既定は無い: 別のアカウントのロールが読み取り専用ロールを引き受けて監査するならそのアカウントの ID (allowlist.yaml にも `account:` で書く)、外から監査しないなら `none`。どちらかは人に確かめる (推測で選ばない) | 人の指示があれば |
| `arata config init --diff` | 今の設定とこの版の雛形の差分 (入っていないチェック、既定値と違う値、未知のキー、選んでいない `audit_account`) | よい (読み取りのみ) |
| `arata config check` | 設定と allowlist.yaml の形をオフラインで検査 (AWS・ストアに繋がない。`ok` / `warn` / `ng` と「ファイル:行」。問題があれば終了コード 2)。allowlist.yaml を編集したら実行する | よい (読み取りのみ) |
| `arata profiles [--format json]` | プロファイルごとに実際に走るチェックとパラメータ、その由来 (overrides / checks: / 既定値) | よい (読み取りのみ) |
| `arata doctor` | 権限・ロググループ・形式の解釈率を検査 | よい (読み取りのみ) |
| `arata init [--window 7d] [--resume]` | ベースライン収集 (findings は出さない) | 人の指示があれば |
| `arata run --profile daily --out DIR` | 収集 → 評価 → レポート | 組み込み側が定期実行する |
| `arata run --profile daily --dry-run [--window 1h] --out DIR` | 試しの実行。ストアに何も書かず、いま定時の実行を流したら出るものを見る (指摘は報告済みにならず、次の定時の実行でも出る)。`--window` で見る期間を短くできる。レポートは `dry_run: true` で、aratam は送らない | よい (ストアは読むだけ。AWS の読み取りは行い、Logs Insights の費用は期間に応じてかかる) |
| `arata report --profile daily [--format md]` | 最後のレポートを再表示 | よい |
| `arata report --month 2026-10` / `--from D --to D` | ストアだけから期間レポート (収集しない) | よい |
| `arata review [--format json]` | 未対応 (open / acked) の一覧と approve の対象 | よい |
| `arata approve <id> --note ... [--expires] [--tag] [--commit]` | allowlist に追記し finding を解消 (`--destination` は主体ではなく、外向きの引き受けの行き先のアカウントを既知にする) | **しない** (人に提案する) |
| `arata ack / snooze --until / resolve <id>` | finding の状態を変える | 人の指示があれば |
| `arata help ai onboarding` | 導入の流れ (init の後、最初の run の指摘を通知の前に片付ける手順。ack / snooze / resolve の使い分け) | よい (読み取りのみ) |
| `arata help ai logs` | 記録の集め方 (どの記録があればどのチェックが動くか、ログの出し方、doctor の読み方) | よい (読み取りのみ) |
| `arata help ai request_lines` | 1 リクエストが複数行のアプリのログ (Rails の既定のログなど) を `format: request_lines` で読む設定の書き方と確かめ方 | よい (読み取りのみ) |
| `arata help ai playbook [<check>]` | チェックごとの対処手順 | よい (読み取りのみ) |
| `arata help ai runtime` | GitHub Actions で動かす環境 (リポジトリの設定・OIDC の信頼・secrets) のチェックリストと、`context_file` の下書きの手順 | よい (読み取りのみ) |

## 終了コード

- `0`: 正常 (findings の有無に関係なく)
- `2`: 設定 / 権限エラー (doctor は問題があれば 2)
- `3`: 収集の一部失敗。レポートは出ている。`coverage.sources_failed` を見る

## 標準エラーのログと code

エンジン自身のログは標準エラーに JSON 行で出る。`code` は固定語彙。

| code | 意味 | 対処 |
|---|---|---|
| `ACCESS_DENIED` | IAM 権限不足 (`action` に不足した action) | 読み取りロールに action を足す。`arata doctor` の表の最後に必要な action が出る |
| `LOG_GROUP_MISSING` | ロググループが無い / 名前変更 | config.yaml の `log_group` を直す |
| `FORMAT_MISMATCH` | 解釈率が閾値未満 (そのソースは失敗扱い) | `samples` を見て `format` / `fields` / `regex` / `stream_prefix` を直す。混在ストリームなら `expected_match_rate` を下げる。`request_lines` で `reason` が `request_id` / `complete_rate` なら `request.id` と最初の行の正規表現を直す (`arata help ai request_lines`) |
| `FORMAT_DRIFT` | 解釈率が直近平均から急落 (警告) | アプリのデプロイでログ形式が変わっていないか確認する |
| `QUERY_LIMIT` | Insights の同時実行・スキャン上限、LookupEvents のスロットル | 時間を置いて再実行。`max_scan_gb` を見直す |
| `QUERY_INVALID` | クエリ / 設定の不備 (Insights の構文エラーなど) | `arata doctor` の `queries` 行を見る |
| `STORE_LOCKED` | 同じストアを別プロセスが使用中 (`run --dry-run` は、ストアを複製する間に書き込み中の実行がいるとき) | 前の実行が終わるのを待つ |
| `STORE_CORRUPT` | SQLite を開けない (`arata rebuild` で既存の SQLite が無い・読めないときも)。`s3://` のストアで raw があるのに SQLite が無いときも、書き込み系のコマンドはこれで止まる (`report` / `review` は警告して続く) | 人に知らせる。`arata rebuild` で raw から作り直せる。SQLite が読めなければ `--from-scratch` (findings が空になり次の run で全部が再報告されるので、人の判断を仰ぐ) |
| `STORE_CONFLICT` | `s3://` のストアを別の実行が先に書いた (終了コード 2。何も上書きしていない。この実行の結果は保存されず、report も出ない) | 同じコマンドをもう一度実行する。繰り返すなら同時に走っている実行を止める |
| `STORE_UNAVAILABLE` | `s3://` のストアに問い合わせられない (権限・通信。終了コード 2) | `arata doctor` の `store_read` を見る。破損ではないので `rebuild` はしない |
| `INTERRUPTED` | SIGINT / SIGTERM で止まった (終了コード 2。`s3://` のストアには保存していない) | 同じコマンドをもう一度実行する |
| `RUN_MISSED` | 前回実行から周期の 2 倍以上空いた | 起動側 (cron など) の障害を疑う。`truncated: true` なら取りこぼしあり |
| `COLLECT_FAILED` | 上記に分類できない収集エラー | ネットワークなどを確認して再実行 |
| `CONFIG_INVALID` | 設定ファイルの読み込み・検証エラー | エラーメッセージに従い設定を直す |
| `CHECK_UNUSED` | どのプロファイルにも入っていないチェックがある (警告。`checks` に名前) | 入れ忘れなら profiles に足す。`arata config init --diff` で雛形と比べる。意図して外したなら人に確認するだけでよい |
| `REPORT_NOT_FOUND` | `arata report --profile X` で、そのプロファイルの run がまだ無い (終了コード 2) | 先に `arata run --profile X` を実行する。プロファイル名の打ち間違いも疑う |

`RUN_MISSED` と終了コードは LLM を経由せず組み込み側が直接通知する規則になっている。

## allowlist.yaml の形式

```yaml
principals:                       # 主体の指定は arn / account / arn_pattern のどれか 1 つ
  - arn: arn:aws:iam::123456789012:role/github-actions-deploy
    note: GitHub Actions の OIDC デプロイロール
    approved_by: alice
    approved_at: 2026-10-21
    tags: [deploy]                # IAM 変更を info に下げる
  - account: "111122223333"       # そのアカウントの全主体 (SaaS 連携用)
    note: SaaS の監視連携
  - arn_pattern: arn:aws:iam::123456789012:role/ci-*   # glob (* は / も含む)
    expires: 2026-12-31           # 期限付き。過ぎたら expired として再報告
    dynamic_source: true          # 送信元が毎回変わる主体。principal_new_source の low を出さない
  - arn: arn:aws:iam::123456789012:role/ai-investigation-readonly
    note: 個人情報を含むロググループは IAM で Deny している
    expected_denied: ["logs:StartQuery", "logs:Get*"]   # access_denied で数えない拒否 (サービス:操作の glob。note 必須)
source_ips:
  - cidr: 203.0.113.0/24          # アプリ層チェックの対象外にする IP。principal_new_source でも新しい送信元にしない
    note: 本社
secrets_access:                   # 主体 × 読んでよい秘匿値 (名前・パスの glob)。secret_access の初出に数えない
  - principal: arn:aws:iam::123456789012:role/example-app-task
    secrets: ["prod/app/*"]
assume_destinations:              # 外向きの引き受けで、行き先として既知のアカウント。そこへの MFA ありの引き受けは unknown_assume_role が報告しない
  - account: "111122223333"       # principals の account: (呼び出し元の承認) とは別。主体は承認されない
    note: 運用を受託しているアカウント  # 必須
    expires: 2027-03-31           # 任意。roles: ["ReadOnly"] でロールに絞れる
```

承認の判断基準は `arata help ai approve`。

## 認証の注意

- エンジンは AWS SDK の標準認証チェーン (環境変数 / `~/.aws/config` の profile / ロール) に従う
- `aws login` (ブラウザでのサインイン) のセッションは Go SDK から直接読めない。
  `credential_process = aws configure export-credentials --profile <login 済み profile> --format process` の profile を作るか、
  本番は Roles Anywhere / インスタンスロールを使う
- 権限は読み取りのみ。追加の裏取りをするときも読み取り API だけを使う
- 例外は `iam:GenerateCredentialReport` (書き込み系: 認証情報レポートの生成のみ)。拒否されても 4 時間以内に生成済みのレポートがあれば使う。
  必要な action の一覧は `arata doctor` の表の最後に出る

## 次に読むもの

- `arata help ai report`: report.json の構造と要約の手順
- `arata help ai approve`: 承認判断の基準
- `arata help ai onboarding`: 導入の流れ。init の後の最初の run は通知せずに流し、review で 1 件ずつ片付けてから定時の通知を始める
- `arata help ai logs`: 記録の集め方。チェックが skip される・解釈率が低い・ロググループが無いときに読む (チェックと記録の対応表、ALB・WAF・nginx・アプリのログの出し方)
- `arata help ai request_lines`: 複数行のアプリのログ (Rails の既定のログなど) をリクエスト単位にまとめて読む設定。見本の行から `request:` を書くとき、`requests` が `FORMAT_MISMATCH` のときに読む
- `arata help ai playbook <check>`: チェックごとの対処手順 (確かめる順番・判断の分かれ目・対処の選択肢)。一覧は `arata help ai playbook`
- `arata help ai runtime`: 利用者の環境 (GitHub Actions で動かすリポジトリ) を作る・見直すときのチェックリスト。
  環境を作るときは、aratam の `llm.context_file` (監査対象の前提) の下書きまで行う (手順は同じ文書。マージは人)
- `--format json` を付けると `{topic, sections: [{title, body}]}` で受け取れる
