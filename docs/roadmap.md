# ロードマップと引き継ぎ (2026-10-24 時点)

ここは「今どこまでできていて、次に何をするか」をまとめる文書。仕様は `design.md` / `aratam.md`、判断の経緯は `adr/`。
更新は PR ごとに行い、終わった項目は消す (履歴は git に残る)。

## 1. 現状

- arata: 設計書 10 章の Step 1〜3 まで実装済み (CloudTrail / CloudWatch Logs / 週次のアカウント状態、allowlist と承認、
  期間レポート、`config init` と `profiles`、doctor)。v0.1.0 をリリース済み (arata のバイナリのみ)
- aratam: `docs/aratam.md` 7 章の実装順 1〜4 まで実装済み (入力検査と振り分け、`none` / `claude-cli` / `bedrock`、doctor、test-notify、
  リリースへの追加)。**まだリリースしていない** (v0.2.0 が最初)
- サプライチェーン対策 (ADR 0017) と依存削減 (ADR 0019) は適用済み
- 実動確認の状況:
  - arata の daily 相当のチェック、doctor、approve の一括解消、週次の doctor は実環境で確認済み
  - 週次の `init` / `run` と `report --month` は未実施 (`iam:GenerateCredentialReport` を呼ぶため、利用者側の判断待ちだった)
  - aratam は `claude-cli` で `notify --dry-run` を実データ相当の report.json で確認済み。**Slack への実送信と `bedrock` は未確認**

## 2. すぐにやること

1. **v0.2.0 のリリース**: aratam のバイナリが初めて Release に並ぶ。`make build` の成果物 4 つ + SHA256SUMS。
   タグを push すると release ワークフローが走る (来歴証明は公開リポジトリになるまでスキップされる)
2. **aratam の実送信試験**: 試験用チャンネルの Incoming Webhook で `aratam doctor` → `test-notify` → `notify` を 1 回ずつ。
   `bedrock` は推論プロファイルを 1 つ用意して `doctor` で応答を確かめる
3. **v0.2.0 の README 見直し**: aratam の節が「cron で 2 つのコマンドをつなぐ」例まで含むか

## 3. 残項目 (優先度順の案)

| 項目 | 内容 | メモ |
|---|---|---|
| GuardDuty High の hourly 化 | 週次の `guardduty_findings` とは別に、High 以上の新規 finding を hourly で拾う | 週次のスナップショットと二重に鳴らない設計が要る (ADR 0015) |
| `allowlist_stale` | 承認済みの主体で長く観測が無いものを棚卸しとして報告 | weekly / info。承認の期限 (`expires`) との関係を整理 |
| 古いパスワード | 認証情報レポートからパスワード未変更の期間を見る | `credential_hygiene` に閾値を足す形 |
| Insights の 1 日あたり費用上限 | ソース単位の `max_scan_gb` に加え、監査対象全体の 1 日上限と縮退 | 設計書 11 章の未決 |
| prune / rebuild | 保持期間を過ぎたデータの削除と、raw JSONL からの SQLite 再構築 | 設計書 5-3 章。`finding_events` の扱いを決める |
| `openai-api` プロバイダ | Chat Completions を `net/http` で | `docs/aratam.md` 3-1 章。名前は呼び方を表す |
| Lambda + S3 バックエンド | `s3://` ストアと Lambda ハンドラ | 設計書 9 章。改ざん耐性 (別アカウント / Object Lock) を含めて設計 |
| 入口スキル | LLM 実行環境に置く数行のスキル (「最初に `arata help ai` を読む」) | 配布先は利用者側のリポジトリ |
| 国判定 | IP → 国。MaxMind 同梱か GuardDuty 頼みか | 設計書 11 章の未決 |
| allowlist の雛形共有 | 監査対象をまたいで共通になる承認 (開発会社の switch role など) | 設計書 11 章の未決 |

## 4. 未決の判断 (利用者側に確認する)

- リポジトリを公開するか。公開すると Release の来歴証明が自動で有効になる。公開前に `git log` と PR / Release の本文に顧客情報が無いことを再確認する
- Slack の書式 (mrkdwn の本文だけで続けるか Block Kit にするか)
- hourly と daily の通知をまとめるか (今は別々)
- `aratam` の `--in` に既定を持たせない方針を維持するか (`docs/aratam.md` 5 章の決定)

## 5. 既知の落とし穴

- ADR 番号は並行する PR で衝突する。出す前に `main` と open な PR を確かめる
- 依存を上げるときは公開 7 日未満の版が age-gate で落ちる。1 つ前の版にする
- `docs/ai/*.md` を変えると `help ai` のゴールデンが変わる
- テストで `claude-cli` を使う設定は、必ず偽の実行ファイルを PATH に置く (本物を起動しない)
- GNU の `cut -c` / `head -c` はバイト単位で切るので、日本語の出力を確認するときに壊れて見える。aratam の切り詰めは文字 (rune) 単位で正しい
- `arata report --profile X` はその profile の run が無いと `REPORT_NOT_FOUND` (終了コード 2)
