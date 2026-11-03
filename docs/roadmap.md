# ロードマップと引き継ぎ (2026-11-03 時点)

ここは「今どこまでできていて、次に何をするか」をまとめる文書。仕様は `design.md` / `aratam.md`、判断の経緯は `adr/`。
更新は PR ごとに行い、終わった項目は消す (履歴は git に残る)。

## 1. 現状

- arata: 設計書 10 章の Step 1〜3 まで実装済み (CloudTrail / CloudWatch Logs / 週次のアカウント状態、allowlist と承認、
  期間レポート、`config init` と `profiles`、doctor)。v0.2.0 以降に、拒否された API 呼び出しの急増を見る `access_denied` (ADR 0021) と、
  拒否された IAM 操作を「試行 (拒否)」と表示する `iam_changes` の修正、作成直後のロググループで init が止まる不具合の修正が入った
- aratam: `docs/aratam.md` 7 章の実装順 1〜4 まで実装済み。v0.2.0 で初めてリリースした
- サプライチェーン対策 (ADR 0017) と依存削減 (ADR 0019) は適用済み
- 試験環境 sandbox (`deploy/sandbox`、CDK。ADR 0020) を開発用アカウントに deploy し、`scenarios/01〜05` を一巡した。
  login_bruteforce / probe_paths / iam_changes / unknown_assume_role / new_principal / guardduty_findings / access_analyzer /
  credential_hygiene / posture / access_denied がシナリオどおりに出ること、posture の不備を直すと次の weekly で「解消」になることを、本物の AWS で確認済み
- 監査・検知の無効化 `defense_evasion` と公開設定の変更 `public_exposure` (ADR 0026) を実装した。sandbox の `scenarios/07`・`08` での確認はこれから
- 既知の主体の初めての送信元・リージョン `principal_new_source` と秘匿値の読み取りの異常 `secret_access` (ADR 0027) を実装した。
  sandbox の `scenarios/09`・`10` での確認はこれから (09 は CloudTrail を収集し終えた日が 15 日以上要る)
- 未確認: aratam の Slack への実送信と `bedrock`、`report --month`

## 2. すぐにやること

1. **access_denied の運用調整** (進行中): 想定済みの拒否を「主体 × API」で除外する allowlist の `expected_denied` と、
   ack / snooze 中でも重大度が上がったら再報告する仕組み (全チェック共通)。ack すると主体の悪化 (medium → high) まで隠れる穴を塞ぐ
2. **WAF の修正提案** (arata 側を実装、ADR 0023。aratam の Slack の節が残り): 定期の監査のついでに WAF ログと WebACL の設定を集計し、aratam の LLM が修正案 (誤検知の除外、
   すり抜けている攻撃へのルール、レート制限、カウントモードのルールの評価) を Slack 通知に含める。PR までの自動化は対象外。
   提案は「カウントモードで様子を見る → ブロック」の段階を前提にし、ヘッダー・クエリなどの生の値は通知に出さない
3. **v0.3.0 のリリース**: 1 と 2 の結果を見て中身を決める
4. **aratam の実送信試験**: 試験用チャンネルの Incoming Webhook で `aratam doctor` → `test-notify` → `notify` を 1 回ずつ。
   `bedrock` は sandbox の `bedrock.enabled` で推論プロファイルを作り、`doctor` で応答を確かめる

## 3. 残項目 (優先度順の案。利用者側の意見を反映)

| 優先度 | 項目 | 内容 | メモ |
|---|---|---|---|
| 高 | GuardDuty High の hourly 化 | 週次の `guardduty_findings` とは別に、High 以上の新規 finding を hourly で拾う | 週次のスナップショットと二重に鳴らない設計が要る (ADR 0015) |
| 高 | ConsoleLogin の失敗 | コンソールのサインイン失敗 (errorCode ではなく responseElements に出る) を主体・送信元ごとに数える | root のサインインは root_usage が扱う。access_denied とは別の仕組み |
| 中 | allowlist の雛形共有 | 監査対象をまたいで共通になる承認 (開発会社の switch role、CDK の bootstrap ロール `cdk-hnb659fds-*` など) | 設計書 11 章の未決。CDK を使うアカウントでは deploy のたびに unknown_assume_role / iam_changes が出る |
| 中 | `allowlist_stale` | 承認済みの主体で長く観測が無いものを棚卸しとして報告 | weekly / info。承認の期限 (`expires`) との関係を整理 |
| 中 | Insights の 1 日あたり費用上限 | ソース単位の `max_scan_gb` に加え、監査対象全体の 1 日上限と縮退 | 設計書 11 章の未決。WAF ログを読むと量が増える |
| 低 | 古いパスワード | 認証情報レポートからパスワード未変更の期間を見る | `credential_hygiene` に閾値を足す形 |
| 低 | prune / rebuild | 保持期間を過ぎたデータの削除と、raw JSONL からの SQLite 再構築 | 設計書 5-3 章。`finding_events` の扱いを決める |
| 低 | `openai-api` プロバイダ | Chat Completions を `net/http` で | `docs/aratam.md` 3-1 章 |
| 低 | Lambda + S3 バックエンド | `s3://` ストアと Lambda ハンドラ | 設計書 9 章。cron で回す運用なら後回し |
| 低 | 国判定 | IP → 国。MaxMind 同梱か GuardDuty 頼みか | 設計書 11 章の未決 |
| 低 | 入口スキル | LLM 実行環境に置く数行のスキル (「最初に `arata help ai` を読む」) | 配布先は利用者側のリポジトリ |

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
- Logs Insights は、問い合わせの終わりがロググループの作成時刻より前、または保持期間より古いと MalformedQueryException で拒否する
  (始まりは古くてもよい)。フェイクだけでは気づけなかったもので、sandbox で見つかった
- CloudTrail の errorCode は API の応答と書き方が違うことがある (応答が `AccessDeniedException` でも記録は `AccessDenied` など)
- sandbox を deploy すると、CDK の bootstrap と deploy 自体が unknown_assume_role / iam_changes として出る (scenarios/README の抑え方を参照)
