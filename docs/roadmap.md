# ロードマップと引き継ぎ (2026-11-03 時点、v0.3.0 リリース後)

ここは「今どこまでできていて、次に何をするか」をまとめる文書。仕様は `design.md` / `aratam.md`、判断の経緯は `adr/`。
更新は PR ごとに行い、終わった項目は消す (履歴は git に残る)。

## 1. 現状 (v0.3.0)

- arata: 設計書 10 章の Step 1〜3 に加え、次のチェックを実装済み。すべて sandbox (`deploy/sandbox`、ADR 0020) で本物の AWS を相手に、
  `scenarios/01〜10` どおりに出ることを確認した
  - `access_denied` (拒否された API の急増。ADR 0021)、`expected_denied` と ack / snooze 中の重大度の上昇の再報告 (ADR 0022)
  - `waf_review` (WAF の改善提案と COUNT のルールの状況。ADR 0023)
  - `defense_evasion` (監査・検知の無効化) と `public_exposure` (公開設定の変更。ADR 0026)
  - `principal_new_source` (既知の主体の初めての送信元・リージョン) と `secret_access` (秘匿値の読み取りの異常。ADR 0027)
  - `unused_region_activity` (ふだん使わないリージョンでの書き込み) と `cost_anomaly` (Cost Anomaly Detection の異常を予想に対する割合で。ADR 0032)。
    sandbox ではシナリオ 12 と doctor (権限・モニターの検出) で確かめる (異常の発生は試験できないので cost_anomaly の判定はテストのフェイクで固定)
  - チェックごとの対処手順 (`arata help ai playbook <check>`。ADR 0025)
- aratam: WAF の改善提案の 2 通目、利用者の事情 (`llm.context_file`。ADR 0024)、出たチェックの対処手順を LLM に渡す
- サプライチェーン対策 (ADR 0017) と依存削減 (ADR 0019) は適用済み
- 未確認: aratam の Slack への実送信と `bedrock`、`report --month`

## 2. すぐにやること

1. **段階 E**: `endpoint_abuse` (会員登録・パスワード再設定・メッセージ送信などへの分散した連打)。主役は短い時間幅の画面全体の件数と、
   同じ User-Agent が多数の IP にまたがること。結果は遮断の提案にせず件数の異常として伝える。利用者側のふだんの件数が分かってから閾値を決める
2. **aratam の実送信試験**: 試験用チャンネルの Incoming Webhook で `aratam doctor` → `test-notify` → `notify` を 1 回ずつ。
   `bedrock` は sandbox の `bedrock.enabled` で推論プロファイルを作り、`doctor` で応答を確かめる
3. **小さな残り**: 自アカウントの root を「外部アカウント」と表示しない守り (CloudTrail の recipientAccountId を使う)、
   「本日報告済み」の欄が still_open のとき Data を更新しない件 (expected_denied を足した直後に古い件数が見える)

## 3. 残項目 (優先度順の案。利用者側の意見を反映)

| 優先度 | 項目 | 内容 | メモ |
|---|---|---|---|
| 高 | GuardDuty High の hourly 化 | 週次の `guardduty_findings` とは別に、High 以上の新規 finding を hourly で拾う | 週次のスナップショットと二重に鳴らない設計が要る (ADR 0015) |
| 高 | ConsoleLogin の失敗 | コンソールのサインイン失敗 (errorCode ではなく responseElements に出る) を主体・送信元ごとに数える | root のサインインは root_usage が扱う。access_denied とは別の仕組み |
| 中 | allowlist の雛形共有 | 監査対象をまたいで共通になる承認 (開発会社の switch role、CDK の bootstrap ロール `cdk-hnb659fds-*` など) | 設計書 11 章の未決。CDK を使うアカウントでは deploy のたびに unknown_assume_role / iam_changes が出る |
| 中 | `allowlist_stale` | 承認済みの主体で長く観測が無いものを棚卸しとして報告 | weekly / info。承認の期限 (`expires`) との関係を整理 |
| 中 | Insights の読み取りをさらに減らす | (1) 前回の続きから読み、時間幅の細かい行を保存して日次を Go で作り直す (2) フィールドインデックス (`filterIndex`) を doctor で案内し、あれば使う | ADR 0031 の検討した選択肢。(1) は IP と生パスの保存・schema の更新・pct の再現が論点。(2) は sandbox で効果を測ってから |
| 中 | endpoint_abuse の複数ソースの異なり IP | 1 つの画面を複数のソースで数えると、異なり IP 数が和集合でなく足し算になる | ADR 0031。ソースは別のロググループなので 1 本にまとめられない |
| 中 | Insights の 1 日あたり費用上限 | ソース単位の `max_scan_gb` に加え、監査対象全体の 1 日上限と縮退 | 設計書 11 章の未決。WAF ログを読むと量が増える |
| 低 | 古いパスワード | 認証情報レポートからパスワード未変更の期間を見る | `credential_hygiene` に閾値を足す形 |
| 低 | prune | 保持期間を過ぎたデータの削除 | 設計書 5-3 章。`finding_events` の扱いを決める。rebuild は実装済み (5-4、ADR 0033) |
| 低 | `openai-api` プロバイダ | Chat Completions を `net/http` で | `docs/aratam.md` 3-1 章 |
| 低 | Lambda + S3 バックエンド | `s3://` ストアと Lambda ハンドラ | 設計書 9 章。cron で回す運用なら後回し |
| 低 | 国判定 | IP → 国。MaxMind 同梱か GuardDuty 頼みか | 設計書 11 章の未決 |
| 低 | 入口スキル | LLM 実行環境に置く数行のスキル (「最初に `arata help ai` を読む」) | 配布先は利用者側のリポジトリ |

## 4. 未決の判断 (利用者側に確認する)

- リポジトリを公開するか。公開すると Release の来歴証明が自動で有効になる。公開前に `git log` と PR / Release の本文に顧客情報が無いことを再確認する
- ~~Slack の書式 (mrkdwn の本文だけで続けるか Block Kit にするか)~~ (決定: Block Kit。`slack.format: text` で従来の本文も選べる。ADR 0029)
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
- 「導入直後は報告しない」の判定は「データのある日」ではなく「収集し終えた日」で数える。操作の少ないアカウントでは、データのある日がいつまでも足りない (ADR 0027)
- WAF の `ListResourcesForWebACL` は資源の種類ごとに別サービスの権限を要求し、エラー文も統一されていない。文言で判定しない (ADR 0023)
- 一般的なコスト削減は arata に入れない (別の製品の候補。月次・手動実行)。費用の急増だけをセキュリティの兆候として見る
