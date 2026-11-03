# ADR (Architecture Decision Records)

設計上の重要な判断を、背景・選択肢・理由とともに残す。`docs/design.md` は「現在の仕様」、ADR は「なぜそうなったか」。

- 1 ファイル 1 決定。番号は連番、ファイル名は `NNNN-短い題名.md`
- 状態は `提案` / `採用` / `廃止` / `置換 (→ NNNN)`。採用済みの ADR は書き換えず、変更は新しい ADR で置き換える
- 書く基準: 後から「なぜこうした?」と聞かれそうな判断、却下した案があった判断、外部 (顧客・運用) に影響する判断。実装の細部は設計書の「決定:」注記で足りる

## テンプレート

```markdown
# NNNN. 題名

- 日付: YYYY-MM-DD
- 状態: 採用

## 背景
## 決定
## 検討した選択肢
## 結果 (良い点・引き受けるコスト)
```

## 一覧

| 番号 | 題名 | 状態 |
|---|---|---|
| [0001](0001-engine-boundary.md) | エンジンの責務は収集・保存・差分判定・レポート生成まで | 採用 |
| [0002](0002-go-single-binary.md) | Go 製の単一静的バイナリ | 採用 |
| [0003](0003-two-layer-store.md) | JSONL 原本 + SQLite 派生の二層ストア | 採用 |
| [0004](0004-new-signal-and-baselines.md) | 「新規」の判定は既知リスト (git 管理) と前回状態の二層で行う | 採用 |
| [0005](0005-event-vs-state-checks.md) | チェックをイベント型と状態型に分け、差分判定の挙動を変える | 採用 |
| [0006](0006-format-profiles.md) | ロググループと形式プロファイルの紐付け、Logs Insights での集計取得 | 採用 |
| [0007](0007-baseline-principals.md) | init のベースライン収集で初出した主体は `baseline` 状態にし、new_principal の対象外にする | 採用 |
| [0008](0008-deploy-tag-in-allowlist.md) | 既知デプロイ主体は allowlist の principals に `tags: [deploy]` で表す | 採用 |
| [0009](0009-insights-query-templates.md) | Logs Insights のクエリテンプレートは前処理・集計・後処理の 3 層で組み、UTC 日次の集計を置き換えで保存する | 採用 |
| [0010](0010-approve-text-insertion.md) | approve は allowlist.yaml を構造として書き直さず、principals の末尾に行を差し込む | 採用 |
| [0011](0011-init-daily-chunks.md) | init のベースライン収集は UTC の 1 日単位に分け、進捗を runs に記録して再開できるようにする | 採用 |
| [0012](0012-help-ai-embedded-docs.md) | LLM 向けの使い方は skill として配らず、`arata help ai` としてバイナリに埋め込む | 採用 |
| [0013](0013-ingest-delay-rescan.md) | 記録の遅延は窓の終わりをずらさず、各ソースが `ingest_delay` だけ前を再走査して拾う | 採用 |
| [0014](0014-explicit-config-scaffold.md) | 既定のプロファイルを実行時に暗黙で効かせず、推奨設定を雛形として書き出す | 採用 |
| [0015](0015-weekly-snapshot-state-checks.md) | 週次チェックはアカウントの状態をスナップショットとして取り、成功したときだけ丸ごと置き換えて state 型で比べる | 採用 |
| [0016](0016-period-report-from-store.md) | 期間レポートは収集せずストアだけから作り、そのために finding の状態遷移を履歴として残す | 採用 |
| [0017](0017-supply-chain-hardening.md) | サプライチェーン対策は Actions の SHA 固定・依存の 7 日待機 (2 段構え)・来歴証明で行う | 採用 |
| [0018](0018-aratam-output-coupling.md) | LLM 要約と通知は aratam が担い、arata とは出力リソースだけで連携する | 採用 |
| [0019](0019-reduce-dependencies.md) | 標準ライブラリで無理なく書ける依存は持たない (cobra と x/time を外す。SQLite は残す) | 採用 |
| [0020](0020-sandbox-cdk.md) | 試験環境 (sandbox) は開発用の AWS アカウントに CDK (TypeScript) で作り、配布用のロールは素の CloudFormation のまま取り込む | 採用 |
| [0021](0021-access-denied-check.md) | 拒否された API 呼び出しを events に残し、主体ごとの種類と件数を平常帯と比べる `access_denied` チェックを足す | 採用 |
| [0022](0022-expected-denied-and-escalation.md) | 想定済みの拒否は allowlist の `expected_denied` で主体 × API の単位で除き、ack / snooze 中でも重大度が上がれば再報告する | 採用 |
| [0023](0023-waf-review-proposals.md) | WAF の修正提案の候補は arata が規則で作り、report.json の `proposals` に出す (WebACL の設定は `waf-config` のスナップショット) | 採用 |
| [0024](0024-aratam-waf-proposals.md) | aratam は WAF の修正提案の候補を 2 通目として通常用に送り、LLM には候補だけを渡して書き起こさせる (アプリの事情は `llm.context_file`) | 採用 |
| [0025](0025-check-playbooks.md) | チェックごとの対処手順 (playbook) を `docs/ai/playbooks/<check>.md` としてバイナリに埋め込み、全チェックに必須にする | 採用 |
| [0026](0026-defense-evasion-public-exposure.md) | 監査・検知の無効化 (`defense_evasion`) と公開設定の変更 (`public_exposure`) を、CloudTrail の注目イベントと要求の内容だけで判定する | 採用 |
| [0027](0027-principal-new-source-secret-access.md) | 既知の主体の初めての送信元・リージョン (`principal_new_source`) と秘匿値の読み取りの異常 (`secret_access`) を、CloudTrail の主体の活動の日次集計と注目イベントで判定する | 採用 |
| [0029](0029-aratam-block-kit.md) | aratam の Slack 通知を Block Kit にし、同じチェックの指摘は規則でまとめ、LLM は要約と「→ 何をするか」だけを書く | 採用 |
