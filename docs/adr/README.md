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
| [0008](0008-deploy-tag-in-allowlist.md) | 既知デプロイ主体は allowlist の principals に `tags: [deploy]` で表す | 採用 (下げない変更は 0056 で置き換え) |
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
| [0028](0028-waf-resources-challenge-cost.md) | WAF の分析を資源で絞り、Challenge / CAPTCHA の影響を「解かれた割合」で評価し、Insights の費用を doctor で見積もる | 採用 |
| [0029](0029-aratam-block-kit.md) | aratam の Slack 通知を Block Kit にし、同じチェックの指摘は規則でまとめ、LLM は要約と「→ 何をするか」だけを書く | 採用 |
| [0030](0030-endpoint-abuse.md) | 画面への分散した集中と「A のあと B」の連鎖 (`endpoint_abuse`) を、画面ごとの時間幅の集計とふだんの p99 で判定する | 採用 (集計の本数は 0031 で置き換え) |
| [0031](0031-merge-insights-queries.md) | Logs Insights の集計クエリをソースごとに数本にまとめ、振り分けを Go で行う (読み取り量を約半分〜5 分の 2 に) | 採用 |
| [0032](0032-unused-region-activity-cost-anomaly.md) | ふだん使わないリージョンでの書き込み (`unused_region_activity`) を専用のソースで引き、費用の急増 (`cost_anomaly`) は AWS Cost Anomaly Detection の結果を予想に対する割合で読む | 採用 |
| [0033](0033-rebuild-from-raw.md) | `arata rebuild` は raw から作れる表だけを作り直し、作れないものは既存の SQLite から引き継ぐ。raw には rebuild に要る印を足す | 採用 |
| [0034](0034-s3-store.md) | S3 ストアは実行のたびに作業用の複製を出し入れし、確定は明示の Commit と条件付き書き込みで行う | 採用 |
| [0035](0035-supply-chain-ci.md) | サプライチェーンの検査を CI で常に行い、Actions の 7 日待機を強制し、release を権限で分ける | 採用 |
| [0036](0036-sensitive-info-scan.md) | 公開できない情報の検査は、一般的な秘密を gitleaks、禁止語を secrets の一覧と `tools/wordscan` で行い、CI で常に回す | 採用 |
| [0037](0037-sast-and-untrusted-log-values.md) | 静的解析を CI で常に回し、ログ由来の値と LLM の出力を信用しない前提で通知を組み立てる | 採用 |
| [0038](0038-source-catchup-and-reported-after-staging.md) | 失敗したソースはソースごとの位置から追いつき、報告済みの印は出力の準備の後に付ける | 採用 |
| [0039](0039-actions-lock-with-sha-pins.md) | Actions のロックファイルを、uses の SHA 固定と併用して `--no-narrow` で作る | 採用 |
| [0040](0040-github-actions-runner-template.md) | GitHub Actions の実行の仕組みは素の CloudFormation で配り、信頼は `sub` の完全一致に絞る | 採用 (environment の扱いは 0057 で置き換え) |
| [0041](0041-fuzz-untrusted-input.md) | 信用できない入力を解釈する箇所を、Go 標準のファズテストで確かめる | 採用 |
| [0042](0042-offline-config-check-and-triage-workflow.md) | 設定と allowlist の形はオフラインの `config check` で PR の時点に確かめ、finding の片付けは Actions の手動実行で行う | 採用 |
| [0043](0043-vulnerability-fix-exempt-from-cooldown.md) | 脆弱性の修正版は、条件を満たせば 7 日の待機の対象外にする | 採用 |
| [0044](0044-aratam-secrets-via-environment.md) | aratam は秘密を環境変数で受け取り、置き場所と取り出し方は実行環境に任せる | 採用 |
| [0045](0045-init-requires-audit-account.md) | `config init` は監査する側のアカウントを必ず選ばせ、選んだ結果を設定と既知リストに残す | 採用 |
| [0046](0046-alb-access-logs.md) | ALB のアクセスログは CloudWatch Logs への配信 (plain) を既存の `alb_access` で読み、S3 を直接読む案は次の段にする (Athena・S3 Select との比較) | 提案 |
| [0047](0047-known-assume-destinations.md) | 外向きの引き受けは、行き先として既知のアカウントへの MFA ありのものだけ報告しない (`assume_destinations`) | 採用 |
| [0048](0048-posture-alb-waf.md) | posture は、インターネット向けの ALB に WAFv2 の WebACL が付いていないことを報告する (読み取りの権限を 2 つ足す) | 採用 |
| [0049](0049-run-dry-run.md) | 試しの実行 (`run --dry-run`) はストアの複製の上で評価し、複製を捨てる (ストアに何も書かず、aratam は送らない) | 採用 |
| [0050](0050-log-hygiene.md) | アプリのログに残った「載せるべきでない値」を、種類ごとの件数だけで週次に報告する (`log_hygiene`。値は取り出さない) | 採用 |
| [0051](0051-request-records-and-field-tiers.md) | 複数行のアプリのログは request_id でリクエスト単位にまとめて集計し、取れる項目の段ごとに動かせるチェックを決める | 採用 (段 0 とユーザー ID の読み取りまで実装) |
| [0052](0052-actor-and-auth-lines.md) | アプリに足してもらう行は actor と auth の 2 種類にし、行末まで固定した正規表現で読んで、値の形を規則で絞る | 採用 |
| [0053](0053-readonly-role-denied-log-groups.md) | 読み取り専用ロールに、読ませないロググループの名前を受けるパラメータを足し、中身を読む操作を明示の Deny で止める | 採用 |
| [0054](0054-machine-readable-output-schemas.md) | 機械が読む出力は `--format json` で出し、Go の型から作った JSON Schema とテストで固定する (人向けの出力を機械で読ませない) | 採用 |
| [0055](0055-oidc-assume-role.md) | OIDC でのロールの引き受けを、(プロバイダ, sub, ロール) の組で既知リストと比べる (`oidc_assume_role`) | 採用 |
| [0056](0056-deploy-principal-not-lowered.md) | 既知デプロイ主体でも、アクセスキーの作成と、信頼ポリシーを外へ広げる変更は下げない。ロールの作成も信頼ポリシーを読んで報告する (`iam_changes`) | 採用 |
| [0057](0057-runner-github-environment.md) | 実行の仕組みを GitHub の environment に対応させ、見本は秘密を environment に置く (`sub` は environment、ブランチは `ref` で絞る) | 採用 |
| [0058](0058-threat-coverage-table.md) | 公開された攻撃の事例ごとに、arata で見える段階と見えない段階を、出典の URL 付きの対応表として持つ | 採用 |
| [0059](0059-repo-init.md) | 監査を回すリポジトリの一式を `arata repo init` で書き出し、見本はその出力から作る (GitHub の設定は Terraform。秘密の箱は、既にある秘密を取り込んでから作る) | 提案 |
