# ロードマップと引き継ぎ (2026-11-09 時点、v0.5.0 リリースとリポジトリの公開の後)

ここは「今どこまでできていて、次に何をするか」をまとめる文書。仕様は `design.md` / `aratam.md`、判断の経緯は `adr/`。
更新は PR ごとに行い、終わった項目は消す (履歴は git に残る)。

## 1. 現状 (v0.5.0)

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
- v0.4.0: `endpoint_abuse` (ADR 0031)、S3 ストア (`store: s3://`、ADR 0034) と `arata rebuild` (ADR 0033)、GitHub Actions の見本 (`examples/github-actions/`)、aratam の Block Kit
- v0.5.0: 公開前の点検 (ADR 0035〜0039)。サプライチェーン (actions の lock、SBOM、release の権限の分離)、秘密と禁止語の検査、SAST、
  LLM と Slack への攻撃の守り、失敗したソースの追いつき (ADR 0038)、検知の取りこぼしの修正
- 2026-11-09 にリポジトリを公開 (MIT)。GitHub の設定は `docs/supply-chain.md`「GitHub の画面で人が行う設定」
- 未確認: GitHub Actions の見本の実際の実行 (OIDC の引き受け・`concurrency`)、aratam の `bedrock`、`report --month`

## 2. すぐにやること

1. **実行の仕組みのテンプレート** (`deploy/github-actions/runner.yaml`): OIDC プロバイダ・ストアのバケット・実行用ロール (任意で Bedrock の呼び出し) を
   1 コマンドで置く素の CloudFormation。見本の手順を `aws cloudformation deploy` の 2 つにし、複数のアカウントの書き方 (matrix) を足す (作業中)
2. **最初の利用者での運用の開始**: 非公開の運用リポジトリで、上のテンプレートと見本をそのまま使って GitHub Actions で毎日動かす。
   ここで面倒だった手順を、4 の配り方の材料にする
3. **ファズテスト**: 信用できない入力 (LLM の出力・ログの行・CloudTrail・利用者のファイル) の解釈 (作業中)
4. **使うための道具の配り方** (2 の後):
   - 中心: バイナリに雛形とテンプレートを入れ、`arata scaffold github-actions` (名前は仮) で書き出す。バイナリの版と雛形の版が必ず揃い、`config init --diff` のように新しい版との差分も見せられる
   - 同じテンプレートを Release にも添付する (来歴証明と `SHA256SUMS` で本物か確かめられる)
   - 利用者が増えたら、取得と照合をまとめた action (`setup-arata` など) を足す。ワークフロー全体の共有 (reusable workflow) は OIDC の信頼の条件が arata 側のワークフローになり分かりにくいので採らない
   - LLM のエージェント向けのスキルを書き出す: 例 `arata scaffold skill` で、Claude Code などのエージェントのスキル (SKILL.md) を利用者のリポジトリに書き出す。
     `help ai` は、読めと言われないと読まれない。スキルなら、関係する作業で自動的に読み込まれる。
     中身は薄くする: いつ使うか (description)、最初に `arata help ai` をその版のバイナリで読むこと、守る規則の数行
     (LLM は approve・ack を実行しない、承認は allowlist の PR、監査対象に書き込まない、実行環境のチェックリスト `arata help ai runtime` への参照) だけ。
     手順の本文は写さない (バイナリの版と食い違わないように。本文の正は `help ai`)。
     書き出した版をスキルに記し、`config init --diff` と同じように版の違いを確かめられるようにする案
   - GitHub のテンプレートリポジトリは作らない (作った後の更新が利用者に届かず、書き出しと中身が二重になる)。作るなら書き出しを置いただけの薄いもの
5. **v0.5.1**: 公開してから最初のリリース (来歴証明が初めて付く)。3 と 1 が入ったら

## 3. 残項目 (優先度順の案。利用者側の意見を反映)

| 優先度 | 項目 | 内容 | メモ |
|---|---|---|---|
| 高 | GuardDuty High の hourly 化 | 週次の `guardduty_findings` とは別に、High 以上の新規 finding を hourly で拾う | 週次のスナップショットと二重に鳴らない設計が要る (ADR 0015) |
| 高 | ConsoleLogin の失敗 | コンソールのサインイン失敗 (errorCode ではなく responseElements に出る) を主体・送信元ごとに数える | root のサインインは root_usage が扱う。access_denied とは別の仕組み |
| 高 | ALB のアクセスログで `http_access` のチェックを動かす | nginx のログを CloudWatch Logs に送っていない利用者でも、`login_bruteforce`・`probe_paths`・`endpoint_abuse` を動かす。第 1 段: 利用者が ALB のアクセスログを CloudWatch Logs へ配信し (plain・既定の項目・空白区切り)、既存の cloudwatch-logs のソースと `alb_access` で読む。arata の変更は無いか最小。第 2 段 (取り込み料金を避けたい・量が多い利用者向け): S3 の gzip のファイルを直接読み、Go で同じ日次集計を作る | 提案の段階 (設計書 2-3 章、ADR 0046)。採用の前に、実際のログで doctor の解釈率を見て `alb_access` が合うことを確かめ (合わなければ `parse` を直す)、手順を README と `examples/` に書く。json 形式は `request_line` を分ける新しいプロファイルが要るので今は案内しない。Athena は採らない |
| 高 | `secret_access` の一括読み出し | 起動時に秘匿値をまとめて読む主体 (ECS の実行ロールなど) は、読まない日が 0 件と数えられて中央値が 0 のままになり、デプロイの日ごとに high になる。判定を改良する (読んだ日だけの中央値、allowlist で主体 × 秘匿値ごとの想定件数など) | 承認 (`secrets_access`) では止められず、ack だと以後の一括読み出しも隠れる。ADR 0027 の判定を変えるので ADR を足す |
| 中 | 複数行のアプリのログの、段 0 の新しいチェック (`id_enumeration`) | 1 つの送信元が同じ形のパスで触った異なる ID の数を数える。`request_lines` (段 0。実装済み) の上に、対象 ID の位置の定義・上位 N 件と分布の保存・playbook を足す | ADR 0051 の 7 節の 3。先に `request_lines` を実データの `--dry-run` で見て、続けるかを決める |
| 中 | ユーザー ID を使うチェック (段 1。`source_multi_user` → `user_multi_source`) | 1 つの送信元から使われた異なるユーザー ID の数、1 つのユーザー ID が使った異なる送信元の数を、ふだんと比べる。`by` (代わりにログインした操作) の付いたリクエストは異なり数に入れない | ADR 0051 の 7 節の 5。ユーザー ID の読み取り (`request.user_id`・`request.auth`・`http_user`・ID の付いた割合・0 件の run の skip) は実装済み (ADR 0052)。下限を超えた key の上位 N 件と分布の保存・playbook を足す。ID の付いた割合が直近の平均から落ちたときの警告 (0051 の 4 節) と、`json` 形式の `fields.user_id` から `http_user` を出すことも未実装 |
| 中 | `log_hygiene` の実データでの確認 | 実装済み (ADR 0050)。クエリが Insights の方言でそのまま通るか (繰り返しの回数の指定・`\s`・選択肢の長い並び・条件を 40 個ほど並べた `fields`) を実際のロググループで確かめ、通らなければ表現を直す | `arata doctor` の queries が構文を確かめる。正規表現は設計書 7 章「log_hygiene」 |
| 中 | 実行の仕組みのテンプレートを GitHub の environment に対応させる | `runner.yaml` に environment の名前のパラメータを足し、`sub` を `repo:...:environment:<名前>` の形でも受ける。secrets を environment に置き、デプロイできるブランチを main に限れるようにする | 見本の README「実行するリポジトリと環境を堅くする」の 5。environment の形ではブランチが `sub` から消えるので、`ref` の条件キーを足すか、`sub` の組み立ての変更 (リポジトリの OIDC の設定) で両方を入れられるかを実際のトークンで確かめる。ADR 0040 を新しい ADR で置き換える |
| 中 | bot トークンを AWS Secrets Manager に置く | Slack の bot トークンを GitHub の secret ではなく AWS Secrets Manager に置き、main のワークフロー (OIDC で絞った実行用ロール) だけが読めるようにする。`runner.yaml` の実行用ロールに、その 1 つの秘密を読む権限 (`secretsmanager:GetSecretValue`) を足し、見本のワークフローの step が取り出して notify の `env` に入れる | aratam は変えない (秘密は環境変数で受け取る。ADR 0044)。リポジトリの secret は書き込み権限のある人が別のブランチから読み出せるが、実行用ロールは `sub` で main に絞ってあるので、この経路を塞げる。取り出した値をログに出さない (`::add-mask::`)、ほかの step に渡さない |
| 中 | aratam の通知の末尾のパス | 通知の末尾に `--in` の report.md のパスを出しているが、GitHub Actions ではランナーの一時ディレクトリのパスで、読む人に意味がない。出し方を見直す (設定で表示する場所を渡す、ストアの `reports/` を案内する、出さない、など) | WAF の提案の全文 (`waf-proposals.md`) のパスも同じ |
| 中 | allowlist の雛形共有 | 監査対象をまたいで共通になる承認 (開発会社の switch role、CDK の bootstrap ロール `cdk-hnb659fds-*` など) | 設計書 11 章の未決。CDK を使うアカウントでは deploy のたびに unknown_assume_role / iam_changes が出る |
| 中 | ack / snooze / resolve の理由と操作した人の記録 | `--by` / `--reason` を足し、ストア (findings か finding_events) に残して report / review に出す | ADR 0042 で見送り。今は GitHub Actions の見本 (`arata-triage.yml`) が実行の Summary に残すだけで、保持期間で消える。スキーマの変更と移行、S3 ストアの互換が要る |
| 中 | `allowlist_stale` | 承認済みの主体で長く観測が無いものを棚卸しとして報告 | weekly / info。承認の期限 (`expires`) との関係を整理 |
| 中 | Insights の読み取りをさらに減らす | (1) 前回の続きから読み、時間幅の細かい行を保存して日次を Go で作り直す (2) フィールドインデックス (`filterIndex`) を doctor で案内し、あれば使う | ADR 0031 の検討した選択肢。(1) は IP と生パスの保存・schema の更新・pct の再現が論点。(2) は sandbox で効果を測ってから |
| 中 | endpoint_abuse の複数ソースの異なり IP | 1 つの画面を複数のソースで数えると、異なり IP 数が和集合でなく足し算になる | ADR 0031。ソースは別のロググループなので 1 本にまとめられない |
| 中 | Insights の 1 日あたり費用上限 | ソース単位の `max_scan_gb` に加え、監査対象全体の 1 日上限と縮退 | 設計書 11 章の未決。WAF ログを読むと量が増える |
| 低 | 古いパスワード | 認証情報レポートからパスワード未変更の期間を見る | `credential_hygiene` に閾値を足す形 |
| 低 | prune | 保持期間を過ぎたデータの削除 | 設計書 5-3 章。`finding_events` の扱いを決める。rebuild は実装済み (5-4、ADR 0033) |
| 低 | `openai-api` プロバイダ | Chat Completions を `net/http` で | `docs/aratam.md` 3-1 章 |
| 低 | Lambda ハンドラ | `s3://` ストア (ADR 0034) の上に Lambda で動かす | 設計書 9 章。cron で回す運用なら後回し |
| 低 | 国判定 | IP → 国。MaxMind 同梱か GuardDuty 頼みか | 設計書 11 章の未決 |

## 4. 未決の判断 (利用者側に確認する)

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

## 6. 公開後の課題

公開前の点検 (ADR 0037) で見つけ、公開後に Issue にする項目。高い重大度のものは公開前に直した。

検知の取りこぼし:
- `unknown_assume_role`: OIDC / SAML の AssumeRole は主体の ARN が無く、報告されない (playbook の記述と合わせる)
- `iam_changes` の対象外の操作: `CreatePolicyVersion`・`SetDefaultPolicyVersion`・`AddUserToGroup`・`UpdateLoginProfile`・`CreateRole`・`DeactivateMFADevice`・境界の変更など
- パスの照合が生の文字列: 大文字小文字、連続スラッシュ、`%xx`、末尾の `/`、絶対 URI の形で `login_bruteforce`・`probe_paths`・`waf_review` の除外をすり抜ける
- 解釈率が閾値を切るとそのソースの集計を全部止める。ごみの HTTP で検知を止められる。解釈できた行は出し、未解釈の急増を finding にする
- `ip` を検証していない: X-Forwarded-For を対応させた設定で、許可 IP の騙り、値を変えた閾値の回避、finding の増加が起きる
- 同じ Key への集約で根拠が隠れる (`iam_changes` の `policy_arn`、`defense_evasion` の `changes`、`public_exposure` の `public_statements`)
- GuardDuty の `UpdateDetector` の旧形式 (`dataSources`) の無効化を見ていない
- `secret_access` が `GetParameterHistory` を見ない
- Lambda の権限の条件 (`lambda_conditions`) も値を見ていない
- CloudTrail の項目の型が想定と違う記録は無言で捨てる。捨てた件数を stats に出す
- `s3express.amazonaws.com` (ディレクトリバケット) の `PutBucketPolicy`・`DeleteBucketPolicy` を `public_exposure` が評価しない
- サインインの別の eventName (`UserAuthentication`・`CredentialVerification`・`CreateOAuth2Token` など) を残していない
- `CreateFunctionUrlConfig`・`UpdateFunctionUrlConfig` (Lambda の公開) を見ていない
- `DeleteAccountPublicAccessBlock` の eventSource を実際の記録で確かめる (`Put` は `s3.amazonaws.com` と確認済み。`docs/cloudtrail-event-names.md`)

堅牢さ:
- `probe_paths` の key に json / regex 形式でクエリ文字列が残る。長さと件数の上限が無い
- `arata review` と doctor の表が制御文字をそのまま出す
- `isServiceLinkedRole` が部分一致
- 許可 IP が Top N の枠を消費する (`baseline`、`waf_block_trend`)
- `secret_access` の `paths`、`ips` に上限が無い
- `Mask` が二重の URL エンコードや非 ASCII のローカル部を伏せない
- API のページングの繰り返しに上限が無い
- `--` の後もフラグとして解釈する。位置引数を黙って無視する (`arata run hourly`)
- 期間の設定値の整数オーバーフロー
- rebuild: パスに `[` があると 0 ファイルになる。不正な行があっても終了コード 0。raw の改竄は検知しない
- 異常終了した run が期間レポートの「取れなかった run」に出ない
- `store: dir://相対パス` が作業ディレクトリ基準
- agegate: 入力 0 件で成功する、疑似バージョンの日付はコミット時刻で偽装できる
- allowlist の `expected_denied: ["*:*"]` を拒否していない。同じ ARN の重複を許す
