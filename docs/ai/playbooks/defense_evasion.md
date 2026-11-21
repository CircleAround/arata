# defense_evasion: 監査・検知の仕組みを止める・弱める操作

## この指摘の意味

CloudTrail・GuardDuty・Access Analyzer・CloudWatch Logs・VPC フローログ・AWS Config・Security Hub・WAF のログ・証跡の宛先バケットを
止める・弱める操作が**成功した** (daily)。侵入者が最初にやることの 1 つ (足跡を消し、検知を止めてから本題に入る)。失敗した試行は access_denied が扱う。

- 重大度: CloudTrail の `StopLogging` / `DeleteTrail` と、arata の監査対象のロググループ (cloudwatch-logs のソース) への削除・保持期間の短縮は critical。他は high。
  allowlist で `tags: [deploy]` の承認済み主体なら 1 段下げる (critical → high、high → medium。info にはしない)
- 「弱めた」かは要求の内容だけで判断している (CloudTrail には前の値が残らない)。弱めたか分からない変更 (UpdateTrail の SNS の変更、データイベントの追加など) は出ない
- Key は `<サービス>:<操作>|<主体>|<対象>`
- data: `api`、`principal`、`principal_kind`、`target` (証跡名・detector・アナライザー/ルール・ロググループ・フローログ・レコーダー・WebACL の ARN・バケット)、
  `reason`、`changes` (`multi_region=false`・`log_validation=false`・`s3_bucket=...`・`include_management_events=false`・`enable=false`・`<機能>=DISABLED` など)、
  `audit_log_group`、`retention_days` / `min_log_retention_days`、`shorter_than_baseline_days` (arata の平常帯の日数より短い)、
  `lifecycle_expiration_days`、`known_deploy_principal`、`count`、`ips`、`first_time`、`last_time`
- GitHub の OIDC から来たセッション (`oidc_origins`。ADR 0081): 呼び出し側のセッションを 1 段目の `AssumeRoleWithWebIdentity` までキーの一致でたどれたら、1 段目の `repo`・`ref` / `environment`・`run_id`・`assumed_at`・`chain_depth` が付く (たどれない理由は `oidc_origin_unmatched`)。
  **手がかりであって証拠ではない**。`run_id` はふつう無い (今の configure-aws-credentials は userAgent に入れない)。実行は `repo` の Actions の一覧から `environment` / `ref` と `assumed_at` で人に探してもらう。読み方は `arata help ai playbook oidc_assume_role`

## まず確かめること

1. 今も止まっているか (最優先。止まっている間は他の検知も効かない):
   - CloudTrail: `aws cloudtrail get-trail-status --name <証跡>` の `IsLogging`、`aws cloudtrail describe-trails` (マルチリージョン・ログ検証・宛先)、`aws cloudtrail get-event-selectors --trail-name <証跡>`
   - GuardDuty: `aws guardduty get-detector --detector-id <id>` の `Status` と `Features`、`aws guardduty list-filters` (ARCHIVE のフィルタ)
   - Access Analyzer: `aws accessanalyzer list-analyzers`、`aws accessanalyzer list-archive-rules --analyzer-name <名前>`
   - ログ: `aws logs describe-log-groups --log-group-name-prefix <名前>` (残っているか・`retentionInDays`)
   - Config: `aws configservice describe-configuration-recorder-status`。Security Hub: `aws securityhub get-enabled-standards`。WAF: `aws wafv2 get-logging-configuration --resource-arn <ARN>`
2. 操作した主体と送信元: `arata review --format json` で同じ主体の new_principal・unknown_assume_role・access_denied・iam_changes を探す。
   拒否の急増や IAM 変更の後の無効化は、侵害が進んでいる疑いが強い
3. 中身を CloudTrail で見る: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<操作> --start-time <first_time> --end-time <last_time> --region <リージョン>`
   (証跡を止められても LookupEvents の管理イベントは 90 日残る)
4. 止めていた間に何が起きたか: 同じ時間帯の `RunInstances`・IAM の変更・秘匿値の読み取りなどを LookupEvents で探す
5. 作業の記録 (変更の申請・IaC の PR) と、利用者の事情 (context_file) に説明があるか

## 判断の分かれ目

- **正規の可能性が高い**: 既知のデプロイ主体による IaC の変更で、対応する PR がある (証跡の作り直し・ロググループの整理・費用のための保持期間の見直しなど)。
  sandbox や検証用の資源で、作業の記録がある
- **要対応**: 人の主体・既知外の主体による操作、作業の記録が無い、`StopLogging` / `DeleteTrail`、GuardDuty の無効化や ARCHIVE のフィルタ、
  arata の監査対象のロググループの削除・保持期間の短縮 (`shorter_than_baseline_days` なら arata の平常帯も作り直せない)、
  他の指摘 (access_denied・iam_changes・unknown_assume_role) と同じ主体・同じ時間帯

## 対処の選択肢

緊急度の順。封じ込めと設定の修正は**人が判断して実行する**。LLM は提案まで。

1. **元に戻す** (今も止まっているなら最優先): `aws cloudtrail start-logging --name <証跡>`、証跡の設定を戻す、GuardDuty を有効に戻す・ARCHIVE のフィルタを消す、
   アーカイブルールを消す、ロググループの保持期間を戻す、Config のレコーダーを `start-configuration-recorder` で再開する、WAF のログ設定を戻す
2. **封じ込め** (侵害の疑い): 操作した主体の認証情報を止める (アクセスキーの無効化、ロールの `Revoke sessions`)。止めていた間の操作を調べる
3. **承認**: 正規のデプロイ主体なら、allowlist.yaml の principals にその主体を `tags: [deploy]` で人が書く (PR で。重大度が 1 段下がるが、報告は続く)。`arata approve` はこのチェックの finding を受け付けない
4. **expected_denied**: 対象外 (成功した操作だけを見ている)
5. **片付け**: 片付けは下の「片付け」の節。ack はできない (同じ Key のまま重大度が上がらないので、ack すると最後になる)
6. **設定の修正**: 監査の設定を変える権限を IaC のパイプラインに寄せる。SCP で `cloudtrail:StopLogging`・`guardduty:DeleteDetector` などを拒否する。
   保持期間の下限が合わなければ `checks.defense_evasion.min_log_retention_days` を見直す。証跡の宛先が別のバケットなら `trail_buckets` に書く

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| critical・high・medium | なし | snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- resolve: 作業として確かめた 1 回の変更で、守りを元に戻した (または意図した設定だと確かめた) なら resolve。同じ操作がまた起きれば新規として報告される
- snooze: 作業が続く間だけ、作業の終わりの日まで
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- deploy タグの主体 (重大度が 1 段下がったもの) を「いつものデプロイ」として見逃さない。監査の無効化は IaC でも人が見る
- 「今は戻っている」ことを確かめずに ack しない。止まっていた間の操作を調べずに閉じない
- LLM が証跡・GuardDuty・ログの設定を変えない。元に戻す操作も提案まで
- 削除されたロググループ・止められた間のログが残っていると書かない (戻せないものは戻せないと伝える)
- `oidc_origins` があることや、既知のリポジトリ・environment から来たことだけを理由に、片付けたり「CI の正規の操作」と書いたりしない (`run_id` は呼ぶ側が書ける。ADR 0081)

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats scarleteel-2023-02`: CloudTrail の記録を止めた段階 (`StopLogging`)
- `arata help ai threats lucr-3-2023-09`: GuardDuty の detector を消し、CloudTrail を止める・消す段階
