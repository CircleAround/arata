# public_exposure: 資源を外部に開く設定変更

## この指摘の意味

セキュリティグループ・S3・RDS・スナップショット / AMI・Lambda を外部に開く設定変更が**成功した** (daily)。
情報の持ち出しや侵入の入口になり得る。意図した公開でも毎回見るため、`tags: [deploy]` の主体でも重大度を下げない (data の `known_deploy_principal` に残す)。

| 変更 | 重大度 |
|---|---|
| セキュリティグループの ingress を 0.0.0.0/0・::/0 に開けた: 機微なポート (`checks.public_exposure.sensitive_ports`) か全ポート | high |
| 同上: その他のポート (443 など) | low |
| `ModifySecurityGroupRules` (記録に ingress / egress の向きが無い) | 上の 1 段下 (high → medium) |
| S3 のバケットポリシーで誰でも (Principal `*`) に条件なしで Allow。`aws:SecureTransport` だけの条件は公開とみなす | high |
| S3 の ACL で AllUsers / AuthenticatedUsers に付与、公開の既定 ACL (`public-read` など) | high |
| S3 の Public Access Block の削除・無効化 (バケット単位・アカウント単位) | high |
| RDS の `PubliclyAccessible=true` (インスタンス・クラスター) | high |
| EBS スナップショット・AMI・RDS スナップショットの全員への共有 (`all`) | high |
| Lambda の AddPermission で Principal `*` (関数 URL の AuthType NONE、または送信元の条件なし) | medium |

- Key は `<サービス>:<操作>|<資源>|<開いた中身>` (例 `ec2:AuthorizeSecurityGroupIngress|sg-0abc|tcp/22 0.0.0.0/0`)。同じ資源を同じように開いた呼び出しは主体をまとめて 1 件
- data: `api`、`target`、`exposure`、`principal` / `principals`、`sensitive`、`direction_unknown`、`public_statements` (`Sid: action,...`)、
  `known_deploy_principal`、`count`、`ips`、`first_time`、`last_time`。ポリシー全文は残していない

## まず確かめること

1. 今も開いているか:
   - セキュリティグループ: `aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg>`。どの資源に付いているか: `aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg>`
   - S3: `aws s3api get-bucket-policy-status --bucket <b>`、`get-bucket-policy`、`get-bucket-acl`、`get-public-access-block`、`aws s3control get-public-access-block --account-id <自アカウント>`
   - RDS: `aws rds describe-db-instances --db-instance-identifier <id> --query 'DBInstances[0].PubliclyAccessible'`
   - スナップショット: `aws ec2 describe-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission`、`aws rds describe-db-snapshot-attributes --db-snapshot-identifier <id>`
   - Lambda: `aws lambda get-policy --function-name <fn>`、`aws lambda get-function-url-config --function-name <fn>`
2. 中身: 何が公開されたか (バケットの中身・DB の種類・スナップショットの元の資源)。個人情報や秘匿値を含み得るか
3. 外からの利用の痕跡: S3 のサーバーアクセスログ・CloudTrail のデータイベント、VPC フローログ、GuardDuty の findings (`arata review`)。
   weekly の access_analyzer・posture も同じ公開を状態として出す
4. 操作した主体: `arata review --format json` で同じ主体の他の指摘 (iam_changes・access_denied・defense_evasion) を探す
5. 作業の記録 (変更の申請・IaC の PR) と利用者の事情 (context_file)。公開が仕様の資源 (静的サイトのバケット・公開の API) か

## 判断の分かれ目

- **正規の可能性が高い**: 公開が仕様の資源 (静的サイト・公開の API・CDN の配信元) で、作業の記録がある。443 / 80 の公開 (low) で、ロードバランサーの SG
- **要対応**: SSH / RDP / DB などの機微なポートの公開、DB・スナップショットの公開、中身の分からないバケットの公開、作業の記録が無い、
  人の主体・既知外の主体による変更、他の指摘と同じ主体・同じ時間帯。すぐ閉じた (開けて閉じた) 場合も、開いていた間の利用を確かめる

## 対処の選択肢

緊急度の順。封じ込めと設定の修正は**人が判断して実行する**。LLM は提案まで。

1. **閉じる** (意図しない公開): SG のルールを消す (`aws ec2 revoke-security-group-ingress`)、バケットポリシー / ACL を戻す・Public Access Block を有効に戻す、
   `PubliclyAccessible` を false に戻す、スナップショット / AMI の共有を外す、Lambda の権限を消す (`aws lambda remove-permission`)
2. **封じ込め** (侵害の疑い): 操作した主体の認証情報を止める。公開されていた中身 (秘匿値・鍵) を入れ替える
3. **承認**: allowlist の承認では重大度は下がらない (公開は毎回見る)。意図した公開なら ack
4. **expected_denied**: 対象外 (成功した操作だけを見ている)
5. **ack / snooze**: 意図した公開と確かめた変更は ack (同じ資源を別の形で開けば別の Key で再報告される)
6. **設定の修正**: アカウント単位の Public Access Block を有効にする、SG の変更を IaC に寄せる、SSH の代わりに Session Manager を使う。
   機微なポートの一覧が合わなければ `checks.public_exposure.sensitive_ports` を見直す

## やってはいけないこと

- 「すぐ閉じたので問題なし」と書かない。開いていた間の利用を確かめるまで閉じない
- deploy タグの主体の変更でも、公開の中身を確かめずに ack しない
- 公開された中身 (秘匿値など) を report・通知・会話に書き写さない
- LLM が SG・バケット・DB の設定を変えない。閉じる操作も提案まで

## 関連する事例

対応する公開の事例はまだ無い (`arata help ai threats`)。
