# access_analyzer: 外部からアクセスできる資源

## この指摘の意味

IAM Access Analyzer (外部アクセスのアナライザー) が、アカウントの外からアクセスできる資源を見つけた (weekly、状態型。アーカイブ・解消されると resolved)。
公開 (誰でも) なら high、特定の外部アカウントなどなら medium。資源のポリシー (バケットポリシー・KMS のキーポリシー・ロールの信頼ポリシー・Lambda・SQS・SNS・Secrets Manager など) が対象。

- Key は Access Analyzer の finding ID
- data: `resource` (ARN)、`resource_type`、`is_public`、`principal` (許可されている外部の主体)、`actions` (許可されている操作)、`analyzer`、`region`

## まず確かめること

1. 詳細: IAM コンソール > アクセスアナライザー (Access analyzer) > 結果 で finding を開く。CLI は
   `aws accessanalyzer list-analyzers --region <region>` で ARN を得て、`aws accessanalyzer get-finding --analyzer-arn <ARN> --id <finding ID> --region <region>`
2. 資源のポリシーを読む (読み取りのみ): S3 は `aws s3api get-bucket-policy --bucket <名前>` と `get-bucket-acl`、KMS は `aws kms get-key-policy --key-id <ID> --policy-name default`、
   ロールは `aws iam get-role --role-name <名前>`、Lambda は `aws lambda get-policy --function-name <名前>`、Secrets Manager は `aws secretsmanager get-resource-policy --secret-id <名前>`
3. `principal` の外部アカウントが既知か (自社の別アカウント・SaaS の公式のアカウント ID)。`111122223333` のような ID を利用者の事情と照らす
4. いつ変わったか: CloudTrail でポリシーの変更 (`PutBucketPolicy`・`PutKeyPolicy`・`UpdateAssumeRolePolicy`・`AddPermission` など) を引く
5. 公開なら、中身が公開してよいものか (静的な配信物か、利用者のデータ・バックアップか)
6. `arata review --format json` で、ポリシーを変えた主体の finding (iam_changes・new_principal・unknown_assume_role) を探す

## 判断の分かれ目

- **正規の可能性が高い**: 自社の別アカウント・既知の SaaS との連携、意図した公開 (公開の配信物で、条件や CloudFront の経由が設計どおり)
- **要対応**: 公開 (`is_public`) で中身が公開してよいと確かめられない、知らない外部アカウント、書き込み・削除の操作の許可、最近の変更で開いた

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (意図しない公開): ポリシーから公開の文・不明な主体を外す。S3 ならバケットの Public Access Block を有効にする。データが読まれた可能性があれば S3 のアクセスログ・CloudTrail のデータイベントを調べる
2. **承認**: 対象外 (arata の allowlist ではなく、Access Analyzer 側で扱う)
3. **expected_denied**: 対象外
4. **ack / snooze**: 意図したアクセスなら、Access Analyzer 側でアーカイブする (人が行う。arata では resolved になる)。同じ形が続くなら条件を絞ったアーカイブルールを人が作る。
   直す予定が決まっていれば `arata snooze`
5. **設定の修正**: 外部のアクセスに条件を付ける (`aws:PrincipalOrgID`・`aws:SourceVpce`・`sts:ExternalId` など)、公開の配信は CloudFront の OAC を経由する

## やってはいけないこと

- 公開されている中身を確かめずに「意図した公開」と書かない
- 広いアーカイブルール (資源の種類だけ・アカウント全体) を勧めない (新しい公開が見えなくなる)
- LLM がポリシー・Access Analyzer の設定を変更しない

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats wfx-loot-2026-11`: ロールの信頼ポリシーを、どの AWS アカウントからでも引き受けられる形に書き換える段階 (出典はスクリプトの機能として書く)
