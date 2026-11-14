# posture: アカウントの姿勢

## この指摘の意味

アカウントの基本の守りが欠けている (weekly、状態型。項目ごとに 1 件。直れば resolved)。
権限不足などで取れなかった項目は、前回の finding を維持する (`coverage.sources_failed` に `partial: true`)。権限が外れたことを「直った」と誤認しないため。

| Key | 意味 | 重大度 |
|---|---|---|
| `cloudtrail_logging` | 記録中のマルチリージョンの CloudTrail 証跡が無い | high |
| `cloudtrail_log_validation` | ログファイルの検証が無効な証跡がある | medium |
| `guardduty_enabled\|<region>` | そのリージョンで GuardDuty が有効でない | high |
| `root_mfa` | ルートユーザーに MFA が無い | high |
| `s3_public_access_block` | アカウント単位の S3 Public Access Block が未設定か、4 項目のどれかが無効 | high |
| `alb_waf\|<region>\|<ALB>` | インターネット向けの ALB に WAF (WAFv2 の WebACL) が付いていない (ALB ごと。internal は対象外) | medium |
| `password_policy` | IAM のパスワードポリシーが未設定か、最小文字数が `min_password_length` (既定 14) 未満 | medium |

## まず確かめること

1. 新しく出たのか、前からあるのか (`first_seen`)。**前は問題なかった項目が急に悪くなった**なら、誰かが守りを外した可能性がある。CloudTrail で変更を探す:
   `StopLogging`・`DeleteTrail`・`UpdateTrail` (CloudTrail)、`DeleteDetector`・`UpdateDetector` (GuardDuty)、`DeleteAccountPublicAccessBlock`・`PutAccountPublicAccessBlock` (S3 のアカウント単位)、`DeleteAccountPasswordPolicy`。
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<操作>`
2. 項目ごとの今の状態 (読み取り):
   - CloudTrail: `aws cloudtrail describe-trails` と `aws cloudtrail get-trail-status --name <証跡>` (`IsLogging`)。`IsMultiRegionTrail`・`LogFileValidationEnabled`
   - GuardDuty: `aws guardduty list-detectors --region <region>` と `aws guardduty get-detector --detector-id <ID> --region <region>` (`Status`)
   - ルートの MFA: `aws iam get-account-summary` の `AccountMFAEnabled`
   - S3: `aws s3control get-public-access-block --account-id 123456789012`
   - パスワードポリシー: `aws iam get-account-password-policy` (未設定なら NoSuchEntity)
   - ALB の WAF: `aws wafv2 get-web-acl-for-resource --resource-arn <data.arn> --region <region>` (WebACL が無ければ `WebACL` が返らない)。
     前は付いていたなら CloudTrail で `DisassociateWebACL`・`DeleteWebACL` を探す。Scheme と用途は `aws elbv2 describe-load-balancers --names <ALB>`
3. `coverage.sources_failed` に `partial: true` があれば、どの項目が取れていないか (`action` の権限) を確かめる。取れていない項目は今の状態が分からない
4. `arata review --format json` で、同じ時期の root_usage・iam_changes・access_denied を探す (守りを外した主体の手がかり)
5. S3 の Public Access Block を有効にする前に、意図して公開しているバケットが無いかを確かめる (静的サイトは CloudFront の OAC で非公開のまま配信できる)

## 判断の分かれ目

- **前からある欠け**: 設定の不備。計画して直す (緊急ではないことが多い)
- **ALB の WAF**: WAF は最低限の防御として勧めるが、無いこと自体は侵害の兆候ではない (medium)。前から無いなら計画して付ける。
  送信元をセキュリティグループで固定の相手に絞っている、前段の CloudFront に WebACL がある (ALB は CloudFront からだけ受ける) なら、理由を記録して ack
- **要対応**: 急に悪くなった項目 (特に CloudTrail の停止・GuardDuty の無効化)。侵入者が最初に行う「監査の無効化」の疑いとして扱い、同じ時期の他の finding を探す

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (守りが外された): 外した主体を突き止め、その認証情報を止める (キーの無効化・`Revoke sessions`)。CloudTrail は `aws cloudtrail start-logging --name <証跡>` で再開する
2. **承認**: 対象外
3. **expected_denied**: 対象外
4. **ack / snooze**: 直す予定の日が決まっていれば snooze。意図して外している (例: 使わないリージョンを SCP で止めていて GuardDuty を入れない) なら理由を記録して ack
5. **設定の修正**: マルチリージョンの証跡を作る (`--is-multi-region-trail`)、ログファイルの検証を有効にする (`--enable-log-file-validation`)、
   GuardDuty を有効にする、ルートに MFA を付ける、S3 の Public Access Block の 4 項目を有効にする、パスワードポリシーを設定する
   (`aws iam update-account-password-policy --minimum-password-length 14` など)。可能なら IaC で。
   ALB の WAF は、REGIONAL の WebACL を作って ALB に関連付ける (`aws wafv2 associate-web-acl`)。**マネージドルールはまず COUNT で入れ**、
   WAF のログで誤検知が無いことを確かめてから BLOCK に変える。ログを CloudWatch Logs に出せば waf_block_trend・waf_review でも見られる

## やってはいけないこと

- 取れなかった項目 (`partial`) を「問題なし」と書かない
- 公開しているバケットを確かめずに Public Access Block の有効化を勧めない (配信が止まる)
- WebACL をいきなり BLOCK で付けることを勧めない (正規のリクエストが止まる)。前段の守りを確かめずに「無防備」と断定しない
- LLM が設定を変更しない

## 関連する事例

対応する公開の事例はまだ無い (`arata help ai threats`)。
