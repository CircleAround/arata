# root_usage: ルートユーザーの利用

## この指摘の意味

自アカウントのルートユーザーが API またはコンソールを使った (hourly、critical)。ルートは IAM で制限できず、侵害されるとアカウントのすべてを失う。
ふだんの運用でルートを使う場面は、請求・アカウント設定・ルート専用の作業 (サポートプランの変更など) に限られる。

- Key は `<ルートの ARN>|<送信元 IP>`。送信元 IP が変われば別の finding になる
- data: `count`、`event_names` (操作の種類)、`ips`、`first_time` / `last_time`、`mfa` (MFA を使ったか。取れたときだけ)、`has_errors` (失敗した操作を含む)、
  `invoked_by` (送信元の IP が無いときだけ。ルートの代わりに API を呼んだ AWS のサービス名)
- 見出しが「AWS のサービス (`<名前>`) 経由で」のものは、AWS のサービスがルートの権限で呼んだ記録 (CloudTrail の `sourceIPAddress` と `userIdentity.invokedBy` がサービス名)。
  送信元の IP が無いのは記録の仕様で、「送信元不明」ではない。ルートでサインインした人がコンソールで行った操作に付随して出ることが多い。
  「IP の記録の無い送信元から」は、IP もサービス名も記録に無かったもの

## まず確かめること

1. `arata review --format json` で同じ時間帯の他の finding (iam_changes・access_denied・posture の root_mfa / credential_hygiene の root_access_key) を探す。重なれば 1 つの話としてまとめる
2. `event_names` を見る。`ConsoleLogin` だけか、IAM・請求・CloudTrail・GuardDuty などの変更があるか。`StopLogging`、`DeleteTrail`、`CreateAccessKey`、`CreateUser`、`DeleteDetector` は特に重い
3. `mfa` が false (MFA なしのサインイン) か、`has_errors` (失敗の混在。パスワードの総当たりや権限の無い操作の試行) があるか
4. 操作の詳細を CloudTrail で見る: コンソールの CloudTrail > イベント履歴で「ユーザー名」に `root` を入れる。CLI は
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root --start-time <first_time> --end-time <last_time>`
   (リージョンごと。IAM・請求・サインインの操作は多くが us-east-1 に記録される)
5. `invoked_by` があるとき (サービス経由): 同じ時間帯に、IP のあるルートのサインイン (`ConsoleLogin`) か操作の finding があるかを探す。
   あれば、その人の操作に付随したものとして 1 つの話にまとめる。無ければ、そのサービスの機能を誰が・いつ有効にしたかを CloudTrail で確かめる
6. 送信元 IP が業務の場所 (オフィス・管理者の回線) と整合するか。利用者の事情 (context_file など) にルートの利用予定が書かれていないか
7. ルートの認証情報の状態: `aws iam get-account-summary` の `AccountMFAEnabled` と `AccountAccessKeysPresent` (1 ならルートにアクセスキーがある)

## 判断の分かれ目

- **正規の可能性が高い**: 事前に決まった作業 (請求・アカウント設定) で、MFA あり、送信元が業務の場所、操作がその作業に限られる
- **要対応**: 予定に無い利用、MFA なし、見知らぬ送信元、IAM の作成・アクセスキーの作成・監査の無効化 (CloudTrail / GuardDuty の停止) を含む、
  失敗の連続 (`has_errors`)。どれか 1 つでも当てはまれば侵害の疑いとして扱う
- 迷ったら要対応にする (critical は通知の規則でも緊急扱い)

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): ルートのパスワードを変える、ルートのアクセスキーがあれば無効化・削除する (ルートでサインインしてセキュリティ認証情報の画面から)、
   MFA を登録し直す。ルートの操作で作られた IAM ユーザー・アクセスキー・ロールの信頼ポリシーの変更を洗い出して取り消す
2. **承認**: できない (root_usage は主体の承認の対象ではない)
3. **expected_denied**: 対象外
4. **ack / snooze**: 正規の作業と確認できたら `arata ack <id>` (人が実行)。同じ IP から続けて使う予定なら作業の終わりの日で `arata snooze <id> --until YYYY-MM-DD`
5. **設定の修正**: ルートに MFA を付ける、ルートのアクセスキーを持たない、日常の作業は IAM の主体 (IAM Identity Center など) で行う。ルートを使う作業は記録に残す

## やってはいけないこと

- critical を「たぶん正規」として情報扱いにしない。正規と確かめられるまで要対処として書く
- LLM がルートの認証情報・アクセスキーを操作しない (提案まで)。`arata ack` も LLM は実行しない
- サービス経由 (`invoked_by`) だけを理由に重大度を下げない・「送信元不明」とも書かない。きっかけになった人の操作を確かめる
- 送信元 IP や操作の一覧だけで「侵害ではない」と断定しない。裏取りしていないことは「可能性」と書く
