# iam_changes: IAM の権限変更

## この指摘の意味

権限を広げ得る IAM の変更 (または変更の試行) があった (daily、medium。`tags: [deploy]` の承認済み主体なら info)。
対象は `CreateAccessKey`・`CreateUser`・`CreateLoginProfile`・`UpdateAssumeRolePolicy`・`Attach*Policy`・`Put*Policy`。侵入者が居座るための典型的な操作でもある。

- Key は `<操作>|<変更した主体>|<対象>`
- data: `principal`、`principal_kind`、`target` (ユーザー名・ロール名・グループ名・ポリシー名)、`policy_arn`、`count`、`ips`、
  `known_deploy_principal`、`denied` (すべて拒否された試行)、`has_errors` (失敗が混ざる)、`error_codes`
- `denied: true` は変更は起きていないが、権限の無い主体が IAM を変えようとした (対象は記録されないので「不明」)

## まず確かめること

1. 操作の種類で重さを見る:
   - `CreateAccessKey` (特に他人のユーザーへの)、`CreateLoginProfile` (コンソールのパスワードを作る) は認証情報の追加
   - `UpdateAssumeRolePolicy` はロールを誰が引き受けられるかの変更 (外部アカウントの追加は裏口になり得る)
   - `Attach*Policy` / `Put*Policy` は権限の付与。`policy_arn` が `AdministratorAccess`・`IAMFullAccess` や `*` を許すポリシーなら重い
2. `arata review --format json` で同じ主体の new_principal・unknown_assume_role・access_denied を探す。拒否の急増の後の変更は権限の列挙からの昇格の疑い
3. 変更の中身を CloudTrail で見る: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=<操作> --start-time <first_time> --end-time <last_time> --region us-east-1`。
   `requestParameters` (付けたポリシー・信頼ポリシーの本文・作ったキーの対象ユーザー) を確かめる
4. 今の状態: `aws iam get-role --role-name <対象> --query Role.AssumeRolePolicyDocument`、`aws iam list-access-keys --user-name <対象>`、
   `aws iam list-attached-user-policies --user-name <対象>` / `list-attached-role-policies --role-name <対象>`
5. 変更した主体が既知のデプロイ主体 (IaC のパイプライン) か。対応する変更 (IaC の PR・作業の記録) があるか。利用者の事情に説明があるか

## 判断の分かれ目

- **正規の可能性が高い**: 既知のデプロイ主体による、IaC に対応する変更がある、権限が役割に合う
- **要対応**: 人の主体や既知外の主体による変更、他人のユーザーへのアクセスキーの作成、知らない外部アカウントを信頼ポリシーに足した、管理者権限の付与、
  拒否の急増 (access_denied) の後の変更、`denied` の試行 (権限の無い主体が IAM を変えようとした)

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): 作られたアクセスキーを無効化する (`aws iam update-access-key --user-name <対象> --access-key-id <キー> --status Inactive`)、
   作られたログインプロファイルを消す、信頼ポリシー・付けたポリシーを元に戻す。変更した主体の認証情報も止める (キーの無効化、ロールの `Revoke sessions`)
2. **承認**: 変更した主体が正規のデプロイ主体なら `arata approve <id> --tag deploy --note "<理由>"` を人に提案する (以後この主体の IAM 変更は info)。
   `deploy` は IaC のパイプラインの主体だけに付け、人の主体には付けない
3. **expected_denied**: 対象外 (拒否の数を数えるのは access_denied)
4. **ack / snooze**: 作業として確認できた 1 回の変更は ack。続く作業なら作業の終わりで snooze
5. **設定の修正**: IAM の変更を IaC のパイプラインに寄せる、人の主体から IAM の書き込み権限を外す

## やってはいけないこと

- `known_deploy_principal` (info) でも、操作が役割と合わないもの (デプロイ主体が他人のアクセスキーを作るなど) を見逃さない
- 拒否された試行 (`denied`) を「変更は起きていないので問題なし」と書かない
- LLM が IAM を変更しない。元に戻す操作も提案まで
