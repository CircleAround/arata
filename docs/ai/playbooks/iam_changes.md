# iam_changes: IAM の権限変更

## この指摘の意味

権限を広げ得る IAM の変更 (または変更の試行) があった (daily、medium。`tags: [deploy]` の承認済み主体なら info)。
対象は `CreateAccessKey`・`CreateUser`・`CreateRole`・`CreateLoginProfile`・`UpdateAssumeRolePolicy`・`Attach*Policy`・`Put*Policy`。侵入者が居座るための典型的な操作でもある。

**既知デプロイ主体でも下げない変更** (`not_lowered` に理由。CI のロールを奪った者の手口):

- `CreateAccessKey` → medium (`access_key`)
- `UpdateAssumeRolePolicy` / `CreateRole` の信頼ポリシーに、そのアカウントの外の主体がある → medium (`trust_external`。`trust_external_accounts`・`trust_external_federated`)
- 信頼ポリシーが誰でも (`*`) を許す → **high** (`trust_wildcard`。デプロイ主体でない主体も high)。`trust_has_condition: true` は Condition があるという事実だけで、
  条件が実際に絞っているかは判定していない
- 信頼ポリシーを読めない → medium (`trust_unreadable`。拒否された呼び出し、以前の版で集めた記録、決まった形でない主体)

- Key は `<操作>|<変更した主体>|<対象>`
- data: `principal`、`principal_kind`、`target` (ユーザー名・ロール名・グループ名・ポリシー名)、`policy_arn`、`count`、`ips`、
  `known_deploy_principal`、`not_lowered`、`trust_policy` (ok / unreadable)、`trust_wildcard`、`trust_external_accounts`、`trust_external_federated`、`trust_has_condition`、
  `denied` (すべて拒否された試行)、`has_errors` (失敗が混ざる)、`error_codes`
- `denied: true` は変更は起きていないが、権限の無い主体が IAM を変えようとした (対象は記録されないので「不明」)

## まず確かめること

1. 操作の種類で重さを見る:
   - `CreateAccessKey` (特に他人のユーザーへの)、`CreateLoginProfile` (コンソールのパスワードを作る) は認証情報の追加
   - `UpdateAssumeRolePolicy` / `CreateRole` はロールを誰が引き受けられるかの変更 (外部アカウントの追加は裏口になり得る。`*` はどの AWS アカウントからでも引き受けられる)
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

- `known_deploy_principal` (info) でも、操作が役割と合わないものを見逃さない
- `trust_has_condition: true` を「条件で絞られているので問題ない」と書かない (条件の中身は CloudTrail と今の信頼ポリシーで確かめる)
- 外のアカウントが `principals` で承認済みでも、信頼ポリシーに足してよいとは限らない (承認は「呼び出し元として既知」)
- 拒否された試行 (`denied`) を「変更は起きていないので問題なし」と書かない
- LLM が IAM を変更しない。元に戻す操作も提案まで

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats wfx-loot-2026-11`: 長期のアクセスキーを作り、ロールの信頼ポリシーを広げる段階 (出典はスクリプトの機能として書く。既知デプロイ主体でも下げない)
- `arata help ai threats env-extortion-2024-08`: ロールを作り、`AdministratorAccess` を付けた段階
- `arata help ai threats scarleteel-2023-02`: ユーザーの作成とアクセスキーの作成を試みて拒否された段階
- `arata help ai threats lucr-3-2023-09`: ポリシーの書き換えと、IAM ユーザー・アクセスキー・ログインプロファイルの作成で居座る段階
