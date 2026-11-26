# iam_changes: IAM の権限変更

## この指摘の意味

権限を広げ得る IAM の変更 (または変更の試行) があった (daily、medium。`tags: [deploy]` の承認済み主体なら info)。
対象は `CreateAccessKey`・`CreateUser`・`CreateRole`・`CreateLoginProfile`・`UpdateAssumeRolePolicy`・`Attach*Policy`・`Put*Policy` と、サインインの長さを変えた `UpdateLoginProfile`。侵入者が居座るための典型的な操作でもある。

**既知デプロイ主体でも下げない変更** (`not_lowered` に理由。CI のロールを奪った者の手口):

- `CreateAccessKey` → medium (`access_key`)
- `UpdateAssumeRolePolicy` / `CreateRole` の信頼ポリシーに、そのアカウントの外の主体がある → medium (`trust_external`。`trust_external_accounts`・`trust_external_federated`)
- 信頼ポリシーが誰でも (`*`) を許す → **high** (`trust_wildcard`。デプロイ主体でない主体も high)。`trust_has_condition: true` は Condition があるという事実だけで、
  条件が実際に絞っているかは判定していない
- 信頼ポリシーを読めない → medium (`trust_unreadable`。拒否された呼び出し、以前の版で集めた記録、決まった形でない主体)
- `UpdateLoginProfile` でサインインの長さ (`maxSigninSessionDuration`) を変えた → medium (`signin_duration`。ADR 0092)。
  `max_signin_session_duration` は秒 (同じ Key の中でいちばん新しい記録の値)。延ばしたか縮めたかは、前の値が記録に無いので出さない。
  パスワードだけの変更は報告しない。ロールのサインインの長さ (`UpdateRole`) は記録の形を確かめていないので見ない

- Key は `<操作>|<変更した主体>|<対象>`
- data: `principal`、`principal_kind`、`target` (ユーザー名・ロール名・グループ名・ポリシー名)、`policy_arn`、`count`、`ips`、
  `known_deploy_principal`、`not_lowered`、`max_signin_session_duration`、`trust_policy` (ok / unreadable)、`trust_wildcard`、`trust_external_accounts`、`trust_external_federated`、`trust_has_condition`、
  `denied` (すべて拒否された試行)、`has_errors` (失敗が混ざる)、`error_codes`
- `denied: true` は変更は起きていないが、権限の無い主体が IAM を変えようとした (対象は記録されないので「不明」)
- GitHub の OIDC から来たセッション (`oidc_origins`。ADR 0081): 呼び出し側のセッションを 1 段目の `AssumeRoleWithWebIdentity` までキーの一致でたどれたら、1 段目の `repo`・`ref` / `environment`・`run_id`・`assumed_at`・`chain_depth` が付く (たどれない理由は `oidc_origin_unmatched`)。
  **手がかりであって証拠ではない**。`run_id` はふつう無い (今の configure-aws-credentials は userAgent に入れない)。実行は `repo` の Actions の一覧から `environment` / `ref` と `assumed_at` で人に探してもらう。読み方は `arata help ai playbook oidc_assume_role`

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
4. **片付け**: 片付けは下の「片付け」の節。作業として確かめた 1 回の変更は resolve、続く作業なら作業の終わりで snooze
5. **設定の修正**: IAM の変更を IaC のパイプラインに寄せる、人の主体から IAM の書き込み権限を外す

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high・medium・info | なし | approve・snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- approve: 変更した主体が正規のデプロイ主体なら `--tag deploy` (以後この主体の IAM 変更は info)。人の主体には付けない
- resolve: 作業として確かめた 1 回の変更 (導入作業でロールを作った、など)。同じ変更がまた起きれば新規として報告される
- snooze: 続く作業なら、作業の終わりの日まで
- 信頼ポリシーの変更は同じ Key のまま high になりうるが、多くの変更は上がらないので ack は許さない
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- `known_deploy_principal` (info) でも、操作が役割と合わないものを見逃さない
- `trust_has_condition: true` を「条件で絞られているので問題ない」と書かない (条件の中身は CloudTrail と今の信頼ポリシーで確かめる)
- 外のアカウントが `principals` で承認済みでも、信頼ポリシーに足してよいとは限らない (承認は「呼び出し元として既知」)
- 拒否された試行 (`denied`) を「変更は起きていないので問題なし」と書かない
- LLM が IAM を変更しない。元に戻す操作も提案まで
- `oidc_origins` があることや、既知のリポジトリ・environment から来たことだけを理由に、片付けたり「CI の正規の操作」と書いたりしない (`run_id` は呼ぶ側が書ける。ADR 0081)

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats wfx-loot-2026-11`: 長期のアクセスキーを作り、ロールの信頼ポリシーを広げる段階 (出典はスクリプトの機能として書く。既知デプロイ主体でも下げない)
- `arata help ai threats env-extortion-2024-08`: ロールを作り、`AdministratorAccess` を付けた段階
- `arata help ai threats scarleteel-2023-02`: ユーザーの作成とアクセスキーの作成を試みて拒否された段階
- `arata help ai threats lucr-3-2023-09`: ポリシーの書き換えと、IAM ユーザー・アクセスキー・ログインプロファイルの作成で居座る段階
