# new_principal: 新規の主体

## この指摘の意味

allowlist にもベースライン (`arata init` の時点で見えた主体) にも無い主体が、CloudTrail に初めて現れた (daily、medium、状態型)。
承認されるまで毎回観測され、still_open として残る。承認の期限が切れた主体も `allowlist_status: expired` で出る。

- Key は主体の ARN (ロールのセッションはロールの ARN にまとめる)。ルートは root_usage が扱うので対象外
- data: `kind` (user / role / assumed-role / unknown)、`external_account`、`first_seen` / `last_seen`、`count`、`ips`、`allowlist_status`

## まず確かめること

1. `arata review --format json` で、同じ主体の unknown_assume_role・access_denied・iam_changes を探す。重なればまとめて書く
2. 主体の名前と種類から役割を推定する (CI のロール、新しいアプリのロール、社員の IAM ユーザー、外部アカウント)。推定は「可能性」と書く
3. 作られた経緯: その主体の作成イベントを CloudTrail で引く (IAM ユーザーなら `CreateUser`、ロールなら `CreateRole`)。
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<ユーザー名かロール名>` (90 日以内。IAM のイベントは us-east-1)
4. 誰が作ったか (作成イベントの主体) が既知のデプロイ主体か。iam_changes の finding と重なるか
5. 送信元 `ips` が業務の場所・CI のランナー・SaaS の公開レンジと整合するか
6. 主体の権限: `aws iam list-attached-role-policies --role-name <名前>` / `aws iam list-attached-user-policies --user-name <名前>`。役割に対して広すぎないか

## 判断の分かれ目

- **正規の可能性が高い**: IaC や既知のデプロイ主体が作った、名前と権限が役割に合う、送信元が整合する、利用者の事情に説明がある
- **要対応**: 作成者が不明・既知外、作成直後から IAM の変更や拒否の急増がある、権限が広い (AdministratorAccess など)、送信元が業務と合わない
- 導入直後で既存の正規の主体が多数出る場合は、ベースラインの取り直しではなく 1 つずつ承認するのが原則 (侵入済みの主体を紛れ込ませないため)

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): IAM ユーザーならアクセスキーを無効化 (`aws iam update-access-key --user-name <名前> --access-key-id <キー> --status Inactive`)、
   ロールなら信頼ポリシーの見直しと `Revoke sessions`。作成者の主体も調べる
2. **承認**: 正規なら `arata approve <id> --note "<理由>"` を人に提案する。一時的な主体は `--expires`、デプロイ主体は `--tag deploy`、監査・AI 用は `--tag ai`。
   同じ役割で名前が増える主体は `--arn-pattern`。基準は `arata help ai approve`
3. **expected_denied**: 対象外
4. **ack / snooze**: 判断を保留するなら ack (未対応一覧に残る)。`resolve` は状態型なので次の run で再び new になる。承認せずに止めたいときは使わない
5. **設定の修正**: 不要な主体は削除する (人が判断)

## やってはいけないこと

- 名前がそれらしいだけで承認を勧めない。作成者・権限・送信元を根拠に書く
- 広い `arn_pattern` (アカウント全体に近いもの) を提案しない
- LLM が `arata approve` を実行しない
