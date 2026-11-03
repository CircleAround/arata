# unknown_assume_role: 既知リストに無い主体の AssumeRole

## この指摘の意味

allowlist に無い主体 (呼び出し元) が IAM ロールを引き受けた、または引き受けようとした (hourly、high)。
AWS のサービス主体 (EC2・Lambda などのインスタンスロール) は対象外。外部アカウントからのクロスアカウントの引き受けは「外部アカウント NNN」と表示される。

- Key は `<呼び出し元 ARN>-><引き受けたロール ARN>`
- data: `caller`、`caller_kind`、`role_arn`、`external_account` (外部アカウントのとき)、`allowlist_status` (unknown / expired)、`count`、`ips`、`event_names` (AssumeRole / AssumeRoleWithWebIdentity / AssumeRoleWithSAML など)、
  `has_errors` (失敗した引き受けを含む)

## まず確かめること

1. `arata review --format json` で、同じ呼び出し元の new_principal・access_denied・iam_changes を探す。同じ呼び出し元ならまとめて 1 つの話として書く
2. 呼び出し元が何者か: 自アカウントの IAM ユーザー / ロール、外部アカウント (SaaS 連携・自社の別アカウント)、OIDC (`AssumeRoleWithWebIdentity`。CI など)、SAML
3. 引き受けたロールの信頼ポリシー: `aws iam get-role --role-name <ロール名> --query Role.AssumeRolePolicyDocument`
   (コンソールは IAM > ロール > 対象 > 信頼関係)。Principal に何が書かれているか、`sts:ExternalId` などの条件があるか
4. `allowlist_status: expired` なら、以前承認した主体の期限切れ。期限の延長でよいかを確かめる
5. `has_errors` があれば引き受けは失敗している (信頼ポリシーで拒否)。成功が混ざるかは CloudTrail で確かめる:
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole --start-time <first_time> --end-time <last_time>`
6. 引き受けた後の操作: AssumeRole のイベントの `responseElements.credentials.accessKeyId` (一時キー) で
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<一時キー>` を引く
7. 外部アカウントなら、その ID が SaaS の公式ドキュメントに載っている ID か、自社の別アカウントかを確かめる

## 判断の分かれ目

- **正規の可能性が高い**: 社員の switch role、CI/CD の OIDC ロール、委託先・SaaS の公開されたアカウント ID からの引き受けで、操作が役割と合う
- **要対応**: 知らない外部アカウント、信頼ポリシーが広い (Principal が `*` やアカウント全体で条件が無い)、引き受けた後に IAM の変更・秘匿値の読み取り・大量の拒否がある、
  送信元が業務の場所と合わない
- 失敗だけ (`has_errors` で成功なし) は、引き受けられてはいないが、誰かが信頼関係を探っている兆候。信頼ポリシーの確認を勧める

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): ロールの信頼ポリシーから不審な主体を外す。発行済みのセッションは IAM > ロール > 対象の `Revoke sessions` で失効できる
   (`AWSRevokeOlderSessions` のインラインポリシーが付き、それより前に発行されたセッションを拒否する)
2. **承認**: 正規なら `arata approve <id> --note "<理由>"` を人に提案する。外部アカウントの root は `account:` で承認される。期限付きの委託は `--expires`。基準は `arata help ai approve`
3. **expected_denied**: 対象外 (access_denied のための設定)
4. **ack / snooze**: 承認したくないが当面続くもの (移行期間など) は ack、終わりが決まっているものは snooze
5. **設定の修正**: SaaS 連携の信頼ポリシーに `sts:ExternalId` の条件を付ける、Principal をアカウント全体ではなく特定のロールにする

## やってはいけないこと

- 外部アカウント ID を確かめずに `account:` で承認を提案しない (そのアカウントの全主体を通すことになる)
- 信頼ポリシーの変更やセッションの失効を LLM が実行しない
- 「外部アカウント NNN」を自アカウントのルートユーザーの利用 (root_usage) と混同しない
