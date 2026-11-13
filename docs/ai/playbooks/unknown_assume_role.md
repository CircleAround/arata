# unknown_assume_role: 既知リストに無い主体の AssumeRole

## この指摘の意味

allowlist に無い主体 (呼び出し元) が IAM ロールを引き受けた、または引き受けようとした (hourly、high)。
AWS のサービス主体 (EC2・Lambda などのインスタンスロール) は対象外。

### 呼び出し元がアカウントしか分からないとき (`caller_identity: account_only`)

引き受けられた側 (ロールのあるアカウント) の CloudTrail には、呼び出し元のアカウント ID しか残らない。相手のどの主体 (IAM ユーザー・ロール・CI) かは記録に無い。

- 見出しは「既知リストに無い外部アカウント 111122223333 (呼び出した主体は記録に無い) が自アカウントのロール Admin を 3 回引き受け (内向き、MFA 不明)」
- `caller` と Key の `arn:aws:iam::111122223333:root` は**アカウントそのもの**を指す ARN (承認・ack との一致のため変えていない)。
  **相手のルートユーザーが使われたことを表さない**。正規の CI や SaaS のロールの引き受けも同じ形になる
- 「外部アカウント 111122223333」と書く。「111122223333 の root」「ルートユーザーから」と書かず、ルートユーザーの利用を理由に緊急度を上げない
- どの主体だったかは相手のアカウントの CloudTrail にある。相手の管理者に時刻 (`first_time`〜`last_time`) とロール (`role_arn`) を伝えて確かめてもらう

見出しの末尾の括弧に、引き受けの**向き**と **MFA** が規則で書かれる。向きを自分で推測しない・書き換えない。

- **外向き** (`direction: outbound`): 監査対象のアカウント (自アカウント) の主体が、**別のアカウントのロール**を引き受けた。
  例「既知リストに無い自アカウントの user/alice が外部アカウント 111122223333 のロール partner-admin を 1 回引き受け (外向き、MFA あり)」。
  外部の主体が自アカウントに入ったのではない。危ないのは「自アカウントの主体 (の認証情報) が、知らない外部アカウントで使われた」こと
- **内向き** (`direction: inbound`): 別のアカウントの主体が、**自アカウントのロール**を引き受けた。自アカウントのロールの権限が外部に渡っている
- **内部** (`direction: internal`): 呼び出し元もロールも自アカウント
- 向きが書かれていない (`direction` が無い): 記録から決められなかった。`caller` と `role_arn` のアカウント ID を読み、どちらが自アカウントかを人に確かめる。推測で向きを書かない
- **MFA** (`mfa`): `true` (あり)・`false` (なし)・`unknown` (不明。記録に MFA の項目が無い。**「なし」ではない**)・`mixed` (イベントによって違う)

- Key は `<呼び出し元 ARN>-><引き受けたロール ARN>`
- data: `caller`、`caller_kind`、`caller_identity` (`account_only` のときだけ)、`role_arn`、`direction`・`caller_account`・`role_account` (向きが決まったとき)、`mfa`、`external_account` (そのときのアカウント ID)、`allowlist_status` (unknown / expired)、`count`、`ips`、`event_names` (AssumeRole / AssumeRoleWithWebIdentity / AssumeRoleWithSAML など)、
  `has_errors` (失敗した引き受けを含む)、`invoked_by` (送信元の IP が無く、AWS のサービス経由のとき。コンソールのスイッチロールなど)
- `ips` が無いのは、記録の送信元が AWS のサービス名で IP が無いとき (収集で落としているのではない)

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

### 外向き (outbound) のとき

1. 引き受けたのは外部アカウントのロール。自アカウントから `aws iam get-role` で信頼ポリシーは見られない。相手のアカウント ID (`role_account`) が何者か
   (自社の別アカウント、委託先、SaaS) を人に確かめる。知らないアカウントなら要対応
2. 呼び出し元 (`caller`) に `sts:AssumeRole` を許しているポリシーを確かめる: `aws iam list-attached-user-policies --user-name <名前>` / `aws iam list-user-policies --user-name <名前>`
   (ロールなら `list-attached-role-policies` / `list-role-policies`)。Resource が `*` なら、どのアカウントのロールでも引き受けられる
3. 引き受けた後の操作は**相手のアカウントの CloudTrail** に記録される。自アカウントの記録には出ない。相手のアカウントの管理者に確かめてもらう
4. `mfa` が `false` / `unknown` で、送信元 (`ips`) が業務の場所と合わないなら、呼び出し元のアクセスキー・パスワードの漏えいを疑う:
   `aws iam list-access-keys --user-name <名前>` と、同じ呼び出し元の他の finding (new_principal・principal_new_source・access_denied)

### 内向き (inbound) のとき

1. 引き受けられたのは自アカウントのロール。信頼ポリシー (上の 3) の Principal に相手のアカウント (`caller_account` / `external_account`) が書かれているか、
   `sts:ExternalId` や `aws:MultiFactorAuthPresent` の条件があるか
2. 相手のアカウント ID が SaaS の公式ドキュメントに載っている ID か、自社の別アカウントかを確かめる (上の 7)
3. 引き受けた後の操作は**自アカウントの CloudTrail** に記録される (上の 6 の一時キーで引く)。ロールに付いた権限: `aws iam list-attached-role-policies --role-name <ロール名>`
4. `mfa` はロール側の記録では `unknown` になりやすい (呼び出し元のセッションの情報が載らない)。MFA を必須にしたいなら信頼ポリシーの条件で守る

## 判断の分かれ目

- **正規の可能性が高い**: 社員の switch role、CI/CD の OIDC ロール、委託先・SaaS の公開されたアカウント ID からの引き受けで、操作が役割と合う
- **要対応**: 知らない外部アカウント、信頼ポリシーが広い (Principal が `*` やアカウント全体で条件が無い)、引き受けた後に IAM の変更・秘匿値の読み取り・大量の拒否がある、
  送信元が業務の場所と合わない
- 失敗だけ (`has_errors` で成功なし) は、引き受けられてはいないが、誰かが信頼関係を探っている兆候。信頼ポリシーの確認を勧める

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): ロールの信頼ポリシーから不審な主体を外す。発行済みのセッションは IAM > ロール > 対象の `Revoke sessions` で失効できる
   (`AWSRevokeOlderSessions` のインラインポリシーが付き、それより前に発行されたセッションを拒否する)
   外向きのときは、自アカウントで止められるのは呼び出し元だけ (呼び出し元のアクセスキーの無効化、`sts:AssumeRole` の権限を絞る)。外部アカウントのロールのセッションは相手の管理者が失効する
2. **承認**: 正規なら `arata approve <id> --note "<理由>"` を人に提案する。`caller_identity: account_only` の finding は `account:` で承認される。期限付きの委託は `--expires`。基準は `arata help ai approve`
3. **expected_denied**: 対象外 (access_denied のための設定)
4. **ack / snooze**: 承認したくないが当面続くもの (移行期間など) は ack、終わりが決まっているものは snooze
5. **設定の修正**: SaaS 連携の信頼ポリシーに `sts:ExternalId` の条件を付ける、Principal をアカウント全体ではなく特定のロールにする

## やってはいけないこと

- 外部アカウント ID を確かめずに `account:` で承認を提案しない (そのアカウントの全主体を通すことになる)
- 信頼ポリシーの変更やセッションの失効を LLM が実行しない
- 「外部アカウント NNN」を自アカウントのルートユーザーの利用 (root_usage) と混同しない
- `caller_identity: account_only` の呼び出し元を「NNN の root」「ルートユーザー」と書かない (その証拠は記録に無い)
- 向きを逆に書かない。外向き (自アカウントの主体が外部のロールを引き受けた) を「外部の主体が自アカウントのロールを引き受けた」と要約しない。見出しの括弧と `direction` のとおりに書く
- `mfa: unknown` を「MFA なし」と書かない
