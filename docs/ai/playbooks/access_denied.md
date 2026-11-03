# access_denied: 拒否された API 呼び出しの急増

## この指摘の意味

主体ごとの拒否された API 呼び出しが、その主体自身の平常帯を超えた (daily。種類が多い `breadth` は medium、さらに多ければ high。件数の多い `volume` は medium)。
`breadth` は権限の列挙 (盗んだ認証情報で何ができるかを探る) の兆候、`volume` は権限の足りないアプリの繰り返しのことが多い。
allowlist で承認済みの主体でも出る (承認は「居ること」を認めるもので、権限を探ってよいという意味ではない)。

- Key は主体の ARN。サービス主体とルートは対象外
- data: `principal`、`principal_kind`、`allowlist_status`、`external_account`、`threshold` (`breadth` / `volume`)、`distinct_apis`、`count`、
  `apis` (件数の多い順に最大 10。`iam:ListUsers × 3`)、`error_codes`、`ips`、`baseline_median_count` / `baseline_median_distinct`、
  `expected_denied_excluded` (想定済みとして数えなかった件数)、`escalated_from_suppressed` (ack / snooze 中に重大度が上がった)

## まず確かめること

1. `threshold` と `apis` を見る。`iam:List*`・`iam:Get*`・`sts:GetCallerIdentity` に続いて多数のサービスの `List*` / `Describe*` が並ぶのは列挙の典型。
   同じ 1〜2 個の API だけが多いのは設定ミスのアプリの典型
2. `arata review --format json` で同じ主体の new_principal・unknown_assume_role・iam_changes (`denied` を含む) を探す
3. `ips` が業務の場所・CI・SaaS と整合するか。ふだんの送信元と違うなら認証情報の持ち出しの疑い
4. CloudTrail で拒否の中身を見る: 拒否されたイベントの `accessKeyId` で
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<キー>` を引き、成功した操作も含めて並べる (成功した書き込みがあれば重い)。
   IAM ユーザーなら `AttributeKey=Username,AttributeValue=<ユーザー名>` でもよい
5. 主体の権限 (`aws iam list-attached-role-policies` など) と、拒否された API が業務で必要なものかを照らす
6. `expected_denied_excluded` が多い主体は、想定内の拒否が既に除かれている (数に入っていない分があると書き添える)

## 判断の分かれ目

- **正規の可能性が高い**: `volume` で同じ API の繰り返し、デプロイ・アプリの変更の直後、送信元がいつもと同じ。
  IAM の Deny を意図して入れている主体 (監査・AI 用の調査ロールなど) の想定内の拒否
- **要対応**: `breadth`、特に high。送信元がいつもと違う、成功した書き込み・秘匿値の読み取りが混ざる、承認済みの SaaS の主体が列挙している (SaaS 側の侵害の疑い)

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (列挙で説明が付かない): IAM ユーザーならアクセスキーを無効化 (`aws iam update-access-key ... --status Inactive`)、ロールなら `Revoke sessions` と信頼ポリシーの見直し。
   外部アカウントの主体なら、そのアカウントを信頼しているロールの信頼ポリシーから外すことを検討する
2. **承認**: 主体の承認では止まらない。`--expected-denied` を付けない approve は拒否される
3. **expected_denied**: 想定内の拒否なら、主体 × API の単位で `arata approve <id> --expected-denied '<サービス:操作>' --note "<なぜ想定内か>"` を人に提案する。
   広い glob (`*:*`、`iam:*`) は列挙を隠すので勧めない。詳しくは `arata help ai approve` の「access_denied が鳴ったとき」
4. **ack / snooze**: 権限の足りないバッチの修正待ちなどは ack / snooze (重大度が上がれば再報告される)
5. **設定の修正**: アプリに必要な権限を足す、不要な呼び出しをやめる (アプリ側の修正)

## やってはいけないこと

- 承認済みの主体 (`allowlist_status: approved`) だからと軽く扱わない
- 拒否されたので被害は無いと断定しない。拒否の前後の成功した操作を確かめる
- 列挙を隠すほど広い `expected_denied` を提案しない。LLM が approve / ack を実行しない
