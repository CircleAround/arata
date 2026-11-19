# 0073. 起動のたびに決まった秘匿値をまとめて読むロールは、`secrets_access` の項目に `bulk: exempt` を明示して、その秘匿値だけを一括読み出しの数から外す

- 日付: 2026-11-19
- 状態: 採用

## 背景

secret_access (ADR 0027) は、主体が 1 日に読んだ異なる秘匿値の数が `max(min_distinct, その主体の日ごとの数の中央値 × factor)` を超えると high (一括読み出し。持ち出しの兆候) にする。
allowlist の `secrets_access` に書いた「主体 × 秘匿値」は初出に数えないが、一括読み出しの数には数える (設計書 6 章の決定・ADR 0027)。

実際の監査で次のことが起きた (値は書かない)。

- 本番のアプリのタスクを起動するたびに、ECS のエージェントがタスクの実行用のロールで SSM の SecureString を十数個、`GetParameters` の 1 回でまとめて読む
  (タスク定義の `secrets` に書いた値を、起動の時に読む。ECS とデプロイの道具の標準の形)
- デプロイは数日〜週に 1 回なので、その主体の日ごとの数の中央値は 0。閾値は `min_distinct` (10) になり、デプロイのある日は毎回 high になる
- high は ack できない (ADR 0068)。`secrets_access` に書いても high は消えない。人がその都度 resolve している。
  利用者からは「正規の起動時の読み取りを arata の仕組みで扱える形がほしい」と求められた

平常帯 (中央値) は「毎日同じだけ読む」主体には効くが、「たまに、決まった組をまとめて読む」主体には効かない。
後者の読み方は、持ち出し (多数の秘匿値を 1 度に読む) と数の上では区別できない。区別できるのは「どの秘匿値か」だけである。

### 公式文書で確かめたこと (2026-11-19 に読んだ)

1. ECS の開発者ガイド「Amazon ECS task execution IAM role」
   <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html>
   - 「The task execution role grants the Amazon ECS container and Fargate agents permission to make AWS API calls on your behalf.」
   - `ssm:GetParameters` は「Required if you are referencing a Systems Manager Parameter Store parameter in a task definition.」
   - 信頼ポリシーの主体は `"Service": "ecs-tasks.amazonaws.com"`
   - 読むのは ECS (コンテナ・Fargate の) エージェントで、実行用のロールの認証情報は「they aren't directly accessible by the containers in the task」
2. ECS の開発者ガイド「Pass Systems Manager parameters as Amazon ECS environment variables」
   <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-ssm-paramstore.html>
   - 「Sensitive data is injected into your container when the container is initially started.」
   - Secrets Manager の版 (<https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html>) も同じく実行用のロールで読む
3. CloudTrail のユーザーガイド「CloudTrail userIdentity element」
   <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html>
   - `invokedBy`: 「The name of the AWS service that made the request, when a request is made by an AWS service」「This field is only present when a request is made by an AWS service.」
4. CloudTrail のユーザーガイド「CloudTrail record contents for management, data, and network activity events」
   <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>
   - `sourceIPAddress`: 「For services in AWS, only the DNS name is displayed. For events originated by AWS, this field is usually `AWS Internal/#`」
   - `userAgent`: 「For events originated by AWS, if CloudTrail knows which AWS service made the call, this field is the event source of the calling service ... Otherwise, this field is `AWS Internal/#`」。
     SDK・CLI の呼び出しの値の例 (`aws-sdk-java`・`aws-cli/...`) も挙がっており、誰が値を決めるかは書かれていない
   - `tlsDetails`: 「The `tlsDetails` field is not present if the API call was made by an AWS service on your behalf. The `invokedBy` field in the `userIdentity` element identifies the AWS service that made the API call.」

**公式文書に無かったこと**: ECS のエージェントが秘匿値を読むときの CloudTrail の記録 (`sourceIPAddress`・`userAgent`・`invokedBy`) の形は、上のどの文書にも無かった。
Fargate と EC2 の起動タイプで形が違うかも書かれていない。実例を示す公式のブログ・回答も見つけていない。

### 実際の記録で確かめたこと (2026-11-19)

出典: 実際の監査の CloudTrail の記録を、2026-11-19 に開発リードが読んだ形。アカウント・ロール・パラメータの名前と値は書かない。

5. 読み取りの主体は、タスクの**実行用のロール** (タスクのロールではない)。デプロイの道具が作るロール
6. 1 回の起動で `GetParameters` が 2 回 (合わせて十数個)。`userIdentity.type` は `AssumedRole`、一時的な認証情報 (`ASIA` で始まるキー)。
   `sourceIPAddress` は IP (AWS の範囲の IP が 1 つ)、**`invokedBy` は無い**。`userAgent` は Fargate のエージェントを名乗る文字列
   (`Amazon Fargate Agent - v... (+http://aws.amazon.com/ecs/)` の形)。公式文書の 3・4 の「サービスが代わりに呼んだ記録」の形 (`invokedBy` があり、送信元は DNS 名) ではない。
   エージェントが実行用のロールの一時的な認証情報を受け取り、自分で呼んでいる形と読める
7. その約 1 秒前に、実行用のロールの `AssumeRole` がある。呼び出し側は `userIdentity.type: AWSService`、`invokedBy`・`sourceIPAddress`・`userAgent` はどれも `ecs-tasks.amazonaws.com`。
   `roleSessionName` は 32 桁の 16 進 (タスクの ID) で、6 の読み取りのセッション名と同じ。
   別に、セッション名が `ECSIAMRoleChecker-` で始まる `AssumeRole` もある (呼び出し側は同じく `ecs-tasks.amazonaws.com`)
8. 秘匿値の名前は区切りが 5 つの形 (`/<a>/<b>/<c>/secrets/<名前>` の形)。3 節の基準に収まる
9. 同じ時間帯に、定時のジョブの実行用のロールも毎回十数個を読んでいたが、high にならなかった。毎日読むので、日ごとの数の中央値がその数になり、
   閾値が `max(min_distinct, 中央値 × factor)` (既定の factor は 3。十数個 × 3) に上がるため。読む日が `baseline_days` の半分に満たないと中央値は 0 になり、
   起動時の読み取りと同じく `min_distinct` で high になる (ジョブの間隔が 2 日以上なら起きる)

## 決定

### 1. `secrets_access` の項目に `bulk: exempt` を足す (明示の opt-in)

```yaml
secrets_access:
  - principal: arn:aws:iam::123456789012:role/example-app-task-execution
    secrets: ["/example-app/prod/secrets/*"]
    bulk: exempt                          # この項目に一致する秘匿値を、一括読み出しの数から外す (ADR 0073)
    note: タスクの起動のたびに、ECS がタスク定義の secrets をまとめて読む
```

- `bulk` の値は `exempt` だけ (書かなければ今と同じ)。ほかの値は読み込みエラー。将来の値 (例: まとめて 1 と数える) のために真偽ではなく語にする
- **既定は今と同じ**。`bulk: exempt` の無い項目は、今どおり初出だけを止め、一括読み出しの数には数える
- `bulk: exempt` の項目は `note` が必須 (`expected_denied` と同じ。なぜ外してよいかを残す)
- `arata approve` はこの項目を書かない (人が書く。`oidc_subjects` と同じ)
- 名前は `startup: true` も考えたが、効き目 (一括読み出しの数から外す) を名前にした。「起動時」は理由で、`note` に書く

### 2. 外すのは一致した秘匿値だけ。一致しない秘匿値は今どおり数える

- 窓の異なる秘匿値のうち、その主体の `bulk: exempt` の項目に一致するものを数から外し、残りの数を閾値と比べる
- 平常帯 (過去の日ごとの数) からも同じ秘匿値を外す (比べる両側で同じものを数える)
- 承認した組の外を読めば、今どおり high になる。例: 外した十数個に加えて、別のアプリの秘匿値を 11 個読めば high
- 初出の扱いは変えない (`secrets_access` の項目は、`bulk` の有無によらず初出を止める)

### 3. 広すぎる項目は読み込みエラーにする

`bulk: exempt` は high を黙らせるので、外す範囲が広いと持ち出しが見えなくなる。次は読み込みエラーにする (警告にしない。警告は見落とされ、効き目は静かに high を消すことだから)。

- `principal` がロールでない (ARN に `:role/` が無い)。IAM ユーザーの長期のキーで起動時にまとめて読む形は勧めない
- `secrets` の glob で、最初の `*`・`?` より前の固定の部分に、空でないパスの区切りが 2 つ以上無いもの。
  例: `*`・`/*`・`prod/*`・`/example-app/*` はエラー、`/example-app/prod/*`・`prod/example-app/*`・`/example-app/prod/DB_PASSWORD` (ワイルドカード無し) は可
- `secrets` が `arn:` で始まるもの (シークレットの名前で書く。名前の部分で比べる仕組みは今のまま。ARN の形の glob の広さを数えにくいため)

### 4. 外すのは、AWS のサービスが引き受けるロールのときだけ

- 判定の時に、その主体が過去 `baseline_days` から窓の終わりまでに AWS のサービスに引き受けられたロール
  (principal_new_source と同じ判定。保存済みの AssumeRole の呼び出し元がサービス主体。ECS のタスク・Lambda・EC2 のインスタンスプロファイル) のときだけ外す
- そうでなければ外さず (今どおり数える)、data に `bulk_exempt_ignored: not_service_role` を残す
- 理由: 人が使う SSO のロールなどもロールなので、3 節の `:role/` だけでは「人が CloudShell からまとめて読む」(ADR 0058 の lucr-3-2023-09 の段階) を書き方次第で黙らせられる。
  人の主体を外せないことを規則で固定する
- 引き受けの記録が期間に無ければ外さない (鳴る側に倒れる)

#### 4 の 2. 読み取りの記録の印 (`invokedBy`・`userAgent`) は条件にしない

4 節は「主体がサービスのロールか」で絞るので、そのロールの資格情報が盗まれれば外から同じ組を読める (下の評価)。
読み取りの記録そのものに「AWS のサービスが代わりに呼んだ」印があれば、印のある読み取りだけを外せる。印に使えるかは、**AWS が付ける値か、呼ぶ側が書ける値か**で決めた
(ADR 0037・0055: 呼ぶ側が書ける値は判定に使わない)。

- `invokedBy`: AWS が付ける値だが、**実際の記録 (背景の 6) に無い**。条件にできない
- `userAgent`: Fargate のエージェントを名乗っているが、SDK を使えば呼ぶ側が書ける値で、盗んだ資格情報でも同じ値を名乗れる。条件にしない。手がかりとして data に残すかは実装の時に決める
- `tlsDetails` が無いこと (公式文書の 4): `invokedBy` と同時に現れる印で、`invokedBy` の無い形では印にならない。今は収集もしていない。使わない
- 「送信元がそのロールのいつもの出口か」で絞る案 (任意の `source_ips`) は入れない (レビューで決定)
- 収集の現状: cloudtrail collector は、主体がサービスでない記録の `invokedBy` (無ければ DNS 名の `sourceIPAddress`) を、決まった形 (`record.ServiceName`) のときだけ
  `data.invoked_by` に残している (root_usage のため)。秘匿値の読み取りも残るが、上のとおり今回の形では値が無い

4 節の判定は、実際の記録の `AssumeRole` (背景の 7。呼び出し側が `AWSService` の `ecs-tasks.amazonaws.com`) で成り立つ。

#### 4 の 3. セッションの単位で絞る (後で足せる。今回は入れない)

もう一段強める形として、「その読み取りのセッションが、サービスの `AssumeRole` で発行されたものであること」を条件にできる。
背景の 7 のとおり、サービスの `AssumeRole` の `roleSessionName` (タスクの ID) と、読み取りのセッション名 (`userIdentity.arn` の `assumed-role/<ロール>/` より後ろ) は一致する。
発行された一時的な認証情報のキー (`responseElements.credentials.accessKeyId`) と、読み取りの `userIdentity.accessKeyId` も突き合わせられるはずである (実際の記録では未確認)。

- 今の収集では突き合わせられない: `AssumeRole` は `role_arn` だけを残し、`roleSessionName` も発行したキーも残していない (ADR 0055 などの「roleSessionName は残さない」)。
  読み取りの側も、主体はロールの ARN に寄せ、セッション名とキーは残していない (SSO のセッション名は利用者のメールアドレスであることが多い)
- 足すときの大きさ: collector で (1) 呼び出し側がサービスの `AssumeRole` の `roleSessionName` を、決まった形 (例: 16 進 32 桁) のときだけ残す、
  (2) 秘匿値の読み取りのセッション名を、同じ形のときだけ残す (人のセッション名を残さないため、形に合わなければ捨てる。ファズで固定する。ADR 0041)、
  (3) secret_access でその日の `AssumeRole` と突き合わせる。保存の形が変わるので raw と rebuild (ADR 0033) の扱いも要る。キーで突き合わせるなら (1)(2) の代わりにキーを残す
- 今回入れない理由: 実行用のロールは信頼ポリシーで `ecs-tasks.amazonaws.com` だけが引き受けられ、コンテナからも使えない (公式文書の 1)。
  ロールの単位で見ても、セッションの単位で見るのとほぼ同じ効き目になる。残る差 (発行された一時的な認証情報を、エージェントの外で使われる形) は、下の評価の info の `ips` で見る

### 5. 外した分を黙って消さない

- 外した秘匿値があった主体の finding (初出・一致しない秘匿値の一括読み出しで出たもの) には、data に次を足す:
  `bulk_exempted` (外した数)、`bulk_counted` (閾値と比べた数)、`bulk_exempt_patterns` (一致した項目の glob。allowlist の値で、ログ由来ではない)
- 外した結果、何も報告しない主体は、主体ごとに info で 1 行残す (ADR 0047 の `known-destination:` と同じ形)。
  Key は `bulk-exempt:<主体の ARN>`、data に `bulk_exempted`・`bulk_exempt_patterns`・`count`・`ips`・`event_names`。
  info は件数・通知に数えない。Fingerprint は固定 (毎回 changed にしない)。人と aratam の LLM が「いつもの送信元か」を見られる材料として残す
- `distinct_secrets` の意味は変えない (外す前の数)。足すのは項目だけなので互換 (ADR 0054。finding の `data` は型を決めていない)

### 6. 設定・文書の扱い

- `config.yaml` のパラメータは増やさないので、`config init --diff` に出るものは無い。allowlist の雛形にも足さない
  (外す組は利用者ごとに違い、既定で書けるものが無い)
- `arata config check`: 3 節は読み込みエラーなので、PR の時点 (ADR 0042) で止まる。`expires` は任意のまま (起動時の読み取りは恒常的なため、無くても warn にしない)
- `docs/ai/index.md` (allowlist の例)・`docs/ai/approve.md`・`docs/ai/onboarding.md` (「書いても high は消えない」を「`bulk: exempt` を書けば、その秘匿値だけ外れる」に)・
  playbook `secret_access.md` (data の項目・承認の手順・見逃しの注意・毎日読む主体が high にならない理由と、間隔が 2 日以上のジョブは中央値が 0 になること (背景の 9))・設計書 6 章の決定を直す
- `docs/threats.md`: lucr-3-2023-09 の「秘匿値をまとめて読む段階」は人の主体なので 4 節により変わらない。対応表は直さない。playbook の「関連する事例」もそのまま

## 引き受ける見逃し (評価)

`bulk: exempt` を書いたロールの資格情報が盗まれ、**外した組だけ**を読まれたとき、secret_access には何も出ない (info の 1 行だけ)。そのときに見えるものを確かめた (今の実装を読んだ)。

- **principal_new_source**: 新しい送信元 (/24・/48) だけでは low で、AWS のサービスが引き受けるロールは low を出さない (ADR 0027。送信元が毎回変わるため)。
  medium 以上になるのは、新しい送信元からの書き込みが `min_writes` (5) 以上、新しいリージョンでの書き込み、同じ窓の access_denied のどれか。
  **読むだけ (GetParameters だけ) なら principal_new_source にも出ない**
- **access_denied**: 盗んだ側が権限を探れば (ListSecrets・DescribeParameters・他の秘匿値の読み取りの拒否など) 出る。権限の内側で読むだけなら出ない
- **secret_access の残り**: 外した組の外を 1 つでも読めば初出 (low)、`min_distinct` を超えれば high
- **info の `ips`**: 外した読み取りの送信元が残る。いつもの出口 (NAT など) と違えば人が気づける。ただし規則では判定しない。
  実行用のロールは `ecs-tasks.amazonaws.com` だけが引き受けられ、コンテナからも使えない (公式文書の 1) ので、残る見逃しの主な形は「エージェントに発行された一時的な認証情報を、外で使われる」こと。
  そのときは送信元がエージェントの送信元 (タスクの出口) と変わるはずなので、info の `ips` がその材料になる (セッションの単位の突き合わせは 4 の 3 で後から足せる)
- **コンテナの中から盗まれた場合** (アプリの脆弱性からタスクの認証情報を使う): 送信元も同じなので、どのチェックでも区別できない。これは bulk: exempt の有無によらない

つまり、**この形の見逃しを arata の判定で補うものは無い** (読み取りの記録に AWS の付ける印は無かった。4 の 2)。だから外す範囲を 3 節・4 節で狭く固定し、playbook には arata の外の守りとして次を書く:

- 実行用のロールの権限を、その組の秘匿値だけに絞る (`Resource` に ARN を書く)。外した組の外を読もうとすれば access_denied に出る
- 可能なら、IAM の条件 (VPC エンドポイント経由のときの `aws:SourceVpce` など) で、実行環境の外からの読み取りを止める

## 検討した選択肢

- **デプロイの印 (ECS の `UpdateService`・`RunTask` など) と時刻で突き合わせ、デプロイの直後の読み取りを外す**: 攻撃者もデプロイの操作ができる (デプロイの権限を持つ主体を奪えば、印を作ってから読める)。
  また、ECS の操作を注目イベントに足す収集の変更と、チェックの順 (どの記録が先に届くか) への依存が要る。却下
- **平常帯を中央値ではなくピーク (最大値) で取る**: デプロイの間隔が `baseline_days` (14 日) より長いと、過去にピークが無く効かない。
  また、1 度の持ち出しが平常帯に入ると、以後の同じ規模の持ち出しが見えなくなる。却下
- **平常帯を「読んだ日だけ」の中央値にする (読まない日を 0 と数えない)**: 毎回同じ組を読む主体には効くが、明示が無いまま全主体の閾値が上がる (ADR 0014 の暗黙の既定に近い)。
  たまにしか読まない主体が、初めてまとめて読んだときも閾値が上がる。却下
- **`secrets_access` に書いた組を、設定なしに一括読み出しの数から外す (既定を変える)**: 既に初出を止める目的で広い glob を書いている利用者で、気づかないうちに high が消える。却下 (opt-in にした)
- **`bulk: exempt` の組を 0 ではなく 1 と数える**: 他の読み取りと合わせたときの差が 1 だけで、説明が増える。却下 (将来の値として `bulk` を語にしておく)
- **項目に `source_ips` (送信元の CIDR) を書かせ、その内からの読み取りだけを外す**: 出口が固定の環境では盗まれた資格情報の外からの利用を拾えるが、
  サービスのロールの送信元は環境によって毎回変わり (ADR 0027)、必須にすると使えない環境がある。入れない (レビューで決定)
- **`userAgent` (ECS のエージェントの名乗り) の読み取りだけを外す**: `userAgent` は SDK で呼ぶ側が書ける値で、盗んだ資格情報でも同じ値を名乗れる (ADR 0055 と同じ理由)。却下
- **一括読み出しの high を ack できるようにする**: 後で本物の持ち出しが起きても報告されない (ADR 0068)。却下

## 結果 (良い点・引き受けるコスト)

- 起動時の決まった読み取りを、人が毎回 resolve せずに、allowlist の明示の 1 項目で扱える。外した事実は data と info に残る
- 外した組の外の読み取り・人の主体の読み取りは今どおり high
- 引き受けるコスト: 外したロールの資格情報で外した組だけを読まれると、arata では判定できない (上の評価)。外す範囲は書き手の判断に依る (3 節で極端な広さだけを止める)
- 実装は allowlist (項目の読み込みと検査、一致の関数) と secret_access (数え方・data・info) と文書。収集・権限・スキーマ (型のある出力) は変えない。
  テストは、外す・外さない (一致しない秘匿値・サービスのロールでない・引き受けの記録が無い)・広い glob のエラー・平常帯の両側・info の形を固定する
