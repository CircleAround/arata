# 0085. ECS の負荷を変える操作 (タスク定義の登録・タスクの起動・サービスの更新) を、デプロイする主体の外からのものと、ロール・秘匿値の参照の変化で報告する (`ecs_workload_changes`)

- 日付: 2026-11-25
- 状態: 提案

## 背景

secret_access の allowlist の `bulk: exempt` (ADR 0073・0076) は、ECS が発行した認証情報で、発行の直後に読まれた秘匿値の読み取りを、一括読み出しの数から外す。
0076 で「盗まれた認証情報を外で使われる」形は狭めたが、**ECS に正規の手順で起動させる**形は残っている (ADR 0079 の「名前が合うロールを攻撃者が作れた場合」にも同じ穴を書いた)。

- 攻撃者が、同じ実行ロールを使う新しいタスク定義を登録し (`RegisterTaskDefinition`)、`RunTask` すると、ECS がそのロールで認証情報を発行し、直後に秘匿値を読む。
  secret_access から見ると正規の起動と区別がつかず、読み取りは外れる
- 秘匿値はコンテナの環境変数に入る (下の出典 6)。持ち出しはコンテナの中 (攻撃者のイメージ・コマンド) で起き、API の記録には残らない
- 新しいタスク定義は要らない場合もある。`RunTask` の `overrides` で、既存のタスク定義のままコマンドを上書きでき、実行ロール・タスクロールも上書きできる (出典 2)
- `iam:PassRole` は API ではなく権限で、CloudTrail に記録が出ない (出典 4)。どのロールを渡したかは、`RegisterTaskDefinition` の `executionRoleArn`・`taskRoleArn` と、
  `RunTask`・`StartTask` の `overrides` で見るしかない

今の arata は、ECS では `ExecuteCommand` (ecs_exec。ADR 0072) しか注目イベントに残していない (`internal/collect/cloudtrail/cloudtrail.go` の `notableAPIs`)。
`RegisterTaskDefinition`・`RunTask`・`CreateService`・`UpdateService` は principal_seen の集計に入るだけで、誰が・どのロールで・どの秘匿値を参照して起動したかは残らない
(`RunTask`・`CreateService` は unused_region_activity の `compute_apis` にあるが、ふだん使わないリージョンだけの話である)。
オーナーは、`bulk: exempt` と合わせてこのチェックを進めることに同意している。

### 公式文書で確かめたこと (2026-11-25 に読んだ)

1. ECS の API リファレンス「RegisterTaskDefinition」 <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html>
   - 要求: `family` (必須、文字列)、`containerDefinitions` (必須、ContainerDefinition の配列)、`executionRoleArn` (任意。「task execution role that grants the Amazon ECS container agent permission to make AWS API calls on your behalf」)、
     `taskRoleArn` (任意。短い名前か ARN。「All containers in this task are granted the permissions that are specified in this role」)
   - 応答: `taskDefinition` (登録したタスク定義の全体。`taskDefinitionArn`・`revision` を含む)
2. ECS の API リファレンス「RunTask」「TaskOverride」「StartTask」
   <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html> ・ <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_TaskOverride.html> ・
   <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_StartTask.html>
   - RunTask の要求: `taskDefinition` (必須。`family:revision` か ARN。revision を省けば最新の ACTIVE)、`cluster` (任意。省けば既定のクラスター)、`count` (最大 10)、
     `startedBy` (任意、128 文字まで)、`overrides` (任意。JSON で 8192 文字まで)、`launchType`、`enableExecuteCommand` ほか
   - TaskOverride に `executionRoleArn` (「task execution role override for the task」) と `taskRoleArn` がある。`containerOverrides` で `command` と `environment` を上書きできる
   - 応答: `tasks` (置けたタスク) と `failures`
   - StartTask はコンテナインスタンスを指定して起動する。`overrides` は RunTask と同じ TaskOverride、`startedBy` は 36 文字まで、`count`・`launchType` は無い
3. ECS の API リファレンス「ContainerDefinition」「Secret」
   <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html> ・ <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Secret.html>
   - `secrets` は Secret (`name`・`valueFrom`。どちらも必須) の配列。`valueFrom` は「either the full ARN of the AWS Secrets Manager secret or the full ARN of the parameter in the SSM Parameter Store」。
     SSM のパラメータは、同じリージョンなら名前でもよい
   - `environment` は平文の値を持つ (「We don't recommend that you use plaintext environment variables for sensitive information」)。`environmentFiles`・`image`・`command`・`entryPoint` もある
4. IAM のユーザーガイド「Grant a user permissions to pass a role to an AWS service」 <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>
   - 「`PassRole` is not an API call. `PassRole` is a permission, meaning no CloudTrail logs are generated for IAM `PassRole`.」
   - 「you must review the CloudTrail log that created or modified the AWS resource receiving the role」
5. ECS の API リファレンス「CreateService」「UpdateService」「CreateTaskSet」
   <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html> ・ <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateService.html> ・
   <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateTaskSet.html>
   - UpdateService の `taskDefinition`: 「Amazon ECS spawns a task with the new version of the task definition and then stops an old task after the new version is running」「This parameter triggers a new service deployment」
   - UpdateService の `forceNewDeployment` (真偽。タスク定義を変えずに入れ替える)。`desiredCount` は「doesn't trigger a new service deployment」
   - CODE_DEPLOY・EXTERNAL のデプロイの方式では、タスク定義の変更は UpdateService ではなく、CodeDeploy のデプロイか新しいタスクセット (`CreateTaskSet`。`taskDefinition` が必須) で行う
6. ECS の開発者ガイド「Pass Secrets Manager secrets through Amazon ECS environment variables」と「task execution IAM role」
   <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html> ・ <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html>
   - 「Sensitive data is injected into your container when the container is initially started.」読むのはタスクの実行ロール
   - 秘匿値を更新しても動いているコンテナには入らず、新しいタスクの起動 (サービスなら新しいデプロイ) が要る
7. ECS の開発者ガイド「Log Amazon ECS API calls using AWS CloudTrail」 <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/logging-using-cloudtrail.html>
   - 「logs all Amazon ECS control plane operations as management events」。本文の例は `CreateService`・`RunTask`・`DeleteCluster`。
     載っている記録の例は 1 件だけで (説明は CreateService、JSON の eventName は `CreateCluster`)、上の操作の記録の例は無い
8. CloudTrail のユーザーガイド「CloudTrail record contents」と「userIdentity」
   <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html> ・
   <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html>
   - `requestParameters`・`responseElements` は 100 KB が上限で、超えると中身が省かれる (「the `requestParameters` content is omitted」)。切り詰めではない
   - `invokedBy` は「The name of the AWS service that made the request」。サービスの主体・サービスにリンクされたロール・サービスのロールで呼ばれた要求を含む
9. 人が操作していない起動 (4 節で使う)
   - サービスのスケジューラー <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html>: 止まったタスク・異常なタスクを入れ替え、デプロイを進める。
     **そのとき `RunTask` の記録が出るかは書いていない**
   - Fargate のタスクの保守 <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-maintenance.html>: サービスのタスクはスケジューラーが入れ替える。
     単独のタスク (RunTask で起動したもの。EventBridge Scheduler・Step Functions などから起動したものを含む) は「Amazon ECS doesn't launch a replacement task when a task is stopped」。
     **CloudTrail の記録については書いていない**
   - サービスの自動スケーリング <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-auto-scaling.html> と
     Application Auto Scaling のサービスにリンクされたロール <https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-service-linked-roles.html>:
     ECS は Application Auto Scaling で desired count を変え、ECS 用のロールは `AWSServiceRoleForApplicationAutoScaling_ECSService`。
     **どの API (UpdateService か) をどの主体の形で呼び、どう記録されるかは書いていない** (Application Auto Scaling の CloudTrail のページは本文を読めなかった)
   - EventBridge Scheduler での定時のタスク <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/tasks-scheduled-eventbridge-scheduler.html>:
     Scheduler が、利用者の作る実行ロールで RunTask を呼ぶ (ロールの権限の中身は、このページには書いていない)

**未確認のこと** (公式文書に無く、実際の記録も読んでいない):

- 上の 6 つの操作の CloudTrail の記録の形 (requestParameters・responseElements の鍵が API リファレンスのとおりか、`containerDefinitions` が記録に入るか、`environment` の値が伏せられるか)
- サービスのスケジューラーの起動・入れ替え、Fargate の保守による入れ替えが、`RunTask` (や別の名前) の記録になるか、なるならその主体の形
- 自動スケーリングが desired count を変えるときの記録の操作名・主体の形 (`invokedBy`)
- 拒否・失敗した呼び出しで requestParameters が残るか (ADR 0072 の 6 節と同じく推定のまま)

このため、本 ADR の判定は「サービスの起動が記録に出るか」に依らない形にし (4 節)、実装の前に実際の記録で確かめることを 9 節に並べる。

## 決定

### 1. チェック `ecs_workload_changes` (hourly、event、trail_event) と、注目イベントに足す範囲

- 対象の操作 (eventSource `ecs.amazonaws.com`):

  | 操作 | 見る理由 |
  |---|---|
  | `RegisterTaskDefinition` | 実行ロール・タスクロール・秘匿値の参照・イメージを決める (PassRole の唯一の手がかり。背景の出典 4) |
  | `RunTask`・`StartTask` | 単独のタスクを起動する。`overrides` でロールとコマンドを上書きできる (出典 2) |
  | `CreateService`・`UpdateService` | サービスにタスク定義を当て、起動させる (`taskDefinition`・`forceNewDeployment`) |
  | `CreateTaskSet` | CODE_DEPLOY・EXTERNAL の方式で、新しいタスク定義を当てる (出典 5) |

- `notableAPIs` の `ecs.amazonaws.com` に上の 6 つを足す (ADR 0026・0072 と同じやり方。チェック側が `checks.ECSWorkloadAPIs` を公開し、collector のテストで突き合わせる)。
  足しても既存のチェックと principal_seen の結果が変わらないことをテストで固定する
- **失敗した呼び出しも残す** (拒否のコードでないもの (`ClientException`・`InvalidParameterException` など) も)。理由は ecs_exec と同じで、
  知らない主体が本番の負荷を変えようとしたこと自体が指摘になり、`ClientException` は access_denied に数えられない。扱いは 2 節の表
- 外した操作: `DeleteService`・`StopTask`・`DeregisterTaskDefinition` (止める・消すだけで、新しい起動と秘匿値の読み取りを生まない。止める操作の可用性への影響は別の話)、
  `UpdateTaskSet`・`UpdateServicePrimaryTaskSet` (タスクセットの割合だけを変える)。**実装の前に、CodeDeploy のデプロイで `CreateTaskSet` が記録に出る主体を 9 節で確かめる**
- 周期は hourly (ecs_exec と同じ)。知らない主体の起動は早く知らせたい。ADR 0082 の取得の回の速報 (`min_severity: high`) にも乗る。
  材料は既に引いている LookupEvents (と `cloudtrail-s3`) の記録だけで、読み取りの権限も API の呼び出しも増えない

### 2. 報告の条件と重大度

主体を 3 つに分ける。

- **デプロイする主体**: allowlist の `ecs_deployers` (3 節) の期限内の項目に、主体・操作・クラスターの全部が一致する
- **既知の主体**: デプロイする主体でなく、new_principal が報告しない主体 (ecs_exec と同じ関数。allowlist の `principals` で期限内に承認済み、またはストアの状態が `baseline` / `approved`)
- **知らない主体**: どちらでもない。root を含む (root_usage が別に critical で報告する。ecs_exec と同じく片方に寄せない)。承認の期限切れも含む

変化の種類 (どれも、そのタスク定義のファミリーの「これまで」と比べる。「これまで」の作り方は 3 節):

- `role_changed`: 登録したタスク定義の実行ロール・タスクロールが、これまでのものに無い (無かったロールが付いた場合を含む)
- `role_override`: `RunTask`・`StartTask` の `overrides` に `executionRoleArn` か `taskRoleArn` がある (値がこれまでのものと同じでも)
- `command_override`: `RunTask`・`StartTask` の `containerOverrides` に `command` がある
- `secrets_added`: 登録したタスク定義の秘匿値の参照先 (`valueFrom`) に、これまでのものに無いものがある
- `new_family`: これまでの記録が無いファミリーを登録した

| 主体 | 成功した呼び出し | すべて失敗した試行 |
|---|---|---|
| 知らない主体 | high (変化によらない) | medium |
| 既知の主体 | medium。`role_changed`・`role_override`・`command_override` のどれかがあれば high | low |
| デプロイする主体 | `role_changed`・`role_override` は medium。`secrets_added`・`new_family` は low。それ以外は報告しない (info) | 報告しない (info に件数) |

- 既知の主体の `command_override` を high にする理由: 背景のとおり、既存のタスク定義と実行ロールのまま、コマンドだけを替えて秘匿値を持ち出せる。新しいタスク定義も新しいロールも要らない、いちばん静かな形である
- デプロイする主体の `command_override` は報告しない。マイグレーションなどの単発のジョブでふつうに使う。デプロイする主体を奪われた形は 8 節の評価に書く
- デプロイする主体の `role_changed` を medium にする理由: ロールの付け替えは基盤の変更で、まれで、正規でも人が見る価値がある。high にしないのは、CDK などでスタックを作り直すとロールの名前が変わり (ADR 0079)、正規の変更でも鳴るため (high は ack できない。ADR 0068)
- `secrets_added` を low にする理由: 正規の開発で秘匿値は足される。足された秘匿値の読み取りは、`bulk: exempt` の glob の外なら secret_access がそのまま数える。glob の内なら、ここが唯一の手がかりになる (data の `bulk_exempt_covered`。5 節)
- **ecs_exec との揃え方**: 知らない主体は high・既知の主体は medium・すべて失敗は 1 段下げ、root は high・承認の期限切れは知らない主体、を揃える。違うのは、デプロイする主体の日常の操作を報告しないこと。
  ecs_exec は「本番でシェルを開くことは既知の人でも毎回見る」と決めた (0072 の 4 節) が、デプロイは CI が 1 日に何度も行う日常の操作で、毎回の報告は量に埋もれる。変化 (ロール・秘匿値) だけを拾う
- `tags: [deploy]` (ADR 0008) は使わない。あれは IAM の変更を info に下げる印で、ECS に何を起動してよいかとは意味が違う。共用すると、ECS を触らない IaC の主体まで ECS の起動を許すことになる
- 重大度を上げる材料 (深夜帯・新しい送信元) は入れない (ecs_exec と同じ理由。送信元は principal_new_source が見る)

### 3. 設定の形と既定

**デプロイする主体は allowlist (git 管理の既知リスト。ADR 0004) に書く:**

```yaml
ecs_deployers:                    # ECS の負荷を変えてよい主体。ecs_workload_changes が日常の操作を報告しない (ADR 0085)
  - principal: arn:aws:iam::123456789012:role/github-actions-deploy
    operations: [RegisterTaskDefinition, UpdateService]   # 省けば 1 節の 6 つ全部。RunTask を使わない CI は書かない
    clusters: [prod-cluster]                               # 省けば全部 (名前の完全一致)
    note: 本番のデプロイ
  - principal: arn:aws:iam::123456789012:role/prod-app-scheduler
    operations: [RunTask]
    clusters: [prod-cluster]
    note: EventBridge Scheduler の定時のジョブ
    expires: 2027-03-31
```

- 主体は `principal` (完全一致) か `principal_pattern` (ADR 0079 と同じ規則。末尾の乱数だけ) のどちらか 1 つ。`arn_pattern` の自由な glob と `account` は受け付けない
  (デプロイする主体は少数で名前が決まっている。広い指定は「誰でも起動してよい」になる)
- `note` は必須。`operations` は 1 節の 6 つの名前だけ (知らない名前は読み込みエラー)。`expires` は任意 (過ぎたら既知の主体として扱う)
- `operations` で絞ることを playbook で勧める。CI の主体が RunTask を使わないなら、RunTask を書かなければ、奪われた CI の主体の RunTask が medium 以上で出る
- `arata approve` は `ecs_deployers` を書かない (人が書く。oidc_subjects と同じ)。ecs_workload_changes の finding の approve は断る

**チェックのパラメータは設定 (`checks.ecs_workload_changes`) に書く:**

```yaml
checks:
  ecs_workload_changes:
    history_days: 90    # 「これまで」として見る、ファミリーの過去の登録の日数 (ADR 0085)
```

- 「これまで」は、保存済みの注目イベントのうち、**デプロイする主体の成功した** `RegisterTaskDefinition` で、同じファミリーのもの (過去 `history_days` 日) のロールと秘匿値の参照の和にする
  - デプロイする主体の外の登録は「これまで」に入れない。攻撃者が 1 度登録したロールが、次から「これまで」になるのを防ぐ
  - `history_days` の既定は 90 (events の保持 `retention.events` の既定と同じ)。`retention.events` より長い値・0 以下は読み込みエラー
  - 保持の外にしか登録が無いファミリーは `new_family` になる (鳴る側。デプロイする主体なら low)
  - init のベースライン収集で集めた記録も入る (LookupEvents の 90 日の範囲)。init のときに `ecs_deployers` が無ければ「これまで」は空で、最初の登録は `new_family` になる
- 暗黙には動かさない (ADR 0014)。`config init` の雛形の hourly と daily のプロファイルに入れ、`checks:` に `history_days: 90` を書く。既存の設定には入らないので、
  `config init --diff` が `unused_check` (説明「ECS のタスク定義の登録・タスクの起動・サービスの更新を、デプロイする主体の外からのものと、ロール・秘匿値の変化で報告する」) と、パラメータの既定値を見せる
- `ecs_deployers` が空のまま動かすと、CI のデプロイが毎回「既知の主体の操作」(medium) になる。黙らせず (鳴る側)、report.json の `coverage.notes` に
  「ecs_deployers が無い」を 1 行出す (`checks.Noter`。新しいログの code は足さない)。`config check` も、プロファイルにこのチェックがあって allowlist に `ecs_deployers` が無ければ警告する。
  導入の手順 (onboarding) は「最初の review で CI の主体を確かめて `ecs_deployers` に書く」

### 4. 人が操作していない起動 (サービスのスケジューラー・Fargate の保守・スケール) との違い

- サービスのスケジューラーの入れ替え・Fargate の保守による入れ替え・スケールアウトは、**どれも既に当たっているタスク定義を起動するだけ**で、ロールと秘匿値の参照は変わらない。
  攻撃者が新しいロール・新しい秘匿値・新しいコマンドで起動させるには、1 節の操作のどれかを主体として呼ぶ必要がある (背景の出典 1・2・5)。
  本チェックはその主体の呼び出しを見るので、**サービスの起動が記録に出るかどうかに依らない**
- それでも、サービスの起動が `RunTask` などの記録として出る場合に、知らない主体の high にならないよう、次の記録は報告せず、info の件数にだけ入れる:
  - `userIdentity.type` が `AWSService`
  - 主体がサービスにリンクされたロール (ARN のパスが `/aws-service-role/`。パスは AWS が決め、利用者は作れない)
  - **`invokedBy` だけでは除かない** (ほかのサービス (EventBridge Scheduler・Step Functions) が利用者のロールで呼んだ記録にも付きうる。それらは利用者が決めた起動で、`ecs_deployers` に書く)
- 自動スケーリングの `UpdateService` が `desiredCount` だけを変える呼び出しなら、上の除外に入る想定である。ただし主体の形は未確認 (背景の 9)。
  除外に入らない形 (利用者のロール) だったら、`UpdateService` の要求が `desiredCount` だけ (タスク定義・`forceNewDeployment`・ロール・ネットワークの変更が無い) のものを、主体によらず low に下げる。
  どちらにするかは実際の記録で確かめてから実装で決め、設計書に「決定:」で残す
- Fargate の保守は、単独のタスクを入れ替えない (出典 9)。単独のタスクを定時に起動し直す運用 (EventBridge Scheduler) の主体は `ecs_deployers` に `operations: [RunTask]` で書く
- 未確認のこと (背景) は、どれも「人が操作していない起動が本チェックで鳴るか」だけに効き、「攻撃者の操作が見えるか」には効かない。確かめるまでは、鳴る側 (知らない主体の high) に倒れる

### 5. 収集で取り出す値

normalize で Data に取り出すのは次だけ。どれも攻撃者が書ける値 (ADR 0037) なので、決まった形のときだけ残し、外れたら残さず `unparsed` の印を付ける。

| 操作 | 取り出す値 |
|---|---|
| `RegisterTaskDefinition` | ファミリー (英数字・`_`・`-` の 255 文字まで)、実行ロール・タスクロール (ARN。短い名前ならアカウントを補わず名前のまま `role_name_only`)、秘匿値の参照先 (`valueFrom`。最大 50 個。超えた数)、コンテナごとの名前とイメージ (最大 10 個。256 文字で切る)、`command`・`entryPoint` の有無と分類 (ecs_exec の `command_kinds` と同じ関数)、応答の `taskDefinitionArn`・`revision` |
| `RunTask`・`StartTask` | クラスター (名前)、タスク定義 (`family:revision`)、`count`、`launchType`、`enableExecuteCommand`、`overrides` の `executionRoleArn`・`taskRoleArn`、`containerOverrides` の `command` の有無と分類・`environment` の上書きの数、応答の `taskArn` (最大 10 個)・`failures` の数 |
| `CreateService`・`UpdateService` | クラスター、サービスの名前、タスク定義、`forceNewDeployment`、`desiredCount` の有無、`enableExecuteCommand` |
| `CreateTaskSet` | クラスター、サービス、タスク定義 |

- **取り出さない**: `environment` の値と名前・`environmentFiles` (平文の秘匿値が入りうる。出典 3)、`command`・`entryPoint` の文字列 (秘匿値を打ち込めるのは ExecuteCommand と同じ。分類だけ残す)、
  `startedBy` (呼ぶ側が書く。判定に使わない)、`overrides` の残り、タグ、ネットワークの設定。今の normalize は使う鍵だけを読むので、取り出さなければストアに残らない
- イメージは残す (攻撃者のイメージかを見る材料)。report.md にはコードの囲みで出し、aratam の Slack と LLM には、レジストリのホストの部分 (決まった形のときだけ) と「これまでのイメージと違うか」だけを渡す
- requestParameters が省かれた記録 (100 KB 超。出典 8) は、responseElements の `taskDefinition` から同じ値を取る。どちらも無ければ `params_omitted` を付け、変化は「分からない」として扱い、
  デプロイする主体でも low で出す (分からない登録を黙らせない)
- `bulk_exempt_covered`: 実行ロールが allowlist の `secrets_access` の `bulk: exempt` の項目の主体で、タスク定義の秘匿値の参照先がその glob に入るなら真。
  そのタスクの起動時の読み取りは secret_access で外れる、という意味で、見出しと playbook で「secret_access には出ない」と案内する (判定の重さには使わない)

### 6. まとめ方 (Key)・片付け

- Key は `<主体の ARN>|<リージョン>/<クラスター名>|<ファミリー>|<UTC の日付>` (取れない部分は `-`)。`RegisterTaskDefinition` はクラスターが無いので `-`。
  ecs_exec と同じく日付を入れ、同じ日の同じ組は 1 件にまとめ、変化の種類 (`reasons`) と記録を足していく
- Fingerprint は 重大度 + 主体の分け方 + `reasons` の集合 + その Key に入った記録の event_id の集合 (の要約)。同じ日に新しい操作が加われば changed で出し直す (ADR 0072 の 4 節と同じ)
- info の行はデプロイする主体ごとに 1 行 (`deployer:<主体の ARN>`。操作ごとの件数。Fingerprint は固定)
- 片付けは ecs_exec にならう: high は snooze・resolve、medium・low も snooze・resolve (同じ日の次の操作が見えなくなるので ack は許さない)。approve は受け付けない (`ecs_deployers` は人が書く)。
  `checks.TriageRows` と playbook の表を突き合わせるテスト (ADR 0068) に乗る

### 7. 保存・スキーマ・ファズ・文書

- 保存: `events.data` の項目が増えるだけ (raw の `trail_event` の行の `data` にも入る)。rebuild (ADR 0033) は raw の `data` をそのまま入れ直すので作り直せる。新しい表は要らない。
  以前の版で集めた記録は上の操作が注目イベントに無く、`history_days` の「これまで」は版を上げた日から貯まる。そのあいだのデプロイする主体の登録は `new_family` の low になる (鳴る側。Release の本文に書く)
- 量: 注目イベントが、上の操作の回数だけ増える。多いのは定時の `RunTask` (5 分ごとなら 1 日 288 件) で、1 件は数百バイト。90 日で数万行の規模
- スキーマ: finding の `data` は型を決めていない (ADR 0054) ので、`schemas/` は変えない。新しいログの code も足さない (3 節の注記は `coverage.notes`)
- ファズ (ADR 0041): 上の記録を解釈する関数と、allowlist の `ecs_deployers` の読み込み (利用者のファイル) に足す。守る規則:
  - パニックしない
  - `environment` の名前と値・`command`・`entryPoint`・`startedBy` の文字列が Data のどこにも現れない
  - ファミリー・クラスター・サービスの名前・ロールの ARN は決まった形だけで、Key の各部に `|` と制御文字が入らない
  - 一覧は上限 (秘匿値 50・コンテナ 10・タスク 10) を超えず、超えた数が残る
  - `ecs_deployers` は 3 節の規則に合わない項目 (自由な glob・`account`・知らない操作名・`note` 無し) を必ず読み込みエラーにする
- 文書 (実装の PR で): playbook `docs/ai/playbooks/ecs_workload_changes.md` (ADR 0025。無ければテストが落ちる)、`docs/ai/index.md` の allowlist の例、`docs/ai/onboarding.md`、
  playbook `secret_access.md` の「引き受ける見逃し」に「ECS に正規の手順で起動させる形は ecs_workload_changes が見る」を足す、設計書 6・7 章、`docs/cloudtrail-event-names.md` (6 つの操作と記録の形)
- `docs/threats.md` と playbook の「関連する事例」(ADR 0058): ECS のタスク定義の登録・タスクの起動を使った公開の事例は、ADR 0072 の 10 節で「多い」と書いたが、
  本 ADR を書いた時点で出典を読んで確かめたものは無い。実装の PR で出典を読んで確かめた事例を足し、確かめられなければ「対応する公開の事例はまだ無い」と書く。既存の事例の表は変えない

### 8. 引き受ける見逃し (評価)

- **デプロイする主体を奪われた場合**: その主体の、許した操作の範囲の変化の無い起動は報告されない (info の件数だけ)。`command_override` も出ない。
  手がかりは、奪い方の側 (oidc_assume_role・principal_new_source・unknown_assume_role) と、`operations`・`clusters` の絞りの外の操作 (既知の主体として medium 以上)。
  playbook で `operations` を絞ることを勧める
- **同じロール・同じ秘匿値のまま、イメージだけを攻撃者のものにした登録** (デプロイする主体から): 毎回のデプロイでイメージ (のタグ) は変わるので、規則では区別しない。data の `images` で人が見る
- **コンテナの中から** (アプリの脆弱性) 環境変数を読まれた場合: ECS の操作が無いので、本チェックでは見えない (0073・0076 の評価と同じ)
- **失敗した呼び出しで requestParameters が残らない場合**: クラスター・ファミリーが `-` の別の finding になる (ecs_exec の 6 節と同じ)

### 9. 実装の前に実際の記録で確かめること

実装の PR を出す前に、開発リードが実際の監査の記録 (か sandbox。ADR 0020) で確かめ、`docs/cloudtrail-event-names.md` の「記録の形を確かめた操作」に鍵と型だけを残す。
形が本 ADR の想定と違えば、取り出しを直し、設計書に「決定:」で書く (判定の考えが変わるなら新しい ADR)。

1. `RegisterTaskDefinition` の requestParameters に `containerDefinitions` (`secrets`・`environment`・`image`) が入るか。`environment` の値が伏せられているか (伏せられていても取り出さない)
2. `RunTask`・`UpdateService`・`CreateService` の要求と応答の鍵 (`overrides` の形、`taskDefinition` が名前か ARN か)
3. サービスのデプロイ・スケジューラーの入れ替え・スケールアウトの前後に、`RunTask` などの記録が出るか。出るなら主体の形 (`AWSService`・サービスにリンクされたロール・`invokedBy`)
4. 自動スケーリングの desired count の変更の記録 (操作名・主体の形・要求の鍵)
5. EventBridge Scheduler の定時の `RunTask` の主体の形 (利用者の実行ロール・`invokedBy`)
6. CodeDeploy のブルー/グリーンのデプロイで `CreateTaskSet` が記録に出るか、出るならその主体

## 検討した選択肢

- **`bulk: exempt` の側で、デプロイの操作と時刻で突き合わせる**: 0073・0076 で却下した (攻撃者もデプロイの操作ができ、タスクはデプロイの外でも起動する)。
  本 ADR は突き合わせず、操作そのものを、誰が・何を変えたかで別に見る。secret_access の判定は変えない
- **RunTask の応答のタスクの ID と、ECS の `AssumeRole` のセッション名を突き合わせ、デプロイする主体の外が起動したタスクの読み取りを `bulk: exempt` から外さない**:
  0076 の背景の 1 で、実行ロールの発行のセッション名は 16 進 32 桁だった。タスクの ID と同じなら強い結び付きになるが、同じかは確かめていない。
  また、セッション名を残さない方針 (ADR 0055) の例外 (ハッシュで残す) が要る。今回は入れず、9 節で記録を見るときに一緒に確かめ、同じなら別の ADR で考える
- **アカウントの状態のスナップショット (`ListTaskDefinitions`・`DescribeTaskDefinition`) でタスク定義を比べる**: 読み取りの権限が増え、`DescribeTaskDefinition` は `environment` の平文の値を返す
  (arata が秘匿値を読むことになる)。誰が登録したかも分からない。却下
- **「これまで」を前の 1 リビジョンだけにする**: 単純だが、攻撃者が登録したリビジョンが次の比較の基準になる。デプロイする主体の登録の和にした
- **「これまで」をストアの新しい表 (ファミリーごとの既知のロール) に持つ**: 保持の期間に依らず残るが、表と rebuild の扱い・承認の操作が増える。90 日の events で足りる間は持たない。
  まれにしか登録しないファミリーが `new_family` の low で鳴るのが困る大きさになったら、別の ADR で考える
- **デプロイする主体を `checks.ecs_workload_changes.deployers` (設定) に書く**: 既知の主体は allowlist に置く決まり (ADR 0004・0008・0055) に合わない。設定はパラメータだけにした
- **`tags: [deploy]` を流用する**: 2 節のとおり意味が違う。却下
- **デプロイする主体の操作も毎回報告する (ecs_exec と同じ)**: 量に埋もれ、本当の変化が見えなくなる。変化だけにした
- **知らない主体の RunTask を critical にする**: ecs_exec と揃えて high にした。high は ADR 0082 の速報に乗り、ack もできない
- **`environment` の名前は残す**: 名前だけでも調べる材料になるが、攻撃者が書ける文字列で、名前に値を書き込む使い方もありうる。数だけにした
- **失敗を残さない**: ecs_exec と同じ理由で却下

## 結果 (良い点・引き受けるコスト)

- `bulk: exempt` の残りの穴 (ECS に正規の手順で起動させる形) のうち、デプロイする主体の外からの起動・ロールの付け替え・コマンドの上書き・秘匿値の参照の追加が、毎日の単位で見える。
  知らない主体なら high で hourly に知らせる。読み取りの権限は増えない
- PassRole の記録が無い中で、どのロールをどこに渡したかが events に残り、調べられる
- 引き受けるコスト:
  - allowlist の節 (`ecs_deployers`) と、その検査・ファズが増える。導入時に CI の主体を書くまで、デプロイのたびに medium が出る (3 節の注記で案内する)
  - デプロイする主体を奪われた場合の、許した範囲の起動は見えない (8 節)
  - 人が操作していない起動の記録の形が未確認で、確かめるまでは鳴る側に倒れる (4 節・9 節)
  - 注目イベントが増える (7 節の量)。版を上げた直後は「これまで」が空で、最初の登録が low になる
- 実装: `internal/collect/cloudtrail` (注目イベントと取り出し・ファズ)、`internal/allowlist` (`ecs_deployers`・ファズ)、`internal/config` (`history_days` と検査・雛形)、
  `internal/checks` (判定・info・注記・片付けの表)、文書 (7 節)
