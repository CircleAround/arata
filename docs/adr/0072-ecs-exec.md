# 0072. 本番のコンテナでシェルを開く操作 (ECS Exec の `ExecuteCommand`) を、誰が・どこに・何を、で毎回報告する (`ecs_exec`)

- 日付: 2026-11-17
- 状態: 提案

## 背景

ECS Exec (`ecs:ExecuteCommand`) は、動いているタスクのコンテナでコマンドを実行し、多くはシェルを開く操作である。
コマンドはコンテナの中で root として動く (下の出典 1)。奪われた認証で入られると、環境変数の秘匿値・タスクロールの認証情報・DB の接続に直接届く。
アプリのログにも WAF にも現れないので、arata が見られるのは CloudTrail の `ExecuteCommand` の記録だけである。

実際の監査で、正規の作業として本番のコンテナに ECS Exec で入ったことが、タスクロールが new_principal に出るという副作用でしか見えなかった。
arata には ExecuteCommand を見るチェックが無い (`ecs.amazonaws.com` の操作は注目イベントに入っておらず、events に残らない)。
副作用に頼ると、タスクロールが既知になった後の 2 回目からは何も見えない。

### 公式文書で確かめたこと (2026-11-17 に読んだ)

1. ECS の開発者ガイド「Monitor Amazon ECS containers with ECS Exec」
   <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html>
   - 「you can audit which user accessed the container using the `ExecuteCommand` event in AWS CloudTrail」(eventName は `ExecuteCommand`)
   - ECS Exec は Systems Manager の Session Manager を使う。コマンドとその出力の記録は、クラスターの `executeCommandConfiguration` で CloudWatch Logs か S3 に送る (CloudTrail ではない)
   - 「While starting SSM sessions outside of the `execute-command` action is possible, this results in the sessions not being logged ...
     We recommend limiting this access by denying the `ssm:start-session` action using an IAM policy.」
2. ECS の API リファレンス「ExecuteCommand」 <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ExecuteCommand.html>
   - 要求: `cluster` (任意)、`command` (必須)、`container` (任意。タスクにコンテナが 1 つなら省ける)、`interactive` (必須、真偽)、`task` (必須)
   - 「Amazon ECS only supports initiating interactive sessions, so you must specify `true` for this value」
   - 応答: `clusterArn`、`containerArn`、`containerName`、`interactive`、`session` (`sessionId`・`streamUrl`・`tokenValue`)、`taskArn`
   - 失敗の例: `TargetNotConnectedException` (権限の不足、コンテナの中で SSM のエージェントが動いていない、など)、`AccessDeniedException`
3. ECS の API リファレンス「Session」 <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Session.html>
   - `tokenValue` は「An encrypted token value containing session and caller information. It's used to authenticate the connection to the container.」
4. ECS の開発者ガイド「Log Amazon ECS API calls using AWS CloudTrail」
   <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/logging-using-cloudtrail.html>
   - 「logs all Amazon ECS control plane operations as management events」。データイベントとして挙がるのはコンテナインスタンスの API だけ。
     ExecuteCommand は名指しされていないが、制御面の操作なので管理イベント (LookupEvents で引ける) と読む
5. ECS の開発者ガイド「Amazon ECS task IAM role」の ECS Exec の権限
   <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html>
   - タスクロールに `ssmmessages:CreateControlChannel`・`CreateDataChannel`・`OpenControlChannel`・`OpenDataChannel` が要る
6. Systems Manager のユーザーガイド「Logging AWS Systems Manager API calls with AWS CloudTrail」
   <https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html>
   - `StartSession` は管理イベント。`ssmmessages` の `CreateControlChannel`・`OpenControlChannel` はデータイベント (イベント履歴には出ない)
7. AWS のブログ「NEW – Using Amazon ECS Exec to access your containers on AWS Fargate and Amazon EC2」(2021-03-16)
   <https://aws.amazon.com/blogs/containers/new-using-amazon-ecs-exec-access-your-containers-fargate-ec2/>
   - 「the command itself will be logged in AWS CloudTrail as part of the ECS `ExecuteCommand` API call」
   - 対話のシェルでは、最初の `/bin/bash` だけが CloudTrail に残り、シェルの中で打ったコマンドは残らない

**確かめられなかったこと**: ExecuteCommand の CloudTrail の記録の実例 (requestParameters と responseElements の実際の形) は、上の文書のどこにも無かった。
`eventSource` が `ecs.amazonaws.com` であること、requestParameters と responseElements の鍵の名前が API の要求・応答の名前と同じであること
(ほかの ECS の操作の記録の例はそうなっている)、拒否された呼び出しで requestParameters が残るか、`tokenValue` が記録で伏せられているかは、推定である。
そのため、実装は「無い鍵は不明として扱い、知らない形で落ちない」ように書き、記録の実例での確認を実装の PR の完了の条件にする (決定の 9)。

## 決定

### 1. チェック `ecs_exec` (hourly、event、trail_event)

- 成功した `ExecuteCommand` (eventSource `ecs.amazonaws.com`) を、**誰が・どこに・何を・どこから**の単位でまとめて毎回報告する
- 周期は hourly (root_usage・unknown_assume_role と同じ)。知らない主体のシェルは発生そのものが異常で、早く知らせたい。
  hourly のチェックは雛形の daily のプロファイルにも入るので、hourly を回さない運用でも日次で拾える。
  材料は既に引いている LookupEvents (と `cloudtrail-s3`) の記録だけで、読み取りの権限も API の呼び出しも増えない
- **暗黙には動かさない** (ADR 0014)。実行されるのは設定の `profiles` に書いたときだけ。`config init` の雛形には (ほかのチェックと同じく) 入れ、
  既存の設定には入らないので、`config init --diff` が `unused_check` として見せる (説明は「本番のコンテナでシェルを開く操作 (ECS Exec) を毎回報告する」)。
  パラメータを足したら (4 節の上限)、雛形の `checks:` に既定値を書き、`config init --diff` の比較の対象にする

### 2. collector: 注目イベントに足し、要る値だけを取り出す

- `notableAPIs` に `ecs.amazonaws.com: ExecuteCommand` を足す (ADR 0026 と同じやり方。チェック側が `checks.ECSExecAPIs` を公開し、collector のテストで突き合わせる)。
  注目イベントの追加で、既存のチェックと principal_seen の結果が変わらないことをテストで固定する
- normalize で Data に取り出すのは次だけ:
  - 要求から `cluster`、`task`、`container`、`command`、`interactive`
  - 応答から `clusterArn`、`taskArn`、`containerName`、`session.sessionId`
- **`session.tokenValue` と `session.streamUrl` は取り出さない** (接続の認証に使う値。記録で伏せられているかを確かめられていないので、伏せられていない前提で扱う)。
  今の normalize は rawEvent の使う鍵だけを読み、生の記録全体を raw にも SQLite にも残さないので、取り出さなければ残らない
- `command` は利用者が打った文字列で、攻撃者が書ける (ADR 0037)。取り出すときに、制御文字・書式の文字 (Unicode の Cc・Cf) を除き、
  256 文字 (rune) で切り、切ったことを `command_truncated` で残す。値の解釈 (シェルかどうか) は 5 節の規則で行う
- 主体は既存の正規化 (assumed-role のセッションはロールの ARN) のまま。**セッション名は出さない** (SSO のセッション名は利用者のメールアドレスであることが多い。
  レポートに個人を特定できる値を書かない)

### 3. 重大度

| 場合 | 重大度 |
|---|---|
| 知らない主体 (下の「既知」でない。root を含む) | high |
| 既知の主体 | medium |
| 知らない主体の、すべて失敗した試行 | medium |
| 既知の主体の、すべて失敗した試行 | low |

- 「既知」は new_principal が報告しない主体と同じ判定にする: allowlist の `principals` で期限内に承認済み、またはストアの主体の状態が `baseline` / `approved`。
  同じ関数を使い、判定がずれないことをテストで固定する
- root の ExecuteCommand は high (root_usage が別に critical で報告する。片方に寄せない。ECS Exec の playbook の手順が要るため)
- 承認済みでも、`tags: [deploy]` でも下げない (IaC のパイプラインは ECS Exec を使わない。使うなら毎回人が見る)
- 重大度を上げる材料 (深夜帯・新しい送信元) は入れない。新しい送信元は principal_new_source が別に見る。時間帯は利用者ごとに違い、規則で決められない

### 4. まとめ方 (集約の Key) と量

- **Key は `<主体の ARN>|<リージョン>/<クラスター名>|<コンテナ名>|<UTC の日付>`**
  - クラスターは応答の `clusterArn`、無ければ要求の `cluster` から名前を取る (ARN でも名前でも同じ Key になるように)。取れなければ `-`。
    要求に `cluster` が無いのは既定のクラスター (`default`) だが、推測で埋めず `-` にする
  - コンテナは応答の `containerName`、無ければ要求の `container`、どちらも無ければ `-`
  - タスクは Key に入れない (デプロイのたびに変わり、同じ作業が別の finding に割れる)。data に出す
  - 日付を入れる: 同じ人が同じコンテナに何日も入っても、日ごとに別の finding になり、その日の中身 (コマンド・送信元・タスク) が残る
- **Fingerprint は 重大度 + 既知かどうか + 全部失敗かどうか + その Key に入った記録の event_id の集合 (の要約)**
  - 同じ日の同じ Key に新しいセッションが加われば changed になり、新しい中身で出し直す (still_open のまま古い data が残るのを避ける。ADR 0068 の 5 節の追記の穴)
  - hourly の後の daily の run は同じ記録を引き直すので、event_id の集合は変わらず still_open になる (二重に知らせない)
- data: `principal`、`principal_kind`、`known`、`principal_status`、`region`、`cluster`、`container`、`count` (呼び出しの数)、`sessions` (成功の数)、
  `commands` (異なるコマンド。最大 10 個、それぞれ 2 節の 256 文字)、`commands_more` (載せきれなかった数)、`command_kinds` (5 節)、`interactive`、
  `tasks` (タスク ID。最大 10 個)、`session_ids` (最大 10 個。CloudWatch Logs / S3 のセッションの記録と突き合わせるため)、`ips`、`first_time`、`last_time`、
  `denied` (全部失敗)、`has_errors` (失敗が混ざる)、`error_codes`
- 量の見積もり: 既知の人が毎日使っても、1 日に (主体 × クラスター × コンテナ) ごとに 1 件。同じ日に何度入っても 1 件で、changed が増えるだけ。
  aratam は同じチェックの指摘を規則でまとめる (ADR 0029) ので、通知も 1 つのまとまりになる
- **日常の利用を黙らせる仕組み (既知の人の medium を出さない) は入れない**。本番のコンテナでシェルを開くことは、既知の人でも毎回見る出来事である。
  日常的に使っているなら、それ自体が「運用の作業を手順やジョブに移す」べき指摘で、黙らせる設定はその気づきを消す。
  量が実際に困る大きさになったら、黙らせる前に、まず使っている作業を調べる (playbook)。それでも要るなら、別の ADR で、
  allowlist に主体 × クラスター × 期限の項目を足し、その範囲を low にする (出さないのではなく下げる) 案から考える

### 5. コマンドの扱い

- `command_kinds` は規則で付ける分類: `shell` (先頭の語が `sh`・`bash`・`ash`・`dash`・`zsh` か、それらへのパス。`-c` が付けば `shell_c`) と `other`
- **report.json / report.md には `commands` を出す** (誰が何を始めたかを見るのがこのチェックの目的)。md ではコードの囲みに入れ、Markdown として解釈させない
- **aratam の Slack の通知には、コマンドの文字列を出さず、`command_kinds` と件数だけを出す**。LLM の入力にも `commands` を渡さず `command_kinds` を渡す
  - 理由: `command` には、作業者が打った秘匿値 (`sh -c "PGPASSWORD=... psql ..."` など) が入りうる。CloudTrail を読める人と、Slack のチャンネルを読める人は同じではない。
    また、攻撃者が書ける文字列を LLM に渡さない (ADR 0037)
  - 全文は report.md と CloudTrail で読む (通知の末尾に案内)
- 対話のシェルの中で打ったコマンドは CloudTrail に残らない (出典 7)。playbook で、ECS Exec のセッションの記録 (`executeCommandConfiguration` の CloudWatch Logs / S3) を案内する。
  セッションの記録を arata が読むことはしない (アプリのログと同じく、読ませるロググループは利用者が決める。ADR 0062)

### 6. 失敗した ExecuteCommand (errorCode あり)

- 捨てずに同じチェックで報告し、すべて失敗した Key は 3 節の表で 1 段下げ、見出しを「ECS Exec の試行 (失敗)」にする。`denied: true` と `error_codes` を残す。
  成功が混ざれば成功の重大度で、`has_errors: true`
  - 理由: 知らない主体が本番のコンテナに入ろうとしたこと自体が指摘になる (iam_changes の拒否と同じ考え)。下げるのは、入れていないから
  - 既知の主体の `TargetNotConnectedException` (エージェントが動いていない・設定の誤り) は作業の失敗で、low で足りる
- `AccessDenied*` は access_denied にも数えられる (拒否の幅と量)。二重になるが、見ているものが違う (access_denied は列挙の兆候、ecs_exec は入ろうとした先) ので、片方に寄せない
- 拒否された呼び出しでは requestParameters が残らないことがある (iam_changes で確かめた事実。ExecuteCommand でも同じかは未確認)。
  そのときクラスターとコンテナは `-` になり、成功の Key とは別の finding になる

### 7. SSM の `StartSession` は含めない

- 却下の理由:
  - 入る先が違う。StartSession の多くは EC2 のインスタンス (やオンプレミスの管理ノード) で、封じ込めの手順 (インスタンスの隔離・インスタンスプロファイル) が違う。
    1 つのチェックにすると、playbook と片付けの表が「どちらの場合か」で分かれる
  - 記録の形が違う (`target`・`documentName`・`parameters`)。ポートの転送 (`AWS-StartPortForwardingSession` など) はシェルではなく、重さの決め方が別に要る
  - ECS Exec が内部で Session Manager を使うとき、CloudTrail に StartSession も残るかは文書に無い。同じチェックで両方を数えると、1 回の ECS Exec を 2 回と数えるおそれがある
- ただし、出典 1 のとおり、**ECS Exec を通さずにコンテナへ StartSession することができ、その場合はセッションが記録されない**。これは ecs_exec が見えない入り方である。
  設計書 7 章の未実装の `ssm_session` を、別の ADR で ecs_exec と同じ形 (誰が・どこに・何を、毎回) で作り、そこで次を扱う:
  - インスタンス ID (`i-`・`mi-`) でない target (コンテナを指すもの) への StartSession は、ECS Exec の迂回として重く扱う。target の書式は公式文書で確かめてから決める (今回は見つからなかった)
  - 本 ADR と同じまとめ方・重大度・コマンドの扱いを、関数として共用する
- それまでは ecs_exec の playbook で、`ssm:StartSession` をコンテナに対して拒否する IAM の方針 (出典 1) を案内する

### 8. 片付け (ADR 0068 の表に足す行)

playbook `docs/ai/playbooks/ecs_exec.md` の「片付け」の節:

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high | なし | snooze・resolve |
| medium・low | あり | snooze・resolve |

- 上がる余地: medium は、主体の承認が期限切れになれば同じ Key で high になる。low は、同じ日に成功が混ざれば medium になる
- **ack は許さない** (余地のある行も)。ack 中に出直すのは重大度が上がったときだけ (ADR 0022) で、同じ日の 2 回目のセッション (changed) が見えなくなる。
  日付が Key に入るので、確かめた日の finding を resolve すれば、次の日の利用は新しく報告される
- **approve は受け付けない**。主体を既知にするのは new_principal の approve (`principals`) で、それで high が medium になる。ecs_exec の finding を approve で消す道は作らない
- resolve: 作業として確かめた日の利用 (誰の・何の作業か)。snooze: 障害の対応などで続けて入る期間を、終わりの日まで
- `checks.TriageRows` と playbook の表を突き合わせるテスト (ADR 0068 の 4 節) に乗る。`arata approve` が ecs_exec を断ることもテストで固定する

### 9. 記録の実例での確認 (実装の PR の完了の条件)

- テストの記録は、API リファレンスの鍵の名前と、架空の値 (`123456789012`・`prod-cluster`・`app`・`alice`) で作る。鍵が無い記録・型の違う記録・`tokenValue` を含む記録も作る
- `ExecuteCommand` の記録を解釈する関数にファズテストを足す (ADR 0041)。守る規則: パニックしない、`tokenValue`・`streamUrl` の値が Data のどこにも現れない、
  `command` が 256 文字以下で制御文字・書式の文字を含まない、Key の各部に `|` が入らない (入れば置き換える)
- 実際の記録の形は、開発用のアカウント (sandbox) で ECS Exec を 1 回行って得た記録で確かめ、形が違えば取り出しを直す。
  sandbox には今 ECS が無いので、要る資源 (Exec を有効にしたタスク 1 つ) を足すか、手で 1 回作って消すかは、開発リードが決める (deploy は開発リードが行う。ADR 0020)。
  確かめた形は `docs/cloudtrail-event-names.md` に、出典と一緒に足す

### 10. 攻撃の事例との対応 (ADR 0058)

- ECS Exec を使ったと出典が書いている公開の事例は、2026-11-17 の時点で見つからなかった
  (ECS を狙った事例の多くは、タスクの作成・タスク定義の登録による採掘や、タスクロールの認証情報の持ち出しで、ExecuteCommand ではない)。
- そのため、playbook の「関連する事例」は「対応する公開の事例はまだ無い」とし、`docs/threats.md` の「チェックごとの事例」に同じ行を足す。
  既存の事例の表は変えない (出典に無い段階を足さない)
- 出典を読んで確かめられる事例が出たら、その PR で事例を足す

## 検討した選択肢

- **Key をセッション (sessionId か event_id) ごとにする**: 「毎回」を最も素直に表すが、障害の対応で 1 日に何十回も入ると finding が何十件になり、片付けも何十回になる。
  同じ日・同じ人・同じコンテナにまとめ、セッションが増えたら changed で出し直す形にした
- **Key に日付を入れない (主体 × クラスター × コンテナ)**: finding は増えないが、open のまま次の利用が来ると still_open になり、data が最初の報告のまま更新されない。
  resolve の後の利用は new になるが、resolve を忘れると、その後の利用の中身がどこにも出ない。却下
- **既知の主体の利用を info にする (ai_path_usage のように 1 行残すだけ)**: 量は減るが、奪われた既知の認証で入られたときに medium の通知が出ない。
  入った人が正規かを、既知の主体という事実だけで決めない。却下
- **知らない主体だけを報告する**: 背景の事例 (正規の作業) は見えたほうがよかった。既知の人の利用でも、誰が何を始めたかは残すべき。却下
- **失敗を報告しない (access_denied に任せる)**: access_denied は拒否のコードだけを、主体ごとの幅と量で見る。`TargetNotConnectedException` は拒否ではなく数えられず、
  「本番のコンテナに入ろうとした」という意味も失われる。却下
- **失敗を成功と同じ重さにする**: 既知の人の設定の誤りが medium で毎回鳴る。1 段下げた
- **StartSession も同じチェックで見る**: 7 節の理由で却下し、`ssm_session` として別に作る
- **コマンドを Slack にも出す**: 通知だけで判断できるが、作業者が打った秘匿値がチャンネルに流れうる。分類と件数だけにした (全文は report.md)
- **既定のプロファイルに暗黙で入れる**: 暗黙の既定を持たない (ADR 0014)。雛形には入れ、既存の設定には `config init --diff` で見せる
- **深夜帯・新しい送信元で上げる**: 時間帯は利用者ごとに違い、規則で決められない。送信元は principal_new_source が見る。入れない

## 結果 (良い点・引き受けるコスト)

- 本番のコンテナへのシェルが、既知の人の作業でも毎日 1 件の単位で見え、知らない主体なら high で hourly に知らせる。権限は増えない
- コマンドの全文は report にだけ残り、通知と LLM には分類だけが渡る
- 引き受けるコスト:
  - 既知の人が日常的に使う環境では、毎日 medium が出て、片付け (resolve) が毎日要る。これは、本番のシェルを日常の手段にしていることへの指摘として受け入れる
  - 対話のシェルの中のコマンドは見えない。ECS Exec の記録の設定は利用者に任せる
  - ECS Exec を通さない StartSession は、`ssm_session` を作るまで見えない
  - 記録の実例を sandbox で確かめるまでは、取り出しの形は推定である (9 節)
  - 注目イベントが 1 つ増え、events の行が ExecuteCommand の数だけ増える (少ない)
