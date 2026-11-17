# ecs_exec: 本番のコンテナでシェルを開く操作 (ECS Exec)

## この指摘の意味

誰かが ECS Exec (`ecs:ExecuteCommand`) で、動いているタスクのコンテナでコマンドを実行した (多くはシェルを開いた) (hourly)。
コマンドはコンテナの中で root として動き、環境変数の秘匿値・タスクロールの認証情報・DB の接続に直接届く。アプリのログにも WAF にも現れない。
既知の人の正規の作業でも毎回報告する (本番のシェルは、誰が何を始めたかを毎回残すべき出来事)。

| 場合 | 重大度 |
|---|---|
| 知らない主体 (root を含む。承認の期限切れを含む) | high |
| 既知の主体 (allowlist で承認済み、またはベースラインの主体) | medium |
| 知らない主体の、すべて失敗した試行 | medium |
| 既知の主体の、すべて失敗した試行 | low |

- `tags: [deploy]` の主体でも下げない (IaC のパイプラインは ECS Exec を使わない)
- Key は `<主体>|<リージョン>/<クラスター>|<コンテナ>|<UTC の日付>`。同じ人が同じコンテナに同じ日に何度入っても 1 件で、新しいセッションが加われば changed として出直す。
  次の日の利用は別の finding になる。クラスター・コンテナが記録に無いとき (拒否された呼び出しなど) は `-`
- data: `principal`、`principal_kind`、`known`、`principal_status` (approved / baseline / unknown / expired / unseen / root)、`region`、`cluster`、`container`、`date`、
  `count` (呼び出しの数)、`sessions` (成功の数)、`commands` (始めたコマンド。最大 10 個、1 つ 256 文字まで)、`commands_more`、`command_kinds` (`shell`・`shell_c` (シェルに -c で文字列を渡した)・`other`)、
  `interactive`、`tasks` (タスク ID。最大 10 個)、`session_ids` (最大 10 個)、`ips`、`first_time` / `last_time`、`denied` (すべて失敗)、`has_errors` (失敗が混ざる)、`error_codes`
- `commands` は CloudTrail に残った**最初のコマンドだけ**。対話のシェルの中で打ったコマンドは CloudTrail に残らない。中身はクラスターの ECS Exec の記録
  (`executeCommandConfiguration` の CloudWatch Logs / S3。設定していれば) で `session_ids` を手がかりに読む
- `commands` には作業者が打った秘匿値が入りうるので、通知 (Slack) と LLM には渡さない。report.md と CloudTrail で読む

## まず確かめること

1. 主体と `known`・`principal_status` を見る。`known: false` なら、その主体が誰かを先に確かめる (`arata review --format json` で、同じ主体の new_principal・unknown_assume_role を探す)
2. `ips` が業務の場所と合うか。同じ主体の principal_new_source (初めての送信元) が同じ時間帯にあれば、認証情報の漏洩の疑いが強い
3. `commands` と `command_kinds` を見る。`shell_c` (文字列を渡した) は中身を読む。`env`・`printenv`・`cat /proc/1/environ`・`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` を使う curl
   (タスクのメタデータのエンドポイントからタスクロールの認証情報を取り出す)・DB のクライアントは重い
4. ECS Exec の記録があれば、`session_ids` のセッションで打ったコマンドを読む:
   `aws ecs describe-clusters --clusters <cluster> --query 'clusters[].configuration.executeCommandConfiguration'` で記録の行き先を確かめる
5. 同じ時間帯に、タスクロールの主体の new_principal・secret_access・access_denied が無いか。コンテナの中の SSM のエージェントは、セッションのたびにタスクロールで
   ssm の `CreateDataChannel` と、logs の `DescribeLogGroups`・`DescribeLogStreams`・`CreateLogStream` (セッションの記録用) を呼ぶ。
   ECS Exec を初めて使ったときに、タスクロールが new_principal に出るのはこのため
6. CloudTrail で詳細を見る: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ExecuteCommand --start-time <first_time> --end-time <last_time> --region <region>`
7. 作業の記録 (障害の対応・調査のチケット) と合うか。利用者の事情に説明があるか

## 判断の分かれ目

- **正規の可能性が高い**: 既知の人が、業務の場所から、作業の記録のある時間に入った。始めたコマンドがシェルか作業に合うもの
- **要対応**: 知らない主体・承認の期限切れの主体、見知らぬ送信元、作業の記録が無い、環境変数・認証情報を読むコマンド、同じ時間帯の秘匿値の読み取りや拒否の急増
- `denied` の試行: 知らない主体なら、入ろうとしたこと自体を侵害の疑いとして扱う。既知の主体の `TargetNotConnectedException` は、エージェントが動いていない・権限の設定の誤りで、作業の失敗のことが多い

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): 入った主体の認証情報を止める (アクセスキーの無効化、ロールの `Revoke sessions`)。入られたタスクを止めて入れ替える
   (`aws ecs stop-task`。サービスが新しいタスクを起こす)。コンテナから読めた秘匿値 (環境変数・Secrets Manager の値・DB のパスワード) を入れ替える。
   タスクロールの一時的な認証情報は、タスクを止めても期限まで使えるので、タスクロールのセッションも取り消す
2. **承認**: ecs_exec の finding は approve できない。主体を既知にするのは new_principal の approve (`principals`)。既知にしても medium で毎回報告される
3. **expected_denied**: 対象外
4. **片付け**: 片付けは下の「片付け」の節
5. **設定の修正**: ECS Exec を使える人を IAM で絞る (`ecs:ExecuteCommand` の Condition でクラスター・コンテナを絞る)。本番のサービスは `enableExecuteCommand` を既定で切り、使うときだけ有効にする。
   ECS Exec の記録 (`executeCommandConfiguration`) を有効にする。日常の作業はシェルではなく、手順やジョブ (タスクの単発の実行など) に移す。
   ECS Exec を通さずにコンテナへ `ssm:StartSession` するとセッションが記録されない (AWS の文書) ので、コンテナに対する `ssm:StartSession` は IAM で拒否する

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high | なし | snooze・resolve |
| medium・low | あり | snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。このチェックは event 型 (観測されなくても解消にならない)。

- 上がる余地: medium は、主体の承認が期限切れになれば同じ Key で high になる。low は、同じ日に成功が混ざれば medium になる
- **ack は許さない** (余地のある行も)。ack 中に出直すのは重大度が上がったときだけで、同じ日の次のセッション (changed) が見えなくなる
- resolve: 作業として確かめた日の利用 (誰の・何の作業か) を `arata resolve <id> --reason "<作業>"`。次の日の利用は新しく報告される
- snooze: 障害の対応などで同じコンテナに続けて入る期間を、終わりの日まで `arata snooze <id> --until YYYY-MM-DD`
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- `known: true` だけを理由に正規と書かない (奪われた既知の認証でも known になる)。送信元・時間・作業の記録で確かめる
- `commands` に無いことを「何もしていない」と書かない (対話のシェルの中のコマンドは CloudTrail に残らない)
- 通知や要約に `commands` の文字列を書き写さない (秘匿値が入りうる)
- LLM がタスクを止めない・認証情報を操作しない (提案まで)

## 関連する事例

対応する公開の事例はまだ無い (`arata help ai threats`)。ECS Exec を使ったと出典が書いている公開の事例は、2026-11-17 の時点で見つかっていない。
