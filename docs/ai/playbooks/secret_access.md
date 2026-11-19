# secret_access: 秘匿値の読み取りの異常

## この指摘の意味

主体が秘匿値 (Secrets Manager のシークレット、SSM の SecureString を復号した読み取り) を、ふだんと違うやり方で読んだ (daily)。
対象は成功した `GetSecretValue` / `BatchGetSecretValue` と、`withDecryption=true` の `GetParameter` / `GetParameters` / `GetParametersByPath`。失敗は access_denied が扱う。

- 初めて読む秘匿値: その主体が過去 `baseline_days` (既定 14 日) に読んでいない秘匿値を読んだ → low。その主体が秘匿値を読むこと自体が初めてなら medium
- 一括読み出し: 窓 (1 日) に読んだ異なる秘匿値の数が `max(min_distinct, その主体の日ごとの中央値 × factor)` を超えた → high (持ち出しの兆候)。
  `GetParametersByPath` はパス単位で 1 と数える (再帰的に読むと 1 回で多数が読める。`paths` に `(recursive)` が付く)
- allowlist の `secrets_access` に書いた「主体 × 秘匿値」は初出に数えない (一括読み出しの数には数える)。
  `bulk: exempt` を書いた項目の組は、一括読み出しの数からも外す (窓と平常帯の両側。AWS のサービスに引き受けられたロールのときだけ。下の「起動時の読み取り」)。
  導入直後 (CloudTrail を収集し終えた過去日が `min_baseline_days` 未満) は初出を報告しない (一括読み出しは報告する)
- 秘匿値の値は CloudTrail に入らないので arata も持たない。名前 / ARN だけ
- Key は主体の ARN。data: `principal`、`principal_kind`、`allowlist_status`、`distinct_secrets`、`secrets` (最大 20。`secretsmanager:<名前か ARN>` / `ssm:<名前>` / `ssm-path:<パス>`)、
  `paths`、`bulk`、`threshold`、`baseline_median_distinct`、`new_secrets` (最大 20)、`new_secret_count`、`first_reader`、`secrets_access_matched`、`count`、`ips`、`event_names`。
  `bulk: exempt` に一致した秘匿値があれば `bulk_counted` (閾値と比べた数)、外したなら `bulk_exempted` (外した数)・`bulk_exempt_patterns` (一致した glob)、
  外さなかったなら `bulk_exempt_ignored: not_service_role` (サービスに引き受けられたロールでない)。`distinct_secrets` は外す前の数
- info の行 (Key は `bulk-exempt:<主体の ARN>`、`bulk_exempt: true`): `bulk: exempt` の組だけを読み、ほかに報告することが無かった主体。
  data は `principal`、`bulk_exempted`、`bulk_counted`、`bulk_exempt_patterns`、`count`、`ips`、`event_names`。件数・通知には数えない

## まず確かめること

1. `bulk` と `distinct_secrets`・`threshold` を見る。ふだん数個しか読まない主体が数十個を読んだのは持ち出しの典型。`paths` の `(recursive)` で上位のパス (`/` など) を読んでいないか
2. `new_secrets` の名前を見る。主体の用途 (どのアプリ・どの環境) と合うか。本番のアプリのロールが別の環境・別のアプリの秘匿値を読むのは要注意
3. `ips` を見る。ふだんの送信元 (アプリの実行環境・NAT・オフィス) と違うなら、同じ主体の principal_new_source を探す
4. `arata review --format json` で同じ主体の principal_new_source・access_denied (特に `secretsmanager:ListSecrets`・`ssm:DescribeParameters` の拒否)・iam_changes を探す
5. CloudTrail で読み取りの前後を並べる: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue`
   (ssm は `GetParameter` / `GetParametersByPath`) を引き、主体・送信元・`userAgent` を見る。直前の `ListSecrets` / `DescribeParameters` (秘匿値の一覧の取得) は探索の兆候
6. デプロイ・アプリの変更 (新しい設定値の追加、起動時に読む値の変更) と時刻が合うかを確かめる
7. info の行 (`bulk-exempt:`) は、`ips` がそのロールのいつもの送信元 (タスクの出口) と同じかだけを見る。違えば、発行された一時的な認証情報が外で使われた疑いとして、上の 3〜5 を行う

## 判断の分かれ目

- **正規の可能性が高い**: 新しい秘匿値の追加・アプリの改修と同時刻。送信元がいつもの実行環境。読んだ名前がその主体の用途に合う。
  運用者が障害対応で値を確かめた (持ち主が説明できる)
- **要対応**: high (一括読み出し)。名前が用途に合わない (別のアプリ・別の環境・管理者の認証情報)。送信元がいつもと違う、principal_new_source や access_denied と同時。
  読み取りの直前に秘匿値の一覧の取得がある。人の主体 (IAM ユーザー) が多数の本番の秘匿値を読んだ

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (説明が付かない): 読まれた秘匿値をすべて漏洩したものとして扱い、値を変更 (ローテーション) し、その値で入れる先 (DB・外部 API) の利用履歴を確かめる。
   読んだ主体のアクセスキーの無効化・ロールのセッションの失効 (`Revoke active sessions`)。どの値を変えるかの順番は人が決める
2. **承認**: 正規の読み手なら、恒常的な「主体 × 秘匿値」を allowlist の `secrets_access` に人が書く (`principal` と `secrets` の glob。例 `["prod/app-a/*"]`)。
   広い glob (`*`) は初出を隠すので勧めない。起動のたびに決まった組を読むロールは、下の「起動時の読み取り」の `bulk: exempt`
3. **設定の修正**: 主体の権限を必要な秘匿値に絞る (`Resource` に ARN・パスを書く。`GetParametersByPath` の再帰を上位のパスに許さない)、
   リソースポリシー・KMS キーのポリシーで読める主体を絞る、人が本番の秘匿値を直接読む運用をやめる

### 起動時の読み取り (`bulk: exempt`。ADR 0073)

ECS のタスクの起動のたびに、ECS のエージェントがタスクの実行用のロールで、タスク定義の `secrets` に書いた秘匿値をまとめて読む (`GetParameters` の 1〜数回)。
デプロイが数日〜週に 1 回だと、日ごとの数の中央値が 0 のままなので、閾値は `min_distinct` になり、デプロイの日は毎回 high になる。
毎日読む主体 (毎日動く定時のジョブなど) が high にならないのは、中央値がその数になり、閾値が `中央値 × factor` に上がるため。間隔が 2 日以上のジョブは、起動時の読み取りと同じく中央値が 0 になる。

正規の起動時の読み取りと確かめたら、人が allowlist.yaml の `secrets_access` に、その組だけを `bulk: exempt` で書く。

```yaml
secrets_access:
  - principal: arn:aws:iam::123456789012:role/example-app-task-execution   # タスクの実行用のロール (ARN の完全一致)
    secrets: ["/example-app/prod/secrets/*"]                                  # その組だけ
    bulk: exempt
    note: タスクの起動のたびに ECS がタスク定義の secrets を読む
```

- 確かめること: 主体がタスクの実行用のロール (信頼ポリシーの主体が `ecs-tasks.amazonaws.com`)、読んだ名前がタスク定義の `secrets` と一致、時刻がタスクの起動 (デプロイ) と合う、送信元がいつもの出口
- 書けないもの (読み込みエラー): ロールでない主体、`note` の無い項目、`arn:` の形、広い glob (ワイルドカードより前に `/` で閉じた区切りが 2 つ未満: `*`・`/*`・`prod/*`・`/example-app/*`・`/example-app/prod*`)
- 外すのは、その主体が AWS のサービスに引き受けられたロールのときだけ (保存済みの AssumeRole の呼び出し元がサービス)。人の SSO のロールなどに書いても外れない (`bulk_exempt_ignored: not_service_role`)
- 組の外の読み取りは今どおり数える。外した組の外を読めば初出 (low)、組の外が閾値を超えれば high
- `arata config check` で形を確かめる。書いた後の起動では、finding の代わりに info の行 (`bulk-exempt:`) が出る

見逃しとして引き受けること: そのロールの資格情報 (エージェントに発行された一時的な認証情報) が盗まれ、外した組だけを読まれると、secret_access は info の行しか出さない。
サービスのロールは principal_new_source の low (新しい送信元だけ) も出ないので、読むだけなら他のチェックにも出ない。材料は info の行の `ips` (送信元がいつもの出口と違う)。
arata の外の守りとして、次を勧める (人が判断する):

- 実行用のロールの権限を、その組の秘匿値だけに絞る (`Resource` に ARN を書く)。組の外を読もうとすれば access_denied に出る
- 可能なら、IAM の条件 (VPC エンドポイント経由なら `aws:SourceVpce` など) で、実行環境の外からの読み取りを止める

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high | なし | snooze・resolve |
| medium・low | あり | ack・snooze・resolve |
| info | なし | snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- snooze: 正規の読み手なら、導入から `baseline_days` が過ぎる日まで (平常帯がそろえば出なくなる)。移行作業・障害対応などの一時的な読み取りも期日を決めて
- ack: low・medium (初めて読む秘匿値) だけ。同じ主体が後で一括読み出しをすれば high で出直す
- resolve: 終わった 1 回の読み取り。また起きれば新規として報告される
- info (`bulk-exempt:` の行) は記録のための行。何もしなくてよい。送信元を確かめて終わりなら resolve
- high (一括読み出し) は ack できない。ack すると、後で本物の持ち出しが起きても二度と報告されない
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- 「値は CloudTrail に残らないから漏れていない」と考えない。読み取りが成功していれば値は相手に渡っている
- 承認済みの主体だからと軽く扱わない。調べる前に `secrets_access` の追加や ack を提案しない
- `bulk: exempt` を、人の主体・広い組・起動時でない読み取りに使わない。high を消すための書き換えとして提案しない (上の「確かめること」を満たしたときだけ)
- 指摘や要約に秘匿値の値を書かない・取りに行かない (調査で `get-secret-value` を実行しない)。LLM が approve / ack / ローテーションを実行しない

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats lucr-3-2023-09`: CloudShell から Secrets Manager の秘匿値をまとめて読む段階
