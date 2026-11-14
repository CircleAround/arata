# secret_access: 秘匿値の読み取りの異常

## この指摘の意味

主体が秘匿値 (Secrets Manager のシークレット、SSM の SecureString を復号した読み取り) を、ふだんと違うやり方で読んだ (daily)。
対象は成功した `GetSecretValue` / `BatchGetSecretValue` と、`withDecryption=true` の `GetParameter` / `GetParameters` / `GetParametersByPath`。失敗は access_denied が扱う。

- 初めて読む秘匿値: その主体が過去 `baseline_days` (既定 14 日) に読んでいない秘匿値を読んだ → low。その主体が秘匿値を読むこと自体が初めてなら medium
- 一括読み出し: 窓 (1 日) に読んだ異なる秘匿値の数が `max(min_distinct, その主体の日ごとの中央値 × factor)` を超えた → high (持ち出しの兆候)。
  `GetParametersByPath` はパス単位で 1 と数える (再帰的に読むと 1 回で多数が読める。`paths` に `(recursive)` が付く)
- allowlist の `secrets_access` に書いた「主体 × 秘匿値」は初出に数えない (一括読み出しの数には数える)。
  導入直後 (CloudTrail を収集し終えた過去日が `min_baseline_days` 未満) は初出を報告しない (一括読み出しは報告する)
- 秘匿値の値は CloudTrail に入らないので arata も持たない。名前 / ARN だけ
- Key は主体の ARN。data: `principal`、`principal_kind`、`allowlist_status`、`distinct_secrets`、`secrets` (最大 20。`secretsmanager:<名前か ARN>` / `ssm:<名前>` / `ssm-path:<パス>`)、
  `paths`、`bulk`、`threshold`、`baseline_median_distinct`、`new_secrets` (最大 20)、`new_secret_count`、`first_reader`、`secrets_access_matched`、`count`、`ips`、`event_names`

## まず確かめること

1. `bulk` と `distinct_secrets`・`threshold` を見る。ふだん数個しか読まない主体が数十個を読んだのは持ち出しの典型。`paths` の `(recursive)` で上位のパス (`/` など) を読んでいないか
2. `new_secrets` の名前を見る。主体の用途 (どのアプリ・どの環境) と合うか。本番のアプリのロールが別の環境・別のアプリの秘匿値を読むのは要注意
3. `ips` を見る。ふだんの送信元 (アプリの実行環境・NAT・オフィス) と違うなら、同じ主体の principal_new_source を探す
4. `arata review --format json` で同じ主体の principal_new_source・access_denied (特に `secretsmanager:ListSecrets`・`ssm:DescribeParameters` の拒否)・iam_changes を探す
5. CloudTrail で読み取りの前後を並べる: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue`
   (ssm は `GetParameter` / `GetParametersByPath`) を引き、主体・送信元・`userAgent` を見る。直前の `ListSecrets` / `DescribeParameters` (秘匿値の一覧の取得) は探索の兆候
6. デプロイ・アプリの変更 (新しい設定値の追加、起動時に読む値の変更) と時刻が合うかを確かめる

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
   広い glob (`*`) は初出を隠すので勧めない
3. **ack / snooze**: 移行作業・障害対応などの一時的な読み取りは ack / snooze (重大度が上がれば再報告される)。同じ秘匿値は 14 日の間に既知になる
4. **設定の修正**: 主体の権限を必要な秘匿値に絞る (`Resource` に ARN・パスを書く。`GetParametersByPath` の再帰を上位のパスに許さない)、
   リソースポリシー・KMS キーのポリシーで読める主体を絞る、人が本番の秘匿値を直接読む運用をやめる

## やってはいけないこと

- 「値は CloudTrail に残らないから漏れていない」と考えない。読み取りが成功していれば値は相手に渡っている
- 承認済みの主体だからと軽く扱わない。調べる前に `secrets_access` の追加や ack を提案しない
- 指摘や要約に秘匿値の値を書かない・取りに行かない (調査で `get-secret-value` を実行しない)。LLM が approve / ack / ローテーションを実行しない

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats lucr-3-2023-09`: CloudShell から Secrets Manager の秘匿値をまとめて読む段階
