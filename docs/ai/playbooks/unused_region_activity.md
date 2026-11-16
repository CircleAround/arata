# unused_region_activity: ふだん使わないリージョンでの書き込み

## この指摘の意味

アカウントで有効なリージョンのうち、`cloudtrail-lookup` の `regions` (ふだん使うリージョン) に無いリージョンで、AWS のサービス以外の主体による書き込みがあった (daily)。
漏洩した認証情報の悪用 (仮想通貨の採掘のためのインスタンス作成など) は、利用者が見ないリージョンで行われることが多い。
対象のリージョンは `cloudtrail-unused-regions` のソースが毎回 `account:ListRegions` (opt-in の状態) から決める。

- 重大度: 成功した書き込みは high、計算資源の作成 (`checks.unused_region_activity.compute_apis`。`ec2:RunInstances`・`lambda:CreateFunction`・`ecs:RunTask` など) を含めば critical。
  計算資源の作成の試行 (拒否など、失敗したもの) は medium。それ以外の失敗は報告しない。allowlist で `tags: [deploy]` の承認済み主体なら 1 段下げる (info にはしない)
- AWS のサービスの主体と `ignore_event_sources` (IAM・STS などのグローバルサービス。記録は us-east-1) は数えない
- Key は `<リージョン>|<主体>`。同じリージョン・主体で操作の種類が増えるか重大度が上がれば changed
- data: `region`、`principal`、`principal_kind`、`apis` (`<サービス>:<操作>`)、`compute_apis`、`failed` (失敗した件数)、`known_deploy_principal`、
  `service_linked_role` / `service_linked_service` (主体がサービスリンクロールのとき。そのロールを使う AWS のサービス名)、
  `count`、`event_names`、`ips`、`first_time`、`last_time`
- 主体がサービスリンクロール (`role/aws-service-role/<サービス>/…`。見出しに「サービスリンクロール」と出る) の書き込みは、利用者が機能を有効にした結果として
  AWS のサービスが行うことが多い (人の操作に付随する)。重大度は下げない (有効にしたのが正規の人かは別に確かめる)

## まず確かめること

1. 今も動いている資源があるか (最優先。採掘なら時間ごとに費用が増える):
   - EC2: `aws ec2 describe-instances --region <リージョン> --filters Name=instance-state-name,Values=pending,running`、スポットは `aws ec2 describe-spot-instance-requests --region <リージョン>`
   - Lambda: `aws lambda list-functions --region <リージョン>`、ECS / EKS: `aws ecs list-clusters`・`aws eks list-clusters` (`--region <リージョン>`)
   - 他の書き込み (`apis`) の資源: セキュリティグループ・キーペア・IAM ロールの作成など、後で使う足場が残っていないか
2. 中身を CloudTrail で見る: `aws cloudtrail lookup-events --region <リージョン> --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --start-time <first_time> --end-time <last_time>`
   (インスタンスの種類・台数・使った AMI・キーペア)
3. 主体の他の活動: `arata review --format json` で同じ主体の principal_new_source (初めての送信元)・access_denied・iam_changes・new_principal を探す。
   同じ時間帯に初めての送信元から使われていれば、認証情報の漏洩の疑いが強い
4. サービスリンクロール (`service_linked_role`) のとき: 同じ時間帯 (`first_time` の前後) に、人がその機能 (`service_linked_service` のサービス) を有効にしたかを確かめる。
   ふだん使うリージョンの CloudTrail で、そのサービスの設定の操作 (有効化・作成) と `iam:CreateServiceLinkedRole` を探し、誰が・どこから行ったかを見る。
   正規の人の作業なら付随する書き込みとして扱い、有効にした人が見つからない・既知外の主体なら、その主体の操作として下の「要対応」で判断する
5. 費用: cost_anomaly の指摘、Cost Explorer の日ごとの費用 (リージョン別)
6. 作業の記録 (検証・移行・DR の準備など) と、利用者の事情 (context_file) に説明があるか

## 判断の分かれ目

- **正規の可能性が高い**: 既知のデプロイ主体 (StackSets・Control Tower などの全リージョンへの配布) で、対応する IaC の変更がある。
  計画したリージョンの追加 (検証・DR) で作業の記録がある。この場合は `cloudtrail-lookup` の `regions` に足すのが本来の形。
  サービスリンクロールの書き込みで、同じ時間帯に正規の人がその機能を有効にしている
- **要対応**: 計算資源の作成 (特に GPU や大きなインスタンス、多数のスポット)、人の主体や既知外の主体、作業の記録が無い、
  同じ主体の初めての送信元・拒否の急増・IAM の変更と同じ時間帯、opt-in したばかりのリージョン

## 対処の選択肢

緊急度の順。封じ込め・資源の停止・設定の修正は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): 主体の認証情報を止める (アクセスキーの無効化、ロールの `Revoke sessions`)。作られた資源を止める (インスタンスの停止・スポットの取消し・関数の削除)。
   証拠のために消す前に、資源の ID・AMI・ユーザーデータを記録する。漏洩が疑わしければ AWS サポートに連絡する
2. **承認**: 正規のデプロイ主体なら、allowlist.yaml の principals にその主体を `tags: [deploy]` で人が書く (PR で。重大度が 1 段下がるが、報告は続く)。`arata approve` はこのチェックの finding を受け付けない
3. **expected_denied**: 対象外 (試行の medium は拒否された計算資源の作成だけ)
4. **片付け**: 片付けは下の「片付け」の節。作業として確かめた 1 回の書き込みは resolve
5. **設定の修正**: そのリージョンを今後も使うなら `cloudtrail-lookup` の `regions` に足す (以後はこのチェックの対象外になり、他のチェックが見る)。
   使わないなら SCP の `aws:RequestedRegion` でリージョンを拒否する、opt-in したリージョンを無効に戻す。
   計算資源の一覧が合わなければ `checks.unused_region_activity.compute_apis` を見直す

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| critical・high | なし | snooze・resolve |
| medium | あり | ack・snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- ack: medium (拒否された計算資源の作成の試行) だけ。同じ主体がそのリージョンで作成に成功すれば重大度が上がって出直す
- resolve: 作業として確かめた 1 回の書き込み (作った資源を確かめた・消した)。また起きれば新規として報告される
- snooze: 作業が続く間だけ
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- 「使っていないリージョンだから影響は無い」と判断しない。費用と足場はどのリージョンでも同じ
- 資源の停止や削除を確かめずに ack しない。LLM が資源を止めない・消さない (提案まで)
- 正規の利用を見つけたとき、`compute_apis` や `ignore_event_sources` から外して黙らせない (`regions` に足すか ack する)

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats ghostaction-2026-10`: 盗んだアクセスキーで、ふだん使わないリージョンに資源を作る段階 (出典には無い想定)
- `arata help ai threats env-extortion-2024-08`: Lambda 関数を有効な全リージョンへ配った段階
