# principal_new_source: 既知の主体の初めての送信元・リージョン

## この指摘の意味

承認済み・ベースラインの主体 (IAM ユーザー、ロールのセッション) が、過去 `baseline_days` (既定 30 日) に無かった送信元 (/24・/48) から使われた、
または書き込みをしていなかったリージョンで書き込んだ (daily)。アクセスキーやセッションの漏洩の典型。new_principal は主体の初出しか見ないので、既知の主体の悪用はここで見る。

- 重大度: 新しい送信元だけ → low。新しい送信元からの書き込みが `min_writes` 以上、または新しいリージョンでの書き込み → medium。
  新しい送信元 + 同じ窓で access_denied (拒否の急増) も出ている → high
- allowlist の主体の項目に `dynamic_source: true` があれば (CI のランナーなど) low は出ない (medium 以上は出る)。
  AWS のサービスが引き受けるロール (Lambda・ECS のタスク・EC2 のインスタンスプロファイル。`service_assumed: true`) も同じ扱い。
  さらにサービスが引き受けるロールでは、実行環境がログの置き場所を作る書き込み (`logs:CreateLogGroup`・`logs:CreateLogStream`) を `min_writes` と比べる書き込みに数えない
  (差し引いた件数は `runtime_writes_excluded`。新しいリージョンの書き込みと access_denied との相関には効かない。IAM ユーザーとほかのロールでは数える)。
  allowlist の `source_ips` の内の送信元は新しい送信元にしない。導入直後 (CloudTrail を収集し終えた過去日が `min_baseline_days` 未満) は報告しない
- 材料は日ごとの「主体 × 送信元」「主体 × 書き込みのリージョン」の有無と件数。件数は時ごとの集計の和でその日の全件 (以前の版で集めた日は一部しか数えていないことがある)。国の判定はしない
- Key は主体の ARN。data: `principal`、`principal_kind`、`allowlist_status`、`reasons` (`new_source` / `new_source_writes` / `new_region` / `access_denied`)、
  `new_sources` (`prefix`・`events`・`writes`・`ips` (窓で観測した IP))、`new_regions` (`region`・`writes`)、`writes_from_new_sources`、
  `access_denied`、`active_in_baseline` (false なら過去 `baseline_days` は使われていなかった = 休眠していたキー)、`dynamic_source`、`service_assumed`、
  `runtime_writes_excluded` (差し引いた下回りの書き込みの件数。`writes_from_new_sources` と `writes` は差し引く前の件数)、`baseline_days_with_data`

## まず確かめること

1. `new_sources` の `ips` と `prefix` を、利用者の業務の場所 (オフィス・VPN・自宅回線・CI・SaaS) と照らす。
   `whois <IP>` で事業者を見る (クラウド事業者・VPS・Tor の出口などは要注意)。送信元の国は arata では判定しないので、必要なら人が調べる
2. `reasons` と `writes_from_new_sources`・`new_regions` を見る。ふだん使わないリージョンでの書き込み (インスタンスの作成など) は採掘の典型。
   `service_assumed: true` で `new_source_writes` が出たら、`writes_from_new_sources` から `runtime_writes_excluded` を引いた残りが、ログの置き場所を作る以外の書き込み。
   その中身を 4 の手順で並べる (関数のふだんの書き込みか、ふだん無い操作か)。以前の版で集めた日は下回りの書き込みも数えている (`runtime_writes_excluded` が無い)
3. `active_in_baseline: false` なら休眠していたキーの再利用。キーの持ち主・用途がまだ有効かを確かめる。
   `service_assumed: true` のロールが AWS の外 (利用者のオフィス・VPS など) の送信元から使われていれば、インスタンスメタデータなどから持ち出したセッションの疑い
   (GuardDuty の `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` も確かめる)
4. CloudTrail で新しい送信元からの操作を並べる: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<ユーザー名>`
   (ロールなら `AttributeKey=ResourceName,AttributeValue=<ロール名>`、キーが分かれば `AttributeKey=AccessKeyId`) を新しい送信元のリージョンでも引き、
   `sourceIPAddress` が新しい送信元のものについて、書き込み・IAM の変更・秘匿値の読み取り (secret_access)・`sts:GetCallerIdentity` から始まる列挙を探す
5. `arata review --format json` で同じ主体の access_denied・secret_access・iam_changes・defense_evasion を探す (組み合わせは侵害の可能性を上げる)
6. 主体の持ち主に、その時刻にその場所から使ったかを確かめる (旅行・新しい回線・新しい CI ランナー・VPN の出口の変更など)

## 判断の分かれ目

- **正規の可能性が高い**: 持ち主が場所・回線の変更を説明できる。CI・SaaS の主体で送信元が事業者の範囲内。
  新しいリージョンが計画された展開 (新しい環境の構築) と一致する。読み取りだけで、操作の中身もいつもと同じ
- **要対応**: high (拒否の急増と同時)。持ち主が説明できない。VPS・匿名化の出口・想定外の国からの利用。ふだん使わないリージョンでの計算資源の作成。
  IAM の変更 (ユーザー・アクセスキーの作成、ポリシーの付与)・秘匿値の読み取り・監査の無効化が新しい送信元から行われた。休眠していたキーの突然の利用

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (説明が付かない): IAM ユーザーならアクセスキーを無効化 (`aws iam update-access-key --user-name <ユーザー> --access-key-id <キー> --status Inactive`)、
   コンソールならパスワードの再設定と MFA の確認。ロールなら IAM コンソールの `Revoke active sessions` と、引き受けられる経路 (信頼ポリシー・引き受け元) の確認。
   新しいリージョンに作られた資源 (インスタンスなど) の確認と停止。漏洩したキーで作られた IAM ユーザー・アクセスキーの棚卸し
2. **承認・既知の送信元**: 持ち主の正規の利用なら、恒常的な拠点の送信元を allowlist の `source_ips` に人が書く (`note` に何の拠点か)。
   CI のように送信元が毎回変わる主体は、主体の項目に `dynamic_source: true` を人が書く (low が出なくなる。medium 以上は出る)
3. **片付け**: 片付けは下の「片付け」の節。一時的な出張・回線の切り替えなどは ack (low・medium) か snooze
4. **設定の修正**: 長期のアクセスキーをやめる (ロール・IAM Identity Center・OIDC に移す)、`aws:SourceIp` の条件で使える場所を絞る、使わないリージョンを SCP で拒否する

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high | なし | snooze・resolve |
| medium・low | あり | ack・snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- ack: low・medium だけ。一時的な出張・回線の切り替えなど。同じ主体が書き込みを増やす・拒否と重なれば重大度が上がって出直す
- snooze: 一時的な利用の終わりの日まで
- resolve: 終わった 1 回の利用。同じ送信元は 30 日の間に既知になる
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- 承認済みの主体 (`allowlist_status: approved`) だからと軽く扱わない。承認済みの主体の悪用を見るためのチェック
- 「送信元が AWS の IP だから正規」と決めつけない (攻撃者もクラウドの VPS を使う)。国・事業者だけで判断しない
- 調べる前に `dynamic_source: true` や広い `source_ips` を提案しない (漏洩を隠す)。LLM が approve / ack / キーの無効化を実行しない

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats wfx-loot-2026-11`: 作られたアクセスキーが、後で攻撃者の環境から使われる段階 (出典には無い想定)
- `arata help ai threats artex-2026-10`: 盗んだ資格情報を与えられたエージェントが、AWS で動き始める段階
- `arata help ai threats ghostaction-2026-10`: 盗んだアクセスキーが攻撃者の環境から使われる段階 (出典には無い想定)
- `arata help ai threats env-extortion-2024-08`: 漏れたキーが Tor・VPN から使われ、新しいリージョンに Lambda 関数を作った段階
- `arata help ai threats scarleteel-2023-02`: 盗んだロールの認証情報と、Lambda で見つけた IAM ユーザーのキーが外から使われた段階
- `arata help ai threats lucr-3-2023-09`: 乗っ取った人の主体が、攻撃者の送信元から使われる段階
