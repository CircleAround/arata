# scarleteel-2023-02: コンテナからインスタンスのロールの認証情報を盗み、CloudTrail を止めて、データと別アカウントのキーを取る (SCARLETEEL)

## 概要

- 公開日: 2023-02-28
- AWS の上で自前で動かしていた Kubernetes の、公開されたサービスから入られた事例。Sysdig が被害の環境の調査として報告した
- コンテナで採掘を動かしつつ、インスタンスメタデータ (IMDSv1) からワーカーのロールの一時的な認証情報を取り、AWS の API を呼んだ
- Lambda 関数のコードと環境変数から IAM ユーザーのキーを見つけ、S3 から 1 TB を超えるデータを読み、CloudTrail の記録の一部を止めた
- S3 にあった Terraform の状態ファイルから別の AWS アカウントのキーを得て移ろうとしたが、権限が無くほぼすべて失敗した

## 出典

- Sysdig "SCARLETEEL: Operation leveraging Terraform, Kubernetes, and AWS for data theft" (2023-02-28): https://sysdig.com/blog/cloud-breach-terraform-data-theft/

## 攻撃の段階と arata で見えるもの

| 攻撃の段階 | 出典の書き方 | arata のチェック | 記録 | 出るもの |
|---|---|---|---|---|
| 初期の侵入: 公開されたサービスからコンテナに入り、採掘を動かす | 観測 | — | 無し | 見えない (コンテナの中) |
| 認証情報の入手: インスタンスメタデータからロールの一時的な認証情報を取る | 観測 | — | 無し | 見えない (メタデータへのアクセスは CloudTrail に残らない) |
| AWS での利用: 盗んだロールの認証情報で、Lambda と S3 を列挙する | 観測 | `principal_new_source`, `guardduty_findings` | CloudTrail: そのロールの API 呼び出し。GuardDuty の検出 | インスタンスのロールは新しい送信元だけ (low) では出ない。新しい送信元からの書き込みで medium、拒否の急増が重なれば high。GuardDuty が検出を出していれば weekly に拾う (7 以上は high。検出が出たかは出典に無い) |
| 永続化の試行: ユーザーとグループを作る、既存のユーザーにアクセスキーを作る (すべて拒否) | 観測 | `iam_changes`, `access_denied` | CloudTrail: 拒否された `CreateUser`・`CreateAccessKey` | iam_changes が「IAM 変更の試行 (拒否)」として medium。拒否の種類が平常帯を超えれば access_denied が medium か high |
| 認証情報の入手: Lambda 関数のコードと環境変数から IAM ユーザーのキーを見つけて使う | 観測 | `principal_new_source` | CloudTrail: その IAM ユーザーの API 呼び出し | 既知の IAM ユーザーが新しい送信元から使われて low、書き込みがあれば medium |
| 検知の無効化: CloudTrail の記録を止める (一部が成功) | 観測 | `defense_evasion` | CloudTrail: `StopLogging` | critical |
| 持ち出し: S3 から 1 TB を超えるデータと Terraform の状態ファイルを読む | 観測 | — | S3 のデータイベント | 見えない (arata が読むのは管理イベント。出典の環境でもこの記録は無かった) |
| 横への移動: 状態ファイルにあった別アカウントのキーを使う (`GetCallerIdentity` 以外は失敗) | 観測 | `access_denied`, `principal_new_source` | CloudTrail (その別アカウント): 拒否された呼び出し | そのアカウントを監査していれば、拒否の種類が平常帯を超えて medium か high、新しい送信元と重なって principal_new_source が high |

## arata では見えないもの

- **コンテナと Kubernetes の中** (侵入、採掘、メタデータへのアクセス): arata はホストやコンテナの記録を読まない
- **S3 のオブジェクトの読み出し**: データイベントは arata の読む記録に無い。1 TB の読み出しも、状態ファイルの取得も出ない
- **読み取りだけの列挙が成功している間**: Lambda のコードや環境変数の取得は管理イベントに残るが、読み取りを指摘するチェックは無い。
  盗まれたロールがインスタンスのロールなら、新しい送信元だけでは出ない (AWS のサービスが引き受けるロールは送信元が変わるため)
- **CloudTrail を止めた後の操作**: `StopLogging` は出るが、止まっていた間の操作は記録が無い
- 監査していないアカウントでの動き (別アカウントへの移動は、そのアカウントの記録にしか無い)

## 予定している改善

無し。
