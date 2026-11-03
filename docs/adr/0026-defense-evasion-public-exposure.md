# 0026. 監査・検知の無効化 (`defense_evasion`) と公開設定の変更 (`public_exposure`) を、CloudTrail の注目イベントと要求の内容だけで判定する

- 日付: 2026-11-03
- 状態: 採用

## 背景

CloudTrail LookupEvents はすべての管理イベントを引いているが、注目イベント (events) として残し判定していたのはルート利用・IAM・AssumeRole・拒否などに限られていた。
侵入者が最初にやる「監査・検知を止める」操作 (CloudTrail の停止、GuardDuty の無効化、ログの削除など) と、情報の持ち出しの入口になる「外部に開く」設定変更
(セキュリティグループの 0.0.0.0/0、S3 の公開、RDS の PubliclyAccessible、スナップショットの公開共有など) を、追加の権限なしで日次に知らせたい。
設計書 7 章にあった未実装の `trail_tampering` / `network_exposure` はこの 2 つに置き換える。

## 決定

- daily のイベント型チェックを 2 つ足す。成功した呼び出し (errorCode なし) だけを見る (失敗は access_denied が扱う)
- 注目イベント (`cloudtrail.DefaultNotable`) には、2 つのチェックが見る操作だけを足す (全書き込みは足さない)。チェック側が操作の一覧
  (`checks.DefenseEvasionAPIs` / `PublicExposureAPIs`) を公開し、collector のテストで「すべて注目イベントに入る」ことを固定する
- collector の normalize で、該当する操作の requestParameters から判定に要る値だけを Data に取り出す (公開した ingress の組、公開と判定したステートメントの Sid と action、
  無効にした Public Access Block の項目など)。ポリシー全文やフィルタの条件は残さない
- 「弱めた」「開いた」かは要求の内容だけで判断する。CloudTrail には前の値が残らないので、弱めたか分からない変更 (UpdateTrail の SNS の変更、データイベントの追加、
  ARCHIVE でない GuardDuty のフィルタ) は報告しない。保持期間は前の値の代わりに下限 (`min_log_retention_days`、既定 90) と比べる
- defense_evasion の重大度: CloudTrail の停止・削除と、arata の監査対象のロググループ (cloudwatch-logs のソースの log_group から自動で作る) への削除・保持期間の短縮は critical、
  他は high。`tags: [deploy]` の承認済み主体なら 1 段下げる (info にはしない)
- public_exposure の重大度: 機微なポート (`sensitive_ports`) か全ポートの 0.0.0.0/0・::/0 への公開、S3・RDS・スナップショットの公開は high、他のポートは low、
  Lambda の Principal `*` は medium。deploy タグでも下げない。ModifySecurityGroupRules は記録に向き (ingress / egress) が無いので 1 段下げる
- S3 のバケットポリシーの「条件なし」は、送信元・組織・アカウントで絞る条件キー (aws:SourceIp・aws:SourceVpce・aws:PrincipalOrgID など) が無いこと。
  aws:SecureTransport だけの条件は公開とみなす (通信路を縛るだけで、誰でも読める)
- 証跡の宛先バケット (DeleteBucketPolicy / PutBucketLifecycle を報告する対象) は、設定の `trail_buckets` と保存済みの CreateTrail / UpdateTrail の宛先の和
- 読み取りロールの権限は増やさない (LookupEvents だけで足りる)

## 検討した選択肢

- **すべての書き込みを注目イベントにする**: 判定の自由度は上がるが、保存量が数十倍になり、events の保持 (90 日) と SQLite の大きさに響く。却下
- **今の状態を Describe して前の値と比べる**: 「短くした」「マルチリージョンを外した」を正確に判定できるが、各サービスの読み取り権限が増え、状態は weekly の posture が既に見ている。
  イベントの判定は要求の内容だけで行い、状態は posture / access_analyzer に任せる
- **public_exposure も deploy タグで下げる**: IaC の公開は意図したものが多いが、公開は毎回人が見るべきで、止めたいときは ack で足りる (重大度が上がれば再報告される)。却下
- **証跡の宛先を posture のスナップショットから取る**: posture の Data と指紋が変わり、週次でしか更新されない。設定と保存済みのイベントで足りるので見送った
- **ModifySecurityGroupRules を ingress と同じ重さにする**: 既定の egress (0.0.0.0/0 全ポート) の編集が high になる誤検知が出る。1 段下げて `direction_unknown` を残す

## 結果 (良い点・引き受けるコスト)

- 追加の権限なしで、侵入の初手と公開の事故を日次に知らせられる。注目イベントの追加で既存のチェックと principal_seen が変わらないことはテストで固定した
- 前の値が分からないので、弱めたか判断できない変更は見逃す (状態は posture が週次で拾う)。保持期間の判定は下限との比較なので、元から短いグループの再設定も報告する
- 新しい操作を足すときは、チェックの一覧・collector の注目イベント・取り出しの 3 か所を揃える (一覧と注目イベントのずれはテストが落とす)
