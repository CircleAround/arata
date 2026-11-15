# 0063. CloudTrail を trail の S3 への配信から読むソースの種類 (`cloudtrail-s3`) を足す

- 日付: 2026-11-15
- 状態: 提案

## 背景

`cloudtrail-lookup` は LookupEvents で管理イベントを全件引く。LookupEvents は 1 ページ最大 50 件、アカウント・リージョンごとに毎秒 2 回までなので、
1 日に引ける量は 1 リージョンあたり最大 864 万件ではあるが、実際は 1 ページ 0.5 秒で頭打ちになる。

ある利用者のアカウントの実測:

- 1 日に約 20.5 万件。ap-northeast-1 だけで 4,102 ページになり、収集だけで 34 分かかった
- GitHub Actions では読み取り専用ロールを役割の連鎖 (role chaining) で引き受けるので、資格情報は最長 1 時間で切れる。
  止まった後の追いつき (ADR 0038) で 2 日分を読むと、途中で資格情報が切れて失敗する。失敗したソースは前の位置のままなので、次の run も同じ量を読んで失敗し続ける

件数に比例して時間がかかる仕組みは、件数の多いアカウントほど効かない。多くのアカウントには既に trail があり、同じ記録を S3 に gzip の JSON で置いている。

## 公式文書で確かめたこと (2026-11-15 に読んだ)

| 項目 | 内容 | 出典 |
|---|---|---|
| キー | `<bucket>/[<prefix>/]AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/<file>.json.gz`。組織の trail は `AWSLogs/<o-id>/<account-id>/CloudTrail/...` | [1] |
| 種類ごとの段 | 管理・データイベントは `CloudTrail`、Insights は `CloudTrail-Insight`、ネットワークアクティビティは `CloudTrail-NetworkActivity`、データイベントの集約は `CloudTrail-Aggregated`、ダイジェストは `CloudTrail-Digest` | [1] [4] |
| ファイル名 | `<account>_CloudTrail_<region>_YYYYMMDDTHHmmZ_<16 文字>.json.gz`。時刻は**配信した時刻** (UTC、分まで) で、それより前の任意の時点の記録が入りうる。末尾の 16 文字に意味は無い | [2] |
| 中身 | gzip の JSON で `{"Records":[...]}`。1 ファイルは圧縮前で 50 MB まで | [2] [3] |
| 重複 | まれに同じイベントが重複して届く。多くは同じ `eventID` | [1] |
| 配信の頻度・遅れ | 「約 5 分ごと」に 1 時間に何度もファイルを書く。API の呼び出しから平均で約 5 分以内に配信 (保証ではない)。「15 分」の記述は読んだ範囲には無かった | [1] [5] |
| ダイジェスト | 1 時間ごとに、直前 1 時間に配信したファイルの名前と SHA-256 を持つ。前のダイジェストの署名を含む鎖。活動が無くても `logFiles: []` が届く。遅れたときは `_backfill` が届く | [4] [6] |
| 読む権限 | 他のアカウントにログを読ませる公式の例は `s3:Get*`・`s3:List*` を、`arn:aws:s3:::<bucket>/<prefix>/AWSLogs/<account-id>/*` とバケット自身に許す。ListObjectsV2 には `s3:ListBucket` が要り、1 回 1,000 キーを辞書順に返す | [7] [8] |
| KMS | コンソールで作った trail は既定で SSE-KMS。S3 の読み取りに加えてキーポリシーで復号を許す必要がある (読む主体ごとに `kms:Decrypt`、条件 `"Null": {"kms:EncryptionContext:aws:cloudtrail:arn": "false"}`)。別アカウントの主体ならキーポリシーと主体の IAM ポリシーの両方が要る | [9] [10] |
| LookupEvents | 返すのは管理イベントと (`EventCategory=insight` のときだけ) Insights。直近 90 日、1 リージョンずつ、1 回最大 50 件、アカウント・リージョンごとに毎秒 2 回 | [11] [3] |
| CloudTrailEvent | LookupEvents の `CloudTrailEvent` は「イベントを表す JSON 文字列」で、項目の意味は S3 の記録と同じ record contents のページを参照するよう書かれている。`eventContext` はどちらにも入らない | [12] [13] [14] |
| data event | trail は既定では記録しない。記録するには種類 (`AWS::S3::Object` など) を足し、追加の料金がかかる | [15] |

[1] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html
[2] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html
[3] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html
[4] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html
[5] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html
[6] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
[7] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-sharing-logs.html
[8] https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
[9] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
[10] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html
[11] https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
[12] https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Event.html
[13] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-cli.html
[14] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
[15] https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html

## LookupEvents と S3 の記録の違いと、今のチェックが要る項目

今の collector (`internal/collect/cloudtrail`) は `CloudTrailEvent` の JSON を `rawEvent` に読み、使うのは次の項目だけ:
`eventID`・`eventTime` (LookupEvents の外側の `EventId`・`EventTime` を優先し、無ければ JSON)・`eventSource`・`eventName`・`awsRegion`・`sourceIPAddress`・
`userAgent`・`errorCode`・`readOnly`・`userIdentity` (type・arn・accountId・invokedBy・userName・identityProvider・sessionContext)・
`requestParameters`・`responseElements`・`resources`。S3 の記録は同じ record contents の定義なので、**どれも S3 の記録にある** (送信元の IP・errorCode を含む)。
外側の `EventId`・`EventTime` が無い分は、今ある JSON への代替がそのまま効く。

| | LookupEvents | trail の S3 |
|---|---|---|
| 何が入るか | 管理イベントの全部 (読み・書き)。trail の設定に依らない | **trail のイベントセレクタで選んだものだけ**。書き込みだけの trail・KMS / RDS Data API の除外があり得る |
| data event | 返さない | 設定していれば同じ `CloudTrail/` の段に混ざる (除く必要がある) |
| Insights | `EventCategory=insight` のときだけ | 別の段 (`CloudTrail-Insight/`)。読まなければ混ざらない |
| 範囲 | 直近 90 日 (trail が無くても) | trail を作ってからで、バケットのライフサイクルの分だけ |
| 遅れ | 通常 5〜15 分 (設計書 3 章の見込み) | 平均約 5 分 (保証なし)。ファイルの時刻は配信時刻 |
| 速さ | 50 件 / 0.5 秒 | ファイル単位。約 5 分ごと × リージョン数のファイル。件数にほぼ依らない |
| 重複 | 同じイベントは複数リージョンに見えうる (今も event_id で除く) | まれに重複配信 (多くは同じ eventID) |

違いがチェックに効くのは「trail が何を記録しているか」だけ。今のチェックが前提にしている管理イベントのうち、

- 読み取りのイベント (`GetSecretValue`・`ListUsers` など) は `secret_access`・`new_principal`・`principal_new_source` が使う。書き込みだけの trail では欠ける
- KMS のイベント (`ScheduleKeyDeletion`・`DisableKey`) は `defense_evasion` が使う。KMS を除いた trail では欠ける

ので、doctor が trail の設定 (`cloudtrail:GetEventSelectors`) を読み、「読み取りも書き込みも記録し、管理イベントの種類を除いていない」ことを確かめる。

## 決定

### ソースの種類と設定

新しいソースの種類 `cloudtrail-s3` を足す。出すレコードは `cloudtrail-lookup` と同じ (`trail_event`・`principal_seen`・主体の活動の日次集計)。
正規化は今の `normalize` を共有し、入口 (`types.Event` か S3 の記録か) だけを分ける。

```yaml
sources:
  - id: trail
    kind: cloudtrail-s3
    bucket: example-trail-logs          # trail の配信先のバケット
    prefix: ""                          # trail の S3 キーの接頭辞 (無ければ空)
    organization_id: ""                 # 組織の trail なら o-xxxxxxxxxx (キーに入る)
    account_id: "123456789012"          # 読むアカウント。省略すると監査する側のアカウント (ADR 0045)
    regions: [ap-northeast-1, us-east-1]
    ingest_delay: 15m
```

- 決定: **同じ run が `cloudtrail-lookup` と `cloudtrail-s3` の両方を必要とする設定は `config check` で止める**。events は event_id で重複しないが、
  `principal_ips.count` と主体の活動の集計は二重に足される。移るときは `cloudtrail-lookup` をプロファイルから外す (下の「互換」)
- 決定: `regions` は明示する (暗黙の既定を持たない。ADR 0014)。`config init` は `cloudtrail-lookup` の雛形と同じリージョンをコメントで示す

### 読み方

- 1 リージョンにつき、`AWSLogs/[<o-id>/]<account-id>/CloudTrail/<region>/YYYY/MM/DD/` を ListObjectsV2 で引く。日のプレフィックスは**配信時刻**の日なので、
  窓の始まり − `ingest_delay` の日から、窓の終わりの日までを引く (日をまたいで配信された記録は、次の日のプレフィックスに入る)
- ファイル名の配信時刻 (`YYYYMMDDTHHmmZ`) で絞る: 配信時刻が `[窓の始まり − ingest_delay, 窓の終わり + 配信の余裕)` のファイルを読む。配信の余裕は `ingest_delay` と同じ値
  (窓の終わりの直前に起きて、後で配信される分を、次の run ではなくこの run で拾うため。拾えなかった分は次の run の再走査が拾う)
- 記録の `eventTime` で窓に入れるかを決める (今と同じ。`[ScanFrom, From)` は遅れて届いたものとして ADR 0013 のとおりに扱う)
- 決定: **`eventCategory` が `Management` の記録だけを使う**。data event・ネットワークアクティビティは捨てる (今のチェックは使わない。混ぜると `principal_seen` が膨らむ)。
  読む段は `CloudTrail/` だけで、`CloudTrail-Insight/`・`CloudTrail-Digest/` などは引かない
- 同じ `eventID` は 1 回だけ数える (今の `doneIDs` と同じ。重複配信にも効く)
- 読むファイルの数・バイト数・記録の数・捨てた data event の数を INFO と stats に残す。gzip を解いた大きさの上限 (公式の 50 MB に余裕を足した値) を超えたファイルは
  読まずに ERROR にする (信用できない入力。ADR 0037)
- 決定: S3 の記録は信用できない入力として扱い、JSON の読み取りと `{"Records":[...]}` の取り出しにファズテストを足す (ADR 0041)。
  性質は「パニックしない」に加え、「data event を trail_event・principal_seen にしない」「窓の外の eventTime を窓の中の件数に数えない」を書く

### 権限 (`deploy/iam/readonly-role.yaml`)

パラメータを 3 つ足す。どれも既定は空で、空なら文を足さない (今の利用者の更新でロールは変わらない)。

| パラメータ | 内容 |
|---|---|
| `CloudTrailBucketName` | trail の配信先のバケットの名前。空なら S3 の文を足さない |
| `CloudTrailBucketPrefix` | trail の S3 キーの接頭辞 (無ければ空) |
| `CloudTrailKmsKeyArn` | trail のファイルを暗号化している KMS キーの ARN。空なら KMS の文を足さない |

足す文 (概略):

```yaml
- Sid: CloudTrailS3List
  Effect: Allow
  Action: s3:ListBucket
  Resource: arn:aws:s3:::<CloudTrailBucketName>
  Condition:
    StringLike:
      s3:prefix: <prefix>AWSLogs/*            # 読ませるのは AWSLogs の下だけ
- Sid: CloudTrailS3Read
  Effect: Allow
  Action: s3:GetObject
  Resource: arn:aws:s3:::<CloudTrailBucketName>/<prefix>AWSLogs/*
- Sid: CloudTrailKmsDecrypt
  Effect: Allow
  Action: kms:Decrypt
  Resource: <CloudTrailKmsKeyArn>
  Condition:
    'Null':
      kms:EncryptionContext:aws:cloudtrail:arn: 'false'
- Sid: CloudTrailSelectors                   # doctor が trail の記録の範囲を確かめる
  Effect: Allow
  Action: cloudtrail:GetEventSelectors
  Resource: '*'
```

- 決定: `s3:Get*` / `s3:List*` (公式の例) ではなく、`s3:GetObject` と `s3:ListBucket` だけにする。読み取り専用 (設計書 8 章) を保ち、ACL やバケットの設定は読ませない
- 決定: アカウント ID まではキーに含めない (`AWSLogs/*`)。組織の trail のバケットは他のアカウントの記録も持つので、絞りたい利用者は
  `CloudTrailBucketPrefix` に `AWSLogs/<o-id>/<account-id>/` までを書けるようにする (その場合、上の Resource と条件の `AWSLogs` を前に含めない形にする。実装の PR で型を決める)
- 組織の trail のバケットは、多くはログ用の別アカウントにある。その場合はロールのポリシーだけでは読めず、**バケットポリシーとキーポリシーで読み取り専用ロールを許す**
  必要がある (ログ用のアカウント側の作業)。`arata config role-params` は上のパラメータを設定から作り、ログ用のアカウントに貼る文の雛形を `--format json` で出す
- doctor: 読み取り専用ロールで `ListObjectsV2` (1 件)・`GetObject` (直近の 1 ファイル)・`GetEventSelectors` を試し、拒否されたら足りない action と「どこの
  ポリシー (ロール・バケット・キー) か」の候補を出す。trail が書き込みだけ・管理イベントの種類を除いている・マルチリージョンでなく `regions` を覆わない、なら WARN

### 費用と時間の見込み

- 1 アカウント・1 リージョンで 1 日約 288 ファイル (約 5 分ごと。[5] からの推測。件数が多い時間は増える)。リージョン 17 で約 5,000 GET と、日・リージョンごとに数回の LIST
- 20 万件 / 日のアカウントでも、読むのはファイルの数に比例する回数の GET なので、収集は数分以内に収まる見込み (実測は試験環境と利用者のアカウントで確かめる)
- S3 の GET・LIST の単価、利用者側のバケットのデータ転送の扱い (同じリージョンか) は、実装の PR で公式の料金表を読んで書く (未確認)

## 互換

- 新しい種類なので、既存の設定・ストアは変わらない。ストアの移行は無い (同じレコードの種類を出す)
- 移るとき: `cloudtrail-lookup` から `cloudtrail-s3` へは、両方を同じ run で使えないので、設定の 1 回の変更で入れ替える。ソースの ID が変わるので
  ADR 0038 の位置は新しいソースには無く、窓の始まりから読む (通常の run と同じ)。主体 (`principals`)・`principal_ips` は ARN と IP の単位なので引き継がれる。
  主体の活動の日次集計は `source` を持ち、チェックは読むときにソースをまたいで足す (`internal/checks/baseline.go` の `loadSeries`)。入れ替えた日は両方のソースの行が
  足されて、その日の件数だけが多めになる。判定は「その日に有ったか」と下限値に使うので、新しい送信元を見落とす向きには働かない。平常帯は入れ替えの前の日の分を引き継ぐ
- `cloudtrail-unused-regions` (ADR 0032) は LookupEvents のまま残す。マルチリージョンの trail なら同じバケットの他のリージョンのプレフィックスから読めるが、
  ふだん使わないリージョンは件数が少なく LookupEvents で困っていないので、この ADR では変えない (今後の候補)
- `init` のベースライン (既定 7 日) は、trail とバケットのライフサイクルが 7 日以上を残していれば同じく取れる。足りなければ取れた分だけで、doctor が先に知らせる

## 検討した選択肢

- **LookupEvents の並びを工夫する (リージョンを並行に引く)**: 採らない。上限はアカウント・リージョンごとなので、ap-northeast-1 の 4,102 ページは縮まない
- **LookupEvents を `ReadOnly=false` などで絞る**: 採らない。`secret_access`・`new_principal`・`principal_new_source` は読み取りのイベントを使う。絞れる属性も 1 つだけ [11]
- **CloudTrail Lake**: 採らない。取り込み量の課金と、クエリのスキャン量の課金がかかり、利用者側に新しい資源を作らせる ([cloudtrail-lake-manage-costs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-manage-costs.html))。arata の側でも SQL の方言が増える
- **trail を CloudWatch Logs に配信させ、Logs Insights で読む**: 採らない。全イベントを Logs Insights で読むとスキャン量の課金が件数に比例し、ADR 0065 で減らそうとしている費用と同じ種類の費用が増える。
  256 KB を超えるイベントは送られない ([send-cloudtrail-events-to-cloudwatch-logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html))
- **S3 の通知 (EventBridge・SQS) で新しいファイルを受け取る**: 採らない (今回は)。利用者側に資源と書き込みの権限が要り、arata は定時に読むだけの方が単純。ADR 0064 の短い間隔の収集で足りる
- **Athena で S3 を引く**: 採らない。ADR 0046 の比較と同じ理由 (利用者側のテーブル定義と、クエリ結果を書くバケットへの書き込みが要る)
- **ダイジェストでファイルの完全性を確かめる**: この ADR では採らないが、今後の候補として残す。trail のファイルの削除・改ざんは監査・検知の無効化 (`defense_evasion`) の一種で、
  ダイジェストの鎖の欠けで見える。`cloudtrail:ListPublicKeys` と署名の検証 (標準ライブラリの RSA と SHA-256 で書ける) が要る

## 結果

- 良い点: 収集の時間が件数にほぼ依らなくなり、役割の連鎖の 1 時間の中で数日分の追いつきができる見込み。data event を記録している trail でも、管理イベントだけを使う
- 引き受けるコスト: 利用者側の作業が増える (バケットポリシー・キーポリシー。特に組織の trail で別アカウントのバケット)。記録の範囲が trail の設定に依るので、doctor の検査が要る
- 引き受けるコスト: 信用できない入力の入口が 1 つ増える (S3 のファイル)。ファズテストと大きさの上限で受ける

## 手間の見積もり

- collector (List・Get・gzip・JSON・配信時刻での絞り込み・data event の除外) とテスト (S3 は `httptest` の偽物): 2 日
- ファズテスト・`config check` (両方の種類の併用を止める)・`config init` の雛形・`help ai` の文書とゴールデン: 1 日
- 読み取り専用ロールのパラメータ・`role-params`・`readonly_role_test`・sandbox の CDK (trail とバケット): 1 日
- doctor (権限と trail の設定の確認): 1 日
- 合計 約 5 日。利用者の環境での確認 (バケットポリシー・キーポリシーの手順) は別

## 未確認の点

- 「15 分」の遅れの記述の出典 (FAQ・SLA)。`ingest_delay` の既定は今の `cloudtrail-lookup` と同じ 15m にする予定
- LookupEvents の `CloudTrailEvent` と S3 の記録がバイト単位で同じ JSON か (項目の定義が共通であることまでは確かめた)。試験環境で同じ eventID を両方から引いて突き合わせる
- `eventCategory` の値の綴り (`Management`・`Data`・`NetworkActivity`) を record contents のページで確かめる
- `GetEventSelectors` の応答 (基本のセレクタと高度なセレクタの両方) から「管理イベントの読み書きを全部」「除いた種類」を読む方法
- Insights のファイル名の形式 (読まないので実装には影響しない)
- S3 の GET・LIST の単価と、バケットが別リージョンにあるときの転送料金
