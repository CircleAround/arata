# 0046. ALB のアクセスログは CloudWatch Logs への配信 (plain) を既存の `alb_access` で読み、S3 を直接読む案は次の段にする

- 日付: 2026-11-13
- 状態: 提案

実装していない。この ADR は案の比較と推奨で、採用を決めるときに状態を変える。仕様の案は設計書 2-3 章。
事実は公式の文書で確かめ、末尾の「出典」の番号を付けた。確かめられなかったものは「未確認」、見積もりは「推測」と書く。

## 背景

`http_access` を使うチェック (`login_bruteforce`・`probe_paths`・`endpoint_abuse`) は、今は CloudWatch Logs のソース
(Logs Insights の集計。ADR 0006・0009・0031) からしか動かない。nginx のログを CloudWatch Logs に送っていない利用者では、
これらのチェックが「設定不足」で skip されたままになる。

ALB のアクセスログは 1 リクエスト 1 行で、送信元 IP・メソッド・URL・ステータス・User-Agent・処理時間が同じ行に揃う [1]。
アプリにもサーバーにも手を入れずに有効にできる。一方、アプリの標準のログは 1 リクエストが複数行に分かれて
IP とステータスが同じ行に無いことがあり (Rails の標準のログなど)、`regex` プロファイルでは拾いきれない。

ただし、従来のアクセスログ (ALB の属性で有効にするもの。以下「従来のログ」) の出力先は S3 だけである [1][2]。

### 確かめた事実 (ALB の従来のログ)

- ノードごとに 5 分おきにファイルを出す。配信は結果整合 (eventually consistent) で、遅れの上限は書かれていない。
  同じ期間に複数のファイルが出ることがある。記録はベストエフォートで、全リクエストの完全な記録ではない [1]
- キーは `<bucket>[/<prefix>]/AWSLogs/<アカウント ID>/elasticloadbalancing/<region>/<yyyy>/<mm>/<dd>/<アカウント ID>_elasticloadbalancing_<region>_app.<LB の ID>_<end-time>_<IP>_<乱数>.log.gz`。
  `yyyy/mm/dd` は**配信された日**、`end-time` は 5 分の区間の終わり (UTC。`20140215T2340Z` なら 23:35〜23:40 のリクエスト)。gzip で圧縮される [1]
- 行は空白区切り。先頭から `type time elb client:port target:port request_processing_time target_processing_time response_processing_time elb_status_code target_status_code received_bytes sent_bytes "request" "user_agent" ...`。
  `"request"` は `メソッド scheme://host:port/path?query HTTP の版` で、クライアントが送った URL をそのまま残す。
  新しい項目は**行の末尾**に足される (今は 36 項目) [1]
- `client:port` は、ALB の前にプロキシがあるとプロキシの IP になる [1]。X-Forwarded-For は記録されない (項目の一覧に無い)
- ターゲットに届かなかったリクエスト (不正なリクエスト、正常なターゲットが無いとき) も記録される。WAF が止めたリクエストは
  `elb_status_code` が 403 (カスタムの応答コードならその値) で残る。WebSocket は接続が閉じたときに 1 行だけ書かれる [1]
- バケットは ALB と同じリージョン。別のアカウントのバケットでもよい。**サーバー側の暗号化は SSE-S3 だけが使える** (SSE-KMS のバケットには配信できない)。
  バケットポリシーで `logdelivery.elasticloadbalancing.amazonaws.com` に `s3:PutObject` を許す (2022 年 8 月より前からあるリージョンでは、
  リージョンごとの ELB のアカウントを許す古い書き方も使える) [2]
- 課金は S3 の保管だけで、ALB から S3 への転送には課金されない [1]

### 既存の形式プロファイル `alb_access` が前提にしていること

`alb_access` は **cloudwatch-logs のソースの形式プロファイル**で、S3 は読まない (`internal/collect/cwlogs/profile.go` の `albParse`)。
ロググループの `@message` が従来のログの 1 行そのままであることを前提に、Insights の `parse` で先頭 14 項目から
`ip` (`client:port` の IP)・`duration` (`target_processing_time`)・`status` (`elb_status_code`)・`method`・`path` (URL からクエリを除いたパス)・`ua` を取り出す。
つまり「誰かが S3 のファイルの行を CloudWatch Logs に流し直している」構成でしか使えない。ALB から CloudWatch Logs への配信の仕組み (下) は、このプロファイルを作った時点では想定していなかった。

### 確かめた事実 (ALB から CloudWatch Logs への配信)

ALB は、従来のログとは別の仕組みで、アクセスログを CloudWatch Logs・Data Firehose・S3 に配信できる
(CloudWatch Logs の「vended logs」。コンソールでは ALB の Integrations タブ。従来のログは Attributes タブ) [1][3]。
公式の文書には行の形が書かれていない [3] ので、配信の設定のひな形を返す API を実際に呼んで確かめた
(2026-11-13。`aws logs describe-configuration-templates --service elasticloadbalancing --log-types ALB_ACCESS_LOGS --delivery-destination-types CWL`。AWS が公開している仕様で、特定のアカウントの値は含まない):

- 出力の形式は、CloudWatch Logs 宛てでは `plain` と `json` (Firehose 宛ては plain / json / raw、S3 宛ては plain / json / w3c / parquet)
- 項目は選べる。既定は全部で、並びは `type, time, elb, client_port, target_port, request_processing_time, target_processing_time, response_processing_time, elb_status_code, target_status_code, received_bytes, sent_bytes, request_line, user_agent, ssl_cipher, ssl_protocol, target_group_arn, trace_id, domain_name, chosen_cert_arn, matched_rule_priority, request_creation_time, actions_executed, redirect_url, error_reason, target_port_list, target_status_code_list, classification, classification_reason, conn_trace_id, transformed_host, transformed_uri, request_transform_status, ip_address`。
  従来のログの先頭 34 項目と同じ並びで、名前だけ `client:port` → `client_port`、`target:port` → `target_port` のように変わっている
- plain の区切りは、タブ・空白・カンマから選べる

未確認 (実際のログで確かめる): plain・既定の項目・空白区切りの行が、従来のログの行と**文字の単位で同じ**か (引用符の付き方、`client_port` が `IP:ポート` の形か、末尾の `ip_address` との関係)。
配信の設定に要る権限、従来のログとの併用の可否、配信の遅れも文書に無く未確認 [3]。

## 決定 (提案)

**(c1) を推奨する。** 利用者が ALB のアクセスログを CloudWatch Logs へ **plain・既定の項目 (全部)・空白区切り**で配信し、
arata は既存の cloudwatch-logs のソースと `alb_access` でそのまま読む。arata のコードの変更は無いか、最小にとどまる見込み。

```yaml
sources:
  - id: alb_prod
    kind: cloudwatch-logs
    log_group: prod-alb-access        # ALB の配信先に選んだロググループ
    format: alb_access
```

(a) の「S3 を直接読む」は、CloudWatch Logs の取り込み料金を避けたい利用者・量が多い利用者のための**次の段**として残す。
(b) の Athena は今は採らない。

理由:

1. **arata のコード・読み取り専用ロール・依存を変えずに済む。** 既にある `logs:*` の読み取りだけで動き、解釈率・`FORMAT_MISMATCH`・doctor・`max_scan_gb` がそのまま効く
2. **読み取り専用ロールに S3 のオブジェクトの読み取りを入れずに済む。** (a) は絞るとはいえ、監査用のロールが初めて S3 の中身を読むことになる
3. **利用者の作業は ALB の設定だけ。** アプリにもサーバーにも触れない
4. **量が小さい利用者では取り込み料金も小さい。** 1 行を 0.5〜1 KB と置くと (推測)、1 日 5,000 リクエストで月に 75〜150 MB。
   バージニア北部の単価 (1 GB あたり 0.50 USD。要約経由で読んだ値で未確認。東京の単価も未確認) [13] なら月に 0.1 USD 未満、数十円以下の見込み (推測)
5. 引き受ける弱点は「取り込み料金が量に比例する」こと。非圧縮で 1 日 3 GB なら月に約 45 USD + 保管 + Insights のスキャン (推測: 取り込みは非圧縮の量で数える)。
   こういう利用者には (a) を用意する

### 注意点

- **利用者向けの手順では「plain・既定の項目・空白区切り」を指定する。** 項目を選んだり、区切りをタブ・カンマにしたりすると、行の並びが変わって `alb_access` の `parse` が合わない
  (解釈率が落ち、`FORMAT_MISMATCH` で気づける)
- **plain の行が従来の行と同じかは、実際のログで doctor の解釈率を見るまで未確認。** 違っていたら `alb_access` の `parse` を両方に合うように直す (これが「最小の変更」の中身)
- **json 形式は今の `format: json` では読めない。** メソッドとパスが `request_line` の 1 項目 (`メソッド URL HTTP の版`) にまとまっていて、
  `json` の対応表 (項目名 → 正規化の名前) では分けられない。`client_port` もポートを含む見込み。json を使うなら、`request_line` を分ける新しい組み込みのプロファイルが要る。
  今は plain を案内し、json 用のプロファイルは作らない
- 取り込み料金は doctor の既存の仕組みでは見積もれない (doctor が出すのは Insights のスキャンの費用)。手順に量と料金の目安を書く

## 次の段: (a) の仕様の案 (要点。設計書 2-3 章)

S3 のアクセスログを読む新しいソースの種類 (`s3-access-logs`。名前は仮) を足し、arata が gzip のファイルを直接読み、
Go で解釈して、cloudwatch-logs のソースと**同じ日次集計**を作る。生の行は保存しない。

ADR 0006 は「生ログをダウンロードしてエンジン内でパースする」案を、転送量と処理時間を理由に却下している。その判断は
「Insights で集計できる CloudWatch Logs のログ」についてのもので、変えない。(a) は、Insights が使えない S3 のログに限って直接読む、という追加である。

- 読む範囲は、今の cloudwatch-logs と同じ「窓に重なる UTC の日の 0 時から窓の終わりまで」で、日次集計を置き換えで保存する (ADR 0009)。
  **「どのファイルまで読んだか」の位置は持たない。** 遅れて届いたファイルは、その日を読み直すたびに自然に入る
- 行は、ファイル名ではなく行の `time` で UTC の日に振り分ける。ディレクトリの日付は配信日なので、日 D の行は `D` と `D+1` のディレクトリを一覧して読む
- 先頭 14 項目だけを解釈し、それより後ろは読まない (項目は末尾に足されるため [1])
- User-Agent は読んだ直後にハッシュにし、パスは Go で正規化・伏せ字にする (今の cloudwatch-logs と同じ規則)。生の行・IP 以外の個人を特定できる値は残さない
- 解釈率 (`lines_total` / `lines_matched`)・`FORMAT_MISMATCH`・`FORMAT_DRIFT` は同じ規則で出す
- 上限 `max_download_gb` (1 回の収集で読んでよい圧縮後の量。`max_scan_gb` と同じ考え方で、既定は 0 = 無制限、doctor が推奨値を出す)。
  一覧 (ListObjectsV2) でサイズが分かるので、**読む前に**超えるかどうかを判定できる
- 信用できない入力 (ログの行) を解釈する関数なので、ファズテストを足す (ADR 0041)。1 行の長さと、1 ファイルの展開後の大きさに上限を置く
- 読み取り専用ロール (`deploy/iam/readonly-role.yaml`) には、バケットと接頭辞をパラメータで受けて、その範囲だけに
  `s3:ListBucket` (`s3:prefix` の条件つき) と `s3:GetObject` を足す。パラメータが空なら文を作らない。`Resource: '*'` にはしない
  (S3 のオブジェクトの読み取りを広く許すと、監査用のロールが業務データを読めてしまう)

## 検討した選択肢

量の前提: 1 日のログが非圧縮で 3 GB。gzip で 10 分の 1 前後になると置く (推測。ログの中身で変わる。doctor は一覧から圧縮後の実際の量を測る)。
すると圧縮後は 1 日 0.3 GB、30 日で 9 GB。ファイル数は 1 日 288 個 × ノード数 (2〜3 ノードで 600〜900 個。通信が多いともっと増える [1])。

### (a) S3 のファイルを arata が直接読み、Go で集計する (次の段)

| 観点 | 評価 |
|---|---|
| 読み取り専用 | 守れる。呼ぶのは `ListObjectsV2` と `GetObject` だけ。設計書 8 章の例外 (`iam:GenerateCredentialReport`) を増やさない |
| IAM | `s3:ListBucket` (バケット。`s3:prefix` で絞る) [6]、`s3:GetObject` (`<prefix>/AWSLogs/<アカウント ID>/elasticloadbalancing/*`)。バケットが別のアカウント (ログ集約用) なら、そのバケットポリシーでも読み取り専用ロールに同じ 2 つを許す |
| 費用 (S3) | GET は 1,000 回 0.0004 USD (料金ページの例の値。バージニア北部) [4]。1 日 900 個を約 1 日分読むと、30 日で 2.7 万回 = 約 0.01 USD。LIST は PUT と同じ単価の区分 [4] で、1 回 1,000 件まで返る [6] ので 1 日数回 |
| 費用 (転送) | 同じリージョンの AWS のサービスへの転送は無料。インターネットへの転送は毎月 100 GB まで無料 (全サービス・全リージョンの合算) [4]。超えた分は 1 GB あたり 0.09 USD 前後 (料金ページの例の値。東京の単価は取得したページの本文に表が無く未確認)。前提の量 (30 日で 9 GB) なら無料枠に収まる見込み。圧縮後で 1 日 3 GB なら 30 日で 90 GB となり、他の転送と合わせて無料枠を超え得る |
| GitHub Actions | GitHub のランナーは Azure か AWS で動く [8]。AWS で動いても同じリージョンとは限らないので、**転送料は出る前提**で見積もる |
| 量 | 行を流しながら数えるので、メモリは集計の大きさだけ (ファイルの大きさに比例しない)。集計の大きさは今の Insights の結果より大きくなり得る (10000 行の上限が無い) ので、Go 側に Top N と上限を置く |
| 実行時間 | 前提の量 (圧縮後 0.3 GB、非圧縮 3 GB) で数分以内の見込み (推測。実装時にベンチマークで確かめる)。並行に GET する。認証は 1 時間 (`configure-aws-credentials` の既定 [7]、読み取り専用ロールの `MaxSessionDuration: 3600`) なので、`max_download_gb` と時間の上限で必ず打ち切る。途中で止まったら、そのソースは失敗として次回に追いつく (ADR 0038) |
| 差分の取り方 | 位置を持たない。UTC の日の頭から読み直して置き換える。daily を UTC 0 時の少し後に回せば、読むのは約 1 日分 (今の Insights と同じ考え方。設計書 8 章の doctor の `cost`) |
| ログの遅れ | 5 分おきの配信 + 結果整合 [1]。`ingest_delay` の既定を 10 分とする案 (cloudwatch-logs は 5 分)。同じ日のうちに届いた分は読み直しで入る。日をまたいで大きく遅れた分は入らない (今の cloudwatch-logs と同じ限界) |
| KMS | 従来のログのバケットは SSE-S3 だけなので [2]、`kms:Decrypt` は要らない。SSE-KMS を既定にしたバケットには ALB が配信できない [2] ので、doctor の案内に書く |
| `alb_access` との関係 | 同じ名前の形式を、新しいソースの種類でも使う (`format: alb_access`)。解釈の規則 (どの項目を何に対応させるか) は 1 つにし、Insights の `parse` と Go の解釈が同じ結果になることをテストで固定する |
| doctor | `permission` (一覧を 1 件、最新のファイルを 1 つ読む)、`match_rate` (最新のファイルの先頭 100 行を手元で解釈)、`freshness` (最新のファイルが古ければ warn: ログが無効・接頭辞の誤り)、`cost` (直近 24 時間の一覧からファイル数と圧縮後の量を**読まずに**実測し、GET と転送の概算、`max_download_gb` の推奨値) |
| 利用者の準備 | ALB の従来のログを有効にする (バケット、バケットポリシー [2])。読み取り専用ロールのスタックにバケットを渡して更新する |
| 新しい依存 | 無い (S3 の SDK は使用中。gzip は標準ライブラリ) |

弱点: AWS の外で動かすと転送料と時間が量に比例する。IP とパスを含む生の行が、実行中だけランナーのメモリを通る
(ディスクには書かない。今も Insights の結果として IP とパスは通っている)。

### (b) Athena で集計する (今は採らない)

| 観点 | 評価 |
|---|---|
| 読み取り専用 | 条件つきで守れる。(1) 表の定義 (`CREATE EXTERNAL TABLE`。RegexSerDe で従来のログの行を解釈する [9]) を arata が行うと書き込みになるので、**利用者が先に作る**。(2) 問い合わせの結果は既定では利用者の S3 のバケットに書かれる [10]。AWS の管理ポリシーも結果用のバケットへの `s3:PutObject` を含む [11]。「管理された問い合わせ結果」(ワークグループの設定) を使えば、結果用のバケットを用意せずに問い合わせでき、結果は 24 時間で消え、追加の料金は無い [12]。この設定なら arata のロールに S3 の書き込みは要らない見込み (未確認: 最小の権限の一覧のページを取得できなかった。sandbox で確かめる必要がある)。`athena:StartQueryExecution` は問い合わせを 1 つ作る操作で、今の `logs:StartQuery` と同じ位置づけ |
| IAM | `athena:StartQueryExecution`・`GetQueryExecution`・`GetQueryResults`・`StopQueryExecution` (ワークグループで絞る。管理された結果では `GetQueryResults` をワークグループに明示して許す [12])、`glue:GetDatabase`・`GetTable` など、**加えて (a) と同じ S3 の読み取り** (Athena は呼び出し元の権限でログを読む、という理解。未確認)。(a) より広い |
| 費用 | スキャンした量に課金。料金ページの例は 1 TB あたり 5 USD で、圧縮したデータは圧縮後の大きさで数える [5]。前提の量で 3 本流すと 30 日で約 27 GB = 約 0.14 USD。転送料はほぼ無い (結果だけ) |
| 量・実行時間 | 最も強い。量が増えても arata 側の時間と転送は増えない |
| 差分・遅れ | (a) と同じ (日の頭から集計し直す)。パーティション射影で日付のディレクトリだけを読める [9] |
| KMS | ログのバケットは SSE-S3 のまま。管理された結果を利用者の鍵で暗号化するなら `kms:Decrypt` などが要る [12] |
| `alb_access` との関係 | Insights のテンプレートとは別に、Athena の SQL の集計テンプレートが要る (解釈率、探索パス、sign-in の失敗、endpoint_abuse)。同じ集計を 2 つの方言 + Go で保つことになる |
| doctor | 表・ワークグループ・結果の設定・権限・構文を確かめる項目が増える。表の正規表現は項目が足されると更新が要る [1][9] |
| 利用者の準備 | ALB のログの有効化に加え、Glue のデータベースと表、ワークグループ。arata が配るテンプレートが 1 つ増える |
| 新しい依存 | Athena の SDK (ADR 0019 の「理由を説明する」対象) |

却下の理由: 利用者の準備と権限が (a) より多く、S3 の読み取り権限は結局要る。集計の定義が二重になる。読み取り専用の約束に
「利用者が管理された結果を設定していること」という条件が付き、設定が違うと書き込みが要る。
得られるのは量への強さだが、想定する量 (1 日数 GB) では (a) で足りる。量が 1 桁大きい利用者が出たら、この ADR を新しい ADR で置き換えて足す。

### (c1) ALB から CloudWatch Logs に配信してもらい、既存の cloudwatch-logs のソースで読む (推奨)

| 観点 | 評価 |
|---|---|
| 読み取り専用 | 守れる。今と同じ Logs Insights の問い合わせだけ |
| IAM | 追加なし (読み取り専用ロールの既存の `logs:DescribeLogGroups`・`StartQuery`・`GetQueryResults`・`StopQuery`) |
| 費用 | 利用者側に CloudWatch Logs の取り込み料金 (量に比例。上の理由 4・5) と保管。arata の読み取りは Insights のスキャン (今の http_access のソースと同じ 2〜3 本)。データ転送は集計の結果だけ |
| 量・実行時間 | 今の cloudwatch-logs のソースと同じ。arata 側の時間はほぼ量に依らない。結果の行数の上限 (10000) も今と同じ |
| 差分・遅れ | 今と同じ (UTC の日の頭から集計し直す。`ingest_delay`)。配信の遅れは未確認 [3] で、実際のログで見て `ingest_delay` の案内を決める |
| KMS | ロググループを利用者の鍵で暗号化している場合に読み取りに要る権限は未確認 (今の cloudwatch-logs のソースと同じ扱いになる) |
| `alb_access` との関係 | そのまま使う。plain・既定の項目・空白区切りが前提。json は読めない (注意点) |
| doctor | 今のまま (`log_group`・`queries`・`match_rate`)。解釈率が、行の形が合っているかの確認になる |
| 利用者の準備 | ALB の Integrations タブ (または CloudWatch Logs の配信の API) で、アクセスログを CloudWatch Logs のロググループへ配信する。形式は plain、項目は既定、区切りは空白。ロググループの保持期間を決める |
| 新しい依存 | 無い |

弱点: 取り込み料金が量に比例する。行の形が未確認。利用者が形式や項目を変えると合わなくなる (解釈率で気づける)。

### (c2) S3 Select (採らない)

S3 Select は 2024-07-25 から新しい利用者には提供されていない (既存の利用者は使えるが、機能は増えない) [14][15]。
AWS が代わりに勧めるのは、1 つのオブジェクトなら「GET して手元で絞る」(= (a))、複数のオブジェクトなら Athena (= (b)) [15]。
もともと 1 オブジェクトずつの問い合わせで、1 日数百個のファイルの集計には向かない。

### (c3) 利用者が S3 から CloudWatch Logs に流し直す (採らない)

S3 のイベントで Lambda を動かし、行を CloudWatch Logs に書く構成。今の `alb_access` が前提にしている形だが、
利用者が Lambda を置いて運用することになり、取り込み料金も出る。(c1) が同じ結果を ALB の設定だけで得られるので、勧めない。

### (c4) arata を AWS の中 (同じリージョン) で動かす

選択肢というより (a) の動かし方。同じリージョンの AWS のサービスへの転送は無料 [4] なので、量が多い利用者は
Lambda・CodeBuild などで動かせば転送料が消える。Lambda ハンドラはロードマップの残項目にある。(a) の実装はどこで動いても同じ。

## 結果 (良い点・引き受けるコスト)

良い点:
- nginx のログを CloudWatch Logs に送っていない利用者でも、ALB の設定だけで `login_bruteforce`・`probe_paths`・`endpoint_abuse` が動く
- arata のコード・読み取り専用ロール・依存を変えない (か、`alb_access` の `parse` の小さな直しで済む)。すぐに試せる
- 量が多い利用者・取り込み料金を避けたい利用者には、(a) という次の段がある

引き受けるコスト:
- 利用者側に CloudWatch Logs の取り込み料金と保管料が出る。量が多いと (a) より高い
- 行の形が合うことを、実際のログで確かめるまで約束できない。利用者が配信の形式・項目・区切りを変えると読めなくなる
- ALB の前に CloudFront などのプロキシがある構成では、送信元がプロキシの IP になり [1]、IP ごとの判定 (`login_bruteforce` など) が意味を持たない。
  この構成は対象外と文書に書く ((a) でも同じ)
- 記録はベストエフォート [1] なので、件数は下限として扱う

(a) を実装するときに引き受けるコスト:
- 読み取り専用ロールに、初めて S3 のオブジェクトの読み取りが入る。バケットと接頭辞で必ず絞り、パラメータが空なら付けない。
  `internal/engine/readonly_role_test.go` の突き合わせも、資源を絞った文を扱えるように直す
- 集計の実装が Insights (クエリ) と Go の 2 つになる。同じログから同じ日次集計になることを、ゴールデンで固定する
- AWS の外で動かすと、量に比例して転送料と時間がかかる。doctor の `cost` と `max_download_gb` で見えるようにし、止められるようにする
- S3 のデータイベントを CloudTrail で記録している利用者では、arata の GET がその記録を増やす (推測: 設定による)

採用までに確かめること:
- 実際の ALB で CloudWatch Logs への配信 (plain・既定の項目・空白区切り) を有効にし、doctor の解釈率で `alb_access` が合うことを確かめる。
  合わなければ `parse` を直す。あわせて配信の遅れ、配信の設定に要る権限、取り込み料金の実際の額を見る
- 確かめた手順を README と `examples/` に書く (ALB の設定、ソースの書き方、料金の目安、対象外の構成)
- (a) は、必要とする利用者が出た時に、sandbox で従来のログを有効にして量・圧縮率・GitHub Actions からの実行時間を測り、
  設定の名前 (`s3-access-logs`、`max_download_gb`) とエラーの `code` を決めてから実装する

## 出典

確認日はすべて 2026-11-13。

1. Access logs for your Application Load Balancer — https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
2. Enable access logs for your Application Load Balancer — https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
3. CloudWatch Logs for your Application Load Balancer — https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-logs.html
4. Amazon S3 pricing — https://aws.amazon.com/s3/pricing/ (リージョンごとの表は取得した本文に無く、例と説明の文だけを使った)
5. Amazon Athena pricing — https://aws.amazon.com/athena/pricing/ (同上。1 TB あたり 5 USD は例の値)
6. ListObjectsV2 — https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
7. aws-actions/configure-aws-credentials (`role-duration-seconds` の既定は 1 時間) — https://github.com/aws-actions/configure-aws-credentials
8. About GitHub-hosted runners — https://docs.github.com/en/actions/using-github-hosted-runners/using-github-hosted-runners/about-github-hosted-runners
9. Athena: Query Application Load Balancer logs — https://docs.aws.amazon.com/athena/latest/ug/application-load-balancer-logs.html 、表の定義 https://docs.aws.amazon.com/athena/latest/ug/create-alb-access-logs-table.html
10. Athena: Work with query results — https://docs.aws.amazon.com/athena/latest/ug/querying.html
11. AmazonAthenaFullAccess — https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonAthenaFullAccess.html
12. Athena: Managed query results — https://docs.aws.amazon.com/athena/latest/ug/managed-results.html
13. Amazon CloudWatch pricing — https://aws.amazon.com/cloudwatch/pricing/
14. Amazon S3 Select (新しい利用者には提供しない旨) — https://docs.aws.amazon.com/AmazonS3/latest/userguide/selecting-content-from-objects.html
15. How to optimize querying your data in Amazon S3 (2024-07-25) — https://aws.amazon.com/blogs/storage/how-to-optimize-querying-your-data-in-amazon-s3/
16. CDK `ApplicationLoadBalancer.logAccessLogs` — https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationLoadBalancer.html
17. AWS Copilot の environment manifest (`http.public.access_logs`) — https://aws.github.io/copilot-cli/docs/manifest/environment/
