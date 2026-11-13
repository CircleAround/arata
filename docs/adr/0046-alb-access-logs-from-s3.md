# 0046. S3 に出る ALB のアクセスログは、arata が直接読んで Go で集計する

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
つまり「誰かが S3 のファイルの行を CloudWatch Logs に流し直している」構成でしか使えない。ALB から CloudWatch Logs への配信の仕組みは、
このプロファイルを作った時点では想定していなかった (その仕組みは選択肢 (c1))。

## 決定 (提案)

**(a) を推奨する。** S3 のアクセスログを読む新しいソースの種類 (`s3-access-logs`。名前は仮) を足し、arata が gzip のファイルを直接読み、
Go で解釈して、今の cloudwatch-logs のソースと**同じ日次集計**を作る。生の行は保存しない。
(c1) の CloudWatch Logs への配信は、arata を変えずに使える見込みの代わりの道として、sandbox で確かめてから README に書く。
(b) の Athena は今は採らない。

理由:

1. **読み取り専用を、例外を足さずに守れる。** 要るのは `s3:ListBucket` と `s3:GetObject` だけで、問い合わせの実行・結果の書き込み・表の定義が無い
2. **利用者の準備が最も少なく、利用者側の費用が増えない。** ALB の従来のログを有効にするだけ (S3 の保管料のみ [1])。
   (b) は Glue の表とワークグループ、(c1) は CloudWatch Logs の取り込み料金が要る
3. **新しい依存が無い。** S3 の SDK は S3 ストア (ADR 0034) で既に使っている。(b) は Athena の SDK と、Insights とは別の SQL の集計テンプレートが要る
4. **「集計だけ持ち帰る」方針と矛盾しない。** 持ち帰る先は実行中のメモリで、ストアに残すのは今と同じ日次集計だけ。
   Insights の結果の行数の上限 (10000) による数え漏れ (`truncated`) も、このソースでは起きない
5. 引き受ける弱点は「AWS の外で動かすと転送料が出る」「量が増えると時間がかかる」の 2 つで、どちらも doctor で事前に測れ、上限 (`max_download_gb`) で止められる。
   1 日に圧縮後で数 GB を超える利用者には、AWS の中で動かすか (b) を足すかを、その時に決める

ADR 0006 は「生ログをダウンロードしてエンジン内でパースする」案を、転送量と処理時間を理由に却下している。その判断は
「Insights で集計できる CloudWatch Logs のログ」についてのもので、変えない。この ADR は、Insights が使えない S3 のログに限って直接読む、という追加である。

### 仕様の案 (要点。詳しくは設計書 2-3 章)

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

### (a) S3 のファイルを arata が直接読み、Go で集計する (推奨)

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

### (c1) ALB から CloudWatch Logs に配信してもらい、既存の cloudwatch-logs のソースで読む (代わりの道として文書に書く)

ALB は、従来のログとは別の仕組みで、アクセスログを CloudWatch Logs・Data Firehose・S3 に配信できるようになっている
(CloudWatch Logs の「vended logs」。コンソールでは ALB の Integrations タブ) [1][3]。

- arata の変更は不要か、わずか。ロググループに入る行が従来のログと同じ空白区切りなら `alb_access` がそのまま、JSON なら `json` プロファイルで読める。
  **どちらの形で入るかは公式の文書に書かれておらず、未確認** [3]。sandbox で実際に配信して確かめる
- 読み取り専用ロールの変更も不要 (既にある `logs:*` の読み取りだけ)
- 利用者側に CloudWatch Logs の取り込み料金が出る。料金ページの値は、バージニア北部で最初の 10 TB が 1 GB あたり 0.50 USD
  (要約経由で読んだ値。未確認。東京の単価も未確認) [13]。前提の量 (非圧縮で 30 日 90 GB) なら約 45 USD/月 + 保管 + Insights のスキャン (推測: 取り込みは非圧縮の量で数える)。
  (a) の利用者側の追加費用はほぼ 0 なので、差は大きい
- 利用者の作業は ALB の設定だけ (アプリ・サーバーには触れない)。配信の設定に要る権限、従来のログとの併用の可否、配信の遅れは未確認 [3]

位置づけ: 「CloudWatch Logs にお金を払ってよく、arata のロールに S3 の読み取りを足したくない」利用者の道。(a) と排他ではない。
確かめた後、README とロードマップに書く。`alb_access` をこの配信の形に合わせる必要があるかも、その時に決める。

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
- 読み取り専用の例外を増やさない。利用者側の追加費用がほぼ無い。新しい依存が無い
- Go で数えるので、Insights の行数の上限による数え漏れが無く、パスの正規化 (ロードマップ 6 章「パスの照合が生の文字列」) も 1 か所で直せる

引き受けるコスト:
- 読み取り専用ロールに、初めて S3 のオブジェクトの読み取りが入る。バケットと接頭辞で必ず絞り、パラメータが空なら付けない。
  `internal/engine/readonly_role_test.go` の突き合わせも、資源を絞った文を扱えるように直す
- 集計の実装が Insights (クエリ) と Go の 2 つになる。同じログから同じ日次集計になることを、ゴールデンで固定する
- AWS の外で動かすと、量に比例して転送料と時間がかかる。doctor の `cost` と `max_download_gb` で見えるようにし、止められるようにする
- ALB の前に CloudFront などのプロキシがある構成では、`client:port` がプロキシの IP になり [1]、IP ごとの判定 (`login_bruteforce` など) が意味を持たない。
  この構成は対象外と文書に書き、doctor で気づけるか (送信元の IP が少数に偏る、など) は実装時に検討する
- 記録はベストエフォート [1] なので、件数は下限として扱う (今の Insights の集計も同じ性質)
- S3 のデータイベントを CloudTrail で記録している利用者では、arata の GET がその記録を増やす (推測: 設定による)。doctor の案内に書く

採用までに確かめること:
- sandbox で ALB の従来のログを有効にし、実際のファイルで解釈・量・時間を測る (圧縮率、1 日のファイル数、GitHub Actions からの実行時間)
- (c1) の配信を sandbox で有効にし、ロググループに入る行の形と料金を確かめる
- 設定の名前 (`s3-access-logs`、`max_download_gb`)、エラーの `code` (バケットが無い・上限を超えた) を既存の語彙に合わせて決める

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
