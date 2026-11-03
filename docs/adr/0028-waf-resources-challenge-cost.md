# 0028. WAF の分析を資源で絞り、Challenge / CAPTCHA の影響を「解かれた割合」で評価し、Insights の費用を doctor で見積もる

- 日付: 2026-11-03
- 状態: 採用

## 背景

ADR 0023 の WAF の修正提案を実際の規模の環境で使うと、次のことが分かった (数字は形だけを書く)。

- 1 つの WebACL (REGIONAL) を本番と staging の複数の ALB が共有していて、ログに staging の通信が混ざる。監査したいのは本番だけ
- 1 日に数百万リクエストのうち、Challenge と CAPTCHA が ALLOW に次いで多い。利用者にとって一番価値があるのは「正規の利用者が Challenge / CAPTCHA に巻き込まれていないか」の評価
- ログは 1 日に数 GB で、daily の集計クエリはそれを何本もスキャンする。費用の見当が付かない

方針は変えない: arata は LLM を使わず規則で候補を作る (ADR 0001・0023)。迷ったら提案しない。事実は observation で伝える。COUNT → BLOCK は提案しない。
ヘッダー・クエリ・Cookie・authorization・User-Agent は保存も通知もしない。

## 決定

### 資源で絞る

- wafv2 の `cloudwatch-logs` ソースに `resources` (任意。ログの `httpSourceId` の完全一致か `*` / `?` の glob の一覧) を足す。前処理に
  `filter httpSourceId like /^(...)$/` を入れるので、解釈率・全集計が同じ範囲を数える。集計条件 (変えると日次集計の意味が変わる)
- 集計の key に資源は入れない (行数が資源の数だけ増える)。分けて見たい利用者は同じロググループで resources の違うソースを 2 つ書く
- Insights はロググループ全体をスキャンするので、**絞っても費用は減らない** (雛形と文書に書く)
- doctor は、ログの宛先がそのロググループの WebACL の資源 (`ListResourcesForWebACL`) から httpSourceId の候補を作り、resources のどれかが候補に当たらなければ warn にする。
  waf-config のソースが設定に無くても、wafv2 のソースのリージョンで waf-config の collector を一時的に作って読む (読み取りだけ。必要な action は waf-config と同じ)

### Challenge / CAPTCHA の影響評価

- 日次集計を 2 本足す (daily のクエリは lines + waf_block_ip + 7 本 + レートの 10 本分のスキャンになる)
  - 出した行: `action` が CHALLENGE / CAPTCHA (トークンが無い・無効・期限切れで止めた)。ルールは終了ルール、グループの中は BLOCK と同じ規則 (ADR 0023)
  - トークンが受理された行 (解いた後の再訪): 下の「文書の食い違い」のとおり 2 つの形を受け付ける
- 「解いた」は**ルールではなく種類 (challenge / captcha) で数える**。トークン (`aws-waf-token`) は WebACL のルールで共有されるので、どのルールのトークンかは区別できない
- 解いた IP = その日・その method と正規化パスで出された IP のうち、同じ日・同じ method とパスで同じ種類のトークンが受理された IP (積集合)。
  後からトークンを持って別の画面に来た IP は数えない (割合が 1 を超えない)。IP の集合は Go で作り、保存するのは数だけ
- metric (key `<WebACL>|<challenge|captcha>|<ルール>[/<中>]|<method>|<正規化パス>`、日ごとに上位 `top_paths`):
  `waf_challenge_issued` (出した件数) / `waf_challenge_issued_ips` (出した異なり IP) / `waf_challenge_solved_ips` (そのうち解いた異なり IP)
- 解かれた割合 = 解いた IP / 出した IP を、期間 (`days`) の日ごとの値を足して比べる (「IP・日」の比)
- waf_review に足すもの:
  - 提案 `challenge_on_app_path` (stage `review`): 探索パスではない **GET** の画面で、出した IP (日ごとの最大) が `challenge_min_distinct_ips` (10) 以上、
    解かれた割合が `challenge_solve_ratio` (0.5) 以上 → 「人が解いている = 正規の利用者が巻き込まれている疑い。このパスを対象から外す (scope-down) か条件を絞ることを検討し、様子を見る」。
    止めるのではなく緩める提案なので count_first ではなく review。BLOCK に変えることは勧めない
  - 決まった除外 (observation、`excluded_by_rule`): sign-in のパス、レートベースのルール、送信元の評判のグループ。設定と突き合わせられないときは `undetermined`
  - observation `challenge_impact` (`reason: informational`): 毎回、出した数の多い `challenge_top_rules` (10) 個のルールの出した数・解かれた割合・GET 以外の件数・主なパス。**事実だけを書き、解釈しない**
- GET 以外は提案しない。Challenge / CAPTCHA はブラウザが画面として受け取る GET でしか解けず、POST や XHR は割合が低くなる構造。
  割合が低いのを「人が巻き込まれていない」と読ませないため、challenge_impact に「GET 以外 N 件 (解けない)」を添える
- 割合が低いものは提案しない (ボットを止めているのか、解けない通信なのかを区別できない)。challenge_impact に数字だけ載る

### 費用の見積もりと上限

- doctor に wafv2 のソースごとの行 `cost` を足す。1 日のログの量 × 範囲の日数 × クエリの本数で 1 回の run のスキャン量を出し、
  wafv2 を引くプロファイルの 1 日の run 数 (24h / 窓) を掛けて、1 日と 30 日の概算 (USD) を表示する。範囲は窓 + ingest_delay + 日の頭への寄せ (最大 24h) の上限側
- 1 日のログの量は、解釈率のサンプルのクエリ (直近 `--window`) のスキャン量から推定する (追加の費用なし)。`doctor --measure-scan` なら直近 24h に解釈率の集計を流して実測する (1 日分のスキャンの費用)
- 単価は Logs Insights の東京の 0.0076 USD/GB を定数で持ち、表示に「東京の単価」と書く (リージョンと改定で変わるので設定にしない。概算であることを示す)
- `max_scan_gb` が無い wafv2 のソースは warn にし、推奨値 (1 回の見積もりの 1.5 倍) を添える。見積もりより小さい max_scan_gb も warn。雛形の wafv2 の例に max_scan_gb を書く

### 文書の食い違い (両方の形を受け付ける)

AWS の公式文書 (Log fields / Log examples、2026-11 時点) は次の 2 点で説明と例が食い違う。両方の形を受け付け、sandbox の実ログで確かめる。

- **トークンが受理された行**: フィールドの説明は「`captchaResponse` / `challengeResponse` は終了でも非終了でも入る。非終了なら solve timestamp を含む。
  `failureReason` が空でないかで見分けられる」と読める。一方、有効なトークンの CAPTCHA の例では、`captchaResponse` は `nonTerminatingMatchingRules` の要素の中
  (`action: "CAPTCHA"`、`responseCode 0`、`solveTimestamp`) にだけあり、トップレベルに無い。
  → トップレベルの `<種類>Response.solveTimestamp` があり `failureReason` が無く、その種類で止めていない行と、`nonTerminatingMatchingRules.N.action`
  (グループの中は `ruleGroupList.N.nonTerminatingMatchingRules.0.action`) が CHALLENGE / CAPTCHA の行の両方を「受理」とする。
  期限切れ (`failureReason: TOKEN_EXPIRED`) は solveTimestamp が入っていても受理としない
- **httpSourceId**: 説明は「ALB は load-balancer-id、API Gateway の REST API は api-id」だが、例は API Gateway で `<アカウント>:<api-id>:<ステージ>`、ALB はダミーの値。
  → resources は利用者がログの値を見て書く前提にし、doctor の照合は ARN から両方の形 (ALB: id・name/id・app/name/id、API Gateway: api-id・api-id:ステージ・アカウント:api-id:ステージ、他: ARN の末尾) を候補にする。
  照合は推定なので ng にせず warn

## 検証方法と前提 (「解かれた割合が高い = 人が巻き込まれている」は仮説)

- 前提: Challenge (無音の JavaScript の検査) と CAPTCHA (パズル) は、ふつうのブラウザなら解けて、単純なボット (HTTP ライブラリ) は解けない。
  人は出された画面を解いて同じ URL を開き直すので、同じ日・同じパスにトークン付きの行が来る
- 崩れる場合: ヘッドレスブラウザのボットは Challenge を解ける (CAPTCHA は解きにくい)。多くの人が 1 つの NAT の IP を共有すると IP 数は少なく出る。
  日をまたいで解かれると数えない。行の上限 (10000) で切れると件数の少ない組 (1〜2 件の人) が落ち、割合は低めに出る (提案は出にくい側)
- 検証: sandbox で「解かれない」側 (curl で叩く = 出した行だけ) の実ログの形を確かめる。「解かれる」側はブラウザが要るので、公式文書の例の形をテストのフェイクで固定し、
  利用者の環境で、提案の出たパスについて「その画面に人が来ているか」(アプリのアクセスログ・利用者の声) と突き合わせて確かめる。外れが多ければ閾値か判定を見直す

## 検討した選択肢

- **資源を集計の key に入れる**: 却下。全集計の行数が資源の数だけ増え、上限 (10000) に当たりやすい。分けたいときはソースを 2 つ書けば足りる
- **解いた数をルールごとに数える (位置の ruleId で突き合わせる)**: 却下。トークンはルールで共有され、どのルールのトークンかに意味がない。グループの ruleGroupId と WebACL のルール名の対応も要る
- **解いた数をトークン付きの行の件数で数える**: 却下。1 回解くと有効期間のあいだ全部の要求にトークンが付くので、割合が 1 を大きく超え、人の数を表さない
- **Insights の count_distinct で異なり IP を数える**: 却下。生パスごとに数えて足すと、1 つのボットが /items/1..500 を列挙したときに 500 IP と数える
  (ヘッドレスのボットなら解かれた割合も高く、正規の利用者が巻き込まれたと取り違える = 緩める提案をしてしまう。ADR 0023 と同じ理由)
- **ラベル (`awswaf:managed:token:accepted` など) で受理を判定する**: 見送り。ラベルの名前と付く条件を実ログで確かめられていない
- **TOKEN_EXPIRED の内訳 (期限切れで出し直した = 前に解いた人)**: 見送り。人が居る強い手がかりだが、まず割合の判定を実ログで確かめる。将来の候補
- **IncomingBytes (CloudWatch のメトリクス) で 1 日の量を測る**: 却下。cloudwatch の SDK が新しい依存になる (ADR 0019)。DescribeLogGroups の storedBytes は日量が分からない
- **doctor で常に 1 日分の集計を流して実測する**: 見送り。doctor のたびに 1 日分のスキャンの費用がかかる。推定が少なく出ると分かったら既定を切り替える (`--measure-scan` で選べる)

## 結果 (良い点・引き受けるコスト)

- 良い点: 本番だけを監査できる。Challenge / CAPTCHA の影響が毎週数字で届き、正規の画面での巻き込みは規則で提案になる。費用の見当と上限の推奨値が doctor で分かる
- コスト: daily の wafv2 のスキャンが 8 本分から 10 本分に増える。解かれた割合の解釈は仮説で、ヘッドレスのボットや NAT で崩れる。
  ログの形 (受理の位置・httpSourceId) が公式文書で食い違うので、sandbox の実ログで確かめ、片方の形に決まれば判定を狭める
