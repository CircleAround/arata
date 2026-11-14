# waf_review: WAF の修正提案の候補

## この指摘の意味

weekly に、daily が貯めた WAF の日次集計と WebACL の設定 (`waf-config`) から、決まった規則で WAF の修正の候補を作る。候補は finding ではなく、report.json の `proposals` に毎週その時点のものが出る。
finding になるのは、正規の画面で多数の IP が BLOCK された誤検知の疑い (`false_positive|<WebACL>|<ルール>|<method> <path>`、low) だけ。適用するかは人が判断する。

- 提案 (`kind`): `false_positive` (誤検知の疑い)、`challenge_on_app_path` (正規の画面に Challenge / CAPTCHA を出し、人が解いている疑い)、`probe_allowed` (すり抜けている探索)、`rate_limit_missing` (レート制限の不足)、`rate_limit_loose` / `rate_limit_tight` (値の見直し)、`unused_rule` (使われていないルール)
- `stage`: `count_first` = まず COUNT で様子を見てから確定する、`review` = 人が見直す (変更を勧めるものではない)
- `observation` (`stage: none`): 提案に至らなかったが不審な観測。`about` (関わる候補の種類) と `reason` (提案しなかった理由: `below_threshold`・`undetermined`・`excluded_by_config`・`excluded_by_rule`・`position_limit`)
- `about: count_rule_status` (`reason: informational`): COUNT で動いているルールの状況 (`matches`・`suspect_ratio`・`matching_days` / `days`)。提案ではなく、COUNT → BLOCK を計画する材料
- `about: challenge_impact` (`reason: informational`): Challenge / CAPTCHA を出した数の多いルールの、出した数 (`issued`)・解かれた割合 (`solve_ratio`)・GET 以外の件数 (`issued_non_get`)・主なパス
- 読み方の詳細は `arata help ai report` の「WAF の修正提案の候補 (proposals)」

## まず確かめること

1. `coverage.checks_skipped` に waf_review が無いか (wafv2 のソースが無い・waf-config が取れない)。`coverage.sources_failed` の waf-config の `action`
2. `proposals` を種類ごとに読み、`evidence` の数字 (`count`・`distinct_ips_max_per_day`・`days`・`p99_per_5min`・`proposed_limit`・`current_limit_per_5min`) を根拠にする。
   `distinct_ips_max_per_day` は日ごとの最大で、期間全体の IP 数の下限
3. `false_positive` は、そのパスが正規の画面か (利用者の事情)、BLOCK が始まった時期に WAF の設定・アプリのデプロイの変更が無いか
   (`aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL`)
4. 今の設定 (読み取り): `aws wafv2 list-web-acls --scope REGIONAL --region <region>` (CloudFront 用は `--scope CLOUDFRONT --region us-east-1`)、
   `aws wafv2 get-web-acl --name <名前> --scope <scope> --id <ID>` でルール・action・scope-down を確かめる
5. `challenge_on_app_path` は、そのパスが人の来る画面か (検索・一覧などの入口)、Challenge / CAPTCHA を出す条件 (referer・国・ボットの判定) が広すぎないか。
   `solve_ratio` は「解いた IP / 出した IP」で、高いほど人が解いている。ヘッドレスブラウザのボットも Challenge は解けるので、アプリのアクセスログで人の来訪と合うかを確かめる
6. `challenge_impact` の `solve_ratio` が低いのは「ボットを止めている」とは限らない。POST や XHR (`issued_non_get`) は構造上解けず、画面が壊れている (正規の利用者が先へ進めない) こともある
7. `probe_allowed` は、探索が 200 で返っていないか (`arata help ai playbook probe_paths`)
8. 同じ IP・パスの finding (waf_block_trend・probe_paths・login_bruteforce) を `arata review --format json` で探す

## 判断の分かれ目

- **候補どおり進めてよい**: 根拠の数字が十分で、利用者の事情 (正規の送信元・リクエストの多い画面) と矛盾しない。`count_first` はまず COUNT で様子を見る
- **見送る・事情を確かめる**: リクエストが多いのが仕様の画面 (決済など)、正規の送信元 (監視・開発会社) が混ざる。設定 `trusted_cidrs`・`expected_high_rate_paths` に書くよう人に提案する
- `challenge_on_app_path` は緩める提案。進めるならまず対象のパスを scope-down で外すか条件を絞り、Challenge / CAPTCHA の数と、BLOCK・不審な通信が増えないかを 1〜2 週間見る
- `observation` は事実として伝えるだけ。提案に格上げしない。`count_rule_status` の `suspect_ratio` が高くても「BLOCK に上げるべき」とは書かない

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め**: 攻撃そのものは findings 側 (waf_block_trend・probe_paths・login_bruteforce) の手順で扱う。`probe_allowed` で探索が当たっていたら probe_paths の封じ込め
2. **承認**: 対象外
3. **expected_denied**: 対象外
4. **ack / snooze**: `false_positive` の finding は、確認して直す予定なら snooze、意図した BLOCK なら ack。proposals 自体は状態を持たないので操作は無い
5. **設定の修正**: 候補を文章と設定の例に書き起こす (何を・なぜ (evidence の数字)・段階)。適用は IaC で、`count_first` はまず COUNT にしてから確定する。`unused_rule` の削除は勧めない

## やってはいけないこと

- 候補に無い提案を足さない。数字を作らない
- COUNT → BLOCK の切り替えを勧めない (運用で計画して行う作業)。Challenge / CAPTCHA を BLOCK に変えることも勧めない
- `challenge_impact` の解かれた割合が低いことを「人が巻き込まれていない」「ボットだけ」と書かない
- ヘッダー・クエリ文字列・Cookie などの生の値を推測で補わない (report.json に無い)
- LLM が WAF の設定を変更しない

## 関連する事例

対応する公開の事例はまだ無い (`arata help ai threats`)。
