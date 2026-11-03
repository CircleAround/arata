# waf_block_trend: WAF の BLOCK の変化

## この指摘の意味

WAF の BLOCK に変化があった (daily、low)。攻撃の始まりか、WAF の設定・アプリの変更による誤検知の始まりのどちらか。

- `rule|<ルール>`: 過去 `baseline_days` (既定 14) 日に BLOCK していなかったルールが BLOCK し始めた (`reason: new_rule`)
- `top_ip|<IP>`: その日の BLOCK 件数の上位に、過去の上位に居ない IP が入った (`reason: new_top_ip`)
- data: `rule` か `ip`、`date`、`count`、`past_top_ips`、`baseline_days_with_data`。導入直後 (データのある日が少ない間) は出ない

## まず確かめること

1. `arata review --format json` で同じ IP の login_bruteforce・probe_paths を探す。weekly の report があれば `proposals` の同じルールの候補 (`false_positive` など)
2. 新しいルールなら、その日に WAF の設定を変えていないか: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL`
   (CLOUDFRONT の WebACL は us-east-1、REGIONAL はそのリージョン)。アプリのデプロイと重なっていないか
3. 何が BLOCK されたか: WAF のログを CloudWatch Logs Insights で、そのルール (`terminatingRuleId`) かその IP (`httpRequest.clientIp`) に絞り、`httpRequest.uri` と件数を数える。
   直近 3 時間以内なら `aws wafv2 get-sampled-requests` でも見られる (`--web-acl-arn`・`--rule-metric-name`・`--scope`・`--time-window`)
4. BLOCK されたのが探索・攻撃のパスか、正規の画面か。正規の画面なら異なり IP の数 (多ければ誤検知の疑い)

## 判断の分かれ目

- **攻撃 (WAF が守っている)**: 探索・既知の攻撃のパス、少数の IP からの集中。WAF が止めているので、多くは記録でよい
- **誤検知の疑い**: 正規の画面への BLOCK が多数の IP に広がる、設定変更・デプロイの直後に始まった。利用者の不具合の報告と重なる
- **要対応**: 攻撃が BLOCK 以外の経路 (同じ IP の 200 の応答) でも続いている、BLOCK の件数が急増し続ける

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (攻撃が続く): その IP を WAF の IP set で拒否する、レートベースのルールを足す (IaC で、まず COUNT で様子を見る)
2. **承認**: 対象外。正規の監視・診断の送信元なら `source_ips` に足すことを人に提案する
3. **expected_denied**: 対象外
4. **ack / snooze**: 攻撃を WAF が止めているだけなら ack
5. **設定の修正**: 誤検知なら、そのパスだけ COUNT にする (ルールの action の上書きか scope-down) → 様子を見て除外を確定する。weekly の waf_review の候補も参照する

## やってはいけないこと

- 誤検知の疑いでも、ルール全体を外す・無効にすることを勧めない (パスに限って COUNT にする)
- WAF のログのヘッダー・クエリ・Cookie の生の値を要約に転記しない
