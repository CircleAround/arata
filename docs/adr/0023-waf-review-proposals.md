# 0023. WAF の修正提案の候補は arata が規則で作り、report.json の `proposals` に出す (WebACL の設定は `waf-config` のスナップショット)

- 日付: 2026-11-03
- 状態: 採用

## 背景

定期の監査 (arata run → aratam で Slack) のついでに、WAF のアクセスと設定を分析して修正案を知らせたい。
利用者は「カウントモードで様子を見る → ブロック」の段階で変える。決済など、リクエストが多いのが仕様の画面がある。監視や開発会社からのアクセスは正規。
通知にヘッダー・クエリ・Cookie などの生の値や、個人 (メール・氏名) を出さない。修正の適用 (PR・IaC の変更) の自動化は対象外。

arata は LLM を使わず (ADR 0001)、aratam は判定を LLM に任せない (docs/aratam.md 2 章)。両者は出力ファイルだけで連携する (ADR 0018)。

## 決定

- **候補は arata が決まった規則で作る** (根拠の数字つき)。aratam の LLM は候補を文章と設定例に書き起こすだけで、候補に無い提案を作らない
- 素材は 2 つ
  - wafv2 の `cloudwatch-logs` ソースの日次集計 (daily) に、ルールごとの件数・正規化パスごとの BLOCK と異なり IP・許可された探索・カウントモードの一致・1 IP あたり 5 分の件数の分布を足す。
    ヘッダー・クエリ・Cookie・User-Agent・本文は引かない。パスは Go 側で正規化 (クエリを落とし、数字・UUID の区間を `:id`) してから (パス, IP) で異なり IP を数える
  - 新しいソース種類 `waf-config` (ListWebACLs / GetWebACL / GetLoggingConfiguration / ListResourcesForWebACL。REGIONAL は regions、CLOUDFRONT は us-east-1) で
    WebACL とルールの要約を `snapshot_items` に置く (ADR 0015)。Statement の全体は保存しない。読み取りロールに wafv2 の 4 つを足す。
    ListResourcesForWebACL は資源の種類ごとにサービス側の権限 (例 `cognito-idp:ListResourcesForWebACL`) も要るが、それは足さず、呼べない種類は「不明」として記録して続ける
- weekly のチェック `waf_review` が、保存済みの日次集計と設定から 6 種類の候補 (誤検知の疑い・BLOCK に上げてよいカウントルール・すり抜けている探索・レート制限の不足 / 値の見直し・
  使われていないルール) を作り、report.json の新しい節 `proposals` に出す。**finding ではない** (差分判定に乗せず、毎週その時点の候補を出す)。
  重大な候補 (正規の画面で多数の IP が BLOCK された誤検知の疑い) だけ low の finding にもする
- 閾値と、利用者ごとの事情 (`trusted_cidrs` = 正規の送信元、`expected_high_rate_paths` = リクエストが多いのが仕様のパス) は `checks.waf_review` の設定 (雛形と `config init --diff` に出る。ADR 0014)。
  集計に効くもの (`top_paths` / `rate_path_groups` / `trusted_cidrs`、ソースの `strip_path_prefix`) は集計条件で、overrides では変えられない
- **迷ったら提案しない**。設定と突き合わせられない・scope-down を解釈できない・データの日数が足りないときは提案しない。
  ただし**不審な事実は必ず伝える**: 提案に至らなかった不審な観測は `kind: observation` として、提案しなかった理由 (`reason`) と根拠の数字を添えて残す。
  攻撃そのものの検知は既存のチェックの finding が担い、observation は WAF の設定の観点に限る
- weekly の run は wafv2 のログを引かない (Insights の費用)。waf_review は daily が貯めた日次集計だけを読む。wafv2 のソースが設定に無ければ skip
- ログの配列 (カウントの一致、ルールグループ) は Insights の平坦化 (`ruleGroupList.N.…`) の位置で取る。止めたグループの中のルール名は、
  `terminatingRuleType` がグループの行で `terminatingRule` が null でない最後の位置とする (前の COUNT のグループは評価済みで null でなく、止めたグループより後ろは評価されない)。
  位置の上限を超えたら決めずにグループ単位にし、数え漏れの可能性を observation で伝える

## 検討した選択肢

- **LLM に生のログか集計を渡して修正案を考えさせる**: 却下。ADR 0001 (arata は LLM を使わない) と aratam の原則 (判定を LLM に任せない) に反する。
  提案の根拠が再現できず、テストで固定できない。生のログを渡すとヘッダーやクエリの値が LLM と通知に流れる
- **候補を finding にする (差分判定に乗せる)**: 却下。候補は「今の設定に対する提案」で、閾値の前後で new / resolved を繰り返すと通知がうるさい。
  ack / snooze の対象でもない。重大な 1 種類だけ finding にも出す
- **weekly で wafv2 のログを 7 日分スキャンする**: 却下。daily で既に引いている日のスキャンを毎週やり直すことになり費用が倍になる。日次集計を貯めて読む
- **生パスごとの count_distinct を足して正規化パスの異なり IP にする**: 却下。1 IP が `/items/1..500` を列挙すると 500 IP と数え、攻撃を「誤検知の疑い」と取り違える (危ない方向に間違える)。
  (パス, IP) で集計して Go で数える。行の上限で切れても少なめに数える側に倒れる
- **Insights の `unnest` で配列を展開する**: 見送り。新しい構文で、実環境での挙動 (stats との組み合わせ) を確かめられていなかった。平坦化の位置は sandbox で確かめた
- **`parse @message` の正規表現で止めたグループの中のルール名を取る**: 却下。最初に一致するのは前にある COUNT のグループの `terminatingRule` のことがある (sandbox の実ログで確認)
- **`labels` (例 `awswaf:managed:aws:known-bad-inputs:Log4JRCE_Header`) で一致したルールを取る**: 見送り。位置に頼らない利点はあるが、大文字小文字が ruleId と違い、
  COUNT と BLOCK を見分けられない
- **ListResourcesForWebACL のためにサービス側の読み取り権限 (cognito-idp・apprunner・ec2 など) を読み取りロールに足す**: 却下。守っている資源は提案の補助で、
  監査ロールに資源ごとのサービスの権限を足す理由が弱い (最小権限)。呼べない種類は不明として残し、doctor は warn にする
- **呼ぶ種類を、追加の権限が要らないものに絞る**: 見送り。どの種類が追加の権限を要るかは文書と実環境で確かめきれていない。全種類を呼び、拒否された種類だけを不明にすれば、確かめた結果に依らない
- **scope-down を全部解釈してレート制限の受け持ちを決める**: 見送り。Statement の木は任意に深い。UriPath の ByteMatch とその And だけを解釈し、他は「判断できない」として提案しない

## 結果 (良い点・引き受けるコスト)

- 良い点: 提案は規則と数字で再現でき、テストで固定できる。通知に生の値が出ない。利用者の事情は設定で表せる。提案できないときも不審な事実は残る
- コスト: daily の wafv2 のクエリが 3 本から lines + 6 本 (レートは日数分) に増える (`max_scan_gb` は効く)。既に配った読み取りロールには wafv2 の 4 つを足す必要がある
  (足さなければ waf-config だけが ACCESS_DENIED になり、waf_review が skip される)。配列の位置の上限 (トップレベル 3、グループ 8) を超えた一致は数え漏れる。
  ログの JSON の形 (配列の並び、`terminatingRuleType`) に依存するので、AWS が形を変えたら sandbox で確かめ直す
- aratam の Slack の節 (none の書式と LLM の書き起こし) は後続。それまでは report.json と report.md に出るだけ
