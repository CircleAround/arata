# 0070. 目印 (ラベル) を付けるための COUNT のルールを、BLOCK にするかの材料から分けて出す

- 日付: 2026-11-17
- 状態: 採用 (オーナーの承認。2026-11-17)

## 背景

waf_review の `count_rule_status` (ADR 0023) は、COUNT で動いているルールごとに一致の件数と「怪しい通信の割合」を、BLOCK にするかを人が計画する材料として出す。
ある利用者で、COUNT のルールの多くが、Bot Control などのマネージドのルールグループのカテゴリだと分かった。これらは後ろのルールが使うラベルを付けるために、
わざと COUNT にしている (公式の使い方の例どおり)。BLOCK にする候補ではないので、「怪しい N%」を出しても判断の材料にならない。

## 公式文書で確かめたこと (2026-11-17 に読んだ)

| 項目 | 内容 | 出典 |
|---|---|---|
| ルールのラベル | WebACL のルールの RuleLabels の完全な名前は `awswaf:<アカウント>:webacl:<WebACL の名前>:<名前空間…>:<名前>`。ルールグループの参照とマネージドのグループの文には付けられない | [1] [2] |
| COUNT とラベル | Count の action でも、ほかのルールが照合するラベルを付けられる | [3] |
| マネージドのラベル | `awswaf:managed:<vendor>:<グループ>:…`。例 `awswaf:managed:aws:core-rule-set:SizeRestrictions_Body`、`awswaf:managed:aws:bot-control:bot:category:http_library`。ラベルの大小文字はルール名と違うことがある | [1] [4] [5] |
| グループの中の COUNT | RuleActionOverrides で Count にしたルールは、その action のルールとして扱われる。公式の例は「グループのルールを Count にし、後ろのルールがグループのラベルで扱う」 | [6] [7] |
| DescribeManagedRuleGroup | `LabelNamespace` (グループのラベルの前の部分)、`AvailableLabels` (グループ単位の一覧。ルールとの対応は無い)、`Rules` (名前と action だけ)。action は `wafv2:DescribeManagedRuleGroup` (Read) | [8] [9] [10] |
| LabelMatchStatement | Scope が LABEL なら鍵は名前を含み、前の名前空間を省ける (省くと、照合するルールと同じ WebACL のラベルだけに一致する)。awswaf: から書けば完全な名前で一致する。NAMESPACE なら鍵は名前空間で、末尾が `:` | [11] [12] [13] |
| 評価の順 | ラベルを見られるのは、先に評価された (Priority が小さい) ルールのラベルだけ | [12] [14] |
| 入れ子 | LabelMatchStatement は And・Or・Not と、レートベース・マネージドのグループの scope-down の中に、どの深さにも入れられる | [12] [15] |

[1] https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-label-requirements.html
[2] https://docs.aws.amazon.com/waf/latest/APIReference/API_Rule.html
[3] https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
[4] https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
[5] https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html
[6] https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-group-override-options.html
[7] https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html
[8] https://docs.aws.amazon.com/waf/latest/APIReference/API_DescribeManagedRuleGroup.html
[9] https://docs.aws.amazon.com/waf/latest/APIReference/API_RuleSummary.html
[10] https://docs.aws.amazon.com/service-authorization/latest/reference/list_wafv2.html
[11] https://docs.aws.amazon.com/waf/latest/APIReference/API_LabelMatchStatement.html
[12] https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-label-match.html
[13] https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-label-match-examples.html
[14] https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-processing-order.html
[15] https://docs.aws.amazon.com/waf/latest/APIReference/API_Statement.html

## 決定

- **目印のルール** = COUNT のルール (グループの中の COUNT を含む) のうち、付けるラベルを後ろ (Priority が大きい) のルールの LabelMatchStatement が使っているもの。
  `count_rule_status` から外し、`about: label_rule` の observation (`reason: informational`) で出す。
  本文は「目印のルール: COUNT の X: 直近 N 日でラベル L を M 件付けた。使っているルール: Y」。evidence は `matches`・`matching_days`・`days`・`labels`・`consumers`。
  「怪しい通信」は出さない (BLOCK にするかの材料ではないため)。aratam の 2 通目は、COUNT のルールの行の中に「目印」の行として出す
- waf-config のスナップショットに、ルールの `labels` (RuleLabels の名前)・`label_matches` (`<LABEL|NAMESPACE>:<鍵>`。入れ子も見る)、WebACL の `label_prefix`、
  マネージドのグループの `label_namespace` (DescribeManagedRuleGroup の LabelNamespace) を足す
- 見分け方:
  - WebACL のルール: `label_prefix` + RuleLabels の名前を、後ろのルールの鍵と照合する (LABEL は完全一致か、前の名前空間を省いた鍵が区間の単位で後ろから一致。
    NAMESPACE はラベルの名前空間が鍵で始まるか (完全な名前)、鍵で終わるか (省いた鍵))
  - マネージドのグループの中のルール: どのルールがどのラベルを付けるかは API で分からないので、使われているラベルのうち `label_namespace` の下の部分を英数字だけにしたものが、
    ルール名を英数字だけにしたもので終わるときに、そのルールのラベルとみなす (CategoryHttpLibrary ↔ `bot:category:http_library`、SizeRestrictions_BODY ↔ `SizeRestrictions_Body`)。
    NAMESPACE の鍵は、その最後の区間でルール名が始まるとき (`signal:` ↔ SignalAutomatedBrowser)、またはグループの名前空間全体を覆うときに一致とみなす。
    グループ全体を COUNT にしたもの (OverrideAction Count) は、グループのどのラベルでも一致とみなす
- **見分けられないとき**は、今までどおり `count_rule_status` で出し、evidence に `label_rule: undetermined`、本文に「目印のルールかどうかは見分けられなかった」を足す:
  マネージドのグループのラベルの名前空間を読めなかった (`WAF_LABELS_UNKNOWN` の WARN)、自分のルールグループ (中のルールのラベルを読んでいない)、前の版が取ったスナップショット
- 読み取り専用ロールに `wafv2:DescribeManagedRuleGroup` を足す (Read。グループの定義を読むだけ)。拒否されても waf-config のソースは失敗にしない。doctor は試して、拒否なら warn

## 互換

- 報告 (report.json) の形は変えない。`proposals` の observation の `about` に新しい値 `label_rule` が増え、evidence の項目が増えるだけ (`about` は開いた語彙)。
  読む側 (aratam の古い版) は、知らない `about` を観察の 1 行として出す
- 目印のルールは `count_rule_status` から消える。`count_rule_status` の数で何かを数えていた利用者には、その分だけ減る (Release の本文に書く)
- 既に配った読み取り専用ロールには action を足す必要がある。足すまでは `WAF_LABELS_UNKNOWN` の WARN が出て、マネージドのグループの COUNT のルールは今までどおり出る
- 新しいログの code `WAF_LABELS_UNKNOWN` (足すのは互換)

## 検討した選択肢

- **ログの `labels` 項目 (付いたラベル) を Logs Insights で数える**: 採らない (今は)。ルールとラベルの対応がログからも直接は分からず、クエリが 1 本増える (読み取りが増える)。
  設定 (waf-config) だけで見分けられる範囲を先に入れる
- **AWS のマネージドのグループのルールとラベルの対応表を arata に持つ**: 採らない。公式文書の表は版で変わり、他の vendor のグループに効かない。名前の突き合わせで足りる範囲から始める
- **自分のルールグループの中のラベルも読む (`wafv2:GetRuleGroup`)**: この ADR では入れない。利用者のアカウントで自分のルールグループの COUNT が問題になったら足す

## 手間の見積もり

- スナップショットの項目・DescribeManagedRuleGroup・doctor・ロール: 0.5 日 / 見分け方と observation・aratam の行・文書: 1 日

## 未確認の点

- グループ全体を OverrideAction Count にしたとき、中のルールがラベルを付けるかを明言した文は見つからなかった (グループの中の評価は変わらないとある)。付くものとして扱う
- LabelMatchStatement の NAMESPACE で、前の名前空間を省いた鍵が、より深い名前空間のラベルに一致するか (`header:` が `header:encoding:utf8` に一致するか)。
  一致しないものとして扱う (見分けを控えめにする。外れても今までどおり BLOCK にするかの材料として出るだけ)
- マネージドのグループの名前の突き合わせで見分けられないラベル (`bot:name:<名前>` など、ルール名と形の違うもの)。実データで見分けの漏れを確かめる
