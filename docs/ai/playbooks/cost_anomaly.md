# cost_anomaly: 費用の異常 (急増)

## この指摘の意味

AWS Cost Anomaly Detection (利用者が作ったモニター) が費用の異常を検出した (daily)。採掘や漏洩した認証情報の悪用は、まず費用の急増として現れることがある。
arata は異常の判定を AWS に任せ、`cost-anomaly` のソースが直近 `lookback_days` 日に終わった (続いている) 異常を読む。費用の削減の提案はしない。

- 重大度は**予想に対する増加の割合** (影響額 / 予想額) で決める。固定の金額はサービスの規模で意味が変わるため:
  `medium_impact_ratio` (既定 0.5 = 予想の 1.5 倍) 以上で medium、`high_impact_ratio` (既定 1.0 = 2 倍) 以上で high。critical は出さない (費用だけでは侵害と言えない)
- 影響額が `min_impact_usd` (既定 10 USD) 未満は割合が大きくても出ない。予想額が無いときは割合を出せないので、下限以上なら medium
- コンソールで Feedback を「異常でない (NO)」「計画した活動 (PLANNED_ACTIVITY)」にした異常は出ない
- Key は異常の ID。続いている間は毎日観測されるが、重大度が上がるまで再報告しない
- data: `anomaly_id`、`monitor_arn`、`dimension_value` (サービスなど)、`start_date` / `end_date`、`total_expected_spend` (予想額)、`total_actual_spend` (実際の額)、
  `total_impact` (影響額)、`impact_ratio`、`total_impact_percentage`、`max_impact`、`max_score`、`feedback`、
  `root_causes` (`service`・`region`・`usage_type`・`linked_account` (ID)・`contribution`。最大 10 件)

## まず確かめること

1. 根本原因の資源が今も動いているか: `root_causes` のリージョン・サービス・使用タイプから資源を探す
   (例: `EU-BoxUsage:p3.16xlarge` なら `aws ec2 describe-instances --region eu-west-1 --filters Name=instance-type,Values=p3.16xlarge`)
2. 同じ時間帯の操作: `arata review --format json` で unused_region_activity (ふだん使わないリージョンでの作成)・principal_new_source・iam_changes を探す。
   CloudTrail は `aws cloudtrail lookup-events --region <リージョン> --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances --start-time <start_date>`
3. コンソールの Cost Anomaly Detection で異常の詳細 (日ごとの推移、根本原因の寄与) を見る。Cost Explorer でサービス・リージョン・使用タイプ別に絞る
4. 作業の記録 (リリース・キャンペーン・負荷試験・データの移行) と、利用者の事情 (context_file) に説明があるか

## 判断の分かれ目

- **正規の可能性が高い**: リリースや利用者の増加・計画した処理 (バッチ・移行・負荷試験) と時期が合う。ふだん使うリージョン・サービスの、既知の資源の増加
- **要対応**: 使っていないリージョン・使っていないサービス (GPU・大きなインスタンス・データ転送) の急増、作業の記録が無い、
  unused_region_activity や principal_new_source と同じ時間帯、増加の割合が大きく今も続いている (`end_date` が今日)

## 対処の選択肢

緊急度の順。資源の停止・設定の修正は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): 原因の資源を作った主体の認証情報を止め、資源を止める (資源の ID と作成の記録を残してから)。AWS サポートに連絡する
2. **承認**: 対象外 (主体ではなく費用の指摘)
3. **expected_denied**: 対象外
4. **ack / snooze / Feedback**: 計画した活動ならコンソールで Feedback を「計画した活動」にする (以後は出ない) か ack する。一時的な増加の間は snooze
5. **設定の修正**: 誤報が多ければ `checks.cost_anomaly.medium_impact_ratio` / `high_impact_ratio` / `min_impact_usd` を見直す。
   モニターの範囲 (サービス・連結アカウント・コストカテゴリ) はコンソールで調整する。予算 (AWS Budgets) のアラートも併用できる

## やってはいけないこと

- 費用の削減の提案 (リザーブドインスタンス・Savings Plans・サイズの見直しなど) をしない。このチェックは急増の兆候を伝えるだけ
- 金額だけで重大さを書かない (予想額・実際の額・割合を並べて伝える)
- 根本原因を確かめずに「正規の増加」と断定しない。LLM が資源を止めない・Feedback を付けない (提案まで)
