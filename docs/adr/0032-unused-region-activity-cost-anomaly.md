# 0032. ふだん使わないリージョンでの書き込み (`unused_region_activity`) を専用のソースで引き、費用の急増 (`cost_anomaly`) は AWS Cost Anomaly Detection の結果を予想に対する割合で読む

- 日付: 2026-11-03
- 状態: 採用

## 背景

漏洩した認証情報の悪用 (仮想通貨の採掘のためのインスタンス作成など) は、利用者が見ないリージョンで行われることが多い。
`cloudtrail-lookup` は設定の `regions` (ふだん使うリージョン) だけを引くので、それ以外のリージョンの操作は見えなかった (ADR 0027 の結果)。
また、悪用はまず費用の急増として現れることがあるが、arata は費用を見ていなかった。設計書 7 章の未実装の `foreign_region` (ap-northeast-1 以外のイベントを medium) はこの 2 つに置き換える。

## 決定

- source.kind を 2 つ足す。1 source = 1 つの権限の塊 (ADR 0015) なので、新しい権限が拒否されてもそのチェックだけが skip される
  - `cloudtrail-unused-regions`: 毎回 `account:ListRegions` (ENABLED / ENABLED_BY_DEFAULT) から、全 `cloudtrail-lookup` の `regions` を除いたリージョンを対象にする (設定に regions を書かせない。
    cloudtrail-lookup が無ければ設定の誤り)。各リージョンで LookupEvents を `ReadOnly=false` で窓 (再走査を含む) の分だけ引き、AWS のサービス以外の主体の書き込みを (失敗も) events に残す。
    レコードの種類は `unused_region_event` (このソースが失敗したら unused_region_activity を skip し、「0 件」と誤らない)
  - `cost-anomaly`: スナップショット。us-east-1 の Cost Explorer で GetAnomalyMonitors (モニターが無ければ Unavailable で skip、GetAnomalies は呼ばない) と、
    直近 `lookback_days` 日に終わった異常の GetAnomalies (影響額 >= `min_impact_usd` をサーバー側で絞る)
- 未使用リージョンのイベントは events の source 列で分け、unused_region_activity だけが見る。engine は他のチェックに source を除いた Query を渡す。
  principal_seen と主体の活動の日次集計も出さない。既存のチェック (defense_evasion・public_exposure・access_denied・new_principal・principal_new_source・iam_changes) の結果が変わらないことはテストで固定した
- `unused_region_activity` (daily、event、Key `<リージョン>|<主体>`): 成功した書き込みは high、計算資源の作成 (`compute_apis`) なら critical、計算資源の作成の試行 (失敗) は medium、他の失敗は報告しない。
  `ignore_event_sources` (グローバルサービス) は数えない。`tags: [deploy]` の承認済み主体なら 1 段下げる
- `cost_anomaly` (daily、event、Key は異常の ID): 重大度は予想に対する増加の割合 (TotalImpactPercentage、無ければ影響額 / 予想額) で決める。
  `medium_impact_ratio` (0.5 = 予想の 1.5 倍) 以上で medium、`high_impact_ratio` (1.0 = 2 倍) 以上で high。影響額が `min_impact_usd` (10 USD) 未満は報告しない。予想額が無ければ medium。
  Feedback が NO / PLANNED_ACTIVITY の異常は報告しない。critical は出さない。費用の削減の提案はしない
- 読み取りロールに `account:ListRegions`・`ce:GetAnomalyMonitors`・`ce:GetAnomalies` を足す (読み取りだけ)。doctor は権限と、cost の行 (LookupEvents は無料 / Cost Explorer の見込み) を出す
- 雛形: `cloudtrail-unused-regions` は有効 (無料)、`cost-anomaly` はコメント (有料で、モニターを作ってから使う)。2 つのチェックは daily のプロファイルに入る

## 検討した選択肢

- **cloudtrail-lookup の regions に全リージョンを書いてもらう**: 設定だけで済むが、全リージョンの読み取りも引くのでリクエストが数倍になり、保存・判定の対象も変わる (既存の平常帯が崩れる)。
  使っていないリージョンを「書き込みだけ」引く方が安い。却下
- **cloudtrail-lookup の collector に「未使用リージョンも引く」を足す**: ソースは 1 つで済むが、ListRegions の拒否で CloudTrail 全体が失敗扱いになり、既存のチェックが skip される。別のソースにした
- **未使用リージョンのイベントを既存のチェックにも見せる**: 公開設定の変更なども拾えるが、同じイベントが unused_region_activity と二重に鳴り、access_denied の平常帯も変わる。
  使っていないリージョンの書き込みは種類を問わず 1 つの指摘で十分なので分けた
- **failure (拒否) もすべて報告する**: 権限の列挙は access_denied の領分で、ノイズの元になる。計算資源の作成の試行だけを medium にした
- **費用の重大度を固定の金額 (例 100 USD / 1000 USD) で決める**: 分かりやすいが、サービスの規模で意味が変わる (月 50 USD の環境と月 5 万 USD の環境)。割合で決め、金額は小さすぎる異常を除く下限にだけ使う
- **arata が Cost Explorer の日ごとの費用から平常帯を作る**: 利用者がモニターを作らずに済むが、GetCostAndUsage の呼び出しが増え (有料)、AWS の異常検出の再実装になる。AWS の結果を読むだけにした
- **cost_anomaly を state にする**: 異常が `lookback_days` の外に出たときに「解消」と報告してしまう。event にし、続く間は still_open、重大度が上がれば changed にした

## 結果 (良い点・引き受けるコスト)

- 使っていないリージョンでの悪用と費用の急増を日次に知らせられる。LookupEvents は無料で、使っていないリージョンはふつう 1 回ずつ (15 前後のリージョンで 15 回ほど。レート制限の 2 回/秒で約 8 秒)
- Cost Explorer の API は 1 リクエスト 0.01 USD (GetAnomalies が対象かは公式に明記が無いので対象とみなした)。daily で 1 回 2 リクエスト、月 0.6 USD ほど。doctor も約 0.02 USD
- 既に配ったロールには 3 つの action を足す必要がある (無ければそのソースだけ ACCESS_DENIED、終了コード 3)
- cost_anomaly はモニターを利用者が作るまで skip される。異常の発生は試験できないので、判定はテストのフェイクで固定し、sandbox では権限とモニターの検出だけを確かめる
- us-east-1 を cloudtrail-lookup の regions に入れていない環境では、グローバルサービスの書き込みを `ignore_event_sources` で除く (既定に IAM・STS など)
