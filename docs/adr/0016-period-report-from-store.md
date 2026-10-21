# 0016. 期間レポートは収集せずストアだけから作り、そのために finding の状態遷移を履歴として残す

- 日付: 2026-10-21
- 状態: 採用

## 背景

月次・四半期・任意期間のレポート (設計書 3 章) は顧客への報告と棚卸しに使う。期間内の新規・再発・解消の一覧が要るが、
findings テーブルは「今の状態」しか持たない (first_seen / last_changed / status)。再発や「期間内に一度 open になって解消したもの」は復元できない。
また、過去の期間を AWS から引き直すと、CloudTrail LookupEvents の 90 日の上限・Logs Insights の費用・当時の allowlist との差で、日々のレポートと違う結果になる。

## 決定

- `arata report --from YYYY-MM-DD --to YYYY-MM-DD` (UTC、両端を含む) は**収集も評価もせず、ストアだけから作る**。`--month 2026-10` はその月の初日〜末日の糖衣
- finding の状態遷移 (new / changed / recurred / resolved) を `finding_events` テーブルに追記する。記録するのは
  - run / evaluate の差分判定の結果 (run_id とプロファイル付き)
  - 人の resolve / approve、allowlist の編集による一括解消 (run_id 空)
  Severity / Summary / Data はその時点の値を写す (後で finding が変わっても当時の内容で読める)
- 履歴は schema 4 以降の最初の run の開始時刻 (`meta.history_since`) から。期間の一部がそれより前にかかる場合は、
  レポートの先頭 (`notes`) に「YYYY-MM-DD 以前は状態遷移の履歴なし」と出す
- 内容: 期間内の new / recurred / changed / resolved の一覧、重大度別件数 (新規・再発した finding の重複なし)、新規主体 (principals.first_seen が期間内)、
  未対応の残存 (生成時点の open / acked)、アプリ層の日次推移 (metrics を日 × 指標で合計)、取れなかった run (partial / failed と、
  同じプロファイルの連続する run の間が窓の 2 倍以上空いた RUN_MISSED)。severity=info は数えない
- 期間内に run が 1 つも無いプロファイルは RUN_MISSED にしない (使っていないプロファイルで鳴らないように)

## 検討した選択肢

- **期間を指定して AWS から引き直し、評価し直す**: 90 日を超える期間が作れず、費用がかかり、日々のレポートと結果がずれる。却下
- **runs.stats や保存済みの日次レポート (reports/*.json) を集計する**: 最新しか保存しておらず、人の resolve も入らない。却下
- **findings の first_seen / last_changed だけで近似する**: 再発と、期間内に変化した回数が分からない。却下
- **raw JSONL から再生して遷移を復元する**: allowlist や設定がその後変わっていると当時の判定にならない。却下

## 結果

- 月次レポートを任意の時点でいつでも作り直せる (同じストアなら同じ結果)
- finding_events は run ごとに数行ずつ増える。保持期間 (prune) は後続の Step で findings と同じ扱いにする
- schema 4 にする前のストアは、移行後の最初の run 以前の遷移が数えられない (notes で明示する)
