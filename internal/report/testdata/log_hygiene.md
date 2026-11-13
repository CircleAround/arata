# arata weekly レポート (acme)

- 期間: 2026-10-14T09:00:00Z 〜 2026-10-21T09:00:00Z
- 新規 3 / 変化 0 / 再発 0 / 解消 0 / 未対応 0 / 最大重大度 **medium**

## 新規 (3)

- **[medium]** ロググループ prod-app のログに、隠されていない送信項目 (address, name, zipcode) が 446 行 (直近 7 日。保持期間は無期限) `log_hygiene`
  - count: 446
  - fields: address 137, name 175, zipcode 134
  - kind: unfiltered_param
  - log_group: prod-app
  - retention: never
  - window_hours: 168
  - id: f-001 (初出 2026-10-21T09:00:00Z)
- **[medium]** summary `log_hygiene`
  - count: 1
  - fields: tel 1
  - kind: unfiltered_param
  - id: f-003 (初出 2026-10-21T09:00:00Z)
- **[low]** ロググループ prod-app のログに、debug の SQL の出力が 403,003 行 (直近 7 日。保持期間は 30 日) `log_hygiene`
  - count: 403003
  - kind: debug_sql
  - log_group: prod-app
  - retention: set
  - retention_days: 30
  - window_hours: 168
  - id: f-002 (初出 2026-10-21T09:00:00Z)

## 変化 (0)

変化した指摘はありません。

## 再発 (0)

再発した指摘はありません。

## 解消 (0)

解消した指摘はありません。

## 未対応 (0)

未対応の指摘はありません。

## カバレッジ

- 取得できたソース: app_prod
- 取得に失敗したソース: なし
- 実行したチェック: log_hygiene
- スキップしたチェック: なし
