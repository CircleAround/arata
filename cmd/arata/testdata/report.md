# arata daily レポート (acme)

- 期間: 2026-10-21T09:00:00Z 〜 2026-10-22T09:00:00Z
- 新規 3 / 変化 0 / 再発 0 / 解消 0 / 未対応 0 / 最大重大度 **critical**

## 新規 (3)

- **[critical]** ルートアカウント arn:aws:iam::123456789012:root が 198.51.100.8 から 1 件の操作 `root_usage`
  - count: 1
  - event_names: [ConsoleLogin]
  - first_time: 2026-10-22T08:00:00Z
  - ips: [198.51.100.8]
  - last_time: 2026-10-22T08:00:00Z
  - principal: arn:aws:iam::123456789012:root
  - id: id-006 (初出 2026-10-22T09:00:00Z)
- **[high]** 既知リストに無い自アカウントの user/mallory が自アカウントのロール Admin を 1 回引き受け (内部、MFA 不明) `unknown_assume_role`
  - allowlist_status: unknown
  - caller: arn:aws:iam::123456789012:user/mallory
  - caller_account: 123456789012
  - caller_kind: user
  - count: 1
  - direction: internal
  - event_names: [AssumeRole]
  - first_time: 2026-10-22T07:00:00Z
  - ips: [198.51.100.7]
  - last_time: 2026-10-22T07:00:00Z
  - mfa: unknown
  - role_account: 123456789012
  - role_arn: arn:aws:iam::123456789012:role/Admin
  - id: id-007 (初出 2026-10-22T09:00:00Z)
- **[medium]** 新規の主体 arn:aws:iam::123456789012:user/mallory (user) `new_principal`
  - allowlist_status: unknown
  - count: 1
  - first_seen: 2026-10-22T07:00:00Z
  - ips: [198.51.100.7]
  - kind: user
  - last_seen: 2026-10-22T07:00:00Z
  - id: id-005 (初出 2026-10-22T09:00:00Z)

## 変化 (0)

変化した指摘はありません。

## 再発 (0)

再発した指摘はありません。

## 解消 (0)

解消した指摘はありません。

## 未対応 (0)

未対応の指摘はありません。

## カバレッジ

- 取得できたソース: trail
- 取得に失敗したソース: なし
- 実行したチェック: access_denied, ai_path_usage, defense_evasion, iam_changes, new_principal, principal_new_source, public_exposure, root_usage, secret_access, unknown_assume_role
- スキップしたチェック:
  - cost_anomaly: no cost_anomaly source
  - endpoint_abuse: no http_access source
  - login_bruteforce: no http_access source
  - probe_paths: no http_access source
  - unused_region_activity: no unused_region_event source
  - waf_block_trend: no waf_action source
