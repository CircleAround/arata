# arata 期間レポート (acme)

- 期間: 2026-10-01 〜 2026-10-31 (UTC、両端を含む)
- **注意**: 2026-10-21 以前は状態遷移の履歴なし (履歴は 2026-10-21T09:00:00Z の run から記録)。それより前の new / changed / recurred / resolved は数えていない
- 新規 3 / 変化 0 / 再発 0 / 解消 1 / 未対応の残存 2 (info は数えない)
- 期間内に新規・再発した指摘の重大度: critical 1 / high 1 / medium 1

## 新規 (3)

- 2026-10-22T09:00:00Z **[medium]** 新規の主体 arn:aws:iam::123456789012:user/mallory (user) `new_principal` (daily、id id-003)
- 2026-10-22T09:00:00Z **[critical]** ルートアカウント arn:aws:iam::123456789012:root が 198.51.100.8 から 1 件の操作 `root_usage` (daily、id id-004)
- 2026-10-22T09:00:00Z **[high]** 既知リストに無い arn:aws:iam::123456789012:user/mallory が arn:aws:iam::123456789012:role/Admin を 1 回引き受け `unknown_assume_role` (daily、id id-005)

## 再発 (0)

ありません。

## 変化 (0)

ありません。

## 解消 (1)

- 2026-10-22T10:00:00Z **[critical]** ルートアカウント arn:aws:iam::123456789012:root が 198.51.100.8 から 1 件の操作 `root_usage` (人の操作 / allowlist、id id-004)

## 新規の主体 (2)

| 主体 | 種類 | 初出 | 状態 |
|---|---|---|---|
| arn:aws:iam::123456789012:user/mallory | user | 2026-10-22T07:00:00Z | unknown |
| arn:aws:iam::123456789012:root | root | 2026-10-22T08:00:00Z | unknown |

## 未対応の残存 (2)

- **[high]** 既知リストに無い arn:aws:iam::123456789012:user/mallory が arn:aws:iam::123456789012:role/Admin を 1 回引き受け `unknown_assume_role` (open、初出 2026-10-22T09:00:00Z、id id-005)
- **[medium]** 新規の主体 arn:aws:iam::123456789012:user/mallory (user) `new_principal` (open、初出 2026-10-22T09:00:00Z、id id-003)

## アプリ層の日次推移 (UTC)

日次集計はありません (cloudwatch-logs ソースが無いか、期間内に集計していない)。

## 実行の状況

- daily: run 2 (ok 2 / partial 0 / failed 0)
- 取れなかった run:
  - daily `RUN_MISSED` 2026-10-22T09:00:00Z 〜 2026-10-25T10:00:00Z (3.0 日 空いた (窓 24 時間))
  - daily `RUN_MISSED` 2026-10-25T10:00:00Z 〜 2026-11-01T00:00:00Z (6.6 日 空いた (窓 24 時間))
