# arata 期間レポート (acme)

- 期間: 2026-10-01 〜 2026-10-31 (UTC、両端を含む)
- **注意**: 2026-10-05 以前は状態遷移の履歴なし (履歴は 2026-10-05T09:00:00Z の run から記録)。それより前の new / changed / recurred / resolved は数えていない
- 新規 2 / 変化 1 / 再発 1 / 解消 2 / 未対応の残存 2 (info は数えない)
- 期間内に新規・再発した指摘の重大度: critical 1 / high 1

## 新規 (2)

- 2026-10-06T09:00:00Z **[critical]** ルートユーザーの利用 `root_usage` (daily、id f1)
- 2026-10-07T09:00:00Z **[high]** ルートユーザーに MFA が無い `posture` (weekly、id f2)

## 再発 (1)

- 2026-10-20T09:00:00Z **[critical]** ルートユーザーの利用 `root_usage` (daily、id f1)

## 変化 (1)

- 2026-10-14T09:00:00Z **[medium]** GuardDuty: Recon (4 回) `guardduty_findings` (weekly、id f4)

## 解消 (2)

- 2026-10-14T09:00:00Z **[high]** ルートユーザーに MFA が無い `posture` (weekly、id f2)
- 2026-10-21T03:00:00Z **[medium]** 新規の主体 `new_principal` (人の操作 / allowlist、id f5)

## 新規の主体 (1)

| 主体 | 種類 | 初出 | 状態 |
|---|---|---|---|
| 外部アカウント 111122223333 | unknown | 2026-10-09T02:00:00Z | unknown |

## 未対応の残存 (2)

- **[critical]** ルートユーザーの利用 `root_usage` (open、初出 2026-10-06T09:00:00Z、id f1)
- **[medium]** GuardDuty: Recon (4 回) `guardduty_findings` (acked、初出 2026-10-02T09:00:00Z、id f4)

## アプリ層の日次推移 (UTC)

| 日 | probe_hits | sign_in_failures |
|---|---:|---:|
| 2026-10-06 | 0 | 123 |
| 2026-10-07 | 9 | 0 |

## 実行の状況

- daily: run 4 (ok 2 / partial 1 / failed 1)
- weekly: run 4 (ok 4 / partial 0 / failed 0)
- 取れなかった run:
  - daily `partial` 2026-10-07T09:00:00Z (失敗したソース 1)
  - daily `RUN_MISSED` 2026-10-07T09:00:00Z 〜 2026-10-20T09:00:00Z (13.0 日 空いた (窓 24 時間))
  - daily `RUN_MISSED` 2026-10-20T09:00:00Z 〜 2026-10-31T09:00:00Z (11.0 日 空いた (窓 24 時間))
  - daily `failed` 2026-10-31T09:00:00Z (check new_principal: boom)
