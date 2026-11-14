# 実際に起きた攻撃と、arata で見えるもの

公開された攻撃の事例ごとに、「攻撃のどの段階が、arata のどのチェックで、どの記録から、どう見えるか」と「どの段階は見えないか」をまとめた対応表の入口。
利用者が「なぜこのチェックを入れるか」「入れても何が見えないか」を判断するための文書。判断の経緯は [ADR 0058](adr/0058-threat-coverage-table.md)。

本文はバイナリに埋め込んであり、エンジンの版と揃う。`arata help ai threats` (一覧) と `arata help ai threats <id>` (事例) で読める (`--format json` で節ごと)。

## 読み方

- 事例ごとに、**出典** (URL と日付)、**攻撃の段階と arata で見えるもの** (表)、**arata では見えないもの**、**予定している改善**を書いている
- 表の「出典の書き方」は、その段階を出典がどう書いているかの区別:

  | 語 | 意味 |
  |---|---|
  | 観測 | 出典が、被害の環境や公開の記録で実際に見たと書いている |
  | 機能 | 出典が、スクリプトや道具にその機能があるとだけ書いている (被害の環境で起きたとは書いていない) |
  | 推定 | 出典が、推定・評価として書いている |
  | 記述 | 出典が攻撃者の手口として書いているが、観測か機能かを明示していない |
  | 想定 | 出典には無い。前の段階の結果として起こり得ることを、arata の側で想定したもの |

- 「見えるチェック」は、そのチェックを設定の `profiles` に入れ、要る記録を集めているときの話 (`arata profiles`、`arata help ai logs`)
- **表に載っていることは、検知できるという保証ではない。** 既知リストの状態・平常帯・周期によって出ないことがある。条件は各事例の表に、出ない場合は「arata では見えないもの」に書いてある
- arata が読むのは AWS の記録 (CloudTrail の管理イベント、CloudWatch Logs のアクセスログ、アカウントの設定) だけ。GitHub・ID プロバイダ・SaaS の中、ホストやコンテナの中、S3 などのデータイベントは読まない

## 事例の一覧

| 事例 | 公開日 | 内容 | 見えるチェック | 本文 |
|---|---|---|---|---|
| wfx-loot-2026-11 | 2026-11-12 | 乗っ取った GitHub アカウントから CI の秘密を盗むスクリプトを push する ("wfx-loot") | access_analyzer, iam_changes, new_principal, principal_new_source, unknown_assume_role | `arata help ai threats wfx-loot-2026-11` |
| ghostaction-2026-10 | 2026-10-07 | 乗っ取った GitHub アカウントに「Security Audit」のワークフローを足し、secrets と履歴の認証情報を送る (GhostAction) | access_denied, credential_hygiene, principal_new_source, unused_region_activity | `arata help ai threats ghostaction-2026-10` |
| env-extortion-2024-08 | 2024-08-15 | 公開された .env から得たアクセスキーで、管理者のロールを作り、S3 のデータを消して身代金を求める | access_denied, iam_changes, new_principal, principal_new_source, probe_paths, unused_region_activity | `arata help ai threats env-extortion-2024-08` |
| lucr-3-2023-09 | 2023-09-20 | ID プロバイダの乗っ取りから AWS に入り、秘匿値を集め、IAM に居座り、検知を止める (LUCR-3 / Scattered Spider) | defense_evasion, iam_changes, new_principal, principal_new_source, secret_access | `arata help ai threats lucr-3-2023-09` |
| scarleteel-2023-02 | 2023-02-28 | コンテナからインスタンスのロールの認証情報を盗み、CloudTrail を止めて、データと別アカウントのキーを取る (SCARLETEEL) | access_denied, defense_evasion, guardduty_findings, iam_changes, principal_new_source | `arata help ai threats scarleteel-2023-02` |

本文のファイル (GitHub で読むとき):

- [wfx-loot-2026-11](ai/threats/wfx-loot-2026-11.md)
- [ghostaction-2026-10](ai/threats/ghostaction-2026-10.md)
- [env-extortion-2024-08](ai/threats/env-extortion-2024-08.md)
- [lucr-3-2023-09](ai/threats/lucr-3-2023-09.md)
- [scarleteel-2023-02](ai/threats/scarleteel-2023-02.md)

## チェックごとの事例

そのチェックが当たる段階を持つ事例。各チェックの対処手順 (`arata help ai playbook <check>`) の「関連する事例」からも案内している。

| チェック | 事例 |
|---|---|
| access_analyzer | wfx-loot-2026-11 |
| access_denied | ghostaction-2026-10, env-extortion-2024-08, scarleteel-2023-02 |
| ai_path_usage | 対応する公開の事例はまだ無い |
| cost_anomaly | 対応する公開の事例はまだ無い |
| credential_hygiene | ghostaction-2026-10 |
| defense_evasion | lucr-3-2023-09, scarleteel-2023-02 |
| endpoint_abuse | 対応する公開の事例はまだ無い |
| guardduty_findings | scarleteel-2023-02 |
| iam_changes | wfx-loot-2026-11, env-extortion-2024-08, lucr-3-2023-09, scarleteel-2023-02 |
| log_hygiene | 対応する公開の事例はまだ無い |
| login_bruteforce | 対応する公開の事例はまだ無い |
| new_principal | wfx-loot-2026-11, env-extortion-2024-08, lucr-3-2023-09 |
| posture | 対応する公開の事例はまだ無い |
| principal_new_source | wfx-loot-2026-11, ghostaction-2026-10, env-extortion-2024-08, lucr-3-2023-09, scarleteel-2023-02 |
| probe_paths | env-extortion-2024-08 |
| public_exposure | 対応する公開の事例はまだ無い |
| root_usage | 対応する公開の事例はまだ無い |
| secret_access | lucr-3-2023-09 |
| unknown_assume_role | wfx-loot-2026-11 |
| unused_region_activity | ghostaction-2026-10, env-extortion-2024-08 |
| waf_block_trend | 対応する公開の事例はまだ無い |
| waf_review | 対応する公開の事例はまだ無い |

## 保守の決まり

- 新しいチェックを足す PR では、そのチェックで見える公開の事例を `docs/ai/threats/<id>.md` に足すか、playbook の「関連する事例」に「対応する公開の事例はまだ無い」と書く
- 事例には、公開日と、日付の付いた出典の URL (一次情報か、調査した会社の記事) が必ずある。出典を自分で読んで確かめられないものは入れない
- 事例の ID は `<名前>-<公開の年>-<月>`。見出しは固定 (概要 / 出典 / 攻撃の段階と arata で見えるもの / arata では見えないもの / 予定している改善)
- 表に書くチェックの名前は、実在するチェックだけ。これから作るものは「予定している改善」に、予定と分かるように書き、実装した PR で表へ移す
- チェックの重大度や条件を変えたら、そのチェックが出てくる事例の表も直す
- 出典の文は長く写さない (要約と短い引用)。利用者の環境で見た事実は書かない。攻撃の基盤の値 (IP など) は書き写さず、出典へ案内する
- 上の 2 つの表は事例の本文から作る。事例を足す・直すと `go test ./docs/ai/` が、貼り替える表を出す
- どれもテストが確かめる (`docs/ai/threats_test.go`、`internal/checks/playbook_test.go`)
