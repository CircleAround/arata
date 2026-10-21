# 0005. チェックをイベント型と状態型に分け、差分判定の挙動を変える

- 日付: 2026-10-21
- 状態: 採用

## 背景

差分判定を全チェック共通で「観測があれば new / changed / still_open、無くなれば resolved」とすると、
ルート利用や IAM 変更のような**窓内の出来事**を扱うチェックで次の問題が出る。

- 翌日の窓に無いだけで「解消」として報告され、意味を成さないノイズになる
- 継続して観測される主体は件数や時刻が毎回変わるため、毎回「変化」として鳴る

一方、新規主体・設定不備・GuardDuty findings のような**状態**は、「解消した」ことにも価値がある。

## 決定

- `Check` は `Mode()` で `event` か `state` を宣言する
  - event: root_usage, iam_changes, unknown_assume_role, secret_access_unknown, console_login など
  - state: new_principal, posture_*, credential_hygiene, access_analyzer, guardduty_findings など
- event 型の finding は、窓内に観測されなくても resolved にしない (open のまま、レポートには出さない)。
  再観測されたら `recurred` として報告する
- state 型は従来どおり resolved を報告する
- `changed` の判定は `Observation.Fingerprint` (安定した要素だけ: 重大度、送信元 IP 集合、対象など) で行う。
  件数や初回/最終時刻は Data に残して根拠として表示するが、変化判定には使わない
- 「新規」の状態はチェック単位で持ち、周期ごとには持たない。hourly で報告済みの事象は daily で二重に鳴らない

## 検討した選択肢

- チェックごとに差分の扱いを実装させる: 履歴の意識がチェックに漏れ、テストが散る。却下
- event 型の finding を窓ごとに別 Key にする (Key に日付を含める): 「再発」が追えず、同じ事象が毎日 new になる。却下

## 結果

- report.json の findings に `recurred` 配列が加わる
- チェック実装者は Fingerprint に何を入れるかを考える必要がある (設計書 7 章にチェックごとの指針を書く)
