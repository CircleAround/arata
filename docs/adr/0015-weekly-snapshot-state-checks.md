# 0015. 週次チェックはアカウントの状態をスナップショットとして取り、成功したときだけ丸ごと置き換えて state 型で比べる

- 日付: 2026-10-21
- 状態: 採用

## 背景

Step 3 の週次チェック (credential_hygiene / guardduty_findings / posture / access_analyzer) は、CloudTrail のような「窓内の出来事」ではなく
アカウントの「今の状態」(IAM 認証情報レポート、GuardDuty の findings、姿勢の項目、Access Analyzer の findings) を見る。
状態は「直った」ことにも価値がある (ADR 0005 の state 型)。一方で、観測されなかったことを「解消」と読むと、
**読み取りロールから権限が外れた・API が失敗した**だけで、未対応の指摘がすべて resolved として報告されてしまう。監査エンジンとして最悪の誤り。

## 決定

- 取得は既存の Collector → ストア → Check の流れに乗せる (Check から AWS を呼ばない)。source.kind を 4 つ足す:
  `iam-credential-report` / `guardduty` / `access-analyzer` / `posture`。1 source = 1 つの権限の塊なので、AccessDenied は
  既存の仕組みどおり「そのソースだけ失敗 → 対応するチェックだけ skip (coverage に action)、他は続行」になる
- 取ったものは `record.SnapshotItem` (kind, source, key, data) として出し、`snapshot_items` テーブルに保存する。
  **収集が成功したときだけ (kind, source) 単位で丸ごと置き換える** (0 件なら空にする)。失敗したときは前回のまま残し、チェックは skip する
  (state 型でも観測が無いので resolved にならない)
- 収集は成功したがその種類が取れない状態 (GuardDuty が無効、アナライザーが無い) は、collector が理由を返し、チェックを skip して
  `coverage.checks_skipped` に理由を出す。スナップショットは置き換えない。GuardDuty が無効であること自体は posture が finding として報告する
- posture は 5 系統の API (CloudTrail・GuardDuty・IAM・S3 Control・STS) を使うので、一部だけ拒否されても他の項目は取る。
  取れなかった項目は `unknown` として保存し、posture チェックは**その項目の前回の finding (open / acked / snoozed) をそのまま観測し直して維持**する。
  問題は `coverage.sources_failed` に `partial: true` と `action` 付きで出し、標準エラーに ACCESS_DENIED、終了コード 3
- 週次チェックはすべて `ModeState`。Key と Fingerprint は設計書 7 章。毎週変わる値 (未使用の日数など) は Data に残し Fingerprint に入れない。
  GuardDuty の `count` は「増えた」ことを知らせたいので Fingerprint に入れる (changed)
- `iam:GenerateCredentialReport` は書き込み系 (レポートの生成のみ)。拒否されても `GetCredentialReport` で 4 時間以内のレポートが取れればそれを使い、
  生成時刻を Data の `report_generated_at` に残す。doctor は Generate を試さない
- 週次のソースは週次のプロファイルの run でだけ引く (プロファイルのチェックが必要とするレコードを出すソースだけを収集する既存の仕組み)。hourly / daily では API を呼ばない

## 検討した選択肢

- **Check の Evaluate から AWS を直接呼ぶ**: 取得の失敗と「状態が無い」の区別がチェックごとの実装に散る。ストアに残らないので evaluate や期間レポートで使えない。却下
- **アカウント単位で 1 つの source kind (`aws-account`) にまとめる**: 設定は短いが、1 つの権限不足で 4 チェックがすべて skip になる。権限の塊ごとに分けた
- **スナップショットを時刻付きで積み、最新のものを読む**: 0 件のスナップショット (全部直った) を表せず、古い項目が残る。成功時の丸ごと置き換えにした
- **posture の部分失敗をソース全体の失敗にする**: 実装は単純だが、S3 の権限が 1 つ無いだけでルート MFA などの検査が全部止まる。項目単位で維持する形にした
- **設計書 5-2 の `posture` テーブル (check, resource, value)**: 4 種類で同じ形 (key と data) に収まるので、`snapshot_items` 1 つにまとめた

## 結果

- 権限を外された・API が落ちたときに、未対応の指摘が誤って「解消」と報告されない
- 権限不足は doctor (ng 行と必要な action の一覧) と coverage (sources_failed の action) の両方で見える
- 週次のソースを足すと設定の sources が 4 行増える (雛形は有効で出す)
- GuardDuty の High を hourly で鳴らす (設計書 3 章の表) はまだ無い。guardduty_findings は weekly のみ
