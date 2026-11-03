# 0033. `arata rebuild` は raw から作れる表だけを作り直し、作れないものは既存の SQLite から引き継ぐ。raw には rebuild に要る印を足す

- 日付: 2026-11-04
- 状態: 採用

## 背景

二層ストア (ADR 0003) では `audit.sqlite` を「raw JSONL から再構築できる派生物」としてきたが、`arata rebuild` は未実装だった。
S3 ストア (`store: s3://`。後の ADR) では SQLite を実行のたびに出し入れするので、SQLite が壊れた・失われたときの戻し方として rebuild が先に要る。

実装にあたって raw と SQLite を突き合わせると、次のものは raw からは作れない、または raw だけでは同じ結果にならないことが分かった。

- **raw に無いもの**: `runs` (差分判定の窓の基準と履歴)、`findings` (差分判定の状態、ack / snooze と `suppressed_severity`)、`finding_events` (期間レポートの元)、
  `meta` (`history_since`)、`principals.status` (approved / expired / baseline。init のベースラインの印を含む)
- **raw だけでは区別できなかったもの**:
  1. スナップショット (ADR 0015) は「収集が成功したら (kind, source) を丸ごと置き換える」。成功して 0 件なら表は空になるが、raw には何も書かれない
     (例: GuardDuty の finding が全部なくなった → rebuild すると古い finding が戻る)。逆に途中で失敗した収集の項目は raw に書かれるが、表は置き換えない
  2. `principal_ips.count` は再走査の分 (`rescan_count`) を「(arn, ip) の行を初めて作るとき」だけ足す (ADR 0013)。同じソースの中は時刻が単調なので行順で決まるが、
     別のソース (リージョンごとの cloudtrail ソースなど) に同じ主体 × IP が出ると、どちらが先だったかが raw から分からない

## 決定

- **raw に印を足す (後方互換)**
  - `principal_seen` に `collected_at` (収集した run の時刻。engine が付ける) を足す。rebuild は (collected_at, 設定のソースの順, 行順) で「最初の記録」を決める
  - スナップショットを置き換えたら、raw に `snapshot_replaced` の行 (`snapshot_kind`・`source`・`time`・`count`) を書く (`store.ReplaceSnapshot` が書く)。
    rebuild は (kind, source) ごとに最後の印の収集の項目だけを入れる (0 件の置き換えも再現し、失敗した収集の項目は入れない)
  - これらが無い以前の版の raw は近似する (principal_seen は時刻の順、スナップショットは時刻が最大の収集) し、近似したことを警告に出す
- **raw 由来の表** (`events`・`principals`・`principal_ips`・`metrics`・`snapshot_items`) は記録したときと同じ規則で入れ直す
  (events は event_id ごとに最初に収集した行、metrics は行順に置き換え、principals / principal_ips の初出・最終観測は保存と同じ文字列の MIN / MAX)
- **raw に無いもの** は、既定では既存の `audit.sqlite` から引き継ぐ (Open と同じ移行を通してから読む)。主体の状態は ARN ごとに引き継ぎ、既存に無い主体は unknown
  (次の run が allowlist と同期する)。既存の SQLite が無い・読めないときは `STORE_CORRUPT` で止め、`--from-scratch` を案内する
- **`--from-scratch`** は既存の SQLite を読まない。runs・findings・finding_events・meta は空から作る (次の run で未解決の finding が全部 new として再報告される旨を警告する)。
  主体は既定で **unknown** (new_principal が全主体を一度報告し、人が approve / ack で片付ける)。`--baseline` を付けたときだけ全主体を baseline (init と同じ扱い) にする
- 作り直しは同じディレクトリの一時ファイル (`audit.sqlite.rebuild-tmp`) に作ってから rename で入れ替える。元のファイルは `audit.sqlite.bak` に 1 世代残す
  (ハードリンク。次の rebuild で上書き)。ロック (`audit.lock`) を取ってから行う
- 知らない種類の行 (新しい版で書いた raw) と読めない行 (書き込み途中で止まった最後の行など) は飛ばし、件数と場所を出す (失敗にしない)
- prune (保持期間を過ぎたデータの削除) は対象外

## 検討した選択肢

- **raw の形式を拡張せず、差を「既知の差」として扱う**: rebuild の実装は小さくなるが、スナップショットの 0 件の置き換えが再現できない (消えたはずの GuardDuty や
  Access Analyzer の finding が rebuild 後に戻り、次の収集まで残る) うえ、「run を重ねたストアと rebuild したストアが一致する」をテストで固定できず、
  将来の変更で rebuild が黙って崩れても気づけない。足す項目は小さく後方互換 (`omitzero` と新しい種類の行) なので、拡張を選んだ。却下
- **raw に無いものも空から作る (常に --from-scratch)**: 実装は単純だが、rebuild のたびに未解決の finding が全部再報告され、ack / snooze と承認の状態を失う。
  SQLite が読める限りは引き継ぐほうが運用の負担が小さい。既定にはせず、壊れたときの手段として残した
- **--from-scratch の主体を既定で baseline にする**: 再報告は少なくなるが、失う前に open だった「承認されていない主体」が黙って消える。監査の安全側として既定は unknown にし、
  baseline は利用者が選ぶ (`--baseline`)
- **元のファイルを残さない / 世代を重ねる**: 残さないと rebuild の誤りを戻せない。世代を重ねると容量が増える。1 世代 (`.bak`) にした

## 結果

- 良い点: SQLite が壊れても raw から戻せる (S3 ストアの戻し方の前提)。rebuild の規則と記録の規則の一致を engine を通したテストで固定した
  (init・再走査・2 つの cloudtrail ソース・集計の引き直し・スナップショットの 0 件の置き換え・人の判断を含めて、表の中身が全部一致する)
- 引き受けるコスト: raw の行が少し増える (スナップショットの収集ごとに 1 行、principal_seen に時刻 1 つ)。以前の版で書いた raw からの rebuild は近似になる
  (警告を出す)。古い版の arata は `snapshot_replaced` の行を知らないが、raw を読むのは rebuild だけなので影響しない
