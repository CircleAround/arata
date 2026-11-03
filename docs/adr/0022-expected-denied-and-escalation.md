# 0022. 想定済みの拒否は allowlist の `expected_denied` で主体 × API の単位で除き、ack / snooze 中でも重大度が上がれば再報告する

- 日付: 2026-11-03
- 状態: 採用

## 背景

本番では、正規の主体が恒常的に拒否されることがある。例えば AI 調査用の読み取りロールに、個人情報を含むロググループへの IAM Deny を
意図的に入れておくと、調査のたびに権限外の API を試して拒否される。監視・定期処理のロールや、移行途中の旧ロールでも起きる。

access_denied (ADR 0021) は主体ごとに 1 件の finding で、止める手段は ack / snooze しか無かった。
ところが差分判定 (diff) は、acked と期日前の snoozed を重大度が変わっても suppressed (再報告しない) にしていた。
そのため、AI 調査用ロールのふだんの拒否 (medium) を ack すると、そのロールが乗っ取られて 30 種類の API を探っても (high) 報告されない。

## 決定

1. allowlist.yaml の `principals[]` に `expected_denied` (「サービス:操作」の glob のリスト。access_denied の `apis` と同じ書式。
   例 `logs:StartQuery`、`logs:Get*`、`secretsmanager:*`) を足す。
   - access_denied は、主体に一致する **期限内の** 項目の `expected_denied` に一致する拒否を、数える前に除く。窓のイベントにも平常帯の過去分にも同じく適用する。
     期限切れなら除かない (再び数える)。窓で除いた件数は Data の `expected_denied_excluded` に残す
   - 主体に一致する期限内の項目が複数あれば、それらの `expected_denied` の和で判定する (項目ごとに理由と期限が違ってよいため)。
     タグの判定に使う項目 (最も具体的な 1 つ、同じ arn の重複は後勝ち) の決め方は変えない
   - 読み込み時に検証する: 空のリスト、空の要素、コロンの無いもの・空白を含むものはエラー。`expected_denied` を持つ項目は `note` が必須
   - 項目そのものは今までどおり主体を承認する。`expected_denied` のためだけに新しく項目を作ると new_principal なども止まる
   - `arata approve <access_denied の finding> --expected-denied <glob>` (複数可) で主体の項目を追記できる。finding は resolved にしない
     (次の run で除いて数え直し、閾値を下回れば報告されなくなる)。主体の項目が既にあれば書き換えずに止まり、足す行を示す (ADR 0010 は行の差し込みだけ)。
     `--expected-denied` を付けない access_denied の approve は拒否する (主体の承認は権限を探ってよいという意味ではない)
2. finding に `suppressed_severity` (ack / snooze したときの重大度) を持つ。store の schema を 5 に上げ、既存の acked / snoozed の行には今の severity を入れる。
   - diff は、acked / 期日前の snoozed で観測の重大度が `suppressed_severity` より重いとき、**changed** として再報告し open に戻す
     (`suppressed_severity` は空にする。再び ack すればその時の重大度を記録する)。全チェック共通。
   - Data に `escalated_from_suppressed: true`・`suppressed_status` (acked / snoozed)・`suppressed_severity` を、Summary の先頭に
     「(確認済み (ack) だったが重大度が medium → high に上昇)」を付ける。event 型の recurred の条件と重なっても changed (上昇を優先)
   - 重大度が同じか軽いときは今までどおり suppressed

## 検討した選択肢

- ack を Fingerprint の変化でも解く: 却下。event 型の Fingerprint は IP 集合を含むので、IP が変わるたびに再報告されて ack の意味が無くなる (通知疲れ)
- access_denied だけ特別扱いする: 却下。ack 中の悪化が見えない穴は他のチェック (new_source_ip、iam_changes など) にも同じくある
- 上昇を新しい class (`escalated`) にする: 却下。report.json のスキーマと aratam の振り分けを変える必要がある。
  changed に印を付ければ aratam は今のまま (`summary.changed` で静かでなくなり、`max_severity` で緊急用に振り分ける) 届く
- 想定済みの拒否を設定 (config.yaml の checks.access_denied) に書く: 却下。主体の承認と同じく「誰をなぜ」の判断で、承認者・期限・理由を
  git の履歴に残したい。allowlist が適する
- 想定済みの拒否を主体単位 (API を指定しない) で除く: 却下。主体ごと除くと乗っ取られたときの列挙も見えなくなる。主体 × API にすることで、想定外の API の拒否は数え続ける
- approve で既存の項目に `expected_denied` を書き足す / 同じ主体の 2 つ目の項目を足す: 却下。前者は ADR 0010 (行の差し込みだけ) を崩す。
  後者は同じ主体の項目が 2 つになり、期限の違う項目で主体の承認が延びるなど分かりにくい。既存の項目には手で足す (エラーに足す行を示す)

## 結果 (良い点・引き受けるコスト)

- 良い点: 想定内の拒否を API の単位で除けるので、ack せずに済み、乗っ取られたときの想定外の列挙は報告される。ack / snooze していても悪化は報告される
- 良い点: report.json のスキーマと aratam は変わらない
- コスト: `expected_denied` は項目を作ると主体も承認する。新しい主体に付けるときは、主体の承認としても妥当かを確かめる必要がある (文書に明記)
- コスト: 平常帯の過去分にも、評価する時点の allowlist を当てる (過去の時点の allowlist ではない)。`expected_denied` を足した直後から平常帯も小さくなる
- コスト: store の schema が 5 になる。古いバイナリは列を知らないので、古いバイナリで ack した行は `suppressed_severity` が空になる
  (その場合は今の severity と比べる。suppressed の間に観測で上書きされた値なので、上昇の見逃しがあり得る)
