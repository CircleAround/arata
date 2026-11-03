# 0027. 既知の主体の初めての送信元・リージョン (`principal_new_source`) と秘匿値の読み取りの異常 (`secret_access`) を、CloudTrail の主体の活動の日次集計と注目イベントで判定する

- 日付: 2026-11-03
- 状態: 採用

## 背景

アクセスキーやセッションの漏洩は、既知の主体が「いつもと違う場所から」使われる形で現れる。new_principal は主体の初出しか見ないので、承認済み・ベースラインの主体の悪用は見えなかった。
また、侵入の後には秘匿値 (Secrets Manager・SSM の SecureString) がまとめて読まれることが多いが、秘匿値の読み取りは注目イベントとして残しているだけで判定していなかった。
設計書 7 章の未実装の `new_source_ip` (主体 × IP の初出、国外なら medium) と `secret_access_unknown` (allowlist に無い組の読み取りを high) はこの 2 つに置き換える。

材料の問題: events は注目イベントだけ、principal_ips は (主体, IP) ごとの初出・最終観測の累計で、日ごとの履歴も書き込みのリージョンも無い。
last_seen が今日の観測で上書きされるので「過去 30 日に同じ送信元が無い」を正確に判定できず、「主体が書き込んだリージョン」はどこにも残っていなかった。

## 決定

- cloudtrail collector が主体の活動の日次集計を `record.Metric` で出す (metrics テーブル。スキーマは変えない):
  `principal_source` (主体 × 送信元の /24・/48)、`principal_source_writes` (その成功した書き込み)、`principal_write_region` (主体 × 書き込みのリージョン)。
  対象は IAM ユーザーとロール (のセッション)。サービス主体・root・IP でない送信元は数えない。init のベースライン収集でも出るので、平常帯が作れる
- Metric は同じ (日, ソース, 指標, key) を後の値で置き換える。cloudtrail は日の頭から引き直さないので、値は「その日を最後に引いた run が見た件数」(下限) になる。
  判定は「その日に有ったか」と下限値 (書き込みの件数) にだけ使う。期間レポートの推移表には出さない。collector の Yields に metric は足さない (他のチェックの skip 判定を変えない)
- `principal_new_source` (daily、event): 既知の主体の窓の日の送信元・書き込みのリージョンが、過去 `baseline_days` (30) 日に無ければ報告する。
  新しい送信元だけ → low、新しい送信元からの書き込みが `min_writes` (5) 以上か新しいリージョンでの書き込み → medium、新しい送信元 + 同じ窓の access_denied → high
- access_denied との相関は、principal_new_source の中で AccessDenied の Evaluate を同じ入力で呼んで得る。access_denied がプロファイルに無くても材料として呼ぶ (finding は出さない)
- ノイズ対策: allowlist の主体の `dynamic_source: true` と、AWS のサービスが引き受けるロール (保存済みの AssumeRole の呼び出し元がサービス) は low を出さない (medium 以上は出す)。
  allowlist の `source_ips` の内の送信元は新しくない。導入直後 (データのある過去日が `min_baseline_days` 未満) と、過去 30 日の間に初めて現れた主体は報告しない
- `secret_access` (daily、event): 成功した GetSecretValue / BatchGetSecretValue と、復号した GetParameter(s) / GetParametersByPath を主体ごとに見る。
  初めて読む秘匿値 → low (読むこと自体が初めてなら medium)、窓の異なる秘匿値の数が `max(min_distinct, 中央値 × factor)` を超えた → high。
  GetParametersByPath はパス単位で 1 と数える。allowlist の `secrets_access` (Step 1 から読むだけだった) に一致する秘匿値は初出に数えない
- collector の normalize で秘匿値の名前 / ARN・パス・recursive・with_decryption だけを取り出す (値は CloudTrail に入らない)。with_decryption は常に残し、無いものは以前の版で集めたものとして扱う。
  BatchGetSecretValue を注目イベントに足した。run の stats に `secret_read_events` (保存量の目安) を残す
- 読み取りロールの権限は増やさない (LookupEvents だけで足りる)

## 検討した選択肢

- **新しいテーブル (主体 × 日 × 送信元・リージョン) を作る**: 値も正確になるが、スキーマの移行と rebuild の対応が要る。判定に要るのは有無と下限値だけなので metrics で足りる。見送った
- **principal_ips の first_seen だけで送信元を判定する**: 追加の保存は要らないが、過去 30 日の有無を判定できず (last_seen が上書きされる)、リージョンは判定できない。却下
- **送信元を IP 単位で比べる**: 同じ回線・同じ事業者の近い IP の入れ替わり (動的 IP) を毎回新しい送信元にする。/24・/48 で比べる
- **国の判定を入れる (国外なら medium)**: GeoIP のデータベースが要り (依存とライセンス、更新)、VPN やクラウドの出口では誤る。未決として入れず、`new_sources` の要素に後から country を足せる形にした
- **サービスが引き受けるロールを対象から外す**: Lambda などの送信元の入れ替わりによるノイズは消えるが、インスタンスメタデータなどから持ち出したセッションの悪用を見逃す。low だけ出さない形にした
- **access_denied の結果を run の中で共有する**: チェックの順序と実行の有無に依存する。同じ規則を同じ入力で呼べば同じ結果になるので、中で呼ぶ
- **secret_access を「allowlist に無い組の読み取りは high」にする (当初の secret_access_unknown)**: allowlist を書き切るまで鳴り続ける。初出と一括読み出しを平常帯で見て、`secrets_access` は初出を止める用途にした

## 結果 (良い点・引き受けるコスト)

- 追加の権限なしで、既知の主体の悪用 (漏洩したキーの利用・休眠キーの再利用・使わないリージョンでの書き込み) と秘匿値の持ち出しを日次に知らせられる。
  日次集計と取り出しの追加で既存のチェックの結果が変わらないことはテストで固定した
- 版を上げた既存のストアには過去の日次集計が無いので、principal_new_source は 15 日、secret_access の初出は 7 日の間報告しない (init し直せば即時)
- metrics の行が増える (1 日あたり主体数 × 送信元数 × 2 + 主体数 × リージョン数)。サービスのロールが多い環境では年 100 万行に近づくので、prune を入れるときに `principal_*` の保持を短くする
- 判定は `cloudtrail-lookup` の `regions` のリージョンだけ。使っていないリージョンでの書き込みは P-D (unused_region_activity) で扱う
