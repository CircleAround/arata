# 0031. Logs Insights の集計クエリをソースごとに数本にまとめ、振り分けを Go で行う (読み取り量を約半分〜5 分の 2 に)

- 日付: 2026-11-04
- 状態: 採用 (ADR 0028 の費用の見積もり・ADR 0030 の「画面ごとに 1 本」を置き換える)

## 背景

Logs Insights は 1 クエリごとに、問い合わせた範囲のロググループのログを全部読んだ量で課金される (東京 0.0076 USD/GB)。
arata は集計ごとに 1 本ずつ流していたので、読み取り量は「範囲 × 本数」だった。

- wafv2: 解釈率・`waf_block_ip`・`waf_rule_action`・`waf_block_path`・`waf_allow_probe`・「BLOCK された IP」・カウントの一致・Challenge の出した / 受理・レートで **10 本**
- http_access: 解釈率・`sign_in_failures`・`probe_hits`・`probe_paths` の 4 本 + endpoint_abuse の画面ごとに 1 本

範囲は「窓の始まりを含む UTC の日の 0 時から窓の終わりまで」(日次集計を置き換えで保存するため。設計書 3 章)。daily を UTC 22:00 (JST 07:00) に回すと約 46 時間になる。
1 日 4〜5 GB の WAF ログでは 1 回最大 80 GB・月 18 USD ほどになる見込みだった (doctor の cost 行)。

## 決定

同じソースの集計を、細かい group by の数本にまとめ、どの集計に入るかの振り分け (filter の一部) を Go で行う。endpoint_abuse (ADR 0030) の「1 本で細かく数えて Go で分ける」を全体に広げる。
値は変えない (前の版と同じログから同じ metrics が出る)。使う Insights の機能は sandbox で確認済みのもの (OR の filter、null を含む group by、ephemeral なフィールドへの parse、parse の複数回) だけにする。

- wafv2 は **4 本**
  1. 解釈率 + `waf_rule_action` (+ `waf_block`): 全行を `(日, WebACL, ルール, action)` で数え、`count(*)` と `count(action)` を同時に取る (行は数十)
  2. 止めた・出した系: filter は `action = "BLOCK" or ((CHALLENGE / CAPTCHA or 許可された探索 or トークンの受理) and 正規の送信元でない)`。
     group by は前の 4 本の軸の和集合。`waf_block_ip`・`waf_block_path`・`waf_allow_probe`・「BLOCK された IP」・Challenge の出した / 解いた IP を Go で作る。
     `trusted_cidrs` (`net/netip`、isIpInSubnet と同じ意味)・探索パス (接頭辞一致。`regexLiteral` は文字どおりなので同じ意味)・sign-in のパス (完全一致)・
     レートベース / 既定の action の除外は Go で行う
  3. カウントの一致は別のまま
  4. レートは別のまま (2 段の stats の pct。UTC の 1 日ずつ)
- http_access は **2 本 + endpoint があれば 1 本**
  1. 解釈率 + `probe_paths`: 全行を `(日, status, probe_path)` で数える。`probe_path` は `parse path /^(?<probe_path>\/\.env.*|...)/` で探索パスの行だけ値を持つので、
     行は日 × status × (1 + 探索パスの数) 程度
  2. `sign_in_failures` + `probe_hits` (どちらも IP 別): filter は両方の条件の和。`(日, ip, method, status, パスの印)` で数える。印は parse の名前付き捕獲
     (sign-in は `^(...)$` の完全一致、探索と除外は接頭辞)
  3. endpoint_abuse: 全画面で 1 本。filter は画面ごとの条件の和、group by は `(時間幅, ip, ua)` に method・status (条件に使う画面があるとき) と、
     glob ごとの印 (一致したときだけ先頭の `/` を捕獲する `parse`。値が常に `/` なので行は増えない) を足す。中のグループは名前付きにする
     (名前の無いグループを parse に入れたときの扱いに頼らない)。先頭の `**` は `(\/s)*\/next` を同じ意味の `\/(s\/)*next` に書き換える
- 行数の上限 (10000): 前の版より 1 本あたりの行が増える (filter を Go に移した分、Insights から返る行が増える。読む量は同じ)。
  上限に当たったらその範囲を時に揃えて半分に分けて引き直し (1h まで。endpoint は時間幅に揃え、従来どおり UTC の 1 日ずつ)、それでも当たればまとめた集計から作る metric の名前を
  全部 `truncated` に残す。分けて流してもスキャン量は範囲に比例するので増えない。増えるのは上限に当たって引き直した分だけ (INFO に残す)。
  日次の集計は範囲全体を 1 本で流し、当たったときだけ分ける (多くの日は上限に遠く、API の呼び出しを増やさない)
- 値の同一性は、ログの行から各クエリの結果を作る簡易シミュレーター (`cwlogstest.Sim`) とゴールデン (`internal/collect/cwlogs/testdata/equiv_*.golden`) で固定する。
  ゴールデンはまとめる前のコードで作り、まとめた後も変えていない
- doctor の cost 行: クエリの本数を新しい数にし、「範囲は実行時刻で決まる」ことを具体的な時刻で案内する。範囲が最小になる時刻は
  UTC 0 時 + 窓 + ingest_delay + 余裕 15 分 (daily・ingest_delay 5m なら UTC 00:20 = JST 09:20、範囲約 24.3 時間)。直近の run の時刻は保存したレポート
  (`reports/<profile>.json` の窓の終わり) から読む (doctor はストアを開かない。ファイルを読むだけ)

見積もり (1 日のログ 4 GB の wafv2、daily を UTC 22:00 に 1 日 1 回):

| | 本数 | 範囲 | 1 回 | 30 日 |
|---|---|---|---|---|
| 前の版 | 10 | 最大 48.1 時間 | 最大 80.1 GB | 18.3 USD |
| この版 | 4 | 最大 48.1 時間 | 最大 32.1 GB | 7.3 USD |
| この版 + UTC 00:20 に回す | 4 | 約 24.3 時間 | 16.2 GB | 3.7 USD |

http_access は endpoint 2 つで 6 本 → 3 本、endpoint なしで 4 本 → 2 本 (どちらも半分)。

## 検討した選択肢

- **読み直しをやめる (前回の続きから読み、時間幅の小計を足す)**: 採らない (今回は)。日次の値の多くは足し算で作れない (異なり IP 数・日ごとの上位 `top_paths`・
  suspect の「その日 BLOCK された IP」・p50 / p99)。同じ値を保つには (時間幅, path, ip, ...) の細かい行をストアにキャッシュして日次を Go で作り直す必要があり、
  IP と生パスの新しい保存 (プライバシーと容量)、schema_version の更新、init / rebuild / 再走査 (ADR 0013) との整合、Insights の pct を Go で同じ式で再現できない
  (値が少し変わる) という論点がある。効果は実行時刻次第 (最大約 1.9 倍、UTC 0 時過ぎに回せば 1 倍) で、doctor の案内で設定だけで同じ効果を得られる
- **カウントの一致を止めた・出した系に入れる**: 採らない。評価中のマネージドルールを COUNT にすると全行に一致し、path の軸に入れると (path, ip) の行が爆発する
- **probe_hits と probe_paths を 1 本にする**: 採らない。(ip, path) の直積になり、分散した探索 (多数の IP × 多数のパス) で行が爆発する
- **すべてを 1 本にまとめる (concat と parse で「ある種類の行だけ値を持つ」フィールドを作る)**: 採らない (今回は)。Insights の `concat` と null の扱いが未確認。
  まとめても 2 段の stats のレートは別に要る
- **フィールドインデックス (`filterIndex`)**: 記録だけにする。`action` などに索引があれば、BLOCK だけを読むクエリは BLOCK の行しか読まない。ただし利用者側の設定
  (`PutIndexPolicy`) と、読み取り専用ロールへの `logs:DescribeIndexPolicies` の追加が要る。また「分けて filterIndex で絞る」方が得になり、この決定 (まとめる) と相性が逆。
  sandbox で効果を測ってから判断する (roadmap)

## 結果 (良い点・引き受けるコスト)

- 良い点: wafv2 の読み取り量が 5 分の 2 (2.5 分の 1)、http_access が半分。実行時刻を合わせればさらに約半分。値は変わらない
- 良い点: 行数の上限に当たったときに分けて引き直すので、前の版 (範囲最大 2 日を 1 本) より上限に当たりにくい
- コスト: 止めた・出した系は 1 本の行の上限を共有する。当たったときは 6 つの集計がまとめて `truncated` になる (前の版は当たった集計だけ)
- コスト: filter の意味の一部が Go にあり、クエリの文字列だけでは何を数えるかが分からない。シミュレーターのテストで両方の意味を突き合わせる
- コスト: parse の名前付きグループの入れ子・繰り返し (`(?<x>...)*`) と group by の軸 30 本ほどは sandbox で確かめる (doctor の queries の検査で受理を確かめられる)
- 別件 (記録): endpoint_abuse で 1 つの画面を複数のソースで数えると、metrics の合算で異なり IP 数が和集合ではなく足し算になる。ソースは別のロググループ
  (別の形式プロファイル) なので 1 本のクエリにはまとめられず、ここでは直さない (別の PR)
