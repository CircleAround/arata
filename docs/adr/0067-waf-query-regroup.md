# 0067. WAF の集計クエリを、行の多い種類ごとに組み替える (本数は 4 本のまま。BLOCK 側とカウントの一致の合計を上限から守る)

- 日付: 2026-11-15
- 状態: 提案 (ADR 0031 の wafv2 の 4 本の分け方を置き換える。ADR 0065 の 4 節「1 本にまとめる」より先に行う)

## 背景

ADR 0065 で wafv2 を時の単位で読むようにした後、大きなアカウント (1 日約 4.5 GB) で、1 時間でも行数の上限 (10,000) に当たる時が 1 日に 7〜10 時間あった
(土曜の日本時間の朝。日曜の同じ時間帯は当たらない)。上限に当たった時の、返った行の action ごとの数 (`rows_by_action`。#117):

| 時 (UTC) | クエリ | CAPTCHA | BLOCK | CHALLENGE | ALLOW |
|---|---|---|---|---|---|
| 2026-11-14T00 | 止めた・出した系 (`waf_actions`) | 7,542 | 1,900 | 506 | 52 |
| 2026-11-14T01 | 止めた・出した系 (`waf_actions`) | 8,449 | 1,027 | 450 | 74 |
| 2026-11-14T01 | カウントの一致 (`waf_rule_count_match`) | (action の軸なし) | | | |

- **CAPTCHA の行が 75〜85% を埋め、BLOCK の行が押し出されている**。CAPTCHA は異なる IP 約 9 千・異なるパス約 1 万で、(path × ip) の組がほぼ 1 件ずつ。
  BLOCK はその時に 1,770 件だけで、BLOCK だけなら上限に遠い
- カウントの一致も上限に当たった。軸に ip があり、評価中の COUNT のルールが多くの送信元に一致すると (ルール × ip) の組が増える
- 読み取りは 4 本で 1 時間に約 0.75 GB。本数を増やすと、その分だけ読み取りが増える

今の 4 本 (ADR 0031):

| | filter | 軸 | 作る metric |
|---|---|---|---|
| 1 | なし (全行) | 日, WebACL, ルール, action | 解釈率・`waf_rule_action`・`waf_block` |
| 2 | BLOCK、または (CHALLENGE / CAPTCHA・許可された探索・トークンの受理) かつ正規の送信元でない | 日, WebACL, ルール, action, グループの中のルール, method, path, **ip**, Challenge の項目 | `waf_block_ip`・`waf_block_path`(`_ips`)・`waf_allow_probe`(`_ips`)・suspect の「BLOCK された IP」・`waf_challenge_*` |
| 3 | カウントのルールのどれかに一致 | 日, WebACL, カウントのルールの位置…, 探索パスの印, **ip** | `waf_rule_count_match`・`_suspect` |
| 4 | 正規の送信元でない | (5 分, パスの組, ip) → 度数 | `waf_ip_rate_*` |

## 決定 (案)

本数は 4 本のまま、**行の多い種類 (CAPTCHA・カウントの一致の ip) を、BLOCK と同じクエリに置かない**。使う Insights の機能は、今も使っていて
sandbox で確かめた「null を含む group by」と「parse の名前付き捕獲 (一致しない行では null)」だけにする (ADR 0031)。ADR 0065 の 4 節で確かめる
「ある行だけ値を持つフィールド」には頼らない。

| | filter | 軸 | 作る metric |
|---|---|---|---|
| 1' | なし (全行) | 日, WebACL, ルール, action, **カウントのルールの位置…, 探索パスの印** | 解釈率・`waf_rule_action`・`waf_block`・**`waf_rule_count_match` (合計)**・**`_suspect` のうち探索パスの分** |
| 2' | BLOCK、または許可された探索 (正規の送信元でない) | 日, WebACL, ルール, action, グループの中のルール, method, path, ip | `waf_block_ip`・`waf_block_path`(`_ips`)・`waf_allow_probe`(`_ips`)・「BLOCK された IP」 |
| 3' | (CHALLENGE / CAPTCHA・トークンの受理) かつ正規の送信元でない | 日, WebACL, ルール, action, グループの中のルール, method, path, ip, Challenge の項目 | `waf_challenge_issued`(`_ips`)・`waf_challenge_solved_ips` |
| 4 | (今と同じ) | | `waf_ip_rate_*` |

- 1': カウントのルールの位置のフィールドは、一致しない行では null で、null を含む組は 1 行にまとまる。行は (ルール × action) × (一致したカウントのルールの組) ×
  (探索パスか) で、数十〜数千の見込み。**カウントの一致の合計は、上限に当たらずに全件になる** (今は ip の軸のせいで下限になることがある)
- 2': BLOCK と許可された探索だけ。上限の時でも BLOCK は 1,000〜2,000 行で、上限に遠い。**BLOCK 側の metric は上限から守られる**
- 3': Challenge / CAPTCHA だけ。CAPTCHA の多い時は上限に当たり得るが、当たっても truncated になるのは Challenge の metric だけ (今は 6 つの metric がまとめて truncated)
- `waf_rule_count_match_suspect` の「その日 BLOCK された IP からの一致」は、カウントの一致と ip の組が要る。これを 1' に入れると ip の軸で行が爆発する。そこで次のどちらかにする
  (オーナーに確かめる):
  - **(i) 意味を変える**: suspect を「探索パスへの一致 (1' から作る)」と「BLOCK されたリクエストでもカウントのルールが一致した件数 (2' に
    カウントのルールの位置の軸を足して作る。2' は BLOCK の行だけなので軸を足しても行は増えにくい)」の和にする。
    「同じ日に別のリクエストで BLOCK された IP からの、許可されたリクエストへの一致」は数えなくなる
  - **(ii) 今の意味のまま、ip の軸を持つ 5 本目を足す**: 読み取りが 1 本分 (この利用者で 1 時間約 0.19 GB) 増える。上限に当たったら suspect だけが下限になる
  - 推奨は (i)。suspect の目的は「COUNT のルールが悪い送信元を捕まえているか」(ADR 0023 の `count_rule_status`) で、BLOCK されたリクエストでの一致は
    その直接の証拠になる。読み取りを増やさない

## 互換

- metric の名前・key は変えない。値は次のように変わる
  - `waf_rule_count_match`: 下限 → 全件 (上限に当たっていた時に増える)
  - BLOCK 側 (`waf_block_ip`・`waf_block_path` など): 上限に当たっていた時に増える
  - `waf_rule_count_match_suspect`: (i) なら意味が変わる (Release の本文と、waf_review の playbook に書く)
- 同値のゴールデン (`equiv_waf.golden`) は、(i) の suspect の行だけ変わる見込み。シミュレーターで組み替えの前後の値を突き合わせる (ADR 0031 と同じ確かめ方)
- ストアの移行は無い。`collect: hourly` の部分の行はクエリの名前で分かれるので、組み替えた版に上がった日だけ、新しい名前の部分の行が 0 時から揃わない。
  ADR 0065 の「その日の 0 時からの部分の行が無ければ日の頭から読む」が効くよう、新しいクエリの名前で揃いを確かめる

## 検討した選択肢

- **Challenge / CAPTCHA を別にして 5 本にする (本数を増やす)**: 採らない (案の (ii) の形だけを残す)。読み取りが 25% 増える
- **ADR 0065 の 4 節「1 本にまとめる」(BLOCK の行だけ path・ip を持つフィールド) を先に確かめる**: 採らない (今は)。開発用のアカウントでの確かめが要り、
  確かめられても CAPTCHA の (path × ip) は残るので、上限の問題は解けない。この組み替えの後に、1' と 2' をまとめられるかとして試す
- **Challenge 側の path を、パスの組 (rate_path_groups) に粗くする**: 3' の上限がなお問題になったら足す。challenge_on_app_path の提案 (ADR 0028) がパスの組の単位になる
- **count_distinct で異なり IP の数を取る**: 採らない。`waf_challenge_solved_ips` は出した IP と解いた IP の積で、集合が要る。count_distinct は近似でもある

## 手間の見積もり

- クエリの組み替え (WAFQueries と、行の振り分けの分け直し) とシミュレーターの同値のテスト: 1.5 日
- suspect の (i) の実装・playbook・ゴールデン: 0.5 日
- 大きなアカウントで、上限に当たる時 (土曜の朝) の 1〜2 時間を流して確かめる (開発リード)

## 未確認の点

- 1' の行の数 (カウントのルールの組の数)。評価中の COUNT のルールが多い WebACL では、数千を超えるかもしれない。超えたら 1' のカウントのルールの軸を「位置ごとのルール ID」から
  「一致したかの印」に減らす
- 3' が CAPTCHA の多い時に上限に当たる頻度 (CAPTCHA 8,449 + CHALLENGE 450 で、今の例では上限の手前)
