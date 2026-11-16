# 0069. 怪しい IP の一覧をストアに持ち、チェックをまたいで使う (判定に使う期間と保持の期間を分ける。最初の使い道は count_rule_status の suspect)

- 日付: 2026-11-17
- 状態: 提案 (ADR 0067 の (i) の suspect に、一覧の IP からの一致を足す。ADR 0065 の部分の行と ADR 0064 の位置を前提にする)

## 背景

- ADR 0067 で、wafv2 の `waf_rule_count_match_suspect` の「その日 BLOCK された IP からの一致」を作るのをやめた。カウントの一致に ip の軸を持たせると、
  大きなアカウントで 1 時間でも行数の上限 (10,000) に当たるため。代わりに (i)「探索パスへの一致」と「BLOCK されたリクエストでもカウントのルールが一致した件数」の和にした
- (i) の実装 (#119) を大きな利用者の実データで流すと、suspect の割合が 5.4% から 0.04% に落ちた。「BLOCK された IP が、別のリクエスト (許可されたもの) で
  COUNT のルールに一致した」件数が、suspect のほとんどだったことになる。(i) では count_rule_status (ADR 0023) が「COUNT のルールが悪い送信元を捕まえているか」を伝えられない
- 今の arata は WAF (`waf_block_ip` など)・アプリのログ (`sign_in_failures`・`probe_hits`)・CloudTrail (`principal_ips`) を別々に見ている。
  「怪しいとした IP」を 1 か所に持てば、ソースをまたいで突き合わせる鍵になる
- オーナーの着眼 (2026-11-17): 怪しいとしている IP を SQLite に保存しておけば、ためになるのでは。補足: 一覧は一定期間でアクティブではなくなる設計か

### 前提の確かめ (公式文書。2026-11-17 に読んだ)

- Logs Insights の問い合わせの文 (`StartQuery` の `queryString`) は **10,000 文字まで** (API Reference の StartQuery、Length Constraints の Maximum length 10000)
- `filter <field> in [...]` で集合に含まれるかを確かめられる (CloudWatch Logs のユーザーガイドの filter の頁)。要素の数の上限は書かれていない (文の長さの上限が効く)
- 料金は Insights が読んだ量 (data scanned) で決まる。filter で絞っても、範囲のログは全部読む (ADR 0031・0065 と同じ前提。インデックスを使う場合は別で、下の「検討した選択肢」)

## 決定

### 1. 何で一覧に載るか

一覧は**チェックではなく、ストアに持つ派生の表**。日の値 (`metrics`。ADR 0065 では部分の行から作る日の値) を作るときに、決まった規則で載せる。Insights のクエリは足さない
(載せるのに要る値は、今のクエリの行にもうある)。

| 理由 (`reason`) | ソース | 元の値 | 載る条件 (既定の案) |
|---|---|---|---|
| `waf_block` | wafv2 | 2' (`waf_blocks`。ADR 0067) の行。日ごとの IP の件数 | BLOCK が `min_count` (1) 件以上。**suspect の「BLOCK された IP」と同じものを除く**: レートベースのルール・既定の action・sign-in のパス (`login_bruteforce.paths`) での BLOCK、`trusted_cidrs` (設計書 2 章の決定) |
| `probe` | http_access | `probe_hits` (key = ip) | 日に `min_count` (3) 件以上 |
| `probe` | wafv2 | 2' の許可された探索の行 | 日に `min_count` (3) 件以上 (WAF をすり抜けた探索) |
| `sign_in_failure` | http_access | `sign_in_failures` (key = ip) | 日に `min_count` (20) 件以上 (login_bruteforce の閾値とは別に持つ。片方を変えても、もう片方は変わらない) |

- 決定: **endpoint_abuse は最初の版では載せない**。endpoint_abuse の集計は IP の原文を保存しない形にした (ADR 0030。時間幅ごとの件数・異なり IP の数・UA のハッシュだけ)。
  載せるには時間幅ごとの IP を返して保存することになり、この ADR の範囲を超える。候補として 5 節に残す
- 決定: 載せない IP: allowlist の `source_ips` の内、`checks.waf_review.trusted_cidrs` の内 (wafv2 の理由だけ)。載せるときに除き、**使うときにも除く**
  (allowlist は後から足されるので、載った後に既知になった IP も効かないようにする)
- 決定: IP は `netip.ParseAddr` で読めたものだけを、`netip.Addr.String()` の正規の形で持つ (IPv4 射影の IPv6 は IPv4 に直す)。読めない値は載せず、
  件数だけを run の stats に残す。**ログ由来の値を、後で Insights の問い合わせの文に入れるため** (4 節。ADR 0037)
- 決定: 閾値は設定 `ip_list.reasons.<reason>.min_count` に書く。**`ip_list:` が無ければ一覧を作らない** (今と同じ動作。ADR 0014)。雛形 (`config init`) は
  上の表の値で `ip_list:` を書き出し、既存の設定には `config init --diff` で見える。理由を 1 つも書かない `ip_list:` は設定の誤り (`config check` で止める)

```yaml
ip_list:
  active: 7d          # 判定に使う期間 (N)。最後に見てから N を過ぎた IP は、使わない (休止)
  reasons:
    waf_block:       { min_count: 1 }
    probe:           { min_count: 3 }
    sign_in_failure: { min_count: 20 }
retention:
  ip_list: 30d        # 保持の期間 (M)。最後に見てから M を過ぎたら、記録ごと消す。N ≦ M
```

### 2. 表の形

**日ごとの行**を持ち、「初めて見た日・最後に見た日・件数」は読むときに組み立てる。

| 表 | 主なカラム | 主キー |
|---|---|---|
| `ip_list_days` | date, source, reason, ip, count | (date, source, reason, ip) |

- 決定: 日の値と同じく、(date, source) ごとに**丸ごと置き換える**。日の値は「途中の値」として毎回作り直され (ADR 0065)、
  cloudtrail は下限の値を置き換える (設計書 5-2) ので、`count` を足し込む形 (`ip_reputation(ip, reason, source, first_seen, last_seen, count)` を UPSERT) にすると、
  作り直すたびに二重に数える。日ごとの行なら、作り直しは同じ値を書き直すだけになる
- 読むときの形 (Go の型。保存しない):

| 値 | 組み立て方 |
|---|---|
| `first_seen` | 残っている行の date の最小 (保持の期間 M の中で初めて見た日) |
| `last_seen` | date の最大 |
| `active_since` | 今の「アクティブな続き」の始まり。last_seen から日を遡り、N を超える空きがあればその後の最初の日 |
| `count` | 期間を指定して和 (例: 直近 N 日) |
| `reasons` / `sources` | 行の集合 |

- 決定: 時の単位にしない (日まで)。使い道 (4・5 節) は日の単位で足り、時にすると行が 24 倍になる。部分の行 (`metric_parts`) の時の行から作るが、
  保存は日の値と同じ単位にする
- 部分の行との関係: `waf_block` と wafv2 の `probe` は、その日の部分の行 (2') から日の値を作るときに一緒に作る。部分の行は 3 日で消える (ADR 0065) が、
  一覧の行は日の値と同じく残る。`collect: hourly` でないソースは、今のクエリの行から同じ規則で作る (振り分けは同じ関数)
- 行数の見積もり: 1 日あたり (載った IP の数 × 理由の数)。BLOCK された IP が 1 日数千の大きなアカウントでも、30 日で 10 万行ほど。1 行は 50 バイトほどで、数 MB
- 決定: **raw (JSONL) に書かない**。rebuild (ADR 0033) は既存の SQLite から引き継ぐ (`metric_parts` と同じ)。raw の保持は 365 日で、一覧の保持の期間 (M) より長いため。
  引き継げないとき (`--from-scratch`) は空から始め、標準エラーに出す (一覧は日の値から作り直せるが、wafv2 の部分の行は 3 日分しか無い)
- ストアのスキーマ: `ip_list_days` を足すので `schema_version` を上げる。**番号は実装の時点の main の次** (ADR 0068 の `finding_actions` が 7 → 8 にする予定なので、
  0068 が先に入れば 9)。どちらの表も `CREATE TABLE IF NOT EXISTS` で作るので、順番が変わっても移行はぶつからない。実装の PR で main の `schemaVersion` を確かめる

### 3. 判定に使う期間 (N) と保持の期間 (M)

2 つを分ける。

| | 意味 | 既定の案 | 過ぎたら |
|---|---|---|---|
| **N** (`ip_list.active`) | 判定に使う期間 | 7d | last_seen が N より前の IP は、どの使い道でも使わない。一覧の上では「休止」(行は残る) |
| **M** (`retention.ip_list`) | 保持の期間 | 30d | last_seen が M より前の IP は、その IP の行を全部消す (prune) |

- 決定: **N ≦ M** を設定の読み込みで確かめる (破れていれば `config check` で止める)。N も M も雛形が書き出し、`config init --diff` で見える (暗黙の既定にしない)
- 決定 (消し方): prune (設計書 5-3。run の最後) が、date が M より前の日の行を消す (metrics と同じ消し方)。最後に見てから M を過ぎた IP は、行が全部無くなり、記録ごと消える。
  続けて悪さをする IP も、M より前の日の行は消える (first_seen は「M の中で初めて見た日」)。`arata prune --dry-run` で、消える行の数と、記録ごと消える IP の数を出す
  - 採らない案: 「最後に見た日が M より前の IP だけを、全部の日について消す」。続けて悪さをする IP の古い日の行が、いつまでも消えない (保持の期間が上限にならない)
- 決定 (休止した IP がまた悪さをしたとき): その日の行が足されるので、last_seen が進み、**また効く**。first_seen は M の中に古い行が残っていれば残る (初めて見た日を残す)。
  `active_since` はその日に変わるので、「休止の後に戻ってきた」が分かる。M を過ぎて消えた後に戻ってきた IP は、初めて見た IP として扱う (消したものは覚えていない)
- 決定 (N を短めにするか): 既定は **7d** にする。理由:
  - 共有の IP (大学・会社・携帯の回線の CGNAT) は、悪い 1 人のせいで載っても、N 日で休止に戻る。短いほど巻き込まれる期間が短い
  - count_rule_status は直近 `days` (7) 日を見る。N を 7d にすると、その期間の中で載った IP がそのまま効き、期間と揃う
  - 1d (その日だけ) にすると ADR 0067 の前の意味に近いが、「前日に BLOCK された IP が、今日は許可されたリクエストで COUNT に一致した」を数えない。
    一覧の利点 (日をまたぐ) が無くなる
  - 長く (30d) すると、共有の IP で COUNT のルールの suspect が高く出る (危ない方向の間違い: 正規の利用者に当たっている COUNT のルールを「怪しい通信ばかり」と見せる。設計書 2 章の決定と同じ理由)
- 決定: M の既定は **30d**。IP は個人に結び付き得る値なので、使い道 (N と、5 節の「休止の後に戻ってきた」) に要る長さに留める。90d は採らない (使い道が無い)
- 決定: 理由ごとの N は最初の版では持たない (1 つの N)。`sign_in_failure` は共有の IP に当たりやすいので、使い道の側で使う理由を選ぶ (4 節の `reasons`)

### 4. 最初の使い道: count_rule_status の suspect

**一覧の IP だけに絞った問い合わせ**で、許可されたリクエストでの COUNT のルールの一致を、IP ごとに数える。行は (一覧の IP の数 × 一致した COUNT のルール) に収まり、上限に当たらない。

```
fields httpRequest.clientIp as ip, ...
| filter httpRequest.clientIp in ["198.51.100.7", "2001:db8::1", ...]
| filter action != "BLOCK"
| filter <カウントのルールのどれかに一致> and not <探索パス>
| stats count(*) by <WebACL>, <カウントのルールの位置…>
```

- 決定: 結果は新しい metric `waf_rule_count_match_listed` (key は `waf_rule_count_match` と同じ `<WebACL>|<ルール>`) に置く。
  waf_review は suspect を **`waf_rule_count_match_suspect` (ADR 0067 の (i)) + `waf_rule_count_match_listed`** として読む。
  3 つは重ならない: (i) の探索パスの分は探索パスだけ、BLOCK の分は BLOCK のリクエストだけ、listed は探索パスでない許可されたリクエストだけ。
  metric を分けるのは、(i) の値が時ごとに作り直され (途中の値)、listed は日が揃ってから 1 回作る (下) ので、置き換えの単位が違うため。evidence にも内訳を出す
- 決定 (どの IP か): 使う日の終わりの時点でアクティブな IP (last_seen がその日を含めて直近 N 日の中)。理由は `checks.waf_review.suspect_ip_list.reasons` で選ぶ
  (既定の案 `[waf_block, probe]`。`sign_in_failure` は共有の IP に当たりやすく、正規の利用者の打ち間違いでも載るので既定に入れない)。
  `suspect_ip_list:` が無ければ問い合わせない (suspect は (i) のまま)。雛形が書き出し、`--diff` で見える
- 決定 (いつ流すか): **UTC の日が揃った (確定した) 後に、その日について 1 回**。daily の run が、wafv2 のソースの「listed を作り終えた日」の位置
  (ADR 0064 の位置に、このための key を 1 つ足す) から、確定した日までを 1 日ずつ流す。時ごとに流さない理由:
  - その日の後の時に初めて BLOCK された IP は、前の時の問い合わせの一覧にまだ無い。日が揃ってからなら、その日の全部の IP を使える
  - 読む量は、時ごとに流しても日に 1 回でも同じ (1 日分)
  - 失敗した日は位置を進めず、次の run で流し直す (ADR 0038 と同じ)
- 決定 (文の長さの上限を超えるとき): 一覧の IP を、文が 10,000 文字に収まる組 (要素の部分に約 8,000 文字。IPv4 は 1 つ最大 18 文字で約 440、IPv6 は最大 42 文字で約 190) に分け、
  組ごとに 1 本流す。**組ごとに範囲の全部を読む** (料金がその分増える) ので、本数の上限 `suspect_ip_list.max_queries` (既定の案 2) を持つ。
  上限を超える IP は、直近 N 日の件数の多い順に残し、残りは数えない。そのときは listed が下限になるので、count_rule_status の evidence に
  `listed_ips_total`・`listed_ips_queried`・`listed_is_lower_bound: true` を残す (数えた割合を隠さない)
- 決定 (費用): **絞っても範囲の全部を読むので、費用は下がらない。1 本 × 1 日分が増える**。1 日 4.5 GB の wafv2 なら、1 日あたり約 4.5 GB
  (東京 0.0076 USD/GB で 1 日約 0.034 USD、30 日で約 1.0 USD)。組が 2 本なら倍。ADR 0067 の (ii) (ip の軸を持つ 5 本目) と同じ読み取りの増え方だが、
  (ii) と違って行数の上限に当たらない (行は一覧の IP の数で決まる)。doctor の cost の行に、この 1 本を足して見積もる
- 決定 (weekly の run の直近 1 日分だけに流す案): 採らない。weekly は wafv2 を引かない (設計書 7 章の waf_review の決定。保存済みの日次集計だけを読む)。
  1 日分では、count_rule_status の直近 7 日の割合と期間が揃わない (6 日分の listed が 0 になる)。費用の差は 30 日で約 0.9 USD
- 決定 (問い合わせの文の組み立て): IP は 1 節で正規化した値を、組み立ての直前にもう一度 `netip.ParseAddr` で読み直し、`String()` の値だけを `"` で囲んで入れる。
  一覧はストアから読む値なので、ストアが書き換えられていても文の構造を変えられないようにする。この関数はファズテストを足す
  (規則: どんな入力でも、出力の文の `in [...]` の要素はすべて IP の正規の形で、要素の外の文字は固定の部品と一致する。ADR 0041)
- `collect: hourly` でないソースも同じ (日の頭から読み直すソースでも、listed は確定した日に 1 回)

### 5. 次の使い道 (候補。この ADR では入れない)

**重さは、一覧に載っただけでは上げない。ほかの兆候と重なったときに上げる** (一覧は共有の IP を含み得る、弱い兆候のため)。

| 使い道 | 突き合わせ | 重なったときに |
|---|---|---|
| 一覧の IP からのログインの成功 | `http_user`・auth の行の success (ADR 0052) を、送信元の IP ごとに集計して (今は IP ごとに持っていない。足す必要がある) | login_bruteforce の失敗の後の成功 (乗っ取りの疑い) として上げる |
| 一覧の IP からの AWS の操作 | `principal_ips` (主体 × IP。すでに SQLite にある) と ip で突き合わせる。Insights も CloudTrail の読み直しも要らない | principal_new_source (ADR 0027) の新しい送信元が一覧の IP なら上げる |
| 一覧の IP の「多数の利用者」 | source_multi_user (ADR 0051 の段 1。未実装) の key と突き合わせる | 認証情報の使い回しの成功の疑いとして上げる |
| endpoint_abuse の IP | 時間幅ごとの IP の保存が要る (1 節) | — |
| 休止の後に戻ってきた IP | `active_since` が変わった IP | observation として伝える (重さは上げない) |

### 6. 誤検知 (共有の IP)

- 大学・会社・携帯の回線 (CGNAT) の IPv4 は、悪い 1 人と多数の正規の利用者が同じ IP を使う。一覧に載ると、正規の利用者の COUNT の一致まで suspect に数える
- 守り:
  - N を短く (7d) し、休止に戻す (3 節)
  - `waf_block` の理由から、正規の利用者も当たり得る BLOCK (レートベース・既定の action・sign-in のパス) を除く (1 節。今の suspect と同じ)
  - suspect に使う理由を選ぶ (`sign_in_failure` は既定で使わない。4 節)
  - 既知の共有の送信元 (自社・利用者の会社) は allowlist の `source_ips` に書けば、載らないし使われない (1 節)。新しい仕組み (一覧の除外の表) は足さない
  - 5 節の使い道でも、一覧に載っただけでは重さを上げない
- 残る限界: 携帯の回線のように、利用者が知らない共有の IP は除けない。count_rule_status は観測 (observation) で、提案にも finding にもしない (設計書 7 章) ので、
  間違えても「COUNT のルールを BLOCK にしよう」とは勧めない。playbook (`waf_review`) に「listed は共有の IP を含み得る」と書く

### 7. 報告への出し方

- 決定: **一覧そのもの (IP の原文) は、report.json にも通知 (aratam・LLM) にも出さない**。出すのは件数だけ:
  - run の stats: 理由ごとの、その日に載った IP の数とアクティブな IP の数、読めずに捨てた値の数
  - count_rule_status の evidence: `listed_matches`・`listed_ips_total`・`listed_ips_queried`・`listed_is_lower_bound`
- 理由: 一覧は判定の材料で、人が 1 つずつ見るものではない。IP の原文を LLM に渡す量を増やさない (ADR 0037)
- 今もある IP の扱いとの関係: login_bruteforce などの finding の key と、ip を key に持つ metric (`sign_in_failures`・`waf_block_ip` など) は、すでに IP の原文を持ち、
  raw は 365 日・metrics は 400 日残る (設計書 5-3)。**この ADR の M は、一覧の表だけの保持の期間で、それらを短くしない**。IP を key に持つ metric の保持を短くするかは、別に決める (候補)
- 調べるとき (maintenance の調査) に一覧を見るコマンド (`--format json` とスキーマ。ADR 0054) は、使い道が出てから足す (候補)

## 検討した選択肢

- **`ip_reputation(ip, reason, source, first_seen, last_seen, count)` の 1 行を UPSERT する**: 採らない。日の値の作り直し (途中の値・下限の置き換え) で count を二重に数える。
  直すには「どの日の分をいくつ足したか」を持つことになり、日ごとの行と同じになる (2 節)
- **一覧を表にせず、使うたびに metrics を読む** (ip を key に持つ metric から閾値で拾う): 採らない。metric ごとに key の形と除外が違い、`waf_block` の除外 (レートベースなど) を
  した IP は metric に無い (2' の行からしか作れない)。保持の期間 (M) も metrics (400 日) と分けられない
- **IP をハッシュで持つ**: 採らない。Insights の問い合わせの文に原文が要る (4 節)。5 節の `principal_ips` との突き合わせも原文
- **IP を CIDR (/24・/64) に丸めて、`isIpInSubnet` で絞る**: 採らない (今は)。文の長さには効くが、同じ /24 の別の利用者まで巻き込み、共有の IP の誤検知を広げる。
  IPv6 の /64 は 1 つの回線であることが多いので、IPv6 の多い一覧で文の長さが足りなくなったら、IPv6 だけ /64 にする案を試す
- **時ごとの問い合わせの中で、一覧の IP だけ ip の軸を持つ** (ADR 0065 の 4 節の「条件を満たす行だけ値を持つフィールド」): 採らない (今は)。Insights でその書き方が
  できるかは未確認で、できても一覧はその時の始まりの時点のもので、その日の後の時に載る IP を数えない。できれば読み取りが増えない利点があるので、4 節を確かめるときに一緒に試す
- **フィールドインデックス (`httpRequest.clientIp` に `PutIndexPolicy`) で、絞った問い合わせの読み取りを減らす**: 記録だけにする。filter の頁に、インデックスのある
  フィールドへの `in [...]` は該当しない行を読み飛ばす旨がある。費用は下がり得るが、利用者側の設定と読み取り専用ロールの権限が要る (ADR 0031・0065 と同じ扱い)
- **ADR 0067 の (ii)、ip の軸を持つ 5 本目**: 採らない (0067 のとおり)。読み取りの増え方は 4 節と同じだが、行数の上限に当たる
- **一覧を allowlist.yaml (git 管理) に書き出す**: 採らない。IP の原文を git の履歴に残すことになり、M で消せない。allowlist は人が承認した既知のもの (ADR 0004) で、意味も逆

## 互換

- `ip_list:` と `checks.waf_review.suspect_ip_list:` を書かなければ、今と同じ (一覧を作らず、問い合わせも足さない)
- ストア: `ip_list_days` を足して `schema_version` を上げる (2 節)。古い版の arata は知らない表を読まない (今の動作)
- report.json: count_rule_status の evidence に項目を足すだけ (互換。`schema_version` は上げない。ADR 0054)。`suspect_ratio` の値は listed の分だけ増える。
  Release の本文に、`suspect_ip_list` を書いたソースでは `suspect_ratio` が一覧の IP からの一致を含むことを書く
- 設定: 新しい項目は `ip_list.*`・`retention.ip_list`・`checks.waf_review.suspect_ip_list.*`。どれも雛形が書き出し、`--diff` で見える

## 結果

- 良い点: count_rule_status の suspect が、ADR 0067 の前に数えていた「BLOCK された IP の、許可されたリクエストでの一致」を、行数の上限に当たらずに数えられる。日をまたいで (N 日) 数えられる
- 良い点: ソースをまたいで突き合わせる鍵が、保持の期間を決めた 1 つの表になる (5 節)
- 引き受けるコスト: wafv2 の読み取りが 1 日 1 本 × 1 日分 (組の数だけ) 増える。一覧が大きい日は listed が下限になる
- 引き受けるコスト: IP の原文を持つ表が 1 つ増える (M = 30 日)。rebuild は引き継ぎで、raw からは作れない

## 確かめ方

- シミュレーター (`cwlogstest.Sim`): `filter ... in [...]` を Sim に足し (今の Sim はこの形を解釈しない)、本物の Insights と同じ「完全な文字列の一致」にする
- 値の突き合わせ (ゴールデン): `ip_list.active: 1d`・理由 `[waf_block]`・一覧が 1 本に収まるとき、**(i) + listed が、ADR 0067 の前の suspect (その日 BLOCK された IP からの一致) と同じ値**になること。
  ADR 0067 の前のゴールデン (`equiv_waf.golden` の #119 の前の版) と突き合わせる。`active: 7d` では、前日に載った IP の分だけ増えることを別のテストで固定する
- 組に分けたとき: 一覧を小さな文の上限で分けて流した結果の和が、1 本で流した結果と同じこと。`max_queries` を超えたら `listed_is_lower_bound` になること
- 一覧の規則: 作り直しで二重に数えない (同じ日を 2 回作っても行が同じ)・N と M の境目・休止の後の戻り (first_seen が残り、active_since が変わる)・M を過ぎたら IP の全部の行が消える・
  `source_ips` と `trusted_cidrs` が載らず使われない・読めない IP を捨てる
- ファズ: 問い合わせの文の組み立て (4 節の規則)
- 実データ (開発リードが PR の後に): 大きな利用者の wafv2 で、確定した 1 日について listed を流し、(i) + listed の suspect の割合が、ADR 0067 の前の 5.4% に近い値に戻るか
  (`active: 1d` で比べ、その後 `7d` の値を見る)。あわせて、その日にアクティブな IP の数 (組が何本になるか) と、1 本の読み取り量・時間を見る

## 手間の見積もり

- 表・移行・prune・rebuild の引き継ぎ・設定 (`ip_list`・`retention.ip_list`・N ≦ M の検査・雛形と `--diff`): 1.5 日
- 日の値を作るときに一覧を作る (2' の行・`probe_hits`・`sign_in_failures` から。除外の規則): 1 日
- listed の問い合わせ (組み立て・組に分ける・位置・metric・waf_review の読み方と evidence・playbook): 2 日
- Sim の `in`・ゴールデンの突き合わせ・ファズ: 1 日
- 合計 約 5.5 日

## 未確認の点

- 大きな利用者で、1 日にアクティブになる IP の数 (`waf_block` + `probe`)。数千なら 1〜2 本に収まらず、listed が下限になる。実データで数えてから `max_queries` の既定を決める
- 1 本の問い合わせ (1 日分、`in` の要素が数百) の実行時間。GitHub Actions の実行時間 (有料の前提) に効く
- `in [...]` の要素の数に、文の長さのほかの上限があるか (公式文書には書かれていない。sandbox で数百の要素の文を流して確かめる)
- WAF のログの `httpRequest.clientIp` の IPv6 の書き方が、`netip.Addr.String()` の正規の形 (省略形・小文字) と同じか。違えば `in` の完全な一致で外れるので、
  sandbox のログで確かめ、違えばログの書き方に合わせて文を組む
