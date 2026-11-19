# 0075. request_lines のソースに `yields: http_user` を明示して http_access を出さないようにし、プロファイルの `records` で、要るチェックが無くても引かせる

- 日付: 2026-11-19
- 状態: 採用 (2026-11-19、開発リードの判断)

例の値はすべて架空。

## 背景

`format: request_lines` のソース (ADR 0051) は必ず `http_access` を出し、`request.user_id` を書けば `http_user` も出す (ADR 0052)。

入口のアクセスログ (ALB の `alb_access`・nginx) を `http_access` のソースにしている監査対象で、アプリのログ (Rails の複数行のログ) から
ユーザー ID (actor の行) と auth の行だけを読みたい、という求めがあった。今の形でアプリのログのソースを足すと、次のことが起きる。

- 同じリクエストを入口とアプリの 2 か所で数える。`http_access` の日次の集計 (`sign_in_failures`・`probe_hits`・`probe_paths`) は、チェックが
  ソースをまたいで足す (`internal/checks/baseline.go` の `loadSeries`) ので、login_bruteforce・probe_paths の数が二重になる。endpoint_abuse も
  `sources` を書かなければ両方を読む。文書は「1 つの入口につき 1 つ」と書いている (`docs/ai/logs.md`)
- アプリのログは行が多く、`http_access` のための集計のクエリ (`http_hits`・endpoint_abuse) の分だけスキャンの費用が増える

もう 1 つの問題: `http_user` を要るチェックはまだ無い (ADR 0071 は採用済みで未実装)。run は、プロファイルのチェックが要る種類 (`Needs()`) を出すソースだけを引く
(`internal/engine/engine.go` の `neededKinds`)。`http_access` を出さないソースは、今のどのプロファイルの run にも引かれず、ユーザー ID と auth の日次の集計
(`user_requests`・`auth_*`) と coverage が貯まらない。段 1 のチェック (ADR 0071) の平常帯は、この日次の集計を前もって貯めておく必要がある。

## 決定

### 1. ソース: 既存の `yields` に `http_user` を書けるようにする

```yaml
  - id: rails_users
    kind: cloudwatch-logs
    log_group: prod-rails
    format: request_lines
    yields: http_user        # 書かなければ http_access (今までどおり)
    request: { id: …, lines: […], user_id: { from: app_line, regex: … }, auth: { regex: … } }
```

- `format: request_lines` の `yields` に `http_access` (既定) と `http_user` を書ける。ほかの形式は今のまま (`http_user` は `CONFIG_INVALID`)
- `yields: http_user` には `request.user_id` (`from` が `none` でないもの) が要る。無ければ何も出さないソースになるので `CONFIG_INVALID`。
  auth の集計は `http_user` の metric なので、`auth` だけでは足りない
- `request.lines` の規則 (ip と path を同じ行で取る) は今のまま。リクエストの数と ID の付いた割合 (`user_rate`) の分母が最初の行の数だから
- このソースは `http_user` だけを出す。流すクエリは**解釈率のクエリの 1 本だけ** (ユーザー ID と auth の数はこの 2 段目の軸で数える。ADR 0052)。
  探索パスの印も付けない。`sign_in_failures`・`probe_hits`・`probe_paths`・endpoint_abuse の集計は出さない。日次の metric (`lines_total`・`requests_total` を含む) の `From` はすべて `http_user`
  (endpoint_abuse の「集めた日」の判定は `From` が `http_access` の `lines_total` だけを見るので、混ざらない)
- endpoint_abuse の `sources` には書けない (今の検査が `http_access` を出すソースを要る)
- ID の付いたリクエストが 0 件の run は、今と同じく `Unavailable` (ADR 0051 の 2 節)。ソースは失敗にせず、標準エラーに WARN を出す。毎日の run は落ちない

### 2. プロファイル: `records` で、要るチェックが無くても引く種類を書く

```yaml
profiles:
  daily:
    window: 24h
    checks: [default-daily]
    records: [http_user]
```

- `profiles.<name>.records` に書いた記録の種類は、プロファイルのチェックが要らなくても、その run で引く (`neededKinds` に足す)。
  その種類を出すソースだけを引き、collector もその種類を選んで集める (`Select`)
- 今書けるのは `http_user` だけ。重複と、それを出すソース (user_id のある request_lines) が無い設定は `CONFIG_INVALID` (書いても何も起きない設定を黙って受け取らない)
- 暗黙の既定は持たない (ADR 0014)。雛形は daily にコメントで見せるだけ (`# records: [http_user]`)。`config init --diff` が出す既定値は増えない
- `http_user` を要るチェック (ADR 0071) が入れば、そのプロファイルは `records` が無くても引く。`records` は残っても害は無い
- 設計書 2-5 の「プロファイルのチェックが `http_user` だけを必要としていても、このソースを引く」は変わらない (`http_access` も出すソースの話)。
  `records` は、要るチェックがまだ無い間の引き方を埋める

### 3. 見えるところ

- report.json の `coverage.formats[].yields` に、その run でソースが出した記録の種類を出す (取れなかった種類と、失敗したソースの種類は入らない)。
  項目を足すだけなので `schema_version` は上げない (ADR 0054)。report.md の解釈率の行にも「記録: …」を添える
- doctor は `yields: http_user` のソースに `records` の行を出す。引くプロファイル (`records` か `http_user` を要るチェック) を並べ、どれも無ければ warn
  (設定としては正しく、`arata collect` では引けるので ng にしない)
- `config check` は 1・2 の規則を設定の読み込みで確かめる (run・doctor と同じ規則)

## 却下した案

- **`request.access: false` のような request の下の印**: 同じことを別の語で表す。ソースが出す種類は既に `yields` で表している (`wafv2` の `waf_action` と同じ語彙)。
  `yields` なら「http_access を出すソースか」の判定 (endpoint_abuse の sources など) も今の比較のまま効く
- **`http_access` を要るプロファイルは、`http_user` だけのソースも引く** (同じ入口の付き物として): 設定が要らないが、引くかどうかが書いていないことで決まる (ADR 0014 に反する)。
  hourly に http_access のチェックを入れたときに、知らずにアプリのログを毎時読むことにもなる
- **既存のチェックの `Needs()` に `http_user` を足す**: 要らない種類を要ると言うことになり、skip の判定 (`no http_user source`) が壊れる
- **`arata collect` を別に回してもらう**: 見本のワークフローは `arata run` だけで、手順と GitHub Actions の実行時間が増える。`collect` は位置を読みも進めもしない (ADR 0064)
- **名前を `collect` にする**: ソースの `collect: hourly` (ADR 0065) と同じ語になり紛らわしい。プロファイルの側は「記録の種類」を並べるので `records` にした
  (`docs/ai/logs.md` の「記録」と同じ語)
- **`records` に任意の種類を書けるようにする**: `log_hygiene` を daily で引くと weekly のスナップショットを置き換え (ADR 0050)、`http_access` を hourly で引くと費用が増える。
  チェック無しで引く理由が出た種類から足す

## 影響

- 設定: `sources[].yields` (request_lines で `http_user`)、`profiles.<name>.records`。どちらも書かなければ今と同じ
- 出力: `coverage.formats[].yields` (足しただけ。互換)。doctor の行の項目に `records`
- 費用: `yields: http_user` のソースは解釈率のクエリの 1 本だけなので、同じロググループを今の形で読むより少ない。引くのは `records` を書いたプロファイルの run だけ
- 文書: `arata help ai user_id` の「入口のアクセスログと並べる」、`request_lines`・`logs`・`report` から案内。設計書 2-5
