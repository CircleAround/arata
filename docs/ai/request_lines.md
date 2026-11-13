# 複数行のアプリのログをリクエスト単位に読む (request_lines)

## 使い方

1 リクエストが複数行に分かれ、各行に同じ request_id が付くログ (Rails の既定のログなど) は、`format: request_lines` で読む。
arata は Logs Insights の中で行を request_id ごとにまとめ、その結果に `http_access` の集計を当てる。アプリは変えない。チェックと設定 (`checks.login_bruteforce` など) は 1 行のログと同じ。

項目の揃う 1 行のログ (ALB・nginx) があるなら、そちらを使う (UA があり、スキャン量も少ない)。アプリのログは行が多く、1 本あたりのスキャン量が大きい。`max_scan_gb` を書く。

- arata は**読み取り専用**で、LLM を呼ばない。設定の正規表現は、利用者の環境の LLM が**見本の行から**書いてよい。効くのは設定に書いた規則だけ
- 行を LLM に渡す前に、メールアドレスなどの個人を特定できる値を伏せる (氏名は機械的に伏せられないので、渡す範囲を人が決める)
- 書いたら必ず道具で確かめる (下の「確かめ方」)。例の値はすべて架空

## 見本 (Rails の既定のログ)

Logger の既定の formatter と `config.log_tags = [:request_id]` (本番の既定) の形:

```
I, [2026-11-01T01:02:03.000000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] Started POST "/users/sign_in" for 203.0.113.10 at 2026-11-01 01:02:03 +0000
I, [2026-11-01T01:02:03.004000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] Processing by Devise::SessionsController#create as HTML
I, [2026-11-01T01:02:03.016000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] Completed 422 Unprocessable Content in 12ms
```

```yaml
sources:
  - id: rails_app
    kind: cloudwatch-logs
    log_group: prod-app
    format: request_lines
    max_scan_gb: 5
    request:
      # まとめる鍵。名前付きキャプチャは request_id だけ。前の区切りまで含めて書く
      id: '(?:^| -- : )\[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] '
      # max_duration: 60s            # 1 リクエストの行が出終わるまでの見込み (既定 60s)。問い合わせ範囲の後ろに足す余白
      lines:
        - name: started              # ip と path を取り出す行 = 最初の行。リクエストはこの行の数で数える
          regex: 'Started (?P<method>[A-Z]+) "(?P<path>[^"?]*)[^"]*" for (?P<ip>\S+) at '
        - name: completed
          regex: 'Completed (?P<status>\d{3}) '
        - name: no_route             # 経路の無いリクエストは Completed の行が出ない。例外の行があれば 404 として数える
          regex: 'ActionController::RoutingError'
          set: { status: 404 }
    # expected_match_rate: 0.8       # request_id の付いた行 / 全行
    # expected_complete_rate: 0.8    # 最初の行のあるリクエスト / request_id の数 (既定 0.8)
```

## 書き方の決まり

`arata config check` がオフラインで確かめる。破ると `CONFIG_INVALID`。

- `request.id` の名前付きキャプチャは `(?P<request_id>…)` だけ。`request.lines` で取り出せる項目は `ip`・`method`・`path`・`status`・`ua`・`duration` だけ
  (`Parameters:` の行のように利用者の入力が入る行から、任意の値を取り出す設定は書けない)
- `ip` と `path` は同じ行の種類で取り出す。同じ項目を 2 つの行の種類で取り出さない。値の出ない場合の補いは `set` (書けるのは `status` だけ)
- 正規表現は Go (RE2) で読める形。先読み・後方参照は使えない。行の種類は 8 つまで、1 つ 512 文字まで

## 鍵 (request.id) の書き方

いちばん大事な項目。誤ると数が壊れる。

- 行頭だけに固定しない (`^\[…\]`)。既定の formatter では鍵は ` -- : ` のあとに来るので、1 行も当たらない
- 「最初の角括弧」を取らない (`\[(?P<request_id>[^\]]+)\]`)。時刻やホスト名の角括弧を鍵に取り違え、全部の行が数個の鍵にまとまる
- 例外など複数行のメッセージは、2 行目以降が別の行になり、Logger の前置きが無く行頭が `[<request_id>] ` になる。見本が「前置きのあと」と「行頭」の両方を受けているのはこのため
- **行頭に別の角括弧 (ホスト名・コンテナの ID など) が付く独自の formatter** では、見本の「行頭」の選択肢がその角括弧を拾う。実際の行を見て、
  鍵の直前の区切りだけを受ける形に書き直す (例: `' -- : \[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] '`)
- 鍵の文字を UUID の形に絞らない。Rails はリクエストの `X-Request-Id` ヘッダーの値を (英数字・`_`・`-`・`@` 以外を除き、255 文字までに切って) request_id に使うので、
  絞ると、形の違う ID を送ったリクエストが全部のチェックから外れる

## 確かめ方

1. `arata config check` (オフライン。正規表現が読めるか、キャプチャの名前が決まったものか、ip と path が同じ行にあるか)
2. `arata doctor` の `requests` の行 (直近 `--window` の行をまとめた結果。解釈率のクエリを 1 本流すので、その分のスキャンの費用がかかる)
   - 「まとめられた割合」が `expected_complete_rate` 未満なら ng (`FORMAT_MISMATCH`)。最初の行の正規表現が当たっていない (「行の種類」の started の数を見る) か、鍵が行ごとに違う値 (時刻など) になっている
   - 「request_id の異なりの数が最初の行の数の半分未満」も ng。`request.id` が別の角括弧 (時刻・ホスト名) を拾っている。実際の行と見比べ、鍵の直前の区切りを含めて書き直す
   - 「行の種類」は種類ごとの当たった行数。0 の種類があれば warn (その行の正規表現を見直す。経路の無いリクエストが窓に無いだけなら、そのままでよい)
   - `match_rate` (request_id の付いた行の割合) は、SQL や起動時の行などタグの付かない行が多いロググループでは低くて正常 (`expected_match_rate` を下げる)
3. `arata run <profile> --dry-run` で、実際に出る指摘を見る。ログイン失敗を 1 回起こして数えられるかを確かめる (`checks.login_bruteforce` の `paths`・`failure_statuses`)
4. run の後は report.json の `coverage.formats[].requests` (`complete_rate`・`request_id_reused`・`starts_untagged`) を見る

## 送る側が選べる値

- request_id は信用しない。同じ ID を使い回されても、リクエストの数は最初の行の数で数えるので減らない。ただし 1 つの ID に入った複数のリクエストは項目 (パス・ステータス) が混ざる。
  その ID の数は `request_id_reused` (report.json の `coverage.formats[].requests`、doctor) に出る。使い回しが大半を占めると `FORMAT_MISMATCH` で止まる
- 記号だけの `X-Request-Id` を送ると、Rails はその行に request_id のタグを付けない。その行はリクエストにまとめられず、どの集計にも入らない (`starts_untagged` に数が出る)
- どちらも、前段 (リバースプロキシ・ALB の後ろの nginx など) で `X-Request-Id` を上書きすれば防げる。できるなら設定する
- `for <IP>` が利用者の送信元か、前段のプロキシの IP かは、アプリの「信頼するプロキシ」の設定で決まる。doctor では判定できない。Logs Insights で自分のリクエストの行を見て確かめる

## 数え方

- リクエストは最初の行の時刻の日に数える。日をまたぐリクエストは始まった日の分
- 件数は最初の行の数。同じ request_id に最初の行が複数あれば、その数だけ数える
- 問い合わせは範囲の後ろに `request.max_duration` (既定 60s) だけ広げて、終わりぎわに始まったリクエストの残りの行を拾う。これより長いリクエストはステータスが欠ける
- Rails の既定のログには UA が無い。endpoint_abuse の「同じ UA が多くの IP にまたがる」は出ない
