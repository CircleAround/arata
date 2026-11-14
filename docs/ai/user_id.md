# アプリにユーザー ID の行を足して読む (request.user_id / request.auth)

## 使い方

`format: request_lines` のソース (`arata help ai request_lines`) は、アプリを変えずに段 0 のチェック (`login_bruteforce`・`probe_paths`・`endpoint_abuse`) を動かす。
**ユーザー ID の要るチェック**を動かすには、アプリに 2 種類の行 (actor と auth) を足してもらい、`request.user_id` / `request.auth` で読む (ADR 0052)。足さなくても、段 0 は同じに動く。

- arata は読み取り専用で、LLM を呼ばない。アプリへ行を足すのは利用者の開発の作業。この文書は、その形と出し方の勧めと、読む側の設定
- 出すのは**種類と内部の ID だけ**。例の値はすべて架空

## アプリに足す行

```
I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] actor kind=user id=42
I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] actor kind=user id=42 by=staff:5
I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] auth result=success kind=user id=42 via=password
I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] auth result=failure kind=user id=42 reason=invalid
I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] auth result=failure kind=user id=none reason=not_found_in_database
I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] auth result=impersonate kind=user id=42 by=staff:5
```

- **actor**: そのリクエストが認可に使った、ログインした身元の 1 人だけ。ログインしているリクエストにだけ、1 リクエストに 1 行出す。
  `kind` は利用者の種類 (認証の単位。小文字と `_`)、`id` は内部の番号か不透明な ID。パスの中の ID (操作の対象) は出さない
- `by=<kind>:<id>` は、代わりにログインした操作のときだけ付ける。**`by` が実際に操作した人**。`by` の付いたリクエストは、利用者本人の行動として数えない
- **auth**: ログインの結果。項目の順は `result` → `kind` → `id` → `via` → `by` → `reason` で固定
  - `result`: `success` (strategy = パスワードかログインの保持で認証したときだけ)・`failure`・`impersonate` (代わりのログインを始めた時点。`by` 付き)
  - `id`: 失敗では、送られた識別子から利用者を引けたときだけその ID、ほかは `none`
  - `via`: `password` か `remember` (成功だけ)。`reason`: 認証ライブラリが失敗に付ける記号 (Devise なら failure の message の記号。小文字と `_`。合わない値はアプリの側で `other`)
- **出さないもの**: メールアドレス・氏名・ログイン名・送られた識別子・セッションの ID。メールアドレスを ID に使うアプリは、別の内部の ID を出す
- ID の無いリクエスト (ログイン前・webhook・ヘルスチェック) は必ず残る。ログインの成否は、今までどおりパスとステータスでも数える (`login_bruteforce`)

## 出す時点と読み方 (Rails + Devise の例)

```ruby
# Rails + Devise の例 (ApplicationController)。around_action の ensure で出す: 例外・throw・打ち切りのときも動く (after_action は動かない)
prepend_around_action :log_actor

def log_actor
  yield
ensure
  begin
    user = warden.user(scope: :user, run_callbacks: false)   # 副作用なしに読む (current_user はフックを動かす)
    logger.info("actor kind=user id=#{user.id}") if user
  rescue StandardError
    # ログのための処理で応答を壊さない
  end
end
```

- **`ensure` で出す**。アクションが例外を出したとき・`throw` で抜けたとき (未ログインの扱い)・後ろのフィルターが打ち切ったときも動く。ほかのフィルターより前に置く (`prepend_around_action`)
- **処理の後に読む**。ログインのリクエストでは成功した後の利用者が、ログアウトのリクエストでは「いない」が読める (行は出ない)
- **副作用なしに読む**。`current_user` や `authenticate_user!` は、利用者を読んだときのフック (最後の操作の時刻の更新・期限切れの判定) を動かす。ほかの認証の仕組みでも「読むだけ」の入口を使う
- 認証の単位 (scope) が複数あるアプリは、その画面の認可に使った単位の行を出す。代わりにログインしている間は `by=` を付ける
- auth の行は、認証ライブラリの成功・失敗のフックから出す。フックの中でも利用者を読み直さず、渡された値だけを使う。未ログインのまま保護された画面を開いただけのリクエストには出さない

## 設定の書き方

`request:` の下に足す (`id:` と `lines:` は `arata help ai request_lines` の見本のまま)。

```yaml
    request:
      user_id:
        from: app_line               # none (書かないのと同じ) | app_line | debug_sql
        regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})(?: by=(?P<by_kind>[a-z_]{1,32}):(?P<by_id>[A-Za-z0-9_-]{1,64}))?$'
      auth:
        regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] auth result=(?P<auth_result>success|failure|impersonate) kind=(?P<auth_kind>[a-z_]{1,32}) id=(?P<auth_id>[A-Za-z0-9_-]{1,64})(?: via=(?P<auth_via>password|remember))?(?: by=(?P<auth_by_kind>[a-z_]{1,32}):(?P<auth_by_id>[A-Za-z0-9_-]{1,64}))?(?: reason=(?P<auth_reason>[a-z_]{1,64}))?$'
```

- `user_id` の名前付きキャプチャは `user_kind`・`user_id` (必須) と `by_kind`・`by_id` (任意。書くなら 2 つとも)。
  `auth` は `auth_result` (必須) と `auth_kind`・`auth_id`・`auth_via`・`auth_by_kind`・`auth_by_id`・`auth_reason` (任意)。ほかの名前は `CONFIG_INVALID`。
  auth の名前に `auth_` が付くのは、2 つの正規表現が同じクエリに入り、Insights が同じ名前の項目を 2 度定義できないため
- **正規表現は `$` で終える** (終わっていなければ `CONFIG_INVALID`)。行の途中の同じ並び (`Parameters:` の中の利用者の入力) を読まないため
- **前の区切りから書く**。既定の formatter では、Logger の前置きの終わり (` -- : `) とタグを含める。利用者の入力の改行で作られた続きの行 (前置きが無く、行頭がタグ) を読まないため。
  独自の formatter では、実際の行を見て、その形の区切りを書く。アプリが利用者の入力を 1 行のメッセージの全体としてそのまま出していると、同じ行を作れる (アプリの側で、入力をそのままログに出さない)
- **値の形は arata が絞る** (正規表現がどう書かれていても効く): 種類は小文字と `_` の 32 文字まで、ID は英数字・`_`・`-` の 64 文字まで、`auth_result` は 3 つの値、`auth_via` は 2 つの値、
  `auth_reason` は小文字と `_` の 64 文字まで。合わない値 (`@` を含む ID など) は**捨てて数だけ残す** (`user_id_invalid`・`auth` の `invalid`)。ID が数字だけのアプリは `[0-9]{1,20}` のように狭く書いてよい
- 1 つのリクエストに行が複数あれば、最後の行を使う。`auth` は `user_id` が無くても書ける (`auth` だけでは `http_user` は出ない)

## debug_sql (消えうる取り方)

- `from: debug_sql` は、debug レベルの SQL の行 (セッションから利用者を読み込む問い合わせ) から同じ仕組みで読む。**消えうる取り方**: 本番で debug のログが出ているのは誤設定で、
  直されれば予告なく 0 件になる。debug のログは秘密や個人の値を含み得るので、arata のために残さない。`app_line` へ移るまでのつなぎで、doctor は使っている間ずっと warn を出す

## 確かめ方と出る場所

- `arata config check` (オフライン。キャプチャの名前、`$` で終わるか)
- `arata doctor` の `requests` の行に、ID の付いたリクエストの数と割合・種類ごとの数・`by` の数・捨てた数・auth の成功 (手段ごと)・失敗 (理由ごと) が出る。
  「行の種類」の `user_id` / `auth` が 0 なら、正規表現が当たっていないか、アプリがまだ行を出していない
- report.json の `coverage.formats[].requests.users` (`with_user`・`user_rate`・`kinds`・`with_by`・`user_id_invalid`) と `.auth` (`success`・`via`・`failure`・`reasons`・`impersonate`・`invalid`)。
  日次の集計は `user_requests` (種類ごと)・`user_requests_by`・`user_id_invalid`・`auth_success` (手段ごと)・`auth_failures` (理由ごと)・`auth_impersonate`・`auth_invalid`
- **ID の付いたリクエストが 0 件の run** では、ユーザー ID の要るチェックは skip され、`coverage.checks_skipped` に理由が出る (「取れなくなった」を「何も起きていない」と取り違えない)。段 0 のチェックは動く
- ユーザー ID の要るチェックが見るのは、ID の付いたリクエストだけ。`user_rate` が「見ている範囲」の広さ
- クエリの本数とスキャン量は増えない (解釈率のクエリの中で数える)
