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

## 入口のアクセスログと並べる (yields: http_user)

ALB・nginx のログを `http_access` のソースにしていて、アプリのログからは**ユーザー ID と auth の行だけ**を読むなら、このソースに `yields: http_user` を書き、daily に `records: [http_user]` を書く (例は架空)。
行頭に別の角括弧 (ホスト名) が付く独自の formatter の例 (`arata help ai request_lines` の「鍵の書き方」)。`request.id` は鍵の直前の区切りだけを受ける。

```
[web-1] I, [2026-11-01T01:02:03.000000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] Started GET "/orders" for 203.0.113.10 at 2026-11-01 01:02:03 +0000
[web-1] I, [2026-11-01T01:02:03.010000 #1]  INFO -- : [5b0c1d2e-7a3f-4c1b-9e2d-0a1b2c3d4e5f] actor kind=user id=42
```

```yaml
  - id: rails_users                  # sources: の 1 つ。http_access は ALB (format: alb_access) のソースだけが出す
    format: request_lines
    yields: http_user                # 書かなければ http_access (今までどおり)。request.user_id が要る (無ければ CONFIG_INVALID)
    request:
      id: ' -- : \[(?P<request_id>[A-Za-z0-9_@-]{1,255})\] '   # 行頭の角括弧を拾わない。lines・user_id・auth は request_lines の見本と上の見本のまま
profiles:
  daily:
    records: [http_user]             # チェックが要らなくても、この run でこのソースを引く (今は http_user だけ書ける)
```

- `http_access` を出さない (同じリクエストを二重に数えない)。クエリは解釈率の 1 本だけで、日次の metric はすべて `From` が `http_user`。最初の行 (ip と path) は要る (リクエストの数と割合の分母)
- 引くのは `records: [http_user]` か、`http_user` を要るチェックのあるプロファイルの run だけ。どれも無ければ doctor の `records` の行が warn。endpoint_abuse の `sources` には書けない
- report.json の `coverage.formats[].yields` に `http_user` が出る。ID の付いたリクエストが 0 件の run では出ない (ソースは失敗にせず、標準エラーに WARN)

## パスの型 (path_ids)

ログインした利用者の総当たりを見るチェック (`user_id_enumeration`・`user_path_breadth`) は、パスを「型」(ID の位置をまとめた形) にして数える。
規則はソースの `path_ids` に書く (書かなければ、そのチェックは skip)。例は架空。

```yaml
    path_ids:
      segments: ['[0-9]{1,20}', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}']   # 区間の全体に当たれば ID
      templates:                     # 区間の形では分からない位置
        - '/users/:id/profile'       # :id は ID (値は Insights の中で数えるだけで持ち帰らない)
        - '/billing/charges/:id/:any'   # :any は ID ではないが形を問わない区間 (年月など。値は捨てる)
      formats: [json, csv]           # 最後の区間の末尾から外す拡張子 (/orders/42.json と /orders/42 を同じ型にする)
      max_segments: 8                # 必須 (1〜12)
```

- **名前・ログイン名・メールアドレスをパスに使う位置** (`/users/taro/orders`) は、`templates` に `:id` として書く。書かないと、その区間が型に残り、key としてストアと報告に入る
  (メールアドレスらしい・数字を含む長い区間などは arata が `:x` に伏せるが、英字だけの名前は見分けられない)
- `arata doctor` の `path_ids` の行に「1 日に 1 人の利用者しか触らなかった型」の数と例が出る。名前の区間は利用者ごとに違うので、この型になる。例に残るのは印と `templates` の固定の区間だけで、`<n>` は伏せた区間の長さ。
  その位置を `templates` に `:id` で書き足す。値そのものは Insights で引いて確かめる (arata は出さない)
- 年月・日付のように ID ではないが値の変わる区間は `:any` にする (`segments` の数字の規則に当たると ID として数えられ、`-` を含むと型が月の数だけ分かれる)
- `segments` には `/`・`^`・`$`・キャプチャ (`( )`。まとめるのは `(?:...)`) を書かない。`templates` は固定の区間を 1 つ以上含む (`/:any/:id` は誤り)。`arata config check` が確かめる

## 利用者ごとのチェック (user_denied・user_id_enumeration・user_path_breadth)

- 動かすには、ユーザー ID を読む request_lines のソースを `checks.<チェック>.sources` に書く (既定は空で、書くまで何も読まない)。型の要る 2 つ (`user_id_enumeration`・`user_path_breadth`) は `path_ids` も要る。例 (架空): `user_denied: { sources: [app_log] }`
- 拒否を転送 (302 など) で返すアプリは `user_id_enumeration.denied_statuses` に足せる (GET と HEAD だけ数える。ソースがメソッドを取り出すことが要る)。`user_denied.statuses` には書けない
- 判定はどれも、本人の平常帯とアプリの平常帯 (ふだんの日のいちばん多い利用者の値) の両方を超えたもの。閾値は仮の値で、実データで見直す。導入の直後 (アプリの記録のある日が `min_baseline_days` に満たない間) は判定せず `coverage.notes` に残りの日数が出る
- 代わりにログインした操作 (`by` の付いた要求) は数えない。1 つの要求に actor の行が複数あれば、**最後の行**の利用者に数える (種類と ID は同じ行の組。片方が形に合わない行は使わない)
- 指摘の読み方と片付けは `arata help ai playbook <チェック>`

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
