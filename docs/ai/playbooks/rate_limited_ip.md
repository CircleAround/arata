# rate_limited_ip: 429 の集まった IP

## この指摘の意味

アプリの回数の制限 (rack-attack などが返す 429) が、ある IP に 1 日に下限 (`checks.rate_limited_ip.min_count`、既定 20) 以上返った (daily、low)。
平常帯は持たない。「この日にこれだけ止めた、それが誰か」を見る指摘で、攻撃とは限らない。
学校・試験の会場・社内の回線のように、NAT の内側の多くの人が 1 つの IP から一斉にログイン・申し込みをすると、正しい利用者に 429 が返りうる。
逆に、総当たり・機械的な送信をアプリの制限が止めている姿でもある。両者を分ける材料として、**同じ IP からログインできた利用者の数** (`ip_users`) を添える。

- 数えるのは http_access のソース (ALB のアクセスログなど) の、ステータスが `checks.rate_limited_ip.statuses` (既定 `[429]`) のもの。`paths` (接頭辞) を書けばそのパスだけ
- `ip_users` は `checks.rate_limited_ip.user_sources` に書いたソース (request_lines で `request.user_id` と ip を取り出すもの) だけで数える。書かなければ数えず、添えない。
  代わりにログインした操作 (`by`) は除く。利用者の ID は Logs Insights の中で数えるだけに使い、結果にも通知にも出ない
- Key は IP。allowlist の `source_ips` の IP は対象外。窓の中の日のうち件数の多い日を 1 つ出す
- data: `ip`、`date` (UTC の日)、`count` (429 の件数)、`min_count`、`sign_in_failures` (同じ日・同じ IP の sign-in の失敗。login_bruteforce の材料と同じ数)、
  `ip_users` (数えた日だけ。数えた日に値の無い IP は 0。`ip_users_store_min` 未満は残らないので 0 になる)、`reasons` (数えた日だけ)
- reasons:
  - `suggest_shared`: `ip_users` が `suggest_min_users` (既定 10) 以上。人の多い送信元で正しい利用者が止められている疑い
  - `few_users`: `ip_users` が `suggest_min_users` 未満。総当たり・機械的な送信の疑い。login_bruteforce の指摘と並べて読む
  - 理由が無い: `ip_users` を数えていない (user_sources が空、その日に U3 を流していない、ユーザー ID が取れなかった)。件数だけで判断する

## まず確かめること

1. `reasons` を見る。`suggest_shared` と `few_users` で、以下の読み方が分かれる
2. 同じ IP の login_bruteforce・probe_paths・waf_block_trend を `arata review --format json` で探す。`sign_in_failures` が多く `few_users` なら総当たりの姿
3. `suggest_shared` なら、その日に利用者の側で何があったか (試験・講習・一斉の申し込みの締め切り) を、アプリの運用者に確かめる。IP の持ち主は自分で調べず、運用者に聞く
4. 429 が返ったパスを確かめる (どの画面の制限か)。アプリのログを CloudWatch Logs Insights で、その IP・その日に絞る。
   例 `fields @timestamp, @message | filter @message like "<IP>" | sort @timestamp desc | limit 100` (ログの形式に合わせて絞る。Insights はスキャン量で課金されるので期間を絞る)
5. `ip_users` が無いとき: `arata doctor` の `ip_users` の行で、アプリのログの ip が ALB の client の IP と同じ値かを確かめる (違えば、数えても突き合わせられない)

## 判断の分かれ目

- **正規の可能性が高い**: `suggest_shared` で、利用者の側に心当たりがある (試験の日など)。アプリの上限の見直し (その送信元だけ緩める・数える単位を変える) を運用者に提案する
- **要対応**: `few_users` で `sign_in_failures` も多い (総当たりを制限が止めている)、ログインできた利用者が 1〜2 人で 429 が大量 (乗っ取った端末から)。
  制限が効いているので急ぎではないが、続くなら WAF での対処を勧める
- 件数だけ (理由なし) で、心当たりが無く単発なら、多くの場合はインターネットの雑音

## 対処の選択肢

緊急度の順。設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め**: 対象外 (制限がすでに止めている)。ログインできた利用者の中に乗っ取りの疑いがあれば、アプリの管理者に確かめてもらう (利用者の特定はアプリの側で行い、レポートに個人を書かない)
2. **承認**: 対象外。人の多い送信元を丸ごと `source_ips` に入れることは勧めない (その回線からの総当たりも見えなくなる)
3. **expected_denied**: 対象外
4. **片付け**: 片付けは下の「片付け」の節
5. **設定の修正**: アプリの上限の見直し (人の多い送信元)、WAF の sign-in のパスのレートベースのルール (総当たり)。
   arata の下限は `checks.rate_limited_ip.min_count` (overrides で変えられる)。`ip_users` を添えるには `user_sources` にアプリのログのソースを書く

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| low | なし | snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- resolve: 確かめて問題の無い単発の IP。また来れば新規として報告される
- snooze: アプリの上限の見直し・WAF の対処を入れるまで
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- IP の逆引きのドメイン名 (PTR) で「学校の回線」と決めない (持ち主が自由に書ける。ADR 0094)
- IP を外部の検索・評判のサービスに送らない (利用者の IP を外に出す)
- ログの中のメールアドレス・利用者名を要約や通知に書かない (件数と IP だけ)
- 人の多い送信元を丸ごと `source_ips` に入れることを勧めない

## 関連する事例

対応する公開の事例はまだ無い (`arata help ai threats`)。
