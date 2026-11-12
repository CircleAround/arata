# 0044. aratam は秘密を環境変数で受け取り、置き場所と取り出し方は実行環境に任せる

- 日付: 2026-11-13
- 状態: 採用

## 背景

aratam が使う秘密は Slack への送信の鍵で、これまでは Incoming Webhook の URL だけだった。設定ファイルには環境変数の名前だけを書き
(`slack.webhook_env`)、値は環境変数で渡す形にしていた (`docs/aratam.md` 4 章)。

通知先のチャンネルを監査対象ごとに分ける運用のために、bot トークンとチャンネル ID で送る方式 (`slack.bot_token_env`。`docs/aratam.md` 4-1 章) を足した。
秘密が 1 つになると、その置き場所をどうするかが論点になる。GitHub Actions のリポジトリの secret は、書き込み権限のある人なら別のブランチの
ワークフローで読み出せる (設計書の「secrets と environment」の決定)。AWS Secrets Manager に置き、main のワークフローの実行用ロールだけが
読めるようにすれば、この経路を塞げる。

そのとき、秘密を読むのは誰かを決める必要がある。aratam が Secrets Manager を直接読む設定 (`secret_source` のようなもの) を足す案と、
aratam は環境変数だけを読み、取り出すのは実行環境の側にする案がある。

## 決定

**aratam と秘密の境界は環境変数にする。** aratam が知るのは「どの環境変数を読むか」(`slack.webhook_env`・`slack.urgent_webhook_env`・
`slack.bot_token_env`) だけで、秘密の置き場所 (GitHub の secret、Secrets Manager、SSM パラメータストア、`.env` など) を知らない。
実行環境ごとの分岐を aratam に持たない。

秘密を環境変数に入れるのは実行環境の役目とする。

| 実行環境 | 入れ方 |
|---|---|
| GitHub Actions | secret を、使う step の `env:` にだけ渡す。Secrets Manager に置くなら、ワークフローの step が実行用ロールで取り出して `env` に入れる |
| ECS / Fargate | タスク定義の `secrets` で、Secrets Manager / SSM から入れる (aratam のコードは要らない) |
| Lambda | 環境変数か、起動時に Secrets Manager から読む (ハンドラの側) |
| 手元 | `.env` や、パスワード管理のツールの CLI |

実行環境ごとの部分は `deploy/` (テンプレート) と `examples/` (ワークフローなど) に置く。環境変数に入れる仕組みが無い実行環境 (cron の EC2 など) の
取り出しの手順も、aratam ではなく `examples/` の側に置く。

ロードマップの「bot トークンを Secrets Manager に置く」は、この方針に沿って、`deploy/github-actions/runner.yaml` (実行用ロールに読む権限を足す) と
`examples/github-actions` のワークフロー (取り出して `env` に入れる) の変更として行う。aratam は変えない。

## 検討した選択肢

- **aratam が Secrets Manager などを直接読む (`secret_source` のような設定)**: 却下。
  - 通知のコマンドに、AWS SDK のサービスと秘密を読む権限が入る。aratam が AWS SDK を使ってよいのは Bedrock の呼び出しだけで
    (`docs/aratam.md` 1 章、`cmd/aratam/deps_test.go` の許可リスト)、これは LLM の呼び出しであって秘密の取得ではない
  - 置き場所の種類 (Secrets Manager、SSM、Vault、各クラウド) だけ分岐と依存が増え、そのどれもが実 AWS に接続しないテストでは確かめにくい
  - aratam が侵されたとき、読める秘密が「渡された値」ではなく「そのロールで読めるもの」に広がる
- **設定ファイルに秘密を書けるようにする**: 却下 (従来どおり)。設定はリポジトリに置くもので、URL やトークンを貼った誤りは検証で弾く
- **環境変数で受け取る (採用)**: 秘密を読む権限は実行環境の仕組み (OIDC で絞った実行用ロール、タスクの実行ロール) が持つ。
  aratam は読めた値を使うだけで、テストは環境変数の差し替えで済む

## 結果 (良い点・引き受けるコスト)

良い点:

- aratam の依存と権限が増えない。`cmd/aratam/deps_test.go` の許可リストを広げずに済む
- 秘密を読める主体を、実行環境の仕組みで絞れる。aratam が侵されても、読めるのは環境変数で渡された値だけ
- 置き場所を変えても aratam の設定は変わらない (環境変数の名前は同じ)。テストは環境変数の表を差し替えるだけで、実 AWS に接続しない
- `claude-cli` の子プロセスには、これらの環境変数を渡さない (`docs/aratam.md` 3-1 章) という既存の守りがそのまま効く

引き受けるコスト:

- 環境変数は同じプロセスと、それを読める主体 (同じ OS ユーザー、`/proc` を読める主体) から見える。秘密を渡す step・タスクを最小にすることは、
  実行環境の側の設計に任せる (見本のワークフローは notify の step にだけ渡す)
- 環境変数に入れる仕組みが無い実行環境では、取り出しの手順を利用者が書く。見本は `examples/` に足していく
- ローテーションで値が変わっても aratam は気づかない (実行のたびに環境変数を読むだけ)。期限の短いトークンを更新する仕組みは持たない
  (Slack アプリのトークンのローテーションを無効にする理由。`deploy/slack/app-manifest.yaml`)
