# CLAUDE.md

arata (AWS ログ定期監査エンジン) と aratam (その出力を LLM で要約して通知するコマンド) の開発規則。
最初に読むもの: `README.md` → `docs/design.md` → `docs/aratam.md` → `docs/adr/README.md` → `docs/roadmap.md`。
LLM 向けの使い方は `go run ./cmd/arata help ai` (バイナリに埋め込んだ文書) で読める。

## 守ること

### 顧客の情報を書かない (最重要)

このリポジトリは公開する可能性がある。**特定の顧客に関する情報を一切書かない**。
コード・例・テスト・ゴールデン・文書・コミットメッセージ・PR 本文・Issue のすべてが対象。

- 顧客名、AWS アカウント ID、ロググループ名、ロール名、利用している SaaS 名、固有のパス、担当者のハンドル名
- 例は架空の値を使う。アカウント ID は `123456789012` (自アカウント) と `111122223333` (外部 SaaS)、承認者は `alice`、ロググループは `prod-nginx-access` のような名前
- 顧客固有の設定は顧客側のリポジトリか実行環境に置く。「最初の適用先は X」のような記述も書かない
- 判断: 設計書 1 章「リポジトリの例」

### 開発の方法

- GitHub-Flow。`main` から枝を切り、PR でマージする。`main` に直接 push しない
- TDD。テストを先に書いて失敗を確かめてから実装する。ゴールデン (testdata) を変えるときは PR に理由を書く
- テストは **実 AWS・実 LLM・実 Slack・実 `claude` に接続しない**。`httptest`、偽の実行ファイル、固定値で差し替える。
  テストが PATH の本物の `claude` を起動しないことを必ず確かめる (過去に 1 度起きた)
- Go は `$HOME/.local/go/bin` の公式 tarball (README「開発」)。cgo は使わない (単一静的バイナリ。ADR 0002)
- `go test ./...` / `go vet ./...` / `gofmt -l $(git ls-files '*.go')` を通してから push する。CI は `go mod verify`・age-gate・govulncheck・ビルドも回す
  (`gofmt -l .` は `deploy/sandbox/node_modules` の中の Go の雛形まで読んで失敗するので、git 管理のファイルだけを見る)
- `deploy/sandbox` (CDK、TypeScript) を変えたら `pnpm test` / `pnpm typecheck` / `pnpm synth` も通す (deploy はしない。ADR 0020)
- 書き込み系の操作 (リリース作成、タグ push、設定変更) は目的と副作用を一言説明してから行う

### 依存とサプライチェーン (ADR 0017・0019)

- 標準ライブラリで無理なく書けるものは依存にしない。新しい依存は追加前に理由を PR で説明する
- 依存は公開から **7 日以上**経った版だけ (CI の `tools/agegate` と Dependabot の cooldown の 2 段構え)。
  `go get` した直後の版は CI で落ちるので、1 つ前の版を選ぶ
- GitHub Actions は SHA で固定し、版はコメントに書く。`permissions` は最小にする
- SQLite (`modernc.org/sqlite`) は残す (決定済み)。cobra / x/time は使わない

### 判断の記録

- 「なぜそうしたか」を残す。小さな判断は `docs/design.md` / `docs/aratam.md` の該当箇所に「決定:」として、
  却下した案があるものや外部に影響するものは `docs/adr/NNNN-*.md` に (`docs/adr/README.md` のテンプレートと一覧)
- ADR の番号は並行する PR で衝突しやすい。PR を出す前に `main` と open な PR の番号を確かめる
- 採用済みの ADR は書き換えず、新しい ADR で置き換える

### コミット・PR の書式

- コミットメッセージは日本語。末尾に `Co-Authored-By: <使ったモデル名> <noreply@anthropic.com>` (例: `Claude Fable 5.1`)
- 文書だけの変更は `[skip ci]` を付ける
- PR タイトルは `[AI]` で始める。本文の末尾に `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- PR 本文には、何を・なぜ・どう確かめたか (テスト、実動確認の内容) を書く

### 委任とレビュー

- 作業を委任したときは、リーダーが PR をレビューし、できるだけ実データで動かして確かめてからマージを判断する。
  LGTM だけでマージしない。レビューで直すことは「何を・なぜ」を添えて担当者に戻す
- 担当者には上の規則 (顧客情報、TDD、実環境に接続しない、依存、書式) を最初の指示に含める
- 終わった委任の worktree とセッションは閉じる

### arata の性質 (壊さないこと)

- arata は **読み取り専用**。AWS の書き込み系 API は呼ばない (例外は `iam:GenerateCredentialReport` のみ。設計書 8 章)
- arata は LLM を使わない (ADR 0001)。LLM と通知は aratam が担い、両者は `--out` の出力ファイルだけで連携する (ADR 0018)
- aratam は判定を LLM に任せない。重大度の下限・finding 欠落の補完・LLM 失敗時の原文送信・入力が無い/古いときの通知は規則で固定 (`docs/aratam.md` 2 章)
- レポートと通知に個人を特定できる値 (メールアドレス、氏名) を書かない。主体は ARN や ID で表す
- 暗黙の既定を持たない。実行されるチェックは設定に書いたものだけ (ADR 0014)。新しい既定値を足したら `config init --diff` で見えるようにする
- `cmd/aratam/deps_test.go` が aratam の依存を許可リストで固定している。aratam に SQLite や監査用 AWS SDK をつながない

## よく使うコマンド

```bash
make test            # go test ./... (ユニット + コマンドレベル e2e)
make vet lint fmt
make build-local     # bin/arata (このホスト向け)
go build -o bin/aratam ./cmd/aratam
go list -m -json all | go run ./tools/agegate -days 7   # 依存の待機期間チェック (CI と同じ)
go run ./cmd/arata help ai                               # LLM 向けの使い方
```

## ディレクトリ

- `cmd/arata`, `cmd/aratam` — CLI (標準 flag の上の `internal/subcmd`)
- `internal/config` 設定 / `internal/collect` 収集 (cloudtrail, cwlogs, account) / `internal/store` JSONL + SQLite /
  `internal/checks` チェック / `internal/engine` run の流れ / `internal/report` レポート (`schema` は標準ライブラリだけ) /
  `internal/allowlist` 既知リスト / `internal/scaffold` 雛形 / `internal/notify`・`internal/llm`・`internal/slack` aratam
- `docs/ai/*.md` はバイナリに埋め込まれる。変えたらテストのゴールデンも変わる。新しいチェックを足したら `docs/ai/playbooks/<check>.md` (対処手順。ADR 0024) も書く (無ければテストが落ちる)
- `tools/agegate` CI 用。`examples/` は架空の値の設定例
- `deploy/iam/readonly-role.yaml` 顧客に配る読み取り専用ロール (素の CFN) / `deploy/sandbox` 試験環境 (CDK、pnpm、Node 24。Go とは独立。ADR 0020)
