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
- PR の本文・コメント・Release の本文・ブランチ名も対象。公開すれば全部読める
- CI (`secrets-scan.yml`) が一般的な秘密と禁止語を全履歴と GitHub の本文で検査する。禁止語の一覧はリポジトリの外にあり、その中身をどこにも書き写さない。手元では `make scan-sensitive`。運用は `docs/sensitive-scan.md`
- 判断: 設計書 1 章「リポジトリの例」、ADR 0036

### 開発の方法

- GitHub-Flow。`main` から枝を切り、PR でマージする。`main` に直接 push しない
- TDD。テストを先に書いて失敗を確かめてから実装する。ゴールデン (testdata) を変えるときは PR に理由を書く
- テストは **実 AWS・実 LLM・実 Slack・実 `claude` に接続しない**。`httptest`、偽の実行ファイル、固定値で差し替える。
  テストが PATH の本物の `claude` を起動しないことを必ず確かめる (過去に 1 度起きた)
- Go は `$HOME/.local/go/bin` の公式 tarball (README「開発」)。cgo は使わない (単一静的バイナリ。ADR 0002)
- `go test ./...` / `go vet ./...` / `gofmt -l $(git ls-files '*.go')` を通してから push する。CI は `go mod verify`・age-gate・govulncheck・ビルドも回す
  (`gofmt -l .` は `deploy/sandbox/node_modules` の中の Go の雛形まで読んで失敗するので、git 管理のファイルだけを見る)
- 信用できない入力 (ログ由来の値・LLM の出力・利用者のファイル) を解釈する関数を足す・変えるときは、ファズテスト (`Fuzz*`) も足す・通す。
  性質は「パニックしない」だけにせず、守る規則を書く。失敗した入力は seed か `testdata/fuzz` に残して本体を直す (ADR 0041、`docs/fuzzing.md`)
- CI の `sast.yml` は golangci-lint (gosec・staticcheck。設定は `.golangci.yml`) を回す。抑制は `#nosec <規則> -- <理由>` の形で理由を必ず書く (ADR 0037)
- `deploy/sandbox` (CDK、TypeScript) を変えたら `pnpm test` / `pnpm typecheck` / `pnpm synth` も通す (deploy はしない。ADR 0020)
- 書き込み系の操作 (リリース作成、タグ push、設定変更) は目的と副作用を一言説明してから行う

### 依存とサプライチェーン (ADR 0017・0019)

- 標準ライブラリで無理なく書けるものは依存にしない。新しい依存は追加前に理由を PR で説明する
- 依存は公開から **7 日以上**経った版だけ (CI の `tools/agegate` と Dependabot の cooldown の 2 段構え)。
  `go get` した直後の版は CI で落ちるので、1 つ前の版を選ぶ
- 例外: 脆弱性の修正版は、該当を道具で確かめ、直した版がその版だけで、公式の配布元から取れ、チェックサムを確かめたなら、7 日を待たずに上げる。
  Go のツールチェーンにも依存にも当てはめる。PR は修正だけにし、本文に脆弱性の ID と公開日を書く (ADR 0043、`docs/supply-chain.md`)
- GitHub Actions は SHA で固定し、版はコメントに書く。`permissions` は最小にする。CI の `tools/actionsgate`・zizmor が確かめる。`uses` を変えたら `gh actions-lock --no-narrow` で `actions.lock` も更新する (`--no-narrow` を忘れると uses がタグに書き換わる。ADR 0035・0039・`docs/supply-chain.md`)
- SQLite (`modernc.org/sqlite`) は残す (決定済み)。cobra / x/time は使わない

### 判断の記録

- 「なぜそうしたか」を残す。小さな判断は `docs/design.md` / `docs/aratam.md` の該当箇所に「決定:」として、
  却下した案があるものや外部に影響するものは `docs/adr/NNNN-*.md` に (`docs/adr/README.md` のテンプレートと一覧)
- ADR の番号は並行する PR で衝突しやすい。PR を出す前に `main` と open な PR の番号を確かめる
- 採用済みの ADR は書き換えず、新しい ADR で置き換える

### コミット・PR の書式

- コミットメッセージは日本語。末尾に `Co-Authored-By: <使ったモデル名> <noreply@anthropic.com>` (例: `Claude Fable 5.1`)
- `[skip ci]` は付けない。main の必須チェックが結果待ちのままになりマージできなくなる。文書の変更も禁止語の検査を通す (`docs/supply-chain.md`)
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
- ログ由来の値と LLM の出力は信用しない。守りはプロンプトではなく規則に置く (ADR 0037)
- 暗黙の既定を持たない。実行されるチェックは設定に書いたものだけ (ADR 0014)。新しい既定値を足したら `config init --diff` で見えるようにする
- `cmd/aratam/deps_test.go` が aratam の依存を許可リストで固定している。aratam に SQLite や監査用 AWS SDK をつながない

## よく使うコマンド

```bash
make test            # go test ./... (ユニット + コマンドレベル e2e)
make vet lint fmt
make fuzz            # ファズテストの探索 (対象ごとに 30 秒。FUZZTIME=2m で変える。1 つだけなら tools/fuzz.sh 2m internal/notify)
make build-local     # bin/arata (このホスト向け)
go build -o bin/aratam ./cmd/aratam
go list -m -json all | go run ./tools/agegate -days 7   # 依存の待機期間チェック (CI と同じ)
GITHUB_TOKEN=$(gh auth token) go run ./tools/actionsgate -days 7 -lock .github/workflows/actions.lock .github/workflows examples/github-actions   # Actions の検査 (CI と同じ)
go run ./cmd/arata help ai                               # LLM 向けの使い方
```

## ディレクトリ

- `cmd/arata`, `cmd/aratam` — CLI (標準 flag の上の `internal/subcmd`)
- `internal/config` 設定 / `internal/collect` 収集 (cloudtrail, cwlogs, account) / `internal/store` JSONL + SQLite /
  `internal/checks` チェック / `internal/engine` run の流れ / `internal/report` レポート (`schema` は標準ライブラリだけ) /
  `internal/allowlist` 既知リスト / `internal/scaffold` 雛形 / `internal/notify`・`internal/llm`・`internal/slack` aratam
- `docs/ai/*.md` はバイナリに埋め込まれる。変えたらテストのゴールデンも変わる。新しいチェックを足したら `docs/ai/playbooks/<check>.md` (対処手順。ADR 0025) も書く (無ければテストが落ちる)
- `tools/agegate`・`tools/actionsgate`・`tools/wordscan` CI 用。`examples/` は架空の値の設定例
- `deploy/iam/readonly-role.yaml` 顧客に配る読み取り専用ロール (素の CFN) / `deploy/github-actions/runner.yaml` GitHub Actions の実行の仕組み (素の CFN。ADR 0040) / `deploy/slack/app-manifest.yaml` aratam の通知用の Slack アプリの manifest (scope は chat:write だけ。`internal/slack/manifest_test.go` が固定) / `deploy/sandbox` 試験環境 (CDK、pnpm、Node 24。Go とは独立。ADR 0020)
