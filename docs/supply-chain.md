# サプライチェーンの点検と運用

公開前の点検の結果 (2026-11-04)、CI で担保していること、GitHub の画面で人が行う設定、道具の更新の手順をまとめる。判断の理由は ADR 0017・0019・0020・0035。

## CI で担保していること

| 検査 | 場所 | 落ちる条件 |
|---|---|---|
| Actions の固定・版の一致・7 日待機 | `tools/actionsgate` (`supply-chain.yml`。固定は `go test` でも) | SHA でない `uses`、版のコメントが無い・SHA と違う、公開から 7 日未満 |
| ワークフローの構文 | actionlint | 構文、式、シェルの誤り |
| ワークフローのセキュリティ | zizmor (`.github/zizmor.yml`) | 式の注入、危険なトリガー、過大な権限、資格情報の残留、キャッシュ汚染、偽装コミット、既知の脆弱な action |
| ロックファイル | `gh actions-lock --verify` | `actions.lock` があるときに、古い・上流と合わない |
| Go の依存の固定と待機 | `go mod verify`、`tools/agegate` | go.sum との不一致、公開から 7 日未満 |
| npm の依存の固定と待機 | `--frozen-lockfile`、`minimumReleaseAge`、`scripts/agegate.ts` | ロックとの不一致、公開から 7 日未満 |
| 脆弱性 | govulncheck (Go)、osv-scanner (pnpm) | 既知の脆弱性。週次でも回す |
| 書き出す Terraform の provider の固定と待機 | `tools/tfprovidergate` (`supply-chain.yml` の `terraform`) | `arata repo init` が書き出す lock の provider の版が、公開から 7 日未満・公開日を確かめられない |
| 書き出す Terraform の形 | `terraform fmt` / `validate` (`go test ./internal/repoinit`。ADR 0059・0060。Terraform は秘密に触れないので、plan も apply もしない) | 形の誤り、lock のハッシュと合わない provider |
| 評価 | OpenSSF Scorecard | 公開後に結果を公開する (落ちない) |

## 点検の結果

| 項目 | 結果 | 対応 |
|---|---|---|
| Actions の SHA 固定 | 漏れなし (見本も含む) | CI で強制した |
| コメントの版と SHA の一致 | 全件一致 (実データで確認) | CI で強制した |
| `permissions` | 全ワークフローで指定済み。見本はワークフロー単位で書き込みを持っていた | 見本をジョブ単位にした |
| `persist-credentials` | 全 checkout で `false` | zizmor で強制 |
| 危険なトリガー (`pull_request_target`、`workflow_run`) | 無し | zizmor で強制 |
| 式の埋め込み | `run` への埋め込みは無し (env 経由)。タグの名前が `make` の引数に入っていた | release で版の形だけを通すようにした |
| キャッシュの汚染 | release が `setup-go` の既定のキャッシュを使っていた | release と検査で切った |
| release の権限 | 書き込みと署名の権限のジョブでテストとビルドを動かしていた | ジョブを分けた |
| Dependabot の範囲 | `examples/github-actions` が外れていた | 足した (いまは `arata repo init` の出力の `examples/audit-repo`。ADR 0059) |
| Go の依存 | `go.sum` あり、7 日待機は強制済み | 変更なし |
| pnpm の依存 | ロックあり、待機は強制済み、pnpm 本体は sha512 で固定。install スクリプトは既定で止まる | 間接の依存の直接参照の禁止などを足した |
| Actions の 7 日待機 | Dependabot のみ | CI で強制した |
| 推移的な action | 未固定 | ロックファイルで固定した (下記。ADR 0039) |
| 脆弱性の検査 | Go のみ、PR と push のみ、release に無し | pnpm・週次・release を足した |
| 来歴証明 | 公開リポジトリで有効になる形で実装済み | SBOM も対象にした |
| SBOM | 無し | release で SPDX JSON を付ける |

## Actions のロックファイル

GitHub 公式の workflow dependency lockfiles (2026-10-14 public preview、[2026-10-28 GA](https://github.blog/changelog/2026-10-28-github-actions-workflow-lockfiles-are-generally-available/)。Enterprise Cloud・Team・Free)。
`.github/workflows/actions.lock` に推移的な依存の commit と owner / repo の数値 ID を記録し、実行時に runner が確かめる。手で編集しない。

- 対象外: 別リポジトリの reusable workflow、`./` のローカル action、コンテナイメージ (scorecard-action の中のイメージも含む)
- 形式は v0.0.3、拡張は 0.x で、変わる途中
- 変更の見方: `commit` の変化は依存の更新として読む。`owner_id` / `repo_id` の変化は別のリポジトリにすり替わった疑いなので、調べてからマージする

導入済み (ADR 0039)。`uses` の SHA 固定と併用する。作り方 (`uses` を足した・変えたときも同じ。公開から 7 日以上の版の拡張を使う):

```bash
gh extension install github/gh-actions-lock --pin v0.4.0
gh actions-lock --no-narrow   # uses の SHA を保ち、キーも SHA で作る
git diff                      # 変わるのは actions.lock だけのはず。uses が書き換わっていたら commit しない
```

- **`--no-narrow` を必ず付ける**。引数なしだと SHA の `uses` をタグに書き換え、lock のキーもタグで作る。そこで `uses` だけを SHA に戻すと、全ワークフローが `startup_failure` になる (確認済み)。`uses` と lock は同じコマンドの結果のまま commit し、lock を手で直さない
- `--verify` は警告 `sha-as-ref` (SHA の `uses` にタグが無い) を出すが、CI は落ちない
- 既知の制限: scorecard-action の中のコンテナイメージ (`ghcr.io/ossf/scorecard-action:v2.5.0`) はタグ参照で、lock も固定しない (`--verify` が警告を出す)。scorecard.yml は公開リポジトリでだけ動き、権限は結果の公開とコードスキャンへの登録だけなので受け入れる

Dependabot は onboard 済みのワークフローの action を上げるときに lock も更新する (設定は要らない)。SHA の `uses` での挙動は最初の更新 PR で確かめる。新しいワークフローは自動では onboard されないので、足すたびに lock を更新する (忘れると CI の `--verify` が落ちる)。

## GitHub の画面で人が行う設定

コードで担保できないもの。2026-11-09 に API (`gh api`) で 1〜5・8 を設定し、同日にリポジトリを公開した。公開の後に、fork の PR の承認 (5) と private vulnerability reporting (8) を有効にした。PR を作れるのは協力者 (書き込み権限のある人) だけにしている (`pull_request_creation_policy`)。確かめるときは `gh api repos/CircleAround/arata/rulesets` などで読める。

1. **ブランチ保護 (main)**: ruleset「main を守る」。PR 必須、force push と削除の禁止、bypass なし (管理者にも適用)。
   決定: レビューの件数は 0。開発は 1 つのアカウントで PR を作りマージするので、自分の PR は承認できず、1 件以上にするとマージできなくなる。人の確認はリーダーのレビューと実データでの確認で担保し、メンバーが増えたら必須にする
2. **必須チェック**: `test`、`gosec + staticcheck`、`gitleaks`、`words`、`actions`、`zizmor`、`vulnerabilities`。
   path や条件で飛ばされるジョブ (`github-text`、CodeQL、sandbox) は入れない。入れると結果が届かずマージできなくなる。
   同じ理由で `[skip ci]` は使わない。ジョブの名前を変えたら ruleset も直す
3. **タグの保護**: ruleset「リリースのタグ v* を管理者に限る」で `v*` の作成・更新・削除を管理者 (bypass) だけにする。release はタグの push で動くので、これが release の権限の境界になる
4. **Immutable releases**: 有効。公開後のリリースの差し替えを防ぐ
5. **Actions の権限**: `Settings > Actions > General`
   - 「Require actions to be pinned to a full-length commit SHA」: 有効
   - 許可する action: GitHub 製 (`actions/*`・`github/*`) と `ossf/scorecard-action@*` だけ。action を足すときはここにも足す (足さないとワークフローが起動しない)
   - `GITHUB_TOKEN` の既定は read-only、「Actions が PR を作成・承認する」は無効
   - fork の PR の実行は「すべての外部の貢献者に承認を要求」
6. **Require lockfile ポリシー**: 未設定。Dependabot の最初の更新 PR で lock が正しく更新されるのを確かめてから Active にする。Evaluate モードは Enterprise Cloud のみ
7. **CODEOWNERS**: 見送り。レビューの件数が 0 の間は強制力が無く、個人のハンドル名は書かない規則 (CLAUDE.md) なので、メンバーが増えて必須レビューにするときに arata 専用のチームを作って `.github/` と `actions.lock` などに書く
8. **Dependabot alerts / security updates**: 有効。private vulnerability reporting も有効 (非公開のリポジトリでは API が 404 を返すので、公開の後に設定した。窓口は `SECURITY.md`)
9. **公開後の確認**: 最初のリリースで `gh attestation verify` が通ること、`scorecard` と CodeQL が動くこと

## 道具の版を上げる

Dependabot が上げないもの (公開から 7 日以上の版を選ぶ):

- `go run` の道具 (`supply-chain.yml` の `env`、`release.yml` の govulncheck): 版を変える。公開日は CI の agegate が確かめる
- zizmor・osv-scanner (`supply-chain.yml`)、syft (`release.yml`): 版と sha256 を一緒に変える。公開日は CI で確かめないのでレビューで見る
- Terraform 本体 (`supply-chain.yml` の `terraform` のジョブ。ADR 0059): 版と sha256 を一緒に変える。Go のモジュールでも action でもないので agegate・actionsgate の対象外で、
  公開日は CI で確かめない。PR の本文に、公式のリリースの公開日と、公式の配布元の `SHA256SUMS` の値を書いてレビューで見る

  ```bash
  gh api repos/hashicorp/terraform/releases/tags/v<版> --jq .published_at
  curl -fsS https://releases.hashicorp.com/terraform/<版>/terraform_<版>_SHA256SUMS | grep linux_arm64
  ```
- Terraform の provider (`integrations/github`。`arata repo init` が書き出す `github/` が固定する版): `internal/repoinit` の `ProviderVersion` を変え、
  lock の雛形 (`internal/repoinit/templates/github/terraform.lock.hcl`) を 4 つの環境のハッシュで作り直し、見本を `-update` で作り直す。
  公開日は CI の `tools/tfprovidergate` が、レジストリの公開日を読んで確かめる (7 日以上)

  ```bash
  # 空のディレクトリに、新しい版を書いた github/main.tf を置いて
  terraform providers lock -platform=linux_amd64 -platform=linux_arm64 -platform=darwin_amd64 -platform=darwin_arm64
  go test ./internal/repoinit -run TestExampleIsTheOutput -update && make test-terraform
  ```

```bash
gh release view <tag> -R <owner>/<repo> --json publishedAt,assets --jq '.publishedAt, (.assets[] | [.name, .digest] | @tsv)'
```

## 脆弱性で CI が落ちたとき

依存 (または Go のツールチェーン) を上げて直す。直った版が 7 日の待機の中にあるときは、次の条件をすべて満たせば待たずに上げる (ADR 0043):

1. 該当を道具で確かめた (govulncheck・osv-scanner・Dependabot alerts など)
2. 直した版がその版だけ (7 日以上経った版に、直したものが無い)
3. 公式の配布元から取れる
4. チェックサムを確かめた (Go の配布物は https://go.dev/dl/ の SHA256、モジュールは go.sum、pnpm はロック、Actions は SHA)

PR は脆弱性の修正だけにし、本文に脆弱性の ID・確かめた方法・直した版の公開日を書く。上げるのは直した版まで。
待機の検査 (`tools/agegate` など) が PR を止めるときは迂回せず、その版に限った除外を同じ PR で見える形で入れる (`-days` を全体に下げない)。条件を満たさないものは 7 日を待つ。
Go の版は `go.mod` の `go` の行と README「開発」の `GO_VERSION` を揃える (CI は `go-version-file: go.mod` で読む)。
pnpm の依存で、使っていない箇所の脆弱性なら `deploy/sandbox/osv-scanner.toml` に理由と期限を書いて除外する (無期限にしない)。
