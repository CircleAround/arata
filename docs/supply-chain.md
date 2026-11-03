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
| Dependabot の範囲 | `examples/github-actions` が外れていた | 足した |
| Go の依存 | `go.sum` あり、7 日待機は強制済み | 変更なし |
| pnpm の依存 | ロックあり、待機は強制済み、pnpm 本体は sha512 で固定。install スクリプトは既定で止まる | 間接の依存の直接参照の禁止などを足した |
| Actions の 7 日待機 | Dependabot のみ | CI で強制した |
| 推移的な action | 未固定 | ロックファイルで固定する (下記) |
| 脆弱性の検査 | Go のみ、PR と push のみ、release に無し | pnpm・週次・release を足した |
| 来歴証明 | 公開リポジトリで有効になる形で実装済み | SBOM も対象にした |
| SBOM | 無し | release で SPDX JSON を付ける |

## Actions のロックファイル

GitHub 公式の workflow dependency lockfiles (2026-10-14 public preview、[2026-10-28 GA](https://github.blog/changelog/2026-10-28-github-actions-workflow-lockfiles-are-generally-available/)。Enterprise Cloud・Team・Free)。
`.github/workflows/actions.lock` に推移的な依存の commit と owner / repo の数値 ID を記録し、実行時に runner が確かめる。手で編集しない。

- 対象外: 別リポジトリの reusable workflow、`./` のローカル action、コンテナイメージ (scorecard-action の中のイメージも含む)
- 形式は v0.0.3、拡張は 0.x で、変わる途中
- 変更の見方: `commit` の変化は依存の更新として読む。`owner_id` / `repo_id` の変化は別のリポジトリにすり替わった疑いなので、調べてからマージする

作り方 (`uses` を足した・変えたときも同じ。公開から 7 日以上の版の拡張を使う):

```bash
gh extension install github/gh-actions-lock --pin v0.4.0
gh actions-lock          # actions.lock を更新する。uses の書き換えが無いかも差分で見る
```

Dependabot は onboard 済みのワークフローの action を上げるときに lock も更新する。新しいワークフローは自動では onboard されないが、CI の `--verify` で分かる。

## GitHub の画面で人が行う設定

コードで担保できないもの。公開の前後に行う。

1. **ブランチ保護 (main)**: PR 必須、レビュー必須、force push と削除の禁止、管理者にも適用
2. **必須チェック**: `test`、`actions`、`zizmor`、`vulnerabilities` と、B・C のワークフローのジョブ
3. **タグの保護**: ruleset で `v*` の作成・更新・削除を管理者に限る。release はタグの push で動くので、これが release の権限の境界になる
4. **Immutable releases を有効にする**: 公開後のリリースの差し替えを防ぐ
5. **Actions の権限**: `Settings > Actions > General`
   - 「Require actions to be pinned to a full-length commit SHA」を有効にする
   - 許可する action を、使うものだけにする。ロックファイルの導入後はタグではなく SHA かワイルドカードで書く (公式の注意)
   - `GITHUB_TOKEN` の既定を read-only に、「Actions が PR を作成・承認する」を無効にする
   - 公開後は fork の PR の実行を「すべての外部の貢献者に承認を要求」にする
6. **Require lockfile ポリシー**: `actions.lock` の導入後、全ワークフローが onboard されてから有効にする。Evaluate モードは Enterprise Cloud のみなので、`gh actions-lock --verify` が通るのを確かめてから Active にする
7. **CODEOWNERS**: `.github/` と `actions.lock` の担当者を決めて必須レビューにする (公式の推奨)
8. **Dependabot alerts / security updates と private vulnerability reporting を有効にする**
9. **公開後の確認**: 最初のリリースで `gh attestation verify` が通ること、`scorecard` が動くこと

## 道具の版を上げる

Dependabot が上げないもの (公開から 7 日以上の版を選ぶ):

- `go run` の道具 (`supply-chain.yml` の `env`、`release.yml` の govulncheck): 版を変える。公開日は CI の agegate が確かめる
- zizmor・osv-scanner (`supply-chain.yml`)、syft (`release.yml`): 版と sha256 を一緒に変える。公開日は CI で確かめないのでレビューで見る

```bash
gh release view <tag> -R <owner>/<repo> --json publishedAt,assets --jq '.publishedAt, (.assets[] | [.name, .digest] | @tsv)'
```

## 脆弱性で CI が落ちたとき

依存を上げて直す。直った版が 7 日の待機の中にあるときは、ADR 0017 のとおり理由を書いて例外の PR を出す。
pnpm の依存で、使っていない箇所の脆弱性なら `deploy/sandbox/osv-scanner.toml` に理由と期限を書いて除外する (無期限にしない)。
