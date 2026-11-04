# 0035. サプライチェーンの検査を CI で常に行い、Actions の 7 日待機を強制し、release を権限で分ける

- 日付: 2026-11-04
- 状態: 採用

## 背景

リポジトリの公開に向けて、ADR 0017・0019・0020 の対策を点検した (結果は [docs/supply-chain.md](../supply-chain.md))。固定や待機の多くは守られていたが、
次の穴があった。

- 守られていることを機械で確かめていない。SHA 固定は見本のテストだけで、`.github/workflows` は人の目に頼っていた
- Actions の 7 日待機は Dependabot の cooldown だけで、Go と npm のような強制の段が無い
- composite の中の action など、推移的な依存は固定していない
- 利用者が写す見本 (`examples/github-actions`) の action は `.github/workflows` の外なので Dependabot が上げない
- 脆弱性の検査は PR と push でしか動かず、コードが変わらない間は新しい脆弱性に気づかない。pnpm の依存は検査していない。release にも無い
- release の 1 つのジョブが `contents: write` と `id-token: write` を持ったまま `go test` と `make build` を動かし、`setup-go` の既定のキャッシュも使っていた

また GitHub Actions に、公式のロックファイル (workflow dependency lockfiles) が 2026-10-28 に GA となった。
`.github/workflows/actions.lock` に推移的な依存の commit と、リポジトリの数値 ID を記録し、実行時に runner が確かめる。

## 決定

- **`supply-chain.yml` で PR・main・週次に検査する**。`actions` (固定・版の一致・待機・actionlint・ロックファイル)、`zizmor`、`vulnerabilities` (govulncheck・osv-scanner) の 3 ジョブ。
  govulncheck は `test.yml` からここへ移し、release にも置く
- **Actions の検査は標準ライブラリと yaml.v3 だけの `tools/actionsgate`**。全 `uses` が 40 桁の SHA で版のコメントがあること、そのタグが SHA を指すこと、公開から 7 日以上であることを確かめる。
  判定できないものは通さない。ロックファイルがあれば推移的な依存の公開時刻も見る。固定の検査は `-offline` で `go test` からも動く
- **`uses` の SHA 固定は残す**。公式はタグ + ロックファイルを勧めるが、見本を写す利用者にはロックファイルが届かず、zizmor と Scorecard の判定も SHA を見るため
- **ロックファイルは後から足せる形にする**。`actions.lock` があれば CI が `gh actions-lock --verify` を行い、無ければ読み飛ばす。拡張は公開から 7 日以上の版 (v0.4.0) を使う。
  SHA の `uses` と組み合わせる形は未確定で、この ADR の時点では導入していない (タグをキーにした lock との組み合わせは `startup_failure` になった。docs/supply-chain.md)
- **検査の道具も固定する**。Go 製 (actionlint・govulncheck・gh-actions-lock) は `go run pkg@version` で sum.golang.org の検証を受け、CI の `tools/agegate` で公開日を確かめる。
  go.mod には足さない。zizmor・osv-scanner・syft はリリースのバイナリを sha256 で照合する。これらの action は使わない (中で別の版を取りに行くものがあり、固定の範囲が広がるため)
- **zizmor は全 action を SHA 固定の方針で動かす** (`.github/zizmor.yml`。既定は `actions/*` のタグ固定を許す)
- **Scorecard は `scorecard.yml` に分け、ジョブを `visibility == 'public'` のときだけ動かす**。公開すれば変更なしで動く
- **release を `build` (読み取りのみ) → `sbom` (権限なし) → `publish` (書き込み) に分ける**。`publish` はリポジトリを checkout せず、成果物の照合と公開だけを行う。
  配布物のビルドではキャッシュを使わない。タグの名前は版の形だけを通す
- **SBOM をリリースに付ける**。syft で SPDX JSON をバイナリごとに作り、SHA256SUMS と来歴証明の対象に入れる。syft はバイナリを作るジョブとは別のジョブで動かす
- **Dependabot の github-actions に `/examples/github-actions` を足す**
- **pnpm に `blockExoticSubdeps`・`strictDepBuilds`・`trustPolicy: no-downgrade` を足す**

## 検討した選択肢

- **ロックファイルだけにして SHA をやめる**: 公式の推奨で `uses` は読みやすいが、見本を写す利用者が守られず、形式も v0.0.3 で v1.0.0 に向けて変わる途中。却下
- **ロックファイルを入れない**: 推移的な依存とリポジトリの差し替えを防げるのはこれだけ。却下
- **`gh extension install --pin` で拡張を入れる (公式の例)**: バイナリの照合が無い。sumdb で検証される `go run` にした
- **Actions の待機を Dependabot だけにする**: 手で足した版を止められない。ADR 0017 の 2 段構えに揃えた
- **tools/agegate に Actions を足す**: 入力も公開時刻の引き方も違い、1 つの道具が 2 つのことを知る。分けた
- **osv-scanner で go.mod も見る**: 呼び出し経路を見ないので、呼んでいない箇所の脆弱性でも落ちる。Go は govulncheck に任せた
- **zizmor-action・osv-scanner-action・sbom-action を使う**: 手軽だが、Docker イメージや道具の取得の固定を action に任せることになる。却下
- **SBOM を build のジョブで作る**: 道具が配布物に触れられる。ジョブを分けた

## 結果

- 固定の漏れ・版の偽り・7 日未満の action は CI で落ちる。ワークフローの危険な書き方は zizmor で落ちる
- 依存の新しい脆弱性に週次で気づく
- テストやビルドで動くコードが乗っ取られても、リリースの書き込み権限と署名の権限に届かない
- 引き受けるコスト: zizmor・osv-scanner・syft の版は Dependabot が上げない。手で上げる (docs/supply-chain.md)
- 引き受けるコスト: 脆弱性の公表の直後は、直った版が 7 日の待機の中にあって CI が赤くなることがある。ADR 0017 と同じく、理由を残して例外の PR を出す
- 引き受けるコスト: CI が GitHub・OSV の API に依存する。落ちたときは判定できないものとして失敗する
- ロックファイルの導入までは、推移的な action は固定されない
- リポジトリの設定 (必須チェック・タグの保護など) はコードで担保できない。手順は docs/supply-chain.md
