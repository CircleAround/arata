# 0039. Actions のロックファイルを、uses の SHA 固定と併用して `--no-narrow` で作る

- 日付: 2026-11-09
- 状態: 採用 (ADR 0035 の「ロックファイルは後から足せる形にする」を確定する)

## 背景

ADR 0035 で、Actions の参照は SHA 固定を残し、公式のロックファイル (`.github/workflows/actions.lock`) は後から足せる形にした。
導入を試すと、`gh actions-lock` (v0.4.0) の既定の動きが SHA 固定と合わなかった。

- 引数なしで実行すると、SHA の `uses` をタグに書き換え、lock のキーもタグ (`actions/checkout@v7.0.1`) で作る
- `uses` だけを SHA に戻してタグのキーの lock を残すと、全ワークフローが `startup_failure` になった (拡張の検査は同じ commit なら通す作りだが、runner は拒否した)

## 決定

- **lock は `gh actions-lock --no-narrow` で作る**。`uses` の SHA を保ち、lock のキーも SHA、`ref` はタグで記録される
  (`'actions/checkout@3d3c…': ref: 'v7.0.1'`)。この形で全ワークフローが起動し、runner が lock の commit を使うこと
  (ログの `Using locked action versions from the workflow's lockfile`) と、`--verify` が通ることを PR の CI で確かめた
- `uses` と lock は同じコマンドの結果のまま commit する。lock を手で直さない
- `--verify` の警告 `sha-as-ref` (SHA の `uses` にタグが無い) は CI を落とさないので受け入れる
- scorecard-action が中で使うコンテナイメージ (`ghcr.io/ossf/scorecard-action:v2.5.0`) はタグ参照のままで、lock も固定しない。
  scorecard.yml は公開リポジトリでだけ動き、権限は結果の公開とコードスキャンへの登録だけなので受け入れる

## 検討した選択肢

- **タグ + lock (公式の推奨)**: `uses` は読みやすく `sha-as-ref` も出ないが、zizmor の SHA 固定の方針、Scorecard の判定、`tools/actionsgate` を lock 前提に変える必要がある。
  見本 (`examples/github-actions`) は利用者が写すと lock の外に出るので、どのみち SHA が要り、方式が 2 つになる。`--no-narrow` で併用できたので却下
- **lock を入れない**: 推移的な依存 (例: attest-build-provenance の中の actions/attest) とリポジトリの差し替え (owner / repo の ID) を防げない。却下
- **scorecard-action を外して scorecard の CLI をバイナリで動かす**: `publish_results` は scorecard-action の制約の中でしか使えない。却下

## 結果

- 直接の action に加えて、推移的な action も commit で固定される。CI の `tools/actionsgate -lock` はそれらの公開時刻も 7 日以上か確かめる
- 引き受けるコスト: `uses` を足す・変えるたびに `gh actions-lock --no-narrow` を実行する。忘れると CI の `--verify` が落ちる
- 引き受けるコスト: `--verify` の出力に `sha-as-ref` の警告が出続ける
- Dependabot は onboard 済みのワークフローの lock を同じ PR で更新するとされるが、SHA の `uses` での挙動は最初の更新 PR で確かめる
