# 0017. サプライチェーン対策は Actions の SHA 固定・依存の 7 日待機 (2 段構え)・来歴証明で行う

- 日付: 2026-10-21
- 状態: 採用

## 背景

arata は監査対象のアカウントに読み取り権限で入るバイナリで、利用者はリリースのバイナリをそのまま置いて使う。
依存 (Go モジュール・GitHub Actions) が乗っ取られて悪意のある版が公開されると、次のビルドでそのまま取り込まれ、監査対象の認証情報に届く。
こうした版は公開から数日以内に見つかって取り下げられることが多いので、「公開直後の版を使わない」だけで大半を避けられる。
また、Actions のタグ (`@v4`) は付け替えられるので、同じワークフローでも中身が変わり得る。

## 決定

- **GitHub Actions は 40 桁のコミット SHA で固定**し、版をコメントに書く (`uses: owner/repo@<SHA> # vX.Y.Z`)。
  SHA は `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` で取り、annotated tag は `git/tags/<sha>` で辿ってコミットにする。公開から 7 日以上経った版を選ぶ
- 全ワークフローに最小権限の `permissions:` を書く (test は `contents: read`。release はジョブ単位で `contents: write` / `id-token: write` / `attestations: write`)。
  checkout は `persist-credentials: false`
- **依存の 7 日待機を 2 段で行う**
  1. 提案: `.github/dependabot.yml` の `cooldown: default-days: 7` (gomod と github-actions、weekly)
  2. 強制: CI で `go list -m -json all | go run ./tools/agegate -days 7`。indirect を含む全モジュールの公開時刻を
     GOPROXY の `<module>/@v/<version>.info` の `Time` で見て、7 日未満なら失敗する。疑似バージョンは版文字列の時刻で判定する。
     公開時刻が取れないものは通さない (fail closed)。go.mod の `go` / `toolchain` 行は対象外
- CI で `go mod verify` (モジュールキャッシュと go.sum の一致) と `govulncheck` (版は固定。7 日以上前の版) を回す
- release で `actions/attest-build-provenance` による **build provenance attestation (来歴証明)** をバイナリに付ける。
  非公開リポジトリの attestation は GitHub Enterprise Cloud が要るため、`github.event.repository.visibility == 'public'` のときだけ動かす。
  非公開の間は SHA256SUMS のみ

## 検討した選択肢

- **Dependabot の cooldown だけ**: 人が手で `go get` した版や、cooldown を無視してマージした PR を止められない。強制には CI 側の検査が要る。単独では却下
- **CI の検査だけ**: 毎週 7 日未満の版を提案する PR が CI で落ち続けて騒がしい。提案側でも待つ
- **age-gate を `internal/` に置く**: エンジンの一部ではなく、ビルドにも入らない開発用の道具なので `tools/agegate` に分けた
- **age-gate に外部の Action やツールを使う**: それ自体が新しい依存になる。標準ライブラリだけの小さな main にした
- **Actions をタグ固定のまま**: タグの付け替えで中身が変わるので却下
- **attestation を continue-on-error で常に試す**: 非公開の間は毎回失敗して赤くなり、本当の失敗と見分けが付かない。visibility で分けた

## 結果

- 公開直後に取り下げられる悪意のある版は、提案にも CI にも入らない
- 引き受けるコスト: 緊急の脆弱性修正も 7 日待つことになる。待てないときは `-days` を下げる PR を明示的に出し、理由を残す
- 引き受けるコスト: SHA 固定の Actions は Dependabot が上げるまで古いまま (cooldown 後に週次で提案される)
- age-gate は CI のたびに proxy.golang.org を引く (モジュール数ぶん。疑似バージョンは引かない)
- 来歴証明は、公開リポジトリにするか Enterprise Cloud にするまで付かない
