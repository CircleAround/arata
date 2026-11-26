# 0088. CI の gitleaks は、PR ではその PR のコミットだけを読み、全部の枝の履歴は main への push・定期実行・手動で読む (0036 の「すべての実行で全履歴」を置き換え)

- 日付: 2026-11-26
- 状態: 採用

## 背景

ADR 0036 は、gitleaks がすべての実行で全履歴 (`--log-opts=--all`) を読むと決めた。`--all` は fetch した全部の枝を含むので、ある枝の 1 件 (誤検知を含む) で、関係のないほかの PR と main の CI まで落ちる。直すには枝の書き換えが要った。

手元の `make scan-sensitive` は `--pre-commit` で、コミットした変更を読まない。コミットした後に流すと 0 件で通り、そのまま push できた (Issue #173)。

## 決定

- `gitleaks` ジョブの差分とコミットメッセージの範囲は、PR ではその PR の `base..head`、それ以外 (main への push・定期実行・手動) は `--all`
- 読み方は `tools/scan-commits.sh` の 1 つにまとめ、CI・make (`scan-sensitive-push`・`scan-sensitive-history`)・pre-push のフックが使う
- gitleaks は git log が失敗しても (存在しないコミットなど) 成功で終わるので、スクリプトは範囲を先に git で確かめ、ワークフローは `base` と `head` が空なら失敗する
- 手元では push の前に、送るコミットを読む (`make scan-sensitive-push` か pre-push のフック)
- 誤検知は枝を書き換えず、直すコミットと `.gitleaksignore` の指紋で外す (`docs/sensitive-scan.md`)

禁止語 (`words` ジョブ) の範囲は変えない。

## 検討した選択肢

- **全部の実行で `--all` のまま、手元の手順だけ足す** (push の前に `make scan-sensitive-history`): 変更は最小だが、手順を忘れた 1 件でほかの PR が止まることは変わらない
- **PR でも `--all` を読み、指紋で外して回る**: 指紋はその枝の外 (main) に入れないと、ほかの PR に効かない
- **gitleaks の出力の `ERR` を読んで失敗にする**: 人向けのログの文言に頼る。範囲を git で確かめる方が確実

## 結果 (良い点・引き受けるコスト)

- 良い点: ある枝の検出で、ほかの PR は落ちない。手元と CI が同じ読み方になる
- 引き受けるコスト
  - PR を出していない枝は、定期実行まで CI で読まれない (以前は、ほかの PR の実行でも読まれた)
  - main への push と定期実行は `--all` なので、残っている枝の検出で main の CI は落ちる。これは意図した動き (公開されている枝は読み続ける)
  - マージコミットの差分は、どちらの範囲でも読まれない (`git log -p` の既定。以前から同じ)
