# 0042. 設定と allowlist の形はオフラインの `config check` で PR の時点に確かめ、finding の片付けは Actions の手動実行で行う

- 日付: 2026-11-09
- 状態: 採用

## 背景

GitHub Actions で定期実行する運用 (ADR 0034・0040) では、ストアは S3 にあり、設定と allowlist.yaml はリポジトリにある。
この形で、手元の実行を前提にしていた 2 つの作業が難しくなった。

- **allowlist.yaml の誤りに気づくのが遅い**。形の検証は run / doctor の起動時にしか行われない。誤った allowlist.yaml をマージすると、
  次の定時の監査が設定エラーで止まり (aratam が「実行されていない」と知らせる)、直すまで監査が空く。doctor は AWS に問い合わせるので、PR の CI では使えない
- **finding を片付けられない**。`arata ack` / `snooze` / `resolve` / `approve` はストアを書く。ストアを書ける認証は実行用ロールだけにしたいので、
  人の手元には無い

## 決定

### 1. `arata config check` / `aratam config check` (オフラインの検査)

- 設定と、それが指す allowlist.yaml の形を、AWS にもストアにも繋がずに検査する。認証も secrets も要らないので、PR の CI (`contents: read` だけ) で回せる
- **規則は足さない**。run / doctor が起動時に使う関数 (`config.Load`、`allowlist.Parse`、`engine.UnknownChecks`、aratam は `notify.LoadConfig`) をそのまま呼ぶ。
  check が通した設定は run でも読め、check が止めた設定は run でも止まる。allowlist の検査はファズテストでこの一致を確かめる (ADR 0041)
- check が足すのは見せ方だけ: 1 行 1 件の `ok` / `warn` / `ng` / `skip`、allowlist の項目の行番号 (`allowlist.EntryError` が節と番号を持ち、YAML から行を引く)。
  終了コードは `ng` があれば 2 (設定エラーの慣例)、`warn` だけなら 0
- allowlist の同じ主体の重複は `warn` にする。run は重複を受け付ける (`expected_denied` は項目ごとに書けて和で判定する。ADR 0022) ので、
  エラーにすると「check は止めるが run は動く」設定ができ、規則が 2 つになる。ただし `expires`・`tags`・`dynamic_source` は 1 つの項目のものしか使われず、
  片方だけ直した誤りになりやすいので知らせる
- aratam の check は Webhook の環境変数を見ない (警告も出さない)。`llm.context_file` は読めるかを見て、読めなければ `warn` (notify が前提なしで続けるのと同じ扱い)
- `config init --diff` は残す。`--diff` は「この版の雛形との差」を緩く読んで見せる道具 (差は誤りではないので終了コード 0)、`check` は「この設定で起動するか」の門。
  未知のキーと未知のチェック名は両方に出る

### 2. finding の片付けは `workflow_dispatch` の見本で行う (`examples/github-actions/arata-triage.yml`)

- ack / snooze / resolve を、Actions の画面から実行用ロールで行う。定時の監査と同じ `concurrency` の group にして、同じストアへは順番に書く
- 入力は `run` に埋め込まず環境変数で渡し、認証の前に形を確かめる (finding の ID は 12 桁の 16 進、期日は `YYYY-MM-DD`、理由は 1 行)。ログの方針は監査と同じ (`code` だけ)
- **approve は入れない**。`arata approve` は allowlist.yaml への追記と同時にストアの finding を resolved にする。Actions で実行すると、
  追記はランナーの作業ツリーに書かれるだけで、finding だけが先に消える。承認は allowlist.yaml を直す PR にし、差分を人が見てマージする。
  次の evaluate が、承認に一致する finding を allowlisted として解消する (既存の動作)。PR の形は上の `config check` が確かめる
- **理由と操作した人は、Actions の実行の Summary に残す**。ack / snooze / resolve には理由と操作した人の欄が無く、ストアには残らない。
  ストアに残す変更 (`--by` / `--reason` とスキーマの変更) はこの決定に含めず、ロードマップの残項目にした

## 検討した選択肢

- **check のための検証を別に書く** (全部のエラーを 1 回で列挙する、行番号を全部に付ける): 却下。規則が 2 か所になり、片方だけ直すと
  「check は通るのに run が止まる」が起きる。それを防ぐのがこの検査の目的なので、最初の 1 件で止まることと、値の検証に行番号が無いことを引き受ける
- **`arata doctor --offline`**: 却下。doctor は「実際に問い合わせて確かめる」コマンドで、表の形も違う。CI で使う門は名前から役割が分かるほうがよい。
  設定を扱う `config` の下に置く (`config init` と同じ並び)
- **allowlist の重複をエラーにする**: 却下 (上の理由)。`--strict` で警告をエラーにするフラグも足さない。必要になったら足せる
- **aratam の check で Webhook の環境変数が無ければ警告する**: 却下。PR の CI に秘密を渡さないのが正しい形で、そこで毎回出る警告は読まれなくなる。
  環境変数の有無は、秘密のある場所で動かす `aratam doctor` が見る
- **`config check` を作らず、PR の CI で `arata profiles` を回す**: 却下。profiles は設定を Load するが allowlist を読まない。allowlist の誤りが目的なので足りない
- **triage に approve も入れ、ワークフローが allowlist.yaml の PR を作る**: 却下。`contents: write` と `pull-requests: write` を、実行用ロールを引き受けるジョブに
  持たせることになる。finding が PR のマージより先に消える問題も残る (マージされなければ、解消された finding が次の run で new として出直す)
- **approve から finding の解消を外すフラグ (`approve --no-resolve`) を足す**: 見送り。PR で allowlist.yaml を手で (または AI が) 直す流れで足りる。
  追記の書式を arata に任せたい要望が出たら検討する
- **ack / snooze / resolve に `--by` / `--reason` を足してストアに記録する**: この決定には含めない。SQLite のスキーマの変更と移行、S3 ストアの互換、
  report への出し方を決める必要がある。それまでは Actions の実行履歴が記録を持つ (保持期間があることを見本の README に書く)

## 結果 (良い点・引き受けるコスト)

- allowlist.yaml の形の誤りは PR で止まり、監査が空かない。行番号が出るので直しやすい
- ストアを書ける認証を人に配らずに、finding を片付けられる
- 承認は必ず allowlist.yaml の差分としてレビューされる
- 引き受けるコスト:
  - check はファイルごとに最初のエラー 1 件で止まる (直して再実行する)
  - 片付けの理由と操作した人は Actions の実行履歴にしか残らず、保持期間で消える
  - 同じ `concurrency` の group で待てる実行は 1 つなので、片付けを続けて実行すると、先に待っていたものが取り消される
  - `runner.yaml` の `GitHubWorkflowRef` で監査のワークフローに絞っている場合、片付けのワークフローは実行用ロールを引き受けられない
  - 見本のワークフローが 4 本になった。共通の step (取得と照合、実行用ロール) が同じであることは `examples/github-actions` のテストで確かめる
