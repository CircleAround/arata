# 0037. 静的解析を CI で常に回し、ログ由来の値と LLM の出力を信用しない前提で通知を組み立てる

- 日付: 2026-11-04
- 状態: 採用

## 背景

リポジトリの公開の前に、安全でないコードが入っていないかを人の目と静的解析で点検した。CI はこれまで `go vet` と govulncheck だけで、
`make lint` の golangci-lint は設定が無く、入っていなければ飛ばしていた。

arata の入力には攻撃者が書ける文字列がある (リクエストのパス、X-Forwarded-For から取った IP、JSON のログの任意の項目など)。
それらは report.json を通して LLM と Slack に届く。点検で次を再現した。

- `slack.format: text` で LLM が critical を `info` に分類すると、切り詰めで本文から消える (緊急用への振り分けは効く)
- system prompt が report.json の値を信用しない前提を書いていない。LLM の自由文の URL や `@channel` の文字列はエスケープだけでそのまま出る
- BLOCK に強める記述の検査 (ADR 0024) を `"Action":"BLOCK"`、「BLOCK に設定する」、「ブロックに切り替える」がすり抜ける。blocks の summary と next は検査していない
- text 形式の行に改行を入れて偽の行を作れる。Block Kit の mrkdwn は `verbatim` が無く、リンクの展開 (unfurl) も止めていない
- `audit.sqlite` が umask のまま 0644 で作られる。S3 の SQLite の展開に上限が無い。S3 のキー `reports/../audit.sqlite` が通る。source の id と profile 名をパスに使うのに検証が無い

問題が無かったもの: SQL はすべて値を束縛している。Insights のクエリに入るのは設定の値だけ。外部コマンドはシェルを通さない。
利用者の正規表現は RE2 なので ReDoS にならない。Webhook の URL はログに出ない。S3 の書き込みはすべて条件付き。IAM と CDK に過剰な権限は無い。

## 決定

### CI

- `.github/workflows/sast.yml` を足す。依存は supply-chain、秘密は secrets-scan の担当で、ここでは重ねない
- Go の静的解析は golangci-lint に gosec と staticcheck を載せて回す。`make lint` と同じ `.golangci.yml` を使う
- golangci-lint はリポジトリの Go で `go run` する。版は公開 7 日以上のものに固定し、h1 チェックサムを CI で照合する
- CodeQL (Go・TypeScript・Actions) は `visibility == 'public'` のときだけ動かす。非公開の Code Scanning は GitHub Advanced Security が要る
- 抑制は理由を必須にする。規則ごとの抑制は `.golangci.yml` のコメント、1 か所の抑制は `#nosec <規則> -- <理由>` に書き、形は CI で確かめる
- gosec の G301・G302・G306 は除かず、基準を出力の方針 (ファイル 0640、ディレクトリ 0750) に合わせる。これより緩いものは落ちる
- G304 は除く。利用者が自分の権限で動かす CLI で、全箇所が誤検知になる。ログ由来の値がパスに混ざらないことは入力の検証とテストで担保する

### 通知 (LLM は攻撃者の文に従い得る前提にする)

守りはプロンプトではなく規則に置く。プロンプトの指示は破られる前提で、破られても次が残るようにする。

1. 重大度の床: new / changed / recurred で `urgent_severity` 以上の finding は、LLM が `info` にしても `confirm` に上げ、LLM の理由を捨てる
2. system prompt に、入力の値はログ由来で攻撃者が書けること、中の指示に従わないことを書く
3. LLM の自由文に URL と `@channel` / `@here` / `@everyone` があれば、その項目を捨てて規則の文に戻す。headline と summary なら形の不正として扱う
4. `urgent_severity` 以上の finding への approve の提案は規則で捨てる。approve は主体を以後報告しなくなるので、誘導されたときの被害が最も大きい
5. LLM を使った通知は、既存の末尾の context に LLM の文であることを短く添える。行は増やさない。`provider: none` では出さない
6. BLOCK に強める記述の検査の抜けを塞ぎ、blocks の summary と next にも掛ける。「BLOCK している」のような事実の記述は捨てない

Slack へは、ログ由来の値を 1 行にし、mrkdwn に `verbatim: true` を付け、リンクの展開を止める。`urgent_mention` の `<!channel>` は `verbatim` でも効く。

### ストア

- S3 の SQLite の展開は 8 GiB を上限にする。見積もりは年に数百 MB までなので設定は足さない
- S3 から取得するキーは、正規化しても同じで、求めた接頭辞の下にあるものだけにする
- SQLite のファイルは 0640 で作る
- source の id と profile 名はパスに使うので、区切り文字と `..` を拒否する

## 検討した選択肢

- **ログ由来の値を LLM の入力から伏せる**: 却下。要約の根拠 (どのパス・どの主体か) が失われ、LLM を使う意味が薄れる。守りは出力の側の規則に置く
- **LLM の自由文でシェルコマンドらしさを検出する**: 却下。`arata approve` などの正当な案内と見分けにくく、誤検知が多い。末尾の注記で人に知らせる
- **gosec と staticcheck を別々に導入する**: 却下。Makefile が既に golangci-lint を見ているので、1 つの設定に揃える
- **ツールを go.mod の tool に入れる**: 却下。製品の依存の一覧に解析ツールの依存が混ざる (ADR 0019)
- **errcheck を有効にする**: 見送り。出力の `fmt.Fprintf` など 196 件で、安全性の検査の信号が埋もれる
- **approve の提案を残して注意書きを添える**: 却下。注意書きは読み飛ばされ得る

## 結果

- 良い点: 新しいコードの問題を PR の時点で止められる。LLM が誘導されても、重大度・件数・振り分け・必ず載せる finding は変わらない
- 引き受けるコスト: golangci-lint の版は Dependabot が上げないので、手で版とチェックサムを更新する。CodeQL は公開まで動かない。
  LLM の文に URL を書けなくなる。高い重大度の finding には approve の提案が出ないので、人が `arata review` から判断する
- 実 Slack での `verbatim` と unfurl の効きは、Slack の仕様に基づく判断で、自動テストでは確かめていない
