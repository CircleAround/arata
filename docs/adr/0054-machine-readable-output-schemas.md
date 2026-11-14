# 0054. 機械が読む出力は `--format json` で出し、Go の型から作った JSON Schema とテストで固定する (人向けの出力を機械で読ませない)

- 日付: 2026-11-14
- 状態: 採用

## 背景

arata / aratam を定時に動かす仕組み (GitHub Actions など) は、コマンドの出力を機械で読んで分岐する。

実際に起きたこと: ある利用の現場で、通知の送り方 (bot か Webhook か) を判別するのに、`aratam config check` の人向けの出力の行末
(`slack bot` で終わること) を grep していた。版を上げたら同じ行の末尾に `, timezone …` が足され、判別に失敗して定時の通知が送れなかった。
人向けの 1 行に項目を足すのは、こちらから見れば互換の変更だった。原因は、機械が読める形でその値を出していなかったことと、
「どの出力を機械で読んでよいか」を決めていなかったことにある。

機械が読む JSON は既にいくつもあるが、どれも次が明文化されていない。

- 外から読んでよい項目はどれか
- どこまで変えてよく、どこから変えてはいけないか
- 変えたときに、読む側がどうやって気づくか

現状 (この ADR を書く時点のコードで確かめた):

| 出力 | 今の形 | 気づいた点 |
|---|---|---|
| `report.json` (`arata run` / `evaluate` / `report` の `--out` と標準出力) | オブジェクト。期間レポートは `kind: "period"` | 版の項目が無い。aratam は未知の項目を無視して読む |
| `arata doctor --format json` | オブジェクト (`rows`・`required_actions`・`store_actions`) | |
| `arata profiles --format json` | オブジェクト (`profiles`・`unused_checks`) | |
| `arata rebuild --format json` | オブジェクト | |
| `arata help ai --format json` | オブジェクト (`topic`・`title`・`sections`) | |
| `arata review --format json` | **最上位が配列** | 版の項目を足す場所が無い |
| `arata config init --diff --format json` | **最上位が配列** | 同上 |
| `aratam notify --dry-run --format json` | `--- route: … ---` の行と Slack の payload が交互に並ぶ | **全体としては JSON ではない** (jq にそのまま渡せない) |
| 構造化ログ (標準エラーの JSON 行。両方のコマンド) | `time`・`level`・`msg` と属性 | `code` の一覧が 1 か所に無い (定数が 4 つのパッケージと文字列の直書きに散っている)。`code` の無い WARN がある。設計書の例は `"level":"error"` だが、実際の値は大文字 (`ERROR`) |
| `arata config check` / `aratam config check` / `aratam doctor` | 人向けの出力だけ | 機械が読む形が無い (今回の原因) |
| 終了コード | arata: 0 / 2 / 3、aratam: 0 / 2 / 3 / 4 / 5 | 文書にはあるが、契約とは書いていない |

## 決定

### 1. 原則

**人向けの出力 (table / text / md、ヘルプ、ログの `msg` の文言) を機械で読ませない。機械が読む値は `--format json` で出し、スキーマとテストで固定する。**

- 人向けの出力は、版をまたいで文言・列・並びを変えてよい。変えても互換の変更として扱う
- 機械が分岐に使う値が人向けの出力にしか無いなら、それは arata の側の不足として扱い、`--format json` に足す
  (見本のワークフローと文書に grep / sed / awk で人向けの出力を読む例を書かない)
- 終了コードは契約に含める (下の「対象」)

### 2. 対象と、外から読んでよい項目

**スキーマに書いた項目が、外から読んでよい項目のすべて**である。スキーマに無い項目は出さない (テストで固定する。5 節)。
下の表の「分岐に使ってよい項目」は、その中で値の語彙まで固定するもの。

| 名前 | 出力 | 分岐に使ってよい項目 (語彙まで固定) | 読んでよいが、語彙・文言は固定しない |
|---|---|---|---|
| `report` | プロファイル実行の report.json | `schema`・`schema_version`、`profile`、`run_id`、`window.from/to`、`generated_at`、`dry_run`、`summary` の件数と `max_severity` (critical / high / medium / low / 空)、`summary.collect_errors[].source/code/partial`、`coverage.sources_failed[].source/code`、finding の `id`・`check`・`key`・`severity`・`status`・時刻の項目、finding がどの差分クラス (`findings.new` / `changed` / `recurred` / `resolved` / `still_open`) の配列にあるか、`coverage.formats[].source/code/match_rate` | finding の `summary` (文)、`data` と proposal の `evidence` (チェックごとのキー。`arata help ai report` と playbook に書く。スキーマでは中身を縛らない)、`coverage.notes` (文) |
| `report-period` | 期間レポートの report.json (`kind: "period"`) | `schema`・`schema_version`、`kind`、`period.from/to`、`generated_at`、`summary` の件数 | `notes` (文)、各 finding の `summary` |
| `doctor` | `arata doctor --format json` | `rows[].status` (ok / warn / ng / skip)、`rows[].code`、`rows[].source`、`rows[].item`、`rows[].kind`、`required_actions`、`store_actions` | `rows[].detail` (文)、`rows[].hint`、`rows[].samples` (ログ由来の値。公開されるログに出さない) |
| `profiles` | `arata profiles --format json` | プロファイル名、チェック名、パラメータの `check`・`key`・`value`・`origin` (由来)、`unused_checks` | |
| `rebuild` | `arata rebuild --format json` | `from_scratch`、`principal_status`、`files`、`records`、`malformed`、`unknown_kinds`、`backup` | `warnings` (文) |
| `help-ai` | `arata help ai --format json` | `topic`、`sections[].title` (節があること) | `title`、`sections[].body` (文書そのもの。文言は固定しない) |
| `review` | `arata review --format json` | `id`、`check`、`key`、`severity`、`status`、`first_seen`、`last_seen`、`snooze_until`、`approve` (追記の対象)、`approve_destination` | `summary`、`data` |
| `config-diff` | `arata config init --diff --format json` | `kind`、`path` | `current`、`template`、`detail` |
| `arata-config-check` | `arata config check --format json` (**新設**) | `ok`、`rows[].status`、`rows[].path`、`rows[].line` | `rows[].message` |
| `aratam-config-check` | `aratam config check --format json` (**新設**。下の例) | `ok`、`slack.method` (bot / webhook)、`slack.format` (blocks / text)、`llm.provider`、`timezone`、`rows[].status` | `name`、`config`、`rows[].message` |
| `aratam-doctor` | `aratam doctor --format json` (**新設**) | `rows[].status`、`rows[].item`、`rows[].code` | `rows[].detail` |
| `aratam-dry-run` | `aratam notify --dry-run --format json` | `messages[].route` (normal / urgent)、`messages[].destination.kind` (webhook / channel) | `messages[].payload` (Slack に送る payload そのもの。形は Slack の Block Kit の仕様に従い、arata のスキーマでは縛らない) |
| `log` | 構造化ログの行 (6 節) | `level`、`code`、`source`、`run_id` | `msg`、`error` ほかの属性 |
| (終了コード) | 両方のコマンド | arata: 0 正常 / 2 設定・権限 / 3 収集の一部失敗。aratam: 0 / 2 設定 / 3 LLM が使えず原文で送った / 4 入力が無い・古い / 5 送信に失敗 | |

漏れとして足したもの: `arata config check`・`aratam config check`・`aratam doctor` の JSON (今は人向けだけ)、終了コード。

対象にしないもの (外から読ませない。形はいつでも変えてよい):

- ストアの中身 (raw の JSONL、SQLite。ADR 0003・0033)。読むのは arata だけ
- `.aratam-notified` (aratam が自分で読む印)
- `report.md`・`waf-proposals.md`・`--format md`・table・text (人向け)
- aratam と LLM の間の入出力 (aratam の中で閉じる)

`aratam-config-check` の形 (架空の値):

```json
{
  "schema": "aratam-config-check",
  "schema_version": 1,
  "ok": true,
  "config": "aws/prod/aratam.yaml",
  "name": "example-prod",
  "llm": {"provider": "claude-cli"},
  "slack": {"method": "bot", "format": "blocks"},
  "timezone": "Asia/Tokyo",
  "rows": [
    {"status": "ok", "item": "config", "message": "…"}
  ]
}
```

設定を読めなかったときは `ok: false` と ng の行だけを出し、`name`・`llm`・`slack`・`timezone` は出さない (終了コードは今と同じ 2)。
`jq -r .slack.method` は `null` になるので、「bot / webhook 以外なら止める」と書いたワークフローは止まる。

### 3. スキーマの持ち方

**JSON Schema (draft 2020-12) のファイルを `schemas/<名前>.schema.json` に置き、バイナリに埋め込み、`arata schema [名前]` / `aratam schema [名前]` で出す。**

- 置き場所はリポジトリの最上位の `schemas/` (Go のパッケージ `schemas`。`docs/ai` と同じく `go:embed` で埋め込む)。
  標準ライブラリだけに依存させ、arata と aratam の両方が import する (`cmd/aratam/deps_test.go` の許可リストに足す)
- `arata schema` (引数なし) は名前の一覧、`arata schema report` はそのスキーマを標準出力に出す。`arata help schema [名前]` も同じものを出す
  (`help ai` と同じ扱い)。aratam は `aratam schema [名前]`。どちらのコマンドも全部のスキーマを出せる
  (aratam だけを入れた環境でも `report` を引ける。分けて持つ理由が無い)
- 各スキーマの `$id` は `urn:arata:schema:<名前>:<版>`。取りに行ける URL にはしない (配布はバイナリとリポジトリのファイルで足りる)
- **スキーマは開いた形にする (`additionalProperties: false` を書かない)。** 読む側が古いスキーマで新しい出力を検証しても、
  足した項目で落ちないようにするため。「スキーマに無い項目を出さない」ことは、スキーマではなく arata のテストで守る
- ファイルは **Go の型から生成する** (4 節)。手で編集しない

### 4. スキーマの作り方と、依存の扱い

**依存は足さない。出力の Go の型から、標準ライブラリ (`reflect`) でスキーマを生成し、生成したファイルをゴールデンとして固定する。**

- 生成器は `internal/jsonschema` に置く (標準ライブラリだけ)。扱うのは出力に使っている形だけ:
  構造体 (項目は定義の順。`omitempty` の無い項目は `required`)、文字列・真偽値・整数・小数、スライス (`array`)、
  `map[string]T` (`additionalProperties`)、`any` / `map[string]any` (中身を縛らない)、ポインタ (`omitempty` があれば省略できる項目、無ければ `null` を許す項目。
  `coverage.formats[].match_rate` が後者)、埋め込みの構造体。
  扱えない型 (チャネル・関数・インタフェースなど) はエラーにする (黙って落とさない)
- 語彙を固定する項目 (`slack.method` など) の `enum` と、項目の説明は、構造体のタグで書く。語彙は既存の定数から取る
- 生成はテストの中で行う (型を持つパッケージの `_test.go`)。`schemas` パッケージは、できたファイルを埋め込むだけで、
  型のパッケージを import しない (aratam に監査用の依存をつながない)
- 検証器 (JSON Schema で値を検証する処理) は持たない。arata も aratam も、実行時にスキーマで検証しない

テストで固定すること (対象ごとに):

1. **ゴールデン**: 型から生成したスキーマが `schemas/<名前>.schema.json` と一致する。型を変えるとテストが落ち、ゴールデンを
   更新する PR に理由を書くことになる (CLAUDE.md の規則)。消す・型を変える変更は、ここで差分として必ず見える
2. **型への読み込み**: コマンドを通して出した実際の出力 (コマンドレベルの e2e) を、`DisallowUnknownFields` でその型に読める。
   型に無い項目を出していない (`map` や別の型から組み立てた出力が、スキーマから外れていない) ことを確かめる
3. **必須の項目**: 同じ出力に、スキーマの `required` の項目がすべてあり、スキーマが `null` を許す項目のほかは `null` でない (配列を `null` で出さない)
4. **版の項目**: `schema` が名前と、`schema_version` がスキーマの版と一致する
5. **埋め込み**: `arata schema <名前>` の出力がファイルと一致し、一覧に全部の名前が出る

### 5. 版の付け方と、互換の決まり

**出力の最上位に `schema` (名前。`arata schema <名前>` の名前と同じ) と `schema_version` (整数。1 から) を足す。**

| 変更 | 扱い |
|---|---|
| 項目を足す | 互換。版は上げない。スキーマとゴールデンに足す |
| 開いた語彙に値を足す (`code`、チェックの名前、proposal の `kind` など) | 互換。版は上げない。読む側は知らない値を「その他」として扱う |
| 項目を消す・名前を変える・型を変える・意味を変える | **`schema_version` を上げる。Release の本文の「出力の互換性」に、何が・どう変わったか・読む側の直し方を書く** |
| 閉じた語彙に値を足す (`slack.method`、`rows[].status`、`level` など、読む側が全部の値を扱う前提のもの) | 同上 (版を上げる) |
| 必須の項目を省略できるようにする | 同上 (版を上げる) |
| 文言 (`msg`・`summary`・`detail`・`message`・`body`) を変える | 互換。文言は固定していない |

- 閉じた語彙はスキーマの `enum` で書く。開いた語彙は `enum` にしない (既知の値は 6 節の形か、説明に書く)
- 読む側の決まり (文書に書く): 知らない項目は無視する。閉じた語彙で知らない値を見たら止める。
  `schema_version` が自分の知る版より大きければ止める
- aratam は report.json の `schema_version` が自分の知る版より大きければ、中身を読まずに `INPUT_INVALID` として扱う
  (「arata と aratam の版が合っていない」と緊急用に送る。今の「読めない入力」と同じ道)。項目が無い (古い arata の出力) なら 1 として読む
- 版を上げるのは、できるだけまとめて、マイナー版のリリースで行う。パッチ版では上げない

**最上位が配列の出力 (`review`・`config-diff`) は、今の形 (配列) を版 1 としてそのまま固定し、`schema` の項目は足さない。**
配列をオブジェクトで包むのは、それ自体が互換を壊す変更で、`review --format json` は playbook が LLM に読ませている。
包むのは、ほかの理由でこの出力の版を上げるときに一緒に行う。今後足す出力は、最上位を必ずオブジェクトにする。

**`aratam notify --dry-run --format json` は、全体を 1 つの JSON にする** (`{schema, schema_version, messages: [{route, destination, payload}]}`)。
今の出力は `--- route: … ---` の行が挟まり JSON として読めないので、機械が読む出力として成り立っていない。これは互換を壊す変更として
Release の本文に書く (版 1 は新しい形から始める)。`payload` は今と同じく、Slack に送る中身そのもの。

### 6. 構造化ログ

標準エラーの JSON 行 (arata と aratam で共通の `log` スキーマ)。1 行ごとに `schema` の項目は足さない (行が長くなるだけで、読む側は行ごとに確かめない)。

| 項目 | 安定 | 内容 |
|---|---|---|
| `time` | 形 (RFC 3339) | 出した時刻 |
| `level` | 語彙 (閉じた語彙: `DEBUG` / `INFO` / `WARN` / `ERROR`。大文字) | |
| `code` | 語彙 (開いた語彙。下) | 何が起きたかを表す固定の語。無い行もある |
| `source` | 意味 | 設定の `sources` の名前。その行がソースに関するときだけ |
| `run_id` | 意味 | 実行の ID。あるときだけ |
| `msg` | あること | 人向けの文。文言は固定しない。**機械で読まない** |
| `error` ほかの属性 | 固定しない | 人が原因を調べるための値。ログ由来の値を含み得るので、公開されるログ (Actions のログ) に出さない |

- 見本のワークフローが出す `{level, code, source}` は、この安定な項目だけを選んでいる (今のまま)
- **`code` の一覧を 1 か所に持つ。** 標準ライブラリだけのパッケージ (`internal/codes`) に、code・出すコマンド (arata / aratam)・意味を並べ、
  既存の定数はそこを指す。テストで次を固定する
  - コードの中で `"code"` の属性に渡している値 (定数と文字列の直書き) が、すべて一覧にある (`go/ast` で走査する。標準ライブラリ)
  - `arata help ai` の code の表と `docs/aratam.md` の code の表が、一覧と一致する
  - `log` スキーマの `code` が一覧と一致する
- `code` は開いた語彙。スキーマでは `anyOf: [{enum: [既知の値…]}, {type: string, pattern: "^[A-Z][A-Z0-9_]*$"}]` と書く
  (既知の値を機械で引けて、足しても古いスキーマの検証で落ちない)。読む側は知らない code を「その他の警告・エラー」として扱う
- code を消す・名前を変える・意味を変えるのは、互換を壊す変更 (Release の本文に書く)。足すのは互換
- **新しく足す ERROR には必ず code を付ける。** WARN は、運用で気づくべきものに付ける。今 code の無い ERROR は、対象を広げる PR で付ける
- 設計書の例の `"level":"error"` は実際の値 (`ERROR`) に直す

### 7. 進める順

1. この ADR と CLAUDE.md の規則 (この PR。文書だけ)
2. 仕組み (生成器・`schemas`・`schema` コマンド・テストの型) と、`aratam-config-check` (新設)・`report` / `report-period`。
   見本のワークフローを `jq -r .slack.method` で読む形に直す
3. `log` と code の一覧
4. 最上位がオブジェクトの既存の出力 (`doctor`・`profiles`・`rebuild`・`help-ai`) に `schema` / `schema_version` を足す
5. `arata-config-check`・`aratam-doctor` (新設)、`aratam-dry-run` (形を変える)、配列の `review`・`config-diff` (今の形を固定)

## 検討した選択肢

### スキーマの作り方

- **A. Go の型から標準ライブラリで生成し、ゴールデンで固定する (採用)**: 依存が増えない。型とスキーマがずれない (ずれたらテストが落ちる)。
  出力は必ず型から作るので、「型に読める」ことの確認がそのまま「スキーマから外れていない」ことの確認になる。
  引き受けるもの: 生成器を自分で持つ (扱う形を絞るので小さい)。JSON Schema の細かい制約 (`minimum`・`format` など) は、タグに書いた分しか出ない
- **B. スキーマを手で書き、テストで検証のライブラリを使って出力を検証する**: JSON Schema の表現を全部使え、検証は本物になる。
  しかし依存が増える (テストだけに使うものでも `go.mod` に入り、age-gate・govulncheck・Dependabot の対象が増える。ADR 0017・0019)。
  型とスキーマを二重に持つので、項目を足したときにスキーマを直し忘れても、スキーマが開いた形だと検証は通ってしまう。
  今回守りたいのは「出力を黙って変えない」ことで、それは A のゴールデンで足りる。却下
- **C. スキーマを手で書き、検証器を自分で書く**: 依存は増えないが、draft 2020-12 の検証器は小さく書けない。
  一部だけ実装すると「検証を通った」の意味が曖昧になる。型との二重持ちは B と同じ。却下
- **D. スキーマのファイルを持たず、Go の型・ゴールデン・文書だけで固定する**: 一番小さい。しかし読む側 (jq を書く人、Go 以外の道具、LLM) が
  機械で引ける定義が無く、「外から読んでよい項目」が文書の表だけになる。文書と実装のずれを機械で確かめられない。却下
- **E. 生成に既製のライブラリを使う** (Go の型から JSON Schema を作るもの): A と同じ結果を依存で得る案。
  扱う形が限られていて自分で書ける量なので、依存にしない (ADR 0019 の基準)。却下

### 版の持ち方

- **整数 1 つの `schema_version` (採用)**: 足すのは互換と決めたので、版が動くのは互換を壊すときだけ。読む側の判定は「知っている版以下か」で済む
- **semver (`1.2.0`)**: 足したことも版で分かる。しかし読む側は足した項目を版ではなく項目の有無で見れば足り、比較が面倒になるだけ。却下
- **版の項目を持たず、バイナリの版 (`arata --version`) で読み分ける**: 出力ファイル (report.json) だけを受け取る側 (aratam) は、
  それを書いた arata の版を知らない。却下
- **`$schema` に URL を書く**: 取りに行ける場所を持つ必要が出る。名前と整数で足りる。却下

### 配列の出力

- **今の形を固定する (採用)**: 読む側 (playbook に従う LLM、利用者のスクリプト) を壊さない。版の項目は持てないが、ゴールデンとテストは同じに掛かる
- **今オブジェクトで包む**: 全部の出力が同じ形になる。しかし、この ADR の目的 (黙って壊さない) のために、いま壊すことになる。却下 (次に版を上げるときに行う)

## 結果 (良い点・引き受けるコスト)

良い点:

- 機械が読んでよい出力と項目が、名前付きで引ける (`arata schema`)。人向けの出力は気兼ねなく直せる
- 出力の型を変えるとゴールデンの差分になり、PR で必ず目に入る。消す・型を変える変更が黙って出ていかない
- 読む側は `schema_version` で、知らない形に気づいて止まれる
- 依存は増えない

引き受けるコスト:

- 出力を足す・変えるたびに、型・スキーマのゴールデン・テストを一緒に直す。新しい `--format json` には、型とスキーマが要る
- 生成器 (`internal/jsonschema`) を自分で保守する
- report.json に `schema` / `schema_version` が足される (report のゴールデンが 1 度変わる。aratam は未知の項目を無視するので、古い aratam でも読める)
- `aratam notify --dry-run --format json` の形が 1 度変わる (互換を壊す変更として Release の本文に書く)
- スキーマは開いた形なので、読む側がスキーマで検証しても「余計な項目が無いこと」は確かめられない (それは arata のテストの役目)
- `data`・`evidence`・Slack の payload の中身はスキーマで縛らない。チェックごとのキーは、今までどおり文書 (`arata help ai report`、playbook) が頼り
