# aratam 設計書

作成: 2026-10-21

`aratam` は arata の出力 (`report.json` / `report.md`) を読み、LLM で要約して通知するコマンド。
arata 設計書 9-1 章 (「report.json から通知までの LLM の仕事」) で組み込み側に任せた仕事を、毎回作らずに済むよう標準品にしたもの。
判断の経緯は ADR 0018。

## 1. 決定事項

| 項目 | 決定 |
|---|---|
| arata との関係 | **出力リソースを介してだけ連携する**。aratam は arata を呼ばず、arata のパス・AWS の監査ロール・ストアを知らない。組み合わせは cron / シェル側で行う |
| 配置 | 同じリポジトリの `cmd/aratam`。リリースには arata と aratam のバイナリを並べる。report.json の形と `docs/ai` の版が arata とずれない |
| 権限 | arata は AWS の読み取りロールだけ、aratam は LLM と通知の鍵だけを持つ。別の OS ユーザーで動かしてもよい |
| LLM | `bedrock` と `claude-cli` (`claude -p`) に対応する。将来 `openai-api`。`none` (LLM を使わず report.md を整形して送る) も選べる |
| 通知先 | Slack Incoming Webhook。通常用と緊急用の 2 本まで。SNS などは後続 |
| 依存 | 標準の `net/http` で書く。例外は Bedrock で、AWS SDK (`service/bedrockruntime`) を使ってよい (arata が AWS SDK の core を既に持つため増分が小さい) |
| 状態 | 持たない。二重送信の防止だけ、入力ディレクトリに `.aratam-notified` (通知済みの run_id) を書く |
| 判定 | LLM に判定させない。重大度の下限・必ず載せる finding・失敗時のフォールバックは aratam の規則で固定する (2 章) |

## 2. 処理の流れ

```
arata run -c config.yaml --profile daily --out /var/lib/arata/out/daily
aratam notify --in /var/lib/arata/out/daily
```

`aratam notify` は次の順で動く。

1. **入力の検査** (LLM を使わない)
   - `report.json` が無い、読めない、`generated_at` が `max_age` より古い → 「arata が実行されていない / 失敗した」と緊急用に直接送って終了 (終了コード 4)。
     cron 側で `arata run ... ; aratam notify ...` とつなげば、arata が出力すら書けなかった場合もここで拾える。
   - `.aratam-notified` に同じ `run_id` がある → 送らずに終了 (`--force` で再送)。
2. **規則による振り分け** (LLM を使わない)
   - 送り先: `summary.max_severity` が `urgent_severity` (既定 high) 以上、または `coverage.sources_failed` がある → 緊急用。それ以外 → 通常用。
   - 新規・変化・再発が 0 件で、取れなかったものも無い → `on_quiet` に従う (`short` = 「新規なし」と 1 行、`silent` = 送らない)。
3. **LLM による要約** (`llm.provider` が `none` 以外のとき)
   - 入力は `report.json` だけ。system には `docs/ai/report.md` (arata が `arata help ai report` で出すのと同じ文書) を埋め込んで渡す。
   - 出力は決まった JSON (3 章) に限る。形が合わない、時間切れ、エラー → 4 へ。
4. **組み立てと検証** (LLM を使わない)
   - LLM が返した分類と説明を、aratam が決まった書式で Slack のメッセージに組み立てる。
   - new / changed / recurred の finding が LLM の出力から漏れていたら、規則で組み立てた行として末尾に足す (LLM が finding を消す経路を作らない)。
   - LLM が使えなかったときは report.md を送る (Slack の上限に合わせて切り詰め、出力ディレクトリのパスを添える)。冒頭に「要約に失敗したため原文を送ります」と書く。
5. **送信** → 成功したら `.aratam-notified` に run_id を書く。

期間レポート (`"kind": "period"`) も同じ流れで扱う。違いは 3 の system 文書と、2 の振り分け (期間レポートは常に通常用) だけ。

決定 (実装順 1):
- 入力: `report.json` が JSON として読めない・`generated_at` が無いか RFC 3339 でない・知らない `kind` も「失敗した」とみなす。
  ログと通知の code は `INPUT_MISSING` (無い・読めない) / `INPUT_INVALID` (解釈できない) / `INPUT_STALE` (古い)。未知のフィールドは無視する (arata が足したフィールドで止まらないように)。
- 入力: 期間レポートの `report.md` が無ければ `report.json` から arata と同じ関数 (`internal/report/schema` の `Markdown`) で作る。
- 入力: 設定の `name` と report.json の `name` が違えば、標準エラーに `NAME_MISMATCH` を出し、通知の冒頭にも警告の行を足す (別の監査対象の出力を送っている取り違えに気付けるように)。
- 二重送信の防止: `.aratam-notified` の中身は直近の 1 件の識別子だけ (入力ディレクトリは監査対象・プロファイルごとに分かれ、arata が毎回上書きするため)。
  識別子は run の `run_id`。期間レポートは run_id を持たないので `period:<from>/<to>@<generated_at>` にする (作り直したら別の報告として送る)。
  入力の問題 (終了コード 4) は記録しない (次の cron でもう一度知らせる)。`on_quiet: silent` で送らなかったときは記録する。
- 二重送信の防止: `.aratam-notified` を書けなくても送信は済んでいるので終了コードは変えず、`MARK_FAILED` の警告だけ出す (次回は同じ報告を再送する)。
- `--dry-run` は `.aratam-notified` を見る (通知済みなら送らない旨をログに出す。中身を見たいときは `--force`) が、書かない。Webhook の環境変数も要らない。
- 期間レポートは件数が 0 でも「静か」とみなさず送る (月次などの定期の報告は、何も無かったことも伝える)。
- メッセージ: Slack の mrkdwn の本文だけで送る (8 章の未決は「まずは本文だけ」で進める)。
- メッセージ (`none` と LLM が使えなかったときの原文): run は report.md をそのまま送らず、report.json から短い形を作る。
  finding 1 件は「重大度・概要・チェック名」の行と「チェックごとの主要キー · id (初出)」の行の 2 行にする
  (report.md は data の全キーを列挙するので 1 件が 10 行を超え、Slack では読めない)。主要キーの対応表は `internal/notify/compact.go` の `keyFields`
  (例: unknown_assume_role = caller・count・ips・last_time、new_principal = kind・count・ips・external_account、login_bruteforce = ip・count・date・reason・threshold)。
  対応表に無いチェックは count と ips だけ。summary の文に既に入っている値は繰り返さない (文字列は部分一致、数値は「N 件」「N 回」の形で見る)。リストは 3 個まで。
  件数 0 の区分は出さない。カバレッジは問題 (取れなかったソース・解釈率の code・スキップしたチェック) があるときだけ出す。末尾に `全文: <dir>/report.md` を添える。
  期間レポートは report.md から件数 0 の節 (`## 見出し (0)`) を除き、見出しを `*見出し*`、`**太字**` を `*太字*` に置き換えて送る。
- メッセージ: report 由来の文字列は `&` `<` `>` をエスケープする。ログ由来の値 (User-Agent など) が `<!channel>` やリンクとして働かないようにするため。メンションは設定に書いたものだけを付ける。
- メッセージ: 1 通は 3,800 文字までに切り詰める (Slack は text を 4,000 文字程度までにするよう求めている)。行の境目で切り、`…(長いため省略)` と report.md のパスを添える。
- 送信: 再送はしない (Slack が受け取ったのに応答が届かなかった場合の二重送信を避ける。失敗は終了コード 5 で cron 側に任せる)。
  `net/http` のエラーは URL を含むので、中身だけを取り出してから返す (Webhook の URL をログに出さない)。

## 3. LLM との契約

LLM に求める出力:

```json
{
  "headline": "1 行の要約",
  "items": [
    {"finding_id": "...", "class": "action | confirm | info", "reason": "根拠付きの説明"}
  ],
  "incidents": [
    {"finding_ids": ["...", "..."], "summary": "同じ主体・同じ時間帯の finding をまとめた見立て"}
  ],
  "approve_suggestions": [
    {"finding_id": "...", "reason": "正当と思われる理由"}
  ]
}
```

- `class` は arata 設計書 9-1 の「要対処 / 確認依頼 / 情報」。**重大度は変えさせない**。表示する重大度は report.json の値を使う。
- `finding_id` が report.json に無いものは捨てる (LLM が作った ID を表示しない)。
- `approve_suggestions` は提案として表示するだけ。aratam は approve を実行しない。表示には `arata approve <id> --note "..."` の形を添える。
- 個人を特定できる値を書かないよう system で指示する。入力の report.json もその前提で作られている。

### 3-1. プロバイダ

| provider | 呼び方 | 認証 |
|---|---|---|
| `bedrock` | `bedrockruntime` の Converse API。`model` (推論プロファイル ID) と `region` は設定で明示する | AWS SDK の標準認証チェーン (`profile` 指定可)。必要なのは `bedrock:InvokeModel` だけ |
| `claude-cli` | `claude -p --output-format json` を子プロセスで起動し、プロンプトを標準入力で渡す。ツールは使わせない設定にし、作業ディレクトリは空の一時ディレクトリにする。決定: `--setting-sources project` で設定は project だけを読む (空のディレクトリなので project 設定は無く、ユーザー設定の hooks・権限設定・プラグインを読ませない。`--bare` は OAuth のログイン状態を読まなくなるので使わない) | `claude` 側のログイン状態 |
| `openai-api` (後続) | Chat Completions を `net/http` で呼ぶ | 環境変数の API キー |
| `none` | LLM を呼ばない | - |

- 共通: `timeout` (既定 120s)。失敗時の再試行は 1 回まで。
- インターフェースは `Summarize(ctx, system, reportJSON) (raw []byte, err error)` の 1 つ。JSON の検証と組み立ては共通部分で行い、プロバイダごとに書かない。

決定 (実装順 2〜3):
- 再試行: エラー・時間切れに加え、形が合わない出力も 1 回だけ再試行する (2 回目は契約どおりに返すことが多いため)。`timeout` は 1 回ごとにかける。
  再試行は `LLM_RETRY`、最終的な失敗は `LLM_FAILED` (標準エラー) で、原文を送って終了コード 3。
- 出力の検証: 前後の文やコードフェンスが付いていたら最初の `{` から最後の `}` までを取り出す。`headline` が空なら形が不正。
  report.json に無い `finding_id`、`class` が action / confirm / info 以外の item、同じ `finding_id` の 2 件目以降は捨てる
  (捨てた finding が new / changed / recurred なら「要約に含まれていなかった指摘 (規則で追加)」として末尾に足される)。
  incidents は知らない ID を除き、ID が残らなければ捨てる。approve_suggestions も知らない ID のものを捨てる。
  知っている ID なら still_open などを分類してもよい (表示は report.json の区分を添える)。
- 組み立て: 1 行目の名前と期間、件数の行、取れなかったソース (期間レポートは取れなかった run)、漏れた finding は report.json から規則で書き、
  LLM の文字列は headline・reason・incidents・approve の理由だけ。どれもエスケープし、改行は空白にする (書式を崩させない)。
  切り詰めは LLM の分類と説明の部分だけを切り、規則で書いた部分 (漏れた finding・取れなかったもの) は落とさない。
- 期間レポート: system の文書は足さない。`docs/ai/report.md` の「期間レポート」の節で足りるため (8 章の未決を閉じる)。
  必ず載せる finding は events の new / changed / recurred。
- system: 出力の契約 (3 章)、「追加の照会はできない。report.json だけで判断する」、続けて `docs/ai/report.md` を埋め込む。
- `claude-cli`: `claude -p --output-format json --tools "" --strict-mcp-config --no-session-persistence --setting-sources project --system-prompt <system> [--model <model>]`。
  ツールも MCP サーバーも使わせず、セッションをディスクに残さない。作業ディレクトリは空の一時ディレクトリ (終わったら消す)。
  子プロセスの環境変数は aratam のものから Webhook の環境変数 (`slack.webhook_env` / `urgent_webhook_env`) を除いて渡す。
  `--output-format json` の `is_error` が真なら失敗。実行ファイルは `llm.command` (空なら PATH の `claude`。cron の PATH が狭い場合に絶対パスで書く)。
- `bedrock`: SDK の自動再試行は切る (RetryMaxAttempts 1。再試行は共通部分で 1 回までと決めているため重ねない)。温度 0、maxTokens 4096。
  stopReason が max_tokens なら失敗 (途中で切れた JSON を検証に回さない)。

## 4. 設定

arata と同じく暗黙の既定を持たない。`aratam config init` で全項目を明示した雛形を出す。

```yaml
name: example                     # 通知に出す監査対象の名前 (report.json の name と違えば警告)
max_age: 26h                      # report.json がこれより古ければ「実行されていない」と通知する
urgent_severity: high             # この重大度以上は緊急用に送る
on_quiet: short                   # short | silent

llm:
  provider: bedrock               # bedrock | claude-cli | none (後続で openai-api)
  model: <推論プロファイル ID>
  region: us-east-1
  # profile: aratam-llm
  timeout: 120s
  # command: /usr/local/bin/claude   # claude-cli の実行ファイル (決定: 実装順 2 で追加。空なら PATH の claude)

slack:
  webhook_env: ARATAM_SLACK_WEBHOOK            # 通常用。URL は設定ファイルに書かず環境変数で渡す
  urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK   # 省略時は通常用に送り、冒頭にメンションを付ける
  urgent_mention: "<!channel>"
```

- Webhook の URL は秘密なので設定ファイルに書かせない (環境変数の名前だけを書く)。

決定 (実装順 1):
- 必須: `name`, `max_age`, `urgent_severity` (critical | high | medium | low), `on_quiet`, `llm.provider`, `slack.webhook_env`。
  `llm.timeout` は provider が `none` 以外なら必須、`bedrock` は `llm.model` と `llm.region` も必須。`claude-cli` の `model` は省略可 (claude 側の既定)。
  `slack.urgent_webhook_env` と `slack.urgent_mention` は省略可。未知のキーは誤記とみなして設定エラーにする (arata と同じ)。
- `*_env` は環境変数の名前 (`[A-Za-z_][A-Za-z0-9_]*`) でなければ設定エラー。URL を貼った誤りを弾き、エラーには値を出さない。
- `urgent_webhook_env` を書いたのに環境変数が空なら、通常用に送り `urgent_mention` を付ける (`URGENT_WEBHOOK_UNSET` の警告を出す)。緊急の通知を落とさないため。
  緊急用の Webhook があるときはメンションを付けない (チャンネル自体が緊急用のため)。
- 雛形 (`config init`) の `llm.provider` は `none` にする。LLM の鍵を用意する前でも notify が動き、まず規則だけの通知で流れを確かめられるように。
  `max_age` などの書式は arata の設定と同じ (`time.ParseDuration` と `d` = 日)。

## 5. CLI

```
aratam config init [--out aratam.yaml] [--force]
aratam notify  --in <dir> [-c aratam.yaml] [--dry-run] [--force]
               # --dry-run は送らずに標準出力へ。LLM は呼ぶ (--llm none で呼ばない)
aratam doctor  [-c aratam.yaml]   # LLM に短い問い合わせを 1 回、Webhook の環境変数の有無を確認 (送信はしない)
aratam test-notify [-c aratam.yaml] # Slack に試験メッセージを 1 通送る
```

- 決定: 設定ファイルのパスには既定を持つ。`-c` > 環境変数 `ARATAM_CONFIG` > カレントディレクトリの `aratam.yaml` の順に探す。
  `config init` の書き出し先も既定は `./aratam.yaml` (既存ファイルは `--force` が無ければ上書きしない)。
  `--in` は既定を持たない (監査対象・プロファイルごとに違うデータの場所で、取り違えると別の report を送ってしまうため)。
- プロバイダ名は呼び方を表す (`claude-cli` / `openai-api`)。同じモデルを別の経路で呼ぶプロバイダを足しても名前が衝突しない。
- 終了コード: 0 = 送った (または on_quiet=silent / 通知済みで送らなかった)、2 = 設定エラー、
  3 = LLM が使えず report.md で送った、4 = 入力が無い・古い (その旨は送った)、5 = 送信に失敗した。
- 送信に失敗したら標準エラーに出して終了コード 5。cron 側の MAILTO などで拾える。
- 決定: CLI は arata と同じ標準 `flag` の上のコマンド層 (`internal/subcmd`) を共有する。ヘルプの書式・フラグのエラー文言・未知のコマンドで終了コード 2 も arata と同じ。
  標準エラーのログも arata と同じ JSON (`msg` と固定語彙の `code`)。
- 決定: `--dry-run` の出力は 1 通ごとに `--- route: <normal|urgent> → <送る Webhook> ---` の行を付けて本文を出す。
- 決定: `--llm` で `llm.provider` を上書きしたら、上書き後の設定で検証し直す (`--llm none` なら model などは要らない)。
- 決定 (`doctor`): config / webhook / llm を表 (STATUS ITEM DETAIL) で出す。Webhook は環境変数の有無だけで URL は表示しない。
  通常用が無ければ ng (`WEBHOOK_UNSET`)、緊急用の名前を書いたのに無ければ warn (`URGENT_WEBHOOK_UNSET`)。
  LLM は「疎通確認です。ok とだけ返してください。」を 1 回送り (report のデータは渡さない。再試行しない)、失敗や claude の実行ファイルが無ければ ng (`LLM_UNAVAILABLE`)。
  ng が 1 つでもあれば終了コード 2、ng / warn の行は標準エラーにも code 付きで出す。
- 決定 (`test-notify`): 既定は通常用、`--urgent` で緊急用に送る (緊急用が無ければ notify と同じく通常用にメンション付き)。送信に失敗したら終了コード 5。

## 6. パッケージ構成

```
cmd/aratam/          # CLI
internal/notify/     # 設定、入力の検査、振り分け、組み立て、検証 (LLM とネットワークに依存しない。テストの中心)
internal/llm/        # Summarizer と各プロバイダ (bedrock / claudecli)
internal/slack/      # Incoming Webhook の送信 (net/http)
internal/subcmd/     # arata と共有する、標準 flag の上のコマンド層
internal/report/schema/  # arata と共有する report.json の型 (標準ライブラリだけに依存)
docs/ai/             # arata と共有。aratam は report.md を system として埋め込む
```

- テストは report.json のゴールデンと、LLM の応答の固定値 (正常・欠落あり・形が不正・時間切れ) で書く。実 LLM と実 Slack には接続しない。
- `internal/report` の型を import して report.json を読む (形のずれをコンパイル時に検出する)。
- 決定: report.json の型 (と JSON・Markdown・Parse) は、標準ライブラリだけに依存する `internal/report/schema` に置き、`internal/report` は型エイリアスで同じ名前を出す。
  `internal/report` は組み立てのために checks / store を import しており、aratam がそれを import すると SQLite と監査用の AWS SDK のサービスがバイナリに入るため。
- 決定: aratam が依存してよいパッケージを `cmd/aratam/deps_test.go` の許可リストで固定する (`go list -deps`)。SQLite・監査用の AWS SDK のサービス・
  `internal/{store,checks,collect,engine,config}` は名指しで禁止する。
- 決定: テストの report.json / report.md は arata のゴールデン (`internal/report/testdata`) をそのまま読む (コピーしない。arata の出力が変われば aratam のテストも落ちる)。

## 7. 実装順

1. `internal/notify` (入力の検査・振り分け・`none` での組み立て) と `internal/slack`、`notify --dry-run`、`config init`
2. `claude-cli` プロバイダと LLM 出力の検証・補完
3. `bedrock` プロバイダ、`doctor`、`test-notify`
4. リリースへの追加 (aratam のバイナリ 2 つ)、README

## 8. 未決事項

- Slack の書式を Block Kit にするか mrkdwn の本文だけにするか (まずは本文だけ)
- ~~期間レポート用の system 文書を `docs/ai` に足すか、report.md の節で足りるか~~ (決定: report.md の節で足りる。3-1 章)
- 同じ run の hourly と daily で通知をまとめるか (まずは別々に送る)
