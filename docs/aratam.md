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
| `claude-cli` | `claude -p --output-format json` を子プロセスで起動し、プロンプトを標準入力で渡す。ツールは使わせない設定にし、作業ディレクトリは空の一時ディレクトリにする | `claude` 側のログイン状態 |
| `openai-api` (後続) | Chat Completions を `net/http` で呼ぶ | 環境変数の API キー |
| `none` | LLM を呼ばない | - |

- 共通: `timeout` (既定 120s)。失敗時の再試行は 1 回まで。
- インターフェースは `Summarize(ctx, system, reportJSON) (raw []byte, err error)` の 1 つ。JSON の検証と組み立ては共通部分で行い、プロバイダごとに書かない。

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

slack:
  webhook_env: ARATAM_SLACK_WEBHOOK            # 通常用。URL は設定ファイルに書かず環境変数で渡す
  urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK   # 省略時は通常用に送り、冒頭にメンションを付ける
  urgent_mention: "<!channel>"
```

- Webhook の URL は秘密なので設定ファイルに書かせない (環境変数の名前だけを書く)。

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

## 6. パッケージ構成

```
cmd/aratam/          # CLI
internal/notify/     # 入力の検査、振り分け、組み立て、検証 (LLM とネットワークに依存しない。テストの中心)
internal/llm/        # Summarizer と各プロバイダ (bedrock / claudecli)
internal/slack/      # Incoming Webhook の送信 (net/http)
docs/ai/             # arata と共有。aratam は report.md を system として埋め込む
```

- テストは report.json のゴールデンと、LLM の応答の固定値 (正常・欠落あり・形が不正・時間切れ) で書く。実 LLM と実 Slack には接続しない。
- `internal/report` の型を import して report.json を読む (形のずれをコンパイル時に検出する)。

## 7. 実装順

1. `internal/notify` (入力の検査・振り分け・`none` での組み立て) と `internal/slack`、`notify --dry-run`、`config init`
2. `claude-cli` プロバイダと LLM 出力の検証・補完
3. `bedrock` プロバイダ、`doctor`、`test-notify`
4. リリースへの追加 (aratam のバイナリ 2 つ)、README

## 8. 未決事項

- Slack の書式を Block Kit にするか mrkdwn の本文だけにするか (まずは本文だけ)
- 期間レポート用の system 文書を `docs/ai` に足すか、report.md の節で足りるか
- 同じ run の hourly と daily で通知をまとめるか (まずは別々に送る)
